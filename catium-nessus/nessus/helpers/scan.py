"""
Nessus helpers for API/UI Scans
:copyright: Tenable Network Security, 2017
:date: Mar 30, 2017
:last_modified: June 25, 2022
:author: @rdutta, @kpanchal, @krpatel
"""
import os
from http import HTTPStatus

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located
from waiting import TimeoutExpired, wait

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path, load_testdata
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.const import LOCALHOST_IPV4, STRING_ON, STRING_YES, TIME_FIFTEEN_MINUTES, TIME_TEN_MINUTES, \
    WAIT_NORMAL, WAIT_SHORT, TIME_THIRTY_MINUTES, TIME_THIRTY_SECONDS
from catium.lib.const.base_constants import TIME_FIFTEEN_SECONDS, TIME_TWO_MINUTES, TIME_FIVE_MINUTES
from catium.lib.errors import CatiumAPIObjectError
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util import poll
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait as webium_wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.audits.audit import get_compliance_id
from nessus.helpers.metadata.scan import get_template_name, get_template_uuid_by_name
from nessus.helpers.nessuscli.helper import get_nessus_cli, get_os_name, start_nessus, \
    stop_nessus, get_nessus_var_dir
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.settings import add_advanced_settings, get_current_advanced_settings
from nessus.helpers.waiters import wait_for_export_to_complete, wait_for_new_advanced_preference, wait_for_plugins, \
    wait_for_scan, wait_for_scanner_login, wait_for_scanner_status, wait_scan_state
from nessus.lib.config import NessusConfig
from nessus.lib.const import API, Nessus, Scanner, random_name, OperatingSystems
from nessus.lib.message.messages import Messages
from nessus.models.scan import ScanModel
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.debug_logs.debug_logs_page import DebugLogsPage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, close_pendo_guide_container_banner_for_nessus_pro
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, VulnerabilityList, ScanExportPage, \
    VulnerabilityDescription, ScansHostList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

WINDOWS_SCAP_SCAN_FILE = 'nessus/tests/api/scan/test_data/U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip'

CISCO_IOS_SCAN_AUDIT_FILE = 'nessus/tests/api/scan/test_data/CIS_Cisco_v2.2_Level_1.audit'
CISCO_IOS_SCAN_CONFIG_FILE = 'nessus/tests/api/scan/test_data/CiscoIOSOffline_PolicyTestFile.txt'

OFFLINE_AUDITS = {'custom': {'add': [{'category': 'Cisco IOS', 'file': ''}]}}
SCAP = {'add': {'Windows': [{'file': '', 'version': '1.1', 'benchmark_id': 'Windows_7_STIG',
                             'profile_id': 'MAC-1_Classified',
                             'oval_result_type': 'Full results w/ system characteristics'}]}}

log = create_logger()


def launch_scan(scan_api: NessusAPI, scan_model: ScanModel, target: str, plugin_id: str,
                scan_type: str = Nessus.Scan.ResultTypes.DEFAULT, download: bool = None,
                export_format: str = API.Scan.ExportFormats.FORMAT_DB,
                db_password: str = None,
                filename: str = None, check_audit: bool = None) -> (str, dict):
    """
    Utility method for launching a scan using the scan_model defined in the functions below.

    :param NessusAPI scan_api: Api object to scanner
    :param ScanModel scan_model: Scan information
    :param str target:       Target for Scan
    :param str plugin_id:    Plugin ID for scan
    :param str scan_type:    Controls how the scan function will deal with multiple hosts.
    :param bool download:    If set to true, the Nessus DB is downloaded.
    :param export_format:    Export format to use when downloading scan results.  Defaults to Nessus DB Format.
    :param str db_password:  Password to use for the DB.  Uses the constant Scanner.Strings.NESSUS_DB_PASSWORD.
    :param str filename:     A filename for the exported file
    :param bool check_audit: if set to true check for the audit file
    """
    # Configure dynamic values outside of function defaults so it's always set at runtime.
    download = NessusConfig.CAT_NESSUS_DB_DOWNLOAD if download is None else download
    db_password = NessusConfig.CAT_NESSUS_DB_PASSWORD if db_password is None else db_password
    filename = NessusConfig.CAT_NESSUS_DB_FILENAME if filename is None else filename

    # TODO: Refactor launch_scan helper function.  Could add parameter for host == host comparisons:
    # https://stash.corp.tenablesecurity.com/projects/AUT/repos/common_ui_framework/
    # pull-requests/529/overview?commentId=29999
    if scan_type == Nessus.Scan.ResultTypes.MOBILE:
        adv_settings = get_current_advanced_settings(scan_api)
        if Nessus.AdvancedSettings.MDM_DISABLE_INACTIVE_DEVICE_FILTERING not in adv_settings:
            add_advanced_settings([{'name': Nessus.AdvancedSettings.MDM_DISABLE_INACTIVE_DEVICE_FILTERING,
                                    'value': STRING_YES}], scan_api)
            wait_for_new_advanced_preference(
                api=scan_api, setting_name=Nessus.AdvancedSettings.MDM_DISABLE_INACTIVE_DEVICE_FILTERING)
    wait_for_scanner_status(api=scan_api, status=API.Status.READY,
                            timeout=TIME_TEN_MINUTES, msg=Scanner.Strings.AVAILABILITY_OF_SCANNER,
                            sleep_interval=WAIT_NORMAL)

    # wait for plugin set to load. In the event Nessus reloads attempt to wait for scanner status before
    # checking plugins status.
    try:
        wait_for_plugins(api=scan_api, timeout=TIME_THIRTY_MINUTES)
    except:
        wait_for_scanner_status(api=scan_api, status=API.Status.READY,
                                timeout=TIME_TEN_MINUTES, msg=Scanner.Strings.AVAILABILITY_OF_SCANNER,
                                sleep_interval=WAIT_NORMAL)
        wait_for_scanner_login(scan_api, NessusConfig.CAT_NESSUS_USERNAME, NessusConfig.CAT_NESSUS_PASSWORD,
                               TIME_TEN_MINUTES, 'Waiting for scanner login to succeed')
        wait_for_plugins(api=scan_api, timeout=TIME_THIRTY_MINUTES)

    # we should be logged in at this point but in some cases Nessus can be reloaded thus logging us out
    try:
        scan = scan_api.scans.create(scan_model)
    except:
        wait_for_scanner_status(api=scan_api, status=API.Status.READY,
                                timeout=TIME_TEN_MINUTES, msg=Scanner.Strings.AVAILABILITY_OF_SCANNER,
                                sleep_interval=WAIT_NORMAL)
        wait_for_scanner_login(scan_api, NessusConfig.CAT_NESSUS_USERNAME, NessusConfig.CAT_NESSUS_PASSWORD,
                               TIME_TEN_MINUTES, 'Waiting for scanner login to succeed')
        scan = scan_api.scans.create(scan_model)

    scan_api.scans.launch(scan['scan']['id'], alt_targets=[target])

    # Poll the API until the Scan is running.
    # Note that sometimes the scan can finish before we reach here, so check for completed status also
    try:
        wait(lambda: scan_api.scans.details(
            scan['scan']['id'])['info']['status'] in [API.Scan.Status.RUNNING, API.Scan.Status.COMPLETED],
             sleep_seconds=WAIT_NORMAL, waiting_for=Scanner.Strings.SCAN_TO_START, timeout_seconds=TIME_TEN_MINUTES)
    except TimeoutExpired:
        scan_api.scans.delete(scan['scan']['id'])
        pytest.fail('Failed to start scan within given time frame.')

    # Poll the API until the Scan is completed.
    try:
        wait_for_scan(api=scan_api, scan_id=scan['scan']['id'], status=API.Scan.Status.COMPLETED,
                      timeout=TIME_FIFTEEN_MINUTES)
    except TimeoutExpired:
        scan_api.scans.stop(scan['scan']['id'])
        poll(lambda: scan_api.server.status)
        scan_api.scans.delete(scan['scan']['id'])
        pytest.fail('Failed to complete scan within given time frame.')

    hosts_out = scan_api.scans.details(scan['scan']['id'])
    if scan_type not in [Nessus.Scan.ResultTypes.MOBILE, Nessus.Scan.ResultTypes.ADSI,
                         Nessus.Scan.ResultTypes.MISCELLANEOUS]:
        # In the case of the scans above, we expect there to occasionally be more than one host, and we need to continue
        # the test if that is the case.
        if len(hosts_out['hosts']) > 1:
            pytest.fail('More than one target included in test. There are %s targets.' % len(hosts_out['hosts']))

    host_id = ''
    for host in hosts_out['hosts']:
        # in the case of a mobile scan we don't care what host it is as long as it's not localhost.
        # for non-mobile scans there will only be one host anyway.
        if scan_type == Nessus.Scan.ResultTypes.MOBILE:
            if host['hostname'] in [LOCALHOST_IPV4, API.Credentials.Host.HostNames.MOBILE_REPORTING]:
                continue
        elif scan_type == Nessus.Scan.ResultTypes.MISCELLANEOUS:
            if host['hostname'] == API.Credentials.Host.HostNames.ESX_MACHINE:
                continue
        host_id = host['host_id']

    if download:
        download_scan(scan_api, scan_id=scan['scan']['id'], export_format=export_format,
                      password=db_password, filename=filename)

    json_out = scan_api.scans.plugin_output(scan_id=scan['scan']['id'], plugin_id=plugin_id, host_id=host_id)
    audit_trail = scan_api.scans.get_audit_trail(scan_id=scan['scan']['id'], plugin_id=plugin_id, hostname=target)
    audit = None
    if 'info' in json_out:
        if 'plugin_information' in json_out['info']['plugindescription']['pluginattributes']:
            plugin_information = json_out['info']['plugindescription']['pluginattributes']['plugin_information']
            if plugin_id == str(plugin_information['plugin_id']):
                scan_api.scans.delete(scan['scan']['id'])
        if audit_trail['trails']:
            for x in audit_trail['trails']:
                audit = str(x['output'])
    else:
        pytest.fail('No plugin information in scan results.  Please review the scan results.')

    outputs = json_out['outputs']
    if outputs is None:
        if not check_audit:
            if audit_trail['trails'] is None:
                pytest.fail('Plugin failed to fire and no audit trail')
            else:
                pytest.fail('plugin did not fire, audit trail: ' + str(audit))

    return json_out, audit


def launch_compliance_scan(scan_api: NessusAPI, scan_model: ScanModel, target: str, compliance_check: str,
                           scan_type: str = Nessus.Scan.ResultTypes.DEFAULT,
                           download: bool = None,
                           export_format: str = API.Scan.ExportFormats.FORMAT_DB,
                           db_password: str = None,
                           filename: str = None) -> (str, dict):
    """
    Utility method for launching a scan using the scan_model defined in the functions below. Identical to launch_scan,
    other than call to compliance_output, but leaving separate incase we need to add different functionality in the
    future.

    :param NessusAPI scan_api:     Api object to scanner
    :param ScanModel scan_model:   Scan information
    :param str target:             Target for Scan
    :param str compliance_check:   Name of the check expected in scan results.
    :param str scan_type:          Controls how the scan function will deal with multiple hosts.
    :param bool download:          If set to true, the Nessus DB is downloaded.
    :param export_format:          Export format to use when downloading scan results.  Defaults to Nessus DB Format.
    :param str db_password:        Password to use for the DB.  Uses the constant Scanner.Strings.NESSUS_DB_PASSWORD.
    :param str filename:           A filename for the exported file
    """
    # Configure dynamic values outside of function defaults so it's always set at runtime.
    download = NessusConfig.CAT_NESSUS_DB_DOWNLOAD if download is None else download
    db_password = NessusConfig.CAT_NESSUS_DB_PASSWORD if db_password is None else db_password
    filename = NessusConfig.CAT_NESSUS_DB_FILENAME if filename is None else filename

    wait_for_scanner_status(api=scan_api, status=API.Status.READY,
                            timeout=TIME_TEN_MINUTES, msg=Scanner.Strings.AVAILABILITY_OF_SCANNER,
                            sleep_interval=WAIT_NORMAL)

    # wait for plugin set to load. In the event Nessus reloads attempt to wait for scanner status before
    # checking plugins status.
    try:
        wait_for_plugins(api=scan_api, timeout=TIME_THIRTY_MINUTES)
    except:
        wait_for_scanner_status(api=scan_api, status=API.Status.READY,
                                timeout=TIME_TEN_MINUTES, msg=Scanner.Strings.AVAILABILITY_OF_SCANNER,
                                sleep_interval=WAIT_NORMAL)
        wait_for_scanner_login(scan_api, NessusConfig.CAT_NESSUS_USERNAME, NessusConfig.CAT_NESSUS_PASSWORD,
                               TIME_TEN_MINUTES, Scanner.Strings.SCANNER_LOGIN_SUCCEED)
        wait_for_plugins(api=scan_api, timeout=TIME_THIRTY_MINUTES)

    # we should be logged in at this point but in some cases Nessus can be reloaded thus logging us out
    try:
        scan = scan_api.scans.create(scan_model)
    except:
        wait_for_scanner_status(api=scan_api, status=API.Status.READY,
                                timeout=TIME_TEN_MINUTES, msg=Scanner.Strings.AVAILABILITY_OF_SCANNER,
                                sleep_interval=WAIT_NORMAL)
        wait_for_scanner_login(scan_api, NessusConfig.CAT_NESSUS_USERNAME, NessusConfig.CAT_NESSUS_PASSWORD,
                               TIME_TEN_MINUTES, Scanner.Strings.SCANNER_LOGIN_SUCCEED)
        scan = scan_api.scans.create(scan_model)

    scan_api.scans.launch(scan['scan']['id'], alt_targets=[target])

    # Poll the API until the Scan is running.
    # Note that sometimes the scan can finish before we reach here, so check for completed status also
    try:
        wait(lambda: scan_api.scans.details(
            scan['scan']['id'])['info']['status'] in [API.Scan.Status.RUNNING, API.Scan.Status.COMPLETED],
             sleep_seconds=WAIT_NORMAL, waiting_for=Scanner.Strings.SCAN_TO_START, timeout_seconds=TIME_TEN_MINUTES)
    except TimeoutExpired:
        scan_api.scans.delete(scan['scan']['id'])
        pytest.fail('Failed to start scan within given time frame.')

    # Poll the API until the Scan is completed.
    try:
        wait_for_scan(api=scan_api, scan_id=scan['scan']['id'], status=API.Scan.Status.COMPLETED,
                      timeout=TIME_FIFTEEN_MINUTES)
    except TimeoutExpired:
        scan_api.scans.stop(scan['scan']['id'])
        poll(lambda: scan_api.server.status)
        scan_api.scans.delete(scan['scan']['id'])
        pytest.fail('Failed to complete scan within given time frame.')

    hosts_out = scan_api.scans.details(scan['scan']['id'])
    if scan_type not in [Nessus.Scan.ResultTypes.MOBILE, Nessus.Scan.ResultTypes.ADSI,
                         Nessus.Scan.ResultTypes.MISCELLANEOUS]:
        # In the case of the scans above, we expect there to occasionally be more than one host, and we need to continue
        # the test if that is the case.
        if len(hosts_out['hosts']) > 1:
            pytest.fail('More than one target included in test. There are %s targets.' % len(hosts_out['hosts']))

    host_id = ''
    for host in hosts_out['hosts']:
        # in the case of a mobile scan we don't care what host it is as long as it's not localhost.
        # for non-mobile scans there will only be one host anyway.
        if scan_type == Nessus.Scan.ResultTypes.MOBILE:
            if host['hostname'] in [LOCALHOST_IPV4, API.Credentials.Host.HostNames.MOBILE_REPORTING]:
                continue
        elif scan_type == Nessus.Scan.ResultTypes.MISCELLANEOUS:
            if host['hostname'] == API.Credentials.Host.HostNames.ESX_MACHINE:
                continue
        host_id = host['host_id']

    if download:
        download_scan(scan_api, scan_id=scan['scan']['id'], export_format=export_format,
                      password=db_password, filename=filename)

    json_out = scan_api.scans.details(scan_id=scan['scan']['id'])
    if json_out['compliance']:
        compliance_plugin_id = get_compliance_id(json_out['compliance'], compliance_check)
        if compliance_plugin_id:
            json_out = scan_api.scans.compliance_output(scan_id=scan['scan']['id'], host_id=host_id,
                                                        plugin_id=compliance_plugin_id)
            scan_api.scans.delete(scan['scan']['id'])
        return json_out
    else:
        pytest.fail('No compliance results in scan results.  Please review the scan results.')


def download_scan(scan_api, scan_id: str, export_format: str = API.Scan.ExportFormats.FORMAT_DB,
                  password: str = None,
                  nessus_db_directory: str = None,
                  filename: str = None):
    """
    Utility method for downloading scan result in the given format.

    :param NessusAPI scan_api:       Api object to scanner
    :param str scan_id:              Scan ID of the scan to download.
    :param str export_format:        Export format.
        Supported Options: nessus, html, pdf, csv or db
    :param str password:             Password if downloading a Nessus DB.
    :param str nessus_db_directory:  Directory where the Nessus DB file should be saved.
    :param str filename:             A filename for the exported file
    """
    # Configure dynamic values outside of function defaults so it's always set at runtime.
    password = NessusConfig.CAT_NESSUS_DB_PASSWORD if password is None else password
    nessus_db_directory = NessusConfig.CAT_NESSUS_DB_DIRECTORY if nessus_db_directory is None else nessus_db_directory
    filename = NessusConfig.CAT_NESSUS_DB_FILENAME if filename is None else filename

    if export_format not in API.Scan.ExportFormats.VALID_FORMATS:
        raise CatiumAPIObjectError('Invalid Scan export format supplied: {0}.'.format(export_format))

    export_details = scan_api.scans.export(scan_id=scan_id, export_format=export_format, password=password)
    if scan_api.http_status_code == HTTPStatus.OK:
        wait_for_export_to_complete(api=scan_api, scan_id=scan_id, file_id=export_details[0])
        scan_db = scan_api.scans.download(scan_id=scan_id, file_id=export_details[0])

        if filename:
            file_name = os.path.join(nessus_db_directory, filename)
        else:
            file_name = os.path.join(nessus_db_directory, "{0}_{1}".format(str(scan_id), Scanner.NESSUS_DB_TIMESTAMP))
        log.info("[download_scan]: Saving to %s", file_name)
        try:
            with open(file_name + ".db", "wb") as file:
                for block in scan_db.iter_content(1024):
                    file.write(block)
                file.close()
            log.info("[download_scan]: Scan results saved as %s.db", file_name)
        except FileNotFoundError:
            log.info("[download_scan]: Unable to write to %s.", nessus_db_directory)
    else:
        pytest.fail("[download_scan]: Unable to export the scan DB.")


def create_scan_helper(api_handler: NessusAPI, file_name: str, template_title: str, change_scan_name: bool = False,
                       staggered_start_mins: int = 0, **kwargs) -> [ResponseObject, ScanModel]:
    """
    :param api_handler:  API object to scanner
    :param kwargs: kwargs to provide additional arguments
    :param file_name:  path to file data
    :param template_title: template title
    :param change_scan_name: boolean to add random characters in scan name or not to avoid same name scans
    :param staggered_start_mins: to add staggered_start_mins in scan to have some delay in launching the scan
    :return:
    """
    log.debug('fixture init: create_scan: Create a Scan')
    # test_data_file is tuple, it's 1st element is .json file path
    # which contain payload
    # file_name = test_data_file[0]

    # test_data_file's 2nd element is template name which will be used to get uuid of the
    # template based on the name
    # template_title = test_data_file[1]

    template_list = api_handler.scans.get_templates()

    # based on template title will get uuid for it
    template_uuid = get_template_uuid_by_name(template_list, template_title)
    scan_model = ScanModel.create_model()

    if file_name:
        scan_data = load_testdata(file_name)
    else:
        scan_data = kwargs.get("payload")

    if 'uuid' in scan_data.keys():
        setattr(scan_model, 'uuid', template_uuid)

    if change_scan_name:
        setattr(scan_model, 'name', random_name(prefix=scan_data['settings']['name'] + '-'))

    template_name = ''
    if scan_data['uuid']:
        template_name = get_template_name(template_list, template_uuid)

    if template_name == Nessus.Scan.TemplateNames.CLOUD_AUDIT:
        if scan_data['credentials']:
            scan_model.add_aws_credential(scan_data['credentials'])
            scan_model.add_audit_file(API.Audits.Type.Feed, scan_data['audits'])

    if template_name == Nessus.Scan.TemplateNames.DISCOVERY:
        if scan_data['settings']['text_targets'] == Nessus.Scan.Target.MAX_DISCOVERY_TARGET:
            setattr(scan_model, 'text_targets', scan_data['settings']['text_targets'])

    if template_name == Nessus.Scan.TemplateNames.MALWARE or template_name == Nessus.Scan.TemplateNames.PATCH_AUDIT:
        if scan_data['credentials']:
            scan_model.add_windows_credential(scan_data['credentials'])

    elif template_name == Nessus.Scan.TemplateNames.MDM or template_name == Nessus.Scan.TemplateNames.MOBILE \
            or template_name == Nessus.Scan.TemplateNames.COMPLIANCE:
        if scan_data['credentials']:
            scan_model.add_airwatch_credential(scan_data['credentials'])
        if scan_data['audits']:
            scan_model.add_audit_file(API.Audits.Type.Feed, scan_data['audits'])

    elif template_name == Nessus.Scan.TemplateNames.OFFLINE:
        # Supported : Cisco IOS(Upload Custom Cisco IOS audit file)
        audit_file = api_handler.file.upload(file=get_file_path(CISCO_IOS_SCAN_AUDIT_FILE))
        config_file = api_handler.file.upload(file=get_file_path(CISCO_IOS_SCAN_CONFIG_FILE))

        OFFLINE_AUDITS['custom']['add'][0]['file'] = audit_file

        scan_data['settings']['cisco_offline_configs'] = config_file

        if scan_data['audits']:
            scan_model.add_audit_file(API.Audits.Type.Custom, scan_data['audits'])

    elif template_name == Nessus.Scan.TemplateNames.SCAP:
        scap_file = api_handler.file.upload(file=get_file_path(WINDOWS_SCAP_SCAN_FILE))
        SCAP['add']['Windows'][0]['file'] = scap_file

        if scan_data['credentials']:
            scan_model.add_windows_credential(scan_data['credentials'])

        if scan_data['scap']:
            scan_model.add_scap_credential(scan_data['scap'])

    elif template_name == Nessus.Scan.TemplateNames.AGENT_BASIC or \
            template_name == Nessus.Scan.TemplateNames.AGENT_ADVANCE or \
            template_name == Nessus.Scan.TemplateNames.AGENT_MALWARE or \
            template_name == Nessus.Scan.TemplateNames.AGENT_SCAP or \
            template_name == Nessus.Scan.TemplateNames.AGENT_COMPLIANCE:
        if template_name == Nessus.Scan.TemplateNames.AGENT_SCAP:
            scap_file = api_handler.file.upload(file=get_file_path(WINDOWS_SCAP_SCAN_FILE))
            SCAP['add']['Windows'][0]['file'] = scap_file
            if scan_data['scap']:
                scan_model.add_scap_credential(scan_data['scap'])

        if 'agent_group_id' in scan_data['settings'].keys():
            scanner_id = 1
            agent_name = random_name('agent_group-')
            agent_group = api_handler.agent_groups.create(scanner_id, agent_name)
            agent_group.update({'name': agent_name})
            agents = api_handler.agents.get_agents(scanner_id)

            if agents['agents'] is None:
                assert 'agents not available'
            else:
                agent_status_check = kwargs.get('agent_status_check', True)

                for agent in agents['agents']:
                    if agent.get('status') in (STRING_ON, Nessus.Agents.AgentStatus.ONLINE) or not agent_status_check:
                        if kwargs:
                            if kwargs['agent_name'] == agent.get('name'):
                                api_handler.agent_groups.add_agent(scanner_id, agent_group['id'], agent['id'])
                                break
                        else:
                            api_handler.agent_groups.add_agent(scanner_id, agent_group['id'], agent['id'])
                            break
                    else:
                        assert "Real Agent not found in List of Agents"

            if staggered_start_mins:
                scan_data['staggered_start_mins'] = str(staggered_start_mins)
                setattr(scan_model, 'staggered_start_mins', scan_data['staggered_start_mins'])

            scan_data['agent_group_id'] = [agent_group['id']]
            setattr(scan_model, 'agent_group_id', scan_data['agent_group_id'])
            setattr(scan_model, 'scanner_id', scanner_id)

    if template_name == Nessus.Scan.TemplateNames.ASD:
        setattr(scan_model, 'domain_discovery_domains', scan_data['settings']['domain_discovery_domains'])
        setattr(scan_model, 'launch_now', scan_data['settings']['launch_now'])
        setattr(scan_model, 'enabled', scan_data['settings']['enabled'])
        setattr(scan_model, 'name', scan_data['settings']['name'])
        setattr(scan_model, 'description', scan_data['settings']['description'])
        setattr(scan_model, 'folder_id', scan_data['settings']['folder_id'])

    if template_name == Nessus.Scan.TemplateNames.ADVANCED or \
            template_name == Nessus.Scan.TemplateNames.BASIC:
        if scan_data['settings']['text_targets'] != Nessus.Scan.Target.LOCALHOST:
            setattr(scan_model, 'text_targets', scan_data['settings']['text_targets'])
        if scan_data['settings']['enable_plugin_debugging'] == 'yes':
            setattr(scan_model, 'enable_plugin_debugging', scan_data['settings']['enable_plugin_debugging'])
        setattr(scan_model, 'log_whole_attack', scan_data['settings']['log_whole_attack'])
        if scan_data['settings']['network_capture_enabled'] == 'yes':
            setattr(scan_model, 'network_capture_enabled', scan_data['settings']['network_capture_enabled'])
            if scan_data['settings'].get('network_capture_hosts') is None:
                setattr(scan_model, 'network_capture_hosts', scan_data['settings']['text_targets'])
            else:
                setattr(scan_model, 'network_capture_hosts', scan_data['settings']['network_capture_hosts'])
            setattr(scan_model, 'network_capture_ports', '1-65535')

    if kwargs.get('add_ssh_credential'):
        if scan_data['credentials']['add']['Host']['SSH']:
            scan_model.add_ssh_credential(scan_data['credentials']['add']['Host']['SSH'][0])
        if scan_data['credentials']['add']['Host']['Windows']:
            scan_model.add_windows_credential(scan_data['credentials']['add']['Host']['Windows'][0])

    response_data = api_handler.scans.create(scan_model)

    if 'agent_group_id' in scan_data['settings'].keys():
        response_data['scan']['agent_group_id'] = scan_data['agent_group_id']

    return response_data, scan_model


def create_scan_with_fake_agent(api_handler: NessusAPI, file_name: str, template_title: str) -> tuple:
    """
    :param NessusAPI api_handler:  API object to scanner
    :param str file_name:  path to file data
    :param str template_title: template title
    :return: return scan details and agent group details
    :rtype: tuple
    """
    template_name = None
    log.debug('Create a Scan with fake Agent')

    template_list = api_handler.scans.get_templates()

    # based on template title will get uuid for it
    template_uuid = get_template_uuid_by_name(template_list, template_title)

    scan_model = ScanModel.create_model()
    scan_data = load_testdata(file_name)

    if 'uuid' in scan_data.keys():
        setattr(scan_model, 'uuid', template_uuid)

    for key, value in scan_data['settings'].items():
        if key == "folder_id":
            value = "3"

        setattr(scan_model, key, value)

    if scan_data['uuid']:
        template_name = get_template_name(template_list, template_uuid)

    if template_name in (getattr(Nessus.Scan.TemplateNames, attr) for attr in
                         ('AGENT_BASIC', 'AGENT_ADVANCE', 'AGENT_MALWARE', 'AGENT_SCAP', 'AGENT_COMPLIANCE')):
        if template_name == Nessus.Scan.TemplateNames.AGENT_SCAP:
            scap_file = api_handler.file.upload(file=get_file_path(WINDOWS_SCAP_SCAN_FILE))
            SCAP['add']['Windows'][0]['file'] = scap_file
            if scan_data['scap']:
                scan_model.add_scap_credential(scan_data['scap'])

        if 'agent_group_id' in scan_data['settings'].keys():
            scanner_id = 1
            agent_name = random_name('agent_group-')
            agent_group = api_handler.agent_groups.create(scanner_id, agent_name)
            agent_group.update({'name': agent_name})
            agents = api_handler.agents.get_agents(scanner_id)

            if agents['agents'] is None:
                assert 'agents not available'
            else:
                for agent in agents['agents']:
                    api_handler.agent_groups.add_agent(scanner_id, agent_group['id'], agent['id'])

            scan_data['agent_group_id'] = [agent_group['id']]
            setattr(scan_model, 'agent_group_id', scan_data['agent_group_id'])
            setattr(scan_model, 'scanner_id', scanner_id)

    return api_handler.scans.create(scan_model), agent_group


def launch_scan_and_wait_for_completion(api_object: NessusAPI, scan_id: int, timeout_seconds: int = TIME_TEN_MINUTES):
    """
    Launch a scan by scan_id and wait for it to complete
    :param NessusAPI api_object: existing Nessus API object of current session
    :param int scan_id: id of the scan
    :param int timeout_seconds: amount of time to wait before timing out
    :return Dict
    """
    # Launch scan and wait for completion by checking the status of scan detailss
    api_object.scans.launch(scan_id)
    wait(lambda: api_object.scans.details(
        scan_id)['info']['status'] in [API.Scan.Status.COMPLETED],
         sleep_seconds=WAIT_NORMAL, waiting_for=Scanner.Strings.SCAN_TO_START,
         timeout_seconds=timeout_seconds)

    details = api_object.scans.details(scan_id=scan_id)
    return details


def delete_scan_by_scan_id(api_object: NessusAPI, scan_id: int = None):
    if scan_id:
        api_object.scans.delete(scan_id=scan_id)


def delete_scan_by_scan_name(api_object: NessusAPI, scan_name: str = None):
    if scan_name:
        scan_id = get_scan_id(api_object=api_object, scan_name=scan_name)
        delete_scan_by_scan_id(api_object=api_object, scan_id=scan_id)


def wait_for_scan_id(api_object: NessusAPI, scan_name: str) -> int:
    """
    Return scan id for the provided scan_name within a given time
    :param NessusAPI api_object: existing Nessus API object of current session
    :param str scan_name: name of the scan
    :return scan_id of the respective scan
    :rtype int
    """

    wait(lambda: get_scan_id(api_object=api_object, scan_name=scan_name) is not None,
         waiting_for=f"Scan Id to be found by name '{scan_name}'",
         sleep_seconds=WAIT_NORMAL, timeout_seconds=TIME_THIRTY_SECONDS)

    scan_id = get_scan_id(api_object=api_object, scan_name=scan_name)
    return scan_id


def get_scan_id(api_object: NessusAPI, scan_name: str) -> int:
    """
    Return scan id for the provided scan_name
    :param NessusAPI api_object: existing Nessus API object of current session
    :param str scan_name: name of the scan
    :return scan_id of the respective scan
    :rtype int
    """
    scan_list = api_object.scans.get_scans()['scans']

    for scan in scan_list[::-1]:
        if scan_name == scan['name']:
            return scan['id']
    else:
        log.debug("%s not found in current scan_list.", scan_name)


def save_and_configure_scan(class_object: NessusBasePage, scan_name: str, **kwargs) -> None:
    """
    method to save scan and click on configure scan again
    :param NessusBasePage class_object: object of class
    :param str scan_name: scan name
    :return:None
    """
    tab_to_navigate = kwargs.get('tab_to_navigate', Nessus.Scan.ScanFeatureTabs.CREDENTIALS)

    scans_page = ScansPage()
    class_object.js_scroll_into_view(scans_page.save_button)
    scans_page.save_button.click()
    LoadingCircle(WAIT_NORMAL)

    ScanList().click_on_scan(scan_name=scan_name)
    LoadingCircle(WAIT_SHORT)

    scan_view_page = ScanViewPage()
    class_object.js_scroll_into_view(scan_view_page.configure_button)
    scan_view_page.configure_button.click()

    if tab_to_navigate == Nessus.Scan.ScanFeatureTabs.CREDENTIALS:
        class_object.credentials_tab.click()
    elif tab_to_navigate == Nessus.Scan.ScanFeatureTabs.COMPLIANCE:
        scans_page.compliance.click()
    elif tab_to_navigate == Nessus.Scan.ScanFeatureTabs.PLUGINS:
        scans_page.plugin.click()
    LoadingCircle(WAIT_SHORT)


def download_exported_diff_history(scan_api, scan_id: int, exported_scan_hist,
                                   export_format: str = API.Scan.ExportFormats.FORMAT_DB,
                                   password: str = None,
                                   nessus_db_directory: str = None,
                                   filename: str = None) -> bool:
    """
    Utility method for downloading scan history results in the given format.

    :param NessusAPI scan_api:       Api object to scanner.
    :param scan_id:                  scan_id of the scan to download
    :param str exported_scan_hist:   Scan History diff.
    :param str export_format:        Export format.
        Supported Options: nessus, html, pdf, csv or db
    :param str password:             Password if downloading a Nessus DB.
    :param str nessus_db_directory:  Directory where the Nessus DB file should be saved.
    :param str filename:             A filename for the exported file
    :return: True if file downloaded
    :rtype: bool
    """
    # Configure dynamic values outside of function defaults so it's always set at runtime.
    password = NessusConfig.CAT_NESSUS_DB_PASSWORD if password is None else password
    nessus_db_directory = NessusConfig.CAT_NESSUS_DB_DIRECTORY if nessus_db_directory is None else nessus_db_directory
    filename = NessusConfig.CAT_NESSUS_DB_DIRECTORY if filename is None else filename

    if export_format not in API.Scan.ExportFormats.VALID_FORMATS:
        raise CatiumAPIObjectError('Invalid Scan export format supplied: {0}.'.format(export_format))

    if scan_api.http_status_code == HTTPStatus.OK:
        wait_for_export_to_complete(api=scan_api, scan_id=scan_id, file_id=exported_scan_hist[0])
        scan_db = scan_api.scans.download(scan_id=scan_id, file_id=exported_scan_hist[0])

        if filename:
            file_name = os.path.join(nessus_db_directory, filename)
        else:
            file_name = os.path.join(nessus_db_directory, "{0}_{1}".format(str(scan_id), Scanner.NESSUS_DB_TIMESTAMP))
        log.info("[download_scan]: Saving to %s", file_name)
        try:
            with open(file_name + ".db", "wb") as file:
                for block in scan_db.iter_content(1024):
                    file.write(block)
                file.close()
            log.info("[download_scan]: Scan results saved as %s.db", file_name)
            return True
        except FileNotFoundError:
            log.info("[download_scan]: Unable to write to %s.", nessus_db_directory)
            return False


def scan_save_launch_and_status_verification(scan_name: str, scan_status: str = API.Scan.Status.COMPLETED,
                                             navigate_to_scan_folder: bool = True, scan_folder_name: str = None,
                                             is_scan_scheduled: bool = False) -> bool:
    """
    Save scan and Check success notification for saving scan
    Navigate to specified scan folder to verify scan listed over there
    Launch the scan and verify it's successful completion status
    :param str scan_name: scan to launch
    :param bool navigate_to_scan_folder: true if you want to navigate to custom scan folder
    :param str scan_folder_name: folder where scan listed
    :param str scan_status: status to verify against the scan
    :param bool is_scan_scheduled: if true then scan will launch automatically at scheduled time
    :return: True if specified scan visible to be in required status
    :rtype: bool
    """
    # Save the scan and verify success notifications
    NewScanForm().save_button.click()

    assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
        "Success notifications for saving scan is mismatched or missing."

    # Navigate to scan folder
    scan_page = ScansPage()
    scan_page.refresh()

    if navigate_to_scan_folder:
        SideNav().get_sidenav_element(element_name=scan_folder_name).click()

    # Verify scan is listed there
    webium_wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scans gets loaded")
    scans_list = ScanList()

    assert scan_name in scans_list.get_all_scans(), 'Scan not listed in specified scan folder.'

    # Launch scan and return its completion status
    return scans_list.launch_scan_and_wait_for_status(
        scan_name=scan_name, status=scan_status, is_scheduled_scan=is_scan_scheduled)


def delete_created_scan(scan_name: str) -> None:
    """
    For cleanup - Delete the created scan permanently
    :param str scan_name: scan to delete
    :return: None
    """
    scan_list = ScanList()

    # Delete scan from scan folder
    scan_list.delete_scan(scan_name=scan_name)

    assert scan_name not in scan_list.get_all_scans(), "Scan '{}' not deleted successfully from scan folder.".format(
        scan_name)

    # Delete scan from Trash folder
    ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

    assert scan_name not in scan_list.get_all_scans(), "Scan '{}' not deleted successfully from Trash folder.".format(
        scan_name)


def restart_server() -> None:
    """
    Restart server and wait for login page

    :return: None
    """
    stop_nessus()
    start_nessus()
    wait_for_scanner_to_be_ready(api=NessusAPI())

    get_driver_no_init().refresh()
    webium_wait(lambda: visibility_of_element_located(LoginPage().username_field), waiting_for='login page')
    LoginPage().login_with_defaults()
    webium_wait(lambda: visibility_of_element_located(HeaderBasePage().scan_link), waiting_for='Scan page to load')


def tamper_with_data_and_restart_server(file_path: str, data: str) -> None:
    """
    Tamper file by adding data and restart server

    :param str file_path: file path
    :param str data: text to be adding
    :return: None
    """
    with SSH() as ssh:
        ssh.write_to_file(remote_file_path=file_path, text=data)

    restart_server()


def update_plugins_and_restart_server() -> None:
    """
    Update plugins and restart server

    :return: None
    """
    prepare_full_plugin_update()

    with SSH() as ssh:
        ssh.execute(command='{} update --plugins-only'.format(get_nessus_cli()))

    restart_server()


def delete_template_file(file: str) -> None:
    """
    Delete credentials.json and restrictions.json file from '/opt/nessus/var/nessus/templates/'

    :param str file: file name
    :return: None
    """
    with SSH() as ssh:
        ssh.execute(command='rm -rf {}/templates/{}'.format(get_nessus_var_dir(), file))


def prepare_full_plugin_update() -> None:
    """
    Delete metadata.json from '/opt/nessus/var/nessus/templates/' and MD5, plugin_feed_info.inc plugins from 
    '/opt/nessus/lib/nessus/plugins/'

    :return: None 
    """
    with SSH() as ssh:
        ssh.execute(command='rm -rf /opt/nessus/var/nessus/templates/metadata.json '
                            '/opt/nessus/lib/nessus/plugins/MD5 '
                            '/opt/nessus/lib/nessus/plugins/plugin_feed_info.inc')


def send_plugin_file_and_update(absolute_path: str, remote_file_path: str) -> bool:
    """
    Send the plugin file through SFTP and then update the plugin.

    :param str absolute_path: path on which the plugin file is to be downloaded
    :param str remote_file_path: path on which the plugin file is to be send/transfer to host
    :return: True if plugin updated successfully or else False
    :rtype: bool
    """
    os_name = get_os_name()

    with SSH() as ssh:
        if os_name == OperatingSystems.WINDOWS:
            remote_path = "C:/{}".format(remote_file_path)
        elif os_name == OperatingSystems.LINUX:
            remote_path = "/root/{}".format(remote_file_path)
        else:
            raise Exception("The support for {} is not present".format(os_name))

        ssh.send_file(os.path.abspath(absolute_path), remote_file_path=remote_path)
        stop_nessus()
        output = ssh.execute(command='{} update {}'.format(get_nessus_cli(), remote_path))
        if any([Messages.NessusCli.PLUGIN_UPDATE_SUCCESSFUL in op for op in output]):
            start_stop_nessus_wait_for_ready(nessus_api=NessusAPI(), status=API.Status.READY)
            sleep(TIME_TWO_MINUTES, reason='waiting for UI to be ready.')
            return True
        return False


def launch_scan_and_get_particular_vulnerability(scan_name: str, vulnerability_name: str) -> list:
    """
    Launch a scan, after it gets completed return the matched vulnerability

    :param str scan_name: scan name in which vulnerability is to be found
    :param str vulnerability_name: name of the vulnerability to be searched
    :return: list of found vulnerability in vulnerability-list or empty
    :rtype: list
    """
    scan_list = ScanList()
    scan_list.loaded()

    scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)
    sleep(TIME_FIFTEEN_SECONDS, reason="Waiting for Nessus UI to be ready!!")

    webium_wait(lambda: invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()),
                waiting_for='Modal is closed', timeout_seconds=TIME_TWO_MINUTES)
    scan_list.click_on_scan(scan_name=scan_name)

    scan_view_page = ScanViewPage()
    webium_wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                waiting_for='Scan results page to load')
    scan_view_page.vulnerability_tab.click()

    return [vulnerability.text for vulnerability in VulnerabilityList().results
            if vulnerability_name in vulnerability.text]


def start_stop_nessus_wait_for_ready(nessus_api: NessusAPI, status: str) -> None:
    """
    This function will wait for plugins to download and compile after activation
    :param NessusAPI nessus_api: existing Nessus API object of current session
    :param str status: status of Nessus for which wait_for_scanner_status must wait
    :return: None
    """
    if not nessus_api:
        nessus_api = NessusAPI()

    stop_nessus()
    start_nessus()

    wait_for_scanner_status(api=nessus_api, status=status, timeout=TIME_THIRTY_MINUTES,
                            msg='Wait for Nessus to be {}'.format(status), sleep_interval=TIME_THIRTY_SECONDS)


def get_severity_count_from_scan_result(scan_vuln_result: list) -> dict:
    """
    Returns count of severity from vulnerability list

    :param list scan_vuln_result: list vulnerabilities from scan results
    :return: severity count details
    :rtype: dict
    """
    scan_results = {}
    severity_values = {Nessus.Scan.Severity.LOW: 1, Nessus.Scan.Severity.MEDIUM: 2, Nessus.Scan.Severity.HIGH: 3,
                       Nessus.Scan.Severity.CRITICAL: 4}

    for key in severity_values.keys():
        count = 0
        for vuln in scan_vuln_result:
            if vuln['severity'] == severity_values[key]:
                count = count + 1
        scan_results[key] = count

    return scan_results


def get_severity_count_from_scan_result_by_occurrences(scan_vuln_result: list) -> dict:
    """
    Returns total count of severity including the occurrences from vulnerability list

    :param list scan_vuln_result: list vulnerabilities from scan results
    :return: severity count details
    :rtype: dict
    """
    scan_results = {}
    severity_values = {Nessus.Scan.Severity.LOW: 1, Nessus.Scan.Severity.MEDIUM: 2, Nessus.Scan.Severity.HIGH: 3,
                       Nessus.Scan.Severity.CRITICAL: 4}

    for key in severity_values.keys():
        count = sum(vuln['count'] for vuln in scan_vuln_result if vuln['severity'] == severity_values[key])
        scan_results[key] = count

    return scan_results


def create_scan_with_custom_policy(api_handler: NessusAPI, file_name: str, policy_id: str, is_agent_scan: bool = False,
                                   change_scan_name: bool = False, **kwargs):
    """
    Helper for creating scan with custom/user-defined policy
    :param api_handler:  API object to scanner
    :param kwargs: kwargs to provide additional arguments
    :param file_name:  path to file data
    :param policy_id: custom policy ID
    :param is_agent_scan: true if the scan is agent_scan or else false
    :param change_scan_name: boolean to add random characters in scan name or not to avoid same name scans
    :return:
    """
    log.debug('fixture init: create_scan_with_custom_policy: Create a Scan with policy')

    scan_model = ScanModel.create_model()
    scan_data = load_testdata(file_name)

    for key in scan_data['settings'].keys():
        value = scan_data['settings'][key]
        try:
            setattr(scan_model, key, value)
        except:
            log.warning("Scan Model does not contain attribute.")
    if change_scan_name:
        setattr(scan_model, 'name', random_name(prefix=scan_data['settings']['name'] + '-'))

    # agent_group_id setting will trigger auto-creation of an agent group and assignment of agents to it
    if is_agent_scan and 'agent_group_id' in scan_data['settings'].keys():
        scanner_id = 1
        agent_name = random_name('agent_group-')
        agent_group = api_handler.agent_groups.create(scanner_id, agent_name)
        agent_group.update({'name': agent_name})
        agents = api_handler.agents.get_agents(scanner_id)

        if agents['agents'] is None:
            assert False, 'agents not available'
        else:
            for agent in agents['agents']:
                if kwargs and kwargs['agent_name'] == agent.get('name'):
                    api_handler.agent_groups.add_agent(scanner_id, agent_group['id'], agent['id'])
                    break
            else:
                assert False, "The agent named %s was not found" % kwargs['agent_name']

        scan_data['agent_group_id'] = [agent_group['id']]
        setattr(scan_model, 'agent_group_id', scan_data['agent_group_id'])
        setattr(scan_model, 'scanner_id', scanner_id)

    scan_data['policy_id'] = policy_id
    setattr(scan_model, 'policy_id', scan_data['policy_id'])
    setattr(scan_model, 'uuid', scan_data['uuid'])

    return api_handler.scans.create(scan_model), scan_model


def download_and_save_exported_scan_file(file_path: str, api: NessusAPI, file_format: str, scan_id: int,
                                         file_id: int) -> None:
    """
    This function download and saves the exported scan file in given format
    :param str file_path: File path where the file needs to be downloaded
    :param NessusAPI api: Instance of NessusAPI
    :param str file_format: Format of file
    :param int scan_id: Scan ID
    :param int file_id: Scan export id
    :return: None
    """
    download = api.scans.download(scan_id, file_id)

    # Verify that exported scan downloaded
    assert download, "Exported file was not downloaded."

    with open(file_path + file_format, "wb") as file:
        for block in download.iter_content(1024):
            file.write(block)
        file.close()


def get_scan_results_export_options(format_type: str) -> list:
    """
    Returns list of vulnerability details options from different report formats

    :param str format_type: scan report format e.g HTML/PDF/CSV
    :return: vulnerability details options
    :rtype: list
    """
    scan_view_page = ScanViewPage()
    scan_export_page = ScanExportPage()

    if format_type == API.Scan.UIExportFormats.FORMAT_CSV:
        scan_view_page.get_element_for_report_format_radio_button(report_format=format_type).click()
        webium_wait(lambda: scan_export_page.is_element_present("clear_link"),
                    waiting_for="Selected report options get displayed")

        options_name = scan_export_page.get_text_from_custom_option_check_box(element=scan_export_page.
                                                                              export_csv_options)
    else:
        scan_view_page.select_report_scan_type_as_custom(format_type=format_type)
        options_name = scan_export_page.get_text_from_custom_option_check_box(element=scan_export_page.
                                                                              vulnerabilities_details_options)

    return options_name


def get_plugin_id_of_highest_cvss_v3_score(nessus_api: NessusAPI, plugin_ids: list, host_id: int, scan_id: int) -> int:
    """
    Returns plugin id that has highest CVSS v3 base score from given plugin ids list

    :param NessusAPI nessus_api: Nessus API object
    :param list plugin_ids: list of plugin ids
    :param int host_id: ID of the host to retrieve
    :param int scan_id: Scan ID
    :return: plugin id that has highest CVSS v3 base score
    :rtype: int
    """
    plugin_id_with_base_score = []
    plugin_details = nessus_api.scans.get_host_vulnerability(host_id=host_id, plugin_id=plugin_ids[0], scan_id=scan_id)
    max_base_score = plugin_details['info']['plugindescription']['pluginattributes']['risk_information'][
        'cvss3_base_score']

    for plugin_id in plugin_ids:
        vuln_details = nessus_api.scans.get_host_vulnerability(host_id=host_id, plugin_id=plugin_id, scan_id=scan_id)
        plugin_risk_info = vuln_details['info']['plugindescription']['pluginattributes']['risk_information']

        if 'cvss3_base_score' in plugin_risk_info:
            base_score = plugin_risk_info['cvss3_base_score']

            if base_score >= max_base_score:
                max_base_score = base_score
                plugin_id_with_base_score.append({plugin_id: base_score})

    max_severity_base = max([list(plugin_id.values())[0] for plugin_id in plugin_id_with_base_score])

    return min([list(plugin_id.keys())[0] for plugin_id in plugin_id_with_base_score if plugin_id[list(
        plugin_id.keys())[0]] == max_severity_base])


def get_plugin_id_of_highest_cvss_v4_score(nessus_api: NessusAPI, plugin_ids: list, host_id: int, scan_id: int) -> int:
    """
    Returns plugin id that has highest CVSS v4 base score from given plugin ids list

    :param NessusAPI nessus_api: Nessus API object
    :param list plugin_ids: list of plugin ids
    :param int host_id: ID of the host to retrieve
    :param int scan_id: Scan ID
    :return: plugin id that has highest CVSS v4 base score
    :rtype: int
    """
    plugin_id_with_base_score = []
    plugin_details = nessus_api.scans.get_host_vulnerability(host_id=host_id, plugin_id=plugin_ids[0], scan_id=scan_id)
    max_base_score = plugin_details['info']['plugindescription']['pluginattributes']['risk_information'][
        'cvss4_base_score']

    for plugin_id in plugin_ids:
        vuln_details = nessus_api.scans.get_host_vulnerability(host_id=host_id, plugin_id=plugin_id, scan_id=scan_id)
        plugin_risk_info = vuln_details['info']['plugindescription']['pluginattributes']['risk_information']

        if 'cvss4_base_score' in plugin_risk_info:
            base_score = plugin_risk_info['cvss4_base_score']

            if base_score >= max_base_score:
                max_base_score = base_score
                plugin_id_with_base_score.append({plugin_id: base_score})

    max_severity_base = max([list(plugin_id.values())[0] for plugin_id in plugin_id_with_base_score])

    return min([list(plugin_id.keys())[0] for plugin_id in plugin_id_with_base_score if plugin_id[list(
        plugin_id.keys())[0]] == max_severity_base])


def empty_trash_folder() -> None:
    """
    Delete all scans from trash folder

    :return: None
    """
    SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()

    trash_page = ScansTrashPage()
    wait(lambda: trash_page.is_element_present("empty_trash_message") or trash_page.is_element_present(
        "empty_trash_button"), waiting_for="scan trash page gets loaded")
    trash_page.js_scroll_into_view(trash_page.empty_trash_button)

    if trash_page.is_element_present('empty_trash_button'):
        trash_page.empty_trash_button.click()
        delete_popup = ActionCloseModal()
        delete_popup.action_button.click()
        delete_popup.wait_for_modal_closed(timeout_seconds=TIME_FIVE_MINUTES)

    HeaderBasePage().scan_link.click()


def go_to_scan(scan_name: str) -> ScanViewPage:
    scan_list = ScanList()
    scan_list.refresh()
    scan_list.loaded()
    wait(lambda: visibility_of_element_located(scan_list.object_table),
         waiting_for='Scan lists to load')

    scan_list.click_on_scan(scan_name=scan_name)
    scan_view_page = ScanViewPage()
    scan_view_page.loaded()

    return scan_view_page


def click_on_scan_and_go_to_vulnerabilities_tab(scan_name: str) -> None:
    """ This function will click on given scan and go to vulnerabilities tab """
    scan_view_page = go_to_scan(scan_name=scan_name)

    webium_wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                waiting_for='Vulnerabilities to get loads')

    scan_view_page.vulnerability_tab.click()
    vulnerability_list = VulnerabilityList()
    vulnerability_list.loaded()


def click_on_scan_and_go_to_hosts_tab(scan_name: str) -> ScansHostList:
    """ This function will click on given scan and go to hosts/records tab """
    scan_view_page = go_to_scan(scan_name=scan_name)

    webium_wait(lambda: visibility_of_element_located(scan_view_page.host_tab),
                waiting_for='Record/Hosts Tab to appear')

    scan_view_page.records_tab.click()
    hosts_list = ScansHostList()
    hosts_list.loaded()
    return hosts_list


def get_scan_report_template_id(api: NessusAPI, template_name: str) -> int:
    """
    Return template id for given report template name
    :param NessusAPI api: Instance of NessusAPI object.
    :param str template_name: Name of report template
    :return : Id of the report template
    :rtype : int
    """
    return [template['id'] for template in api.reports.get_report_templates() if template['name'] == template_name][0]


def revert_save_as_default_option_to_system(scan_name: str, export_format: str) -> None:
    """
    Revert back the save as default options from custom to system options

    :param str scan_name: scan name
    :param str export_format: format type in which file to be exported
    :return: None
    """
    if '/scans/reports' not in get_driver_no_init().current_url:
        HeaderBasePage().scan_link.click()
        scan_list = ScanList()
        scan_list.loaded()
        scan_list.click_on_scan(scan_name=scan_name)

    scan_view_page = ScanViewPage()
    webium_wait(lambda: scan_view_page.is_element_present("report_button"), waiting_for="Report button get displayed")

    scan_view_page.report_button.click()
    export_modal = ActionCloseModal()
    webium_wait(lambda: export_modal.modal, waiting_for='Export modal to open')

    scan_view_page.get_element_for_report_format_radio_button(report_format=export_format).click()
    scan_export_page = ScanExportPage()
    webium_wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
        "hide_system_template_checkbox"), waiting_for="Selected report options get displayed")

    if export_format == API.Scan.UIExportFormats.FORMAT_CSV:
        scan_export_page.system_link.click()
    else:
        scan_export_page.hide_system_template_checkbox.uncheck()

    scan_export_page.save_as_default.check()
    scan_export_page.generate_report_button.click()
    export_modal.wait_for_modal_closed()


def create_packet_capture_scan_helper(nessus_api: NessusAPI, scan_file: str, scan_template: str,
                                      scan_target: str, target_to_capture: str = None) -> tuple:
    """
    Create scan from given scan file path, template and scan target with packet capture setting enabled

    :param str nessus_api: NessusAPI object
    :param str scan_file: json file path of scan info
    :param str scan_template: scan template to be created
    :param str scan_target: scan target to be performed
    :param str target_to_capture: scan target to be captured
    :return: create scan name and id
    :rtype: tuple
    """
    capture_host = target_to_capture if target_to_capture else scan_target

    payload = load_testdata(scan_file)
    pcap_scan_details_dict = {"network_capture_enabled": "yes", "network_capture_ports": "1-65535",
                              "network_capture_hosts": capture_host, "text_targets": scan_target,
                              "name": random_name(prefix='Automated-Scan-')}

    payload.get('settings').update(pcap_scan_details_dict)
    scan_details = create_scan_helper(nessus_api, file_name=None, template_title=scan_template, payload=payload)

    return scan_details[0]['scan']['id'], scan_details[0]['scan']['name']


def get_scan_uuid(api_object: NessusAPI, scan_name: str) -> str:
    """
    Return uuid for given scan name

    :param NessusAPI api_object: existing Nessus API object of current session
    :param str scan_name: name of the scan
    :return uuid of the respective scan
    :rtype str
    """
    scan_list = api_object.scans.get_scans()['scans']

    if scan_list:
        return [scan['uuid'] for scan in scan_list if scan_name == scan['name']][0]
    else:
        log.debug("%s not found in current scan list.", scan_name)


def delete_all_pcap_files_from_debug_logs_table() -> None:
    """
    Deletes all available pcap files from "Debug Logs" table

    :return: None
    """
    debug_logs_page = DebugLogsPage()

    if not get_driver_no_init().current_url.endswith("/settings/logs"):
        debug_logs_page.open()
        webium_wait(lambda: debug_logs_page.is_element_present("search_logs_field") or debug_logs_page.
                    is_element_present("empty_debug_logs"), waiting_for="'Debug Logs' table gets displayed properly")

    if debug_logs_page.is_element_present("search_logs_field"):
        debug_logs_page.select_all_checkbox.check()
        debug_logs_page.delete_button.click()
        delete_log_modal = ActionCloseModal()
        webium_wait(lambda: delete_log_modal.is_element_present("modal"),
                    waiting_for="'Delete Log' modal gets displayed")

        delete_log_modal.action_button.click()
        delete_log_modal.wait_for_modal_closed()
    else:
        log.debug("Debug logs files has either deleted already or not available.")


def launch_scan_and_go_to_debugging_log_report_vuln(nessus_api: NessusAPI(), scan_details: tuple) -> None:
    """
    Launch given scan and go to "Debugging Log Report" vulnerability details page

    :param NessusAPI nessus_api: existing Nessus API object of current session
    :param tuple scan_details: scan details
    :return: None
    """
    scan_id = scan_details[0]
    nessus_api.scans.launch(scan_id=scan_id)

    with polling_ui():
        wait_scan_state(api=nessus_api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)

    scan_page = ScansPage()
    scan_page.refresh()
    wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")
    ScanList().click_on_scan(scan_name=scan_details[1])

    close_pendo_guide_container_banner_for_nessus_pro()
    scan_view_page = ScanViewPage()
    wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
         waiting_for='Vulnerabilities to load')
    scan_view_page.vulnerability_tab.click()

    vuln_name = Nessus.Scan.Vulnerability.DEBUGGING_LOG_REPORT
    scan_view_page.search_box.value = vuln_name
    sleep(WAIT_NORMAL, reason="waiting for matching vulnerability results")

    VulnerabilityList().click_on_vulnerability(vulnerability_name=vuln_name)
    wait(lambda: VulnerabilityDescription().is_element_present("plugin_header"),
         waiting_for="vulnerability details get displayed")


def expected_generated_pcap_file_name(api: NessusAPI, scan_name: str) -> str:
    """
    Returns expected generated pcap file name

    :param NessusAPI api: Nessus API instance
    :param str scan_name: scan name
    :return: generated pcap file name
    :rtype: str
    """
    scan_uuid = get_scan_uuid(api_object=api, scan_name=scan_name)

    return "_".join(["pcap", scan_name, "{}.tgz".format(scan_uuid)])


def import_scan_helper(api_handler: NessusAPI, scan_file_name: str, scan_file_path: str, encrypted: bool = True,
                       folder_id: str = None, password: str = None):
    """
    Imports given file into Nessus via API

    :param NessusAPI api_handler: Nessus API instance
    :param str scan_file_name: file name to be import
    :param str scan_file_path: file path where file is placed
    :param bool encrypted: True if file is encrypted else False
    :param str folder_id: Folder Id where file to be import
    :param str password: file password for Nessus DB format file
    :return: imported file name and folder id
    """
    file_uploaded = api_handler.file.upload(file=get_file_path(scan_file_path + scan_file_name), encrypted=encrypted)

    response = api_handler.scans.import_scan(file_uploaded, folder_id=folder_id, password=password)

    return (response['scan']['name'], folder_id) if folder_id else response['scan']['name']


def create_scan_with_custom_plugin_set(api_handler: NessusAPI, file_name: str, template_title: str,
                                       change_scan_name: bool = False, staggered_start_mins: int = 0, **kwargs):
    """
    :param api_handler:  API object to scanner
    :param kwargs: kwargs to provide additional arguments
    :param file_name:  path to file data
    :param template_title: template title
    :param change_scan_name: boolean to add random characters in scan name or not to avoid same name scans
    :param staggered_start_mins: to add staggered_start_mins in scan to have some delay in launching the scan
    :return:
    """
    template_name = None
    log.debug('fixture init: create_scan: Create a Scan')
    # test_data_file is tuple, it's 1st element is .json file path
    # which contain payload
    # file_name = test_data_file[0]

    # test_data_file's 2nd element is template name which will be used to get uuid of the
    # template based on the name
    # template_title = test_data_file[1]

    template_list = api_handler.scans.get_templates()

    # based on template title will get uuid for it
    template_uuid = get_template_uuid_by_name(template_list, template_title)
    scan_model = ScanModel.create_model()

    if file_name:
        scan_data = load_testdata(file_name)
    else:
        scan_data = kwargs.get("payload")

    if 'uuid' in scan_data.keys():
        setattr(scan_model, 'uuid', template_uuid)

    for key, value in scan_data['settings'].items():
        try:
            if key == "folder_id":
                value = "3"

            setattr(scan_model, key, value)
        except:
            log.warning("Scan Model does not contain attribute.")

    if change_scan_name:
        setattr(scan_model, 'name', random_name(prefix=scan_data['settings']['name'] + '-'))

    if scan_data['uuid']:
        template_name = get_template_name(template_list, template_uuid)

    if 'plugins' in scan_data.keys():
        plugins = scan_data['plugins']
        response = api_handler.plugins.families()
        plugin_list = []
        for plugin in plugins.keys():
            if plugins[plugin] == 'enabled':
                existing_family = next((family for family in response['families'] if family['name'] == plugin), None)
                family_details = api_handler.plugins.family_details(existing_family['id'])
                for family_plugin in family_details['plugins']:
                    plugin_list.append(family_plugin['id'])
        setattr(scan_model, 'plugins', plugin_list)

    if template_name == Nessus.Scan.TemplateNames.CLOUD_AUDIT:
        if scan_data['credentials']:
            scan_model.add_aws_credential(scan_data['credentials'])
            scan_model.add_audit_file(API.Audits.Type.Feed, scan_data['audits'])

    if template_name == Nessus.Scan.TemplateNames.MALWARE or template_name == Nessus.Scan.TemplateNames.PATCH_AUDIT:
        if scan_data['credentials']:
            scan_model.add_windows_credential(scan_data['credentials'])

    elif template_name == Nessus.Scan.TemplateNames.MDM or template_name == Nessus.Scan.TemplateNames.MOBILE \
            or template_name == Nessus.Scan.TemplateNames.COMPLIANCE:
        if scan_data['credentials']:
            scan_model.add_airwatch_credential(scan_data['credentials'])
        if scan_data['audits']:
            scan_model.add_audit_file(API.Audits.Type.Feed, scan_data['audits'])

    elif template_name == Nessus.Scan.TemplateNames.OFFLINE:
        # Supported : Cisco IOS(Upload Custom Cisco IOS audit file)
        audit_file = api_handler.file.upload(file=get_file_path(CISCO_IOS_SCAN_AUDIT_FILE))
        config_file = api_handler.file.upload(file=get_file_path(CISCO_IOS_SCAN_CONFIG_FILE))

        OFFLINE_AUDITS['custom']['add'][0]['file'] = audit_file

        scan_data['settings']['cisco_offline_configs'] = config_file

        if scan_data['audits']:
            scan_model.add_audit_file(API.Audits.Type.Custom, scan_data['audits'])

    elif template_name == Nessus.Scan.TemplateNames.SCAP:
        scap_file = api_handler.file.upload(file=get_file_path(WINDOWS_SCAP_SCAN_FILE))
        SCAP['add']['Windows'][0]['file'] = scap_file

        if scan_data['credentials']:
            scan_model.add_windows_credential(scan_data['credentials'])

        if scan_data['scap']:
            scan_model.add_scap_credential(scan_data['scap'])

    elif template_name == Nessus.Scan.TemplateNames.AGENT_BASIC or \
            template_name == Nessus.Scan.TemplateNames.AGENT_ADVANCE or \
            template_name == Nessus.Scan.TemplateNames.AGENT_MALWARE or \
            template_name == Nessus.Scan.TemplateNames.AGENT_SCAP or \
            template_name == Nessus.Scan.TemplateNames.AGENT_COMPLIANCE:
        if template_name == Nessus.Scan.TemplateNames.AGENT_SCAP:
            scap_file = api_handler.file.upload(file=get_file_path(WINDOWS_SCAP_SCAN_FILE))
            SCAP['add']['Windows'][0]['file'] = scap_file
            if scan_data['scap']:
                scan_model.add_scap_credential(scan_data['scap'])

        if 'agent_group_id' in scan_data['settings'].keys():
            scanner_id = 1
            agent_name = random_name('agent_group-')
            agent_group = api_handler.agent_groups.create(scanner_id, agent_name)
            agent_group.update({'name': agent_name})
            agents = api_handler.agents.get_agents(scanner_id)

            if agents['agents'] is None:
                assert 'agents not available'
            else:
                agent_status_check = kwargs.get('agent_status_check', True)

                for agent in agents['agents']:
                    if agent.get('status') in (STRING_ON, Nessus.Agents.AgentStatus.ONLINE) or not agent_status_check:
                        if kwargs:
                            if kwargs['agent_name'] == agent.get('name'):
                                api_handler.agent_groups.add_agent(scanner_id, agent_group['id'], agent['id'])
                                break
                        else:
                            api_handler.agent_groups.add_agent(scanner_id, agent_group['id'], agent['id'])
                            break
                    else:
                        assert "Real Agent not found in List of Agents"

            if staggered_start_mins:
                scan_data['staggered_start_mins'] = str(staggered_start_mins)
                setattr(scan_model, 'staggered_start_mins', scan_data['staggered_start_mins'])

            scan_data['agent_group_id'] = [agent_group['id']]
            setattr(scan_model, 'agent_group_id', scan_data['agent_group_id'])
            setattr(scan_model, 'scanner_id', scanner_id)

    if kwargs.get('add_ssh_credential'):
        if scan_data['credentials']['add']['Host']['SSH']:
            scan_model.add_ssh_credential(scan_data['credentials']['add']['Host']['SSH'][0])
        if scan_data['credentials']['add']['Host']['Windows']:
            scan_model.add_windows_credential(scan_data['credentials']['add']['Host']['Windows'][0])

    response_data = api_handler.scans.create(scan_model)

    if 'agent_group_id' in scan_data['settings'].keys():
        response_data['scan']['agent_group_id'] = scan_data['agent_group_id']

    return response_data, scan_model
