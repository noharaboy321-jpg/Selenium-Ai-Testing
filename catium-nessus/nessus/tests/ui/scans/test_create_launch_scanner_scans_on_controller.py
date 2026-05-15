"""
Nessus test cases related to Scans on Controller with all available scanner templates

:copyright: Tenable Network Security, 2017
:date: October 9, 2017
:last_modified: May 13, 2021
:author: @rdutta, @mameta, @vsoni, @kpanchal
"""

import time
from datetime import datetime, timedelta

import pytest
import pytz

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path, load_testdata
from catium.lib.aws.s3client import S3Client
from catium.lib.const import WAIT_SHORT, os
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_THREE_SECONDS
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from catium.lib.util import json
from catium.lib.util.util import random_name
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import upload
from nessus.helpers.nessuscli.helper import get_command, path_join
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import scan_save_launch_and_status_verification
from nessus.helpers.scanner import restart_scanner
from nessus.lib.config.environment_variables import NESSUS_DATA_DIR
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.const.constants import Nessus, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.compliances.compliance_sub_categories import TNSBestPracticeWatchGuardAudit
from nessus.pageobjects.credentials.cloud_services import RackSpace
from nessus.pageobjects.credentials.database import MongoDB
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.credentials.miscellaneous import Miscellaneous
from nessus.pageobjects.credentials.mobile_credential import MaaS360, MobileIron
from nessus.pageobjects.credentials.patch_management import DellKaceK1000, SymantecAltiris
from nessus.pageobjects.credentials.plaintext_authentication import PlainTextAuthentication
from nessus.pageobjects.dynamic_plugins.dynamic_plugins_page import DynamicPlugin, PluginFiltersList
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.plugins.plugins_page import Plugin, PluginsList, PluginFamilyList
from nessus.pageobjects.scans.new_scan_form import NewScanForm, ScanType
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, VulnerabilityList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.scap.scap_page import ScapAndOvalForm
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.fixture(scope='class')
def replace_policy_wizards_and_plugin_attributes_files():
    """This fixture will replace policy_wizards.json and plugin_attributes.json files so that Advanced Pre-defined
    Dynamic Scan can be visible on scan templates with pre-defined plugin filters."""

    move_file = get_command(operation='move_file')
    remove_file = get_command(operation='remove_file')
    with SSH() as ssh:
        ssh.execute("{} {} {}".format(move_file, path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                          'policy_wizards.json']),
                                      path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                               'policy_wizards_tmp.json'])))
        plugin_attributes_file_exist = True
        if plugin_attributes_file_exist:
            ssh.execute("{} {} {}".format(move_file,
                                          path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                   'plugin_attributes.json']),
                                          path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                   'plugin_attributes_tmp.json'])))

        plugin_attributes_file = S3Client.get_local_path('nessus/tests/api/server/test_data/plugin_attributes.json')
        policy_wizard_file = S3Client.get_local_path('nessus/tests/api/server/test_data/policy_wizards.json')

        upload(policy_wizard_file, os.path.join(NESSUS_DATA_DIR, 'templates', 'policy_wizards.json'))
        upload(plugin_attributes_file, os.path.join(NESSUS_DATA_DIR, 'templates', 'plugin_attributes.json'))

        api_object = NessusAPI()
        api_object.login()
        restart_scanner(api=api_object)

    yield

    with SSH() as ssh:
        ssh.execute("{} {}".format(remove_file, path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                         'policy_wizards.json'])))
        ssh.execute("{} {}".format(remove_file, path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                         'plugin_attributes.json'])))

        ssh.execute("{} {} {}".format(move_file,
                                      path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                               'policy_wizards_tmp.json']),
                                      path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                               'policy_wizards.json'])))
        if plugin_attributes_file_exist:
            ssh.execute("{} {} {}".format(move_file,
                                          path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                   'plugin_attributes_tmp.json']),
                                          path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                   'plugin_attributes.json'])))
        restart_scanner(api_object)


@pytest.fixture()
def get_read_only_filter_list():
    """This fixture will return read-only plugin filters list from policy_wizards.json and
    plugin_attributes.json files
    The final filter_list will have id, name, operator and value for each plugin filter"""
    with SSH() as ssh:
        data = ssh.read_from_file(remote_file_path=os.path.join(NESSUS_DATA_DIR, 'templates', 'policy_wizards.json'))
        policy_wizard_file = json.loads(str(data.decode('utf8')))
        data = ssh.read_from_file(remote_file_path=os.path.join(NESSUS_DATA_DIR, 'templates', 'plugin_attributes.json'))
        plugin_attributes_file = json.loads(str(data.decode('utf8')))

    filter_list = []
    try:
        for policy in policy_wizard_file:
            if policy['title'] == 'Advanced Pre-Defined Dynamic Scan':
                filters = policy['default_settings']['plugin_filters']['filters']
                for filter in filters:
                    current_filter_dict = {'filter_id': filter['filter'], 'filter_value': filter['value'],
                                           'filter_operator': filter['quality']}
                    filter_list.append(current_filter_dict)
                break

        for filter in filter_list:
            for plugin_filter in plugin_attributes_file['plugin_attributes']:
                if plugin_filter['id'] == filter['filter_id']:
                    filter['filter_name'] = plugin_filter['name']

        for filter in filter_list:
            filter['filter_operator'] = Nessus.Filter.FilterOperators.OPERATOR_MAPPING[filter['filter_operator']]
            if filter['filter_id'] == 'cve':
                filter['filter_name'] = "CVE"
    finally:
        yield filter_list


@pytest.mark.scanning
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login', 'create_new_folder')
class TestCreateAndLaunchScansOnController:
    """Covers test cases related to Scans on Controller with all available scanner templates."""
    cat = None

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'description': 'Created a {} scan for NQA-1301.'.format(Nessus.TemplateNames.ADVANCED_DYNAMIC.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    def test_advanced_dynamic_scan(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 1)
        Test to create and launch a scan with advanced dynamic scan template

        1. Create a Scan using 'Advanced Dynamic Scan' template
        2. Add all mandatory details in 'Setting' tab
        3. Enable Schedule toggle and set schedule information only if it is a schedule scan.
        4. Navigate to 'Dynamic Plugins' tab
        5. Add atleast one plugin filter (eg. PluginName contains 'Nessus')
        6. Save scan, verify success notifications and Launch it
        7. Verify scan is completed successfully and there are no errors on controller
        8. It should shows up vulnerabilities in scan results related to choose dynamic plugins only in scan result
        """
        scan_name = create_scans[0]

        # Add settings and set schedule information if it is a scheduled scan
        NewScanForm().fill_new_scan_detail()

        # Add credentials
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        # Add dynamic plugins filter
        DynamicPlugin().manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'}])

        NewScanForm().save_button.click()
        scan_list = ScanList()
        scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)

        scan_list.click_on_scan(scan_name=scan_name)
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for scan result page to be loaded')

        scan_details_page = ScanViewPage()
        scan_details_page.vulnerability_tab.click()

        # Verify scan must be launched on scheduled time
        assert ['nessus' in plugin_name for plugin_name in VulnerabilityList().get_plugin_names()], \
            'Applied filter value does not matched with scan result value.'
        HeaderBasePage().scan_link.click()

    @pytest.mark.disable_logout
    @pytest.mark.usefixtures('delete_all_scans_in_nessus', 'login', 'create_new_folder')
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'description': 'Created a {} scan for NQA-1301.'.format(Nessus.TemplateNames.ADVANCED_DYNAMIC.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    def test_advanced_dynamic_scheduled_scan(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 1)
        Test to create and launch a scan with advanced dynamic scan template

        1. Create a Scan using 'Advanced Dynamic Scan' template
        2. Add all mandatory details in 'Setting' tab
        3. Enable Schedule toggle and set schedule information only if it is a schedule scan.
        4. Navigate to 'Dynamic Plugins' tab
        5. Add atleast one plugin filter (eg. PluginName contains 'Nessus')
        6. Save scan, verify success notifications and Launch it
        7. Verify scan is completed successfully and there are no errors on controller
        8. It should shows up vulnerabilities in scan results related to choosed dynamic plugins only in scan result
        9. Verify scan must be launch on scheduled time and completed successfully.
        """
        # Get system's timezone and mark the test accordingly as scheduling of scan depends on it.
        log.debug(msg='You are currently in {} timezone.'.format(time.tzname))
        if 'UTC' not in time.tzname:
            SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
            pytest.xfail(reason='Can\'t proceed further as we are supporting only UTC timezone for scheduled scan')

        # scan scheduling information
        schedule_info = {'schedule_date': datetime.today().date(), 'schedule_timezone': time.tzname[0],
                         'schedule_time': (datetime.today() + timedelta(minutes=4)).time(),
                         'schedule_frequency': API.Schedule.Frequencies.FREQ_ONCE.title()}
        # custom_scan_folder = create_new_folder[1]
        scan_name = create_scans[0]

        # Add settings and set schedule information if it is a scheduled scan
        NewScanForm().fill_new_scan_detail()
        schedule_summary = BasicSetting().schedule_scan(**schedule_info)

        # Add credentials
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        # Add dynamic plugins filter
        DynamicPlugin().manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'}])

        NewScanForm().save_button.click()
        scan_list = ScanList()
        with polling_ui():
            scan_list.launch_scan_and_wait_for_status(is_scheduled_scan=True, scan_name=scan_name, launch_scan=False)

        scan_list.click_on_scan(scan_name=scan_name)

        scan_details_page = ScanViewPage()
        wait(lambda: scan_details_page.is_element_present('vulnerability_tab'), waiting_for='scan view page to load')
        scan_details_page.vulnerability_tab.click()

        scan_start_time = scan_details_page.get_levels_value_of_details_section(
            Nessus.Scan.Results.ScanDetailsLevels.SCAN_START_TIME).text

        if scan_start_time.split(' at')[0] == 'Today':
            scan_start_time = datetime.strftime(datetime.today().date(), '%A %B %d %Y') + \
                              ' at{}'.format(scan_start_time.split(' at')[1])

            sc_time = schedule_summary.split('on ')[1].split(', ')
            if int(sc_time[1].split()[1][:-2]) < 10:
                day = sc_time[1][:-2]
                day_month = day.split()[0] + ' ' + '0' + day.split()[1]
                scheduled_time = sc_time[0] + ' ' + day_month + ' ' + sc_time[2]
            else:
                scheduled_time = sc_time[0] + ' ' + sc_time[1][:-2] + ' ' + sc_time[2]
        else:
            sc_summary = schedule_summary.split(', ')[1:]
            scheduled_time = sc_summary[0][:-2] + sc_summary[1][4:]

        assert scan_start_time == scheduled_time, 'Scan has not been started at it\'s scheduled time.'

        assert ['nessus' in plugin_name for plugin_name in VulnerabilityList().get_plugin_names()], \
            'Applied filter value doesnot matched with scan result value.'

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.SCAP_OVAL, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.SCAP_OVAL)),
         'description': 'Created a {} scan for NQA-392.'.format(Nessus.TemplateNames.SCAP_OVAL.lower()),
         'target_ip': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_scap_and_oval_auditing_scan(self, create_new_folder, create_scans):
        """
        #NQA-392 : Short Cycle - Controller - Stage 3 - Scans.
        1. create SCAP and OVAL Auditing scan with scap data
        2. verify scan is completed successfully and there are no errors on controller
        """
        custom_scan_folder = create_new_folder[1]
        scan_name = create_scans[0]

        NewScanForm().fill_new_scan_detail(folder=custom_scan_folder)
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
            auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)

        ScapAndOvalForm().open_form_and_fill_details(
            form_information=API.Scap.SCAP_AND_OVAL_INFORMATION)

        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder), \
            'Scan has not been completed successfully.'

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.OFFLINE_AUDIT, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.OFFLINE_AUDIT)),
         'description': 'Created an {} scan for NQA-392.'.format(Nessus.TemplateNames.OFFLINE_AUDIT.lower()),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_offline_audit_scan(self, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates. (step-10)
        1. create Offline Config Audit Scan with compliance data
        2. verify scan is completed successfully and there are no errors on controller.
        """
        scan_name = create_scans[0]

        compliance_page = TNSBestPracticeWatchGuardAudit()
        LoadingCircle(WAIT_SHORT)
        compliance_page.config_file.send_keys(os.path.abspath(get_file_path("nessus/tests/api/plugins/test_data/"
                                                                            "api_pub_key_target_priv_key")))

        LoadingCircle(TIME_THREE_SECONDS)
        compliance_page.click_compliance_type(category_name=ComplianceConst.ADTRAN_AOS,
                                              compliance_type="Upload a custom {} audit file".
                                              format(ComplianceConst.ADTRAN_AOS))
        LoadingCircle(WAIT_SHORT)
        compliance_page.add_audit_and_config_file(
            audit_file_path='nessus/tests/ui/scan/test_data/', audit_file_name='CIS_Red_Hat_EL6_Server_L1_v2.0.2.audit',
            config_file_path='nessus/tests/api/plugins/test_data/', config_file_name='api_pub_key_target_priv_key')

        assert scan_save_launch_and_status_verification(scan_name=scan_name,
                                                        scan_folder_name=Nessus.Scan.Folder.MY_SCANS), \
            'Scan has not been completed successfully.'

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.AUDIT_CLOUD, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.AUDIT_CLOUD)),
         'description': 'Created a {} for NQA-1265.'.format(Nessus.TemplateNames.AUDIT_CLOUD.lower()),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_audit_cloud_infrastructure_scan(self, create_new_folder, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates. (step-10)
        1. create Audit Cloud Infrastructure Scan with mobile credentials and compliance data
        2. verify scan is completed successfully and there are no errors on controller.
        """
        test_data = load_testdata(filename='nessus/tests/ui/scans/test_data/cloud_services_auth.json')
        custom_scan_folder = create_new_folder[1]
        scan_name = create_scans[0]

        scan_form = NewScanForm()
        scan_form.fill_new_scan_detail(folder=custom_scan_folder)
        RackSpace(cloud_type=API.Credentials.CloudServices.Types.RACKSPACE).fill_rackspace_form(
            auth_method='API-Key', **test_data.get('rackspace'))

        compliance_page = Compliance()
        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.RACKSPACE,
                                              compliance_type="Upload a custom {} audit file".
                                              format(ComplianceConst.RACKSPACE))
        LoadingCircle(TIME_THREE_SECONDS)
        compliance_page.add_audit_and_config_file(audit_file_path='nessus/tests/ui/scan/test_data/',
                                                  audit_file_name='CIS_MS_Windows_7_L1_v3.0.1.audit')

        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder), \
            'Scan has not been completed successfully.'

    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.COMPLIANCE_AUDIT, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.COMPLIANCE_AUDIT)),
        'description': 'Created a {} scan for NQA-1265.'.format(Nessus.TemplateNames.COMPLIANCE_AUDIT.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_policy_compliance_auditing_scan(self, create_new_folder, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates. (step-10)
        1. Create Policy Compliance Auditing Scan with different type of plugins and compliance
        2. Verify scan is completed successfully and there are no errors on controller.
        """
        scan_name = create_scans[0]
        custom_scan_folder = create_new_folder[1]
        NewScanForm().fill_new_scan_detail(folder=custom_scan_folder)

        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        compliance_page = Compliance()
        compliance_page.click_compliance_type(category_name=ComplianceConst.ADTRAN_AOS,
                                              compliance_type="Upload a custom {} audit file".
                                              format(ComplianceConst.ADTRAN_AOS))
        LoadingCircle(WAIT_SHORT)
        compliance_page.add_audit_and_config_file(audit_file_path='nessus/tests/api/plugins/test_data/',
                                                  audit_file_name='api_pub_key_target_priv_key')

        LoadingCircle(WAIT_SHORT)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder), \
            'Scan has not been completed successfully.'

    @pytest.mark.parametrize('create_scans', [
        {'scans_details': [
            {'scan_template': Nessus.TemplateNames.HOST_DISCOVERY, 'add_configuration': True,
             'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, 'target_ip': Nessus.Scan.Target.LOCALHOST,
             'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.HOST_DISCOVERY)),
             'description': 'Created a {} scan for NQA-1265.'.format(Nessus.TemplateNames.HOST_DISCOVERY.lower())}]},
        pytest.param({'scans_details': [
            {'scan_template': Nessus.TemplateNames.PCI_EXTERNAL, 'add_configuration': True,
             'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, 'target_ip': Nessus.Scan.Target.LOCALHOST,
             'description': 'Created a {} for NQA-1265.'.format(Nessus.TemplateNames.PCI_EXTERNAL.lower()),
             'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.PCI_EXTERNAL))}]},
            marks=pytest.mark.skip(reason="Scan takes more than 30 minutes for completion."))], indirect=True)
    @pytest.mark.nessus_expert
    def test_scans_without_credentials_and_compliance(self, create_new_folder, create_scans):
        """
        #NQA-392 : Short Cycle - Controller - Stage 3 - Scans.
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates. (step-10)
        1. Create scan with different type of scanner templates without credentials and compliance data
        2. Verify "Ping on the remote host" vulnerability is returned for Host Discovery Scan
        3. For other scan templates verify vulnerabilities count is greater than 0.
        """
        custom_scan_folder = create_new_folder[1]
        scan_name = create_scans[0]

        scan_form = NewScanForm()
        scan_form.fill_new_scan_detail(folder=custom_scan_folder)
        scan_form.js_scroll_into_view(element=scan_form.save_button)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder), \
            'Scan has not been completed successfully.'

        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)
        scan_details_page = ScanViewPage()
        scan_details_page.vulnerability_tab.click()
        vulns_list = VulnerabilityList()
        if Nessus.TemplateNames.HOST_DISCOVERY.lower() in scan_name.lower():
            assert Nessus.Scan.Vulnerability.PING_THE_REMOTE_HOST in vulns_list.get_plugin_names(), \
                "Expected vulnerability hadn't been returned for {} scan.".format(Nessus.TemplateNames.HOST_DISCOVERY)
        else:
            assert vulns_list.get_total_rows(), 'No vulnerabilities found against this scan.'
        HeaderBasePage().scan_link.click()

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='Advanced Scan - '), 'target_ip': Nessus.Scan.Target.LOCALHOST,
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize('data_to_be_scanned', [pytest.param(
        {'all_plugin_families': []}, marks=pytest.mark.skip(reason="Scan takes more than 30 minutes for completion.")),
        {'one_plugin_family': [{'plugin_family': 'Settings'}]},
        {'custom_couple_plugin_family': [{'plugin_family': 'General', 'plugin_id_list': ['42084']},
                                         {'plugin_family': 'Settings', 'plugin_id_list': ['60024']}]},
        pytest.param({'all_plugin_families_with_compliance': {'compliance_to_scan': [
            {'category_type': ComplianceConst.ADTRAN_AOS, 'file': 'api_pub_key_target_priv_key',
             'file_path': 'nessus/tests/api/plugins/test_data/'},
            {'category_type': ComplianceConst.UNIX, 'file': 'CIS_Red_Hat_EL6_Server_L1_v2.0.2.audit',
             'file_path': 'nessus/tests/ui/scan/test_data/'},
            {'category_type': ComplianceConst.WINDOWS, 'file': 'CIS_MS_Windows_7_L1_v3.0.1.audit',
             'file_path': 'nessus/tests/ui/scan/test_data/'},
            {'category_type': ComplianceConst.EXTREME_EXTREMEXOS, 'file': 'api_pub_key_target_priv_key',
             'file_path': 'nessus/tests/api/plugins/test_data/'}]}},
            marks=pytest.mark.skip(reason="Scan takes more than 30 minutes for completion."))])
    @pytest.mark.nessus_expert
    def test_advanced_scan_with_different_plugins(self, create_new_folder, create_scans, data_to_be_scanned):
        """
        #NQA-392 : Short Cycle - Controller - Stage 3 - Scans.
        1. Create Advanced scan with different type of plugins and compliance
        2. Verify scan is completed successfully and there are no errors on controller.
        """
        scan_name = create_scans[0]
        custom_scan_folder = create_new_folder[1]
        type_of_data_to_be_scanned = list(data_to_be_scanned.keys())[0]
        NewScanForm().fill_new_scan_detail(folder=custom_scan_folder, description='Created an Advanced Scan with {}.'
                                           .format(type_of_data_to_be_scanned))

        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
            auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)

        if type_of_data_to_be_scanned in ['one_plugin_family', 'custom_couple_plugin_family']:
            plugin_page = Plugin()
            plugin_page.disable_all.click()
            if type_of_data_to_be_scanned == 'one_plugin_family':
                PluginFamilyList().toggle_plugin_family(
                    plugin_family_list=data_to_be_scanned.get(type_of_data_to_be_scanned)[0].get('plugin_family'))
            else:
                plugins_list = PluginsList()
                for plugin in data_to_be_scanned.get(type_of_data_to_be_scanned):
                    plugins_list.toggle_plugins(plugin_family=plugin.get('plugin_family'),
                                                plugin_id_list=plugin.get('plugin_id_list'))

        elif type_of_data_to_be_scanned == 'all_plugin_families_with_compliance':
            compliance_page = Compliance()
            for compliance in data_to_be_scanned.get(type_of_data_to_be_scanned).get('compliance_to_scan'):
                compliance_page.click_compliance_type(category_name=compliance.get('category_type'),
                                                      compliance_type="Upload a custom {} audit file".
                                                      format(compliance.get('category_type')))
                LoadingCircle(WAIT_SHORT)
                compliance_page.add_audit_and_config_file(audit_file_name=compliance.get('file'),
                                                          audit_file_path=compliance.get('file_path'))

        LoadingCircle(WAIT_SHORT)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder), \
            'Scan has not been completed successfully.'

    @pytest.mark.usefixtures('load_data_files', 'nessus_api_login')
    @pytest.mark.parametrize('test_data_file', [{
        'patch_mgmt_cred_data': get_file_path('nessus/tests/ui/scans/test_data/test_patch_management_auth.json'),
        'database_cred_data': get_file_path('nessus/tests/ui/scans/test_data/test_database_auth_multiple.json'),
        'misc_cred_data': get_file_path('nessus/tests/ui/scans/test_data/test_miscellaneous_auth.json')}],
                             indirect=True)
    @pytest.mark.parametrize('create_scans', [
        {'scans_details': [
            {'scan_template': Nessus.TemplateNames.INTERNAL_PCI, 'add_configuration': True,
             'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, 'target_ip': Nessus.Scan.Target.LOCALHOST,
             'description': 'Created an {} for NQA-1265.'.format(Nessus.TemplateNames.INTERNAL_PCI.lower()),
             'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.INTERNAL_PCI))}]},
        {'scans_details': [
            {'scan_template': Nessus.TemplateNames.BASIC_NETWORK, 'add_configuration': True,
             'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, 'target_ip': Nessus.Scan.Target.LOCALHOST,
             'description': 'Created a {} for NQA-1265.'.format(Nessus.TemplateNames.BASIC_NETWORK.lower()),
             'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.BASIC_NETWORK))}]},
        {'scans_details': [
            {'scan_template': Nessus.TemplateNames.AUDIT_PATCH, 'add_configuration': True,
             'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, 'target_ip': Nessus.Scan.Target.LOCALHOST,
             'description': 'Created an {} scan for NQA-1265.'.format(Nessus.TemplateNames.AUDIT_PATCH.lower()),
             'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.AUDIT_PATCH))}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_scans_with_credentials_of_multiple_categories(self, create_new_folder, load_data_files, create_scans):
        """
        #NQA-392 : Short Cycle - Controller - Stage 3 - Scans.
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates. (step-10)
        1. Create scan with different type of scanner templates with multiple credentials data
        2. Verify scan is completed successfully and there are no errors on controller.
        """
        scan_name = create_scans[0]
        custom_scan_folder = create_new_folder[1]

        NewScanForm().fill_new_scan_detail(folder=custom_scan_folder)
        if self.cat.api.server.properties()['nessus_type'] == Nessus.Manager.NESSUS_MANAGER:
            DellKaceK1000(patch_type=API.Credentials.PatchManagement.Types.DELL_KACE).fill_dell_kace_form(
                **load_data_files.get('patch_mgmt_cred_data').get('kace'))

            SymantecAltiris(patch_type=API.Credentials.PatchManagement.Types.SYMANTEC_ALTIRIS). \
                fill_symantec_altiris_form(**load_data_files.get('patch_mgmt_cred_data').get('altiris_not_windows'))
        else:
            Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        if Nessus.TemplateNames.INTERNAL_PCI not in scan_name:
            Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.ADSI).fill_form(
                domain_pass='sapphire', **load_data_files.get('misc_cred_data').get('adsi'))

            Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.VMWARE_ESX).fill_form(
                user_name=Nessus.USERNAME, ssl_cert=True, **load_data_files.get('misc_cred_data').get('vmware_esx'))

        if any([getattr(Nessus.TemplateNames, attr) in scan_name for attr in ['BASIC_NETWORK', 'AUDIT_PATCH']]):
            MongoDB(host_type=API.Credentials.Database.Types.MONGODB).fill_monogodb_database_form(
                **load_data_files.get('database_cred_data').get('mongodb'))

        LoadingCircle(WAIT_SHORT)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder), \
            'Scan has not been completed successfully.'

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('create_scans', [
        {'scans_details': [
            {'scan_template': Nessus.TemplateNames.MALWARE, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
             'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True,
             'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.MALWARE)),
             'description': 'Created a {} for NQA-1265.'.format(Nessus.TemplateNames.MALWARE.lower())}]},
        {'scans_details': [
            {'scan_template': Nessus.TemplateNames.WEB_APP, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
             'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True,
             'description': 'Created a {} scan for NQA-1265.'.format(Nessus.TemplateNames.WEB_APP.lower()),
             'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.WEB_APP))}]}], indirect=True)
    @pytest.mark.nessus_expert
    def test_scans_with_credentials_of_host_and_plaintext_auth(self, create_new_folder, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates. (step-10)
        1. Create scan with different type of scanner templates with host and Plain_text authentication credentials data
        2. Verify scan is completed successfully and there are no errors on controller.
        """
        test_data = {'http_auth_type': 'Basic/Digest authentication', 'username': 'admin', 'password': 'admin',
                     'login_method': 'GET', 're_authenticate_delay': 22, 'follow_redirection': 22,
                     'invert_authenticated_regex': True, 'use_authenticated_regex': True,
                     'case_insensitive_authenticated_regex': True}
        scan_name = create_scans[0]
        custom_scan_folder = create_new_folder[1]
        NewScanForm().fill_new_scan_detail(folder=custom_scan_folder)

        if all([getattr(Nessus.TemplateNames, attr) not in scan_name for attr in ['WEB_APP']]):
            Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
                auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)
            LoadingCircle(WAIT_SHORT)

        if any([getattr(Nessus.TemplateNames, attr) in scan_name for attr in ['MALWARE']]):
            Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
            LoadingCircle(WAIT_SHORT)

        if Nessus.TemplateNames.WEB_APP in scan_name:
            PlainTextAuthentication.get_auth_type(pt_auth=API.Credentials.PlaintextAuthentication.HTTP). \
                fill_form(**test_data)

        LoadingCircle(WAIT_SHORT)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder), \
            'Scan has not been completed successfully.'

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.BASIC_NETWORK, 'add_configuration': True,
         'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, 'target_ip': Nessus.Scan.Target.LOCALHOST,
         'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.BASIC_NETWORK))}]}], indirect=True)
    def test_launch_schedule_scan_on_controller(self, create_scans):
        """
        NES-11475 : UI automation to cover scan scheduling
        Scenario Tested:
            [x] Verify that scheduled scan gets saved and launched successfully.
        Steps:
        1. Create a scan with scheduled time and verify that scan saved successfully.
        2. Verify that scheduled scan launched automatically.
        3. Verify that scheduled scan gets completed successfully.
        """
        scan_name = create_scans[0]

        basic_setting = BasicSetting()
        basic_setting.schedule.click()
        basic_setting.enable_schedule.click()
        timezone = basic_setting.timezone.value

        # Scheduling scan at one minute ahead than current time for selected timezone.
        start_time = (pytz.utc.localize(datetime.utcnow()) + timedelta(minutes=1)).astimezone(pytz.timezone(timezone))
        basic_setting.schedule_scan(schedule_date=start_time.strftime('%Y-%m-%d'),
                                    schedule_time=str(start_time.hour) + ":" + str(start_time.minute))

        # Verifying that scan saved successfully.
        scans_page = ScansPage()
        scans_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Scheduled scan does not saved successfully.'

        wait(lambda: scans_page.is_element_present("scan_searchbox"), waiting_for="scan list gets loaded")
        scan_list = ScanList()

        # Verifying that scan appears on scans main page.
        assert scan_name in scan_list.get_all_scans(), "Scan does not appear on scans main page."

        # Verify that scheduled scan gets launched and completed successfully.
        assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, launch_scan=False,
                                                         is_scheduled_scan=True), \
            "Schedule scan failed to launch or did not completed."


@pytest.mark.scanning
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login', 'create_new_folder')
class TestScansOnControllerForNessusManager:
    """Covers test cases related to Scans on Controller with scanner templates available in only Nessus Manager."""

    @pytest.mark.usefixtures('load_data_files')
    @pytest.mark.parametrize('test_data_file', [{
        'misc_cred_data': get_file_path('nessus/tests/ui/scans/test_data/test_miscellaneous_auth.json'),
        'mobile_cred_data': get_file_path('nessus/tests/ui/scans/test_data/test_mobile_auth.json')}], indirect=True)
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.MOBILE_DEVICE, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.MOBILE_DEVICE)),
         'description': 'Created a {} for NQA-1265.'.format(Nessus.TemplateNames.MOBILE_DEVICE.lower()),
         'add_configuration': True}]}], indirect=True)
    def test_mobile_device_scan(self, create_new_folder, load_data_files, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates. (step-10)
        1. create Mobile Device Scan with mobile/Misc. credentials data
        2. verify scan is completed successfully and there are no errors on controller.
        """
        custom_scan_folder = create_new_folder[1]
        scan_name = create_scans[0]

        NewScanForm().fill_new_scan_detail(folder=custom_scan_folder)
        MobileIron(mobile_credential_type=API.Credentials.Mobile.MOBILEIRON).fill_mobileiron_form(
            **load_data_files.get('mobile_cred_data').get('mobileiron'))
        MaaS360(mobile_credential_type=API.Credentials.Mobile.MAAS360).fill_maas_mobile_form(
            **load_data_files.get('mobile_cred_data').get('maas360'))

        Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.ADSI).fill_form(
            domain_pass='sapphire', **load_data_files.get('misc_cred_data').get('adsi'))

        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder), \
            'Scan has not been completed successfully.'

    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.MDM_AUDIT, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'description': 'Created a {} scan for NQA-1265.'.format(Nessus.TemplateNames.MDM_AUDIT.lower()),
        'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.MDM_AUDIT)),
        'dashboard': True, 'add_configuration': True}]}], indirect=True)
    def test_mdm_audit_scan_with_credentials_and_compliance(self, create_new_folder, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates. (step-10)
        1. Create MDM Audit scan with different type of credentials and related compliance
        2. Verify scan is completed successfully and there are no errors on controller.
        """
        test_data = load_testdata(filename='nessus/tests/ui/scans/test_data/test_mobile_auth.json')
        scan_name = create_scans[0]
        custom_scan_folder = create_new_folder[1]
        NewScanForm().fill_new_scan_detail(folder=custom_scan_folder)

        MobileIron(mobile_credential_type=API.Credentials.Mobile.MOBILEIRON).fill_mobileiron_form(
            **test_data.get('mobileiron'))

        compliance_page = Compliance()
        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.MOBILE_DEVICE_MANAGER,
                                              compliance_type="Upload a custom {} audit file".
                                              format(ComplianceConst.MOBILE_DEVICE_MANAGER))
        LoadingCircle(WAIT_SHORT)
        compliance_page.add_audit_and_config_file(audit_file_path='nessus/tests/api/plugins/test_data/',
                                                  audit_file_name='api_pub_key_target_priv_key')

        LoadingCircle(WAIT_SHORT)
        assert scan_save_launch_and_status_verification(scan_name=scan_name, scan_folder_name=custom_scan_folder), \
            'Scan has not been completed successfully.'


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('replace_policy_wizards_and_plugin_attributes_files', 'login')
class TestAdvancedPreDefinedDynamicFiltersScan:
    def test_verify_read_only_filters_in_advanced_pre_defined_dynamic_scan(self, get_read_only_filter_list):
        """
        NES-9975 - Adding new attributes for Dynamic Scan Policy(NES-9973)

        Scenarios:
            [x] Verify the visibility of read only dynamic plugin filters for "Advanced Pre-defined dynamic scan"

        Steps:
        1. Login to Nessus.
        2. Go to "New Scan" and select "Advanced Pre-defined dynamic scan" template.
        3. Verify that "Dynamic Plugins" tab is present.
        4. Verify that pre-defined plugin filters are present in webpage as defined in policy_wizards.json file
        5. Logout from Nessus.
        """

        filter_list = get_read_only_filter_list

        scan_page = ScansPage()
        scan_page.new_scan_button.click()

        wait(lambda: scan_page.is_element_present('scanner'), waiting_for='Scan templates to load properly')

        ScanType().click_by_scan(scan_text=Nessus.TemplateNames.PRE_DEFINED_ADVANCED_DYNAMIC)

        new_scan = DynamicPlugin()

        wait(lambda: new_scan.is_element_present('dynamic_plugins'), waiting_for='New scan form to load properly')

        new_scan.dynamic_plugins.click()

        plugin_filters = PluginFiltersList()

        # Verify Pre-defined filters count is matching with filters defined in policy_wizards.json file
        assert len(filter_list) == len(plugin_filters.rows), \
            "Number of filters in policy_wizards file are not matching with number of plugin filters for Advanced " \
            "Pre-defined Dynamic Scan."

        for index in range(len(filter_list)):
            filter_name = filter_list[index]['filter_name']
            assert filter_name == plugin_filters.rows[index].filter_name.text, \
                "Name for the filter - {} is not present on Dynamic plugins page.".format(filter_name)
            assert filter_list[index]['filter_operator'] == plugin_filters.rows[index].filter_operator.text, \
                "Operator for the filter - {} is not present on Dynamic plugins page.".format(filter_name)
            assert filter_list[index]['filter_value'] == plugin_filters.rows[index].filter_value.text, \
                "Value for the filter - {} is not present on Dynamic plugins page.".format(filter_name)

    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.PRE_DEFINED_ADVANCED_DYNAMIC,
         'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.PRE_DEFINED_ADVANCED_DYNAMIC)),
         'description': 'Created a {} scan for NES-9975.'.format(Nessus.TemplateNames.PRE_DEFINED_ADVANCED_DYNAMIC.
                                                                 lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    def test_create_and_launch_advanced_pre_defined_dynamic_scan(self, create_scans):
        """
        NES-9975 - Adding new attributes for Dynamic Scan Policy(NES-9973)

        Scenarios:
            [x] Create scan for "Advanced Pre-defined dynamic scan" template.

        Steps:
        1. Login to Nessus.
        2. Go to "New Scan" and select "Advanced Pre-defined dynamic scan" template.
        3. create a scan on localhost.
        4. Verify that pre-defined dynamic filters are present in webpage and read only.
        5. Launch the scan and wait till the scan get completed.
        6. Delete scan and logout from Nessus.
        """
        new_scan = DynamicPlugin()
        wait(lambda: new_scan.is_element_present('dynamic_plugins'), waiting_for='New scan form to load properly')
        new_scan.dynamic_plugins.click()

        # Verify that readonly filters are not empty for Advance Pre-defined Dynamic Scan.
        assert PluginFiltersList().loaded(), "Readonly filters are not present"

        new_scan.save_button.click()

        scan_list = ScanList()
        scan_list.loaded()

        # Verify that Advanced Pre-defined Dynamic scan is completed properly.
        assert scan_list.launch_scan_and_wait_for_status(scan_name=create_scans[0]), \
            "Scan has not been completed successfully"

    def test_additional_plugin_filters_in_advanced_dynamic_scan(self):
        """
        NES-9975 - Adding new attributes for Dynamic Scan Policy(NES-9973)

        Scenarios:
            [x] Verify additional plugin filters appearing on Advanced dynamic scan template

        Steps:
        1. Login to Nessus.
        2. Go to "New Scan" and select "Advanced dynamic scan" template.
        3. Verify that plugin filters are added for plugin filters defined in plugin_attributes.json
        5. Delete scan and logout from Nessus.
        """

        with SSH() as ssh:
            data = ssh.read_from_file(remote_file_path=os.path.join(NESSUS_DATA_DIR, 'templates',
                                                                    'plugin_attributes.json'))
            plugin_attributes_file = json.loads(str(data.decode('utf8')))

        additional_plugin_filters = [plugin['name'] for plugin in plugin_attributes_file['plugin_attributes']]

        scan_page = ScansPage()
        scan_page.new_scan_button.click()

        wait(lambda: scan_page.is_element_present('scanner'), waiting_for='Scan templates to load properly')

        ScanType().click_by_scan(scan_text=Nessus.TemplateNames.ADVANCED_DYNAMIC)

        new_scan = DynamicPlugin()

        wait(lambda: new_scan.is_element_present('dynamic_plugins'), waiting_for='New scan form to load properly')

        new_scan.dynamic_plugins.click()

        filter_options_on_scan_page = [filter_option['value'] for filter_option in
                                       new_scan.filter_name_dropdown.option_values]

        # Verifying additional plugin filters defined in plugin_attributes.json appears in filter dropdown list.
        assert all(True if plugin_filter in filter_options_on_scan_page else False for plugin_filter in
                   additional_plugin_filters), \
            "Additional plugin filters are not visible for Advanced dynamic scan"
