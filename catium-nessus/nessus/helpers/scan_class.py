"""
Nessus helpers for API/UI Scans
:copyright: Tenable Network Security, 2017
:date: Mar 30, 2017
:last_modified: May 04, 2021
:author: @rdutta, @kpanchal
"""
import os
from http import HTTPStatus

import pytest
from catium.helpers.testdata import get_file_path, load_testdata
from catium.lib.const import STRING_ON, TIME_TEN_MINUTES, TIME_THIRTY_MINUTES
from catium.lib.const.base_constants import TIME_FIVE_SECONDS, WAIT_NORMAL
from catium.lib.errors import CatiumAPIObjectError
from catium.lib.log import create_logger

from nessus.apiobjects import routes
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.metadata.scan import get_template_uuid_by_name
from nessus.helpers.waiters import wait_for_scanner_status, wait_scan_state, wait_for_export_to_complete, \
    wait_for_scanner_login
from nessus.lib.config import NessusConfig
from nessus.lib.const import API, Nessus, random_name, Scanner
from nessus.models.scan import ScanModel

WINDOWS_SCAP_SCAN_FILE = 'nessus/tests/api/scan/test_data/U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip'

CISCO_IOS_SCAN_AUDIT_FILE = 'nessus/tests/api/scan/test_data/CIS_Cisco_v2.2_Level_1.audit'
CISCO_IOS_SCAN_CONFIG_FILE = 'nessus/tests/api/scan/test_data/CiscoIOSOffline_PolicyTestFile.txt'

OFFLINE_AUDITS = {'custom': {'add': [{'category': 'Cisco IOS', 'file': ''}]}}
SCAP = {'add': {'Windows': [{'file': '', 'version': '1.1', 'benchmark_id': 'Windows_7_STIG',
                             'profile_id': 'MAC-1_Classified',
                             'oval_result_type': 'Full results w/ system characteristics'}]}}

log = create_logger()


class Scan:
    def __init__(self, api_handler: NessusAPI, scan_agent_options=None, scan_data_path=None, scan_id=None,
                 scan_model=None, scan_name=None, scan_type=None, staggered_start_minutes=0):
        self.scan_result = None
        self.scan_details = None
        self.scan_data_path = scan_data_path
        self.scan_test_data = load_testdata(self.scan_data_path) if scan_data_path is not None else None
        self.scan_model = ScanModel.create_model() if scan_model is None else scan_model

        for key, value in self.scan_test_data['settings'].items():
            try:
                setattr(self.scan_model, key, value)
            except:
                log.warning("Scan Model does not contain attribute.")

        if "windows_credentials" in self.scan_test_data.keys():
            self.scan_model.add_windows_credential(self.scan_test_data["windows_credentials"])

        self.api = api_handler
        self.scan_agent_options = scan_agent_options
        self.staggered_start_minutes = staggered_start_minutes
        self._scan_type = None
        self.scan_type = scan_type
        self.id = scan_id
        self.name = scan_name
        self.response_data = None
        self.export_details = None
        self.export_file_id = None
        self.export_file_name = None
        self.export_password = None
        self.token_id = None
        self.hosts = {}

        self.wait_for_scanner()

        if scan_id is not None:
            self.get_all_scans()

    @property
    def scan_type(self):
        return self._scan_type

    @scan_type.setter
    def scan_type(self, value):
        self._scan_type = value
        if self._scan_type == Nessus.Scan.TemplateNames.CLOUD_AUDIT:
            if self.scan_model.credentials:
                self.scan_model.add_aws_credential(self.scan_model.credentials)
                self.scan_model.add_audit_file(API.Audits.Type.Feed, self.scan_test_data['audits'])

        if self._scan_type in [Nessus.Scan.TemplateNames.MALWARE, Nessus.Scan.TemplateNames.PATCH_AUDIT]:
            if self.scan_model.credentials:
                self.scan_model.add_windows_credential(self.scan_model.credentials)

        elif self._scan_type in [Nessus.Scan.TemplateNames.MDM, Nessus.Scan.TemplateNames.MOBILE,
                                 Nessus.Scan.TemplateNames.COMPLIANCE]:
            if self.scan_model.credentials:
                self.scan_model.add_airwatch_credential(self.scan_model.credentials)
            if self.scan_test_data['audits']:
                self.scan_model.add_audit_file(API.Audits.Type.Feed, self.scan_test_data['audits'])

        elif self._scan_type == Nessus.Scan.TemplateNames.OFFLINE:
            # Supported : Cisco IOS(Upload Custom Cisco IOS audit file)
            audit_file = self.api.file.upload(file=get_file_path(CISCO_IOS_SCAN_AUDIT_FILE))
            config_file = self.api.file.upload(file=get_file_path(CISCO_IOS_SCAN_CONFIG_FILE))

            OFFLINE_AUDITS['custom']['add'][0]['file'] = audit_file

            self.scan_model.cisco_offline_configs = config_file

            if self.scan_test_data['audits']:
                self.scan_model.add_audit_file(API.Audits.Type.Custom, self.scan_test_data['audits'])

        elif self._scan_type == Nessus.Scan.TemplateNames.SCAP:
            scap_file = self.api.file.upload(file=get_file_path(WINDOWS_SCAP_SCAN_FILE))
            SCAP['add']['Windows'][0]['file'] = scap_file

            if self.scan_model.credentials:
                self.scan_model.add_windows_credential(self.scan_model.credentials)

            if self.scan_test_data['scap']:
                self.scan_model.add_scap_credential(self.scan_test_data['scap'])

        elif self._scan_type in [Nessus.Scan.TemplateNames.AGENT_BASIC, Nessus.Scan.TemplateNames.AGENT_ADVANCE,
                                 Nessus.Scan.TemplateNames.AGENT_MALWARE, Nessus.Scan.TemplateNames.AGENT_SCAP,
                                 Nessus.Scan.TemplateNames.AGENT_COMPLIANCE]:
            if self._scan_type == Nessus.Scan.TemplateNames.AGENT_SCAP:
                scap_file = self.api.file.upload(file=get_file_path(WINDOWS_SCAP_SCAN_FILE))
                SCAP['add']['Windows'][0]['file'] = scap_file
                if self.scan_test_data['scap']:
                    self.scan_model.add_scap_credential(self.scan_test_data['scap'])

            scanner_id = 1
            if not self.scan_model.agent_group_id:
                agent_name = random_name('agent_group-')
                agent_group = self.api.agent_groups.create(scanner_id, agent_name)
                agent_group.update({'name': agent_name})
                self.scan_test_data['agent_group_id'] = [agent_group['id']]
                self.scan_model.agent_group_id = agent_group['id']
            agents = self.api.agents.get_agents(scanner_id)

            if agents['agents'] is None:
                assert 'agents not available'
            else:
                if self.scan_agent_options is not None:
                    agent_status_check = self.scan_agent_options['agent_status_check'] \
                        if 'agent_status_check' in self.scan_agent_options.keys() else True

                    for agent in agents['agents']:
                        if agent.get('status') in (STRING_ON, Nessus.Agents.AgentStatus.ONLINE) \
                                or not agent_status_check:
                            if 'agent_name' in self.scan_agent_options.keys():
                                if self.scan_agent_options['agent_name'] == agent.get('name'):
                                    self.api.agent_groups.add_agent(scanner_id, self.scan_model.agent_group_id,
                                                                    agent['id'])
                                    break
                            else:
                                self.api.agent_groups.add_agent(scanner_id, self.scan_model.agent_group_id, agent['id'])
                                break
                        else:
                            assert "Real Agent not found in List of Agents"

                if self.staggered_start_minutes:
                    self.scan_test_data['staggered_start_mins'] = str(self.staggered_start_minutes)
                    setattr(self.scan_model, 'staggered_start_mins', self.scan_test_data['staggered_start_mins'])

                setattr(self.scan_model, 'scanner_id', scanner_id)

    def create_scan(self, change_scan_name: bool = False, add_ssh_credential: bool = False):
        """
        :param add_ssh_credential: Adds ssh credentials to scan
        :param change_scan_name: boolean to add random characters in scan name or not to avoid same name scans
        :return:
        """
        log.debug('fixture init: create_scan: Create a Scan')

        template_list = self.api.scans.get_templates()

        # based on template title will get uuid for it
        template_uuid = get_template_uuid_by_name(template_list, self.scan_type)
        if type(self.scan_model) is not ScanModel:
            self.scan_model = ScanModel.create_model()

        if 'uuid' in self.scan_test_data.keys():
            setattr(self.scan_model, 'uuid', template_uuid)

        if change_scan_name:
            setattr(self.scan_model, 'name', random_name(prefix=self.scan_test_data['settings']['name'] + '-'))

        if 'plugins' in self.scan_test_data.keys():
            plugins = self.scan_test_data['plugins']
            response = self.api.plugins.families()
            plugin_list = []
            for plugin in plugins.keys():
                if plugins[plugin] == 'enabled':
                    existing_family = next((family for family in response['families'] if family['name'] == plugin),
                                           None)
                    family_details = self.api.plugins.family_details(existing_family['id'])
                    for family_plugin in family_details['plugins']:
                        plugin_list.append(family_plugin['id'])
            setattr(self.scan_model, 'plugins', plugin_list)

        if 'plugin_families' in self.scan_test_data.keys():
            families = self.scan_test_data['plugin_families']
            family_list = []
            for family in families.keys():
                if families[family] == 'enabled':
                    family_list.append(family)
            setattr(self.scan_model, 'families', family_list)

        if add_ssh_credential:
            if self.scan_model.credentials['add']['Host']['SSH']:
                self.scan_model.add_ssh_credential(self.scan_model.credentials['add']['Host']['SSH'][0])
            if self.scan_model.credentials['add']['Host']['Windows']:
                self.scan_model.add_windows_credential(self.scan_model.credentials['add']['Host']['Windows'][0])

        self.response_data = self.api.scans.create(self.scan_model)
        for key in self.response_data['scan']:
            self.__setattr__(key, self.response_data['scan'][key])

    def get_all_scans(self):
        scans = self.api.scans.get_scans()

        for scan in scans:
            if scan['id'] == self.id:
                for key in scan:
                    self.__setattr__(key, scan[key])

    def get_scan_details(self):
        self.scan_details = self.api.scans.details(scan_id=self.id)

    def delete_scan(self):
        self.api.scans.delete(self.id)

    def download_scan(self, filename: str = None, output_directory: str = None):
        """
        Downloads exported scan details to a specified location
        :param
        """
        # Configure variables and default to CAT variables if not provided
        output_directory = NessusConfig.CAT_NESSUS_DB_DIRECTORY if output_directory is None else \
            output_directory
        filename = NessusConfig.CAT_NESSUS_DB_FILENAME if filename is None else filename

        scan_db = self.api.scans.download(scan_id=self.id, file_id=self.export_file_id)

        if filename:
            self.export_file_name = os.path.join(output_directory, filename) + '.db'
        else:
            filename = f"{self.id}_{Scanner.NESSUS_DB_TIMESTAMP}"
            self.export_file_name = os.path.join(output_directory, filename) + '.db'
        log.info(f"[download_scan]: Saving to {self.export_file_name}")
        try:
            with open(self.export_file_name, "wb") as file:
                for block in scan_db.iter_content(1024):
                    file.write(block)
                file.close()
            log.info(f"[download_scan]: Scan results saved as {self.export_file_name}")
        except FileNotFoundError:
            log.info(f"[download_scan]: Unable to write to {output_directory}.")

    def download_via_token(self):
        if self.token_id is None:
            raise Exception("No download token found! Data must be exported first.")

        return self.api.tokens.download_file(token_id=self.token_id)

    def export_scan(self, export_format: str, password: str = None):
        """
        Exports a scan in a given format. Can then be downloaded by calling download_scan
        :param: export_format:      Format of the exported data. Must be valid per API.Scan.ExportFormats.VALID_FORMATS
        :param: password:           Password, required if downloading a Nessus DB
        """
        # Configure variables and default to CAT variables if not provided
        self.export_password = NessusConfig.CAT_NESSUS_DB_PASSWORD if password is None else password

        if export_format not in API.Scan.ExportFormats.VALID_FORMATS:
            raise CatiumAPIObjectError(f"Invalid Scan export format supplied: {export_format} not in "
                                       f"{API.Scan.ExportFormats.VALID_FORMATS}.")

        self.export_details = self.api.scans.export(scan_id=self.id, export_format=export_format,
                                                    password=self.export_password)
        if self.api.http_status_code == HTTPStatus.OK:
            self.export_file_id = self.export_details[0]
            wait_for_export_to_complete(api=self.api, scan_id=self.id, file_id=self.export_file_id)
            self.token_id = self.export_details[1]
        else:
            pytest.xfail(reason="[export_scan]: Unable to export the scan DB.")

        return {'file_id': self.export_details[0], 'uuid': self.export_details[1]}

    def get_hosts(self):
        self.hosts = {}
        self.get_scan_details()
        raw_hosts = self.scan_details["hosts"]
        for host in raw_hosts:
            self.hosts[host["host_id"]] = host

    def get_kb(self, host_id: int = None) -> dict:
        """
        Download Scan KB
        .. note:: This method returns the RAW file content as Bytes and can be written out to a file
        :param int scan_id: Scan ID
        :param int host_id: Host ID
        :return: Bytes
        :rtype: dict
        """

        if host_id is None:
            self.get_hosts()
            for host in self.hosts.keys():
                self.api.scans.prepare_kb(scan_id=self.id, host_id=host)
                self.hosts[host]["kb_file"] = self.api.scans.get_kb(scan_id=self.id, host_id=host)
        else:
            self.hosts[host_id]["kb_file"] = self.api.scans.get_kb(scan_id=self.id, host_id=host_id)

    def get_web_scanner_plugin_attachments(self):
        self.scan_result = self.api.scans.get_web_scanner_plugin_attachments(scan_id=self.id)

    def launch_scan(self):
        self.scan_result = None
        self.wait_for_scanner()
        self.api.scans.launch(self.id)
        assert self.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.api.http_status_code
        
        self.wait_for_scan_complete()

    def start_scan(self):
        self.scan_result = None
        self.wait_for_scanner()
        self.api.scans.launch(self.id)
        if self.api.http_status_code != HTTPStatus.OK:
            raise Exception('Expected 200, got %s instead.' % self.api.http_status_code)

        self.scan_result = wait_scan_state(api=self.api, scan_id=self.id, end_state=API.Scan.Status.RUNNING,
                                           timeout=TIME_THIRTY_MINUTES)

    def kill_scan(self):
        self.scan_result = None
        self.wait_for_scanner()
        self.api.scans.force_stop(self.id)
        if self.api.http_status_code != HTTPStatus.OK:
            raise Exception('Expected 200, got %s instead.' % self.api.http_status_code)

    def pause_scan(self):
        self.scan_result = None
        self.wait_for_scanner()
        self.api.scans.pause(self.id)
        assert self.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.api.http_status_code

        self.scan_result = wait_scan_state(api=self.api, scan_id=self.id, end_state=API.Scan.Status.PAUSED,
                                           timeout=TIME_THIRTY_MINUTES)
    
    def resume_scan(self):
        self.scan_result = None
        self.wait_for_scanner()
        self.api.scans.resume(self.id)
        assert self.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.api.http_status_code

        self.scan_result = wait_scan_state(api=self.api, scan_id=self.id, end_state=API.Scan.Status.RUNNING,
                                           timeout=TIME_THIRTY_MINUTES)
    
    def wait_for_scan_complete(self):
        self.scan_result = None
        self.wait_for_scanner()
        # self.api.scans.resume(self.id)
        assert self.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.api.http_status_code

        self.scan_result = wait_scan_state(api=self.api, scan_id=self.id, end_state=API.Scan.Status.COMPLETED,
                                           timeout=TIME_THIRTY_MINUTES)

    def scan_state(self):
        scans = self.api.scans.get_scans()['scans']
        assert self.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.api.http_status_code

        # Verify scan exists in list.
        return True if self.id in [scan['id'] for scan in scans] else False

    def update_scan_settings(self, settings_dict: dict):
        """
        Updates a scan's settings.
        :param settings_dict: Dictionary of settings and values to set them to.
        """
        payload = {"uuid": self.scan_model.uuid, "settings": {"name": self.name, "text_targets": self.scan_model.text_targets}}
        for key in settings_dict.keys():
            payload["settings"][key] = settings_dict[key]
        self.api.scans.configure(scan_id=self.id, payload=payload)
        assert self.api.http_status_code == HTTPStatus.OK, \
            f"Expected 200, got {self.api.http_status_code} instead."

    def update_scan_plugins(self, plugins_dict: dict):
        """
        Updates a scan's settings.
        :param plugins_dict: Dictionary of plugins and whether to set them as enabled or disabled.
        """
        payload = {"uuid": self.scan_model.uuid, "settings": {"name": self.name, "text_targets": self.scan_model.text_targets}, "plugins": {}}
        for key in plugins_dict.keys():
            payload["plugins"][key] = {"status": plugins_dict[key]}
        self.api.scans.configure(scan_id=self.id, payload=payload)
        assert self.api.http_status_code == HTTPStatus.OK, \
            f"Expected 200, got {self.api.http_status_code} instead."

    def wait_for_scanner(self, login: bool = False):
        if login:
            wait_for_scanner_login(self.api, NessusConfig.CAT_NESSUS_USERNAME, NessusConfig.CAT_NESSUS_PASSWORD,
                                   TIME_TEN_MINUTES, 'Waiting for scanner login to succeed')
        wait_for_scanner_status(api=self.api, status=API.Status.READY, timeout=TIME_TEN_MINUTES,
                                msg=Scanner.Strings.AVAILABILITY_OF_SCANNER, sleep_interval=WAIT_NORMAL)

