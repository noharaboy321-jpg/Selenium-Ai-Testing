"""
Nessus Scan Vulnerability Severity Base verifications

Test cases to verify scan's severity base feature

:copyright: Tenable Network Security, 2021
:date: Jan 18, 2021
:last_modified: July 29, 2024
:author: @vsoni, @kpanchal, @krpatel
"""
import csv
import io
import os
from http import HTTPStatus

import pdfplumber
import pytest
from _pytest.fixtures import SubRequest
from bs4 import BeautifulSoup
from waiting import wait

from catium.helpers.testdata import get_file_path, load_testdata
from catium.lib.const import TIME_THIRTY_MINUTES, TIME_SIXTY_SECONDS, WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_nessus_cli, stop_nessus, start_nessus
from nessus.helpers.scan import download_and_save_exported_scan_file, get_scan_report_template_id
from nessus.helpers.scan import get_severity_count_from_scan_result
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.config import NessusConfig
from nessus.lib.config import environment_variables as env_var
from nessus.lib.const import API, Nessus, OperatingSystems
from nessus.models.scan import ScanModel
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI
from tenableio.lib.config import TenableIOConfig

log = create_logger()


def get_severity_basis_value():
    """This function returns the fix parameter 'severity_basis' value"""
    with SSH() as ssh:
        output = ssh.execute("{} fix --get {}".format(get_nessus_cli(), 'severity_basis'))

    return None if any(["Could not retrieve value" in op for op in output]) else [
        op.split()[6].rstrip(".").strip("'") for op in output if "current value" in op][0]


def set_severity_basis_value(value: str, api: NessusAPI = NessusAPI(), restart: bool = True) -> None:
    """
    This function sets the severity basis value
    :param str value: severity_basis value which needs to be set
    :param NessusAPI api: Instance of NessusAPI
    :param bool restart: True if restart is required else False
    :return: None
    """
    with SSH() as ssh:
        ssh.execute("{} fix --set severity_basis={}".format(get_nessus_cli(), value))
    if restart:
        stop_nessus()
        start_nessus()
        wait_for_scanner_to_be_ready(api=api)

    assert get_severity_basis_value() == value, "Unable to set the value of severity basis."


@pytest.fixture()
def set_severity_basis(request: SubRequest):
    """This fixture sets the 'severity_basis' value"""
    severity_basis_new_value = request.param.get('value')
    severity_basis_value = get_severity_basis_value()

    if severity_basis_value != severity_basis_new_value or severity_basis_value is None:
        set_severity_basis_value(value=severity_basis_new_value, restart=False)

    return severity_basis_new_value


def verify_scan_results_updated_according_to_severity_base(nessus_api: NessusAPI, scan_id: str) -> tuple:
    """
    Verifies that scan results are getting updated after changing the severity base

    :param NessusAPI nessus_api: Nessus API instance
    :param str scan_id: Scan ID
    :return: scan result details based on severity base
    :rtype: tuple
    """
    scan_result_for_cvss_v2 = {}
    scan_result_for_cvss_v3 = {}

    for base_value in ['cvss_v2', 'cvss_v3']:
        severity_base_payload = {"severity_base": base_value}

        nessus_api.scans.update_severity_base(scan_id=scan_id, payload=severity_base_payload)

        assert nessus_api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % nessus_api.http_status_code

        # Get scan details
        scan_vulnerabilities = nessus_api.scans.details(scan_id)['vulnerabilities']

        assert nessus_api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % nessus_api.http_status_code

        severity_values = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        scan_results = {}

        for key in severity_values.keys():
            value = severity_values[key]
            count = sum(vuln['severity'] == value for vuln in scan_vulnerabilities)
            scan_results[key] = count

        if base_value == 'cvss_v2':
            scan_result_for_cvss_v2 = scan_results
        else:
            scan_result_for_cvss_v3 = scan_results

    return scan_result_for_cvss_v2, scan_result_for_cvss_v3


def verify_scan_result_severity_value_showing_based_on_instance_level_setting(nessus_api: NessusAPI,
                                                                              scan_id: str) -> tuple:
    """
    Verifies that scan result severity value is getting updated after changing the severity value from advanced
    setting

    :param NessusAPI nessus_api: Nessus API instance
    :param str scan_id: Scan ID
    :return: scan result details based on severity base
    :rtype: tuple
    """
    vulns_count_from_dashboard = {}

    scan_details = nessus_api.scans.details(scan_id)

    assert nessus_api.http_status_code == HTTPStatus.OK, \
        'Expected 200, got %s instead.' % nessus_api.http_status_code

    scan_result_vulns_count = get_severity_count_from_scan_result(scan_vuln_result=scan_details['vulnerabilities'])

    severity_values = {Nessus.Scan.Severity.LOW: 1, Nessus.Scan.Severity.MEDIUM: 2, Nessus.Scan.Severity.HIGH: 3,
                       Nessus.Scan.Severity.CRITICAL: 4}

    for severity in severity_values.keys():
        vulns_count_from_dashboard[severity] = scan_details['hosts'][0][severity.lower()]

    return scan_result_vulns_count, vulns_count_from_dashboard


@pytest.mark.usefixtures('wait_for_plugin_families_to_be_available')
class TestScanSeverityBase:
    """Test cases related to Scan Severity Base in Nessus"""
    cat = None

    @pytest.mark.nessus_manager
    @pytest.mark.skip_rhel8
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_scan_vulns_are_based_on_instance_level_setting_for_completed_scan(self, create_scan, test_data_file):
        """
        NES-12659: Verify Scan results are showing vulns based on instance level setting for completed and imported scan

        Scenario Tested:
        [x] Make sure Vulnerability of New scans should show the severity based on current system level.
        [x] Verify setting value reflected on all places if modified from advanced setting
        """
        scan_id = create_scan['scan']['id']

        payload = load_testdata(test_data_file['scan_json_path'])
        payload["settings"]["use_dashboard"] = True

        self.cat.api.scans.configure(scan_id, payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        self.cat.api.scans.launch(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

        scan_result_vulns_count, vulns_count_from_dashboard = \
            verify_scan_result_severity_value_showing_based_on_instance_level_setting(nessus_api=self.cat.api,
                                                                                      scan_id=scan_id)

        assert scan_result_vulns_count == vulns_count_from_dashboard, \
            "Vulnerability count of scan result and the count displayed on dashboard are different."


    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.nessus_manager
    @pytest.mark.flaky_test
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v3'}, {'value': 'cvss_v2'}], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_verify_created_scan_severity_base(self, create_scan, set_severity_basis):
        """
        NES-12485: [Automation] Verify new scans are showing vulnerabilities severity based on instance level setting

        Scenarios tested:
            [x] Verify that correct severity base populated in created scan result
        """
        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id)
        self.cat.api.scans.details(scan_id=scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)
        scan_details = self.cat.api.scans.details(scan_id=scan_id)
        assert scan_details['info']['current_severity_base'] == set_severity_basis, \
            "Severity base populated incorrectly."
        assert scan_details['vulnerabilities'], "Vulnerabilities are empty."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.nessus_manager
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v3'}, {'value': 'cvss_v2'}], indirect=True)
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_verify_imported_scan_severity_base(self, set_severity_basis, import_scan):
        """
        NES-12486: [Automation] Verify imported scans are showing vulnerabilities severity
                   based on instance level setting

        Scenarios tested:
            [x] Verify that correct severity base populated in imported scan result
        """
        scan_details = self.cat.api.scans.details(import_scan)
        assert scan_details['info']['current_severity_base'] == set_severity_basis, \
            "Severity base populated incorrectly."
        assert scan_details['vulnerabilities'], "Vulnerabilities are empty."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.nessus_manager
    @pytest.mark.flaky_test
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v3'}, {'value': 'cvss_v2'}], indirect=True)
    @pytest.mark.parametrize('export_format', [API.Scan.ExportFormats.FORMAT_NESSUS, API.Scan.ExportFormats.FORMAT_DB])
    def test_verify_exported_scan_with_plugin_recast_can_be_imported_with_expected_vulnerabilities(
            self, create_scan, export_format, create_tenable_io_container, set_severity_basis):
        """
        NES-12494: [Automation] Verify user can export scan report in .nessus and .db successfully
        NES-12725: [API-Automation] : Verify imported scan' severity is reflected as per applied plugin rules
                   while exporting the scan
        Scenarios tested:
            [x] Verify that user can import scan using the exported scan with severity_basis set.
            [x] Verify after importing scan , user will get the severity as per the new plugin rule set
                before exporting the scan (Applicable to ".db" formats only and not for ".nessus" format).
        """
        scan_id = create_scan['scan']['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)

        scan_details = self.cat.api.scans.details(scan_id=scan_id)
        plugin_id = scan_details['vulnerabilities'][0]['plugin_id']
        host_id = scan_details['hosts'][0]['host_id']
        original_severity = self.cat.api.scans.get_host_vulnerability(
            host_id=host_id, plugin_id=plugin_id, scan_id=scan_id)['info']['plugindescription']['severity']
        # Update the severity
        payload = {'type': API.Severity.CRITICAL, 'host': scan_details['hosts'][0]['hostname']}
        self.cat.api.scans.update_plugin_severity(scan_id=scan_id, plugin_id=plugin_id, payload=payload)
        export_import_password = "nessus" if export_format == API.Scan.ExportFormats.FORMAT_DB else None
        export = self.cat.api.scans.export(scan_id=scan_id, export_format=export_format,
                                           password=export_import_password)

        # wait for to get ready state and max wait for 30 sec
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='export status to get %s' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        file_name = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(scan_id))

        download_and_save_exported_scan_file(file_path=file_name, api=self.cat.api, file_format="." + export_format,
                                             scan_id=scan_id, file_id=export[0])

        file_uploaded_nessus = self.cat.api.file.upload(file=file_name + "." + export_format, encrypted=True)
        import_scan = self.cat.api.scans.import_scan(file_uploaded_nessus, folder_id=None,
                                                     password=export_import_password)
        assert import_scan['scan']['id'], "Scan does not imported successfully in nessus"
        imported_scan_details = self.cat.api.scans.details(import_scan['scan']['id'])
        assert imported_scan_details['info']['current_severity_base'] == \
               set_severity_basis, "Severity base populated incorrectly in Nessus."

        # Verify that plugin severity is updated for ".db" file and same for ".nessus" file
        updated_severity = self.cat.api.scans.get_host_vulnerability(
            host_id=imported_scan_details['hosts'][0]['host_id'], plugin_id=plugin_id,
            scan_id=import_scan['scan']['id'])['info']['plugindescription']['severity']
        expected_severity = 4
        assert updated_severity == expected_severity, "The imported scan's plugin severity is not as expected."

        tenable_api = TenableCloudAPI(url=TenableIOConfig.CAT_TIO_URL)
        tenable_api.login(username=create_tenable_io_container['container'].model.contact,
                          password=create_tenable_io_container['container'].model.password)
        file_uploaded_tio = tenable_api.file.upload(file_name + "." + export_format, encrypted=True)
        import_scan = tenable_api.scans.import_scan(file=file_uploaded_tio, password=export_import_password)
        assert import_scan['scan']['id'], "Scan does not imported successfully in Tenable.io"

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.nessus_manager
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('import_scan', [{
        'scan': {"filename": 'Engine_Test_-_Compliance_Targeted_qo3sdk.nessus'}}], indirect=True)
    @pytest.mark.parametrize('plugin_name', ['Microsoft Windows SMB Log In Possible'])
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v3'}], indirect=True)
    def test_scan_vulnerability_for_cvss_v2_based_plugins(self, import_scan, plugin_name, set_severity_basis):
        """
        NES-12492: [Automation] Verify Nessus defaults to cvss_v2 when v3 is not available

        Scenarios tested:
            [x] Verify Nessus defaults to cvss_v2 when v3 is not available
        """
        scan_details = self.cat.api.scans.details(import_scan)
        assert scan_details['info']['current_severity_base'] == set_severity_basis, \
            "Severity base populated incorrectly."
        plugin_id = [vulnerability for vulnerability in scan_details['vulnerabilities'] if
                     vulnerability['plugin_name'] == plugin_name][0]['plugin_id']
        plugin_info = self.cat.api.scans.vulnerabilities(scan_id=import_scan, plugin_id=plugin_id)['info'][
            'plugindescription']['pluginattributes']['risk_information']
        cvss_attributes = ['cvss3_base_score', 'cvss3_temporal_vector', 'cvss3_temporal_score', 'cvss3_vector']
        assert all([True if field not in list(plugin_info.keys()) else False for field in cvss_attributes]), \
            "CVSS V3 related information populated in given plugin."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v3'}], indirect=True)
    @pytest.mark.parametrize('new_severity_basis_value', ['cvss_v2'])
    def test_verify_severity_base_change_works_for_user_defined_scans(self, create_policy, set_severity_basis,
                                                                      new_severity_basis_value):
        """
        NES-12660 : [API-Automation] Verify that severity_base can be changed for user defined scans

        Scenario Tested:
            [x] Verify that severity_base can be changed for user defined scans
        """
        config = {'policy_id': create_policy['policy_id'], 'text_targets': Nessus.Scan.Target.LOCALHOST}
        scan_id = self.cat.api.scans.create(ScanModel(name=random_name(prefix="automation-scan-"), **config))[
            'scan']['id']
        self.cat.api.scans.launch(scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)
        self.cat.api.scans.update_severity_base(scan_id=scan_id, payload={"severity_base": new_severity_basis_value})

        # Verify that severity successfully changed for user defined scan
        assert self.cat.api.scans.details(scan_id)['info']['current_severity_base'] == new_severity_basis_value, \
            "Severity base populated incorrectly."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.flaky_test
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v3'}], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    @pytest.mark.parametrize('new_severity_base_value', ['cvss_v2'])
    @pytest.mark.parametrize('override_system_severity', [True, False])
    def test_verify_already_completed_scan_severity_base_changes(self, create_scan, set_severity_basis,
                                                                 new_severity_base_value, override_system_severity):
        """
        NES-12651 : [API-Automation] Verify that scan level severity base changes as per expected value

        Scenario Tested:
            [x] Verify that already completed scan's severity base value does not change as per instance level value
                when system value is overridden from created scan result page
            [x] Verify that already completed scan's severity base value changes as per instance level value change when
                system value is overridden from created scan result page
        """
        scan = create_scan['scan']
        scan_id = scan['id']
        # Launch scan and wait till scan gets completed
        self.cat.api.scans.launch(scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)
        original_severity_base = self.cat.api.scans.details(scan_id=scan_id)['info']['current_severity_base']

        if override_system_severity:
            self.cat.api.scans.update_severity_base(scan_id=scan_id, payload={"severity_base": "cvss_v3"})
        set_severity_basis_value(value=new_severity_base_value, api=self.cat.api, restart=True)
        assert get_severity_basis_value() == new_severity_base_value, "Severity_base value not changed to cvss_v2"
        scan_details = self.cat.api.scans.details(scan_id=scan_id)

        if override_system_severity:
            assert scan_details['info']['current_severity_base'] == original_severity_base != new_severity_base_value, \
                "Completed scan's severity base value has been changed by instance level change " \
                "even after scan level value has been overridden."
        else:
            assert scan_details['info']['current_severity_base'] == new_severity_base_value != original_severity_base, \
                "Completed scan's severity base value has not been changed by instance level change."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.flaky_test
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v3'}], indirect=True)
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    @pytest.mark.parametrize('new_severity_base_value', ['cvss_v2'])
    @pytest.mark.parametrize('override_system_severity', [True, False])
    def test_verify_imported_scan_severity_base_changes(self, import_scan, set_severity_basis, new_severity_base_value,
                                                        override_system_severity):
        """
        NES-12651 : [API-Automation] Verify that scan level severity base changes as per expected value

        Scenario Tested:
            [x] Verify that imported scan's severity base value does not change as per instance level value
                when system value is overridden from created scan result page
            [x] Verify that imported scan's severity base value changes as per instance level value change when
                system value is overridden from created scan result page
        """
        original_severity_base = self.cat.api.scans.details(import_scan)['info']['current_severity_base']
        if override_system_severity:
            self.cat.api.scans.update_severity_base(scan_id=import_scan, payload={"severity_base": "cvss_v3"})

        set_severity_basis_value(value=new_severity_base_value, api=self.cat.api, restart=True)
        assert get_severity_basis_value() == new_severity_base_value, ""

        scan_details = self.cat.api.scans.details(import_scan)
        if override_system_severity:
            assert scan_details['info']['current_severity_base'] == original_severity_base != new_severity_base_value, \
                "Imported scan's severity base value has been changed by instance level change " \
                "even after scan level value has been overridden."
        else:
            assert scan_details['info']['current_severity_base'] == new_severity_base_value != original_severity_base, \
                "Imported scan's severity base value has not been changed by instance level change."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.nessus_manager
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v3'}], indirect=True)
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'CVSS_filters_i32539.nessus'}}], indirect=True)
    @pytest.mark.parametrize('filter_data', [
        {'query': '?filter.0.quality=lt&filter.0.filter=cvss_base_score&filter.0.value=7&filter.search_type=and',
         'output': {'hosts': ['172.26.48.10', '172.26.48.16', '172.26.48.15', '172.26.48.14', '172.26.48.13',
                              '172.26.48.12', '172.26.48.11'],
                    'vulnerabilities': [10114, 30218, 70658, 57690, 18405, 10595, 12217, 78479, 89058, 57608, 58453,
                                        57582, 104743, 65821, 51192, 142960, 35291, 42873]}},
        {'query': '?filter.0.quality=gt&filter.0.filter=cvss_temporal_score&filter.0.value=4.8&filter.search_type=and',
         'output': {'hosts': ['172.26.48.10'], 'vulnerabilities': [138554]}},
        {'query': '?filter.0.quality=nmatch&filter.0.filter=cvss_vector&filter.0.value=CVSS2&filter.search_type=and',
         'output': {'hosts': [], 'vulnerabilities': []}},
        {'query': '?filter.0.quality=match&filter.0.filter=cvss_temporal_vector&filter.0.value=E:H/RL:OF/RC:C&filter.'
                  'search_type=and', 'output': {'hosts': ['172.26.48.10'], 'vulnerabilities': [138554]}},
        {'query': '?filter.0.quality=lt&filter.0.filter=cvss3_base_score&filter.0.value=5&filter.search_type=and',
         'output': {'hosts': ['172.26.48.10', '172.26.48.16', '172.26.48.15', '172.26.48.14', '172.26.48.13',
                              '172.26.48.12', '172.26.48.11'], 'vulnerabilities': [10114, 58453]}},
        {'query': '?filter.0.quality=nmatch&filter.0.filter=cvss3_temporal_score&filter.0.value=5.0&filter.search_type'
                  '=and', 'output': {'hosts': ['172.26.48.10', '172.26.48.16', '172.26.48.15', '172.26.48.13'],
                                     'vulnerabilities': [78479, 89058, 57608, 65821, 35291, 138554]}},
        {'query': '?filter.0.quality=eq&filter.0.filter=cvss3_vector&filter.0.value=CVSS%3A3.0%2FAV%3AN%2FAC%3AH%2FPR%'
                  '3AN%2FUI%3AN%2FS%3AU%2FC%3AH%2FI%3AH%2FA%3AN&filter.search_type=and',
         'output': {'hosts': ['172.26.48.15'], 'vulnerabilities': [142960]}},
        {'query': '?filter.0.quality=match&filter.0.filter=cvss3_temporal_vector&filter.0.value=E:P/RL:O/RC:C&filter.'
                  'search_type=and', 'output': {'hosts': ['172.26.48.10'], 'vulnerabilities': [35291]}},
        {'query': '?filter.0.quality=lt&filter.0.filter=cvss_base_score&filter.0.value=7&filter.1.quality=gt&filter.1.'
                  'filter=cvss3_base_score&filter.1.value=7&filter.search_type=and',
         'output': {'hosts': ['172.26.48.10', '172.26.48.16', '172.26.48.15', '172.26.48.13'],
                    'vulnerabilities': [142960, 35291, 42873]}},
        {'query': '?filter.0.quality=lt&filter.0.filter=cvss_temporal_score&filter.0.value=4.3&filter.1.quality=gt&'
                  'filter.1.filter=cvss3_temporal_score&filter.1.value=4.3&filter.search_type=and',
         'output': {'hosts': ['172.26.48.10', '172.26.48.16', '172.26.48.15', '172.26.48.13'],
                    'vulnerabilities': [78479, 89058, 57608, 65821, 35291]}},
        {'query': '?filter.0.quality=match&filter.0.filter=cvss_vector&filter.0.value=CVSS2&filter.1.quality=nmatch&'
                  'filter.1.filter=cvss3_vector&filter.1.value=CVSS3&filter.search_type=and',
         'output': {'hosts': ['172.26.48.10', '172.26.48.16', '172.26.48.15', '172.26.48.14', '172.26.48.13',
                              '172.26.48.12', '172.26.48.11'],
                    'vulnerabilities': [10114, 12217, 78479, 89058, 57608, 58453, 104743, 65821, 51192, 142960, 20007,
                                        35291, 42873, 108797, 34460, 138554]}},
        {'query': '?filter.0.quality=lt&filter.0.filter=cvss3_base_score&filter.0.value=9&filter.1.quality=gt&filter.1.'
                  'filter=cvss3_base_score&filter.1.value=7&filter.search_type=and',
         'output': {'hosts': ['172.26.48.10', '172.26.48.16', '172.26.48.15', '172.26.48.13'],
                    'vulnerabilities': [142960, 20007, 35291, 42873]}}])
    def test_verify_cvss2_and_cvss3_related_filters_inside_scan_result(self, import_scan, filter_data):
        """
        NES-12676 : [API-Automation] : Verify that CVSS2.0 and CVSS 3.0 related  filters are working fine
                    in vulnerabilities and hosts sections
        Scenario tested:
            Verify that hosts and vulnerabilities are populated correctly when below filters are applied.
            [x] 'CVSS2 Base Score' is less than 7
            [x] 'CVSS2 Temporal Score' is greater than 4.8
            [x] 'CVSS2 Vector' does not contain 'CVSS2'
            [x] 'CVSS2 Temporal Vector' contains 'E:H/RL:OF/RC:C'
            [x] 'CVSS3 Base Score' is less than 5
            [x] 'CVSS3 Temporal Score' does not contain 5.0
            [x] 'CVSS3 Vector' equal to 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N'
            [x] 'CVSS3 Temporal Vector' contains 'E:H/RL:OF/RC:C'
            [x] 'CVSS2 Base Score' is less than 7 and 'CVSS3 Base Score' is greater than 7.
            [x] 'CVSS2 Temporal Score' is less than 4.3 and 'CVSS2 Temporal Score' is greater than 4.3
            [x] 'CVSS2 Vector' contains 'CVSS2' and 'CVSS3 Vector' does not contains 'CVSS3'
            [x] 'CVSS3 Base Score' is greater than 7 and less than 9.
        """
        scan_details = self.cat.api.scans.details(scan_id=import_scan, query=filter_data['query'])
        # Verify that hosts are populated correctly
        assert filter_data.get('output').get('hosts') == [host['hostname'] for host in scan_details['hosts']], \
            "Filtered hosts in scan result are incorrect for given query."

        # Verify that vulnerabilities are populated correctly.
        assert set(filter_data.get('output').get('vulnerabilities')).issubset([
            plugin['plugin_id'] for plugin in scan_details['vulnerabilities']]), \
            "Filtered vulnerabilities in scan result are incorrect for given query."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.flaky_test
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'CVSS_filters_i32539.nessus'}}], indirect=True)
    @pytest.mark.parametrize('filter_data', [
        {'query': '?filter.0.quality=neq&filter.0.filter=severity&filter.0.value=0&filter.1.quality=neq&filter.1.'
                  'filter=severity&filter.1.value=2&filter.search_type=and',
         'cvss3_output': {'hosts': ['172.26.48.10', '172.26.48.16', '172.26.48.15', '172.26.48.13', '172.26.48.12'],
                          'vulnerabilities': [30218, 70658, 78479, 20007, 35291, 42873, 108797, 34460, 138554]},
         'cvss2_output': {'hosts': ['172.26.48.10', '172.26.48.12'],
                          'vulnerabilities': [30218, 70658, 34460, 20007, 108797, 138554]}},
        {'query': '?filter.0.quality=eq&filter.0.filter=severity&filter.0.value=4&filter.search_type=and',
         'cvss3_output': {'hosts': ['172.26.48.10'], 'vulnerabilities': [108797, 34460, 138554,20007]},
         'cvss2_output': {'hosts': ['172.26.48.10'], 'vulnerabilities': [108797, 138554]}}])
    def test_verify_severities_filter_as_per_the_severity_base_selected(self, import_scan, filter_data):
        """
        NES-12695: [API-Automation] Verify the filter 'severity' is working at hosts and vulnerabilities
                   after severity basis change

        Scenario Tested:
            Verify that hosts and vulnerabilities getting populated correctly with below filters and
            when 'Severity Base' is selected to 'CVSS V2' or 'CVSS V3'
            [x] 'Severity' is not "None" or "Medium"
            [x] 'Severity' is "Critical"
        """
        # Update the scan's severity to "CVSS V3".
        self.cat.api.scans.update_severity_base(scan_id=import_scan, payload={"severity_base": "cvss_v3"})

        scan_details = self.cat.api.scans.details(scan_id=import_scan, query=filter_data['query'])
        # Verify that hosts and vulnerabilities are populated correctly when severity_base is set to "CVSS_V3'.
        assert filter_data.get('cvss3_output').get('hosts') == [host['hostname'] for host in scan_details['hosts']], \
            "Filtered hosts in scan result are incorrect for given query."
        assert set([plugin['plugin_id'] for plugin in scan_details['vulnerabilities']]).issubset(set(
            filter_data.get('cvss3_output').get('vulnerabilities'))), \
            "Filtered vulnerabilities in scan result are incorrect for given query."

        # Update the scan's severity to "CVSS V2".
        self.cat.api.scans.update_severity_base(scan_id=import_scan, payload={"severity_base": "cvss_v2"})
        scan_details = self.cat.api.scans.details(scan_id=import_scan, query=filter_data['query'])

        # Verify that hosts and vulnerabilities are populated correctly when severity_base is set to "CVSS_V3'.
        assert filter_data.get('cvss2_output').get('hosts') == [host['hostname'] for host in scan_details['hosts']], \
            "Filtered hosts in scan result are incorrect for given query."
        assert set(filter_data.get('cvss2_output').get('vulnerabilities')).issubset([
            plugin['plugin_id'] for plugin in scan_details['vulnerabilities']]), \
            "Filtered vulnerabilities in scan result are incorrect for given query."

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.flaky_test
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('import_scan', [{'scan': {'filename': 'Basic_Network_Scan_g5br3m.nessus'}}], indirect=True)
    def test_severity_base_can_be_changed_for_completed_scan(self, import_scan):
        """
        NES-12487: [Automation] Verify user is able to switch severity base on a completed scan
        Scenario Tested:
        [x] Verify user is able to switch severity base on a completed scan.
        [x] Verify that scan results are updated appropriately
        """
        if env_var.NESSUS_PLATFORM == OperatingSystems.LINUX:
            with SSH() as ssh:
                check_installed_os = ssh.execute(command='cat /etc/os-release')
            installed_os = check_installed_os[0].split('=')[1].split()[0].strip('"')
            log.debug("Installed OS :: {}".format(installed_os))

            if installed_os == "Kali":
                pytest.xfail("We are getting only info level vulnerabilities in scan results while running scan "
                             "against localhost or AWS targets in 'Kali' OS. Hence, skipped for 'Kali' OS only.")

        scan_id = import_scan
        scan_result_for_cvss_v2, scan_result_for_cvss_v3 = verify_scan_results_updated_according_to_severity_base(
            nessus_api=self.cat.api, scan_id=scan_id)

        assert scan_result_for_cvss_v2 != scan_result_for_cvss_v3, \
            "Scan results are not getting updated according to severity base."

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.flaky_test
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('import_scan', [{'scan': {'filename': 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_severity_base_can_be_changed_for_imported_scan(self, import_scan):
        """
        NES-12488: [Automation] Verify user is able to change severity on an imported scan

        Scenario Tested:
        [x] Verify user is able to change severity on an imported scan.
        [x] Verify that scan results are updated appropriately
        """
        scan_id = import_scan

        scan_result_for_cvss_v2, scan_result_for_cvss_v3 = verify_scan_results_updated_according_to_severity_base(
            nessus_api=self.cat.api, scan_id=scan_id)

        assert scan_result_for_cvss_v2 != scan_result_for_cvss_v3, \
            "Scan results are not getting updated according to severity base."

    @pytest.mark.xray(test_key='NES-18126')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.skip_rhel8
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    @pytest.mark.parametrize('severity_base_value', ['cvss_v2', 'cvss_v3', 'cvss_v4'])
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML,
                                               API.Scan.ExportFormats.FORMAT_CSV])
    def test_scan_report_exported_based_on_selected_severity_base(self, create_scan, severity_base_value,
                                                                  report_format):
        """
        NES-12490: [Automation] Verify exported scan report is based on selected severity base
        NES-18126: Verify the reports contain correct cvss v4 data.

        Scenario Tested:
        [x] Verify exported scan report is based on selected severity base
            - HTML/PDF/CSV
            - Custom
            - Executive summary
        """
        scan_id = create_scan['scan']['id']

        self.cat.api.scans.launch(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES), "Scan failed to complete."

        self.cat.api.scans.update_severity_base(scan_id=scan_id, payload={"severity_base": severity_base_value})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_vulnerabilities = self.cat.api.scans.details(scan_id)['vulnerabilities']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_results = get_severity_count_from_scan_result(scan_vuln_result=scan_vulnerabilities)

        template_id = get_scan_report_template_id(api=self.cat.api,
                                                  template_name="Complete List of Vulnerabilities by Host")
        template_id = template_id if report_format in [API.Scan.ExportFormats.FORMAT_PDF,
                                                       API.Scan.ExportFormats.FORMAT_HTML] else None
        expected_scan_result = {}

        export = self.cat.api.scans.export(scan_id=scan_id, export_format=report_format, template_id=template_id)

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get "%s" state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert download, "Exported file was not downloaded."

        file_path = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(scan_id))
        file_mode = 'r' if report_format == API.Scan.ExportFormats.FORMAT_CSV else 'rb'

        if report_format == API.Scan.ExportFormats.FORMAT_CSV:
            csv_file = io.StringIO(download.content.decode('utf-8'))
            raw_data = [raw for raw in csv.reader(csv_file, delimiter=',', quotechar='"', escapechar='\\')]

            for severity in [Nessus.Scan.Severity.CRITICAL, Nessus.Scan.Severity.HIGH, Nessus.Scan.Severity.MEDIUM,
                             Nessus.Scan.Severity.LOW]:
                count = 0

                for row in raw_data:
                    if row[3] == severity:
                        count += 1

                expected_scan_result[severity] = count

        else:
            with open(file_path + ".{}".format(report_format), "wb") as file:
                for block in download.iter_content(1024):
                    file.write(block)
                file.close()

            expected_vuln_list = []

            if report_format == API.Scan.ExportFormats.FORMAT_HTML:
                with open(file_path + ".{}".format(report_format), mode=file_mode) as file_obj:
                    soup = BeautifulSoup(file_obj.read())

                    for tr in soup.find("tbody").find_all('tr'):
                        for td in tr.find_all('td'):
                            expected_vuln_list.append(td.text)

                    expected_scan_result = {expected_vuln_list[i + 5].capitalize(): int(expected_vuln_list[i])
                                            for i in range(0, 4)}
            elif report_format == API.Scan.ExportFormats.FORMAT_PDF:
                pdf_reader = pdfplumber.open(file_path + ".{}".format(report_format))
                try:
                    page_data = pdf_reader.pages[3].extract_text().split('\n')
                    vulns_index = page_data.index('CRITICAL HIGH MEDIUM LOW INFO') - 1
                    expected_scan_result = {page_data[vulns_index + 1].split()[i].capitalize(): int(
                        page_data[vulns_index].split()[i]) for i in range(0, 4)}
                finally:
                    pdf_reader.close()

        assert scan_results == expected_scan_result, "Scan report is not getting exported in '{}' format based " \
                                                     "on selected severity base.".format(report_format)

        if report_format != API.Scan.ExportFormats.FORMAT_CSV:
            os.remove(file_path + ".{}".format(report_format))

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_severity_base_can_be_updated_in_particular_scan_history(self, create_scan):
        """
        NES-12489: [Automation] Verify user can change severity base on a particular scan history

        Scenario Tested:
        [x] Verify user can change severity base on a particular scan history.
        [x] Verify that only scan results of that history is updated, and other histories are no affected.
        """
        severity_base_list = ['cvss_v2', 'cvss_v3']
        scan_id = create_scan['scan']['id']

        for _ in range(2):
            self.cat.api.scans.launch(scan_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                   timeout=TIME_THIRTY_MINUTES), "Scan failed to complete."

        scan_details = self.cat.api.scans.details(scan_id)
        scan_history_1_id = scan_details['history'][0]['history_id']
        scan_history_2_id = scan_details['history'][1]['history_id']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert len(scan_details['history']) > 1, "Expected more than one history should be there, got only 1 or less."

        history_1_details = self.cat.api.scans.get_scan_result_history(scan_id=scan_id, history_id=scan_history_1_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        severity_base_before_update = history_1_details['info']['current_severity_base']
        severity_base_list.remove(severity_base_before_update)

        self.cat.api.scans.update_severity_base(scan_id=scan_id, history_id=scan_history_1_id,
                                                payload={"severity_base": severity_base_list[0]})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        history_1_details = self.cat.api.scans.get_scan_result_history(scan_id=scan_id, history_id=scan_history_1_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        severity_base_after_update = history_1_details['info']['current_severity_base']

        assert severity_base_before_update != severity_base_after_update, \
            "Failed to update the severity base of particular history of scan result."

        history_2_details = self.cat.api.scans.get_scan_result_history(scan_id, scan_history_2_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert severity_base_after_update != history_2_details['info']['current_severity_base'], \
            "Updated severity base is affected to other history of scan result too."

        assert severity_base_after_update != scan_details['info']['current_severity_base'], \
            "Updated severity base is also affected to the scan results severity base."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.skip_rhel8
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    @pytest.mark.parametrize('severity_base_value', ['cvss_v2', 'cvss_v3'])
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML,
                                               API.Scan.ExportFormats.FORMAT_CSV])
    def test_verify_severity_column_title_should_based_on_selected_severity_base(
            self, create_scan, severity_base_value, report_format):
        """
        NES-12544: [Automation] Verify exported scan report table column showing v2 or v3 for cvss column
        NES-12889: [API-Automation] Verify executive scan reports contains column related to severities base (HTML, PDF)

        Scenario Tested:
        [x] Verify severity column title should be based on selected severity base in exported report
        [x] Verify executive scan reports contains column related to severities base (HTML, PDF)
        """
        scan_id = create_scan['scan']['id']

        self.cat.api.scans.launch(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES), "Scan failed to complete."

        self.cat.api.scans.update_severity_base(scan_id=scan_id, payload={"severity_base": severity_base_value})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        template_id = get_scan_report_template_id(api=self.cat.api,
                                                  template_name="Complete List of Vulnerabilities by Host")
        expected_severity_column_name = []

        template_id = template_id if report_format in [API.Scan.ExportFormats.FORMAT_PDF,
                                                       API.Scan.ExportFormats.FORMAT_HTML] else None

        export = self.cat.api.scans.export(scan_id=scan_id, export_format=report_format, template_id=template_id)

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get "%s" state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert download, "Exported file was not downloaded."

        file_path = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(scan_id))

        if report_format == API.Scan.ExportFormats.FORMAT_CSV:
            csv_file = io.StringIO(download.content.decode('utf-8'))
            raw_data = csv.reader(csv_file, delimiter=',', quotechar='"', escapechar='\\')
            expected_severity_column_name = list(raw_data)[0]
        else:
            with open(file_path + ".{}".format(report_format), "wb") as file:
                for block in download.iter_content(1024):
                    file.write(block)
                file.close()

            file_mode = 'r' if report_format == API.Scan.ExportFormats.FORMAT_CSV else 'rb'

            with open(file_path + ".{}".format(report_format), mode=file_mode) as file_obj:
                html_content = BeautifulSoup(file_obj.read())

            if report_format == API.Scan.ExportFormats.FORMAT_PDF:
                pdf_reader = pdfplumber.open(file_path + ".{}".format(report_format))
                try:
                    for page_num in range(len(pdf_reader.pages)):
                        page_data = pdf_reader.pages[page_num].extract_text()

                        if 'Total' in page_data:
                            expected_severity_column_name = [page_column.replace("\n", " ") for page_column in
                                                             pdf_reader.pages[page_num].extract_table()[0]]
                finally:
                    pdf_reader.close()

        expected_column_title = 'CVSS v2.0 Base Score' if report_format == API.Scan.ExportFormats.FORMAT_CSV else \
            severity_base_value.upper().replace('_', ' ') + '.0'

        if report_format == API.Scan.ExportFormats.FORMAT_HTML:
            assert expected_column_title == html_content.body.find_all(expected_column_title).source.name, \
                "Severity column title is not showing based on selected severity base for '{}' report " \
                "format.".format(report_format)
        else:
            assert expected_column_title in expected_severity_column_name, \
                "Severity column title is not showing based on selected severity base for '{}' report " \
                "format.".format(report_format)
        if report_format != API.Scan.ExportFormats.FORMAT_CSV:
            os.remove(file_path + ".{}".format(report_format))


    @pytest.mark.nessus_manager
    @pytest.mark.jira('NES-17105: fix will be added later')
    @pytest.mark.xfail(reason='NES-17097: expected behavior')
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('import_scan', [{'scan': {'filename': 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_scan_vulns_are_based_on_instance_level_setting_for_imported_scan(self, import_scan):
        """
        NES-12659: Verify Scan results are showing vulns based on instance level setting for completed and imported scan

        Scenario Tested:
        [x] Make sure Vulnerability of imported scans should show the severity based on current system level.
        [x] Verify setting value reflected on all places if modified from advanced setting
        """
        scan_id = import_scan

        self.cat.api.scans.enable_dashboard(scan_id=scan_id, enabled=True)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_result_vulns_count, vulns_count_from_dashboard = \
            verify_scan_result_severity_value_showing_based_on_instance_level_setting(nessus_api=self.cat.api,
                                                                                      scan_id=scan_id)

        assert scan_result_vulns_count == vulns_count_from_dashboard, \
            "Vulnerability count of scan result and the count displayed on dashboard are different."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'Scan_DB_System_Default_9dgvs9.db',
                                                       "password": "nessus", "encrypted": True}},
                                             {'scan': {"filename": 'Scan_DB_V2_l03wgk.db',
                                                       "password": "admin", "encrypted": True}},
                                             {'scan': {"filename": 'Scan_DB_V3_mi3s4i.db',
                                                       "password": "nessus", "encrypted": True}},
                                             {'scan': {"filename": 'Scan_nessus_system_default_kb6lpv.nessus'}},
                                             {'scan': {"filename": 'Scan_nessus_V2_oio7yd.nessus'}},
                                             {'scan': {"filename": 'Scan_nessus_V3_nfoat0.nessus'}}], indirect=True)
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v3'}, {'value': 'cvss_v2'}], indirect=True)
    def test_verify_imported_db_scan_severity_base(self, import_scan, set_severity_basis):
        """
        NES-12696 : [API-Automation] Verify severity base populated correctly for imported scan with .nessus file
        NES-12697 : [API-Automation] Verify severity base populated correctly for imported scan with .db file

        Pre-conditions:
            [x] Scan severity in Scan_DB_System_Default_9dgvs9.db is set to 'system default'.
            [x] Scan severity in Scan_DB_V2_l03wgk.db is set to 'cvss_v2'.
            [x] Scan severity in Scan_DB_V3_mi3s4i.db is set to 'cvss_v3'.
            [x] Scan severity in Scan_nessus_system_default_kb6lpv.nessus is set to 'system default'.
            [x] Scan severity in Scan_nessus_V2_oio7yd.nessus is set to 'cvss_v2'.
            [x] Scan severity in Scan_nessus_V3_nfoat0.nessus is set to 'cvss_v3'.

        Scenario Tested:
            [x] If severity_base is set to 'cvss_v2' While exporting scan file in .db format then scan severity will be
                'cvss_v2' if same scan file imported (irrespective of system severity set to 'cvss_v2' or 'cvss_v3').
            [x] If severity_base is set to 'cvss_v3' While exporting scan file in .db format then scan severity will be
                'cvss_v3' if same scan file imported (irrespective of system severity set to 'cvss_v2' or 'cvss_v3').
            [x] If severity_base is set to 'system default' While exporting scan file in .db format then
                scan severity will be 'cvss_v2' or 'cvss_v3' if same scan file imported
                (same as system severity set in nessus).
            [x] If user imports '.nessus' file in nessus then scan's severity_base
                will always set as system severity in Nessus.
        """
        scan_details = self.cat.api.scans.details(import_scan)
        scan_name = scan_details['info']['name']
        expected_severity_base = ''
        if 'nessus' not in scan_name.lower():
            if 'v3' in scan_name.lower() and set_severity_basis in ['cvss_v3', 'cvss_v2']:
                expected_severity_base = 'cvss_v3'
            elif 'v2' in scan_name.lower() and set_severity_basis in ['cvss_v3', 'cvss_v2']:
                expected_severity_base = 'cvss_v2'
            elif 'default' in scan_name.lower():
                expected_severity_base = 'cvss_v2' if set_severity_basis == 'cvss_v2' else 'cvss_v3'
        else:
            expected_severity_base = set_severity_basis

        assert scan_details['info']['current_severity_base'] == expected_severity_base, \
            "Scan severity is incorrect. Expected is {}, actual is : {}".format(
                expected_severity_base, scan_details['info']['current_severity_base'])

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('import_scan', [{'scan': {'filename': 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_verify_scan_severity_base_can_be_changed_from_trash_folder(self, import_scan):
        """
        NES-12726 : [API-Automation] : Verify that severity base can be changed when scan is present in 'Trash' folder

        Scenario Tested:
            [x] Update scan severity basis when scan is present inside Trash folder.
        """
        trash_folder_id = self.cat.api.folders.get_folders()['folders'][0]['id']
        self.cat.api.scans.move(import_scan, trash_folder_id)
        scan_details = self.cat.api.scans.details(import_scan)

        # Verify that scan moved to trash folder successfully.
        assert scan_details['info']['folder_id'] == trash_folder_id, "Scan did not move to 'Trash' folder"
        original_severity = scan_details['info']['current_severity_base']
        new_severity = [severity for severity in ['cvss_v3', 'cvss_v2'] if severity != original_severity][0]
        self.cat.api.scans.update_severity_base(scan_id=import_scan, payload={"severity_base": new_severity})

        # Verify that scan severity basis is updated when scan is present inside trash folder.
        assert self.cat.api.scans.details(import_scan)['info']['current_severity_base'] == new_severity != \
               original_severity, "Unable to update the scan severity basis when scan is inside trash folder."
