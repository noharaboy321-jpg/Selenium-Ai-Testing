"""
Nessus Scan Endpoint verification

Test cases for Create Scan, Launch Scan,
Import Scan, Export Scan, Configure Scan,
Delete Scan, Scan Permissions,
Export scan history, Delete Scan History,
Move scan, Download plugin attachment

:copyright: Tenable Network Security, 2019
:date: May 27, 2017
:last_modified: Sept, 2024
:author: @sshah, @lambaliya.ctr, @ntarwani.ctr, @dkothari.ctr, @yshah, @kpanchal, @krpatel
"""
import datetime
import json
from datetime import datetime, timedelta
from http import HTTPStatus

import pytest
import pytz
from requests.exceptions import HTTPError
from waiting import wait, TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import load_testdata, get_file_path
from catium.lib.const import TIME_THIRTY_MINUTES, TIME_FIVE_MINUTES, WAIT_NORMAL, TIME_TEN_MINUTES, \
    TIME_TEN_SECONDS, TIME_FIVE_SECONDS
from catium.lib.const.base_constants import STRING_ON, TIME_SIXTY_SECONDS, TIME_FIFTEEN_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util import poll
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_os_name, get_system_datetime
from nessus.helpers.nessuscli.logchecker import is_log_entries
from nessus.helpers.scan import create_scan_helper, get_scan_report_template_id
from nessus.helpers.server import expect_http_error
from nessus.helpers.settings import get_current_advanced_setting_value
from nessus.helpers.waiters import wait_scan_state, wait_for_scan
from nessus.lib.config.environment_variables import NESSUS_LOGS_DIR
from nessus.lib.const import API, NessusCli
from nessus.lib.const.constants import Nessus, OperatingSystems
from nessus.models.scan import ScanModel
from nessus.tests.api.misc.test_scan_wizard import reload_nessus
from tenableio.helpers.metadata.scan import ScanMetadata

log = create_logger()


@pytest.mark.usefixtures('nessus_api_login')
class TestNessusScanEndpoint:
    """Tests for Nessus scan Endpoint"""

    cat = None

    @pytest.mark.parametrize('test_data_file', [
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
                      'scan_type': 'advanced'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                       pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                                                       pytest.mark.nessus_home)),  # NQA-625,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_scan.json'),
                      'scan_type': 'pci'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                  pytest.mark.nessus_expert)),  # NQA-634,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_network_scan.json'),
                      'scan_type': 'basic'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                    pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                                                    pytest.mark.nessus_home)),  # NQA-629,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_webapplication_scan.json'),
                      'scan_type': 'webapp'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                     pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-644,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_host_discovery_scan.json'),
                      'scan_type': 'discovery'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                        pytest.mark.nessus_expert, pytest.mark.nessus_home)),
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_external_scan.json'),
                      'scan_type': 'asv'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                  pytest.mark.nessus_expert)),  # NQA-639,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_malware_scan.json'),
                      'scan_type': 'malware'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA- 635,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_credential_patch_audit_scan.json'),
             'scan_type': 'patch_audit'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                 pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-630,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mdm_config_audit_scan.json'),
         'scan_type': 'mdm'},  # NQA-636,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mobile_device_scan.json'),
         'scan_type': 'mobile'},  # NQA-637,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_policy_compliance_audit_scan.json'),
         'scan_type': 'compliance'},  # NQA-640,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_scan.json'),
                      'scan_type': 'scap'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-641,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_scan.json'),
                      'scan_type': 'scap'}, marks=pytest.mark.sensor_manager),  # NQA-641,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_agent_scan.json'),
                      'scan_type': 'agent_basic'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-646,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_agent_scan.json'),
                      'scan_type': 'agent_advanced'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-645,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_agent_malware_scan.json'),
         'scan_type': 'agent_malware'},  # NQA-647,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_agent_scan.json'),
         'scan_type': 'agent_scap'},  # NQA-649,
        pytest.param({'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_policy_compliance_audit_agent_scan.json'),
            'scan_type': 'agent_compliance'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-648,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_audit_cloud_infrastructure.json'),
             'scan_type': 'cloud_audit'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                 pytest.mark.nessus_expert))  # NQA- 626
    ], indirect=True)
    # API_Tested# POST /scans
    def test_create_scan(self, create_scan):
        """
            Creates a new scan on the given scanner.

            Scenarios tested:
              [x] Successfully create a scan
              [ ] Create a scan with missing required fields and make sure it fails
              [ ] Create a scan with a bad template UUID and make sure it fails
        """

        # Get Scan related information for newly created scan and verify its 200 response
        scan_id = create_scan['scan']['id']
        scans = self.cat.api.scans.get_scans()['scans']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify scan exists in list.
        assert scan_id in [scan['id'] for scan in scans], 'Failed to create scan'

    @pytest.mark.skip_acceptance
    @pytest.mark.scanning
    @pytest.mark.usefixtures('delete_all_scans_in_nessus')
    @pytest.mark.parametrize('test_data_file', [
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
                      'scan_type': 'advanced'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                       pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                                                       pytest.mark.nessus_home)),
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_scan.json'),
                      'scan_type': 'pci'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                  pytest.mark.nessus_expert)),  # NQA-634,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_network_scan.json'),
                      'scan_type': 'basic'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                    pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                                                    pytest.mark.nessus_home)),
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_webapplication_scan.json'),
                      'scan_type': 'webapp'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                     pytest.mark.nessus_expert)),  # NQA-644,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_host_discovery_scan.json'),
                      'scan_type': 'discovery'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                        pytest.mark.nessus_expert)),  # NQA-632,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_external_scan.json'),
                      'scan_type': 'asv'},
                     marks=pytest.mark.skip('skipped as scan take more than 30 min to complete')),  # NQA-639,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_malware_scan.json'),
                      'scan_type': 'malware'},
                     marks=pytest.mark.skip('skipped as scan take more than 30 min to complete')),  # NQA- 635,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_credential_patch_audit_scan.json'),
             'scan_type': 'patch_audit'},
            marks=pytest.mark.skip('skipped as scan take more than 30 min to complete')),  # NQA-630,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mdm_config_audit_scan.json'),
             'scan_type': 'mdm'},
            marks=pytest.mark.skip('skipped as scan take more than 30 min to complete')),  # NQA-636,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mobile_device_scan.json'),
                      'scan_type': 'mobile'},
                     marks=pytest.mark.skip('skipped as scan take more than 30 min to complete')),  # NQA-637,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_policy_compliance_audit_scan.json'),
             'scan_type': 'compliance'},
            marks=pytest.mark.skip('skipped as scan take more than 30 min to complete')),  # NQA-640,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_scan.json'),
                      'scan_type': 'scap'},
                     marks=pytest.mark.skip('skipped as scan take more than 30 min to complete')),  # NQA-641,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_agent_scan.json'),
                      'scan_type': 'agent_basic'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-646,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_agent_scan.json'),
                      'scan_type': 'agent_advanced'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-645,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_agent_malware_scan.json'),
         'scan_type': 'agent_malware'},  # NQA-647,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_agent_scan.json'),
         'scan_type': 'agent_scap'},  # NQA-649,
        {'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_policy_compliance_audit_agent_scan.json'),
            'scan_type': 'agent_compliance'},  # NQA-648,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_audit_cloud_infrastructure.json'),
             'scan_type': 'cloud_audit'},
            marks=pytest.mark.skip('skipped as scan take more than 30 min to complete'))  # NQA- 626
    ], indirect=True)
    # API_Tested# POST /scans/{scan_id}/launch
    def test_launch_scan(self, create_scan):
        """
            Launches a scan.

            Scenarios tested:
              [x] Successfully launches scans
              [ ] Successfully launch a scan with custom targets
              [ ] Try (and fail) to launch a scan with custom targets that are invalid
              [ ] Try (and fail) to launch a scan that does not exist
              [ ] Try (and fail) to launch a scan that is already running
        """

        # Get newly created scan information
        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

        # Get scan details
        self.cat.api.scans.details(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.scanning
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('delete_all_scans_in_nessus')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_network_scan.json'),
         'scan_type': 'basic'},  # NQA-629,
    ], indirect=True)
    # API_Tested# POST /scans/{scan_id}/launch
    def test_launch_basic_scan(self, create_scan):
        """
        Launches a scan.  This is broken out of test_launch_scan so that it can be run during Acceptance tests.
        """

        # Get newly created scan information
        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

        # Get scan details
        self.cat.api.scans.details(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.skip_acceptance
    @pytest.mark.license_change
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('expire_license')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}])
    # API_Tested# POST /scans/{scan_id}/launch
    def test_launch_scan_expired_license(self, create_scan):
        """
            Launches a scan.

            Scenarios tested:
              [x] Receive error when trying to launch a scan with an expired license
        """

        # Get newly created scan information
        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 403 response
        with expect_http_error(code=HTTPStatus.FORBIDDEN):
            self.cat.api.scans.launch(scan_id)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('scan', [
        pytest.param({"filename": 'advance_scan_c7kspv.nessus'}, marks=pytest.mark.nessus_mat),  # NQA-700
        pytest.param({"filename": 'advanced_scan_gxxyl6.db', "encrypted": True, "password": "test1234"},
                     marks=pytest.mark.nessus_mat),
        # NQA-700
        pytest.param({"filename": 'basic_network_scan_59ro29.nessus'}, marks=pytest.mark.nessus_mat),  # NQA-704
        pytest.param({"filename": 'basic_network_scan_ld9por.db', "encrypted": True, "password": "test1234"},
                     marks=pytest.mark.nessus_mat),  # NQA-704
        {"filename": 'credential_Patch_audit_fst5sk.nessus'},  # NQA-705
        {"filename": 'credential_Patch_audit_k20m5i.db', "encrypted": True, "password": "test1234"},  # NQA-705
        {"filename": 'host_discovery_scan_dhame5.nessus'},  # NQA-707
        {"filename": 'host_discovery_scan_fkzerx.db', "encrypted": True, "password": "test1234"},  # NQA-707
        {"filename": 'intel_amt_security_bypass_scan_ffclnc.nessus'},  # NQA-708
        {"filename": 'intel_amt_security_bypass_scan_mh34kw.db', "encrypted": True, "password": "test1234"},  # NQA-708
        {"filename": 'internal_pci_network_scan_i5jc01.nessus'},  # NQA-709
        {"filename": 'internal_pci_network_scan_ht9d9w.db', "encrypted": True, "password": "test1234"},  # NQA-709
        {"filename": 'malware_scan_5bal9i.nessus'},  # NQA-710
        {"filename": 'malware_scan_k03jtm.db', "encrypted": True, "password": "test1234"},  # NQA-710
        {"filename": 'mdm_config_audit_scan_arjq1m.nessus'},  # NQA-711
        {"filename": 'mdm_config_audit_scan_rkok1t.db', "encrypted": True, "password": "test1234"},  # NQA-711
        {"filename": 'mobile_device_scan_mr21e2.nessus'},  # NQA-712
        {"filename": 'mobile_device_scan_qp10bz.db', "encrypted": True, "password": "test1234"},  # NQA-712
        {"filename": 'pci_quarterly_external_scan_s4hruv.nessus'},  # NQA-714
        {"filename": 'pci_quarterly_external_scan_3rzkfz.db', "encrypted": True, "password": "test1234"},  # NQA-714
        {"filename": 'policy_compliance_auditing_jsp7c7.nessus'},  # NQA-715
        {"filename": 'policy_compliance_auditing_c175xd.db', "encrypted": True, "password": "test1234"},  # NQA-715
        pytest.param({"filename": 'scap_and_oval_auditing_scan_udk5xk.nessus'}, marks=pytest.mark.nessus_mat),
        # NQA-716
        pytest.param({"filename": 'scap_and_oval_auditing_scan_eu4adg.db', "encrypted": True, "password": "test1234"},
                     marks=pytest.mark.nessus_mat),
        # NQA-716
        {"filename": 'wannacry_ransomware_0bnkcb.nessus'},  # NQA-718
        {"filename": 'wannacry_ransomware_dsoe33.db', "encrypted": True, "password": "test1234"},  # NQA-718
        {"filename": 'web_application_test_scan_zuni9y.nessus'},  # NQA-719
        {"filename": 'web_application_test_scan_49f5em.db', "encrypted": True, "password": "test1234"},  # NQA-719
        {"filename": 'offline_config_audit_scan_rb06f6.nessus'},  # NQA-713
        {"filename": 'offline_config_audit_scan_c1vber.db', "encrypted": True, "password": "test1234"},  # NQA-713
        {"filename": 'Audit_Cloud_Infrastructure_0xmbqp.nessus'},  # NQA-701
        {"filename": 'Audit_Cloud_Infrastructure_jxzvxk.db', "encrypted": True, "password": "test1234"}])  # NQA-701
    # API_Tested# POST /scans/import/{file}
    def test_import_scan(self, scan):
        """
            Verifies scans can be imported

            Scenarios tested:
              [x] Successfully import scans
              [ ] Fail to import a scan due to malformed XML
              [ ] Import a scan with a bad uuid; it should either fail or convert it to an "Advanced" scan
              [ ] Import an encrypted scan with a bad password.
        """
        # Import a scan and verify 200 status

        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])

        fileuploaded = self.cat.api.file.upload(file=file, encrypted=scan.get('encrypted', None))
        import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None,
                                                     password=scan.get('password', None))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get scans and verify scan was imported
        response = self.cat.api.scans.get_scans()
        new_scan = next((scan for scan in response['scans'] if scan['name'] == import_scan['scan']['name']),
                        None)
        assert new_scan, "Scan was not properly imported."

        # Delete the imported scan
        self.cat.api.scans.delete(import_scan['scan']['id'])

    @pytest.mark.skip_nessustc
    @pytest.mark.parametrize('test_data_file', [
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_wannacry_scan.json'),
                      'scan_type': 'wannacry'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                       pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-743,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
                      'scan_type': 'advanced'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                       pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                                                       pytest.mark.nessus_home)),  # NQA-725,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_scan.json'),
                      'scan_type': 'pci'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                  pytest.mark.nessus_expert)),  # NQA-734,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_network_scan.json'),
                      'scan_type': 'basic'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                    pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-729,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_webapplication_scan.json'),
                      'scan_type': 'webapp'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                     pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-744,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_intelamt_scan.json'),
                      'scan_type': 'intelamt'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                       pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-733,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_ripple_20_remote_scan.json'),
             'scan_type': 'ripple-treck'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                  pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-727,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_host_discovery_scan.json'),
                      'scan_type': 'discovery'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                        pytest.mark.nessus_expert, pytest.mark.nessus_home)),
        # NQA-732,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_zero_logon_remote_scan.json'),
             'scan_type': 'zerologon'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                               pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-728,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_external_scan.json'),
                      'scan_type': 'asv'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                  pytest.mark.nessus_expert)),  # NQA-739,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_malware_scan.json'),
                      'scan_type': 'malware'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA- 735,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_credential_patch_audit_scan.json'),
             'scan_type': 'patch_audit'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                 pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-730,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mdm_config_audit_scan.json'),
         'scan_type': 'mdm'},  # NQA-736,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mobile_device_scan.json'),
         'scan_type': 'mobile'},  # NQA-737,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_policy_compliance_audit_scan.json'),
         'scan_type': 'compliance'},  # NQA-740,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_proxy_logon_ms_exchange_scan.json'),
             'scan_type': 'hafnium'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                             pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-742,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_scan.json'),
                      'scan_type': 'scap'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-741,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_scan.json'),
                      'scan_type': 'scap'}, marks=pytest.mark.sensor_manager),  # NQA-741,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_agent_scan.json'),
                      'scan_type': 'agent_basic'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-746,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_agent_scan.json'),
                      'scan_type': 'agent_advanced'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-745,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_agent_malware_scan.json'),
         'scan_type': 'agent_malware'},  # NQA-747,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_agent_scan.json'),
         'scan_type': 'agent_scap'},  # NQA-749,
        {'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_policy_compliance_audit_agent_scan.json'),
            'scan_type': 'agent_compliance'},  # NQA-748,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_audit_cloud_infrastructure.json'),
         'scan_type': 'cloud_audit'}], indirect=True)  # NQA-726,
    # API_Tested# PUT /scans/{scan_id}
    def test_configure_scan(self, create_scan, test_data_file):
        """
            Verifies the scan can be configured

            Scenarios tested:
              [x] Successfully reconfigure a scan
              [ ] Try to reconfigure a scan with bad data (e.g., invalid input)
              [ ] Try to reconfigure a scan that doesn't exist
        """
        scan_new_name = random_name(prefix='update-scan-')

        # load payload from the json file and edit name
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['settings']['name'] = scan_new_name

        if 'agent_group_id' in payload['settings'].keys():
            payload['settings']['agent_group_id'] = create_scan['scan']['agent_group_id']

        self.cat.api.scans.configure(create_scan['scan']['id'], payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_org_name = self.cat.api.scans.details(create_scan['scan']['id'])['info']['name']

        assert scan_org_name == scan_new_name, \
            'Expected %s, got %s instead.' % (scan_new_name, scan_org_name)

    @pytest.mark.parametrize('test_data_file', [
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
                      'scan_type': 'advanced'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                       pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                                                       pytest.mark.nessus_home)),  # NQA-725,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_network_scan.json'),
                      'scan_type': 'basic'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                    pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                                                    pytest.mark.nessus_home)),  # NQA-729,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_webapplication_scan.json'),
                      'scan_type': 'webapp'}, marks=pytest.mark.nessus_home),  # NQA-744,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_host_discovery_scan.json'),
                      'scan_type': 'discovery'}, marks=pytest.mark.nessus_home),  # NQA-732,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_malware_scan.json'),
                      'scan_type': 'malware'}, marks=pytest.mark.nessus_home),  # NQA- 735,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_credential_patch_audit_scan.json'),
             'scan_type': 'patch_audit'}, marks=pytest.mark.nessus_home),  # NQA-730,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'},  # NQA-725,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_scan.json'), 'scan_type':
            'pci'},  # NQA-734,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_network_scan.json'),
         'scan_type': 'basic'},  # NQA-729,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_webapplication_scan.json'),
         'scan_type': 'webapp'},  # NQA-744,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_host_discovery_scan.json'),
         'scan_type': 'discovery'},  # NQA-732,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_external_scan.json'),
         'scan_type': 'asv'},  # NQA-739,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_malware_scan.json'),
         'scan_type': 'malware'},  # NQA- 735,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_credential_patch_audit_scan.json'),
         'scan_type': 'patch_audit'},  # NQA-730,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mdm_config_audit_scan.json'),
         'scan_type': 'mdm'},  # NQA-736,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mobile_device_scan.json'),
         'scan_type': 'mobile'},  # NQA-737,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_policy_compliance_audit_scan.json'),
         'scan_type': 'compliance'},  # NQA-740,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_scan.json'),
         'scan_type': 'scap'},  # NQA-741,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_agent_scan.json'),
                      'scan_type': 'agent_basic'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-746,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_agent_scan.json'),
                      'scan_type': 'agent_advanced'},
                     marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-745,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_agent_malware_scan.json'),
                      'scan_type': 'agent_malware'}, marks=pytest.mark.nessus_manager),  # NQA-747,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_agent_scan.json'),
             'scan_type': 'agent_scap'}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-749,
        pytest.param({'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_policy_compliance_audit_agent_scan.json'),
            'scan_type': 'agent_compliance'}, marks=pytest.mark.nessus_manager),  # NQA-748,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_agent_scan.json'),
                      'scan_type': 'agent_basic'}, marks=pytest.mark.sensor_manager),  # NQA-746,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_agent_scan.json'),
                      'scan_type': 'agent_advanced'}, marks=pytest.mark.sensor_manager),  # NQA-745,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_agent_malware_scan.json'),
                      'scan_type': 'agent_malware'}, marks=pytest.mark.sensor_manager),  # NQA-747,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_agent_scan.json'),
             'scan_type': 'agent_scap'}, marks=pytest.mark.sensor_manager),  # NQA-749,
        pytest.param({'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_policy_compliance_audit_agent_scan.json'),
            'scan_type': 'agent_compliance'}, marks=pytest.mark.sensor_manager),  # NQA-748,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_audit_cloud_infrastructure.json'),
         'scan_type': 'cloud_audit'}], indirect=True)  # NQA-726,
    # API_Tested# DELETE /scans/{scan_id}
    def test_delete_scan(self, create_scan):

        """
            Verifies scan can be deleted

            Scenarios tested:
              [x] Successfully deletes a scan
              [ ] Try to delete a scan that doesn't exist
              [ ] Try to delete a scan that is currently executing
              [ ] Try to delete a scan that is currently being exported
              [ ] Try to delete a scan that you don't have permissions to delete
        """

        # Get Scan ID for newly created scan
        scan_id = create_scan['scan']['id']

        # Delete scan and verify 200 response
        self.cat.api.scans.delete(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get list of scans in container
        scans = self.cat.api.scans.get_scans()['scans']

        # Verify scan no longer exists.
        if scans:
            assert scan_id not in [scan['id'] for scan in scans], 'Failed to delete scan with id %s.' % scan_id

    # NQA-853
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_advanced_scan_configure_permission.json'),
            'scan_type': 'advanced'}], indirect=True)
    def test_configure_canconfigure_scan_permission(self, create_scan, test_data_file):
        """
            Verifies that a scan's permissions can be modified to "Can Configure"

            Scenarios tested:
              [x] Successfully modifies permissions
              [ ] Try to modify permissions for a scan you don't have permissions to modify
              [ ] Try to modify permissions for a scan that doesn't exist
        """
        # Set CanConfigure scan permissions
        # Get newly created scan information
        scan = create_scan['scan']

        # load payload from the json file and edit scan permissions value
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['settings']['acls'][0]['permissions'] = API.Permissions.Scan.CAN_CONFIGURE
        self.cat.api.scans.configure(scan['id'], payload)

        # Get scan details
        scan_details = self.cat.api.scans.details(scan['id'])
        # Verify edited scan permissions value
        assert scan_details['info']['acls'][0]['permissions'] == API.Permissions.Scan.CAN_CONFIGURE, \
            'Unable to set CanConfigure scan permissions'

    # NQA-852
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_advanced_scan_configure_permission.json'),
            'scan_type': 'advanced'}], indirect=True)
    # API_Tested# PUT /scans/{scan_id}
    def test_configure_cancontrol_scan_permission(self, create_scan, test_data_file):
        """
            Verifies that a scan's permissions can be modified to "Can Control"

            Scenarios tested:
              [x] Successfully modifies permissions
        """
        # Set CanControl scan permissions
        # Get newly created scan information
        scan = create_scan['scan']

        # load payload from the json file and edit scan permissions value
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['settings']['acls'][0]['permissions'] = API.Permissions.Scan.CAN_CONTROL
        self.cat.api.scans.configure(scan['id'], payload)

        # Get scan details
        scan_details = self.cat.api.scans.details(scan['id'])
        # Verify edited scan permissions value
        assert scan_details['info']['acls'][0]['permissions'] == API.Permissions.Scan.CAN_CONTROL, \
            'Unable to set CanControl scan permissions'

    # NQA-851
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_advanced_scan_configure_permission.json'),
            'scan_type': 'advanced'}], indirect=True)
    # API_Tested# PUT /scans/{scan_id}
    def test_configure_canview_scan_permission(self, create_scan, test_data_file):
        """
            Verifies that a scan's permissions can be modified to "Can View"

            Scenarios tested:
              [x] Successfully modifies permissions
            """
        # Set CanView scan permissions
        # Get newly created scan information
        scan = create_scan['scan']

        # load payload from the json file and edit scan permissions value
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['settings']['acls'][0]['permissions'] = API.Permissions.Scan.CAN_VIEW
        self.cat.api.scans.configure(scan['id'], payload)

        # Get scan details
        scan_details = self.cat.api.scans.details(scan['id'])
        # Verify edited scan permissions value
        assert scan_details['info']['acls'][0]['permissions'] == API.Permissions.Scan.CAN_VIEW, \
            'Unable to set CanView scan permissions'

    # NQA-850
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_advanced_scan_configure_noaccess_permission.json'),
            'scan_type': 'advanced'}], indirect=True)
    # API_Tested# PUT /scans/{scan_id}
    def test_configure_noaccess_scan_permission(self, create_scan, test_data_file):
        """
            Verifies that a scan's permissions can be modified to "No Control"

            Scenarios tested:
              [x] Successfully modifies permissions
        """
        # Set NoAccess scan permissions
        # Get newly created scan information
        scan = create_scan['scan']

        # load payload from the json file and edit scan permissions value
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['settings']['acls'][0]['permissions'] = API.Permissions.Scan.NO_ACCESS
        self.cat.api.scans.configure(scan['id'], payload)

        # Get scan details
        scan_details = self.cat.api.scans.details(scan['id'])
        # Verify edited scan permissions value
        assert scan_details['info']['acls'][0]['permissions'] == API.Permissions.Scan.NO_ACCESS, \
            'Unable to set NoAccess scan permissions'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('scan', [{"filename": 'internal_pci_network_scan_i5jc01.nessus'},  # NQA-771,
                                      {"filename": 'advance_scan_c7kspv.nessus'}])  # NQA-770,
    # API_Tested# DELETE /scans/{scan_id}/history/{history_id}
    def test_delete_history(self, scan):
        """
            Verifies the scan history can be deleted.

            Scenarios tested:
              [x] Successfully removes a scan history item
              [ ] Try to remove a scan history item that doesn't exist
              [ ] Try to remove a scan history item for a scan that doesn't exist
              [ ] Try to remove the most recent scan history item for a running scan
        """

        # Import a scan and verify 200 status
        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])
        filename = self.cat.api.file.upload(file=file)
        scan = self.cat.api.scans.import_scan(filename)['scan']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get scan details
        details = self.cat.api.scans.details(scan['id'])
        # Get history id
        history_id = details['history'][0]['history_id']

        # Delete scan history
        self.cat.api.scans.delete_history(scan['id'], history_id)

        # assert the scan history is deleted
        history = self.cat.api.scans.details(scan['id'])['history']
        assert not history, 'History was not deleted.'

        # Delete the imported scan
        self.cat.api.scans.delete(scan['id'])

    @pytest.mark.nessus_mat
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('frequency', [API.Schedule.Frequencies.FREQ_ONCE,
                                           API.Schedule.Frequencies.FREQ_DAILY,
                                           API.Schedule.Frequencies.FREQ_WEEKLY,
                                           API.Schedule.Frequencies.FREQ_MONTHLY,
                                           API.Schedule.Frequencies.FREQ_YEARLY])
    @pytest.mark.parametrize('scheduled', [True, False])
    # API_Tested# PUT /scans/{scan_id}/schedule
    def test_schedule(self, frequency, scheduled):
        """
            [ESQO-756]
            Verifies the schedule for a scan can be enabled and disabled.

            Scenarios tested:
              [x] Successfully enables/disables the schedule
              [ ] Try enabling or disabling a schedule for a scan that doesn't exist
              [ ] Try enabling a schedule with bad schedule parameters
        """

        scan_model = ScanModel()
        scan_model.name = random_name(prefix='scheduled_scan')
        scan_model.uuid = API.Schedule.Uuids.UUID
        scan_model.enabled = False
        scan_model.launch_now = False
        scan_model.timezone = API.Schedule.TimeZone.ZULU_ZONE
        timezone = API.Schedule.TimeZone.ZULU_ZONE
        scan_model.rrules = frequency
        scan_model.starttime = (pytz.utc.localize(datetime.utcnow()) + timedelta(
            minutes=2)).astimezone(pytz.timezone(timezone)).strftime("%Y%m%dT%H%M00")
        scan_model.text_targets = Nessus.Scan.Target.LOCALHOST
        create_scan = self.cat.api.scans.create(scan_model)

        # Get scan ID
        scan_id = create_scan['scan']['id']

        try:
            # Set schedule enabled to false and assert 200 response
            self.cat.api.scans.schedule(scan_id, enabled=scheduled)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            # Get scans and verify enabled is true
            scans = self.cat.api.scans.get_scans()
            scan = scans['scans']
            enabled = False
            for scanner in scan:
                if scanner['id'] == scan_id:
                    enabled = scanner['enabled']

            assert enabled is scheduled, f"Expected {scheduled}, got {enabled}."

        finally:
            self.cat.api.scans.delete(scan_id)

    @pytest.mark.parametrize('test_data_file', [
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
                      'scan_type': 'advanced'},
                     marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-725,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_network_scan.json'),
                      'scan_type': 'basic'},
                     marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert, pytest.mark.nessus_manager,
                            pytest.mark.nessus_home)),  # NQA-729,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_webapplication_scan.json'),
                      'scan_type': 'webapp'},
                     marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-744,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_host_discovery_scan.json'),
                      'scan_type': 'discovery'},
                     marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-732,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_credential_patch_audit_scan.json'),
             'scan_type': 'patch_audit'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert,
                                                 pytest.mark.nessus_home)),  # NQA-730,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_malware_scan.json'),
                      'scan_type': 'malware'},
                     marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA- 784,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_scan.json'), 'scan_type': 'pci'},
            marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert)),  # NQA-783,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_pci_external_scan.json'),
                      'scan_type': 'asv'},
                     marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert)),  # NQA-788,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mdm_config_audit_scan.json'),
         'scan_type': 'mdm'},  # NQA-785,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mobile_device_scan.json'),
         'scan_type': 'mobile'},  # NQA-786,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_policy_compliance_audit_scan.json'),
         'scan_type': 'compliance'},  # NQA-789,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_scan.json'),
                      'scan_type': 'scap'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert)),  # NQA-790,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_agent_scan.json'),
                      'scan_type': 'agent_basic'},
                     marks=pytest.mark.nessus_manager),  # NQA-746,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_agent_scan.json'),
                      'scan_type': 'agent_advanced'},
                     marks=pytest.mark.nessus_manager),  # NQA-745,
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_agent_malware_scan.json'),
                      'scan_type': 'agent_malware'},
                     marks=pytest.mark.nessus_manager),  # NQA-747,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_scap_oval_audit_agent_scan.json'),
             'scan_type': 'agent_scap'}, marks=pytest.mark.nessus_manager),
        # NQA-749,
        {'scan_json_path': get_file_path(
            'nessus/tests/api/scan/test_data/test_policy_compliance_audit_agent_scan.json'),
            'scan_type': 'agent_compliance'},  # NQA-797,
        pytest.param(
            {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_audit_cloud_infrastructure.json'),
             'scan_type': 'cloud_audit'}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_expert))  # NQA-775,
    ], indirect=True)
    # API_Tested# POST /scans/{scan_id}/copy
    def test_copy_scan(self, create_scan):
        """
            Verifies scan can be copied

            Scenarios tested:
              [x] Successfully copies a scan
              [ ] Try copying a scan that doesn't exist
              [ ] Try copying a scan that is running
              [ ] Try copying a scan to a scan with the same name (duplicate name)
        """
        # Get information from newly created ScanModel
        scan = create_scan['scan']
        scan_id = scan['id']

        # Copy scan with new name and verify 200 response
        name = random_name(prefix='copy_') + scan['name']
        response = self.cat.api.scans.copy(scan_id, name=name)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get list of scans and verify copied scan exists
        scans = self.cat.api.scans.get_scans()['scans']
        assert name in [scan['name'] for scan in scans], 'Failed to copy scan.'

        self.cat.api.scans.delete(response['id'])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # NQA-837
    @pytest.mark.skip_acceptance
    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.scanning
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    # API_Tested# PUT /scans/{scan_id}/folder
    def test_move_advanced_scan(self, create_scan):
        """
            Verifies Advanced scan moved to trash folder/MyScans folder.

            Scenarios tested:
              [x] Successfully move a scan from a folder into the trash and back to My Scans
              [ ] Try moving a scan that doesn't exist
              [ ] Try moving a scan to a folder that doesn't exist (make sure it still shows up in the original folder)
        """
        scan_id = create_scan['scan']['id']
        self.cat.api.scans.launch(scan_id)

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=(TIME_FIVE_MINUTES * 4))

        # Verify scan has been completed
        assert result, "Scan failed to launch or taking more than 10 minutes"

        # Move completed Advanced scan into trash folder
        trash_folder_id = self.cat.api.folders.get_folders()['folders'][0]['id']
        self.cat.api.scans.move(scan_id, f"{trash_folder_id}")

        # Get scan details after moving scan to trash folder
        details = self.cat.api.scans.details(scan_id)
        assert details['info']["folder_id"] == trash_folder_id, "Scan does not move into Trash folder"

        # Move Advanced scan from Trash folder into MyScans folder
        my_scan_folder_id = self.cat.api.folders.get_folders()['folders'][1]['id']
        self.cat.api.scans.move(scan_id, f"{my_scan_folder_id}")

        # Get scan details after moving to MyScans folder
        details = self.cat.api.scans.details(scan_id)
        assert details['info']["folder_id"] == my_scan_folder_id, "Scan does not move from Trash into MyScans folder"

    # NQA-881
    @pytest.mark.skip_acceptance
    @pytest.mark.skip_rhel8
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.scanning
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    # API_Tested# GET /scans/{scan_id}/attachments/{attachment_id}?key={key}
    def test_attachments(self, create_scan):
        """
            Verifies the scan attachments can be retrieved.

            Scenarios tested:
              [x] Successfully download a scan's attachment
              [ ] Try downloading an attachment that doesn't exist
              [ ] Try downloading an attachment for a scan that doesn't exist
        """
        # Create and run a scan that will generate an attachment
        scan_id = create_scan['scan']['id']

        self.cat.api.scans.launch(scan_id)

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=(TIME_FIVE_MINUTES * 4))

        # Verify scan has been completed
        assert result, "Scan failed to launch or taking more than 15 minutes"

        # Get scan details
        details = self.cat.api.scans.details(scan_id)

        # Get host id
        host_id = details['hosts'][0]['host_id']

        # Get output for plugin id 84239
        output = self.cat.api.scans.plugin_output(scan_id, host_id, plugin_id=84239)

        # Get attachment ID and key
        attach_id = output['outputs'][0]['ports']['0 / tcp / '][0]['attachments'][0]['id']

        # Get attachment and verify 200 response
        attachment = self.cat.api.scans.attachments(scan_id, attach_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify that attachment is not null
        assert attachment["attachment_token"], "Attachment was not returned."

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    # API_Tested# POST /scans
    def test_create_multiple_scan(self):
        """
            Verifies that multiple scans can be created with the same name

            Scenarios tested:
              [x] Successfully creates a scan with the same name
        """
        scan1 = create_scan_helper(self.cat.api, file_name=get_file_path('nessus/tests/api/scan/test_data'
                                                                         '/test_advanced_scan.json'),
                                   template_title='advanced')
        scan1_detail = self.cat.api.scans.details(scan1[0]['scan']['id'])

        scan2 = create_scan_helper(self.cat.api, file_name=get_file_path('nessus/tests/api/scan/test_data'
                                                                         '/test_advanced_scan.json'),
                                   template_title='advanced')
        scan2_detail = self.cat.api.scans.details(scan2[0]['scan']['id'])

        assert scan1_detail['info']['name'] == scan2_detail['info']['name'], 'Failed to create scan with same name'

        self.cat.api.scans.delete(scan1[0]['scan']['id'])
        self.cat.api.scans.delete(scan2[0]['scan']['id'])

    @pytest.mark.nessus_mat
    @pytest.mark.skip_acceptance
    @pytest.mark.scanning
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('test_data_file', [
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
                      'scan_type': 'advanced'})], indirect=True)  # NQA-834,
    # API_Tested# POST /scans/{scan_id}/stop
    # API_Tested# POST /scans/{scan_id}/launch
    # API_Tested# POST /scans/{scan_id}/pause
    # API_Tested# POST /scans/{scan_id}/resume
    def test_scan_control(self, create_scan):
        """
            Verify scan control actions - launch, pause, resume, and stop

            Scenarios tested:
              [x] Successfully launches a non-launched scan
              [ ] Launch a scan that is already running
              [ ] Launch a scan that has been stopped
              [x] Pause a running scan
              [ ] Pause a stopped scan
              [ ] Pause a paused scan
              [x] Resume a paused scan
              [ ] Resume a running scan
              [ ] Resume a stopped scan
              [x] Stop a running scan
              [ ] Stop a paused scan
              [ ] Stop a stopped/not started scan
        """
        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # small delay to get scan status as running
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                        timeout=TIME_TEN_MINUTES)
        scan_status = self.cat.api.scans.get_status(scan_id=scan_id)
        assert scan_status == API.Scan.Status.RUNNING, "Scan status incorrect. Expected running, got %s" % scan_status

        # stop scan and get its status
        self.cat.api.scans.stop(scan_id=scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                        timeout=TIME_TEN_MINUTES)
        scan_status = self.cat.api.scans.get_status(scan_id=scan_id)
        assert scan_status == API.Scan.Status.CANCELED, "Scan status incorrect. Expected canceled, got %s" % scan_status

        # restart scan and verify its status
        self.cat.api.scans.launch(scan_id)

        # pause scan
        self.cat.api.scans.pause(scan_id=scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.PAUSED,
                        timeout=TIME_TEN_MINUTES)
        scan_status = self.cat.api.scans.get_status(scan_id=scan_id)
        assert scan_status == API.Scan.Status.PAUSED, "Scan status incorrect. Expected paused, got %s" % scan_status

        # resume scan
        self.cat.api.scans.resume(scan_id=scan_id)

        # wait for scan to complete
        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

    @pytest.mark.skip_acceptance
    @pytest.mark.scanning
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('test_data_file', [{'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/'
                                                                                 'test_policy_compliance_audit_agent_scan.json'),
                                                 'scan_type': 'agent_compliance'},  # NQA-836,
                                                {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/'
                                                                                 'test_advanced_agent_scan.json'),
                                                 'scan_type': 'agent_advanced'}],  # NQA-835,
                             indirect=True)
    # API_Tested# POST /scans/{scan_id}/stop
    # API_Tested# POST /scans/{scan_id}/launch
    # API_Tested# POST /scans/{scan_id}/pause
    # API_Tested# POST /scans/{scan_id}/resume
    def test_scan_control_agent(self, create_scan):
        """
            Verify scan control actions for agent scans

            Scenarios tested:
              [x] Successfully launches a non-launched scan
              [ ] Launch a scan that is already running
              [ ] Launch a scan that has been stopped
              [x] Pause a running scan
              [ ] Pause a stopped scan
              [ ] Pause a paused scan
              [x] Resume a paused scan
              [ ] Resume a running scan
              [ ] Resume a stopped scan
              [x] Stop a running scan
              [ ] Stop a paused scan
              [ ] Stop a stopped/not started scan
        """

        # skip test is there is no active agent
        agents = self.cat.api.agents.get_agents(scanner_id=1)
        if agents['agents'] is None:
            pytest.xfail('Real Agent not found in List of Agents')
        else:
            for agent in agents['agents']:
                if agent.get('status') == STRING_ON:
                    break
            else:
                pytest.xfail('Real Agent not found in List of Agents')

        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # small delay to get scan status as running
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                        timeout=TIME_TEN_MINUTES)
        scan_status = self.cat.api.scans.get_status(scan_id=scan_id)
        assert scan_status == API.Scan.Status.RUNNING, "Scan status incorrect. Expected running, got %s" % scan_status

        # stop scan and get its status
        self.cat.api.scans.stop(scan_id=scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                        timeout=TIME_TEN_MINUTES)
        scan_status = self.cat.api.scans.get_status(scan_id=scan_id)
        assert scan_status == API.Scan.Status.CANCELED, "Scan status incorrect. Expected canceled, got %s" % scan_status

        # restart scan and verify its status
        self.cat.api.scans.launch(scan_id)

        # pause scan
        self.cat.api.scans.pause(scan_id=scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.PAUSED,
                        timeout=TIME_TEN_MINUTES)
        scan_status = self.cat.api.scans.get_status(scan_id=scan_id)
        assert scan_status == API.Scan.Status.PAUSED, "Scan status incorrect. Expected paused, got %s" % scan_status

        # resume scan
        self.cat.api.scans.resume(scan_id=scan_id)

        # wait for scan to complete
        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('scan',
                             [{"filename": 'djokinen_-_ANS_-_export_-__import___________________@_________+-____e0okc4.'
                                           'fixed.db', "encrypted": True, "password": "a"}])
    # API_Tested# POST /scans/import
    # API_Tested# POST /scans/{scan_id}/export
    def test_special_char_scan_import_export(self, scan):
        """
            Verify that special chars in a scan name are retained on import
            # NQA- 113

            Scenarios tested:
              [x] Special characters in the scan name are retained when importing, and that the scan can be exported
        """
        # TODO : last step to import scan from last exprt need to implement
        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])
        scan_name = 'djokinen - ANS - export -> import <./;;\'[{}]\';.:">?!@#$%^&*()_+-=`~'
        fileuploaded = self.cat.api.file.upload(file=file, encrypted=scan.get('encrypted'))
        import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None,
                                                     password=scan.get('password'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # verify special char is not changed
        assert '&amp' not in import_scan['scan']['name'], 'special chars are not retained after import'
        assert scan_name == import_scan['scan']['name'], 'scan name changed, special chars are altered'

        # export scan
        export = self.cat.api.scans.export(import_scan['scan']['id'], export_format=API.Scan.ExportFormats.FORMAT_DB,
                                           password='a')

        # Get the export status and verify 200 response
        export_status = self.cat.api.scans.export_status(import_scan['scan']['id'], export[0])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify export status was retrieved
        assert export_status, "Export status was not retrieved."

        # wait for to get ready state and max wait for 30 sec
        wait(lambda: self.cat.api.scans.export_status(import_scan['scan']['id'], export[0]) == API.Status.READY,
             timeout_seconds=30, waiting_for='Scan to go state %s' % API.Status.READY, sleep_seconds=WAIT_NORMAL)

        # Delete the imported scan
        self.cat.api.scans.delete(import_scan['scan']['id'])

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    # API_Tested# DELETE /scans/{scan_id}/hosts/{host_id}
    def test_delete_host(self, import_scan):
        """
            Verifies that a specific host can be deleted for a scan.

            STA-18: Add endpoints to scans.py
            - scans/{scan_id}/hosts/{host_id} (Delete specific host for Scan.)

            Scenarios tested:
              [x] Host can be successfully deleted from a scan
              [ ] Host cannot be deleted for a scan that had "allow_post_scan_editing" turned off
              [ ] Try deleting a host from a scan that doesn't exist
              [ ] Try deleting a host that doesn't exist
        """
        scan_id = import_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        details = self.cat.api.scans.details(scan_id)
        host_id = details['hosts'][0]['host_id']

        self.cat.api.scans.delete_host(scan_id, host_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        new_details = self.cat.api.scans.details(scan_id)
        hosts = new_details['hosts']

        assert host_id not in hosts, '{} host is not deleted.'.format(details['hosts'][0]['hostname'])

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    @pytest.mark.parametrize('scan', [
        {"filename": 'advance_scan_c7kspv.nessus', "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},
        {"filename": 'advance_scan_c7kspv.nessus', "export_format": API.Scan.ExportFormats.FORMAT_HTML},
        {"filename": 'advance_scan_c7kspv.nessus', "export_format": API.Scan.ExportFormats.FORMAT_CSV},
        {"filename": 'advance_scan_c7kspv.nessus', "export_format": API.Scan.ExportFormats.FORMAT_PDF},
        {"filename": 'advance_scan_c7kspv.nessus', "export_format": API.Scan.ExportFormats.FORMAT_DB,
         "password": "test1234"}])
    # API_Tested# DELETE /scans/{scan_id}/export/{export_id}
    def test_cancel_export(self, import_scan, scan):
        """
            STA-18: Add endpoints to scans.py
            - scans/{scan_id}/export/{export_id} (Cancel export for Scan.)

            Scenarios tested:
              [x] Scan export is canceled
              [ ] Try canceling a scan export that isn't running
        """
        scan_id = import_scan

        export = self.cat.api.scans.export(scan_id, export_format=scan['export_format'],
                                           password=scan.get('password', None), chapters=scan.get('chapters', None),
                                           template_id=get_scan_report_template_id(
                                               api=self.cat.api,
                                               template_name="Complete List of Vulnerabilities by Host") if
                                           scan['export_format'] in [API.Scan.ExportFormats.FORMAT_PDF,
                                                                     API.Scan.ExportFormats.FORMAT_HTML] else None)

        self.cat.api.scans.cancel_export(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    # API_Tested# GET /scans/{scan_id}/export/formats
    def test_get_export_formats(self, import_scan):
        """
            STA-18: Add endpoints to scans.py
            - scans/{scan_id}/export/formats (Get export format of Scan)

            Scenarios tested:
              [x] Get export formats for a scan
              [ ] Try getting formats for a scan that doesn't exist
        """
        scan_id = import_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_format_details = self.cat.api.scans.export_format_details(scan_id, scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        format_list = [API.Scan.ExportFormats.FORMAT_HTML,
                       API.Scan.ExportFormats.FORMAT_CSV,
                       API.Scan.ExportFormats.FORMAT_PDF]

        for scan_format in scan_format_details['formats']['format']:
            assert scan_format['value'] in format_list, \
                'Scan report format "' + scan_format['value'] + '" is not valid'

        export_format_list = [API.Scan.ExportFormats.FORMAT_NESSUS, API.Scan.ExportFormats.FORMAT_DB,
                              API.Scan.ExportFormats.FORMAT_POLICY, API.Scan.ExportFormats.FORMAT_TIMING_DATA]

        for scan_format in scan_format_details['formats']['export']:
            assert scan_format['value'] in export_format_list, \
                'Scan export format "' + scan_format['value'] + '" is not valid'

        report_options = {'id', 'cve', 'cvss', 'risk', 'hostname', 'protocol', 'port', 'plugin_name',
                          'synopsis', 'description', 'solution', 'see_also', 'plugin_output'}

        assert report_options.issubset(set([key_value['key'] for key_value in scan_format_details[
            'report_options']['csvColumns']])), "Default CSV columns are incorrect."

        format_options = ['page_breaks']

        for format_option in scan_format_details['report_options']['formattingOptions']:
            assert format_option['key'] in format_options, 'Format option is not available.'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    # API_Tested# GET /scans/{scan_id}/plugins/{plugin_id}
    def test_plugin_details(self, import_scan):
        """
            STA-18: Add endpoints to scans.py
            - scans/{scan_id}/plugins/{plugin_id} (Plugin details under Vulnerability of Scan.)

            Scenarios tested:
              [x] Get plugin details for a scan
              [ ] Try getting plugin details for a scan that doesn't exist
              [ ] Try getting plugin details for a plugin that doesn't exist
        """
        scan_id = import_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        details = self.cat.api.scans.details(scan_id)
        plugin_id = details['vulnerabilities'][0]['plugin_id']

        plugin_details = self.cat.api.scans.vulnerabilities(scan_id, plugin_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert plugin_details, 'Plugin details should not be null.'

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    # API_Tested# DELETE /scans
    def test_delete_bulk_scan(self):
        """
            STA-18: Add endpoints to scans.py
            - /scans (Delete all scans from trash.)

            Scenarios tested:
              [x] Delete all of the provided scan IDs
              [ ] Try deleting a list of scans and include a scan ID that doesn't exist (should delete scans up to that
                  point, but fail on the one that doesn't exist)
              [ ] Try deleting scans and not provide any IDs.
        """
        scan_list = {'advanced': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
                     'basic': get_file_path('nessus/tests/api/scan/test_data/test_basic_network_scan.json'),
                     'discovery': get_file_path('nessus/tests/api/scan/test_data/test_host_discovery_scan.json')}

        created_scan_ids = []

        for template in scan_list.keys():
            scan = create_scan_helper(self.cat.api, file_name=scan_list.get(template), template_title=template)
            created_scan_ids.append(scan[0]['scan']['id'])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

        deleted_scans = self.cat.api.scans.delete_bulk_scans(created_scan_ids)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert created_scan_ids == deleted_scans['deleted'], 'Scans are not deleted.'

        scan_details = self.cat.api.scans.get_scans()['scans']

        if scan_details:
            assert created_scan_ids not in [scan_detail['id'] for scan_detail in scan_details], \
                'Scans are not deleted properly.'
        else:
            assert scan_details is None, 'Scans are not deleted properly.'

    @pytest.mark.skip_acceptance
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    # API_Tested# POST /scans/{scan_id}/diff
    def test_scan_history_diff(self, create_scan):
        """
            STA-18: Add endpoints to scans.py
            - scans/{scan_id}/diff (Difference between history under the history of Scan.)

            Scenarios tested:
              [x] Get the diff between two scan executions
              [ ] Try to get a diff for a scan that doesn't exist
              [ ] Try to get a diff for two history IDs, one of which doesn't exist
        """
        scan = create_scan['scan']
        scan_id = scan['id']

        for i in range(2):
            self.cat.api.scans.launch(scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                            timeout=TIME_TEN_SECONDS)

            self.cat.api.scans.stop(scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                            timeout=TIME_TEN_SECONDS)

        scan_details = self.cat.api.scans.details(scan_id)
        history_id = scan_details['history'][0]['history_id']
        diff_id = scan_details['history'][1]['history_id']

        self.cat.api.scans.diff_scan_history(scan_id, diff_id, history_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        self.cat.api.scans.delete(scan_id)

    @pytest.mark.skip_acceptance
    @pytest.mark.skip_rhel8
    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    # API_Tested# POST /scans/{scan_id}/launch
    # API_Tested# POST /scans/{scan_id}/stop
    def test_scan_repeat_launch_stop(self, create_scan):
        """
        NES-9218 - stopping a scan will sometimes set it 'Completed' instead of 'Cancelled'

        This test mimics the shell script from that ticket that reproduces this bug.

        Scenarios tested:
        [x] Launching and stopping will always put the scan in 'Cancelled' state
        """
        scan = create_scan['scan']
        scan_id = scan['id']

        # start/cancel a bunch of times
        # failure to start/stop is ok (it mimics the shell script)
        for i in range(20):
            try:
                self.cat.api.scans.launch(scan_id)
            except:
                pass
            sleep(TIME_FIVE_SECONDS, reason="scan to move to running state.")

            try:
                self.cat.api.scans.stop(scan_id)
            except:
                pass
            sleep(1, reason="scan to move to canceled state.")

        # make sure the last one finishes stopping
        for i in range(3):
            if self.cat.api.scans.details(scan_id)['info']['status'] == 'canceled':
                break
            try:
                self.cat.api.scans.stop(scan_id)
            except:
                pass
            sleep(TIME_FIVE_SECONDS, reason="scan to finish stopping.")

        scan_details = self.cat.api.scans.details(scan_id)
        assert scan_details['info']['status'] == 'canceled', "Scan didn't stop after several tries."
        assert len(scan_details['history']) > 5, "Not enough scan launches were successful for test."
        for history in scan_details['history']:
            assert history['status'] == 'canceled'

    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    # API_Tested# PUT /scans/{scan_id}/dashboard
    def test_enable_dashboard(self, import_scan):
        """
            STA-18: Add endpoints to scans.py
            - scans/{scan_id}/dashboard (Enable dashboard for Scan.)

            Scenarios tested:
              [x] Enable the dashboard for a scan
              [ ] Try to enable the dashboard for a scan that doesn't exist
              [ ] Try to disable the dashboard
        """
        scan_id = import_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        self.cat.api.scans.enable_dashboard(scan_id, True)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        details = self.cat.api.scans.details(scan_id)

        assert details['dashboard'], 'Dashboard details should not be null.'

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'Compliance_AD_2w9mjh.nessus'}}], indirect=True)
    def test_get_compliance(self, import_scan):
        """
        STA-57: Implement test for /scans/{scan_id}/compliance/{compliance_id}
        (Get compliance for specific scan)
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        details = self.cat.api.scans.details(scan_id)
        compliance_id = details['compliance'][0]['plugin_id']

        compliance = self.cat.api.scans.compliance(scan_id, compliance_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all([compliance['outputs'], compliance['info']]), \
            "Output and Information are None for compliance id {}".format(compliance_id)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_get_host_detail(self, import_scan):
        """
        STA-58: Implement test for /scans/{scan_id}/hosts/{host_id} GET method
        (Get host detail for specific scan)
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        scan_details = self.cat.api.scans.details(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        host_id = scan_details['hosts'][0]['host_id']

        host_details = self.cat.api.scans.host_details(scan_id, host_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all([host_details["vulnerabilities"], host_details["info"]]), \
            "Vulnerabilities and Information type Vulnerabilities are None for host id {}".format(host_id)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'Compliance_AD_2w9mjh.nessus'}}], indirect=True)
    def test_get_host_compliance(self, import_scan):
        """
        STA-59: Implement test case for /scans/{scan_id}/hosts/{host_id}/compliance/{compliance_id}
        (Get compliance for specific host)
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        scan_details = self.cat.api.scans.details(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        host_id = scan_details['hosts'][0]['host_id']
        compliance_id = scan_details['compliance'][0]['plugin_id']

        compliance = self.cat.api.scans.compliance_output(scan_id, host_id, compliance_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all([compliance['outputs'], compliance['info']]), \
            "Output and Information are None for compliance id {}".format(compliance_id)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_get_host_kb_prepare(self, import_scan):
        """
        STA-61: Implement test case for /scans/{scan_id}/hosts/{host_id}/kb/prepare (prepare kb for host)
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        details = self.cat.api.scans.details(scan_id)
        host_id = details['hosts'][0]['host_id']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        kb_resp = self.cat.api.scans.prepare_kb(scan_id, host_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
        assert kb_resp["token"], "'token' key should be available in response"

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_get_host_vulnerability(self, import_scan):
        """
        STA-62: Implement test case for /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        details = self.cat.api.scans.details(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        host_detail = self.cat.api.scans.host_details(scan_id, details['hosts'][0]['host_id'])
        plugin_id = host_detail['vulnerabilities'][0]['plugin_id']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        vuln_resp = self.cat.api.scans.get_host_vulnerability(scan_id, details['hosts'][0]['host_id'], plugin_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
        assert all([vuln_resp['outputs'], vuln_resp['info']]), \
            "Output and Information are None for plugin id {}".format(plugin_id)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_offline_scan(self, import_scan):
        """
        STA-63: Implement test case for /scans/{scan_id}/offline (offline specific scan)
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.scans.delete_offline_plugins(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_snooze_plugin(self, import_scan):
        """
        STA-64: Implement test case for /scans/{scan_id}/plugins/{plugin_id}/snooze
        (Snooze specific plugin of the specific scan)
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        details = self.cat.api.scans.details(scan_id)
        plugin_id = details['vulnerabilities'][0]['plugin_id']

        self.cat.api.scans.snooze_plugin(scan_id, plugin_id, 7)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('scan', [{"filename": 'Basic_Network_Scan_Result.db',
                                       "password": 'nessus', "encrypted": True}])
    def test_get_audit_trails(self, scan):
        """
        STA-65: Implement test case for /scans/{scan_id}/trails (Get audit trail for specific scan)
        """
        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])

        fileuploaded = self.cat.api.file.upload(file=file, encrypted=scan.get('encrypted', None))
        import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None,
                                                     password=scan.get('password', None))

        scan_id = import_scan['scan']['id']

        details = self.cat.api.scans.details(scan_id)
        host_name = details['hosts'][0]['hostname']
        # plugin_id = details['vulnerabilities'][0]['plugin_id']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        audit_trails = self.cat.api.scans.get_audit_trail(scan_id, '50705', host_name)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert audit_trails['trails'], "audit trails is none"

    @pytest.mark.nessus_home
    def test_get_timezone(self):
        """
        STA-66: Implement test case for /scans/timezones (Get scan's timezone)
        """
        timezones = self.cat.api.scans.timezones()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
        assert timezones["timezones"], "'timezones' key should be in response"

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_scan_status(self, import_scan):
        """
        STA-67: Implement test case for /scans/{scan_id}/status (Get scan status)
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        status = self.cat.api.scans.get_status(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
        assert status, "Scan status is None"

    @pytest.mark.nessus_home
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_expert
    @pytest.mark.incompatible
    @pytest.mark.parametrize('scan',
                             [{"filename": 'advance_scan_c7kspv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},
                              {"filename": 'advance_scan_c7kspv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},
                              {"filename": 'advance_scan_c7kspv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                              {"filename": 'advance_scan_c7kspv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},
                              {"filename": 'advance_scan_c7kspv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"}])
    def test_scan_download(self, scan):
        """
        STA-68: Test for /scans/{scan_id}/export/{file_id}/download
        Verifies the scan export status can be retrieved and can be downloaded.

        Scenarios tested:
          [x] Successfully export scans as CSV
          [x] Successfully export scans as PDF
          [x] Successfully export scans as HTML
          [x] Successfully export scans as XML (.nessus)
          [x] Successfully export scans as sqlite3 (Nessus DB)
        """
        # import scan
        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])
        fileuploaded = self.cat.api.file.upload(file=file, encrypted=scan.get('encrypted', None))
        import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None, password=scan.get('password', None))

        # Getting supported export formats
        supported_export_formats = [export_format['name'] for export_format in self.cat.api.scans.export_format_details(
            import_scan['scan']['id'], import_scan['scan']['id'])['formats']['format']]

        log.debug("Supported export formats are : {}".format(supported_export_formats))
        with SSH() as ssh:
            log.debug("Java version is : {}".format(ssh.execute(command="java -version")))

        # export scan
        export = self.cat.api.scans.export(
            import_scan['scan']['id'], export_format=scan['export_format'], password=scan.get('password', None),
            chapters=scan.get('chapters', None), template_id=get_scan_report_template_id(
                api=self.cat.api, template_name="Complete List of Vulnerabilities by Host") if
            scan['export_format'] in [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML] else None)

        # Get the export status and verify 200 response
        export_status = self.cat.api.scans.export_status(import_scan['scan']['id'], export[0])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        # Verify export status was retrieved
        assert export_status, "Export status was not retrieved."

        # wait for to get ready state and max wait for 30 sec
        wait(lambda: self.cat.api.scans.export_status(import_scan['scan']['id'], export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Scan to go state {}'.format(API.Status.READY),
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download = self.cat.api.scans.download(import_scan['scan']['id'], export[0])

        # assert scan export status is retrieved
        assert download, "File was not downloaded."

        # Delete the imported scan
        self.cat.api.scans.delete(import_scan['scan']['id'])

    # STA-113
    # API_Tested #GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id:int}
    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_plugin_output(self, import_scan):
        """
        STA-113: Create tests for scans /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id:int}

        Scenarios tested:
            [x] Successfully get plugin output
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        details = self.cat.api.scans.details(scan_id)
        host_id = details['hosts'][0]['host_id']
        host_detail = self.cat.api.scans.host_details(scan_id, host_id)
        plugin_id = host_detail['vulnerabilities'][0]['plugin_id']
        output = self.cat.api.scans.plugin_output(scan_id, host_id, plugin_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
        assert output, "Plugin output should not be null"

    # STA-113
    # API_Tested #PUT /scans/{scan_id}/plugins/{plugin_id:int}
    @pytest.mark.skip_acceptance
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.skip_rhel8
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_update_plugin_severity(self, create_scan):
        """
        STA-113: Create tests for scans /scans/{scan_id}/plugins/{plugin_id:int}

        Scenarios tested:
            [x] Successfully update the plugin severity
        """
        scan_id = create_scan['scan']['id']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)
        assert result, "Scan failed to complete."

        scan_details = self.cat.api.scans.details(scan_id)
        host_name = scan_details['hosts'][0]['hostname']
        plugin_id = scan_details['vulnerabilities'][0]['plugin_id']
        # modify plugin severity to critical
        payload = {'type': API.Severity.CRITICAL, 'host': host_name}
        self.cat.api.scans.update_plugin_severity(scan_id=scan_id, plugin_id=plugin_id, payload=payload)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        plugin_output = self.cat.api.scans.vulnerabilities(scan_id=scan_id, plugin_id=plugin_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        updated_severity = plugin_output['info']['plugindescription']['severity']
        assert updated_severity == 4, "Severity was not updated."

    # STA-113
    # API_Tested #PUT /scans/{scan_id}/status
    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_read_status(self, import_scan):
        """
        STA-113: Create tests for scans /scans/{scan_id}/status

        Scenarios tested:
            [x] Successfully change scan read status
        """
        scan_id = import_scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.scans.read_status(scan_id, read=True)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        scans = self.cat.api.scans.get_scans()['scans']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        for scan in scans:
            if scan['id'] == scan_id:
                read = scan['read']
        assert read is True, "Expected True, got False."

    # API_Tested# PUT /scans/{scan_id}
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('get_nessus_server_properties')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced',
         'credentials': get_file_path('nessus/tests/api/scan/test_data/oracle_lieberman.json')},
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced', 'credentials': get_file_path('nessus/tests/api/scan/test_data/ssh_beyondtrust.json')},
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced', 'credentials': get_file_path('nessus/tests/api/scan/test_data/ssh_lieberman.json')},
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced', 'credentials': get_file_path('nessus/tests/api/scan/test_data/ssh_thycotic.json')}])
    def test_configure_scan_restricted_credentials(self, create_scan, test_data_file):
        """
            Verifies the scan can not be configured when it includes credentials that are not allowed.

            Scenarios tested:
              [x] Fail to reconfigure a scan to use a restricted credential auth type reconfigure a scan
        """

        # load payload from the json file and add a credential auth type that we shouldn't be allowed to use.
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['credentials'] = load_testdata(test_data_file['credentials'])

        if self.cat.server_properties['license']['type'] != 'manager':
            with expect_http_error(code=400, look_for='Invalid selection'):
                self.cat.api.scans.configure(create_scan['scan']['id'], payload)
        else:
            self.cat.api.scans.configure(create_scan['scan']['id'], payload)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# PUT /scans/{scan_id}
    @pytest.mark.usefixtures('break_credentials_json')
    def test_broken_credentials_json(self):
        """
            Verifies credentials cannot be used when credentials.json has been tampered with

            Scenarios tested:
              [x] Verify that a scan with credentials cannot be created if credentials.json has been tampered with
        """

        # load payload from the json file and add a credential auth type that we shouldn't be allowed to use.
        # TODO: Move this into test data...
        payload = load_testdata(get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan_for_user.json'))
        payload['credentials'] = load_testdata(get_file_path('nessus/tests/api/scan/test_data/ssh_password.json'))

        # This one expects a 500 due to how it fails.
        with expect_http_error(code=500, look_for='Unable to load credentials list'):
            self.cat.api.scans.create_raw(payload)

    @pytest.mark.skip_acceptance
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_create_modify_and_launch_scan(self, create_scan, test_data_file):
        """
        NES-8915: Automated test UI

        Scenario Tested:
            [x] Verify that Advanced scans can be created/modified/run successfully using API.
        """

        # create scan using API
        scan_id = create_scan['scan']['id']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert scan_id in [scan['id'] for scan in self.cat.api.scans.get_scans()['scans']], 'Failed to create scan.'

        # edit scan using API
        scan_new_name = random_name(prefix='update-scan-')

        # load payload from the json file and edit name
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['settings']['name'] = scan_new_name

        self.cat.api.scans.configure(scan_id, payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_org_name = self.cat.api.scans.details(scan_id)['info']['name']

        assert scan_org_name == scan_new_name, \
            'Expected %s, got %s instead.' % (scan_new_name, scan_org_name)

        # launch scan using API
        self.cat.api.scans.launch(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        assert result, "Scan failed to complete."

        self.cat.api.scans.details(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # delete created scan
        self.cat.api.scans.delete(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    ALL_MASKS = 'info,notes,filters,hosts,comphosts,vulnerabilities,compliance,remediations,info.plugin_set'

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [
        {'scan': {"filename": 'advanced_agent_scan_rjc3zu.nessus'}}], indirect=True)
    @pytest.mark.parametrize('masked', [
        None,
        ALL_MASKS,
        '',
        'info',
        'notes',
        'filters',
        'hosts',
        'comphosts',
        'vulnerabilities',
        'compliance',
        'remediations',
        'doesnotexist',
        'doesnotexist,notes',
        'info.plugin_set',
        'info,notes,compliance',
        'info,info.plugin_set',
        'hosts_detail_info',
    ])
    # API_Tested# GET /scans/{scan_id}?mask={masks}
    def test_get_scan_mask(self, import_scan, masked):
        """
        Verify the functionality of the ?mask= query param

        [x] sending no ?mask= param returns all masked items
        [x] sending ?mask= returns no masked items
        [x] sending ?mask=item returns only that item (with exception below)
        [x] sending ?mask=info.plugin_set does not contain item due to lack of 'info'
        [x] sending ?mask=item,item,item returns the listed items
        """
        all_masks = self.ALL_MASKS.split(',')

        if masked is None:
            expected = all_masks
            unexpected = []
        elif masked == '':
            expected = []
            unexpected = all_masks
        elif masked == 'info.plugin_set':
            # special: this will not show up unless 'info' is also in the mask
            expected = []
            unexpected = all_masks
        else:
            expected = masked.split(',')
            expected = list(filter(lambda x: x != 'doesnotexist', expected))
            unexpected = [x for x in all_masks if x not in expected]

        scan_id = import_scan
        details = self.cat.api.scans.details(scan_id, mask=masked)

        for i in expected:
            if i == 'info':
                # details will contain 'info' data even if 'info' was masked, check for info.uuid specifically
                i = 'info.uuid'

            if '.' in i:
                parent, child = i.split('.')
                assert parent in details and child in details[parent], 'scan details does not contain %s' % i
            else:
                assert i in details, 'scan details does not contain %s' % i

        for i in unexpected:
            if i == 'info':
                # details will contain 'info' data even if 'info' was masked, check for info.uuid specifically
                i = 'info.uuid'

            if '.' in i:
                parent, child = i.split('.')
                assert parent not in details or child not in details[parent], 'scan details contains %s' % i
            else:
                assert i not in details, 'scan details contains %s' % i

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'host_discovery_scan_dhame5.nessus'}},
                                             {'scan': {"filename": 'basic_network_scan_59ro29.nessus'}}], indirect=True)
    # API_Tested# GET /scans/{scan_id}?includeHostDetailsForHostDiscovery=true
    def test_get_scan_hosts_detail_info(self, import_scan):
        """
        Verify the functionality of the ?includeHostDetailsForHostDiscovery=true

        [x] the host discovery scan should return hosts_detail_info section
        [x] the none host discovery scans should not return hosts_detail_info section
        """
        scan_id = import_scan
        details = self.cat.api.scans.details(scan_id, query="?includeHostDetailsForHostDiscovery=true")

        assert details['info']['policy_template_uuid'] is not None

        if details['info']['policy_template_uuid'] == 'bbd4f805-3966-d464-b2d1-0079eb89d69708c3a05ec2812bcf':
            assert 'hosts_detail_info' in details
        else:
            assert 'hosts_detail_info' not in details

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'hostcount_yjt5q6.nessus'}}], indirect=True)
    @pytest.mark.parametrize('query', [
        'info',
        '?filter.0.quality=eq&filter.0.filter=plugin_id&filter.0.value=10147&filter.search_type=and&mask=info',
        '?filter.0.quality=eq&filter.0.filter=plugin_id&filter.0.value=11219&filter.search_type=and&mask=info'
    ])
    # API_Tested# GET /scans/{scan_id}?mask={masks}
    def test_scan_mask_host_info(self, import_scan, query):
        """
        Verify the info.count works as expected

        [x] sending ?mask=info works as expected with license limit
        [x] sending ?mask=info works as expected with no license limit
        [x] sending ?mask=info with a plugin filter works as expected with license limit showing below limit
        [x] sending ?mask=info with a plugin filter works when filter shows more than limit (only displays up to limit)
        """
        scan_id = import_scan

        if query == 'info':
            details = self.cat.api.scans.details(scan_id, mask=query)
        else:
            details = self.cat.api.scans.details(scan_id, query=query)

        for k in details:
            if k == 'info':
                hostcount = (details[k]['hostcount'])
                assert hostcount == 110

    @pytest.mark.nessus_mat
    @pytest.mark.skip_acceptance
    @pytest.mark.scanning
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.usefixtures('get_nessus_server_properties')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_host_discovery_scan.json'),
         'scan_type': 'discovery'}], indirect=True)
    # API_Tested# POST /scans/{scan_id}/launch
    def test_scanning_limit_scan(self, create_scan):
        """
            Launches a host discovery scan and checks the host count to make sure it is <= the license ip limit

            Scenarios tested:
              [x] Successfully limit hosts to the correct number IPs
        """
        ip_limit = self.cat.server_properties['license']['ips']

        # Get newly created scan information
        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 200 response
        # This should find about 42 live hosts.
        self.cat.api.scans.launch(scan_id, alt_targets=['172.26.48.10-172.26.48.64'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

        # Get scan details
        response = self.cat.api.scans.details(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        if ip_limit < 20:
            assert response['info']['hostcount'] == ip_limit, 'IPs were not trimmed properly.'
        else:
            assert response['info']['hostcount'] <= ip_limit, 'IPs were not trimmed properly.'

    @pytest.mark.skip_acceptance
    @pytest.mark.skip_rhel8
    @pytest.mark.scanning
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_general_plugins_only_scan.json'),
         'scan_type': 'advanced', 'include': True},
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_general_plugins_only_scan.json'),
         'scan_type': 'advanced', 'include': False}], indirect=True)
    def test_kb_and_audit_trail_inclusion(self, create_scan, test_data_file):
        """
        Verify that KB and Audit Trail data is included/excluded based on the policy setting.

        Scenario Tested:
            [x] Verify that KB and Audit Trail data is excluded
            [x] Verify that KB and Audit Trail data is included
        """
        include = test_data_file['include']

        # create scan using API
        scan_id = create_scan['scan']['id']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert scan_id in [scan['id'] for scan in self.cat.api.scans.get_scans()['scans']], 'Failed to create scan.'

        # load payload from the json file and edit setting
        payload = load_testdata(test_data_file['scan_json_path'])

        if include:
            payload['settings']['audit_trail'] = 'full'
            payload['settings']['include_kb'] = 'yes'
        else:
            payload['settings']['audit_trail'] = 'none'
            payload['settings']['include_kb'] = 'no'

        self.cat.api.scans.configure(scan_id, payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # launch scan using API
        self.cat.api.scans.launch(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES * 2)

        assert result, "Scan failed to complete."

        scan_details = self.cat.api.scans.details(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        if include:
            assert scan_details['info']['haskb'] is True, 'Scan result did not include the KB.'
            assert scan_details['info']['hasaudittrail'] is True, 'Scan result did not include the audit trail.'
        else:
            assert scan_details['info']['haskb'] is False, 'Scan result included the KB.'
            assert scan_details['info']['hasaudittrail'] is False, 'Scan result included the audit trail.'

    test_params = [
        (API.Scan.Actions.LAUNCH, API.Scan.Status.RUNNING), (API.Scan.Actions.PAUSE, API.Scan.Status.PAUSING),
        (API.Scan.Actions.RESUME, API.Scan.Status.RESUMING), (API.Scan.Actions.STOP, API.Scan.Status.STOPPING)]

    # API_Tested# POST /scans/{scan_id}/launch
    # API_Tested# POST /scans/{scan_id}/pause
    # API_Tested# POST /scans/{scan_id}/stop
    # API_Tested# POST /scans/{scan_id}/kill
    @pytest.mark.skip_acceptance
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('method, status', test_params)
    @pytest.mark.parametrize('after_stop', [True, False])
    def test_force_stop_scan(self, method, status, after_stop):
        """
        NES-11204: API automation tests for force stop scans

        Scenario Tested:
        [x] Try to force stop a scan after stopping while it started running.
        [x] Try to force stop a scan without stopping after it started running.
        [x] Try to force stop a scan after stopping while it gets paused.
        [x] Try to force stop a scan without stopping after it gets paused.
        [x] Try to force stop a scan after stopping while it gets resumed.
        [x] Try to force stop a scan without stopping after it gets resumed.
        [x] Try to force stop a scan after it gets stopped.
        """
        # Create scan
        scan_model = ScanModel()
        scan_model.name = random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED))
        scan_model.uuid = ScanMetadata.get_template_uuid(self.cat.api.scans.get_templates(),
                                                         Nessus.TemplateNames.ADVANCED)
        scan_model.text_targets = Nessus.Scan.Target.AWS_LINUX_TARGET_2
        create_scan = self.cat.api.scans.create(scan_model)
        scan_id = create_scan['scan']['id']

        try:
            # Launch scan and verify 200 response
            self.cat.api.scans.launch(scan_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            # Verifies scan status after launching
            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                                   timeout=TIME_SIXTY_SECONDS), \
                "Scan status incorrect after launching. Expected status is 'Running'."

            if method != API.Scan.Actions.LAUNCH:
                # Pause, Resume, Stop scan and verify 200 response
                getattr(self.cat.api.scans, method)(scan_id)

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

                # Verifies scan status after performing different scan actions like Pause, Stop and Resume
                assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=status,
                                       timeout=TIME_SIXTY_SECONDS), \
                    "Scan status incorrect after '{}ing'. Expected status is '{}'.".format(method, status)

                if after_stop and method != API.Scan.Actions.STOP:
                    # Stop scan and verify 200 response
                    self.cat.api.scans.stop(scan_id)

                    assert self.cat.api.http_status_code == HTTPStatus.OK, \
                        'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

                    # Verifies scan status after stopping
                    assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.STOPPING,
                                           timeout=TIME_SIXTY_SECONDS), \
                        "Scan status incorrect after stopping. Expected status is 'Stopping'."

            # Force stop scan and verify 200 response
            self.cat.api.scans.force_stop(scan_id=scan_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            # Verifies scan status after stopping forcefully
            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                                   timeout=TIME_FIVE_MINUTES), \
                "Scan status incorrect after stopping forcefully. Expected status is 'Canceled'."
        finally:
            # Delete scan
            self.cat.api.scans.delete(scan_id=scan_id)

    # API_Tested# POST /scans/{scan_id}/launch
    # API_Tested# POST /scans/{scan_id}/stop
    # API_Tested# POST /scans/{scan_id}/kill
    @pytest.mark.skip_acceptance
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.flaky_test
    @pytest.mark.parametrize('scan_action', [API.Scan.Status.COMPLETED, API.Scan.Status.CANCELED])
    def test_force_stop_scan_after_completed_or_canceled(self, scan_action):
        """
        NES-11204: API automation tests for force stop scans

        Scenario Tested:
        [x] Receive an error while trying to force stop a scan after it gets completed.
        [x] Receive an error while trying to force stop a scan after it gets canceled.
        """
        # Create scan
        scan_model = ScanModel()
        scan_model.name = random_name(prefix='{} - '.format(Nessus.TemplateNames.BASIC_NETWORK))
        scan_model.uuid = ScanMetadata.get_template_uuid(self.cat.api.scans.get_templates(),
                                                         Nessus.TemplateNames.BASIC_NETWORK)
        scan_model.text_targets = Nessus.Scan.Target.LOCALHOST
        create_scan = self.cat.api.scans.create(scan_model)
        scan_id = create_scan['scan']['id']

        try:
            # Launch scan and verify 200 response
            self.cat.api.scans.launch(scan_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            # Verifies scan status after launching
            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                                   timeout=TIME_SIXTY_SECONDS), \
                "Scan status incorrect after launching. Expected status is 'Running'."

            if scan_action == API.Scan.Status.COMPLETED:
                try:
                    assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                           timeout=TIME_FIFTEEN_MINUTES * 2), \
                        "Scan status is incorrect. Expected status is 'Completed'."
                except TimeoutExpired:
                    pytest.xfail(reason="Unable to complete scan within 30 minutes of time!!")
            else:
                # Stop scan and verify 200 response
                self.cat.api.scans.stop(scan_id)

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

                assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                                       timeout=TIME_FIVE_MINUTES), \
                    "Scan status incorrect after stopping. Expected status is 'Canceled'."

            with pytest.raises(HTTPError):
                # Force stop scan after it gets completed or canceled and verify 409 error code
                self.cat.api.scans.force_stop(scan_id=scan_id)

                assert self.cat.api.http_status_code == HTTPStatus.CONFLICT, \
                    'Expected 409, got {} instead.'.format(self.cat.api.http_status_code)
        finally:
            # Delete scan
            self.cat.api.scans.delete(scan_id=scan_id)

    # API_Tested# POST /scans
    # API_Tested# POST /scans/{scan_id}/launch
    def test_launch_schedule_scan(self):
        """
        NES-12242: [API] Verify scheduled scan launch

        Scenario Tested:
        [x] Verify scheduled scan launch
        """
        scan_model = ScanModel()
        scan_model.name = random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED))
        scan_model.uuid = ScanMetadata.get_template_uuid(self.cat.api.scans.get_templates(),
                                                         Nessus.TemplateNames.ADVANCED)
        scan_model.text_targets = Nessus.Scan.Target.PUB_TARGET_4
        scan_model.enabled = True
        timezone = API.Schedule.TimeZone.AMERICA_ZONE
        scan_model.starttime = (pytz.utc.localize(datetime.utcnow()) + timedelta(
            minutes=2)).astimezone(pytz.timezone(timezone)).strftime("%Y%m%dT%H%M00")
        scan_model.timezone = "Eastern Standard Time" if get_os_name() == OperatingSystems.WINDOWS else timezone
        scan_model.launch = 'ONETIME'
        scan_model.rrules = API.Schedule.Frequencies.FREQ_ONCE

        scan_id = self.cat.api.scans.create(scan_model)['scan']['id']
        try:
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                                   timeout=TIME_FIVE_MINUTES), "Schedule scan is not getting launched successfully."
            try:
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                timeout=TIME_THIRTY_MINUTES)
            except Exception as e:
                pytest.xfail("Scan is not getting completed within 30 minutes of time. Error is : {}".format(e))
        finally:
            self.cat.api.login()
            if self.cat.api.scans.get_status(scan_id=scan_id) == API.Scan.Status.RUNNING:
                self.cat.api.scans.stop(scan_id)
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                                timeout=TIME_FIVE_MINUTES)
            self.cat.api.scans.delete(scan_id)

    # API_Tested# POST /scans/{scan_id}/plugins/{plugin_id}/snooze
    # API_Tested# DELETE /scans/{scan_id}/plugins/{plugin_id}/snooze
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    def test_wake_up_snoozed_plugins(self, import_scan):
        """
        NES-12236: [API] Verify waking up a snoozed plugin

        Scenario Tested:
        [x] Verify waking up a snoozed plugin
        """
        scan_id = import_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        details = self.cat.api.scans.details(scan_id)
        plugin_id = details['vulnerabilities'][0]['plugin_id']

        self.cat.api.scans.snooze_plugin(scan_id, plugin_id, 1)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        plugin_output = self.cat.api.scans.vulnerabilities(scan_id=scan_id, plugin_id=plugin_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert plugin_output['info']['plugindescription']['pluginattributes']['snoozed'], \
            "Plugin '{}' is not getting snoozed properly.".format(plugin_id)

        self.cat.api.scans.wake_snoozed_plugin(scan_id, plugin_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        plugin_output = self.cat.api.scans.vulnerabilities(scan_id=scan_id, plugin_id=plugin_id)

        assert 'snoozed' not in plugin_output['info']['plugindescription']['pluginattributes'], \
            "Plugin '{}' is not getting waked up properly.".format(plugin_id)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('scan_count', ["single", "multiple"])
    @pytest.mark.parametrize('setting_detail', [{"setting_name": "paused_scan_timeout", "setting_value": 1,
                                                 "setting_action": "edit"}])
    def test_paused_scan_timeout_setting_functioning_properly(self, scan_count, setting_detail):
        """
        NES-13093 [Automation]: Verify Paused scan timeout setting for multiple scans

        Scenario Tested:
        [x] Verify that "Paused scan timeout" setting is functioning properly for single or multiple scans.
        """
        created_scans_id = []

        scan_details = {"single": [{"scan_file": "nessus/tests/api/scan/test_data/test_advanced_scan.json",
                                    "scan_template": "advanced"}],
                        "multiple": [{"scan_file": "nessus/tests/api/scan/test_data/test_basic_network_scan.json",
                                      "scan_template": "basic"},
                                     {"scan_file": "nessus/tests/api/scan/test_data/test_malware_scan.json",
                                      "scan_template": "malware"}]}

        setting_payload = {"setting.0.name": setting_detail["setting_name"], "setting.0.value": setting_detail[
            "setting_value"], "setting.0.action": setting_detail["setting_action"]}

        default_setting_value = get_current_advanced_setting_value(
            api=self.cat.api, api_version=3, setting_name=setting_detail["setting_name"],
            setting_tab=Nessus.AdvancedSettings.SCANNING_TAB)

        assert default_setting_value == 0, "Default value for 'Paused scan timeout' gets mismatched, " \
                                           "Expected value should be '0'"

        try:
            self.cat.api.settings.update(settings=setting_payload)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            for scan_info in scan_details[scan_count]:
                created_scan = create_scan_helper(self.cat.api, file_name=get_file_path(scan_info["scan_file"]),
                                                  template_title=scan_info["scan_template"])

                created_scans_id.append(created_scan[0]['scan']['id'])

                for scan_id in created_scans_id:
                    self.cat.api.scans.launch(scan_id=scan_id)

                    wait(lambda: self.cat.api.scans.details(scan_id)['info']['status'] == API.Scan.Status.RUNNING,
                         sleep_seconds=WAIT_NORMAL, waiting_for="Scan get started running")

                [self.cat.api.scans.pause(scan_id=scan_id) for scan_id in created_scans_id]

                wait(lambda: self.cat.api.scans.details(scan_id)['info']['status'] == API.Scan.Status.PAUSED,
                     sleep_seconds=WAIT_NORMAL, waiting_for="Scan get paused")

                sleep(sleep_time=setting_detail["setting_value"] * TIME_SIXTY_SECONDS,
                      reason="waiting for scan status aborted")

                for scan_id in created_scans_id:
                    wait(lambda: self.cat.api.scans.details(scan_id)['info']['status'] == API.Scan.Status.ABORTED,
                         sleep_seconds=WAIT_NORMAL, waiting_for="Scan get aborted")

                    assert self.cat.api.scans.details(scan_id)['info']['status'] == API.Scan.Status.ABORTED, \
                        "'Paused Scan Timeout' setting is not functioning properly as scan is not getting in " \
                        "'Aborted' status even after paused for given time."
        finally:
            [self.cat.api.scans.delete(scan_id=scan_id) for scan_id in created_scans_id]

            setting_payload = {"setting.0.name": setting_detail["setting_name"], "setting.0.value": 0,
                               "setting.0.action": setting_detail["setting_action"]}

            self.cat.api.settings.update(settings=setting_payload)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.flaky_test
    def test_log_additional_scan_details_setting_functioning_properly(self):
        """
        NES-13098 [Automation]: Verify "Log Additional Scan Details" setting functioning

        Scenario Tested:
        [x] Verify that "Log Additional Scan Details" setting is functioning properly for scan.
        """
        scan_id = None
        setting_details = [{"setting_name": "log_whole_attack", "setting_value": "true", "setting_action": "edit"},
                           {"setting_name": "log_details", "setting_value": "true", "setting_action": "edit"}]

        for setting in setting_details:
            default_setting_value = get_current_advanced_setting_value(
                api=self.cat.api, api_version=3, setting_name=setting["setting_name"],
                setting_tab=Nessus.AdvancedSettings.LOGGING_TAB)

            assert not default_setting_value, "Default value for '{}' setting identifier gets mismatched, " \
                                              "Expected value should be 'No'".format(setting)

            setting_payload = {"setting.0.name": setting["setting_name"], "setting.0.value": setting["setting_value"],
                               "setting.0.action": setting["setting_action"]}

            self.cat.api.settings.update(settings=setting_payload)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        reload_nessus(api=self.cat.api)
        scan_info = {"scan_file": "nessus/tests/api/scan/test_data/test_advanced_scan.json",
                     "scan_template": "advanced"}

        try:
            created_scan = create_scan_helper(self.cat.api, file_name=get_file_path(scan_info["scan_file"]),
                                              template_title=scan_info["scan_template"])

            scan_id, scan_name = created_scan[0]['scan']['id'], created_scan[0]['scan']['name']

            self.cat.api.scans.launch(scan_id=scan_id)

            start_timestamp = get_system_datetime()
            wait(lambda: self.cat.api.scans.details(scan_id)['info']['status'] == API.Scan.Status.RUNNING,
                 sleep_seconds=WAIT_NORMAL, waiting_for="Scan gets started running")

            end_timestamp = get_system_datetime()

            scan_uuid = self.cat.api.scans.details(scan_id=scan_id)["info"]["uuid"]

            log_msg_to_be_verified = "Started scan '{}' as '{}'".format(scan_name, scan_uuid)
            log.debug("Log message to be verified :: {}".format(log_msg_to_be_verified))

            try:
                wait(lambda: any([is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                                 log_entry=log_msg_to_be_verified, start_timestamp=start_timestamp,
                                                 end_timestamp=end_timestamp, max_lines_per_file=30, log_line=True)]),
                     timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=WAIT_NORMAL)
            except TimeoutExpired:
                assert False, "{} is not present in backend.log file even after enabling 'log_details' setting.".format(
                    log_msg_to_be_verified)
        finally:
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_FIFTEEN_MINUTES)
            self.cat.api.scans.delete(scan_id=scan_id)

            for setting in setting_details:
                setting_payload = {"setting.0.name": setting["setting_name"], "setting.0.value": False,
                                   "setting.0.action": setting["setting_action"]}

                self.cat.api.settings.update(settings=setting_payload)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    def test_verify_plugins_used_in_created_scan(self):
        """
        NES-15572 [API-Automation]: Add API test to verify the list of plugins used in scan

        Scenario Tested:
        [x] Verify the list of plugins used in created scan by using "/scans/{id}/plugins" endpoint
        """
        scan_detail = create_scan_helper(self.cat.api, file_name=get_file_path(
            'nessus/tests/api/scan/test_data/test_advanced_scan.json'), template_title='advanced')

        scan_id = scan_detail[0]['scan']['id']
        self.cat.api.scans.launch(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        assert result, "Scan failed to complete."

        used_plugins = self.cat.api.scans.get_used_plugins(scan_id=scan_id)

        assert all(['plugin_set' in used_plugins, len(used_plugins['plugin_set']) > 0]), \
            "Failed to get used plugins from scan."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize("scan_format", [API.Scan.ExportFormats.FORMAT_NESSUS, API.Scan.ExportFormats.FORMAT_DB])
    def test_verify_plugins_used_in_imported_scan(self, scan_format):
        """
        NES-15572 [API-Automation]: Add API test to verify the list of plugins used in scan

        Scenario Tested:
        [x] Verify the list of plugins used in imported scan by using "/scans/{id}/plugins" endpoint
        """
        import_file_dict = {API.Scan.ExportFormats.FORMAT_NESSUS: 'advance_scan_c7kspv.nessus',
                            API.Scan.ExportFormats.FORMAT_DB: 'basic_network_scan_ld9por.db'}

        file = get_file_path('nessus/tests/api/scan/test_data/' + import_file_dict[scan_format])
        file_password = "test1234" if scan_format == API.Scan.ExportFormats.FORMAT_DB else None

        file_uploaded = self.cat.api.file.upload(file=file, encrypted=True)
        import_scan = self.cat.api.scans.import_scan(file_uploaded, folder_id=None, password=file_password)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        used_plugins = self.cat.api.scans.get_used_plugins(scan_id=import_scan['scan']['id'])

        assert all(['plugin_set' in used_plugins, len(used_plugins['plugin_set']) > 0]), \
            "Failed to get used plugins from scan."

    # API_Tested# GET /scans/{scan_id}/attachments/{attachment_id}/prepare
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.scanning
    @pytest.mark.skip_rhel8
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_error_message_while_pulling_scan_attachment_with_same_token(self, create_scan):
        """
        NES-15743: Verify the error while refreshing the page with same token of scan attachment

        Scenarios tested:
        [x] Verify that user should get error while pulling the scan attachment with same token.
        """
        scan_id = create_scan['scan']['id']

        self.cat.api.scans.launch(scan_id)

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=(TIME_FIVE_MINUTES * 4))

        assert result, "Scan failed to launch or taking more than 15 minutes"

        details = self.cat.api.scans.details(scan_id)
        output = self.cat.api.scans.plugin_output(scan_id, details['hosts'][0]['host_id'], plugin_id=84239)
        attach_id = output['outputs'][0]['ports']['0 / tcp / '][0]['attachments'][0]['id']

        attachment = self.cat.api.scans.attachments(scan_id=scan_id, attachment_id=attach_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected {}, got {} instead.'.format(HTTPStatus.OK, self.cat.api.http_status_code)

        assert attachment["attachment_token"], "Attachment token was not returned."

        scan_attachment_details = self.cat.api.scans.download_scan_attachment(
            attachment_taken=attachment["attachment_token"])

        assert len(scan_attachment_details.content) > 0, "Scan attachment detail is empty"

        with pytest.raises(HTTPError):
            self.cat.api.scans.download_scan_attachment(attachment_taken=attachment["attachment_token"])

        assert self.cat.api.http_status_code == HTTPStatus.NOT_FOUND, \
            'Expected %s, got %s instead.' % (HTTPStatus.NOT_FOUND, self.cat.api.http_status_code)

        error_msg_from_response = json.loads(self.cat.api.http_text)['error']
        expected_error_message = "The requested file was not found."

        assert error_msg_from_response == expected_error_message, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_message, error_msg_from_response)


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusProScanEndpoint:
    """Tests for Nessus scan Endpoint"""

    cat = None

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mdm_config_audit_scan.json'),
         'scan_type': 'mdm'},  # NQA-636,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_mobile_device_scan.json'),
         'scan_type': 'mobile'},  # NQA-637,
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_policy_compliance_audit_scan.json'),
         'scan_type': 'compliance'},  # NQA-640,
    ], indirect=True)
    # API_Tested# POST /scans
    def test_create_scan_np(self, nessus_api_handler: NessusAPI, test_data_file):
        """
        NES-8944: Split mdm pro tests into negative testing

        Scenarios tested:
          [x] Verify "400 - Bad Request" error while creating scan for MDM Config Audit scan, Mobile Device scan and
              Policy Compliance Auditing scan templates.
        """
        try:
            create_scan_helper(nessus_api_handler, file_name=test_data_file['scan_json_path'],
                               template_title=test_data_file['scan_type'])
        except HTTPError:
            pass

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# POST /scans
    def test_scan_no_schedule_limit(self, create_two_scheduled_scans):
        """
        NES-9210: Test that Essentials-only schedule limits are not applied on Pro.

        Scenarios tested:
        [x] Test that adding a scan does not de-schedule other scans (Essentials only)
        [x] Test that editing a scan does not de-schedule other scans (Essentials only)
        [x] Test that scheduling a scan does not de-schedule other scans (Essentials only)
        """
        scan1_id, scan2_id = create_two_scheduled_scans

        def is_enabled(scan):
            basic = scan['settings']['basic']
            groups = basic['groups']
            schedules = list(filter(lambda group: group['name'] == 'schedule', groups))
            return len(schedules) and schedules[0]['enabled']

        # check that they didn't get de-scheduled on create
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert is_enabled(scan1), "First scan got de-scheduled"

        assert is_enabled(scan2), "Second scan got de-scheduled"

        # edit the first scan to be unscheduled then edit back to scheduled
        update_schedule_payload = {
            'settings': {
                'name': 'scan1 enabled',
                'enabled': False,
                'starttime': '20300101T120000',
                'timezone': 'US/Samoa',
                'launch': 'ONETIME',
                'rrules': 'FREQ=ONETIME',
                'text_targets': '127.0.0.3',
            }
        }
        self.cat.api.scans.configure(scan1_id, payload=update_schedule_payload)
        update_schedule_payload['settings']['enabled'] = True
        self.cat.api.scans.configure(scan1_id, payload=update_schedule_payload)

        # check that nothing became de-scheduled
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert is_enabled(scan1), "First scan got de-scheduled"

        assert is_enabled(scan2), "Second scan got de-scheduled"

        # de-schedule then reschedule a scan using the /schedule API
        self.cat.api.scans.schedule(scan1_id, enabled=False)
        self.cat.api.scans.schedule(scan1_id, enabled=True)

        # check that nothing became de-scheduled
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert is_enabled(scan1), "First scan got de-scheduled"

        assert is_enabled(scan2), "Second scan got de-scheduled"


@pytest.mark.skip_acceptance
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusHomeScanEndpoint:
    """ Tests for Nessus scan Endpoint on Home installs """

    cat = None

    # API_Tested# POST /scans
    def test_create_scan_schedule_limit(self, create_two_scheduled_scans):
        """
        NES-9210: Test scan schedule limits when creating scans

        Scenarios tested:
        [x] Test that creating a scan with schedule enabled disables schedule of other scans
        """
        scan1_id, scan2_id = create_two_scheduled_scans

        def is_enabled(scan):
            basic = scan['settings']['basic']
            groups = basic['groups']
            schedules = list(filter(lambda group: group['name'] == 'schedule', groups))
            return len(schedules) and schedules[0]['enabled']

        # check that only one is scheduled
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert not is_enabled(scan1), "First scan is still scheduled after second scheduled scan created"

        assert is_enabled(scan2), "Second scan is not scheduled even though we created it with a schedule enabled"

    # API_Tested# PUT /scans
    def test_edit_scan_schedule_limit(self, create_two_scheduled_scans):
        """
        NES-9210: Test scan schedule limits when updating scans

        Scenarios tested:
        [x] Test that updating a scan with schedule enabled disables schedule of other scans
        [x] Test that updating a scan with unrelated data does not alter schedules
        [x] Test that updating a scan that has schedule enabled does not de-schedule the scan
        """
        scan1_id, scan2_id = create_two_scheduled_scans

        def is_enabled(scan):
            basic = scan['settings']['basic']
            groups = basic['groups']
            schedules = list(filter(lambda group: group['name'] == 'schedule', groups))
            return len(schedules) and schedules[0]['enabled']

        # test that only one is scheduled
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert not is_enabled(scan1), "First scan is still scheduled after second scheduled scan created"

        assert is_enabled(scan2), "Second scan is not scheduled even though we created it with a schedule enabled"

        # change something random in the unscheduled scan
        unrelated_update_payload = {
            'settings': {
                'name': 'scan1 updated',
                'text_targets': '127.0.0.2',
            }
        }

        self.cat.api.scans.configure(scan1_id, payload=unrelated_update_payload)

        # test that it did not unschedule the second scan
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert not is_enabled(scan1), "First scan became scheduled???"

        assert is_enabled(scan2), "Second scan is not scheduled after unrelated update to first scan"

        # edit the first scan to be scheduled
        update_schedule_payload = {
            'settings': {
                'name': 'scan1 enabled',
                'enabled': True,
                'starttime': '20300101T120000',
                'timezone': 'US/Samoa',
                'launch': 'ONETIME',
                'rrules': 'FREQ=ONETIME',
                'text_targets': '127.0.0.3',
            }
        }

        self.cat.api.scans.configure(scan1_id, payload=update_schedule_payload)

        # test that the second scan became de-scheduled
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert is_enabled(scan1), "First scan is not scheduled after update"

        assert not is_enabled(scan2), "Second scan is still scheduled after first was updated"

        # update something in the scheduled scan
        update_name_payload = {
            'settings': {
                'name': 'scan1 renamed',
                'text_targets': '127.0.0.4',
                "enabled": 1
            }
        }

        self.cat.api.scans.configure(scan1_id, payload=update_name_payload)

        # test that this didn't unschedule the scan
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert is_enabled(scan1), "First scan is not scheduled after unrelated update"

        assert not is_enabled(scan2), "Second scan is mysteriously scheduled after first was updated"

    # API_Tested# PUT /scans/{id}/schedule
    def test_schedule_scan_schedule_limit(self, create_two_unscheduled_scans):
        """
        NES-9210: Test scan schedule limits when scheduling scans

        Scenarios tested:
        [x] Test that scheduling a scan disables schedule of other scans
        """
        scan1_id, scan2_id = create_two_unscheduled_scans

        def is_enabled(scan):
            basic = scan['settings']['basic']
            groups = basic['groups']
            schedules = list(filter(lambda group: group['name'] == 'schedule', groups))
            return len(schedules) and schedules[0]['enabled']

        # sanity check that they're unscheduled
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert not is_enabled(scan1), "First scan was mysteriously scheduled"

        assert not is_enabled(scan2), "Second scan was mysteriously scheduled"

        # de-schedule one using the /schedule API, check both are still unscheduled
        self.cat.api.scans.schedule(scan1_id, enabled=False)
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert not is_enabled(scan1), "First scan was mysteriously scheduled after not-schedule was called"

        assert not is_enabled(scan2), "Second scan was mysteriously scheduled after not-schedule was called"

        # schedule one using the /schedule API, check result
        self.cat.api.scans.schedule(scan1_id, enabled=True)
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert is_enabled(scan1), "First scan was not scheduled after schedule was called"

        assert not is_enabled(scan2), "Second scan was mysteriously scheduled after first was scheduled"

        # schedule other using the /schedule API, check that it de-scheduled the first
        self.cat.api.scans.schedule(scan2_id, enabled=True)
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert not is_enabled(scan1), "First scan was still scheduled after second was scheduled"

        assert is_enabled(scan2), "Second scan was not scheduled after schedule was called"

    # API_Tested# GET /editor/scans/{id}
    def test_other_enabled_schedules_schedule_limit(self):
        """
        NES-9210: Test new API parameter that lists scheduled scans

        Scenarios tested:
        [x] Getting a scan populates the new 'other_enabled_schedules' field appropriately
        """
        config = {
            'enabled': True,
            'starttime': '20300101T120000',
            'timezone': 'US/Samoa',
            'launch': 'ONETIME',
            'rrules': 'FREQ=ONETIME',
            'description': 'Created by Automation',
            'text_targets': '127.0.0.1',
        }

        scan1_id = self.cat.api.scans.create(ScanModel(name='scan1', **config))['scan']['id']
        scan1 = self.cat.api.editor.get_scan(scan1_id)

        assert scan1['other_enabled_schedules'] == []

        scan2_id = self.cat.api.scans.create(ScanModel(name='scan2', **config))['scan']['id']
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert scan1['other_enabled_schedules'] == [{'id': scan2_id, 'name': 'scan2'}]

        assert scan2['other_enabled_schedules'] == []

        self.cat.api.scans.schedule(scan2_id, enabled=False)
        scan1 = self.cat.api.editor.get_scan(scan1_id)
        scan2 = self.cat.api.editor.get_scan(scan2_id)

        assert scan1['other_enabled_schedules'] == []

        assert scan2['other_enabled_schedules'] == []

        self.cat.api.scans.delete(scan1_id)
        self.cat.api.scans.delete(scan2_id)

    # API_Tested# POST /scans/{id}/copy
    def test_copy_schedule_limit(self, create_two_scheduled_scans):
        """
        NES-9210: Test schedule limit behavior on copied scans

        Scenarios tested:
        [x] Copying a scheduled scan results in an unscheduled copy
        """
        scan1_id, scan2_id = create_two_scheduled_scans
        scan3_id = self.cat.api.scans.copy(scan2_id, name='copy of scan2')['id']

        def is_enabled(scan):
            basic = scan['settings']['basic']
            groups = basic['groups']
            schedules = list(filter(lambda group: group['name'] == 'schedule', groups))
            return len(schedules) and schedules[0]['enabled']

        # test that copy is not scheduled
        scan2 = self.cat.api.editor.get_scan(scan2_id)
        scan3 = self.cat.api.editor.get_scan(scan3_id)

        assert is_enabled(scan2), "Second scan was not scheduled after copy"

        assert not is_enabled(scan3), "Copied scan was still scheduled after copy"

        self.cat.api.scans.delete(scan3_id)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [
        {'scan': {"filename": 'advanced_agent_scan_rjc3zu.nessus'}}], indirect=True)
    # API_Tested# GET /scans/{scan_id}?filter...
    def test_scan_filter_commas_numeric(self, import_scan):
        """
        Perform various comma-separated filter requests of a numeric field and check that we appropriately split terms
        by comma.

        [x] searching with no filter returns all vulns
        [x] filter for one result returns one result
        [x] filter == a,b returns a and b
        [x] filter == a,b,z returns a and b (z doesn't exist)
        [x] filter != a,b returns c, d, ...
        [x] filter contains a,b returns aa, bc, ...
        [x] filter not contains a,b does not return aa, bc, ...
        """
        scan_id = import_scan
        details = self.cat.api.scans.details(scan_id)

        all_plugin_ids = [v['plugin_id'] for v in details['vulnerabilities']]

        assert len(all_plugin_ids) > 10, "Not enough vulnerabilities in this scan for this test"

        assert len(all_plugin_ids) == len(set(all_plugin_ids)), "Duplicate plugin ids were present"

        all_count = len(all_plugin_ids)
        plugin_a = all_plugin_ids[0]
        plugin_b = all_plugin_ids[1]
        plugin_c = all_plugin_ids[2]

        def search_for_value(op, value):
            query = '?filter.0.quality=%s&filter.0.filter=plugin_id&filter.search_type=and&filter.0.value=%s' % (
                op, value)
            scan_details = self.cat.api.scans.details(scan_id, query=query)
            return [v['plugin_id'] for v in scan_details['vulnerabilities']]

        # searching for one plugin should still work
        result = search_for_value('eq', plugin_a)

        assert len(result) == 1
        assert plugin_a in result

        # search for two plugins using a comma
        result = search_for_value('eq', '%s,%s' % (plugin_a, plugin_b))

        assert len(result) == 2
        assert plugin_a in result
        assert plugin_b in result

        # searching for a non-existent value doesn't break the rest
        result = search_for_value('eq', '%s,%s,999999' % (plugin_a, plugin_b))

        assert len(result) == 2
        assert plugin_a in result
        assert plugin_b in result

        # searching for (all but) two plugins using a comma
        result = search_for_value('neq', '%s,%s' % (plugin_a, plugin_b))

        assert len(result) == all_count - 2
        assert plugin_a not in result
        assert plugin_b not in result
        assert plugin_c in result

        # string matching using a comma
        short_plugin_a = str(plugin_a)[:3]
        short_plugin_b = str(plugin_b)[:3]
        result = search_for_value('match', '%s,%s' % (short_plugin_a, short_plugin_b))

        assert plugin_a in result
        assert plugin_b in result
        assert len(result) < all_count

        # string (un-) matching using a comma
        result = search_for_value('nmatch', '%s,%s' % (short_plugin_a, short_plugin_b))

        assert plugin_a not in result
        assert plugin_b not in result
        assert result, "All results filtered out but there should be something left"

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [
        {'scan': {"filename": 'advanced_agent_scan_rjc3zu.nessus'}}], indirect=True)
    # API_Tested# GET /scans/{scan_id}?filter...
    def test_scan_filter_commas_string(self, import_scan):
        """
        Perform various comma-separated filter requests of a string field and check that we appropriately split terms
        by comma.

        [x] searching with no filter returns all vulns
        [x] filter for one result returns one result
        [x] filter == a,b returns a and b
        [x] filter == a,b,z returns a and b (z doesn't exist)
        [x] filter != a,b returns c, d, ...
        [x] filter contains a,b returns aa, bc, ...
        [x] filter not contains a,b does not return aa, bc, ...
        """
        scan_id = import_scan
        details = self.cat.api.scans.details(scan_id)

        all_families = [v['plugin_family'] for v in details['vulnerabilities']]
        all_families = list(set(all_families))

        assert len(all_families) > 3, "Not enough plugin families in this scan for this test"

        all_count = len(all_families)
        family_a = all_families[0]
        family_b = all_families[1]
        family_c = all_families[2]

        def search_for_value(op, value):
            query = '?filter.0.quality=%s&filter.0.filter=plugin_family&filter.search_type=and&filter.0.value=%s' % (
                op, value)
            scan_details = self.cat.api.scans.details(scan_id, query=query)
            return list(set([v['plugin_family'] for v in scan_details['vulnerabilities']]))

        # searching for one family should still work
        result = search_for_value('eq', family_a)

        assert len(result) == 1
        assert family_a in result

        # search for two families using a comma
        result = search_for_value('eq', '%s,%s' % (family_a, family_b))

        assert len(result) == 2
        assert family_a in result
        assert family_b in result

        # searching for a non-existent value doesn't break the rest
        result = search_for_value('eq', '%s,%s,999999' % (family_a, family_b))

        assert len(result) == 2
        assert family_a in result
        assert family_b in result

        # searching for (all but) two families using a comma
        result = search_for_value('neq', '%s,%s' % (family_a, family_b))

        assert len(result) == all_count - 2
        assert family_a not in result
        assert family_b not in result
        assert family_c in result

        # string matching using a comma
        short_family_a = str(family_a)[:3]
        short_family_b = str(family_b)[:3]
        result = search_for_value('match', '%s,%s' % (short_family_a, short_family_b))

        assert family_a in result
        assert family_b in result
        assert len(result) < all_count

        # string (un-) matching using a comma
        result = search_for_value('nmatch', '%s,%s' % (short_family_a, short_family_b))

        assert family_a not in result
        assert family_b not in result
        assert result, "All results filtered out but there should be something left"
