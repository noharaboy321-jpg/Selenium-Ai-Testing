"""
Nessus Scan Vulnerability Severity Base verifications for scan_diff

Test cases to verify scan_diff with severity base feature

:copyright: Tenable Network Security, 2021
:date: Aug 3, 2022
:author: @krpatel
"""

import pytest

from _pytest.fixtures import SubRequest
from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_THIRTY_MINUTES
from catium.lib.log import create_logger
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API
from nessus.tests.api.scan.test_nessus_scan_severity_base import set_severity_basis_value, get_severity_basis_value

log = create_logger()


@pytest.fixture()
def set_severity_basis(request: SubRequest):
    """This fixture sets the 'severity_basis' value"""
    severity_basis_new_value = request.param.get('value')
    severity_basis_value = get_severity_basis_value()

    if severity_basis_value != severity_basis_new_value or severity_basis_value is None:
        set_severity_basis_value(value=severity_basis_new_value, restart=False)

    return severity_basis_new_value


@pytest.mark.usefixtures('wait_for_plugin_families_to_be_available')
class TestScanDiffSeverityBase:
    """Test cases related to Scan Severity Base in Nessus"""
    cat = None

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('set_severity_basis', 'nessus_api_login')
    @pytest.mark.parametrize('set_severity_basis', [{'value': 'cvss_v2'}], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_scan_diff_history_with_different_severity_base(self, create_scan, set_severity_basis):
        """
        NES-12491: [Automation] Verify scan diff report

        Scenarios tested:
            [x] Verify that scan diff is empty or minimal when scan gets executed with different severity base.
        """
        scan_id = create_scan['scan']['id']

        self.cat.api.scans.launch(scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)

        set_severity_basis_value(value="cvss_v3", api=self.cat.api)

        self.cat.api.scans.launch(scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)

        scan_details = self.cat.api.scans.details(scan_id)
        history_id = scan_details['history'][0]['history_id']
        diff_id = scan_details['history'][1]['history_id']

        scan_diff = self.cat.api.scans.diff_scan_history(scan_id, diff_id, history_id)
        # Verify that scan diff is empty or minimal when scan gets executed with different severity base.
        try:
            assert scan_diff == {}, "Scan diff is not empty"
        except AssertionError:
            assert len(scan_diff['vulnerabilities']) <= 3 and all([vulnerability for vulnerability in scan_diff[
                'vulnerabilities'] if vulnerability['severity'] < 2]), \
                "Scan diff is considerable when scan executed with different severity base."
