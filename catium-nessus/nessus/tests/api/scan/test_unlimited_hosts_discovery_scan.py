"""
Nessus Scan Endpoint verification

Special Test cases for Nessus Home host discovery
:copyright: Tenable Network Security, 2019
:date: July 26, 2022

:author: @krpatel
"""

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_THIRTY_MINUTES
from catium.lib.log.log import create_logger
from nessus.helpers.waiters import wait_for_scan
from nessus.lib.const import API

log = create_logger()


@pytest.mark.skip_acceptance
@pytest.mark.nessus_home
@pytest.mark.nessus_smoke
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusHomeHostDiscovery:
    """ Tests for Nessus scan Endpoint on Home installs """

    cat = None

    @pytest.mark.xfail(reason="Test is very intermittent and depends on target availability.")
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_64_host_discovery.json'),
         'scan_type': 'discovery'}], indirect=True)
    def test_unlimited_host_discovery(self, create_scan):
        """
        Test that Host Discovery scans are unlimited on Nessus Essentials

        Scenarios tested:
        [x] Create a Host Discovery scan for 64 IPs
        [x] Run the scan
        [x] Verify that the scan found more than 32 results
        """
        # Get Scan related information for newly created scan and verify its 200 response
        scan_id = create_scan['scan']['id']
        self.cat.api.scans.launch(scan_id)

        wait_for_scan(api=self.cat.api, scan_id=scan_id, status=API.Scan.Status.COMPLETED,
                      timeout=TIME_THIRTY_MINUTES * 2)
        response = self.cat.api.scans.details(scan_id)
        assert 'info' in response
        assert 'hostcount' in response['info']
        assert response['info']['hostcount'] > 32, "Not enough results in scan to prove that scan was unlimited"
