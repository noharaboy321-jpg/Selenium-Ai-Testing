"""
Unit test for Nessus to retrieve a KB item

This test is using a static instance of Nessus

:copyright: Tenable Network Security, 2017
:date: Jul 14, 2017
:author: @jyerge
"""
from http import HTTPStatus

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_THIRTY_MINUTES
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API


@pytest.mark.scanning
@pytest.mark.unittest
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusGetKBItem:
    """Test the ability to retrieve a KB item from Nessus"""

    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/kb
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'},  # NQA-625,
    ])
    def test_nessus_get_get_kb_item(self, create_scan):
        """Verifies that a KB item can be downloaded from Nessus via the API"""
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
        hosts_out = self.cat.api.scans.details(scan_id=scan_id)
        resp_val = self.cat.api.scans.get_kb(scan_id=scan_id, host_id=hosts_out['hosts'][0]['host_id'])
        assert self.cat.api.http_status_code == HTTPStatus.OK,\
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK.value)

        assert resp_val, 'kb content is none'
