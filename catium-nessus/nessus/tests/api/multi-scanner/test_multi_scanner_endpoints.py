"""
Nessus Multi-Scanner Endpoints Test cases

:copyright: Tenable Network Security, 2019
:date: January 10, 2019
:last_modified: Apr 07, 2021
:author: vsoni, @kpanchal
"""
from http import HTTPStatus

import pytest

from catium.lib.const import TIME_THIRTY_SECONDS
from nessus.helpers.scanner import scanner_token
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const.constants import API


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusScannerEndpoint:
    """Tests for Nessus scanner Endpoint"""

    cat = None

    # API_Tested# POST /multi-scanner/register
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize('add_scanner_locally', [{'is_multi_scanner': True}], indirect=True)
    def test_multi_scanner_register(self, add_scanner_locally):
        """
        STA-82: Implement test case for /multi-scanner/register

        Scenarios tested:
          [x] Successfully register multi-scanner
        """
        multi_scanner_info = add_scanner_locally

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        multi_scanner_token = multi_scanner_info['scanner_response']['reply']['contents']['token']

        assert multi_scanner_token, 'Expected token to be present, got empty token instead.'

    # API_Tested# POST /multi-scanner/register
    # API_Tested# POST /multi-scanner/remote/delete
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize('add_scanner_locally', [{'is_multi_scanner': True}], indirect=True)
    def test_remove_multi_scanner(self, add_scanner_locally):
        """
        STA-83: Implement test case for /multi-scanner/remote/* endpoints

        Scenarios tested:
          [x] Successfully register multi-scanner
          [x] Successfully delete multi-scanner
        """
        multi_scanner_info = add_scanner_locally
        multi_scanner_token = multi_scanner_info['scanner_response']['reply']['contents']['token']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        with scanner_token(self.cat.api, multi_scanner_token):
            self.cat.api.multi_scanner.delete()

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        response = self.cat.api.scanners.get_list()
        new_scanner = next((scanner for scanner in response['scanners'] if
                            scanner['name'] == multi_scanner_info['name']), None)

        assert new_scanner is None, "Scanner %s is still present after delete." % new_scanner['name']

    # API_Tested# POST /multi-scanner/register
    # API_Tested# POST /multi-scanner/remote/ping
    @pytest.mark.parametrize('add_scanner_locally', [{'is_multi_scanner': True}], indirect=True)
    def test_get_multi_scanner_job(self, create_scan_with_scanner):
        """
        STA-83: Implement test case for /multi-scanner/remote/* endpoints

        Scenarios tested:
          [x] Successfully register multi-scanner
          [x] create a scan using multi-scanner
          [x] Successfully fetch the multi-scanner jobs
        """
        scan, multi_scanner_info = create_scan_with_scanner

        multi_scanner_token = multi_scanner_info['scanner_response']['reply']['contents']['token']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.scans.launch(scan_id=scan["id"])

        with scanner_token(self.cat.api, multi_scanner_token):
            payload_data = {"id": multi_scanner_info['id'],
                            "uuid": multi_scanner_info['suuid'],
                            "platform": multi_scanner_info['platform'],
                            "engine_version": multi_scanner_info['engine_version'],
                            "ui_version": multi_scanner_info['ui_version']
                            }
            response = self.cat.api.multi_scanner.get_jobs(payload=payload_data)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            assert response['reply']['contents']['jobs'][0]['name'] == scan['name'], \
                "Scan name inside jobs should be exact same as scan name while created"

            # Completing the Scan for removal of scan
            self.cat.api.multi_scanner.edit_job(data={"id": response['reply']['contents']['jobs'][0]['id'],
                                                      "status": API.Scan.Status.COMPLETED})

            wait_scan_state(api=self.cat.api, scan_id=scan['id'], end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_SECONDS)

    # API_Tested# POST /multi-scanner/register
    # API_Tested# POST /multi-scanner/remote/job
    # API_Tested# POST /multi-scanner/remote/ping
    @pytest.mark.parametrize('add_scanner_locally', [{'is_multi_scanner': True}], indirect=True)
    @pytest.mark.parametrize("scan_status", [
        API.Scan.Status.PENDING, API.Scan.Status.RUNNING, API.Scan.Status.PAUSED, API.Scan.Status.RESUMING,
        API.Scan.Status.STOPPED, API.Scan.Status.IMPORTED, API.Scan.Status.CANCELING, API.Scan.Status.EMPTY,
        API.Scan.Status.PAUSING, API.Scan.Status.STOPPING])
    def test_edit_multi_scanner_job(self, scan_status, create_scan_with_scanner):
        """
        STA-83: Implement test case for /multi-scanner/remote/* endpoints

        Scenarios tested:
          [x] Successfully register multi-scanner
          [x] create a scan using multi-scanner
          [x] Change the status of job
          [x] Successfully fetch the multi-scanner job status and verify
        """
        scan, multi_scanner_info = create_scan_with_scanner
        multi_scanner_token = multi_scanner_info['scanner_response']['reply']['contents']['token']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.scans.launch(scan_id=scan["id"])

        with scanner_token(self.cat.api, multi_scanner_token):
            payload_data = {"id": multi_scanner_info['id'],
                            "uuid": multi_scanner_info['suuid'],
                            "platform": multi_scanner_info['platform'],
                            "engine_version": multi_scanner_info['engine_version'],
                            "ui_version": multi_scanner_info['ui_version']
                            }
            job_details = self.cat.api.multi_scanner.get_jobs(payload=payload_data)['reply']['contents']['jobs'][0]

            self.cat.api.multi_scanner.edit_job(data={"id": job_details['id'],
                                                      "status": scan_status})

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            response = self.cat.api.multi_scanner.get_jobs(payload=payload_data)

            assert response['reply']['contents']['jobs'][0]['status'] == scan_status, \
                "Scan status should match with modified status"

            # Completing the scan for removal of scan
            self.cat.api.multi_scanner.edit_job(data={"id": job_details['id'],
                                                      "status": API.Scan.Status.COMPLETED})

            wait_scan_state(api=self.cat.api, scan_id=scan["id"], end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_SECONDS)
