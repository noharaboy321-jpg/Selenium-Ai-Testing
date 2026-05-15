"""
Nessus Remote Scanners Endpoints Test

:copyright: Tenable Network Security, 2018
:last_modified: July 15, 2020
:author: @lambaliya.ctr, @vsoni, @kpanchal
"""
from http import HTTPStatus

import pytest

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS, TIME_TWO_MINUTES
from nessus.helpers.scanner import scanner_token
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'add_scanner_locally')
class TestNessusRemoteScannerEndpoint:
    """Tests for Nessus remote scanner Endpoint"""

    cat = None

    # GET   /remote/scanner/jobs
    # PUT   /remote/scanner/jobs/{job_uuid}
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize("scan_status", [
        API.Scan.Status.PENDING,
        API.Scan.Status.RUNNING,
        API.Scan.Status.PAUSED,
        API.Scan.Status.RESUMING,
        API.Scan.Status.STOPPED,
        API.Scan.Status.IMPORTED,
        API.Scan.Status.CANCELING,
        API.Scan.Status.EMPTY,
        API.Scan.Status.PAUSING,
        API.Scan.Status.STOPPING])
    def test_configure_remote_scanner_job(self, scan_status, create_scan_with_scanner):
        """
        STA-86: Implement test case for /remote/scanner/jobs(Configure job)
        Scenarios tested:
              [x] Successfully configured a job
              [ ] Configured a job with status [pending, running, paused, pause, completed, resume, stop, aborted]
        """
        scan, scanner_info = create_scan_with_scanner
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.scans.launch(scan_id=scan["id"])
        # Verify scan status is running
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        with scanner_token(self.cat.api, scanner_info["scanner_token"]):
            result = wait_scan_state(api=self.cat.api, scan_id=scan["id"], end_state=API.Scan.Status.PENDING,
                                     timeout=TIME_THIRTY_SECONDS)
            # Verify scan is pass or fail to launch
            assert result, "Scan failed to launch."

            # verify job is created
            resp_jobs = self.cat.api.remote.get_remote_scanner_jobs()
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
            assert resp_jobs["jobs"], "Launched job missing from job's list"

            job = resp_jobs["jobs"][0]
            assert "id" in job, "Jobs element 0 does not contain id"

            # configure job with {"status": "running"}
            job_uuid = resp_jobs["jobs"][0]["id"]
            self.cat.api.remote.configure_remote_scanner_job(job_uuid, {'status': scan_status})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
            result = wait_scan_state(api=self.cat.api, scan_id=scan["id"], end_state=scan_status,
                                     timeout=TIME_THIRTY_SECONDS)
            assert result, "Failed to configure status: {}".format(scan_status)

            # Completing the scan for removal of scan
            self.cat.api.remote.configure_remote_scanner_job(job_uuid, {'status': API.Scan.Status.COMPLETED})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            result = wait_scan_state(api=self.cat.api, scan_id=scan["id"], end_state=API.Scan.Status.COMPLETED,
                                     timeout=TIME_THIRTY_SECONDS)
            # Verify scan is pass or fail to complete
            assert result, "Scan failed to complete."

    # GET   /remote/scanner/jobs
    # PUT   /remote/scanner/jobs/{job_uuid}
    # GET   /remote/scanner/jobs/{job_uuid}/policy
    def test_get_remote_scanner_job_policy(self, create_scan_with_scanner):
        """
        STA-86: Implement test case for /remote/scanner/jobs(Get remote scanner job policy)
        """
        scan, scanner_info = create_scan_with_scanner
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.scans.launch(scan_id=scan["id"])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        result = wait_scan_state(api=self.cat.api, scan_id=scan["id"], end_state=API.Scan.Status.PENDING,
                                 timeout=TIME_THIRTY_SECONDS)
        # Verify scan is pass or fail to launch
        assert result, "Scan failed to launch."

        with scanner_token(self.cat.api, scanner_info["scanner_token"]):
            # verify job is created
            resp_jobs = self.cat.api.remote.get_remote_scanner_jobs()
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
            assert resp_jobs["jobs"], "Launched job missing from job's list"

            job = resp_jobs["jobs"][0]
            assert "id" in job, "Jobs element 0 does not contain id"

            # configure job with {"status": "running"}
            job_uuid = resp_jobs["jobs"][0]["id"]
            self.cat.api.remote.configure_remote_scanner_job(job_uuid, {'status': API.Scan.Status.RUNNING})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            # verify policy of running job
            self.cat.api.remote.get_policy_for_scanner_remote_job(job_uuid)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            # Completing the scan for removal of scan
            self.cat.api.remote.configure_remote_scanner_job(job_uuid, {'status': API.Scan.Status.ABORTED})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            result = wait_scan_state(api=self.cat.api, scan_id=scan["id"], end_state=API.Scan.Status.ABORTED,
                                     timeout=TIME_THIRTY_SECONDS)
            # Verify scan is pass or fail to complete
            assert result, "Scan failed to complete."

    # GET   /remote/scanner/jobs
    # PUT   /remote/scanner/jobs/{job_uuid}
    # POST  /remote/scanner/jobs/{job_uuid}/cache
    @pytest.mark.parametrize("test_data", [{"file_path": 'nessus/tests/api/scan/test_data/',
                                            "file_name": 'advanced_scan_gxxyl6.db'}])
    def test_remote_scanner_job_cache_configuration(self, create_scan_with_scanner, test_data):
        """
        STA-86: Implement test case for /remote/scanner/jobs (Configure remote scan cache)
        """
        scan, scanner_info = create_scan_with_scanner
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.scans.launch(scan_id=scan["id"])
        # Verify scan status is running
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        result = wait_scan_state(api=self.cat.api, scan_id=scan["id"], end_state=API.Scan.Status.PENDING,
                                 timeout=TIME_THIRTY_SECONDS)
        # Verify scan is pass or fail to launch
        assert result, "Scan failed to launch."

        with scanner_token(self.cat.api, scanner_info["scanner_token"]):
            # verify job is created
            resp_jobs = self.cat.api.remote.get_remote_scanner_jobs()
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
            assert resp_jobs["jobs"], "Launched job missing from job's list"

            job = resp_jobs["jobs"][0]
            assert "id" in job, "Jobs element 0 does not contain id"

            # configure job with {"status": "running"}
            job_uuid = resp_jobs["jobs"][0]["id"]
            self.cat.api.remote.configure_remote_scanner_job(job_uuid, {'status': API.Scan.Status.RUNNING})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            # Verify cache configuration for job
            file_path = get_file_path(test_data['file_path'] + test_data['file_name'])
            self.cat.api.remote.configure_cache_for_remote_scanner(job_uuid, file_path)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            # Completing the scan for removal of scan
            self.cat.api.remote.configure_remote_scanner_job(job_uuid, {'status': API.Scan.Status.CANCELED})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            result = wait_scan_state(api=self.cat.api, scan_id=scan["id"], end_state=API.Scan.Status.CANCELED,
                                     timeout=TIME_THIRTY_SECONDS)
            # Verify scan is pass or fail to complete
            assert result, "Scan failed to complete."

    # GET   /remote/scanner/jobs
    # PUT   /remote/scanner/jobs/{job_uuid}
    # POST  /remote/scanner/jobs/{job_uuid}/upload
    @pytest.mark.parametrize("test_data", [{"file_path": 'nessus/tests/api/scan/test_data/',
                                            "file_name": 'advanced_scan_gxxyl6.db',
                                            "payload_for_upload": {"compression": 2, "key": "123456",
                                                                   "status": "completed"}}])
    def test_remote_scanner_job_upload_file(self, create_scan_with_scanner, test_data):
        """
        STA-86: Implement test case for /remote/scanner/jobs (upload file to remote scanner job)
        """
        scan, scanner_info = create_scan_with_scanner
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.scans.launch(scan_id=scan["id"])
        # Verify scan status is running
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        result = wait_scan_state(api=self.cat.api, scan_id=scan["id"], end_state=API.Scan.Status.PENDING,
                                 timeout=TIME_THIRTY_SECONDS)
        # Verify scan is pass or fail to launch
        assert result, "Scan failed to launch."

        with scanner_token(self.cat.api, scanner_info["scanner_token"]):
            # verify job is created
            resp_jobs = self.cat.api.remote.get_remote_scanner_jobs()
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)
            assert resp_jobs["jobs"], "Launched job missing from job's list"

            job = resp_jobs["jobs"][0]
            assert "id" in job, "Jobs element 0 does not contain id"

            # configure job with {"status": "running"}
            job_uuid = resp_jobs["jobs"][0]["id"]
            self.cat.api.remote.configure_remote_scanner_job(job_uuid, {'status': API.Scan.Status.RUNNING})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            # verify the upload file to job
            file_path = get_file_path(test_data['file_path'] + test_data['file_name'])
            json_payload = test_data["payload_for_upload"]
            self.cat.api.remote.upload_file_to_scanner_job(job_uuid, file_path, json_payload)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# GET remote/scanners/update
    def test_get_remote_scanner_updates(self, add_scanner_locally):
        """
        STA-88: Implement test case for /remote/scanner/updates

        Scenarios tested:
          [x] Successfully add remote scanner
          [x] Successfully fetch remote scanner updates
        """
        sleep(TIME_TWO_MINUTES, "waiting for server to be in ready state.")

        scanner_info = add_scanner_locally
        remote_scanner_token = scanner_info['scanner_response']['token']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.add_header({'MS-Scanner': "token={}".format(remote_scanner_token)})
        response = self.cat.api.remote.get_remote_scanner_update(distro=scanner_info['distro'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        print(response)
        assert response['plugins_md5'], "Expected key to be present, got empty key instead."

        self.cat.api.remove_header(key='MS-Scanner')

    # API_Tested# GET remote/scanners/plugins
    def test_get_remote_scanner_plugins(self, add_scanner_locally):
        """
        STA-87: Implement test case for /remote/scanner/plugins
        As per Pre-requisite, remote scanner should be added in Nessus Manager

         Scenarios tested:
          [x] Successfully add remote scanner
          [x] Successfully fetch remote scanner plugins
        """
        scanner_info = add_scanner_locally
        response = self.cat.api.remote.get_remote_scanner_plugins(
            remote_scanner_token=scanner_info['scanner_response']['token'], stream=True)

        assert response.status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % response.status_code
        assert response.headers['File-MD5'], "File-MD5 expected to be present, got empty instead"

    # API_Tested# PUT remote/scanners/directive/{directive_id}
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize("directive_status", [
        API.Scanners.Directive.Status.PENDING,
        API.Scanners.Directive.Status.RUNNING,
        API.Scanners.Directive.Status.PAUSED,
        API.Scanners.Directive.Status.RESUMING,
        API.Scanners.Directive.Status.STOPPED,
        API.Scanners.Directive.Status.IMPORTED,
        API.Scanners.Directive.Status.CANCELING,
        API.Scanners.Directive.Status.EMPTY,
        API.Scanners.Directive.Status.PAUSING,
        API.Scanners.Directive.Status.STOPPING])
    def test_change_remote_scanner_directive_status(self, add_scanner_locally, directive_status):
        """
        STA-85: Implement test case for /remote/scanner/directive/{directive_id}

        Scenarios tested:
          [x] Successfully add remote scanner
          [x] Successfully create logRequest directive of remote scanner
          [x] Successfully change status of logs directive
          [x] Verify the modified status of directive
        """
        scanner_info = add_scanner_locally
        remote_scanner_token = scanner_info['scanner_response']['token']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        scanner_id = scanner_info['id']

        # Creating logRequest directive for scanner
        self.cat.api.scanners.create_scanner_logrequest_directive(scanner_id=scanner_id, data={})

        logrequest_directive_info = self.cat.api.scanners.details(scanner_id)['logRequest']

        directive_id = logrequest_directive_info['id']
        directive_token = logrequest_directive_info['token']
        directive_message = logrequest_directive_info['message']

        edit_directive_payload = {'token': directive_token, 'status': directive_status, 'message': directive_message}

        with scanner_token(self.cat.api, remote_scanner_token):
            response = self.cat.api.remote.edit_remote_scanner_directive(directive_id, data=edit_directive_payload)

            assert response.status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % response.status_code

            assert self.cat.api.scanners.details(scanner_id)['logRequest']['status'] == directive_status, \
                "current directive Status should be same as modified status"

    # API_Tested# POST remote/scanners/directive/{directive_id}
    @pytest.mark.parametrize("test_data", [{"file_path": 'nessus/tests/api/scan/test_data/',
                                            "file_name": 'advanced_scan_gxxyl6.db'}])
    def test_remote_scanner_directive_file_upload(self, add_scanner_locally, test_data):
        """
        STA-85: Implement test case for /remote/scanner/directive/{directive_id}

        Scenarios tested:
          [x] Successfully add remote scanner
          [x] Successfully create logRequest directive of remote scanner
          [x] Successfully upload a file to logRequest directive
        """
        scanner_info = add_scanner_locally
        remote_scanner_token = scanner_info['scanner_response']['token']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        scanner_id = scanner_info['id']

        self.cat.api.scanners.create_scanner_logrequest_directive(scanner_id=scanner_id, data={})

        session_token = self.cat.api._session_token
        directive_id = self.cat.api.scanners.details(scanner_id)['logRequest']['id']
        file_path = get_file_path(test_data['file_path'] + test_data['file_name'])

        with scanner_token(self.cat.api, remote_scanner_token):
            response = self.cat.api.remote.remote_scanner_directive_file_upload(
                directive_id, file_path, data={"token": session_token})

            assert response.status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % response.status_code
