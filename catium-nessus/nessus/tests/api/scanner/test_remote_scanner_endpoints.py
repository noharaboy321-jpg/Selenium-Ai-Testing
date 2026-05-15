"""
Nessus API test cases related to Remote Scanner.

:copyright: Tenable Network Security, 2019
:date: January 04, 2019
:last_modified: July 15, 2020
:author: vsoni, @jchavda, @kpanchal
"""
from http import HTTPStatus

import pytest
from requests import HTTPError

from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_TWO_MINUTES
from nessus.helpers.scanner import scanner_token


@pytest.mark.nessus_manager_mat
@pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_scanner_locally')
class TestNessusRemoteScannerEndpoint:
    """ Tests for Nessus Remote scanner Endpoint """

    cat = None

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
        sleep(TIME_TWO_MINUTES, "waiting for server to be in ready state.")

        scanner_info = add_scanner_locally
        response = self.cat.api.remote.get_remote_scanner_plugins(
            remote_scanner_token=scanner_info['scanner_response']['token'], stream=True)

        assert response.status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % response.status_code
        assert response.headers['File-MD5'], "File-MD5 expected to be present, got empty instead"

    # API_Tested# PUT remote/scanner/
    @pytest.mark.nessus_manager
    def test_edit_remote_scanner(self, add_scanner_locally):
        """
        STA-84: Implement test case for /remote/scanner

         Scenarios tested:
            [x] Successfully Edit remote scanner
        """
        scanner_info = add_scanner_locally

        # Get registration code
        registration_key = self.cat.api.server.properties()['license']['activation_code']

        remote_scanner_token = scanner_info['scanner_response']['token']
        with scanner_token(self.cat.api, remote_scanner_token):
            response = self.cat.api.remote.edit_remote_scanner(registration_code=registration_key)
            assert response.status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % response.status_code

        # Get details of created remote scanner
        details = self.cat.api.scanners.details(scanner_info['id'])
        code = details['registration_code']

        # Verify if registration code has been set
        assert code == registration_key, 'Registration code has not been updated for {}'.format(scanner_info['name'])

    # API_Tested# DELETE remote/scanner/
    @pytest.mark.nessus_manager
    def test_delete_remote_scanner(self, add_scanner_locally):
        """
        STA-84: Implement test case for delete remote scanner

        Scenarios tested:
            [x] Successfully delete remote scanner
        """
        scanner_info = add_scanner_locally

        remote_scanner_token = scanner_info['scanner_response']['token']
        with scanner_token(self.cat.api, remote_scanner_token):
            response = self.cat.api.remote.delete_remote_scanner()
            assert response.status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % response.status_code

        # Verify deleted remote scanner is not present in list
        response = self.cat.api.scanners.get_list()
        new_scanner = next((scanner for scanner in response['scanners'] if scanner['name'] == scanner_info['name']),
                           None)
        assert new_scanner is None, "Remote Scanner {} is still present after delete.".format(new_scanner['name'])

    # API_Tested# GET /remote/scanner/core
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('add_scanner_locally', [{'scanner_details': {'distro': 'agent-win-x86-64',
                                                                          'platform': 'Windows'}}], indirect=True)
    def test_get_remote_scanner_core(self, add_scanner_locally):
        """
        STA-84: Implement test case for /remote/scanner/core

        Scenarios tested:
            [x] Successfully get remote/scanner/core info.
            [x] Get status code 500 if Core update not found for distro
        """
        scanner_info = add_scanner_locally
        remote_scanner_token = scanner_info['scanner_response']['token']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        with scanner_token(self.cat.api, remote_scanner_token):
            try:
                self.cat.api.remote.get_remote_scanner_core(distro=scanner_info['distro'])
            except HTTPError:
                assert self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR, \
                    'Expected 500, got %s instead' % self.cat.api.http_status_code
                assert self.cat.api._text == '{"error":"core update not found for %s"}' % scanner_info['distro'], \
                    'Invalid distro %s' % scanner_info['distro']
            else:
                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead' % self.cat.api.http_status_code
