"""
Test cases for Nessus Remote Endpoint

:copyright: Tenable Network Security, 2019
:date: Nov 05, 2020
:author: @kpanchal
"""

from http import HTTPStatus

import pytest


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusRemoteEndpoint:
    """ Tests for Nessus Remote Endpoint """

    cat = None

    # API_Tested# GET /remote/cert
    def test_get_remote_cert(self):
        """
        NES-12247: [API] Verify GET "/remote/cert"

        Scenarios tested:
          [x] Verify GET /remote/cert
        """
        response = self.cat.api.remote.get_cert()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert 'cert' in response, 'Missing field "cert" from response'

        assert response['cert'].startswith('-----BEGIN CERTIFICATE-----')

    # API_Tested# GET /remote/properties
    def test_get_remote_properties(self):
        """
        NES-12247: [API] Verify GET "/remote/properties"

        Scenarios tested:
          [x] Verify GET /remote/properties
        """
        nessus_properties = self.cat.api.server.properties()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        nessus_ui_version = nessus_properties['nessus_ui_version']
        nessus_version = nessus_properties['server_version']

        response = self.cat.api.remote.get_properties()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert all([response['nessus_ui_version'] == nessus_ui_version,
                    response['nessus_version'] == nessus_version]), \
            "'nessus_version' and/or 'nessus_ui_version' is getting mismatch or empty."

        assert 'key' in response, 'Missing field "key" from response'

        assert len(response['key']) > 0, 'Expected key to be present, got empty key instead'
