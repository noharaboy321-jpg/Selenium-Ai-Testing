"""
Nessus XML RPC server Endpoint verification

:copyright: Tenable Network Security, 2019
:date: Jan 17, 2019
:last_modified: Mar 16, 2022
:author: @dkothari, @kpanchal
"""
from http import HTTPStatus

import pytest


@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home_mat
@pytest.mark.nessus_manager_mat
@pytest.mark.nessus_pro_mat
@pytest.mark.usefixtures('nessus_xmlrpc_api_login')
class TestXmlrpcServerEndpoint:
    """ STA-103: Implement test cases for xmlrpc Server endpoints. """

    cat = None

    # API_Tested# POST xmlrpc/server/load
    def test_xmlrpc_post_server_load(self):
        """
        STA-103: Implement test cases for xmlrpc server endpoint /xmlrpc/server/load
        
        Scenarios tested:
            [x] Successfully get server load information.
        """
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        root = self.cat.api.xmlrpc.server_load()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        assert root.find('./contents/load') is not None, "'/contents/load' tag not found in xml"

    # API_Tested# GET xmlrpc/server/load
    def test_xmlrpc_get_server_status_load(self):
        """
        STA-103: Implement test cases for xmlrpc server endpoint /xmlrpc/server/load
        
        Scenarios tested:
            [x] Successfully get server load information.
        """
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        root = self.cat.api.xmlrpc.get_server_load_status()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        assert root.find('./contents/load') is not None, "'/contents/load' tag not found in xml"
