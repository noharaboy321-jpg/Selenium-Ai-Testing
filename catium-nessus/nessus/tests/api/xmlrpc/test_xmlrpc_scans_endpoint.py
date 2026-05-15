"""
Nessus XML RPC scans Endpoint verification

:copyright: Tenable Network Security, 2018
:date: Jan 08, 2019
:last_modified: Mar 16, 2022
:author: @lambaliya, @kpanchal
"""
from http import HTTPStatus

import pytest

from nessus.lib.const import API


@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home_mat
@pytest.mark.nessus_manager_mat
@pytest.mark.nessus_pro_mat
@pytest.mark.usefixtures('nessus_xmlrpc_api_login')
class TestXmlrpcScanEndpoint:
    """ STA-102: Implement test cases for xmlrpc scan endpoints """

    cat = None

    # API_Tested# POST /xmlrpc/scan/new
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_scan_add(self, add_xmlrpc_scan, add_xmlrpc_policy):
        """
        STA-102: Implement test cases for xmlrpc scan endpoint /xmlrpc/scan/new

        Scenarios tested:
            [x] Successfully add scan
        """
        scan_root = add_xmlrpc_scan
        policy_name = add_xmlrpc_policy.find("./contents/policy/policyName").text

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        scans_element = scan_root.find("./contents/scan")

        assert scans_element is not None, 'reply/contents/scan element not found'

        scan_name = scan_root.find("./contents/scan/scan_name").text

        # Verifying that policy name and scan name matches
        # Policy name itself passed in scan creation payload as scan name
        assert policy_name in scan_name, "Name of created scan not found in response"

    # API_Tested# POST /xmlrpc/scan/list
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_list_xmlrpc_scan(self):
        """
        STA-102: Implement test cases for xmlrpc scan endpoint /xmlrpc/scan/list

        Scenarios tested:
            [x] Successfully get list of scans
        """
        scans_root = self.cat.api.xmlrpc.list_scans()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert scans_root.find("./contents/scans/scanList"), "Failed to list xml rpc scans"

    test_params = [
        ("pause_scan", API.Scan.Status.PAUSING, "pause"),
        ("resume_scan", API.Scan.Status.RESUMING, "resume"),
        ("stop_scan", API.Scan.Status.STOPPING, "stop")
    ]

    # API_Tested# POST /xmlrpc/scan/pause
    # API_Tested# POST /xmlrpc/scan/resume
    # API_Tested# POST /xmlrpc/scan/stop
    @pytest.mark.parametrize('method, status, status_msg', test_params)
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_scan_status(self, add_xmlrpc_scan, method, status, status_msg):
        """
        STA-102: Implement test cases for xmlrpc scan endpoint /xmlrpc/scan/(pause/resume/stop)

        Scenarios tested:
            [x] Successfully pause scan
            [x] Successfully resume scan
            [x] Successfully stop scan
        """
        scan_root = add_xmlrpc_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        uuid_element = scan_root.find("./contents/scan/uuid")

        assert uuid_element is not None, "'/contents/scan/uuid' tag not found in xml"

        scan_uuid = uuid_element.text
        scans_root = getattr(self.cat.api.xmlrpc, method)(scan_uuid)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        status_element = scans_root.find("./contents/scan/status")

        assert status_element is not None, "'/contents/scan/status' tag not found in xml"

        assert status_element.text == status, "Failed to {} scan".format(status_msg)
