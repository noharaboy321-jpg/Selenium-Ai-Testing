"""
Nessus API test cases related to xmlrpc miscellaneous Endpoint and file endpoints

:copyright: Tenable Network Security, 2019
:date: Jan 08, 2019
:last_modified: Mar 16, 2022
:author: @jchavda, @kpanchal
"""
from http import HTTPStatus

import pytest

from catium.helpers.testdata import get_file_path
from nessus.helpers.waiters import wait_for_xmlrpc_scan_to_completed


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager_mat
@pytest.mark.nessus_pro_mat
@pytest.mark.usefixtures('nessus_xmlrpc_api_login')
class TestXmlrpcMiscellaneousEndpoint:
    """
    STA-98: Implement test cases for xmlrpc miscellaneous endpoints
    """
    cat = None

    # API_Tested# GET /xmlrpc/feed
    def test_xmlrpc_get_feed(self):
        """
        STA-98: Implement test cases for xmlrpc miscellaneous endpoint /xmlrpc/feed

        Scenarios tested:
            [x] Successfully get feed information
        """
        root = self.cat.api.xmlrpc.get_feed()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        feed_element = root.find("./contents/feed")

        assert feed_element.text == 'ProFeed', 'Unable to get feed information'

    # API_Tested# POST /xmlrpc/login
    @pytest.mark.nessus_home
    def test_xmlrpc_login(self):
        """
        STA-98: Implement test cases for xmlrpc miscellaneous endpoint /xmlrpc/login

        Scenarios tested:
            [x] Successfully login into nessus xmlrpc
        """
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# POST /xmlrpc/logout
    @pytest.mark.nessus_home
    def test_xmlrpc_logout(self):
        """
        STA-98: Implement test cases for xmlrpc miscellaneous endpoint /xmlrpc/logout

        Scenarios tested:
            [x] Successfully logout from active nessus xmlrpc session.
        """
        self.cat.api.logout()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# POST /xmlrpc/reset
    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_reset(self, add_xmlrpc_scan):
        """
        STA-98: Implement test cases for xmlrpc miscellaneous endpoint /xmlrpc/reset

        Scenarios tested:
            [x] Successfully Deleted matching scan and report from nessus xmlrpc.
        """
        new_scan = add_xmlrpc_scan
        name = new_scan.find('./contents/scan/scan_name')

        self.cat.api.session_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        root = self.cat.api.xmlrpc.reset(report_name=name.text)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        deleted_element = root.find("./contents/msg")

        assert deleted_element is not None, "'reply/contents/msg' element not found"

        assert deleted_element.text == 'Deleted', 'Unable to delete/cancel the Report'

    # API_Tested #POST /xmlrpc/file/report/download
    @pytest.mark.nessus_home
    @pytest.mark.skip_rhel8
    def test_xmlrpc_report_file_download(self, add_xmlrpc_scan):
        """
        STA-99: Implement test case for /xmlrpc/file/report/download

        Scenarios tested:
            [x] Successfully download xmlrpc report file
        """
        new_scan = add_xmlrpc_scan
        scan_uuid = new_scan.find('./contents/scan/uuid')

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        # wait for scan to be in a 'completed' status before xmlrpc report download.
        wait_for_xmlrpc_scan_to_completed(self.cat.api, scan_uuid=scan_uuid.text)

        self.cat.api.session_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        self.cat.api.xmlrpc.download_report(report_uuid=scan_uuid.text)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

    # API_Tested #POST /xmlrpc/file/upload
    @pytest.mark.nessus_home
    @pytest.mark.parametrize("test_data", [{"file_path": 'nessus/tests/api/scan/test_data/',
                                            "file_name": 'advanced_scan_gxxyl6.db'}])
    def test_xmlrpc_file_upload(self, test_data):
        """
        STA-99: Implement test case for /xmlrpc/file/upload

        Scenarios tested:
            [x] Successfully upload xmlrpc file
        """
        file_path = get_file_path(test_data['file_path'] + test_data['file_name'])
        root = self.cat.api.xmlrpc.upload_file(file_path)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        uploaded_file = root.find("./contents/fileUploaded")

        assert uploaded_file.text == test_data['file_name'], 'Unable to upload the file'
