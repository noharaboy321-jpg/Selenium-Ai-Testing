"""
Nessus XML RPC report Endpoint verification

:copyright: Tenable Network Security, 2019
:date: Jan 09, 2019
:last_modified: Mar 16, 2022
:author: @dkothari, @kpanchal
"""
from http import HTTPStatus

import pytest


@pytest.mark.nessus_home
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_xmlrpc_api_login')
class TestXmlrpcReportEndpoint:
    """ STA-101: Implement test cases for xmlrpc report endpoints. """

    cat = None

    # API_Tested #POST /xmlrpc/report/list
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_report_list(self):
        """
        STA-101: Implement test cases for xmlrpc report endpoint /xmlrpc/report/list
        
        Scenarios tested:
            [x] Successfully get list of reports.
        """
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        root = self.cat.api.xmlrpc.list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        assert root.find("./contents/reports/report") is not None, "Failed to list xml rpc report"

    # API_Tested #POST /xmlrpc/report/hosts
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_report_hosts(self, add_xmlrpc_scan):
        """
        STA-101: Implement test cases for xmlrpc report endpoint. /xmlrpc/report/hosts
        
        Scenarios tested:
            [x] Successfully get the information of hosts.
        """
        scan_root = add_xmlrpc_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        uuid_element = scan_root.find("./contents/scan/uuid")

        assert uuid_element is not None, "'/contents/scan/uuid' tag not found in xml"

        hosts = self.cat.api.xmlrpc.hosts(report_uuid=uuid_element.text)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        host_element = hosts.find('./contents/hostList')

        assert host_element is not None, "'/contents/hostList' tag not found in xml"

    # API_Tested #POST /xmlrpc/report/errors
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_report_errors(self, add_xmlrpc_scan):
        """
        STA-101: Implement test cases for xmlrpc report endpoint /xmlrpc/report/errors
        
        Scenarios tested:
            [x] Successfully get the error message.
        """
        scan_root = add_xmlrpc_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        uuid_element = scan_root.find("./contents/scan/uuid")

        assert uuid_element is not None, "'/contents/scan/uuid' tag not found in xml"

        errors = self.cat.api.xmlrpc.errors(report_uuid=uuid_element.text)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        error_element = errors.find('./contents/errors')

        assert error_element is not None, "'/contents/errors' tag not found in xml"

    # # API_Tested #POST /xmlrpc/report/attachment
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_report_attachment(self, add_xmlrpc_scan):
        """
        STA-101: Implement test cases for xmlrpc report endpoint /xmlrpc/report/attachment
        
        Scenarios tested:
            [x] Successfully attach the report.
        """
        scan_root = add_xmlrpc_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        uuid_element = scan_root.find("./contents/scan/uuid")

        assert uuid_element is not None, "'/contents/scan/uuid' tag not found in xml"

        self.cat.api.xmlrpc.attachments(report_uuid=uuid_element.text)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

    # API_Tested #POST /xmlrpc/report/export
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_report_export(self, add_xmlrpc_scan):
        """
        STA-101: Implement test cases for xmlrpc report endpoint /xmlrpc/report/export
        
        Scenarios tested:
            [x] Successfully export the report.
        """
        scan_root = add_xmlrpc_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        uuid_element = scan_root.find("./contents/scan/uuid")

        assert uuid_element is not None, "'/contents/scan/uuid' tag not found in xml"

        payload = {
            "report": uuid_element.text,
            "format": "db",
            "password": "123"
        }

        self.cat.api.xmlrpc.export(payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

    # API_Tested #POST /xmlrpc/report/mlist
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_report_mlist(self, add_xmlrpc_scan):
        """
        STA-101: Implement test cases for xmlrpc report endpoint /xmlrpc/report/mlist
        
        Scenarios tested:
            [x] Successfully fetch the mlist.
        """
        scan_root = add_xmlrpc_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        scan_name = scan_root.find("./contents/scan/scan_name")

        assert scan_name is not None, "'/contents/scan/scan_name' tag not found in xml"

        mlist = self.cat.api.xmlrpc.mlist(report_name=scan_name.text)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        assert mlist.find("./contents/reports/report") is not None, "Failed to list xml rpc report"

    # API_Tested #POST /xmlrpc/report/delete
    @pytest.mark.usefixtures('add_xmlrpc_scan')
    def test_xmlrpc_report_delete(self, add_xmlrpc_scan):
        """
        STA-101: Implement test cases for xmlrpc report endpoint /xmlrpc/report/delete
        
        Scenarios tested:
            [x] Successfully delete report.
        """
        scan_root = add_xmlrpc_scan

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        uuid_element = scan_root.find("./contents/scan/uuid")

        assert uuid_element is not None, "'/contents/scan/uuid' tag not found in xml"

        report = self.cat.api.xmlrpc.delete_report(report_uuid=uuid_element.text)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected a 200 response but got {} instead'.format(HTTPStatus.OK)

        report_element = report.find('./contents/report')

        assert report_element is not None, "'/contents/report' tag not found in xml"
