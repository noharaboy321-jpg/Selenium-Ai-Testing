"""
Nessus XmlRpc Endpoint
"""
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import requests

from catium.lib import const
from catium.lib.api.api_authorization_mixin import APIAuthorizationMixin
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger
from nessus.apiobjects import routes
from nessus.lib.config import NessusEnvironmentConfig as Config

log = create_logger()


class XmlrpcEndpoint(APIAuthorizationMixin):
    """Xmlrpc API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def login(self, username: str = None, password: str = None) -> Element:
        """
        Login as the default username.

        :param str username: username
        :param str password: user password
        :return:  Returns root element from received xml response
        :rtype: Element
        """
        username = Config.CAT_NESSUS_USERNAME if username is None else username
        password = Config.CAT_NESSUS_PASSWORD if password is None else password

        files = [
            ('login', (None, username, 'x-www-form-urlencoded')),
            ('password', (None, password, 'x-www-form-urlencoded'))
        ]

        response = self._cls.request(const.HTTPMethods.POST, routes.XMLRPC + '/login', files=files)
        return ElementTree.fromstring(response.content)

    def logout(self) -> None:
        """
        Logout the current user.

        :return: None
        """
        self._cls.request(const.HTTPMethods.POST, routes.XMLRPC + '/logout', params={'token': self._cls.xmlrpc_token})
        log.debug('Deleted XML RPC API session (token: %s)', self._cls.xmlrpc_token)
        self._cls.xmlrpc_token = None

    def get_feed(self) -> Element:
        """
        Get feed server information.

        :return:  Returns root element from received xml response
        :rtype: Element
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.XMLRPC + '/feed')
        return ElementTree.fromstring(response.content)

    def download_report(self, report_uuid: str) -> requests.Response:
        """
        Download a report

        :param str report_uuid: report uuid to download
        :return: response for xmlrpc report download request
        :rtype: requests.Response
        """
        resource = '%s/file/report/download/' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, params={'token': self._cls.xmlrpc_token},
                                     data='report={}'.format(report_uuid))
        return response

    def upload_file(self, file: str) -> Element:
        """
        Upload a file

        :param str file: File name to upload
        :return: Return element from received xml response for xmlrpc/report/upload request.
        :rtype: Element
        """
        files = [('Filedata', (file, open(file, 'rb'), 'application/octet-stream'))]

        resource = '%s/file/upload' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, params={'token': self._cls.xmlrpc_token},
                                     files=files)
        return ElementTree.fromstring(response.content)

    def process_plugins(self, file_data: dict) -> ResponseObject:
        """
        Need to document
        """
        resource = '%s/plugins/process' % (routes.XMLRPC)
        payload = {'token': self._cls.session_token, 'payload': file_data}
        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        return ResponseObject(response)

    def add_policy(self, payload: dict) -> Element:
        """
        Add xml rpc policy.

        :param dict payload: Payload for policy
        :return: Returns root element from received xml response
        :rtype: Element
        """
        files = [(key, (None, value, 'x-www-form-urlencoded')) for key, value in payload.items()]

        resource = '%s/policy/add' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def delete_policy(self, policy_ids: str) -> Element:
        """
        Delete XML RPC policy.

        :param str policy_ids: comma separated policy ids which needs to be deleted
        :return: Returns root element from received xml response
        :rtype: Element
        """
        resource = '%s/policy/delete' % routes.XMLRPC
        files = [("policy_id", (None, policy_ids, 'x-www-form-urlencoded'))]
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def attachments(self, report_uuid: str) -> ResponseObject:
        """
        Attach the XML RPC report.
        :param str report_uuid: Report uuid
        :return: File Contents.
        :rtype: ResponseObject
        """
        resource = '%s/report/attachments' % routes.XMLRPC
        files = [("report", (None, report_uuid, 'x-www-form-urlencoded'))]
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ResponseObject(response)

    def delete_report(self, report_uuid: str) -> Element:
        """
        Delete XML RPC report.
        :param str report_uuid: Report uuid
        :return: Returns root element from received xml response.
        :rtype: Element
        """
        resource = '%s/report/delete' % routes.XMLRPC
        files = [("report", (None, report_uuid, 'x-www-form-urlencoded'))]
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def errors(self, report_uuid: str) -> Element:
        """
        Get the error of XML RPC report.
        :param str report_uuid: Report uuid
        :return: Returns root element from received xml response.
        :rtype: Element
        """
        files = [("report", (None, report_uuid, 'x-www-form-urlencoded'))]
        resource = '%s/report/errors' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def export(self, payload: dict) -> ResponseObject:
        """
        Export the XML RPC report.
        :param dict payload: Payload for export
        :return: File Contents.
        :rtype:  ResponseObject
        """
        files = [(key, (None, value, 'x-www-form-urlencoded')) for key, value in payload.items()]
        resource = '%s/report/export' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ResponseObject(response)

    def hosts(self, report_uuid: str, report_type: str = 'local') -> Element:
        """
        Get the hosts of XML RPC report.
        :param str report_uuid: Report uuid
        :param str report_type : Type of Report
        :return: Returns root element from received xml response.
        :rtype: Element
        """
        resource = '%s/report/hosts' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, params={'token': self._cls.xmlrpc_token},
                                     data={'report': report_uuid, 'type': report_type})
        return ElementTree.fromstring(response.content)

    def list(self) -> Element:
        """
        Get list of reports
        :return: Returns root element from received xml response for xmlrpc/report/list response
        :rtype: Element
        """
        resource = '%s/report/list' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def mdelete(self, report_name: str) -> Element:
        """
        Delete the XML RPC match List.
        :param str report_name: report - name of report to delete.
        :return: XML root element received from response
        :rtype: Element
        """
        resource = '%s/report/mdelete' % routes.XMLRPC
        files = [("report", (None, report_name, 'x-www-form-urlencoded'))]
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def mlist(self, report_name: str) -> Element:
        """
        Get the match list.
        :param str report_name: Report Name
        :return:  Returns root element from received xml response
        :rtype: Element
        """
        files = [("report", (None, report_name, 'x-www-form-urlencoded'))]
        resource = '%s/report/mlist' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def reset(self, report_name: str) -> Element:
        """
        Delete matching scan and report.

        :param str report_name: report - name of report to cancel/delete
        :return: XML root element received from response
        :rtype: Element
        """
        resource = '%s/reset' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, params={'token': self._cls.xmlrpc_token},
                                     data='report={}'.format(report_name))
        return ElementTree.fromstring(response.content)

    def list_scans(self) -> Element:
        """
        Get XML RPC scans.

        :return: XML root element received from response
        :rtype: Element
        """
        resource = '%s/scan/list' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def new_scan(self, payload: dict) -> Element:
        """
        Create a XML RPC scan.

        :param dict payload: Payload for scan.
        :return: XML root element received from response
        :rtype: Element
        """
        files = [(key, (None, value, 'x-www-form-urlencoded')) for key, value in payload.items()]

        resource = '%s/scan/new' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def pause_scan(self, scan_uuid: str) -> Element:
        """
        Pause XML RPC scan.

        :param str scan_uuid: Scan UUID
        :return: XML root element received from response
        :rtype: Element
        """
        files = [("scan_uuid", (None, scan_uuid, 'x-www-form-urlencoded'))]
        resource = '%s/scan/pause' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def resume_scan(self, scan_uuid: str) -> Element:
        """
        Resume XML RPC scan.

        :param str scan_uuid: Scan UUID
        :return: XML root element received from response
        :rtype: Element
        """
        files = [("scan_uuid", (None, scan_uuid, 'x-www-form-urlencoded'))]
        resource = '%s/scan/resume' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def stop_scan(self, scan_uuid: str) -> Element:
        """
        Stop XML RPC scan.

        :param str scan_uuid: Scan UUID
        :return: XML root element received from response
        :rtype: Element
        """
        files = [("scan_uuid", (None, scan_uuid, 'x-www-form-urlencoded'))]
        resource = '%s/scan/stop' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files,
                                     params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def get_server_load_status(self) -> Element:
        """
        Get the server load status.
        :return: Returns root element from received xml response.
        :rtype: Element
        """
        resource = '%s/server/load' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.GET, resource, params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)

    def server_load(self) -> Element:
        """
        Posts the server load.
        :return: Returns root element from received xml response.
        :rtype: Element
        """
        resource = '%s/server/load' % routes.XMLRPC
        response = self._cls.request(const.HTTPMethods.POST, resource, params={'token': self._cls.xmlrpc_token})
        return ElementTree.fromstring(response.content)
