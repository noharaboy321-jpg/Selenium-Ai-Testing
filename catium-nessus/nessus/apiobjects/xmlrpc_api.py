"""
XML RPC API Class

This class is comprised of the XML RPC API resources (a.k.a. endpoints)

:copyright: Tenable Network Security, 2019
:date: Jan 10, 2019
:last_modified: Jan 17, 2019
:author: @lambaliya
"""

from catium.lib.api.api_authorization_mixin import APIAuthorizationMixin
from catium.lib.api.base_api_object import BaseApiObject
from nessus.apiobjects.endpoints.server import ServerEndpoint
from nessus.apiobjects.endpoints.xmlrpc import XmlrpcEndpoint
from nessus.lib.config import NessusConfig
from nessus.lib.const.constants import API


class XmlRpcAPI(APIAuthorizationMixin, BaseApiObject):
    """XML RPC API Resources"""

    def __init__(self, login: bool = False, logout: bool = True, url: str = None):
        """
        XML RPC API

        .. note:: Logout is handled automatically unless explicitly told otherwise
        .. note:: ``login`` and ``logout`` are only applicable when used as a ContextManager (i.e. with)
        .. note:: If ``logout`` is False then API logout MUST be handled manually (i.e. programmatically)

        :param bool login: Automatic login. Default: False.
        :param bool logout: Automatic logout. Default: True.
        :param str url: URL for nessus product
        """
        super().__init__()

        self.xmlrpc_token = None
        self._login = login
        self._logout = logout
        self.server = ServerEndpoint(self)
        self.session_url = NessusConfig.CAT_NESSUS_URL if url is None else url
        self.add_header({'X-Automation-Key': API.AUTOMATION_SECRET})
        self.xmlrpc = XmlrpcEndpoint(self)

    def login(self, username: str = None, password: str = None) -> None:
        """
        Login.

        :param str username: User's name
        :param str password: User password
        :return: None
        """
        root = self.xmlrpc.login(username, password)
        token = root.find('./contents/token').text
        if token:
            self.xmlrpc_token = token
            self._active = True

    def logout(self) -> None:
        """
        Logout current user.

        :return: None
        """
        self.xmlrpc.logout()
        self._active = False

    def is_session_active(self) -> bool:
        """
        Get session status.

        :return: True or False
        :rtype: bool
        """
        return self._active
