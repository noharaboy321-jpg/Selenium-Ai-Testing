"""
Nessus API Class

This class is comprised of the Nessus API resources (a.k.a. endpoints)
"""

from catium.lib.api.api_authorization_mixin import APIAuthorizationMixin
from catium.lib.api.base_api_object import BaseApiObject
from nessus.apiobjects.endpoints.agent_groups import AgentGroupsEndpoint
from nessus.apiobjects.endpoints.agents import AgentsEndpoint
from nessus.apiobjects.endpoints.migration import MigrationEndpoint
from nessus.apiobjects.endpoints.nodes import NodesEndpoint
from nessus.apiobjects.endpoints.clustergroups import ClusterGroupsEndpoint
from nessus.apiobjects.endpoints.editor import EditorEndpoint
from nessus.apiobjects.endpoints.exclusions import ExclusionsEndpoint
from nessus.apiobjects.endpoints.file import FileEndpoint
from nessus.apiobjects.endpoints.folders import FoldersEndpoint
from nessus.apiobjects.endpoints.groups import GroupsEndpoint
from nessus.apiobjects.endpoints.mail import MailEndpoint
from nessus.apiobjects.endpoints.misc import MiscEndpoint
from nessus.apiobjects.endpoints.multi_scanner import MultiScannerEndpoint
from nessus.apiobjects.endpoints.passwordmgmt import PasswordMgmtEndpoint
from nessus.apiobjects.endpoints.permissions import PermissionsEndpoint
from nessus.apiobjects.endpoints.plugin_locales import PluginLocalesEndpoint
from nessus.apiobjects.endpoints.plugins import PluginsEndpoint
from nessus.apiobjects.endpoints.policies import PoliciesEndpoint
from nessus.apiobjects.endpoints.profiles import ProfilesEndpoint
from nessus.apiobjects.endpoints.registration import RegistrationEndpoint
from nessus.apiobjects.endpoints.remote import RemoteEndpoint
from nessus.apiobjects.endpoints.reports import ReportsEndpoint
from nessus.apiobjects.endpoints.scanner_health import ScannerHealthEndpoint
from nessus.apiobjects.endpoints.scanners import ScannersEndpoint
from nessus.apiobjects.endpoints.scans import ScansEndpoint
from nessus.apiobjects.endpoints.server import ServerEndpoint
from nessus.apiobjects.endpoints.session import SessionEndpoint
from nessus.apiobjects.endpoints.settings import SettingsEndpoint
from nessus.apiobjects.endpoints.tokens import TokensEndpoint
from nessus.apiobjects.endpoints.users import UsersEndpoint
from nessus.apiobjects.endpoints.was import WASEndpoint
from nessus.lib.config import NessusConfig
from nessus.lib.const.constants import API


class NessusAPI(APIAuthorizationMixin, BaseApiObject):
    """Nessus API Resources"""

    def __init__(self, login: bool = False, logout: bool = True, url: str = None):
        """
        Nessus API

        .. note:: Logout is handled automatically unless explicitly told otherwise
        .. note:: ``login`` and ``logout`` are only applicable when used as a ContextManager (i.e. with)
        .. note:: If ``logout`` is False then API logout MUST be handled manually (i.e. programmatically)

        :param bool login: Automatic login. Default: False.
        :param bool logout: Automatic logout. Default: True.
        """
        super().__init__()

        self.session_url = NessusConfig.CAT_NESSUS_URL if url is None else url
        self._login = login
        self._logout = logout
        self.add_header({'X-Automation-Key': API.AUTOMATION_SECRET})
        
        self.agent_groups = AgentGroupsEndpoint(self)
        self.agents = AgentsEndpoint(self)
        self.nodes = NodesEndpoint(self)
        self.clustergroups = ClusterGroupsEndpoint(self)
        self.editor = EditorEndpoint(self)
        self.file = FileEndpoint(self)
        self.folders = FoldersEndpoint(self)
        self.groups = GroupsEndpoint(self)
        self.mail = MailEndpoint(self)
        self.permissions = PermissionsEndpoint(self)
        self.plugins = PluginsEndpoint(self)
        self.policies = PoliciesEndpoint(self)
        self.profiles = ProfilesEndpoint(self)
        self.registration = RegistrationEndpoint(self)
        self.remote = RemoteEndpoint(self)
        self.scanners = ScannersEndpoint(self)
        self.scanner_health = ScannerHealthEndpoint(self)
        self.scans = ScansEndpoint(self)
        self.settings = SettingsEndpoint(self)
        self.server = ServerEndpoint(self)
        self.session = SessionEndpoint(self)
        self.users = UsersEndpoint(self)
        self.exclusions = ExclusionsEndpoint(self)
        self.passwordmgmt = PasswordMgmtEndpoint(self)
        self.tokens = TokensEndpoint(self)
        self.reports = ReportsEndpoint(self)
        self.misc = MiscEndpoint(self)
        self.multi_scanner = MultiScannerEndpoint(self)
        self.migration = MigrationEndpoint(self)
        self.was = WASEndpoint(self)
        self.locales = PluginLocalesEndpoint(self)

    def disable_automation_api_key(self):
        self.remove_header('X-Automation-Key')

    def enable_automation_api_key(self):
        self.add_header({'X-Automation-Key': API.AUTOMATION_SECRET})

    def login(self, username: str = None, password: str = None):
        """
        Login
        :param str username: Username
        :param str password: Password
        """
        # Configure dynamic values outside of function defaults so it's always set at runtime.
        username = NessusConfig.CAT_NESSUS_USERNAME if username is None else username
        password = NessusConfig.CAT_NESSUS_PASSWORD if password is None else password

        self.session.create(username, password)
        self.add_header({'X-Automation-Key': API.AUTOMATION_SECRET})
        self._active = True

    def logout(self):
        """Logout"""
        self.session.delete()
        self._active = False

    def set_api_keys(self, access_key: str, secret_key: str):
        """
        Set API keys for API session

        .. note:: These can be used to authenticate without creating a session

        :param str access_key: Access Key
        :param str secret_key: Secret Key
        """
        header = 'accessKey=%s; secretKey=%s;' % (access_key, secret_key)

        self.remove_header('X-ApiKeys')
        self.add_header({'X-ApiKeys': header})

    @staticmethod
    def check_model_and_payload(model, payload: dict):
        """
        Method to verify conditions of model and payload.

        :param model: A model object (i.e. ContainerModel, UserModel, ScanModel)
        :param dict payload: Payload dictionary
        :raises: AttributeError
        """
        if not model and not payload:
            raise AttributeError('Missing model or payload, please supply at least one.')
        if model and payload:
            raise AttributeError('model and payload cannot be supplied together, please choose one.')
