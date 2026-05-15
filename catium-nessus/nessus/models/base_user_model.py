"""
Base User Model

Product: Nessus, TenableCloud
"""
from catium.lib.util import random_name, random_string
from catium.lib.errors import CatiumModelError
from nessus.lib.config import NessusConfig
from nessus.lib.const import API


class BaseUserModel(object):
    """
    Base User Model

    Defines the parameters needed to create a new user

    permissions:
        Please use API.Permissions. notation for specifying permissions.

        DISABLED       -  User disabled?
        BASIC          -  Users can view and configure scan results
        STANDARD       -  Users can create scans, policies, and user asset lists
        ADMINISTRATOR  -  Users have same privileges as STANDARD but can also manage users, groups, agents, exclusions,
                          asset lists and scanners

    Kwargs:
        username (str): Username for user
        name (str): Real name of user
        email (str): Email address for user
        permissions (int): User permissions. Default: STANDARD
        password (str): Initial user password
        type (str): User type. Default: local.
        enabled (bool): Enable user. Default: True.
        autogen (bool): Automatically generate user parameters, ignores parameters passed

    :raises: CatiumModelError
    """

    def __init__(self, **kwargs):
        super().__init__()

        kwargs.setdefault('username', None)
        kwargs.setdefault('name', None)
        kwargs.setdefault('email', None)
        kwargs.setdefault('permissions', API.Permissions.User.STANDARD)
        kwargs.setdefault('password', None)
        kwargs.setdefault('type', API.User.Types.LOCAL)
        kwargs.setdefault('enabled', True)
        kwargs.setdefault('autogen', False)

        self.username = kwargs.get('username')
        self.name = kwargs.get('name')
        self.email = kwargs.get('email')
        self.permissions = kwargs.get('permissions')
        self.password = kwargs.get('password')
        self.type = kwargs.get('type')
        self.enabled = kwargs.get('enabled')

        if kwargs['autogen']:
            self.username = '%s@%s' % (random_name(prefix='user-'), NessusConfig.CAT_USER_DOMAIN)
            self.password = random_string(16)
            self.name = 'Catium User'
            self.email = self.username
            self.permissions = API.Permissions.User.STANDARD
            self.type = API.User.Types.LOCAL

        if self.password is None:
            raise CatiumModelError('User password is required')

    def create_payload(self) -> dict:
        """Returns a dictionary for use as a request model to API endpoints"""
        dct = {
            'username': self.username,
            'password': self.password,
            'permissions': self.permissions,
            'type': self.type,
            'enabled': self.enabled
        }

        if self.name:
            dct['name'] = self.name
        if self.email:
            dct['email'] = self.email
        if self.type:
            dct['type'] = self.type
        return dct
