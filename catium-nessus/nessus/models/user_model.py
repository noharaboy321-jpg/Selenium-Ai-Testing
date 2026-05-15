from catium.lib.api.base_api_object import ResponseObject
from catium.lib.cat_registry.metadata_registry import register_model
from catium.lib.data_models import fields
from catium.lib.data_models.helpers import check_shared_keys, update_shared_keys
from catium.lib.errors import CatiumModelError
from catium.lib.util import random_name
from nessus.helpers.session import nessus_api_session
from nessus.lib.config import NessusConfig
from nessus.lib.const import API, Nessus, Prefixes
from nessus.models.base_object_model import NessusBaseObject


class UserModelAPIMixin:
    """ Provides helpers to interact with API"""

    username = None
    password = None
    permissions = None
    type = None
    enabled = None
    name = None
    email = None

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

    def create(self, username: str = None, password: str = None,
               api_session: nessus_api_session = None) -> (NessusBaseObject, ResponseObject):
        """Uses the API to create a User"""
        # Configure dynamic values outside of function defaults so it's always set at runtime.
        username = NessusConfig.CAT_NESSUS_USERNAME if username is None else username
        password = NessusConfig.CAT_NESSUS_PASSWORD if password is None else password

        with nessus_api_session(api_username=username, api_password=password, api_session=api_session) as api:
            output = api.users.create(self)
            self.id = output['id']
            return self, output

    def delete(self, username: str = None, password: str = None, api_session: nessus_api_session = None) -> None:
        """Uses the API to delete a User"""
        # Configure dynamic values outside of function defaults so it's always set at runtime.
        username = NessusConfig.CAT_NESSUS_USERNAME if username is None else username
        password = NessusConfig.CAT_NESSUS_PASSWORD if password is None else password

        with nessus_api_session(api_username=username, api_password=password, api_session=api_session) as api:
            api.users.delete(self.id)

    def get(self, username: str = None, password: str = None, api_session: nessus_api_session = None,
            update_model: bool = True) -> (NessusBaseObject, ResponseObject):
        """ Uses the api to get the details of a user. """
        # Configure dynamic values outside of function defaults so it's always set at runtime.
        username = NessusConfig.CAT_NESSUS_USERNAME if username is None else username
        password = NessusConfig.CAT_NESSUS_PASSWORD if password is None else password

        with nessus_api_session(api_username=username, api_password=password, api_session=api_session) as api:
            output = api.users.details(self.id)
            if update_model:
                update_shared_keys(self, output)
            return self, output

    def verify(self, username: str = None, password: str = None, api_session: nessus_api_session = None,
               raise_error: bool=False) -> list:
        """Uses the API to verify a User"""
        # Configure dynamic values outside of function defaults so it's always set at runtime.
        username = NessusConfig.CAT_NESSUS_USERNAME if username is None else username
        password = NessusConfig.CAT_NESSUS_PASSWORD if password is None else password

        _, output = self.get(username=username, password=password, api_session=api_session, update_model=False)
        return check_shared_keys(self, output, raise_error)


@register_model('User')
class UserModel(NessusBaseObject, UserModelAPIMixin):
    """
    User Model

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
    id = fields.Integer(in_model_str=True)
    username = fields.String(in_model_str=True)
    password = fields.String()
    name = fields.String(in_model_str=True)
    email = fields.String(in_model_str=True)
    permissions = fields.Integer(in_model_str=True)
    lastlogin = fields.Integer()
    type = fields.String(in_model_str=True)
    login_fail_count = fields.Integer(default=0)
    login_fail_total = fields.Integer(default=0)
    last_login_attempt = fields.Integer(default=0)
    enabled = fields.Boolean(in_model_str=True)

    @classmethod
    def factory(cls, **kwargs):
        kwargs.setdefault('username', "user")
        kwargs.setdefault('name', None)
        kwargs.setdefault('email', None)
        kwargs.setdefault('permissions', API.Permissions.User.STANDARD)
        kwargs.setdefault('password', Nessus.DEFAULT_PASSWORD)
        kwargs.setdefault('type', API.User.Types.LOCAL)
        kwargs.setdefault('enabled', True)
        kwargs.setdefault('autogen', False)

        username = kwargs.get('username')
        name = kwargs.get('name')
        email = kwargs.get('email')
        permissions = kwargs.get('permissions')
        password = kwargs.get('password')
        type = kwargs.get('type')
        enabled = kwargs.get('enabled')

        if kwargs['autogen']:
            username = '%s@%s' % (random_name(prefix=Prefixes.USER), NessusConfig.CAT_USER_DOMAIN)
            password = Nessus.DEFAULT_PASSWORD
            name = 'Catium User'
            email = username
            type = API.User.Types.LOCAL

        if password is None:
            raise CatiumModelError('User password is required')

        return cls(username=username, name=name, email=email, permissions=permissions,
                   password=password, type=type, enabled=enabled)
