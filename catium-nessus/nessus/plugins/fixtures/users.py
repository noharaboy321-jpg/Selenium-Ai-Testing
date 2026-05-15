"""
    Nessus Users fixtures

    :copyright: Tenable Network Security, 2017
    :date: Aug 08 2017
    :author: @ivargas jyerge
"""
import json
from http import HTTPStatus
from typing import TYPE_CHECKING

import pytest
from requests.exceptions import HTTPError

from catium.lib.log import create_logger
from catium.lib.util import random_name
from nessus.helpers.users import user_data_validation, create_user
from nessus.lib.const import API
from nessus.models.user import UserModel

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture(scope='function')
def get_user_dictionary(request: 'SubRequest', nessus_api_login):
    """
    Automatic API Folder Retrieval.  Returns dictionary of folder names to folder ids.
    """
    log.debug('fixture init: get_user_dictionary: Get user names')
    user_dictionary = {}
    users = nessus_api_login.users.get_users()['users']
    for user in users:
        user_dictionary[user['username']] = user['id']
    request.cls.cat.nessus_user_list = user_dictionary


@pytest.fixture()
def nessus_create_user(request: 'SubRequest', nessus_class_api_login):
    """
    Method to create a random user in Nessus.
    .. note:: This sets self.cat.nessus_uid.  This will create a user for each test that is run.
    .. note:: This will also delete the user at the end of the tests.
    """
    log.debug('fixture init: nessus_create_user: Creates a user in Nessus')
    try:
        created = False
        user_id = None
        username = random_name(prefix='nessus_')
        password = random_name(prefix='Tenable@')
        users = nessus_class_api_login.users.get_users()['users']
        for user in users:
            if username in user['username']:
                created = True
                user_id = user['id']
        if not created:
            nessus_class_api_login.users.create(UserModel(username=username, password=password))
            user = json.loads(nessus_class_api_login.http_text)
            user_id = user['id']
        request.cls.cat.nessus_uid = user_id
        request.cls.cat.nessus_username = username
        request.cls.cat.nessus_password = password
        yield users
    finally:
        log.debug('fixture teardown: nessus_create_user: Remove user from Nessus')
        try:
            nessus_class_api_login.users.delete(user_id)
        except Exception as exc:  # TODO: should we log warning or error in this case?
            log.warning('Deleting user "%s" failed: %s', user_id, exc)


@pytest.fixture(scope='class')
def nessus_class_create_user(request: 'SubRequest', nessus_class_api_login):
    """
    Method to create a random user in Nessus.
    .. note:: This sets self.cat.nessus_uid on a class level.  It will only create one user per test class.
    .. note:: This will also delete the user at the end of the tests.
    """
    log.debug('fixture init: nessus_class_create_user: Create Nessus user class scope')
    try:
        created = False
        user_id = None
        username = random_name(prefix='nessus_')
        password = random_name(prefix='Tenable@')
        users = nessus_class_api_login.users.get_users()['users']
        for user in users:
            if username in user['username']:
                created = True
                user_id = user['id']
        if not created:
            nessus_class_api_login.users.create(UserModel(username=username, password=password))
            user = json.loads(nessus_class_api_login.http_text)
            user_id = user['id']
        request.cls.cat.nessus_uid = user_id
        request.cls.cat.nessus_username = username
        request.cls.cat.nessus_password = password
        yield users
    finally:
        log.debug('fixture teardown: nessus_class_create_user: Remove user %s', user_id)
        try:
            nessus_class_api_login.users.delete(user_id)
        except Exception as exc:
            log.warning('Deleting user "%s" failed: %s', user_id, exc)


@pytest.fixture()
def nessus_create_group(request: 'SubRequest', nessus_api_login):
    """
    Automatic Group Creation using the API.  Creates a randomly named group and then deletes the group when finished.
    """
    log.debug('fixture init: nessus_create_group: Create group in Nessus')
    group_id = None
    try:
        group = random_name(prefix='group_')
        resp = nessus_api_login.groups.create(name=group)
        group_id = json.loads(nessus_api_login.http_text)['id']
        request.cls.cat.group_id = group_id
        yield resp
    finally:
        log.debug('fixture teardown: nessus_create_group: Remove group %s', group_id)
        try:
            nessus_api_login.groups.delete(group_id=group_id)
        except Exception as exc:
            log.warning('Deleting group "%s" failed: %s', group_id, exc)


@pytest.fixture()
def nessus_list_groups(request: 'SubRequest', nessus_api_login):
    """
    Automatic API Group Retrieval.  Returns dictionary of group names to group ids.
    """
    log.debug('fixture init: nessus_list_groups: Get dictionary of group names to IDs')
    groups_dictionary = {}
    groups = nessus_api_login.groups.get_groups()['groups']
    for group in groups:
        groups_dictionary[group['name']] = group['id']
    request.cls.cat.groups = groups_dictionary


@pytest.fixture(scope='function')
def nessus_create_parametrized_ldap_user(request: 'SubRequest', nessus_api_login):
    """
    Creates a LDAP user passed on the parameters passed in.  Deletes the user after the yield.  More parameters can
    be added to this in the future if required / requested.

    Parameters should be as follows:
      - username=request.param[0]
      - permissions = request.param[1]
      - user_type = request.param[2]

    :return dict user_details:  User details returned when creating the user.
    """
    user_details = None
    user_id = None
    log.debug('fixture init: nessus_create_parametrized_ldap_user: Creates an LDAP user')
    try:
        user_id = None
        created = False
        username = request.param[0]
        permissions = request.param[1]
        user_type = request.param[2]
        if user_type not in API.User.Types.VALID_TYPES:
            user_type = API.User.Types.LOCAL
        if not username:
            username = random_name(prefix='automation-')
        users = nessus_api_login.users.get_users()['users']
        for user in users:
            if username in user['username']:
                created = True
                user_details = user
        if not created:
            user_dict = {"username": username, "permissions": permissions, "type": user_type, "name": ""}
            user_details = nessus_api_login.users.create(payload=user_dict)
        user_id = user_details['id']
        request.cls.cat.user_details = user_details
        yield user_details
    finally:
        log.debug('fixture teardown: nessus_create_parametrized_ldap_user: Remove LDAD user id %s', user_id)
        try:
            nessus_api_login.users.delete(user_id)
        except Exception as exc:
            log.warning('Deleting user "%s" failed: %s', user_id, exc)


@pytest.fixture(scope='function')
def nessus_create_parametrized_user(request: 'SubRequest', nessus_api_login, load_test_data: dict):
    """
    Creates a Nessus user based on data from the test_data file.  Deletes the user after the yield.

    The load_test_data user to load should be passed in as a parameter.  For example, if your load_test_data looks
    like:

        {
          "sys_admin_user": {
            "email": "nessus_sysAdmin_user@tenable.com",
            "full_name": "Nessus SysAdmin User",
            "username": "user-SysAdmin",
            "password": "sapphire",
            "permissions": 128,
            "user_type": "local"
          },
          "standard_user": {
            "email": "nessus_standard_user@tenable.com",
            "full_name": "Nessus Standard User",
            "username": "user-Standard",
            "password": "sapphire",
            "permissions": 32,
            "user_type": "local"
          }
        }

    These users can be passed in like:

        @pytest.mark.parametrize('nessus_create_parametrized_user', ["standard_user",
                                                                     "sys_admin_user"], indirect=True)
    Yield data example:
        {
            'name': 'user-SysAdmin',
            'id': 2569,
            'permissions': 128
        }

    """
    log.debug('fixture init: nessus_create_parametrized_user: Creates Nessus user based on parameters')
    try:
        user_id = None
        if request.param:
            user_info = load_test_data[request.param]
            created = False
            validated_user_data = user_data_validation(user_info)
            request.cls.cat.nessus_username = validated_user_data['username']
            request.cls.cat.nessus_password = validated_user_data['password']
            request.cls.cat.nessus_user_permissions = validated_user_data['permissions']
            users = nessus_api_login.users.get_users()['users']
            for user in users:
                if validated_user_data['username'] in user['username']:
                    created = True
                    user_details = user
            if not created:
                user_details = nessus_api_login.users.create(payload=validated_user_data)
                user_details['username'] = validated_user_data['username']
            request.cls.cat.user_details = user_details
            user_id = user_details['id']
            request.cls.cat.nessus_uid = user_id
            user_details['email'] = validated_user_data['email']
            yield user_details
    except AttributeError:
        pytest.fail('No request parameters found, cannot load user data.')
    finally:
        log.debug('fixture teardown: nessus_create_parametrized_user: Remove user id %s', user_id)
        try:
            nessus_api_login.users.delete(user_id)
        except Exception as exc:
            if nessus_api_login.http_status_code == HTTPStatus.NOT_FOUND:
                log.warning('User "%s" already deleted', user_id)
            else:
                log.warning('Deleting user "%s" failed: %s', user_id, exc)


@pytest.fixture()
def create_users_using_api(request: 'SubRequest', nessus_api_login):
    """
    This fixture creates users (using user permissions given in request)
    """
    users_permission = request.param
    created_users = []
    try:
        for permission in users_permission:
            user_password = random_name("automation-")
            user = create_user(api=nessus_api_login, username=random_name("automation-"), password=user_password,
                               permissions=permission)
            user['password'] = user_password
            created_users.append(user)
        yield created_users
    finally:
        for user in created_users:
            try:
                nessus_api_login.users.delete(user_id=user['id'])
            except HTTPError:
                log.warning("Unable to delete user with user id : {}".format(user['id']))
