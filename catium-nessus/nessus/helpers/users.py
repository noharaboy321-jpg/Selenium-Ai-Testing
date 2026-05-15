"""
:copyright: Tenable Network Security, 2017
:date: June 1, 2017
:author: @cdombrowski
"""
from http import HTTPStatus

import pytest
from requests import HTTPError

from catium.lib.const.base_constants import STRING_NONE
from catium.lib.log import create_logger
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.lib.const import API

log = create_logger()


def create_user(api: NessusAPI, username: str = None, password: str = None,
                permissions: int = API.Permissions.User.STANDARD, user_type: str = None) -> dict:
    """
    Helper to create a Nessus user using the username and password being passed in.
    :param NessusAPI api:      Nessus API instance
    :param str username:       The username of the user to create.
    :param str password:       The password of the user that is being created.
    :param int permissions:    The role of the user.
    :param str user_type:      The user account type.
    :return dict data:         Returns dict of the user details
    """
    if permissions not in API.Permissions.User.VALID_PERMISSIONS:
        permissions = API.Permissions.User.STANDARD
    if user_type not in API.User.Types.VALID_TYPES:
        user_type = API.User.Types.LOCAL
    data = {"username": username, "password": password, "permissions": permissions, "type": user_type}
    user_details = api.users.create(payload=data)
    return user_details


def create_api_keys(user_id: int, api: NessusAPI = None) -> dict:
    """
    Helper to create Nessus API secret key and access key for the user_id being passed in.
    :param int user_id:        The user_id that should be used for the API Keys.
    :param NessusAPI api:      Nessus API instance
    :return dict:              Returns dict of the access_key and secret_key
    """
    try:
        resp = api.users.generate_keys(user_id=user_id)
    except HTTPError as exception:
        log.debug('Request Error: %s', exception)
        if api.http_status_code == HTTPStatus.NOT_FOUND:
            return api.http_status_code
        elif api.http_status_code != HTTPStatus.OK:
            pytest.fail('The specified user_id was not found when attempting to create an api key')

    if 'accessKey' and 'secretKey' in resp:
        return {'access_key': resp['accessKey'], 'secret_key': resp['secretKey']}
    else:
        pytest.fail('Unable to retrieve Nessus API access key and/or secret key.')


def get_user_dictionary(users: dict):
    """
    Takes in a dictionary of users returned by the API and formats them into a username: user_id dictionary.
    """
    user_dictionary = {}
    for user in users:
        user_dictionary[user['username']] = user['id']
    return user_dictionary


def user_data_validation(user: dict):
    """
    Takes in a user data request and validates that the data in the request is suitable to use when creating a user.

    :param dict user:         The original user data.
    :return dict user_dict:   The validated data, with any corrections that needed to be made.
    """
    if 'username' not in user or user['username'] == STRING_NONE or user['username'] is None:
        username = random_name(prefix='automation-')
        user['username'] = username
    if 'name' not in user or user['name'] == STRING_NONE or user['name'] is None:
        user['name'] = random_name(prefix='automation-')
    if 'password' not in user or user['password'] == "None" or user['password'] is STRING_NONE:
        user['password'] = random_name(prefix='automation-')
    if 'email' not in user or user['email'] == "None" or user['email'] is STRING_NONE:
        user['email'] = API.User.Users.TEST_EMAIL
    if 'permissions' not in user or user['permissions'] == STRING_NONE or user['permissions'] is None or \
            user['permissions'] not in API.Permissions.User.VALID_PERMISSIONS:
        user['permissions'] = API.Permissions.User.STANDARD
    if 'type' not in user or user['type'] == STRING_NONE or user['type'] is None or \
            user['type'] not in API.User.Types.VALID_TYPES:
        user['type'] = API.User.Types.LOCAL
    return user
