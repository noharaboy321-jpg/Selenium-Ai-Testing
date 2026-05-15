"""
Nessus Users Endpoint Verification

:copyright: Tenable Network Security, 2019
:date: Feb 21, 2019
:last_modified: Apr 05, 2021
:author: @kpanchal
"""
import json
import random
from http import HTTPStatus
from random import randint

import pytest
from _pytest.fixtures import SubRequest
from requests import HTTPError

from catium.lib.log import create_logger
from catium.lib.util import random_string
from catium.lib.util.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.users import create_user
from nessus.lib.const import API

log = create_logger()


@pytest.fixture()
def create_multiple_users(request: 'SubRequest', nessus_api_handler: NessusAPI) -> list:
    """ Create multiple users """
    user_ids = []

    for i in range(request.param):
        user_detail = create_user(api=nessus_api_handler, username=random_name(prefix="Automation_Test_User - "),
                                  password=random_name(prefix="Test@"))

        assert nessus_api_handler.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % nessus_api_handler.http_status_code

        user_ids.append(user_detail['id'])

    return user_ids


@pytest.mark.nessus_manager
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/nessus_qa/test_data/test_nessus_users.json'])
@pytest.mark.usefixtures('nessus_api_login', 'load_test_data')
class TestNessusUsersEndpoints:
    """ Tests Nessus Users Endpoint """

    cat = None

    # API_Tested# GET /users
    # API_Tested# DELETE /users
    @pytest.mark.parametrize('create_multiple_users', [5], indirect=True)
    def test_delete_bulk_users(self, create_multiple_users):
        """
        NES-8870: API test to cover bulk user delete

        Scenarios Tested:
        [x] Successfully delete multiple users
        [x] Successfully fetch user details
        """
        user_ids = create_multiple_users
        response = self.cat.api.users.delete_users(user_ids=user_ids)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert user_ids == response['deleted'], "Users are not deleted successfully."

        users_info = self.cat.api.users.get_users()
        existing_user_ids = [users_info['users'][i]['id'] for i in range(len(users_info['users']))]

        assert all([user_id not in existing_user_ids for user_id in user_ids]), 'Users are exist after deleted.'

    @pytest.mark.parametrize('user', [API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER,
                                      API.User.Users.ADMIN_USER, API.User.Users.BASIC_USER])
    def test_user_creation_not_allowed_with_invalid_user_type(self, user):
        """
        NES-12403: [API] Verify Negative user creation scenarios

        Scenario Tested:
        [x] Verify that user creation not allowed with invalid "type" fields (i.e. other than "local" or "ldap")
        """
        user_permission = {"user-SysAdmin": 128, "user-Admin": 64, "user-Standard": 32, "user-Basic": 16}

        for user_type in ['ldap', 'local']:
            user_data = {"email": "{}@tenable.com".format(user), "full_name": user, "username": random_name(
                prefix=user), "password": "sapphire", "permissions": user_permission.get(user),
                         "type": random_string(string_length=4, input_source=user_type)}

            with pytest.raises(HTTPError):
                self.cat.api.users.create(payload=user_data)

            assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                'Expected {}, got {} instead.'.format(HTTPStatus.BAD_REQUEST, self.cat.api.http_status_code)

            error_msg_from_response = json.loads(self.cat.api.http_text)['error']
            expected_error_message = "Invalid 'type' field"

            assert error_msg_from_response == expected_error_message, \
                "Expected '{}' error msg, got '{}' instead.".format(expected_error_message, error_msg_from_response)

    @pytest.mark.parametrize('user', [API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER,
                                      API.User.Users.ADMIN_USER, API.User.Users.BASIC_USER])
    def test_user_creation_not_allowed_with_invalid_user_permissions(self, user):
        """
        NES-12403: [API] Verify Negative user creation scenarios

        Scenario Tested:
        [x] Verify that user creation not allowed with Invalid Permissions field
        """
        user_permissions = {"user-SysAdmin": 128, "user-Admin": 64, "user-Standard": 32, "user-Basic": 16}

        for permission in [user_permissions.get(user) - 1, user_permissions.get(user) + 1, -1, random_string(
                string_length=2), random.random()]:
            user_data = {"email": "{}@tenable.com".format(user), "full_name": user, "username": random_name(
                prefix=user), "password": "sapphire", "permissions": permission, "type": 'local'}

            with pytest.raises(HTTPError):
                self.cat.api.users.create(payload=user_data)

            assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                'Expected {}, got {} instead.'.format(HTTPStatus.BAD_REQUEST, self.cat.api.http_status_code)

    @pytest.mark.parametrize('user', [API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER,
                                      API.User.Users.ADMIN_USER, API.User.Users.BASIC_USER])
    def test_user_creation_not_allowed_with_username_length_exceeded(self, user):
        """
        NES-12403: [API] Verify Negative user creation scenarios

        Scenario Tested:
        [x] Verify that user creation not allowed with username length exceeding 128 chars
        """
        user_permissions = {"user-SysAdmin": 128, "user-Admin": 64, "user-Standard": 32, "user-Basic": 16}

        user_data = {"email": "{}@tenable.com".format(user), "full_name": user, "username": random_string(
            string_length=randint(129, 999)), "password": "sapphire", "permissions": user_permissions.get(user),
                     "type": 'local'}

        with pytest.raises(HTTPError):
            self.cat.api.users.create(payload=user_data)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected {}, got {} instead.'.format(HTTPStatus.BAD_REQUEST, self.cat.api.http_status_code)

    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER, API.User.Users.STANDARD_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_delete_self_user_account_throws_an_error(self, nessus_create_parametrized_user):
        """
        NES-12403: [API] Verify Negative user creation scenarios

        Scenario Tested:
        [x] Verify that it throws an error while trying to delete own user account
        """
        user_api = NessusAPI()
        user_api.login(username=nessus_create_parametrized_user['username'], password=self.cat.nessus_password)

        with pytest.raises(HTTPError):
            user_api.users.delete(nessus_create_parametrized_user['id'])

        expected_response_code = HTTPStatus.CONFLICT if nessus_create_parametrized_user['username'] in [
            API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER] else HTTPStatus.FORBIDDEN

        assert user_api.http_status_code == expected_response_code, \
            'Expected {}, got {} instead.'.format(expected_response_code, user_api.http_status_code)
