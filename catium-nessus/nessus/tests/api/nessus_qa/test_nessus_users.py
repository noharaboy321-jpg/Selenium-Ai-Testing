"""
Nessus User Endpoints Tests

:copyright: Tenable Network Security, 2017
:date: June 1, 2017
:last_modified: Oct 28, 2021
:author: @cdombrowski, @kpanchal
"""
import json
import random
import string
from http import HTTPStatus
from random import randint

import pytest
from requests import HTTPError, RequestException

from catium.helpers.testdata import get_file_path
from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.const import TIME_FIVE_MINUTES
from catium.lib.log import create_logger
from catium.lib.util import random_name
from catium.lib.util.util import random_string
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.policy import create_policy_helper
from nessus.helpers.scan import create_scan_helper
from nessus.helpers.server import expect_http_error
from nessus.helpers.users import get_user_dictionary, create_user
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.config import NessusConfig
from nessus.lib.const import API
from nessus.lib.const.constants import Nessus
from nessus.models.policy import PolicyModel
from nessus.models.scan import ScanModel
from nessus.models.user import UserModel

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/nessus_qa/test_data/test_nessus_users.json'])
@pytest.mark.usefixtures('nessus_api_login', 'load_test_data')
class TestNessusUsers:
    """
    Class to handle testing Nessus Users.  This includes tests such as creating, editing, and deleting a user.
    NES-12214: [API] Verify all types of user CRUD

    Scenarios:
        [x] Test creation of a user
        [x] Test a user can successfully login
        [x] Test deleting a user
        [x] Test when creating a duplicate user and fails
        [x] Test getting a specific user's details
        [x] Test the creation of a new user exists inside a list of users
        [x] Test updating a user's details
        [x] Test and cross-reference that a user's properties are returned and they are correct, respectively
        [x] Test editing a user that does not exist
        [x] Test updating an existing user's username/password
        [x] Test updating an existing user's username and password
        [x] Test being able to retrieve a user list after changing a user's password
        [x] Test generating a user's API keys via a user ID
        [x] Test multiple login accounts
        [x] Test incorrectly formatted username and fails
        [x] Test a failed login attempt then subsquently test a successful login
        [x] Test inability to use Nessus operations after logging out
        [] Test creating a user with incorrect params
        [] Test creating a user that already exists
        [] Test deleting a user that does not exist
        [] Test getting a user's details that does not exist
        [] Test an invalid user created does not make it inside the list/or fails
        [] Test updating with invalid or missing data
        [] Test receive an invalid user, and ensure their properties do not exist
        [] Test updating an non-existing user's username/password
        [] Test updating an non-existing user's username
        [] Test using an invalid user ID to generate API Keys
        [] Test the "lockout after X amounts" security feature
        [] Test various password complexity settings
    """

    cat = None

    # API_Tested# POST /users
    def test_nessus_create_user(self):
        """
        Tests that we can create and verify the smoke test user accounts.

        Scenarios:
            [x] Test creation of a user
            [] Test creating a user with incorrect params
            [] Test creating a user that already exists
        """
        user_data = {"email": "nessus_basic_user@tenable.com", "full_name": "Nessus Basic User",
                     "username": random_name(prefix="user-Basic"), "password": "sapphire", "permissions": 16,
                     "type": "local"}

        user_details = self.cat.api.users.create(payload=user_data)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        created_users = self.cat.api.users.get_users()['users']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all([user_data[data] in [user[data] for user in created_users] for data in
                    ['email', 'username', 'permissions', 'type']]), "Unable to create user '{}'".format(
            user_data["username"])

        self.cat.api.users.delete(user_id=user_details['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# POST /session
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_user_login(self, nessus_create_parametrized_user):
        """
        Tests that we can log into Nessus with the specified user.

        Scenarios:
            [x] Test a user can successfully login
        """
        self.cat.api.session.create(username=nessus_create_parametrized_user['name'], password=self.cat.nessus_password)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.session.delete()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.session.create(username=NessusConfig.CAT_NESSUS_USERNAME,
                                    password=NessusConfig.CAT_NESSUS_PASSWORD)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        user_data = self.cat.api.users.get(user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert user_data['lastlogin'], 'Unable to login with user {0}'.format(nessus_create_parametrized_user['name'])

    # API_Tested# DELETE /users/{user_id}
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_delete_user(self, nessus_create_parametrized_user):
        """
        Tests that we are able to delete a Nessus user via the API.  Handles creating and deleting the user.

        Scenarios:
            [x] Test deleting a user
            [] Test deleting a user that does not exist
        """
        self.cat.api.users.delete(nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        users_details = self.cat.api.users.get_users()['users']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert nessus_create_parametrized_user['id'] not in [user['id'] for user in users_details], \
            "Unable to delete '{}' user.".format(nessus_create_parametrized_user['name'])

    # API_Tested# POST /users
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_duplicate_user_creation(self, nessus_create_parametrized_user):
        """
        NES-12203: [API] [Negative] Adding a duplicate username throws 409

        Tests that we receive the proper error when attempting to creating a duplicate user.  We should receive a 409
        if the user is already created

        Scenarios:
            [x] Verify adding a duplicate username throws 409
        """
        with pytest.raises(HTTPError):
            self.cat.api.users.create(UserModel(username=nessus_create_parametrized_user['name'],
                                                password=self.cat.nessus_password))

        assert self.cat.api.http_status_code == HTTPStatus.CONFLICT, \
            'Expected 409, got {} instead.'.format(self.cat.api.http_status_code)

        expected_error_msg = json.loads(self.cat.api.http_text)['error']
        error_msg_from_response = "Duplicate username"

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    # API_Tested# GET /users/{user_id}
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_get_user(self, nessus_create_parametrized_user):
        """
        Tests that we are able to retrieve the user's details via the API.

        Scenarios:
            [x] Test getting a specific user's details
            [] Test getting a user's details that does not exist
        """
        user_details = self.cat.api.users.get(user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all([nessus_create_parametrized_user[data] == user_details[data] for data in
                    ['email', 'username', 'permissions']]), "Failed to get user details for '{}' user.".format(
            nessus_create_parametrized_user['name'])

    # API_Tested# POST /users
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.BASIC, API.Permissions.User.ADMINISTRATOR,
                                                         API.Permissions.User.STANDARD]], indirect=True)
    def test_nessus_get_users_list(self, create_users_using_api):
        """
        Tests that we are able to retrieve a list of users from Nessus via the API, and that our generated
        user is in that list.

        Scenarios:
            [x] Test the creation of a new user exists inside a list of users
            [] Test an invalid user created does not make it inside the list/or fails
        """
        users_details = self.cat.api.users.get_users()['users']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        for data in ['id', 'name', 'permissions']:
            assert all([item in [user[data] for user in users_details] for item in
                        [user[data] for user in create_users_using_api]]), "Failed to get created users details"

    # API_Tested# PUT /users/{user_id}
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_edit_user(self, nessus_create_parametrized_user):
        """
        Tests that we are able to edit permissions, name, and e-mail of the given user_id.

        Scenarios:
            [x] Test updating a user's details
            [] Test updating with invalid or missing data
        """
        edited_user_details = {'name': random_name(prefix='automation-'), 'email': API.User.Users.TEST_EMAIL}

        user_model = UserModel(name=edited_user_details['name'], email=edited_user_details['email'],
                               password=random_name(prefix='automation-'))

        self.cat.api.users.edit(nessus_create_parametrized_user['id'], user_model)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        user_details = self.cat.api.users.get(user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all([user_details[data] != nessus_create_parametrized_user[data] for data in
                    ['email', 'name']]), "Unable to edit '{0}' user details.".format(
            nessus_create_parametrized_user['name'])

        assert all([user_details[data] == edited_user_details[data] for data in ['email', 'name']]), \
            "Unable to edit '{0}' user details.".format(nessus_create_parametrized_user['name'])

        assert all([user_details[data] == nessus_create_parametrized_user[data] for data in ['id', 'username']]), \
            "Unable to edit '{0}' user details.".format(nessus_create_parametrized_user['name'])

    # API_Tested# GET /users/{user_id}
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_verify_user_properties(self, nessus_create_parametrized_user, load_test_data):
        """
        Tests that we are retrieve the user's properties and that they are correct.

        Scenarios:
            [x] Test and cross-reference that a user's properties are returned and they are correct, respectively
            [] Test receive an invalid user, and ensure their properties do not exist
        """
        user_data = load_test_data[API.User.Users.USERS_DATA[self.cat.nessus_username]]

        user_details = self.cat.api.users.get(nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all([user_details[data] == user_data[data] for data in ['name', 'email', 'permissions', 'type',
                                                                       'username']]), \
            'Unable to edit {0}\'s account.'.format(nessus_create_parametrized_user['name'])

        assert user_details['id'] == nessus_create_parametrized_user['id'], 'Got incorrect user...'

    # API_Tested# PUT /users/{user_id}
    @pytest.mark.parametrize('invalid_user_id', [-1, 0, 'random'])
    def test_edit_non_exist_nessus_user_throws_an_error(self, invalid_user_id):
        """
        Tests that we receive a 404 when attempting to edit a user that does not exist.

        Scenarios:
            [x] Test editing a user that does not exist
        """
        if invalid_user_id == 'random':
            invalid_user_id = randint(100, 999)

        user_model = UserModel(name=random_name(prefix='MyName_'), password=random_name(prefix='Tenable@'))

        with pytest.raises(HTTPError):
            self.cat.api.users.edit(invalid_user_id, user_model)

        assert self.cat.api.http_status_code == HTTPStatus.NOT_FOUND, \
            'Expected 404, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# PUT /users/{user_id}/chpasswd
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_change_user_password(self, nessus_create_parametrized_user):
        """
        Tests that we are able to change the username for the given user via API.  Creates a user and then updates
        that user's password.  Deletes the user when finished.

        Scenarios:
            [x] Test updating an existing user's username/password
            [] Test updating an non-existing user's username/password
        """
        self.cat.api.users.password(user_id=nessus_create_parametrized_user['id'],
                                    current_password=self.cat.nessus_password,
                                    password=random_name(prefix='automation-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# PUT /session/chpasswd
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_change_current_user_password(self, nessus_create_parametrized_user):
        """
        Tests that we are able to change the username for the given user via API.  Creates a user and then updates
        that user's password.  Deletes the user when finished.

        Scenarios:
            [x] Test updating an existing user's username and password
            [] Test updating an non-existing user's username
        """
        new_password = random_name(prefix='automation-')

        self.cat.api.session.create(username=nessus_create_parametrized_user['name'], password=self.cat.nessus_password)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.session.password(current_password=self.cat.nessus_password, new_password=new_password)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.session.delete()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.session.create(username=nessus_create_parametrized_user['name'], password=new_password)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        details = self.cat.api.session.get()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert details['lastlogin'], "Unable to change the current user's password."

        self.cat.api.session.create(username=NessusConfig.CAT_NESSUS_USERNAME,
                                    password=NessusConfig.CAT_NESSUS_PASSWORD)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# PUT /user/{user_id}/chpasswd
    # API_Tested# POST /session
    # API_Tested# GET /users
    # As per the NES-17501 bug ticket removed the Basic and Standard user from testcase.
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER], indirect=True)
    def test_nessus_verify_changed_password(self, nessus_create_parametrized_user):
        """
        Tests that we are able to retrieve the user list after changing a user's password.
        Creates a user, changes that user's password, logs in as that user, and finally retrieves the user list.
        Deletes the user when finished.

        Scenarios:
            [x] Test being able to retrieve a user list after changing a user's password
        """
        new_password = random_name(prefix='automation-')

        self.cat.api.users.password(user_id=nessus_create_parametrized_user['id'],
                                    current_password=self.cat.nessus_password, password=new_password)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.session.create(username=nessus_create_parametrized_user['name'], password=new_password)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        users = get_user_dictionary(self.cat.api.users.get_users()['users'])

        self.cat.api.session.delete()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.session.create(username=NessusConfig.CAT_NESSUS_USERNAME,
                                    password=NessusConfig.CAT_NESSUS_PASSWORD)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert nessus_create_parametrized_user['name'] in users, 'Unable to retrieve user-list after changing password.'

    # API_Tested# PUT /user/{user_id}/keys
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_generate_nessus_user_keys(self, nessus_create_parametrized_user):
        """
        Tests that we are able to generate a user's API Keys via user ID with the API.

        Scenarios:
            [x] Test generating a user's API keys via a user ID
            [] Test using an invalid user ID to generate API Keys
        """
        api_keys = self.cat.api.users.generate_keys(user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all([api_keys['secretKey'], len(api_keys['secretKey']) == 64, api_keys['accessKey'],
                    len(api_keys['accessKey']) == 64]), \
            'API secretKey or accessKey length was not the expected size.'

    # API_Tested# POST /session
    # API_Tested# GET /session
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_user_relog(self, nessus_create_parametrized_user):
        """
        Tests that we are able to log out as the current user, log in as a different user, log out as the different
        user and then log back in as the original user.

        Scenarios:
            [x] Test multiple login accounts
            [] Test the "lockout after X amounts" security feature
        """
        api = NessusAPI()
        api.session.create(username=nessus_create_parametrized_user['name'], password=self.cat.nessus_password)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        first_user_session_details = api.session.get()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        api.logout()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        api.session.create(username=NessusConfig.CAT_NESSUS_USERNAME, password=NessusConfig.CAT_NESSUS_PASSWORD)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        second_user_session_details = api.session.get()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        api.logout()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        api.session.create(username=nessus_create_parametrized_user['name'], password=self.cat.nessus_password)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        third_user_session_details = api.session.get()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        api.logout()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        assert all([first_user_session_details['lastlogin'] != second_user_session_details['lastlogin'] !=
                    third_user_session_details['lastlogin'],
                    first_user_session_details['name'] != second_user_session_details['name'],
                    second_user_session_details['username'] != third_user_session_details['username'],
                    first_user_session_details['id'] != second_user_session_details['id'],
                    second_user_session_details['email'] != third_user_session_details['email']]), \
            'Failed relog attempt for user {0}.'.format(nessus_create_parametrized_user['name'])

    # API_Tested# POST /session
    @pytest.mark.parametrize('invalid_username', [
        'admin admin', 'random_sys_admin', 'random_admin_use',
        'random_user', 'random_basic_user', 'none'])
    def test_nessus_invalid_user_login(self, invalid_username):
        """
        Tests that we return the expected error message when using an invalid username.
        """
        if invalid_username == 'random_sys_admin':
            invalid_username = random_name(prefix=API.User.Users.SYS_ADMIN_USER)
        elif invalid_username == 'random_admin_user':
            invalid_username = random_name(prefix=API.User.Users.ADMIN_USER)
        elif invalid_username == 'random_user':
            invalid_username = random_name(prefix=API.User.Users.STANDARD_USER)
        elif invalid_username == 'random_basic_user':
            invalid_username = random_name(prefix=API.User.Users.BASIC_USER)
        elif invalid_username == 'none':
            invalid_username = None

        with pytest.raises(HTTPError):
            self.cat.api.session.create(username=invalid_username, password=random_string(string_length=12))

        expected_status_code = HTTPStatus.BAD_REQUEST if invalid_username is None else HTTPStatus.UNAUTHORIZED

        assert self.cat.api.http_status_code == expected_status_code, \
            'Expected {}, got {} instead.'.format(expected_status_code, self.cat.api.http_status_code)

    # API_Tested# POST /session
    @pytest.mark.parametrize('invalid_username', [
        'admin admin /////',
        'random_ascii_upper',
        'random_ascii_lower',
        'random_digits',
        'random_ascoo_letters'])
    def test_nessus_incorrect_format_user_login(self, invalid_username):
        """
        Tests that we return the expected error message when using an incorrectly formatted username.

        Scenarios:
            [x] Test incorrectly formatted username and fails
        """
        if invalid_username == 'random_ascii_upper':
            invalid_username = random_string(input_source=(string.ascii_uppercase + string.punctuation))
        elif invalid_username == 'random_ascii_lower':
            invalid_username = random_string(input_source=(string.ascii_lowercase + string.punctuation))
        elif invalid_username == 'random_digits':
            invalid_username = random_string(input_source=(string.digits + string.punctuation))
        elif invalid_username == 'random_digits':
            invalid_username = random_string(input_source=(string.digits + string.punctuation))
        elif invalid_username == 'random_ascii_letters':
            invalid_username = random_string(input_source=(string.ascii_letters + string.punctuation))

        api = NessusAPI()

        with pytest.raises(HTTPError):
            api.session.create(username=invalid_username, password=random_string(string_length=12))

        assert api.http_status_code == HTTPStatus.UNAUTHORIZED, \
            'Expected 401, got {} instead.'.format(api.http_status_code)

    # API_Tested# POST /session
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_login_with_invalid_password(self, nessus_create_parametrized_user):
        """
        Tests that login fails when using an invalid password.

        Scenarios:
            [x] Test invalid password and fails
        """
        with pytest.raises(HTTPError):
            self.cat.api.session.create(username=nessus_create_parametrized_user['name'],
                                        password=random_string(string_length=12))

        assert self.cat.api.http_status_code == HTTPStatus.UNAUTHORIZED, \
            'Expected 401, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# POST /session
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    @pytest.mark.parametrize('username', ['admin admin /////'])
    def test_nessus_login_after_invalid_user_login(self, username, nessus_create_parametrized_user):
        """
        Tests that we are able to login successfully after a failed login attempt.

        Scenarios:
            [x] Test a failed login attempt then subsquently test a successful login
        """
        api = NessusAPI()

        with pytest.raises(HTTPError):
            api.session.create(username=username, password=random_string(string_length=12))

        assert api.http_status_code == HTTPStatus.UNAUTHORIZED, \
            'Expected 401, got {} instead.'.format(api.http_status_code)

        api.session.create(username=nessus_create_parametrized_user['name'], password=self.cat.nessus_password)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        api.session.delete()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        assert api.http_status_code == HTTPStatus.OK, 'Unable to login successfully after a failed login attempt.'

    # API_Tested# POST /session
    # API_Tested# GET /session
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    def test_nessus_operations_after_logout(self, nessus_create_parametrized_user):
        """
        Tests that we are not able to complete Nessus operations after logging out of the specified user.

        Scenarios:
            [x] Test inability to use Nessus operations after logging out
        """
        api = NessusAPI()
        api.session.create(username=nessus_create_parametrized_user['name'], password=self.cat.nessus_password)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        details = api.session.get()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert details['lastlogin'], "Unable to login with created user '{}'.".format(
            nessus_create_parametrized_user['name'])

        api.session.delete()

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(api.http_status_code)

        with pytest.raises(HTTPError):
            api.session.get()

        assert api.http_status_code == HTTPStatus.UNAUTHORIZED, \
            'Expected 401, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# PUT /user/{user_id}/chpasswd
    # API_Tested# POST /session
    # API_Tested# GET /users
    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.STANDARD_USER, API.User.Users.SYS_ADMIN_USER, API.User.Users.ADMIN_USER,
        API.User.Users.BASIC_USER], indirect=True)
    @pytest.mark.parametrize('password_length', [7, 8, 12])
    def test_simple_password_not_allowed_when_complexity_enabled(self, nessus_create_parametrized_user,
                                                                 password_length):
        """
        NES-12181: [Negative] Verify user is not allowed to set simple password when complexity is enabled

        Scenario Tested:
            [x] Verify user is not allowed to set simple password when complexity is enabled
        """
        upper_case, lower_case, digits, punctuation = string.ascii_uppercase, string.ascii_lowercase, string.digits, \
                                                      string.punctuation
        pwd_setting_payload = {"passwd_complexity": "yes", "session_timeout": "30", "passwd_max_attempts": "",
                               "passwd_min_length": "", "passwd_notifications": "no"}

        try:
            self.cat.api.settings.set_password_complexity(payload=pwd_setting_payload)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            invalid_password_char = [upper_case, lower_case, digits, punctuation, (upper_case + lower_case),
                                     (upper_case + digits), (upper_case + punctuation), (lower_case + digits),
                                     (lower_case + punctuation), (digits + punctuation)]

            for invalid_pwd in invalid_password_char:
                with pytest.raises(HTTPError):
                    new_password = random_string(string_length=password_length, input_source=invalid_pwd)
                    log.debug("Verified for password :: {}".format(new_password))

                    self.cat.api.users.password(user_id=nessus_create_parametrized_user['id'],
                                                current_password=self.cat.nessus_password, password=new_password)

                assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                    'Expected 400, got {} instead.'.format(self.cat.api.http_status_code)

                expected_error_msg = json.loads(self.cat.api.http_text)['error']
                error_msg_from_response = "New password failed to meet password rules."

                assert error_msg_from_response in expected_error_msg, \
                    "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)
        finally:
            pwd_setting_payload["passwd_complexity"] = "no"

            self.cat.api.settings.set_password_complexity(payload=pwd_setting_payload)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.ADMIN_USER, API.User.Users.STANDARD_USER, API.User.Users.BASIC_USER], indirect=True)
    @pytest.mark.parametrize("test_details", [{'product_type': 'home'}, {'product_type': 'professional'}])
    def test_modify_license_with_unauthorized_users(self, nessus_create_parametrized_user, test_details):
        """
        NES-12204: [API] [Negative] Verify Administrator/Basic/Standard user can not modify license

        Scenario Tested:
            [x] Verify Administrator/Basic/Standard user can not modify license
        """
        expiration_days = 365
        activation_code_generator = ActivationCodeGenerator()

        activation_code = activation_code_generator.generate_nessus_manager_code(expiration_days=expiration_days) \
            if test_details['product_type'] == ActivationCodeGenerator.NESSUS_MANAGER else \
            activation_code_generator.generate_code(code_type=test_details['product_type'],
                                                    expiration_days=expiration_days)
        log.debug("Generated Activation code for '{}'".format(test_details['product_type'].capitalize()))

        user_api = NessusAPI()
        user_api.login(username=nessus_create_parametrized_user['username'], password=self.cat.nessus_password)

        with expect_http_error(code=403):
            try:
                user_api.server.server_register(data={"code": activation_code}, stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        API.User.Users.ADMIN_USER, API.User.Users.STANDARD_USER, API.User.Users.BASIC_USER], indirect=True)
    @pytest.mark.parametrize("full_mode, scrub_mode", [(0, 0), (1, 0), (0, 1), (1, 1)])
    def test_download_logs_with_unauthorized_users(self, nessus_create_parametrized_user, full_mode, scrub_mode):
        """
        NES-12205: [API] [Negative] Verify Administrator/Basic/Standard user can not download Nessus logs

        Scenario Tested:
            [x] Verify Administrator/Basic/Standard user can not download Nessus logs
        """
        user_api = NessusAPI()
        user_api.login(username=nessus_create_parametrized_user['username'], password=self.cat.nessus_password)

        with expect_http_error(code=403):
            try:
                user_api.server.post_bug_report(data={"full_mode": full_mode, "scrub_mode": scrub_mode}, stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    @pytest.mark.parametrize('nessus_create_parametrized_user', [
        pytest.param(API.User.Users.ADMIN_USER, marks=pytest.mark.xfail(reason='Refer Jira ID NES-12275')),
        API.User.Users.STANDARD_USER, API.User.Users.BASIC_USER], indirect=True)
    def test_force_update_plugins_with_unauthorized_users(self, nessus_create_parametrized_user):
        """
        NES-12206: [API] [Negative] Verify Administrator/Basic/Standard user can not trigger force plugin update

        Scenario Tested:
            [x] Verify Administrator/Basic/Standard user can not trigger force plugin update
        """
        scanner_id = self.cat.api.scanners.get_list()['scanners'][0]['id']

        user_api = NessusAPI()
        user_api.login(username=nessus_create_parametrized_user['username'], password=self.cat.nessus_password)

        with expect_http_error(code=403):
            try:
                re = user_api.scanners.force_plugin_update(scanner_id=scanner_id, stream=True)
                for chunk in re.iter_content(chunk_size=1024 * 1024):
                    if chunk:  # filter out keep-alive new chunks
                        log.debug("Got a chunk!")
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.BASIC]], indirect=True)
    def test_verify_basic_user_can_not_create_scan(self, create_users_using_api):
        """
        NES-13513 : [API-Automation]: Validate Basic/System/Administrator user's limited access.

        Scenario Tested:
            [x] Verify that basic user can not create scan.
        """
        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])

        # Verify that basic user can not create scan
        with pytest.raises(HTTPError):
            user_api.scans.create(ScanModel().create_model())

        assert user_api.http_status_code == HTTPStatus.FORBIDDEN, \
            'Expected 403, got %s instead.' % user_api.http_status_code

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.BASIC]], indirect=True)
    def test_verify_basic_user_can_not_create_policy(self, create_users_using_api):
        """
        NES-13513 : [API-Automation]: Validate Basic/System/Administrator user's limited access.

        Scenario Tested:
            [x] Verify that basic user can not create policy
        """
        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])

        # Verify that basic user can not create policy
        with expect_http_error(code=403):
            try:
                re = user_api.policies.create(PolicyModel().create_model().create_payload(), stream=True)
                for chunk in re.iter_content(chunk_size=1024 * 1024):
                    if chunk:  # filter out keep-alive new chunks
                        log.debug("Got a chunk!")
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.BASIC]], indirect=True)
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    @pytest.mark.parametrize('scan_operation', ['launch', 'configure', 'delete', 'delete_from_trash'])
    def test_verify_basic_user_can_not_delete_shared_scan_from_trash_folder(self, create_users_using_api, import_scan,
                                                                            scan_operation):
        """
        NES-13513 : [API-Automation]: Validate Basic/System/Administrator user's limited access.

        Scenario Tested:
            [x] Verify that basic user can not launch/execute/delete shared scan.
        """
        # Share scan with Basic user
        permission_objects = {'acls': [{"type": 'user', "id": create_users_using_api[0]['id'], "permissions": 64}]}
        self.cat.api.permissions.change(API.Permissions.Types.SCAN, import_scan, permission_objects)

        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])

        # Verify that Basic user can not launch/execute or delete the shared scan.
        with expect_http_error(code=403):
            try:
                if scan_operation == "launch":
                    re = user_api.scans.launch(scan_id=import_scan, stream=True)
                elif scan_operation == "configure":
                    re = user_api.scans.configure(scan_id=import_scan, payload={}, stream=True)
                elif scan_operation == "delete":
                    re = user_api.scans.delete(scan_id=import_scan, stream=True)
                elif scan_operation == "delete_from_trash":
                    self.cat.api.scans.move(scan_id=import_scan, folder_id="2")
                    re = user_api.scans.delete(scan_id=import_scan, stream=True)

                for chunk in re.iter_content(chunk_size=1024 * 1024):
                    if chunk:  # filter out keep-alive new chunks
                        log.debug("Got a chunk!")
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.ADMINISTRATOR]], indirect=True)
    @pytest.mark.parametrize('new_user_permission', [API.Permissions.User.BASIC, API.Permissions.User.STANDARD,
                                                     API.Permissions.User.ADMINISTRATOR,
                                                     API.Permissions.User.SYSTEM_ADMINISTRATOR])
    def test_verify_users_creation_using_administrator_user(self, create_users_using_api, new_user_permission):
        """
        NES-13513 : [API-Automation]: Validate Basic/System/Administrator user's limited access.

        Scenario Tested:
            [x] Verify that 'Administrator' user can create 'Basic'/'Standard'/'Administrator' user.
            [x] Verify that 'Administrator' user can not create 'System Administrator' user.
        """
        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])

        user_password = random_name("automation-")

        # verify that 'Administrator' user can create Basic/Standard/Administrator user.
        if new_user_permission != API.Permissions.User.SYSTEM_ADMINISTRATOR:
            user = create_user(api=user_api, username=random_name("automation-"), password=user_password,
                               permissions=new_user_permission)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            new_user_api = NessusAPI()
            new_user_api.login(username=user['name'], password=user_password)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        # Verify the error if 'Administrator' user tries to create 'System Administrator' user.
        else:
            with pytest.raises(HTTPError):
                create_user(api=user_api, username=random_name("automation-"), password=user_password,
                            permissions=new_user_permission)

            assert user_api.http_status_code == HTTPStatus.FORBIDDEN, \
                'Expected 403, got %s instead.' % user_api.http_status_code

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_verify_administrator_user_can_not_update_license_key(self, create_users_using_api):
        """
        NES-13513 : [API-Automation]: Validate Basic/System/Administrator user's limited access.

        Scenario Tested:
            [x] Verify that 'Administrator' user can not update license key.
        """
        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])
        activation_code = ActivationCodeGenerator().generate_nessus_manager_code(
            expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)

        # Verify the error if 'Administrator' user tries to update the license key.
        with expect_http_error(code=403):
            try:
                re = user_api.server.register(code=activation_code, stream=True)

                for chunk in re.iter_content(chunk_size=1024 * 1024):
                    if chunk:  # filter out keep-alive new chunks
                        log.debug("Got a chunk!")
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_verify_administrator_user_can_not_update_plugins(self, create_users_using_api):
        """
        NES-13513 : [API-Automation]: Validate Basic/System/Administrator user's limited access.

        Scenario Tested:
            [x] Verify that 'Administrator' user can not update plugins.
        """
        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])

        # Verify the error if 'Administrator' user tries to update the plugins.
        with expect_http_error(code=403):
            try:
                re = user_api.server.update_plugins(data={}, stream=True)

                for chunk in re.iter_content(chunk_size=1024 * 1024):
                    if chunk:  # filter out keep-alive new chunks
                        log.debug("Got a chunk!")
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))


def create_data_for_user(user_api: NessusAPI) -> dict:
    """
    This function will create one scan, one policy and one plugin rule for user
    :param NessusAPI user_api: Instance of NessusAPI
    :return: User data for created scan/ policy/ plugin rule
    :rtype: dict
    """
    scan1 = create_scan_helper(user_api, file_name=get_file_path(
        'nessus/tests/api/scan/test_data/test_advanced_scan_for_user.json'), template_title='advanced')

    policy1 = create_policy_helper(user_api, user_api.editor.get_templates('policy')['templates'],
                                   policy_type="basic", policy_name='Policy_test')

    plugin_id = random.randint(1, 50000)
    user_api.plugins.add_plugin_rules(data={"host": Nessus.Scan.Target.LOCALHOST, "plugin_id": plugin_id,
                                            "type": "recast_critical"})
    plugin_rule_1 = [plugin for plugin in user_api.plugins.list_plugin_rules()['plugin_rules'] if
                     plugin['plugin_id'] == plugin_id and plugin['host'] == Nessus.Scan.Target.LOCALHOST][0]

    return {'scan': {'id': scan1[0]['scan']['id'], 'name': scan1[0]['scan']['name']},
            'policy': {'id': policy1['policy_id'], 'name': policy1['policy_name']},
            'plugin_rule': {'id': plugin_rule_1['id'], 'host': plugin_rule_1['host']}}


def verify_user_data_ownership(api: NessusAPI, user_data: dict, owner_name: str, data_available: bool) -> bool:
    """
    Verify that user has the data ownership or not
    :param NessusAPI api: Instance of NessusAPI class
    :param dict user_data: user data which is to be verified
    :param str owner_name: user name
    :param bool data_available: Data should be available with ownership or not
    :return: True if user has the data availability and ownership else False
    :rtype: bool
    """
    all_scans = api.scans.get_scans()['scans']
    all_policies = api.policies.get_policies()['policies']
    all_plugin_rules = api.plugins.list_plugin_rules()['plugin_rules']

    is_scan_available = user_data.get('scan').get('id') in [scan['id'] for scan in all_scans if scan[
        'name'] == user_data.get('scan').get('name') and scan['owner'] == owner_name] if all_scans else False

    is_policy_available = user_data.get('policy').get('id') in [policy['id'] for policy in all_policies if policy[
        'name'] == user_data.get('policy').get('name') and policy['owner'] == owner_name] if all_policies else False

    is_plugin_rule_available = user_data.get('plugin_rule').get('id') in [
        plugin['id'] for plugin in all_plugin_rules if plugin['host'] == user_data.get(
            'plugin_rule').get('host') and plugin['owner'] == owner_name] if all_plugin_rules else False

    if data_available:
        return is_scan_available and is_policy_available and is_plugin_rule_available
    else:
        return not (is_scan_available or is_policy_available or is_plugin_rule_available)


def delete_created_user_data(api: NessusAPI, user_data: dict) -> None:
    """
    Delete created user data (scan/ policy and plugin_rule
    :param NessusAPI api: Instance of NessusAPI
    :param dict user_data: User data (scan/ policy/ plugin rule) to be deleted
    :return:None
    """
    try:
        api.scans.delete(scan_id=user_data.get('scan').get('id'))
    except HTTPError:
        log.warning("Error while deleting scan - {}".format(user_data.get('scan').get('name')))
    try:
        api.policies.delete(policy_id=user_data.get('policy').get('id'))
    except HTTPError:
        log.warning("Error while deleting policy - {}".format(user_data.get('policy').get('name')))
    try:
        api.plugins.delete_plugin_rule(plugin_id=user_data.get('plugin_rule').get('id'))
    except HTTPError:
        log.warning(
            "Error while deleting plugin rule for host - {}".format(user_data.get('plugin_rule').get('host')))


@pytest.mark.nessus_manager
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/nessus_qa/test_data/test_nessus_users.json'])
@pytest.mark.usefixtures('nessus_api_login', 'load_test_data')
class TestUserDataTransferForNM:
    """Tests related to user data transfer"""

    # API_Tested# POST users/transfer/
    @pytest.mark.parametrize('nessus_create_parametrized_user', [API.User.Users.STANDARD_USER], indirect=True)
    def test_user_data_ownership_transfer(self, nessus_create_parametrized_user):
        """
        NES-12075 : API automation for data transfer between Nessus users
        Scenarios Tested:
            [x] Verify that user data ownership can be transferred successfully.
        """
        user_api = NessusAPI()
        user_api.login(username=nessus_create_parametrized_user['username'], password=self.cat.nessus_password)

        user_data = create_data_for_user(user_api=user_api)
        log.info("Created user data : {}".format(user_data))
        try:
            # Verify that data is available with ownership to new user
            assert verify_user_data_ownership(api=user_api, user_data=user_data,
                                              owner_name=nessus_create_parametrized_user['username'],
                                              data_available=True), \
                "Scan/ Policy/ Plugin rule is not available with owner as : {} user ".format(
                    nessus_create_parametrized_user['username'])

            # Verify that 'admin' user has not ownership for data created by new user.
            assert verify_user_data_ownership(api=self.cat.api, user_data=user_data,
                                              owner_name=NessusConfig.CAT_USERNAME, data_available=False), \
                "Scan/ Policy/ Plugin rule is available with owner as {}".format(NessusConfig.CAT_USERNAME)

            # Transfer user data ownership to 'admin' user
            self.cat.api.users.transfer_user_data(user_id=nessus_create_parametrized_user['id'])
            log.info("User data has been transferred to 'admin' user.")

            # Verify that data ownership is transferred to 'admin' user
            assert verify_user_data_ownership(api=self.cat.api, user_data=user_data,
                                              owner_name=NessusConfig.CAT_USERNAME, data_available=True), \
                "After transferring data ownership - Scan/ Policy/ Plugin rule is not available with owner as : {} " \
                "user ".format(NessusConfig.CAT_USERNAME)

            # Verify that new user does not have data ownership after transfer
            assert verify_user_data_ownership(api=user_api, user_data=user_data,
                                              owner_name=nessus_create_parametrized_user['username'],
                                              data_available=False), \
                "After transferring data ownership - Scan/ Policy/ Plugin rule is available with owner as {}".format(
                    nessus_create_parametrized_user['username'])
        finally:
            # Delete scan/policy and plugin rule
            delete_created_user_data(api=self.cat.api, user_data=user_data)

    # API_Tested# DELETE /users (with transfer parameter as True and False)
    @pytest.mark.parametrize('nessus_create_parametrized_user', [API.User.Users.STANDARD_USER], indirect=True)
    @pytest.mark.parametrize('transfer_data', [True, False])
    def test_user_data_transfer_while_deleting_user(self, nessus_create_parametrized_user, transfer_data):
        """
        NES-12075: API automation for data transfer between Nessus users
        NES-12213: [API] Verify Scan, policies, plugin-rules ownership transfer when user is deleted

        Scenarios Tested:
            [x] Verify that user data can be transferred to 'admin' user while deleting the user
            [x] Verify that user data can be deleted along with user deletion
        """
        user_api = NessusAPI()
        user_api.login(username=nessus_create_parametrized_user['username'], password=self.cat.nessus_password)

        user_data = create_data_for_user(user_api=user_api)
        log.info("Created user data : {}".format(user_data))

        try:
            self.cat.api.users.delete_users(user_ids=[str(nessus_create_parametrized_user['id'])],
                                            transfer=transfer_data)

            # Verify that user is not present any more in users list
            assert nessus_create_parametrized_user['username'] not in [user['username'] for user in
                                                                       self.cat.api.users.get_users()['users']]

            # Based on transfer data flag while deleting user, verify that data transferred to 'admin' user or not
            assert verify_user_data_ownership(api=self.cat.api, user_data=user_data,
                                              owner_name=NessusConfig.CAT_USERNAME, data_available=transfer_data), \
                "After transferring data ownership - Scan/ Policy/ Plugin rule is not available with owner as : {} " \
                "user ".format(NessusConfig.CAT_USERNAME)
        finally:
            # Delete scan/policy and plugin rule
            delete_created_user_data(api=self.cat.api, user_data=user_data)


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestUserDataTransferControls:
    """
    Tests related to User Data Transfer's impact on overall user rights/permissions.
    """

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.ADMINISTRATOR,
                                                         API.Permissions.User.SYSTEM_ADMINISTRATOR]], indirect=True)
    @pytest.mark.parametrize('non_claimable_transfer', [
        {API.Permissions.User.ADMINISTRATOR: API.Permissions.User.SYSTEM_ADMINISTRATOR}])
    def test_admin_user_can_not_claim_data_transfer_of_sys_admin_user(self, create_users_using_api,
                                                                      non_claimable_transfer):
        """
        NES-13538 : [API-Automation] : Verify that user can not claim data transfer of higher authority

        Scenario Tested:
            [x] Verify that 'Administrator' user can not claim data transfer of 'System Administrator' user.
        """
        user_api = NessusAPI()
        user_data = [user for user in create_users_using_api if user['permissions'] == list(
            non_claimable_transfer.keys())[0]][0]
        user_api.login(username=user_data['name'], password=user_data['password'])

        # Verify that 'Administrator' user can not claim data transfer of 'System Administrator' user.
        with pytest.raises(HTTPError):
            user_api.users.transfer_user_data(user_id=[user['id'] for user in create_users_using_api if user[
                'permissions'] == list(non_claimable_transfer.values())[0]][0])

        assert user_api.http_status_code == HTTPStatus.FORBIDDEN, \
            'Expected 403, got %s instead.' % user_api.http_status_code

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD,
                                                         API.Permissions.User.ADMINISTRATOR,
                                                         API.Permissions.User.SYSTEM_ADMINISTRATOR]], indirect=True)
    @pytest.mark.parametrize('scan_owner', [API.Permissions.User.STANDARD, API.Permissions.User.ADMINISTRATOR,
                                            API.Permissions.User.SYSTEM_ADMINISTRATOR])
    @pytest.mark.parametrize('permissions', [API.Permissions.Scan.CAN_CONTROL])
    def test_user_default_permission_persists_after_data_transfer(self, create_users_using_api, permissions,
                                                                  scan_owner):
        """
        NES-13540 : [API-Automation] : Verify that transfer ownership of user data does not impact default permissions

        Scenario Tested:
            [x] After user transfers data, verify that default permissions remains unchanged.
        """
        scan_owner_user = [user for user in create_users_using_api if user['permissions'] == scan_owner][0]
        scan_owner_user_api = NessusAPI()
        scan_owner_user_api.login(username=scan_owner_user['name'], password=scan_owner_user['password'])
        try:
            config = {'acls': [{"type": API.Permissions.Types.DEFAULT, "permissions": permissions}],
                      'text_targets': Nessus.Scan.Target.LOCALHOST}

            scan_id = scan_owner_user_api.scans.create(ScanModel(
                name=random_name(prefix="automation-scan-"), **config))['scan']['id']

            self.cat.api.users.transfer_user_data(user_id=scan_owner_user['id'])

            for user in create_users_using_api:
                if user != scan_owner_user:
                    user_api = NessusAPI()
                    user_api.login(username=user['name'], password=user['password'])
                    assert user_api.scans.details(scan_id)['info']['user_permissions'] == permissions, \
                        "After data transfer of user, " \
                        "other user is not able to control the scan using default permissions."
                    user_api.logout()
        finally:
            scan_owner_user_api.logout()

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD],
                                                        [API.Permissions.User.ADMINISTRATOR],
                                                        [API.Permissions.User.SYSTEM_ADMINISTRATOR]], indirect=True)
    @pytest.mark.parametrize('scan_state', [API.Scan.Status.RUNNING, API.Scan.Status.PAUSED, API.Scan.Status.CANCELED])
    def test_verify_scan_state_remains_same_after_data_transfer(self, create_users_using_api, scan_state):
        """
        NES-13539 : [API-Automation] : Verify scan state is same after transferring data to some other user

        Scenario Tested:
            [x] Verify that scan state ('Paused'/ 'Stopped'/ 'Canceled') remains same after data transfer.
        """
        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])
        scan_created = create_scan_helper(user_api, file_name=get_file_path(
            'nessus/tests/api/scan/test_data/test_advanced_scan_for_user.json'), template_title='advanced')
        scan_id = scan_created[0]['scan']['id']
        try:
            user_api.scans.launch(scan_id=scan_id)
            wait_scan_state(api=user_api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING, timeout=TIME_FIVE_MINUTES)

            # Make the scan in required state ('Paused'/'Canceled').
            if scan_state == API.Scan.Status.PAUSED:
                user_api.scans.pause(scan_id=scan_id)
            elif scan_state == API.Scan.Status.CANCELED:
                user_api.scans.stop(scan_id=scan_id)

            wait_scan_state(api=user_api, scan_id=scan_id, end_state=scan_state, timeout=TIME_FIVE_MINUTES)

            self.cat.api.users.transfer_user_data(user_id=create_users_using_api[0]['id'])
            assert self.cat.api.scans.get_status(scan_id) == scan_state, \
                "Scan state does not remains same after transferring data to some other user."
        finally:
            if self.cat.api.scans.get_status(scan_id) != API.Scan.Status.CANCELED:
                self.cat.api.scans.stop(scan_id=scan_id)
                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                                timeout=TIME_FIVE_MINUTES)
            self.cat.api.scans.delete(scan_id)

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD],
                                                        [API.Permissions.User.ADMINISTRATOR],
                                                        [API.Permissions.User.SYSTEM_ADMINISTRATOR]], indirect=True)
    def test_verify_scan_rights_upgraded_after_data_transfer(self, create_users_using_api):
        """
        NES-13541 : [API-Automation] : Verify 'transfer data' overwrites existing rights to 'can control' rights

        Scenario Tested:
            [x] Verify that scan rights for particular user or users gets changed after transferring data.
        """
        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])

        scan_created = create_scan_helper(user_api, file_name=get_file_path(
            'nessus/tests/api/scan/test_data/test_advanced_scan_for_user.json'), template_title='advanced')
        scan_id = scan_created[0]['scan']['id']

        try:
            permission_objects = {'acls': [{"type": 'user', "id": self.cat.api.session.get()['id'],
                                            "permissions": API.Permissions.Scan.CAN_VIEW}]}
            user_api.permissions.change(object_type=API.Permissions.Types.SCAN, object_id=scan_id,
                                        acls=permission_objects)

            assert self.cat.api.scans.details(scan_id)['info']['user_permissions'] == API.Permissions.Scan.CAN_VIEW, \
                "Initially user rights is not set to 'can_view'."

            self.cat.api.users.transfer_user_data(user_id=create_users_using_api[0]['id'])

            assert self.cat.api.scans.details(scan_id)['info']['user_permissions'] == 128 != \
                   API.Permissions.Scan.CAN_VIEW, "User rights for scan does not upgraded to admin rights after " \
                                                  "transferring data."
        finally:
            self.cat.api.scans.delete(scan_id)
