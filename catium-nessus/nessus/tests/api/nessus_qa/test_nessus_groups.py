"""
Nessus User Groups Endpoints Tests

:copyright: Tenable Network Security, 2017
:date: June 2, 2017
:last_modified: Mar 16, 2022
:author: @cdombrowski, @kpanchal
"""

import json
from http import HTTPStatus
from random import randint

import pytest
from requests import HTTPError

from catium.lib.log import create_logger
from catium.lib.util import random_name
from nessus.lib.const import API

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/nessus_qa/test_data/test_nessus_users.json'])
@pytest.mark.usefixtures('nessus_api_login', 'load_test_data')
class TestNessusGroups:
    """
    Class will handle testing Nessus Groups via the API.  This will include tests such as creating a group,
    adding a user to a group, deleting a group, removing a user from the group, and editing the group.

    NES-12210: [API] CRUD operations for User groups
    NES-12211: [API] Add/list/delete users in user groups
    """

    cat = None

    # API_Tested# POST /groups
    # API_Tested# GET /groups
    def test_nessus_groups_create_group(self):
        """
        Test that group creation is possible via the Nessus API.  Uses the group created with the fixture
        nessus_create_group to test with.

        Scenarios:
            [x] Test successful group creation
        """
        created_group_details = self.cat.api.groups.create(name=random_name(prefix='automation-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        group_details = self.cat.api.groups.get_groups()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all([created_group_details['name'] in [group['name'] for group in group_details['groups']],
                    created_group_details['id'] in [group['id'] for group in group_details['groups']]]), \
            'Failed to create user...'

        self.cat.api.groups.delete(group_id=created_group_details['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# POST /groups/{group_id}/users/{user_id}
    # API_Tested# GET /groups/{group_id}/users/
    @pytest.mark.parametrize('nessus_create_parametrized_user', [API.User.Users.RANDOM_USER], indirect=True)
    def test_nessus_groups_add_user(self, nessus_create_parametrized_user):
        """
        Test that a user can be added to an existing group.  Adds a user, saves the old group members, adds another
        user, saves the new group members, and then compares to ensure our group count went up by 1.

        Scenarios:
            [x] Test a user was successfully added to a group
            [] Test adding a non-existing user to a group
            [] Test an invalid user to a group
            [] Test adding a group to a non-existent group
        """
        created_group_details = self.cat.api.groups.create(name=random_name(prefix='automation-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.groups.add_user(group_id=created_group_details['id'],
                                     user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        users_in_created_group = self.cat.api.groups.list_users(group_id=created_group_details['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert nessus_create_parametrized_user['id'] in [user['id'] for user in users_in_created_group['users']], \
            'Failed to add user in created user group...'

        self.cat.api.groups.delete(group_id=created_group_details['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# DELETE /groups/{group_id}
    def test_nessus_groups_delete_group(self):
        """
        Tests that we can delete groups via the Nessus API.  Uses a separate Group ID than the one created by our
        'nessus_create_group' fixture.

        Scenarios:
            [x] Test deleting a group successfully
            [] Test deleting a group that does not exist
        """
        created_group_details = self.cat.api.groups.create(name=random_name(prefix='automation-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.groups.delete(group_id=created_group_details['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        user_groups = self.cat.api.groups.get_groups()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert True if user_groups['groups'] is None else \
            created_group_details['id'] not in [group['id'] for group in user_groups['groups']], \
            'Failed to delete created user group...'

    # API_Tested# DELETE /groups/{group_id}/users/{user_id}
    @pytest.mark.parametrize('nessus_create_parametrized_user', [API.User.Users.RANDOM_USER], indirect=True)
    def test_nessus_groups_delete_user(self, nessus_create_parametrized_user):
        """
        Test that a user can be removed from an existing group. This test creates and adds a brand new user so we don't
        disrupt any other tests relying on existing users.

        Scenarios:
            [x] Test removing a user successfully from a group
            [] Test removing a user that does not exist
        """
        created_group_details = self.cat.api.groups.create(name=random_name(prefix='automation-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.groups.add_user(group_id=created_group_details['id'],
                                     user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.groups.delete_user(group_id=created_group_details['id'],
                                        user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        users_in_created_group = self.cat.api.groups.list_users(group_id=created_group_details['id'])

        assert users_in_created_group['users'] is None, 'Failed to delete user from created user group...'

        self.cat.api.groups.delete(group_id=created_group_details['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# PUT /groups/{group_id}
    def test_nessus_groups_edit_group(self):
        """
        Tests that we are able to edit a group via the Nessus API.  This test creates a new group so we don't disrupt
        any other tests relying on information contained in an existing group.

        Scenarios:
            [x] Test editing a group successfully
            [] Test editing a group with incorrect parameters
            [] Test editing a group that does not exist
        """
        created_group_name = random_name(prefix='automation-')
        edited_group_name = random_name(prefix='edited_automation-')

        created_group_details = self.cat.api.groups.create(name=created_group_name)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.groups.edit(group_id=created_group_details['id'], name=edited_group_name)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        group_details = self.cat.api.groups.get_groups()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        list_of_group_name = [group['name'] for group in group_details['groups']]

        assert all([created_group_name not in list_of_group_name, edited_group_name in list_of_group_name]), \
            'Failed to edit user group...'

        self.cat.api.groups.delete(group_id=created_group_details['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# POST /groups
    # API_Tested# DELETE /groups/{group_id}
    def test_duplicate_or_empty_user_group_name_not_allowed(self):
        """
        NES-12173: [Negative] Verify duplicate user group names are not allowed
        Tests that we are unable to create a group via the Nessus API if that group name is already in use.
        This test creates a new group so we don't disrupt any other tests relying on information contained in an
        existing group.

        Scenario Tested:
            [x] Test creating a group with a name that already exists
            [X] Verify duplicate or empty user group names are not allowed
        """
        user_group_name = random_name(prefix='user-group-')
        created_user_group_details = {}

        if user_group_name:
            created_user_group_details = self.cat.api.groups.create(name=user_group_name)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

        with pytest.raises(HTTPError):
            self.cat.api.groups.create(name=user_group_name)

        expected_status_code = HTTPStatus.BAD_REQUEST if user_group_name is None else HTTPStatus.CONFLICT

        assert self.cat.api.http_status_code == expected_status_code, \
            'Expected %s, got %s instead.' % (expected_status_code, self.cat.api.http_status_code)

        expected_error_msg = "Invalid 'name' field: missing" if user_group_name is None else \
            "A group with that name already exists"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

        if user_group_name:
            self.cat.api.groups.delete(group_id=created_user_group_details['id'])

    # API_Tested# GET /groups
    def test_nessus_groups_list_groups(self):
        """
        Tests that we are able to retrieve a list of groups via the Nessus API.  This test checks that the group
        created with the 'nessus_create_group' fixture is listed in Nessus' groups.

        Scenarios:
            [x] Test list of groups are returned
        """
        created_groups_details = []

        for _ in range(5):
            created_group = self.cat.api.groups.create(name=random_name(prefix='automation-'))

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            created_groups_details.append(created_group)

        group_details = self.cat.api.groups.get_groups()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        user_groups_ids = [group['id'] for group in group_details['groups']]
        user_groups_names = [group['name'] for group in group_details['groups']]

        assert all([group['id'] in user_groups_ids for group in created_groups_details]), \
            'Failed to get list of created group...'

        assert all([group['name'] in user_groups_names for group in created_groups_details]), \
            'Created groups are not available.'

        for group_id in user_groups_ids:
            self.cat.api.groups.delete(group_id=group_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# GET /groups/{group_id}/users
    @pytest.mark.parametrize('nessus_create_parametrized_user', [API.User.Users.RANDOM_USER], indirect=True)
    def test_nessus_groups_list_users(self, nessus_create_parametrized_user):
        """
        Tests that we are able to retrieve a list of users in a given group via the Nessus API.  Adds a user to the
        group created with the 'nessus_create_group' fixture and checks that we are able to retrieve that user's
        details.

        Scenarios:
            [x] Test to receive a list of users in a given group
            [] Test receiving a list of users in a non-existent group
        """
        created_group_details = self.cat.api.groups.create(name=random_name(prefix='automation-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.groups.add_user(group_id=created_group_details['id'],
                                     user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        users_in_created_group = self.cat.api.groups.list_users(group_id=created_group_details['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert nessus_create_parametrized_user['id'] in [user['id'] for user in users_in_created_group['users']], \
            'Failed to add user in created user group...'

        self.cat.api.groups.delete(group_id=created_group_details['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

    # API_Tested# DELETE /groups/
    def test_delete_groups_in_bulk(self):
        """
        STA-24: Create additional tests for Groups
        """
        created_groups_details = []

        for _ in range(5):
            created_group = self.cat.api.groups.create(name=random_name(prefix='automation-'))

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            created_groups_details.append(created_group)

        group_details = self.cat.api.groups.get_groups()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        created_groups_ids = [group['id'] for group in group_details['groups']]

        self.cat.api.groups.bulk_delete(group_list=created_groups_ids)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # verify all groups are deleted successfully
        group_list = self.cat.api.groups.get_groups()['groups']

        assert True if group_list is None else all(deleted_id not in [group['id'] for group in group_list] for
                                                   deleted_id in created_groups_ids), \
            'Bulk groups are not deleted successfully...'

    # API_Tested# PUT /groups/{group_id}
    # API_Tested# DELETE /groups/{group_id}
    @pytest.mark.parametrize('user_group_name', [True, False])
    def test_duplicate_or_empty_user_group_name_not_allowed_while_edit(self, nessus_create_group, user_group_name):
        """
        NES-12173: [Negative] Verify duplicate user group names are not allowed

        Scenario Tested:
            [x] Verify duplicate group name is not allowed if you edit and existing agent group.
        """
        existing_user_group_details = nessus_create_group
        edited_user_group_name = existing_user_group_details['name'] if user_group_name else None

        created_user_group_details = self.cat.api.groups.create(name=random_name(prefix='user-group-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        with pytest.raises(HTTPError):
            self.cat.api.groups.edit(group_id=created_user_group_details['id'], name=edited_user_group_name)

        expected_status_code = HTTPStatus.BAD_REQUEST if edited_user_group_name is None else HTTPStatus.CONFLICT

        assert self.cat.api.http_status_code == expected_status_code, \
            'Expected %s, got %s instead.' % (expected_status_code, self.cat.api.http_status_code)

        expected_error_msg = "Invalid 'name' field: missing" if edited_user_group_name is None else \
            "A group with that name already exists"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

        self.cat.api.groups.delete(group_id=created_user_group_details['id'])

    @pytest.mark.parametrize('nessus_create_parametrized_user', [API.User.Users.RANDOM_USER], indirect=True)
    def test_add_user_into_group_which_is_already_in_group(self, nessus_create_parametrized_user):
        """
        NES-12211: [API] Add/list/delete users in user groups

        Scenario Tested:
            [x] Verify adding user into group which is already in that group throws an error.
        """
        created_group_details = self.cat.api.groups.create(name=random_name(prefix='automation-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.groups.add_user(group_id=created_group_details['id'],
                                     user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        with pytest.raises(HTTPError):
            self.cat.api.groups.add_user(group_id=created_group_details['id'],
                                         user_id=nessus_create_parametrized_user['id'])

        assert self.cat.api.http_status_code == HTTPStatus.CONFLICT, \
            'Expected 409, got %s instead.' % self.cat.api.http_status_code

        expected_error_msg = "User is already a member of the group"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

        self.cat.api.groups.delete(group_id=created_group_details['id'])

    @pytest.mark.parametrize(('invalid_group_id', 'group_id'), [
        ('negative', -1),
        ('zero', 0),
        ('empty', ''),
        ('none', None),
        ('random', True)])
    def test_delete_group_with_invalid_values(self, invalid_group_id, group_id):
        """
        NES-12210: [API] CRUD operations for User groups

        Scenario Tested:
            [x] Verify deleting user group with invalid values throws an error.
        """
        if invalid_group_id == 'random':
            group_id = randint(1000, 9999)

        with pytest.raises(HTTPError):
            self.cat.api.groups.delete(group_id=group_id)

        expected_status_code = HTTPStatus.BAD_REQUEST if group_id in ['', None] else HTTPStatus.NOT_FOUND

        assert self.cat.api.http_status_code == expected_status_code, \
            'Expected %s, got %s instead.' % (expected_status_code, self.cat.api.http_status_code)

        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        if group_id == '':
            expected_error_msg = "Invalid 'ids' field: missing"
        elif group_id is None:
            expected_error_msg = "Invalid 'group_id' field: invalid type 'string', expecting 'int'"
        else:
            expected_error_msg = "The requested file was not found"

        assert expected_error_msg in error_msg_from_response, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    def test_delete_bulk_groups_with_invalid_values(self):
        """
        NES-12210: [API] CRUD operations for User groups

        Scenario Tested:
            [x] Verify deleting bulk user groups with invalid values throws an error.
        """
        invalid_group_ids = [-1, 0, '', None, randint(1000, 9999)]

        with pytest.raises(HTTPError):
            self.cat.api.groups.bulk_delete(group_list=invalid_group_ids)

        assert self.cat.api.http_status_code == HTTPStatus.NOT_FOUND, \
            'Expected 404, got %s instead.' % self.cat.api.http_status_code

        error_msg_from_response = json.loads(self.cat.api.http_text)['error']
        expected_error_msg = "The requested file was not found"

        assert expected_error_msg in error_msg_from_response, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    @pytest.mark.parametrize('invalid_group_id', [-1, 0, None, 'random'])
    def test_get_non_exist_group_details_throws_an_error(self, invalid_group_id):
        """
        NES-12210: [API] CRUD operations for User groups

        Scenario Tested:
            [x] Verify getting group details which are not exist or created throws an error.
        """
        if invalid_group_id == 'random':
            invalid_group_id = randint(1000, 9999)
        with pytest.raises(HTTPError):
            self.cat.api.groups.group_details(group_id=invalid_group_id)

        assert self.cat.api.http_status_code == HTTPStatus.METHOD_NOT_ALLOWED, \
            'Expected 405, got %s instead.' % self.cat.api.http_status_code

        error_msg_from_response = json.loads(self.cat.api.http_text)['error']
        expected_error_msg = "The requested method is not allowed for this URL"

        assert expected_error_msg in error_msg_from_response, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    @pytest.mark.parametrize('invalid_user_id', [-1, 0, 'random'])
    def test_delete_user_from_group_with_invalid_values(self, invalid_user_id):
        """
        NES-12211: [API] Add/list/delete users in user groups

        Scenario Tested:
            [x] Verify deleting user from group with invalid user id throws an error.
        """
        if invalid_user_id == 'random':
            invalid_user_id = randint(1000, 9999)

        created_group_details = self.cat.api.groups.create(name=random_name(prefix='automation-'))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        with pytest.raises(HTTPError):
            self.cat.api.groups.delete_user(group_id=created_group_details['id'], user_id=invalid_user_id)

        assert self.cat.api.http_status_code == HTTPStatus.NOT_FOUND, \
            'Expected 404, got %s instead.' % self.cat.api.http_status_code

        error_msg_from_response = json.loads(self.cat.api.http_text)['error']
        expected_error_msg = "The requested file was not found"

        assert expected_error_msg in error_msg_from_response, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

        self.cat.api.groups.delete(group_id=created_group_details['id'])
