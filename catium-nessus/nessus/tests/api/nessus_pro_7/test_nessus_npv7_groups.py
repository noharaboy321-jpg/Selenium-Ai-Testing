"""
:copyright: Tenable Network Security, 2017
:date: October 4, 2017
:last_modified: July 15, 2020
:author: @pellsworth, @kpanchal
"""
import pytest

from catium.lib.log import create_logger
from nessus.helpers.server import expect_http_error

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login', 'no_automation_api_key')
class TestNessusGroupsPro7:
    """
    Class will handle testing Nessus Groups via the API, and failing due to the feature not 
    being available.
    """

    cat = None

    # API_Tested# POST /groups
    def test_nessus_groups_create_group(self):
        """Tests Group creation"""
        with expect_http_error(code=403):
            try:
                self.cat.api.groups.create(name='bogus', stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    # API_Tested# POST /groups/{group_id}/users/{user_id}
    def test_nessus_groups_add_user(self):
        """Tests adding a user to a group"""
        with expect_http_error(code=403):
            self.cat.api.groups.add_user(group_id=1, user_id=2, stream=True)

    # API_Tested# DELETE /groups/{group_id}
    def test_nessus_groups_delete_group(self):
        """Tests deleting a group"""
        with expect_http_error(code=403):
            self.cat.api.groups.delete(group_id=1, stream=True)

    # API_Tested# DELETE /groups/{group_id}/users/{user_id}
    def test_nessus_groups_delete_user(self):
        """Tests deleting a user from a group"""
        with expect_http_error(code=403):
            self.cat.api.groups.delete_user(group_id=1, user_id=1, stream=True)

    # API_Tested# PUT /groups/{group_id}
    def test_nessus_groups_edit_group(self):
        """Tests editing a group"""
        with expect_http_error(code=403):
            try:
                self.cat.api.groups.edit(group_id=1, name='bogus', stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    # API_Tested# GET /groups
    def test_nessus_groups_list_groups(self):
        """Tests retrieving a list of groups"""
        with expect_http_error(code=403):
            self.cat.api.groups.get_groups(stream=True)

    # API_Tested# GET /groups/{group_id}/users
    def test_nessus_groups_list_users(self):
        """Tests listing users in a group"""
        with expect_http_error(code=403):
            self.cat.api.groups.list_users(group_id=1, stream=True)
