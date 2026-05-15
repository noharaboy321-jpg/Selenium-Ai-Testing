"""
:copyright: Tenable Network Security, 2017
:date: October 2, 2017
:author: @pellsworth
"""
import pytest
from catium.lib.log import create_logger
from nessus.helpers.server import expect_http_error
from nessus.models.user import UserModel


log = create_logger()


@pytest.mark.skip('As discussed, not in scope for Musikaar team to fix this, hence skipping.')
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login', 'no_automation_api_key')
class TestNessusUsersPro7:
    """
    Class to handle testing the /users endpoints that should be disallowed in Nessus Professional 7.
    Scenarios:
        [x] Test that querying a list of users isn't allowed in NPv7
        [x] Test that querying a specific user isn't allowed in NPv7
        [x] Test that users are unable to create new users in NPv7
        [x] Test that users are unable to edit/update existing users in NPv7
        [x] Test that users cannot delete other users in NPv7
        [x] Test that users cannot bulk delete users in NPv7
    """

    cat = None

    # API_Tested# GET /users
    def test_nessus_get_users(self):
        """
        Tests that querying users isn't allowed in NPv7
        """
        with expect_http_error(code=403):
            self.cat.api.users.get_users()

    # API_Tested# GET /users/{user_id}
    def test_nessus_get_user(self):
        """
        Tests that querying a specific user isn't allowed in NPv7
        """
        with expect_http_error(code=403):
            self.cat.api.users.get(500)

    # API_Tested# POST /users
    def test_nessus_create_user(self):
        """
        Tests that creating a user isn't allowed in NPv7
        """
        with expect_http_error(code=403):
            self.cat.api.users.create(UserModel(username='totallybogus',
                                                password='doesnotmatter'))

    # API_Tested# PUT /users/{user_id}
    def test_nessus_edit_user(self):
        """
        Tests that editing a user isn't allowed in NPv7
        """
        with expect_http_error(code=403):
            self.cat.api.users.edit(500, UserModel(name='Automation',
                                                   password='doesnotmatter'))

    # API_Tested# DELETE /users/{user_id}
    def test_nessus_delete_user(self):
        """
        Tests that deleting a user isn't allowed in NPv7
        """
        with expect_http_error(code=403):
            self.cat.api.users.delete(500)

    # API_Tested# DELETE /users
    def test_nessus_delete_users(self):
        """
        Tests that bulk deleting users isn't allowed in NPv7
        """
        with expect_http_error(code=403):
            self.cat.api.users.delete_users([500, 501])
