"""
:copyright: Tenable Network Security, 2017
:date: June 1, 2017
:author: @cdombrowski
"""
import json
from http import HTTPStatus
from requests import HTTPError

from catium.lib.log import create_logger
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.lib.const import API
from nessus.helpers.session import create_session_api_keys
import pytest

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/nessus_qa/test_data/test_nessus_users.json'])
@pytest.mark.usefixtures('nessus_api_login', 'load_test_data')
class TestNessusSession:
    """
    Class to handle testing Nessus API Keys.  This includes tests such as creating the key (both success and failure)
    as well as regenerating the key.  This should also test that we can access scans when authenticating with API
    keys.
    """

    cat = None

    # API_Tested# POST /session
    @pytest.mark.skip('As discussed, not in scope for Musikaar team to fix this, hence skipping.')
    def test_nessus_session_create(self):
        """
        Tests that we are able to create a session via the Nessus API using the 'nessus_class_api_login' fixture.
        """
        resp = self.cat.api.users.get_users()
        assert resp and self.cat.api.http_request_headers['X-Cookie'] and \
            self.cat.api.http_status_code == HTTPStatus.OK, 'X-Cookie token not found, session creation failed.'

    # API_Tested# DELETE /session
    def test_nessus_session_delete(self):
        """
        Tests that we are able to delete a session via the Nessus API.
        """
        session = NessusAPI()
        session.login()
        session.session.delete()
        with pytest.raises(HTTPError):
            session.users.get_users()

    # API_Tested# PUT /session
    @pytest.mark.skip('As discussed, not in scope for Musikaar team to fix this, hence skipping.')
    @pytest.mark.parametrize('nessus_create_parametrized_user', [API.User.Users.SYS_ADMIN_USER,
                                                                 API.User.Users.STANDARD_USER], indirect=True)
    def test_nessus_session_edit(self, nessus_create_parametrized_user):
        """
        Tests that we are able to edit permissions, name, and e-mail of the current session.
        """
        username = nessus_create_parametrized_user['name']
        password = self.cat.nessus_password
        session = NessusAPI()
        session.login(username=username, password=password)
        session.session.edit(name=random_name(prefix='automation-'),
                             email=API.User.Users.TEST_EMAIL)
        resp = json.loads(session.http_text)
        session.logout()
        assert self.cat.api.http_status_code == HTTPStatus.OK and \
            resp['lockout'] is False and \
            resp['groups'] is None and \
            'automation-' in resp['name'] and \
            resp['username'] == self.cat.nessus_username and \
            resp['type'] == API.User.Types.LOCAL and \
            resp['email'] == API.User.Users.TEST_EMAIL and \
            resp['permissions'] == self.cat.nessus_user_permissions, \
            'Unable to edit {0}\'s current session.'.format(self.cat.nessus_username)

    # API_Tested# GET /session
    def test_nessus_session_get(self):
        """
        Tests that we are able to retrieve the current session details via the Nessus API.
        """
        resp = self.cat.api.session.get()
        assert self.cat.api.http_status_code == HTTPStatus.OK and resp['username'], 'Unable to retrieve the current ' \
                                                                                    'session details.'

    # API_Tested# PUT /session/chpasswd
    @pytest.mark.skip('As discussed, not in scope for Musikaar team to fix this, hence skipping.')
    @pytest.mark.parametrize('nessus_create_parametrized_user', [API.User.Users.SYS_ADMIN_USER,
                                                                 API.User.Users.STANDARD_USER], indirect=True)
    def test_nessus_session_change_password(self, nessus_create_parametrized_user):
        """
        Tests that we are able to change the current session's password via the Nessus API.  Uses the user created by
        the nessus_class_create_user fixture.
        """
        username = nessus_create_parametrized_user['name']
        password = self.cat.nessus_password
        session = NessusAPI()
        session.login(username=username, password=password)
        session.session.password(current_password=password, new_password=random_name(prefix='Tenable@'))
        session.logout()
        with pytest.raises(HTTPError):
            session.login(username=username, password=password)

    # API_Tested# PUT /session/keys
    def test_session_api_keys(self):
        """
        Tests that we are able to create Nessus API Keys for the current user's session.  We also test that these keys
        are the expected length.
        """
        api_keys = create_session_api_keys(api=self.cat.api)
        assert api_keys and len(api_keys['secret_key']) == 64 and len(api_keys['access_key']) == 64, \
            'API secretKey or accessKey length was not the expected size.'

    # API_Tested# PUT /session/keys
    @pytest.mark.skip('As discussed, not in scope for Musikaar team to fix this, hence skipping.')
    def test_session_api_login(self):
        """
        Test that we are able to retrieve a list of Nessus users via the user's session API keys.  If this fails, the
        session was not successfully created with the Nessus API Keys.
        """
        api_keys = create_session_api_keys(api=self.cat.api)
        nessus_api = NessusAPI()
        nessus_api.set_api_keys(access_key=api_keys['access_key'], secret_key=api_keys['secret_key'])
        try:
            resp = nessus_api.users.get_users()
        except HTTPError:
            if nessus_api.http_status_code != HTTPStatus.OK:
                pytest.fail('Unable to authenticate via API Keys')
        assert resp and nessus_api.http_status_code == HTTPStatus.OK, 'Unable to authenticate via API Keys'

    # API_Tested# PUT /session/keys
    def test_api_key_regenerate(self):
        """
        Test our ability to regenerate Nessus API Keys.  Creates an initial set of API Keys and then a second set.  If
        the first and second set are the same, we fail.
        """
        api_keys_original = create_session_api_keys(api=self.cat.api)
        api_keys_new = create_session_api_keys(api=self.cat.api)
        assert api_keys_original and api_keys_new and api_keys_original['secret_key'] != api_keys_new['secret_key'] \
            and api_keys_original['access_key'] != api_keys_new['access_key'] and \
            len(api_keys_new['secret_key']) == 64 and len(api_keys_new['access_key']) == 64,  \
            'API Access Key and Secret Key did not regenerate.'
