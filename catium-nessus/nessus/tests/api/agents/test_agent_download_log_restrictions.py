"""
Test Agent Bug Report Token and Download Routes for Proper Restrictions

NES-19866: Standard Users are Able to use the Nessus Manager API to Download Agent Bug Reports
NES-19872 (Xray Test): Verify download-log and token routes are restricted by user role.

Endpoints under test:
    POST /agents/{AGENT_ID}/download-log   (request a token)
    GET  /tokens/{FILE_TOKEN}/status       (check token status)
    GET  /tokens/{FILE_TOKEN}/download     (download the file)
    POST /tokens/{FILE_TOKEN}/cancel       (cancel the token)

Expected access for POST /agents/{AGENT_ID}/download-log (token request):
    No user (unauthenticated) -> 401
    Basic (16)                -> 403
    Standard (32)             -> 403
    Administrator (64)        -> 200
    System Administrator (128)-> 200

Expected access for GET /tokens/{FILE_TOKEN}/* (token usage):
    All users (including unauthenticated) -> 200
    The token itself serves as authorization (auth mode 'try', rights ACL_NO_ACCESS).

Setup: A dummy log file must exist in the agent's remote logs directory on the NM.
       The fixture creates it via SSH at /opt/nessus/var/nessus/logs/remote/<AGENT_UUID>/
"""
import json
from http import HTTPStatus

import pytest

from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_nessus_var_dir
from nessus.helpers.server import expect_http_error
from nessus.lib.const.constants import API

log = create_logger()

TEST_LOG_FILENAME = 'automation_test.log'


def _get_download_token(api, agent_id):
    """Request a download-log token and return the token string."""
    raw = api.agents.download_logs(agent_id=agent_id, data={'log': TEST_LOG_FILENAME})
    # Response is str(response.content) e.g. b'{"token":"abc123"}'
    cleaned = raw
    if cleaned.startswith("b'") or cleaned.startswith('b"'):
        cleaned = cleaned[2:-1]
    return json.loads(cleaned)['token']


@pytest.fixture()
def agent_with_log_file(request, nessus_api_login):
    """Create a fake agent and place a dummy log file in its remote logs directory.

    Yields (agent_id, agent_uuid) for use in tests.
    Cleans up the log file on teardown.
    """
    # Use the first available real agent, or create a fake one
    fake_agent = None
    agents_resp = nessus_api_login.agents.agents_list()
    agents = agents_resp.get('agents') or []

    if agents:
        agent = agents[0]
        agent_id = agent['id']
        agent_uuid = agent['uuid']
    else:
        fake_agent = nessus_api_login.agents.add_fake_agent()
        agent_uuid = fake_agent['agent_uuid']
        # Look up the agent_id from the agents list
        agents_resp = nessus_api_login.agents.agents_list()
        agent = [a for a in agents_resp.get('agents', []) if a['uuid'] == agent_uuid][0]
        agent_id = agent['id']

    # Create the dummy log file in the agent's remote logs directory via SSH
    var_dir = get_nessus_var_dir()
    log_dir = '%s/logs/remote/%s' % (var_dir, agent_uuid)
    log_path = '%s/%s' % (log_dir, TEST_LOG_FILENAME)

    with SSH() as ssh:
        ssh.execute(command='mkdir -p %s' % log_dir, sudo=True)
        ssh.execute(command='echo "automation test log content" > %s' % log_path, sudo=True)
        ssh.execute(command='chown nessusd:nessusd %s' % log_path, sudo=True)

    yield agent_id

    # Cleanup
    try:
        with SSH() as ssh:
            ssh.execute(command='rm -f %s' % log_path, sudo=True)
    except Exception as exc:
        log.warning('Failed to clean up test log file: %s', exc)
    if fake_agent:
        try:
            nessus_api_login.agents.delete_multiple(ids=[agent_id])
        except Exception as exc:
            log.warning('Failed to clean up fake agent: %s', exc)


@pytest.mark.nessus_manager
@pytest.mark.agent
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentDownloadLogRestrictions:
    """
    NES-19866 / NES-19872: Verify that agent bug report download-log and
    token routes are restricted to Administrator and System Administrator roles.
    """

    cat = None

    @pytest.mark.xray(test_key='NES-19872')
    @pytest.mark.parametrize('create_users_using_api, expected_status', [
        pytest.param([API.Permissions.User.SYSTEM_ADMINISTRATOR], HTTPStatus.OK, id='sysadmin'),
        pytest.param([API.Permissions.User.ADMINISTRATOR], HTTPStatus.OK, id='admin'),
        pytest.param([API.Permissions.User.STANDARD], HTTPStatus.FORBIDDEN, id='standard'),
        pytest.param([API.Permissions.User.BASIC], HTTPStatus.FORBIDDEN, id='basic'),
    ], indirect=['create_users_using_api'])
    def test_download_log_token_request(self, agent_with_log_file, create_users_using_api, expected_status):
        """Verify POST /agents/{id}/download-log is allowed or denied based on user role."""
        agent_id = agent_with_log_file
        user = create_users_using_api[0]

        user_api = NessusAPI()
        user_api.login(username=user['name'], password=user['password'])
        try:
            if expected_status == HTTPStatus.OK:
                token = _get_download_token(user_api, agent_id)
                assert user_api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s' % user_api.http_status_code
                assert token, 'Token was not returned'
            else:
                with expect_http_error(code=expected_status):
                    user_api.agents.download_logs(agent_id=agent_id, data={'log': TEST_LOG_FILENAME})
        finally:
            user_api.logout()

    @pytest.mark.xray(test_key='NES-19872')
    def test_download_log_token_request_unauthenticated(self, agent_with_log_file):
        """Verify POST /agents/{id}/download-log is denied for unauthenticated users."""
        agent_id = agent_with_log_file

        noauth_api = NessusAPI(login=False)
        with expect_http_error(code=HTTPStatus.UNAUTHORIZED):
            noauth_api.agents.download_logs(agent_id=agent_id, data={'log': TEST_LOG_FILENAME})

    @pytest.mark.xray(test_key='NES-19872')
    @pytest.mark.parametrize('create_users_using_api', [
        pytest.param([API.Permissions.User.SYSTEM_ADMINISTRATOR], id='sysadmin'),
        pytest.param([API.Permissions.User.ADMINISTRATOR], id='admin'),
        pytest.param([API.Permissions.User.STANDARD], id='standard'),
        pytest.param([API.Permissions.User.BASIC], id='basic'),
    ], indirect=['create_users_using_api'])
    def test_token_status_and_download(self, agent_with_log_file, create_users_using_api):
        """Verify token status, download, and cancel routes are accessible for all user roles.

        Token routes use auth mode 'try' with ACL_NO_ACCESS — the token itself is the
        authorization. All authenticated users should be able to use a valid token.
        See NES-19891 for context.
        """
        agent_id = agent_with_log_file
        user = create_users_using_api[0]

        user_api = NessusAPI()
        user_api.login(username=user['name'], password=user['password'])
        try:
            token = _get_download_token(self.cat.api, agent_id)
            user_api.tokens.status(token_id=token)
            assert user_api.http_status_code == HTTPStatus.OK, \
                'token status: Expected 200, got %s' % user_api.http_status_code

            token = _get_download_token(self.cat.api, agent_id)
            user_api.tokens.download(token_id=token)
            assert user_api.http_status_code == HTTPStatus.OK, \
                'token download: Expected 200, got %s' % user_api.http_status_code

            token = _get_download_token(self.cat.api, agent_id)
            user_api.tokens.cancel(token_id=token)
            assert user_api.http_status_code == HTTPStatus.OK, \
                'token cancel: Expected 200, got %s' % user_api.http_status_code
        finally:
            user_api.logout()

    @pytest.mark.xray(test_key='NES-19872')
    def test_token_routes_unauthenticated(self, agent_with_log_file):
        """Verify token status, download, and cancel routes are accessible without authentication.

        The token itself serves as authorization (auth mode 'try', rights ACL_NO_ACCESS).
        The security boundary is at the token *request* endpoint (POST /agents/{id}/download-log),
        not at the token *usage* endpoints.
        See NES-19891 for context on why these routes must remain open.
        """
        agent_id = agent_with_log_file
        noauth_api = NessusAPI(login=False)

        token = _get_download_token(self.cat.api, agent_id)
        noauth_api.tokens.status(token_id=token)
        assert noauth_api.http_status_code == HTTPStatus.OK, \
            'token status: Expected 200, got %s' % noauth_api.http_status_code

        token = _get_download_token(self.cat.api, agent_id)
        noauth_api.tokens.download(token_id=token)
        assert noauth_api.http_status_code == HTTPStatus.OK, \
            'token download: Expected 200, got %s' % noauth_api.http_status_code

        token = _get_download_token(self.cat.api, agent_id)
        noauth_api.tokens.cancel(token_id=token)
        assert noauth_api.http_status_code == HTTPStatus.OK, \
            'token cancel: Expected 200, got %s' % noauth_api.http_status_code
