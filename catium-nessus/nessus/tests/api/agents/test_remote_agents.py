""""
Nessus API test cases related to remote/agent endpoints

:copyright: Tenable Network Security, 2018
:date: Dec 21, 2018
:last_modified: July 20, 2020
:author: @yshah, @ntarwani, @jchavda, @dkothari, @kpanchal
"""
import uuid
from contextlib import contextmanager
from http import HTTPStatus
import pytest
from random import randint, randrange
from requests import HTTPError
from waiting import wait

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_TEN_SECONDS, TIME_THIRTY_SECONDS, TIME_FIFTEEN_SECONDS, TIME_TEN_MINUTES, \
    TIME_FIVE_SECONDS, TIME_FIVE_MINUTES, TIME_THIRTY_MINUTES
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import choose_agent_info, get_agent_id_from_list
from nessus.helpers.nessuscli.helper import get_os_name, get_nessus_var_dir, get_command, path_join
from nessus.helpers.scan import create_scan_with_fake_agent, start_stop_nessus_wait_for_ready
from nessus.helpers.waiters import wait_scan_state, wait_for_scan, wait_for_scanner_status
from nessus.lib.const import API, SSHCommands, OperatingSystems

log = create_logger()


@pytest.fixture()
def add_fake_agent(nessus_api_login):
    """
    This fixture create a new fake agent and deletes it after the test case is completed

    :return: dictionary containing agent_name, token and agent_uuid

    Note: The existing fixture in /nessus/plugins/fixtures/agents.py returns agent_id only and modification will affect
    existing test cases. So we have created this new fixture which returns agent_name, agent_uuid and token
    """
    try:
        agent = nessus_api_login.agents.add_fake_agent(agent_name=random_name(prefix="automation-"))
    except HTTPError:
        raise HTTPError("Agent could not be created")
    else:
        yield agent
    finally:
        agent_id, agent_status = get_agent_id_from_list(api=nessus_api_login, agent_name=agent['name'])
        try:
            nessus_api_login.agents.delete_agent(agent_id=agent_id)
        except Exception as exc:
            create_logger().debug('Fixture failed to delete Agent: %s', exc)


@contextmanager
def scan_with_fake_agent(api_handler: NessusAPI):
    """Create scan with fake agent needed in test cases below"""
    try:
        agent = api_handler.agents.add_fake_agent(agent_name=random_name(prefix="automation-"))
        assert api_handler.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % api_handler.http_status_code

        scan_details = create_scan_with_fake_agent(api_handler=api_handler,
                                                   file_name=get_file_path('nessus/tests/api/scan/test_data/'
                                                                           'test_basic_agent_scan.json'),
                                                   template_title='agent_basic')

        details = (scan_details, agent)

        yield details
    finally:
        sleep(sleep_time=TIME_THIRTY_SECONDS, reason="Wait for sometime before next API")

        api_handler.scans.delete(scan_id=scan_details[0]['scan']['id'])
        agent_id, agent_status = get_agent_id_from_list(api=api_handler, agent_name=agent['name'])
        api_handler.agents.delete_agent(agent_id=agent_id)
        api_handler.agent_groups.delete_groups([scan_details[1]['id']])


def check_for_package_download(nessus_api: None, distro: str, platform: str, stream: bool = False):
    """
    Check to see if NM has downloaded the core and placed it in /opt/nessus/var/nessus/remote/
    :param NessusAPI nessus_api: existing Nessus API object of current session
    :param str distro: distro of the host to download core update
    :param str platform: platform of the host to download core update
    :param bool stream: True if need to get response text else False
    :return: True if remote_agent_core API call succeeds else False
    :r-type: bool
    """
    if not nessus_api:
        nessus_api = NessusAPI()
    try:
        # todo: send upgrade_distro when appropriate
        nessus_api.remote.get_remote_agent_core(distro=distro, platform=platform, stream=stream)
        return True
    except HTTPError:
        if nessus_api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            return False


@pytest.mark.nessus_manager
@pytest.mark.skip_nessustc
@pytest.mark.usefixtures('nessus_api_login')
class TestRemoteAgentEndpoints:
    """Tests related to Remote Agent endpoints"""

    cat = None

    # API_Tested# GET /remote/agent/plugins
    # @pytest.mark.nessus_manager_mat TODO: ESQO-974
    @pytest.mark.skip_acceptance
    @pytest.mark.usefixtures('nessus_api_login', 'add_agent_locally')
    def test_get_remote_agent_plugins(self, add_agent_locally):
        """
        Tested /remote/agent/plugins API Endpoints
        Verifies if plugins file is downloaded

        Scenarios tested:
        [X] Add agent locally
        [X] Download plugins file

        Note: #STA-91-test case for /remote/agent/plugins
        """
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        # Add MS-Agent header to session headers
        self.cat.api.add_header({'MS-Agent': "token={}".format(add_agent_locally["token"])})

        # GET the response and headers from /remote/agent/plugins endpoint
        re = self.cat.api.remote.get_remote_agent_plugins(params={'platform': 'WINDOWS', 'distro': 'win-x86-64'},
                                                          stream=True)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code
        assert re.headers['Content-Disposition'] == 'attachment; filename="agent.db.gz"', \
            "Plugins file is not downloaded successfully"
        self.cat.api.remove_header(key='MS-Agent')

    # API_Tested# GET /remote/agent/updates
    @pytest.mark.xray(test_key='NES-18072')
    @pytest.mark.nessus_mat
    def test_get_remote_agent_updates(self, add_fake_agent):
        """
        clear remote directory
        get all agent versions from the feed
        choose a random platform distro
        set the first one as default, create agent_version agent_build file, and the agent package
            e.g. nessus-agent-el7-x86-64.tar.gz, the content is 10.4.1-123
        for each other versions
            create dir agent_versions/version-build
            add nessus-agent-el7-x86-64.tar.gz to the directory, the file content is version-build

        Tested /remote/agent/updates API Endpoints

        Scenarios tested:
        [X] GET the response of remote agent updates

        Note: #STA-92-test case for /remote/agent/updates
        """

        remote_directory = path_join([get_nessus_var_dir(), "remote"])
        versions_directory = path_join([remote_directory, "agent_versions"])

        feed_versions = self.cat.api.settings.agent_versions()
        versions = []

        default_version = ""
        default_build = ""
        for key in feed_versions["versions_in_feed"]:
            build = feed_versions["versions_in_feed"][key]["build"]
            version_digits = key.count('.')
            if version_digits == 2:
                if default_version == "":
                    default_version = key
                    default_build = build
                else:
                    versions.append(key + "-" + build)

        platform, distro, upgrade_distro = choose_agent_info()
        package_name = f"nessus-agent-{upgrade_distro}.tar.gz"

        with SSH() as ssh:
            ssh.execute("{} {}".format(get_command(operation='remove_file'), remote_directory), sudo=True)
            ssh.execute("{} {}".format(get_command(operation='create_directory'), remote_directory), sudo=True)
            ssh.execute("{} {}".format(get_command(operation='create_directory'), versions_directory), sudo=True)
            ssh.execute(get_command(operation='append_to_file').format(default_version,
                        path_join([remote_directory, "agent_version"]), sudo=True))
            ssh.execute(get_command(operation='append_to_file').format(default_build,
                        path_join([remote_directory, "agent_build"]), sudo=True))
            ssh.execute(get_command(operation='append_to_file').format(f"{default_version}-{default_build}",
                        path_join([remote_directory, package_name]), sudo=True))

            for version in versions:
                version_directory = path_join([versions_directory, version])
                ssh.execute("{} {}".format(get_command(operation='create_directory'),
                        version_directory), sudo=True)
                ssh.execute(get_command(operation='append_to_file').format(version,
                       path_join([version_directory, package_name]),
                       sudo=True))

        # test no version parameter
        response = self.cat.api.remote.get_remote_agent_updates(params={"platform": platform, "distro": distro, "upgrade_distro": upgrade_distro})
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code
        assert response["ui_version"] == default_version
        assert response["ui_build"] == default_build

        # test version parameter
        for key in feed_versions["versions_in_feed"]:
            response = self.cat.api.remote.get_remote_agent_updates(params={"platform": platform, "distro": distro, "upgrade_distro": upgrade_distro, "version": key})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code
            assert response["ui_version"] == feed_versions["versions_in_feed"][key]["version"]
            assert response["ui_build"] == feed_versions["versions_in_feed"][key]["build"]

        # test version not exists
        response = self.cat.api.remote.get_remote_agent_updates(params={"platform": platform, "distro": distro, "version": "1000"})
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code
        assert not "ui_version" in response and not "ui_build" in response

    # API_Tested# POST /remote/agent
    @pytest.mark.nessus_mat
    @pytest.mark.incompatible
    @pytest.mark.parametrize('upgrade_distro_param', [False, pytest.param(True, marks=pytest.mark.xfail(
        reason='New distros not yet available in feed, refer AGENT-1830 for more details'))])
    def test_add_and_link_remote_agent(self, upgrade_distro_param):
        """
        STA-89: Implement test case for /remote/agent and /remote/agent/core
        Scenarios Tested:
        [X] Adding and linking an agent to Nessus Manager:
        """
        os_name = get_os_name()
        linking_key = self.cat.api.settings.get_key()['key']
        remote_directory = r"{}\remote".format(get_nessus_var_dir()) if os_name == OperatingSystems.WINDOWS \
            else "{}/remote".format(get_nessus_var_dir())

        delete_files_command = "{} /Q/S {}".format(SSHCommands.Windows.COMMAND['remove_file'], remote_directory) \
            if os_name == OperatingSystems.WINDOWS \
            else "{} {}/*".format(SSHCommands.Linux.COMMAND['remove_file'], remote_directory)

        display_directory_content_command = SSHCommands.Windows.COMMAND['display_directory_content'] \
            if os_name == OperatingSystems.WINDOWS else SSHCommands.Linux.COMMAND['display_directory_content']
        uuid = str(randint(10000000, 99999999)) + "-0000-0000-0000-" + str(randint(100000, 999999)) + str(
            randint(100000, 999999))

        ipv4 = ["{0}.{1}.{2}.{3}".format(randrange(1, 254), randrange(1, 254), randrange(1, 254), randrange(1, 254))]

        os_platform, distro, upgrade_distro = choose_agent_info()

        data = {"name": random_name(prefix="automation-"), "groups": ["All", None], "distro": distro,
                "platform": os_platform, "key": linking_key, "uuid": uuid, "ips": {"v4": ipv4, "v6": None}}

        if upgrade_distro_param:
            data['upgrade_distro'] = upgrade_distro

        with SSH() as ssh:
            if os_name == OperatingSystems.WINDOWS:
                ssh.execute(delete_files_command)
            else:
                for command in ['rm -r /opt/nessus/var/nessus/remote/', 'mkdir /opt/nessus/var/nessus/remote']:
                    ssh.execute(command=command)
            remote_directory_content = ssh.execute("{} {}".format(display_directory_content_command, remote_directory))

            if os_name == OperatingSystems.WINDOWS:
                assert [cmd for cmd in remote_directory_content if "0 File" in cmd and '0 bytes' in cmd], \
                    'Still the files are present after deleting the content of {}, with output as: {}'.format(
                        remote_directory, remote_directory_content)
            else:
                assert not ssh.execute("{} {}".format(display_directory_content_command, remote_directory)), \
                    'Still the files are present after deleting the content of {}, with output as: {}'.format(
                        remote_directory, remote_directory_content)

            self.cat.api.agents.add_agents(agent_info=data)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

            start_stop_nessus_wait_for_ready(nessus_api=self.cat.api, status=API.Status.READY)
            self.cat.api.login()

            wait(lambda: ssh.execute("{} {}".format(display_directory_content_command, remote_directory)),
                 timeout_seconds=TIME_THIRTY_MINUTES, sleep_seconds=TIME_TEN_SECONDS,
                 waiting_for='Nessus to download core updates')

        agent_id, agent_status = get_agent_id_from_list(api=self.cat.api, agent_name=data['name'])
        self.cat.api.agents.delete_agent(agent_id=agent_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead'.format(self.cat.api.http_status_code)

    # API_Tested# GET /remote/agent/core
    @pytest.mark.xfail(reason='New distros not yet available in feed, refer AGENT-1830 for more details')
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None'], pytest.param(
        [1, 'None', 'None', 'no-full', True], marks=pytest.mark.xfail(
            reason='New distros not yet available in feed, refer AGENT-1830 for more details'))], indirect=True)
    def test_get_remote_agent_core(self, nessus_create_nessus_agent):
        """
        STA-89: Implement test case for /remote/agent and /remote/agent/core
        Scenarios Tested:
        [X] Get core updates for an agent linked to Nessus Manager:

        Note- If the core update is not available the response code should be 500 and the response message should be
        '{"error":"core update not found for es5-x86-64"}'
        """
        agent_id = nessus_create_nessus_agent[0]
        agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)
        log.info("agent-details: {}".format(agent_details))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        # Trigger and wait for NM to download the core package
        start_stop_nessus_wait_for_ready(nessus_api=self.cat.api, status=API.Status.READY)
        self.cat.api.login()

        wait(lambda: check_for_package_download(nessus_api=self.cat.api, distro=agent_details['distro'],
                                                platform=agent_details['platform'], stream=True),
             timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=TIME_FIVE_SECONDS,
             waiting_for='Nessus to download core updates')

        try:
            if 'upgrade_distro' in agent_details.keys() and agent_details['upgrade_distro']:
                self.cat.api.remote.get_remote_agent_core(
                    distro=agent_details['distro'], platform=agent_details['platform'],
                    upgrade_distro=agent_details['upgrade_distro'], stream=True)
            else:
                self.cat.api.remote.get_remote_agent_core(distro=agent_details['distro'],
                                                          platform=agent_details['platform'], stream=True)
        except HTTPError:
            assert self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR, \
                'Expected 500, got {} instead'.format(self.cat.api.http_status_code)
            assert self.cat.api._text == '{"error":"core update not found for {}"}'.format(agent_details['distro'])
        else:
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead'.format(self.cat.api.http_status_code)

    # API_Tested# GET /remote/agent/jobs
    @pytest.mark.nessus_mat
    def test_get_agent_jobs(self):
        """
        STA-90: Implement test case for /remote/agent/jobs endpoints
        Scenarios Tested:
        [X] Get remote agent jobs:
        Note- For getting jobs, we need to create an agent scan and launch it.
        """
        with scan_with_fake_agent(api_handler=self.cat.api) as details:
            self.cat.api.scans.launch(details[0][0]['scan']['id'])
            wait_scan_state(api=self.cat.api, scan_id=details[0][0]['scan']['id'], end_state=API.Scan.Status.PENDING,
                            timeout=TIME_THIRTY_SECONDS)

            self.cat.api.add_header({"ms-agent": "token=" + details[1]["token"]})
            jobs = self.cat.api.remote.get_remote_agent_jobs()
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code
            assert jobs['jobs'], 'Jobs are not available for the agent'

            self.cat.api.remove_header("ms-agent")

            self.cat.api.scans.stop(scan_id=details[0][0]['scan']['id'])
            wait_scan_state(api=self.cat.api, scan_id=details[0][0]['scan']['id'], end_state=API.Scan.Status.ABORTED,
                            timeout=TIME_TEN_SECONDS)

    # API_Tested# PUT /remote/agent/jobs/{job_uuid}
    @pytest.mark.nessus_mat
    def test_configure_agent_jobs(self):
        """
        STA-90: Implement test case for /remote/agent/jobs endpoints
        Scenarios Tested:
        [X] Configure remote agent jobs: PUT /remote/agent/jobs/{job_uuid}

        Note- For getting jobs, we need to create an agent scan and launch it.
        """
        with scan_with_fake_agent(api_handler=self.cat.api) as details:
            self.cat.api.scans.launch(details[0][0]['scan']['id'])
            wait_scan_state(api=self.cat.api, scan_id=details[0][0]['scan']['id'], end_state=API.Scan.Status.PENDING,
                            timeout=TIME_THIRTY_SECONDS)

            self.cat.api.add_header({"ms-agent": "token=" + details[1]["token"]})
            jobs = self.cat.api.remote.get_remote_agent_jobs()
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

            self.cat.api.remote.configure_remote_agent_job(job_uuid=jobs['jobs'][0]['id'],
                                                           data={'status': API.Scan.Status.RUNNING})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

            self.cat.api.remove_header("ms-agent")

            self.cat.api.scans.stop(scan_id=details[0][0]['scan']['id'])
            wait_scan_state(api=self.cat.api, scan_id=details[0][0]['scan']['id'], end_state=API.Scan.Status.CANCELED,
                            timeout=TIME_TEN_SECONDS)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

    # API_Tested# GET /remote/agent/jobs/{job_uuid}/policy
    def test_get_job_policy(self):
        """
        STA-90: Implement test case for /remote/agent/jobs endpoints
        Scenarios Tested:
        [X] Get remote agent job policy:

        Note- For getting jobs, we need to create an agent scan and launch it.
        """
        with scan_with_fake_agent(api_handler=self.cat.api) as details:
            self.cat.api.scans.launch(details[0][0]['scan']['id'])
            wait_scan_state(api=self.cat.api, scan_id=details[0][0]['scan']['id'], end_state=API.Scan.Status.PENDING,
                            timeout=TIME_THIRTY_SECONDS)

            self.cat.api.add_header({"ms-agent": "token=" + details[1]["token"]})
            jobs = self.cat.api.remote.get_remote_agent_jobs()
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

            self.cat.api.remote.get_policy_for_agent_remote_job(job_uuid=jobs['jobs'][0]['id'])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

            self.cat.api.remove_header("ms-agent")

            self.cat.api.scans.stop(scan_id=details[0][0]['scan']['id'])
            wait_scan_state(api=self.cat.api, scan_id=details[0][0]['scan']['id'], end_state=API.Scan.Status.ABORTED,
                            timeout=TIME_TEN_SECONDS)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

    # API_Tested# POST /remote/agent/jobs/{job_uuid}/upload
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize('file', [
        {'filename': 'agent-db.db', "encrypted": True, "password": "c16fcd4e11c4caf60bc89670c322df03"}])
    def test_upload_jobs(self, file):
        """
        STA-90: Implement test case for /remote/agent/jobs endpoints
        Scenarios Tested:
        [X] Upload jobs file to remote agent:

        Note- For getting jobs, we need to create an agent scan and launch it.
        """
        with scan_with_fake_agent(api_handler=self.cat.api) as details:
            self.cat.api.scans.launch(details[0][0]['scan']['id'])
            wait_scan_state(api=self.cat.api, scan_id=details[0][0]['scan']['id'], end_state=API.Scan.Status.PENDING,
                            timeout=TIME_THIRTY_SECONDS)

            self.cat.api.add_header({"ms-agent": "token=" + details[1]["token"]})
            jobs = self.cat.api.remote.get_remote_agent_jobs()
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code
            assert all([jobs['jobs'], 'id' in jobs['jobs'][0]]), 'Jobs or job id are not available'

            self.cat.api.remote.configure_remote_agent_job(job_uuid=jobs['jobs'][0]['id'],
                                                           data={'status': API.Scan.Status.RUNNING})

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

            file_path = get_file_path('nessus/tests/api/scan/test_data/' + file['filename'])
            json_payload = {"compression": 2, "key": file['password'], "status": "completed"}

            # self.cat.api.add_header({"ms-agent": "token=" + details[1]["token"]})
            self.cat.api.remote.upload_agent_job(job_uuid=jobs['jobs'][0]['id'], file=file_path, payload=json_payload)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

            sleep(sleep_time=TIME_THIRTY_SECONDS * 2, reason='Wait for some time before next API call')

            # After uploading job, waiting for Nessus to be in ready state.
            wait_for_scanner_status(api=self.cat.api, status=API.Status.READY,
                                    timeout=TIME_FIVE_MINUTES, msg='plugins loading to start.')
            self.cat.api.login()

            try:
                if self.cat.api.scans.get_status(scan_id=details[0][0]['scan']['id']) not in [API.Scan.Status.COMPLETED,
                                                                                              API.Scan.Status.ABORTED,
                                                                                              API.Scan.Status.CANCELED,
                                                                                              API.Scan.Status.STOPPED]:
                    self.cat.api.scans.stop(scan_id=details[0][0]['scan']['id'])
                    wait_for_scan(api=self.cat.api, scan_id=details[0][0]['scan']['id'],
                                  status=API.Scan.Status.CANCELED)
            except:
                # In case scan gets completed in between, verifying if it has completed status.
                if self.cat.api.scans.get_status(scan_id=details[0][0]['scan']['id']) != API.Scan.Status.COMPLETED:
                    raise Exception("Error during stopping the scan.")

    # API Tested PUT remote/agent
    def test_edit_remote_agent(self, add_fake_agent):
        """
        STA-111: Implement Test case for remote agent endpoint - PUT remote/agent

        Scenarios Tested:
        [X] Successfully edit remote agent: PUT remote/agent
        """
        agent = add_fake_agent
        agent_id, agent_status = get_agent_id_from_list(api=self.cat.api, agent_name=agent['name'])

        # Add MS-Agent header to session headers
        self.cat.api.add_header({"ms-agent": "token=" + agent["token"]})

        payload = {"name": random_name(prefix='Edited {}'.format(agent["name"]))}
        self.cat.api.remote.edit_remote_agent(payload=payload)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        # Get the agent details and check that the edit had an effect
        agent_name = self.cat.api.agents.get_agent_details(agent_id=agent_id)
        assert agent_name['name'] == payload['name'], 'Unable to edit Agent name'

    # API Tested DELETE remote/agent
    @pytest.mark.parametrize("agent_config_settings", [{"payload": {"track_unlinked_agents": True}}], indirect=True)
    def test_deleted_agent_status_for_unlinked_enabled(self, add_fake_agent, agent_config_settings):
        """
        STA-111: Implement Test case for remote agent endpoint - DELETE remote/agent
        NES-8919: Fix agent API test

        Scenarios Tested:
        [x] Successfully delete remote agent
        [x] Verify Agent status is "unlinked",If Track Unlinked Agent is enabled
        """
        config_settings = self.cat.api.agents.get_config()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code
        assert agent_config_settings['track_unlinked_agents'] == config_settings[
            'track_unlinked_agents'], "Unable to retrieve agent config settings"

        agent_info = add_fake_agent
        # Add MS-Agent header to session headers
        self.cat.api.add_header({"ms-agent": "token=" + agent_info["token"]})
        self.cat.api.remote.delete_remote_agent()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        agent_id, agent_status = get_agent_id_from_list(api=self.cat.api, agent_name=agent_info['name'])
        assert agent_status == "unlinked", "Agent status is not expected as {}".format(agent_status)

    # API Tested DELETE remote/agent
    @pytest.mark.parametrize("agent_config_settings", [{"payload": {"track_unlinked_agents": False}}], indirect=True)
    def test_deleted_agent_status_for_unlinked_disabled(self, add_fake_agent, agent_config_settings):
        """
        NES-8919: Fix agent API test

        Scenarios Tested:
        [x] Successfully delete remote agent
        [x] Verify Agent status is "None",If Track Unlinked Agent is disabled
        """
        config_settings = self.cat.api.agents.get_config()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code
        assert agent_config_settings['track_unlinked_agents'] == config_settings[
            'track_unlinked_agents'], "Unable to retrieve agent config settings"

        agent_info = add_fake_agent
        # Add MS-Agent header to session headers
        self.cat.api.add_header({"ms-agent": "token=" + agent_info["token"]})
        self.cat.api.remote.delete_remote_agent()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code
        agent_id, agent_status = get_agent_id_from_list(api=self.cat.api, agent_name=agent_info['name'])
        assert agent_status is None, "Agent is not deleted successfully"

    # API_Tested# POST remote/agent/directive/{directive_id}
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize("test_data", [{"file_path": 'nessus/tests/api/scan/test_data/',
                                            "file_name": 'advanced_scan_gxxyl6.db'}])
    def test_remote_agent_directive_file_upload(self, add_fake_agent, test_data):
        """
        STA-111: Implement test case for remote agent endpoint - POST remote/agent/directive/{directive_id}

        Scenarios tested:
        [x] Successfully add remote agent
        [x] Successfully create logRequest directive of remote agent
        [x] Successfully upload a file to logRequest directive
        """
        agent_info = add_fake_agent

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        agent_id, agent_status = get_agent_id_from_list(self.cat.api, agent_name=agent_info['name'])
        self.cat.api.agents.create_log_request_directive(agent_id=agent_id, data={})

        session_token = self.cat.api._session_token
        directive_id = self.cat.api.agents.get_agent_details(agent_id)['logRequest']['id']
        file_path = get_file_path(test_data['file_path'] + test_data['file_name'])

        self.cat.api.add_header({"ms-agent": "token=" + agent_info['token']})
        response = self.cat.api.remote.remote_agent_directive_file_upload(directive_id, file_path,
                                                                          data={"token": session_token})
        assert response.status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % response.status_code

    # API Tested PUT /remote/agent/directive/{directive_id}
    @pytest.mark.nessus_mat
    @pytest.mark.parametrize("directive_status", ['aborted', 'canceling', 'canceled', 'completed', 'imported', 'paused',
                                                  'pausing', 'pending', 'processing', 'resuming', 'running', 'stopped',
                                                  'stopping', 'empty'])
    def test_change_remote_agent_directive_status(self, add_fake_agent, directive_status):
        """
        STA-111: Implement test case for remote agent endpoint - PUT /remote/agent/directive/{directive_id}

        Scenarios tested:
        [x] Successfully add remote agent
        [x] Successfully create logRequest directive of remote agent
        [x] Successfully change status of logs directive
        [x] Verify the modified status of directive
        """
        agent_info = add_fake_agent

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        agent_id, agent_status = get_agent_id_from_list(self.cat.api, agent_name=agent_info['name'])
        self.cat.api.agents.create_log_request_directive(agent_id=agent_id, data={})

        logrequest_directive_info = self.cat.api.agents.get_agent_details(agent_id)['logRequest']

        directive_id = logrequest_directive_info['id']
        directive_token = logrequest_directive_info['token']
        directive_message = logrequest_directive_info['message']

        directive_payload = {'token': directive_token, 'status': directive_status, 'message': directive_message}

        self.cat.api.add_header({"ms-agent": "token=" + agent_info['token']})
        response = self.cat.api.remote.edit_remote_agent_directive(directive_id, data=directive_payload)
        assert response.status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % response.status_code
        if directive_status == "completed":
            assert self.cat.api.agents.get_agent_details(agent_id)['logRequest'] is None, \
                "log request is not empty for the completed directive"
        else:
            assert self.cat.api.agents.get_agent_details(agent_id)['logRequest']['status'] == directive_status, \
                "current directive Status should be same as modified status"

    # API_Tested# GET /remote/agent/platforms/{platform_distro}/plugins/{target_feed_id}/diff/
    #                 {current_feed_id}/formats/{format}
    @pytest.mark.flaky_test
    def test_differential_update(self, add_fake_agent):
        """
        STA-93: Implement test case for /remote/agent/platforms/{platform_distro}/plugins/{target_feed_id}/diff/
                {current_feed_id}/formats/{format}
        Scenarios Tested:
        [X] Get differential updates for remote agent
        """
        agent_token = add_fake_agent["token"]

        os_platform, distro, _ = choose_agent_info()
        self.cat.api.add_header({"ms-agent": "token=" + agent_token})
        target_feed_id = self.cat.api.remote.get_remote_agent_updates(params={"platform": os_platform,
                                                                              "distro": distro})['plugin_feed_id']
        try:
            self.cat.api.remote.get_differential_updates(platform_distro=os_platform,
                                                         target_feed_id=target_feed_id,
                                                         current_feed_id="201810220259", formats="db.gz",
                                                         remote_agent_token=agent_token)

        except HTTPError:
            if self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST:
                assert eval(self.cat.api._text) == eval('{"error": "current_feed_id (201810220259) is later than '
                                                        'target_feed_id (%s)"}' % target_feed_id), \
                    "Message is missing or incorrect."
            elif self.cat.api.http_status_code == HTTPStatus.NOT_FOUND:
                assert eval(self.cat.api._text) == eval('{"error": "Plugin set %s was not found"}' % target_feed_id), \
                    "Message is missing or incorrect"
            elif self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
                assert eval(self.cat.api._text) == eval('{"error": "agent.db not found for %s"}' % os_platform), \
                    "Message is missing or incorrect"
            else:
                raise AssertionError("Error code is {}".format(self.cat.api.http_status_code))
        else:
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

    # API_Tested# POST remote/agent/settings
    @pytest.mark.nessus_mat
    def test_set_remote_agent_settings(self, add_fake_agent):
        """
        NES-12240 : [API] Verify Agent settings can be updated
        Scenario Tested:
            [x] Verify that remote agent settings can be set
        """
        agent_token = add_fake_agent["token"]
        self.cat.api.add_header({"ms-agent": "token=" + agent_token})

        payload = {"available": {"log_whole_attack": {"remote": True, "setting": "log_whole_attack",
                                                      "description": "setting description",
                                                      "id": str(uuid.uuid4()).replace('-',''), "type": "boolean",
                                                      "default": False, "categoryKey": "Logging",
                                                      "name": "Log Verbose Scan Details", "category": "Logging"},
                                 "log_details": {"remote": True, "setting": "log_details",
                                                 "description": "setting description",
                                                 "id": str(uuid.uuid4()).replace('-',''), "type": "boolean",
                                                 "default": False, "categoryKey": "Logging",
                                                 "name": "Log Additional Scan Details", "category": "Logging"},
                                 "backend_log_level": {"remote": True, "setting": "backend_log_level",
                                                       "description": "setting description",
                                                       "allowable_values": [{"value": "verbose"}, {"value": "debug"},
                                                                            {"value": "normal"}],
                                                       "id": str(uuid.uuid4()).replace('-',''), "type": "select",
                                                       "default": "normal",
                                                       "backend_reload": True, "categoryKey": "Logging",
                                                       "category": "Logging",
                                                       "name": "Nessus Log Level"}}, "current": {}}
        # Verify that remote agent settings can be set successfully.
        self.cat.api.remote.set_remote_agent_settings(payload=payload)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

    def test_agent_log_request_directive_in_get_remote_agent_jobs(self, add_fake_agent):
        """
        NES-12241 : [API] Verify Agent is given directive with GET /remote/agent/jobs

        Scenario Tested:
            [x] When Agent request logs from NM, GET /remote/agent/jobs from agent gets the directive in the response.
        """
        agent_info = add_fake_agent

        agent_id, agent_status = get_agent_id_from_list(self.cat.api, agent_name=agent_info['name'])
        self.cat.api.agents.create_log_request_directive(agent_id=agent_id, data={})

        self.cat.api.add_header({"ms-agent": "token=" + agent_info['token']})
        remote_agent_jobs = self.cat.api.remote.get_remote_agent_jobs()

        # Verify that GET /remote/agent/jobs from agent gets the directive for log request in the response.
        assert remote_agent_jobs['directive']['type'] == "log" and remote_agent_jobs['directive']['id'] is not None, \
            "Directive for log request is not present in GET remote/agent/jobs response"
