"""
Test cases for Nessus Profiles.

:copyright: Tenable Network Security, 2024

"""
import json
from datetime import datetime, timedelta
from http import HTTPStatus
from random import randint, randrange

import dateutil
from waiting import wait

from catium.lib.ssh import SSH
from catium.lib.util import random_name

import pytest
from requests.exceptions import HTTPError

from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import choose_agent_info, get_agent_id_from_list
from nessus.helpers.nessuscli import fix
from catium.helpers.testdata import load_testdata
from nessus.helpers.nessuscli.helper import get_os_name, get_nessus_var_dir
from nessus.helpers.scan import start_stop_nessus_wait_for_ready

from nessus.helpers.waiters import wait_for_scanner_status
from catium.lib.const import TIME_FIVE_MINUTES, TIME_FIVE_SECONDS
from nessus.lib.const import API, SSHCommands, OperatingSystems

from catium.lib.log import create_logger
from nessus.tests.api.agents.test_remote_agents import check_for_package_download

log = create_logger()

@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentProfiles:
    """ Test Cases for Nessus Agent Profiles"""
    cat = None

    @pytest.mark.parametrize("create_profile_data", [
        pytest.param({
            "name": random_name(prefix='agent-profile-'),
            "description": "neg testing description",
            "config": None,
            "result_http_code": 400,
            "result_http_text": '{"error":"No profile config provided"}'
            }, id="neg_empty_config"),
        pytest.param({
            "name": random_name(prefix='agent-profile-'),
            "description": "neg testing description",
            "config": "just a string",
            "result_http_code": 400,
            "result_http_text": '{"error":"Provided profile config is of invalid type"}'
        }, id="neg_no_array_config"),
        pytest.param({
            "name": random_name(prefix='agent-profile-'),
            "description": "neg testing description",
            "config": {"test":"1"},
            "result_http_code": 400,
            "result_http_text": '{"error":"Unsupported profile configuration type: test"}'
            }, id="neg_no_version_config"),
        pytest.param({
            "name": random_name(prefix='agent-profile-'),
            "description": "neg testing description",
            "config": {"version":"10","test":"2"},
            "result_http_code": 400,
            "result_http_text": '{"error":"Unsupported profile configuration type: test"}'
            }, id="neg_more_than_version_config"),
        pytest.param({
            "name": random_name(prefix='agent-profile-'),
            "description": "neg testing, no verison in feed",
            "config": {"version":"1000"},
            "result_http_code": 400,
            "result_http_text": '{"error":"The provided version is not supported"}'
            }, id="neg_no_feed_version_config"),
        pytest.param({
            "name": random_name(prefix='agent-profile-'),
            "description": "testing description",
            "config": {},
            "result_http_code": 200,
            "result_http_text": ''
            }, id="empty_version")
        ])
    def test_create_agent_profile(self, create_profile_data):
        """
        Neg testing creating profile,
        Empty profile is allowed

        # API_Tested# GET /profiles/
        # API_Tested# POST /profiles/
        # API_Tested# DELETE /profiles/

        Scenarios tested:
        [X] Get agent profile
        [X] Create agent profile
        [X] Delete agent profile
        """
        try:
            profile = self.cat.api.profiles.create(name=create_profile_data["name"],
                                           description=create_profile_data["description"],
                                           config=create_profile_data["config"])
        except HTTPError:
            pass

        assert self.cat.api.http_status_code == create_profile_data["result_http_code"], \
            'Expected %s, got %s instead.' % (create_profile_data["result_http_code"], self.cat.api.http_status_code)

        if self.cat.api.http_status_code == HTTPStatus.OK:
            profile1 = self.cat.api.profiles.get_profile(profile['profile_uuid'])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert profile1['profile_uuid'] == profile['profile_uuid']

            created_uuids = [profile['profile_uuid']]

            try:
                self.cat.api.profiles.delete_profiles(uuid_list=created_uuids)
            except Exception:
                log.warning("Unable to delete profile in clean up. profile may have been deleted by test.")
        else:
            assert self.cat.api.http_text == create_profile_data["result_http_text"], \
                'Expected %s, got %s instead.' % (create_profile_data["result_http_text"], self.cat.api.http_text)

    @pytest.mark.parametrize('nessus_create_nessus_agent', [
        [1, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json'), 'full']], indirect=True)
    def test_create_agent_profile_with_version_in_feed(self, nessus_create_nessus_agent):
        """
        Pos testing creating profile

        # API_Tested# GET /profiles/
        # API_Tested# POST /profiles/
        # API_Tested# DELETE /profiles/
        # API_Tested# GET /remote/agent/config/{config_id)

        Scenarios tested:
        [X] Get agent profile
        [X] Create agent profile
        [X] Delete agent profile
        """
        versions = self.cat.api.settings.agent_versions()
        for key in versions["versions_in_feed"]:
            isEol = False
            version = versions["versions_in_feed"][key]
            if "eol" in version:
                eol = dateutil.parser.isoparse(version["eol"])
                if eol < datetime.now():
                    isEol = True
            if "release_date" in version:
                eol_date = dateutil.parser.isoparse(version["release_date"])
                eol_date = eol_date.replace(year=eol_date.year+2)
                if eol_date < datetime.now():
                    isEol = True
            try:
                profile = self.cat.api.profiles.create(name=random_name(prefix='agent-profile-'),
                                           description="testing version in feed",
                                           config={"version": key})

                agent = nessus_create_nessus_agent[0]

                agent_api = NessusAPI()
                agent_api.add_header({'ms-agent': 'token=' + agent['token']})
                profile_config = agent_api.remote.get_remote_agent_config(profile['config_id'])

                if profile_config:
                    assert profile_config['eol'], 'Expected %s, got %s instead.' % \
                                                  (eol_date, profile_config['eol'])

                    assert profile_config['release_date'], 'Expected %s, got %s instead.' % \
                                                           (version["release_date"], profile_config['release_date'])

                    assert profile_config['version'], 'Expected %s, got %s instead.' % \
                                                      (version, profile_config['version'])

            except HTTPError:
                pass

            if isEol:
                assert self.cat.api.http_status_code == 400, \
                    'Expected 400, got %s instead.' % self.cat.api.http_status_code
                assert self.cat.api.http_text == '{"error":"The provided version has reached end of life"}'
            else:
                assert self.cat.api.http_status_code == 200, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code
                created_uuids = [profile['profile_uuid']]
                try:
                    self.cat.api.profiles.delete_profiles(uuid_list=created_uuids)
                except Exception:
                    log.warning("Unable to delete profile in clean up. profile may have been deleted by test.")

    @pytest.mark.parametrize("version_digits", [
        pytest.param(1, id="1_digit_version"),
        pytest.param(2, id="2_digit_version"),
        pytest.param(3, id="3_digit_version")])
    def test_list_profile(self, create_valid_profile_endpoint):
        """
        Verifies get profile list

        Scenarios tested:
        [X] Create agent profile
        [X] Get agent profiles
        """
        profile = create_valid_profile_endpoint
        profiles = self.cat.api.profiles.profile_list()

        list = [item for item in profiles['profiles']]
        assert profile['profile_uuid'] in list, \
            'Agent Profile is not created successfully.'

    @pytest.mark.parametrize("version_digits", [
            pytest.param(3, id="3_digit_version")])
    def test_update_profile(self, create_valid_profile_endpoint):
        """
        Verifies update an agent profile
        # API_Tested# PUT /profiles/
        # API_Tested# GET /profiles/{profile_uuid}

        Scenarios tested:
        [X] Create agent profile
        [X] Update agent profile
        """
        profile = create_valid_profile_endpoint
        profile_uuid = profile['profile_uuid']
        name = "updated " + profile['name']
        description = "updated " + profile['description']
        version = profile['config']['version']
        version = version[: version.find('.')]
        config = {"version": version}
        self.cat.api.profiles.update_profile(profile_uuid,
            payload={ "name": name,
                    "description": description,
                    "config": config})

        assert self.cat.api.http_status_code == 200, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        profile1 = self.cat.api.profiles.get_profile(profile_uuid)
        assert profile1["name"] == name
        assert profile1["description"] == description
        assert profile1["config"]["version"] == version

    @pytest.mark.parametrize("version_digits", [
            pytest.param(3, id="3_digit_version")])
    @pytest.mark.parametrize('nessus_create_nessus_agent',
                             [[3, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json')]],
                             indirect=True)
    def test_single_agent_profile_membership(self, create_valid_profile_endpoint, nessus_create_nessus_agent):
        """
            Verifies add/remove single agent to/from a profile

            # API_Tested# PUT /profiles/{profile_uuid}/agents/{agent_id}
            # API_Tested# DELETE /profiles/{profile_uuid}/agents/{agent_id}
        """
        agent_ids = nessus_create_nessus_agent
        profile = create_valid_profile_endpoint
        profile_uuid = profile['profile_uuid']
        try:
            self.cat.api.profiles.change_agent_profile(profile_uuid, 'test')
        except HTTPError:
            pass
        assert self.cat.api.http_status_code == 400, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        self.cat.api.profiles.change_agent_profile(profile_uuid, str(agent_ids[0]))
        assert self.cat.api.http_status_code == 200

        agent = self.cat.api.agents.get_agent_details(agent_ids[0])
        assert agent["profile_uuid"] == profile_uuid

        self.cat.api.profiles.remove_agent_profile(profile_uuid, str(agent_ids[0]))
        assert self.cat.api.http_status_code == 200

        agent = self.cat.api.agents.get_agent_details(agent_ids[0])
        assert agent["profile_uuid"] == None

        try:
            self.cat.api.profiles.remove_agent_profile('test', str(agent_ids[0]))
        except HTTPError:
            pass
        assert self.cat.api.http_status_code == 200, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        try:
            self.cat.api.profiles.remove_agent_profile(profile_uuid, 'test')
        except HTTPError:
            pass
        assert self.cat.api.http_status_code == 400, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        try:
            self.cat.api.profiles.remove_agent_profile(profile_uuid, "82342344")
        except HTTPError:
            pass
        assert self.cat.api.http_status_code == 200, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.parametrize("version_digits", [
            pytest.param(3, id="3_digit_version")])
    @pytest.mark.parametrize('nessus_create_nessus_agent',
                             [[5, 'None']],
                             indirect=True)
    def test_agent_profile_membership(self, create_valid_profile_endpoint, nessus_create_nessus_agent):
        """
        Verifies add/remove bulk agents to/from a profile

        Scenarios tested:
            # API_Tested# PUT /profiles/{profile_uuid}/agents
            # API_Tested# DELETE /profiles/{profile_uuid}/agents
            # API_Tested# GET /profiles/{profile_uuid}/agents
            # API_Tested# DELETE /profiles/agents
        """

        agent_ids = nessus_create_nessus_agent
        profile = create_valid_profile_endpoint
        profile_uuid = profile['profile_uuid']

        # test by passing agent_ids
        # add agents to profile
        self.cat.api.profiles.add_profile_members(profile_uuid, None, agent_ids)
        assert self.cat.api.http_status_code == 200, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        agent = self.cat.api.agents.get_agent_details(agent_ids[0])
        assert agent["profile_uuid"] == profile_uuid

        # get profile agents
        agents = self.cat.api.profiles.get_profile_members(profile_uuid)
        assert self.cat.api.http_status_code == 200, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        profile_agent_ids = [item['id'] for item in agents['agents']]
        for agent_id in agent_ids:
            assert agent_id in profile_agent_ids

        # remote agents from profile
        self.cat.api.profiles.remove_profile_members(profile_uuid, None, agent_ids)
        assert self.cat.api.http_status_code == 200, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # get profile agents
        agents = self.cat.api.profiles.get_profile_members(profile_uuid)
        profile_agent_ids = [item['id'] for item in agents['agents']]
        for agent_id in agent_ids:
            assert agent_id not in profile_agent_ids

        # test by passing filters
        # add agents to profile
        filters = f'filter.0.quality=match&filter.0.filter=name&filter.0.value={agent["name"]}'
        self.cat.api.profiles.add_profile_members(profile_uuid, filters, None)
        assert self.cat.api.http_status_code == 200, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        agent = self.cat.api.agents.get_agent_details(agent['id'])
        assert agent["profile_uuid"] == profile_uuid

        # bulk remove agent profiles
        self.cat.api.profiles.add_profile_members(profile_uuid, None, agent_ids)
        self.cat.api.profiles.bulk_remove_profile_members(None, agent_ids)
        assert self.cat.api.http_status_code == 200, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        agents = self.cat.api.profiles.get_profile_members(profile_uuid)
        assert len(agents['agents']) == 0

    def test_create_agent_profile_with_eol_version(self):
        """
            Neg testing creating profile with eol version
            # To test the eol version, we need get the agent_versions_in_feed from pref and change one of the version
            # to older than two years, wait for nessus restart and then try to create a profile with that version.
        """

        feed_versions_str = fix.get_value("agent_versions_in_feed", True)
        feed_versions = json.loads(feed_versions_str)
        test_eol_version1 = ""
        test_eol_version2 = ""
        for key in feed_versions:
            if key.count('.') != 2:
                continue
            if test_eol_version1 == "":
                test_eol_version1 = key
                continue
            if test_eol_version2 == "":
                test_eol_version2 = key
                break

        expired_date = datetime.now()
        expired_date = expired_date.replace(year=expired_date.year - 2) - timedelta(days=2)
        #        feed_versions[test_version]["release_date"] = "2020-11-08T22:03:34.347948"
        expired_date = expired_date.strftime("%Y-%m-%dT%H:%M:%S.%f")
        feed_versions[test_eol_version1]["release_date"] = expired_date

        eol_date = datetime.now()
        eol_date = eol_date - timedelta(days=2)
        eol_date = eol_date.strftime("%Y-%m-%dT%H:%M:%S.%f")
        feed_versions[test_eol_version2]["eol"] = eol_date

        test_feed_versions_str = "'" + json.dumps(feed_versions) + "'"

        fix.set("agent_versions_in_feed", test_feed_versions_str, True)

        # Waiting till Nessus server status is ready.
        try:
            wait_for_scanner_status(api=self.cat.api, timeout=TIME_FIVE_MINUTES, status=API.Status.LOADING,
                                    msg='Waiting for server to finish loading.')
        finally:
            wait_for_scanner_status(api=self.cat.api, timeout=TIME_FIVE_MINUTES, status=API.Status.READY,
                                    msg='Waiting for server to finish loading.')

        try:
            profile = self.cat.api.profiles.create(name=random_name(prefix='agent-profile-'),
                                                   description="testing version in feed",
                                                   config={"version": test_eol_version1})
        except HTTPError:
            pass

        assert self.cat.api.http_status_code == 400, \
                'Expected 400, got %s instead.' % self.cat.api.http_status_code
        assert self.cat.api.http_text == '{"error":"The provided version has reached end of life"}'

        try:
            profile = self.cat.api.profiles.create(name=random_name(prefix='agent-profile-'),
                                                   description="testing version in feed",
                                                   config={"version": test_eol_version2})
        except HTTPError:
            pass

        assert self.cat.api.http_status_code == 400, \
                'Expected 400, got %s instead.' % self.cat.api.http_status_code
        assert self.cat.api.http_text == '{"error":"The provided version has reached end of life"}'

        fix.set("agent_versions_in_feed", feed_versions_str, True)


    # API_Tested# POST /remote/agent
    @pytest.mark.nessus_mat
    @pytest.mark.incompatible
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    def test_add_and_link_remote_agent_with_agent_profile(self, create_valid_profile_endpoint):
        """
        Implement test case for /remote/agent
        Scenarios Tested:
        [X] Adding and linking an agent assigned to a profile in Nessus Manager:
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
        profile = create_valid_profile_endpoint
        profile_uuid = profile['profile_uuid']

        data = {"name": random_name(prefix="automation-"), "groups": ["All", None], "distro": distro,
                "platform": os_platform, "key": linking_key, "uuid": uuid, "ips": {"v4": ipv4, "v6": None},
                "profile_uuid": profile_uuid}

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

        agent_id, agent_status = get_agent_id_from_list(api=self.cat.api, agent_name=data['name'])
        agent = self.cat.api.agents.get_agent_details(agent_id)
        assert agent['profile_uuid'] == profile_uuid, \
            'Expected agent profile uuid to be %s, got %s' % (profile_uuid, agent['profile_uuid'])
        self.cat.api.agents.delete_agent(agent_id=agent_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead'.format(self.cat.api.http_status_code)

    @pytest.mark.xray(test_key='NES-18075')
    @pytest.mark.xray(test_key='NES-18077')
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[2, 'None']], indirect=True)
    def test_agent_core_with_profile_version(self, create_valid_profile_with_agents):
        # Trigger and wait for NM to download the core package
        profile = create_valid_profile_with_agents
        agents_list = self.cat.api.profiles.get_profile_members(profile["profile_uuid"])
        agent = self.cat.api.agents.get_agent_details(agent_id=agents_list['agents'][0]['id'])

        start_stop_nessus_wait_for_ready(nessus_api=self.cat.api, status=API.Status.READY)
        self.cat.api.login()

        wait(lambda: check_for_package_download(nessus_api=self.cat.api, distro=agent['distro'],
                                                platform=agent['platform'], stream=True),
             timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=TIME_FIVE_SECONDS,
             waiting_for='Nessus to download core updates')

        self.cat.api.remote.get_remote_agent_core(distro=agent['distro'],
                                                  platform=agent['platform'],
                                                  version=profile["config"]["version"], stream=True)

        for agent in agents_list['agents']:
            self.cat.api.add_header({"ms-agent": "token=" + agent['token']})
            remote_agent_jobs = self.cat.api.remote.get_remote_agent_jobs()

            # Verify that GET /remote/agent/jobs from agent gets the profile assignment in the response.
            assert remote_agent_jobs['profile']['assigned'] is not None, \
                "Profile assignment is not present in GET remote/agent/jobs response"

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

