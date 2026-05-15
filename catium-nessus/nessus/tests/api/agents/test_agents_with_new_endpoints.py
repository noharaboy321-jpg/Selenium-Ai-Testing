"""
Test cases for Nessus Agents Endpoints

:copyright: Tenable Network Security, 2018
:date: August 9, 2018
:last_modified: Nov 02, 2020
:author: @ntarwani ,@dkothari, @jchavda, @kpanchal, @krpatel
"""
import json
from http import HTTPStatus

import pytest
from random import randint
from requests import HTTPError
from waiting import wait
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import load_testdata
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS
from catium.lib.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import choose_agent_info
from nessus.helpers.server import expect_http_error
from nessus.lib.const.constants import API
from nessus.lib.const.constants import Nessus


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentsEndpoints:
    """ Test Cases for Nessus Agents Endpoints """

    def __init__(self):
        self.cat = None

    # POST /agents/{agent_id}/download - log
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_create_download_logs(self, nessus_create_nessus_agent):
        """
        STA-115: Add test cases for Agents POST /agents/{agent_id}/download-log endpoint.

        Scenarios tested:
        [X] Create agent
        [x] Download logs
        """
        agent_id = nessus_create_nessus_agent[0]
        agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        assert agent_id == agent_details['id'], 'Agent detail is incorrect'

        token_log = self.cat.api.agents.download_logs(agent_id=agent_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        assert token_log, 'Token has not been generated'


    @pytest.mark.parametrize('nessus_create_nessus_agent', [[3, 'None']], indirect=True)
    def test_get_agents_list(self, nessus_create_nessus_agent):
        """
        #STA-8: Add endpoints to agents.py.
        Verifies that a list of agents can be retrieved

        Scenarios tested:
        [X] Get list of agents

        Note: Verify the data retrieved is expected (e.g. empty list, or null)
        """
        added_agent_ids = nessus_create_nessus_agent
        agents = self.cat.api.agents.agents_list()['agents']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        agent_ids = [agent['id'] for agent in agents]

        for added_agent in added_agent_ids:
            assert added_agent in agent_ids, 'Agent is not in the list of agents'

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_get_agent_details(self, nessus_create_nessus_agent):
        """
        #STA-8: Add endpoints to agents.py.
        Verifies that details for specific agent can be retrieved

        Scenarios tested:
        [X] Get details of an agent
        [ ] Get details for an agent that does not exist

        """
        agent_id = nessus_create_nessus_agent[0]
        agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        assert agent_id == agent_details['id'], 'Agent detail is incorrect'

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_delete_agent(self, nessus_create_nessus_agent):
        """
        #STA-8: Add endpoints to agents.py.
        Verifies that the specific agent can be deleted

        Scenarios tested:
        [X] An agent can be deleted
        [ ] Delete non-existent agent from list

        """
        agent_id = nessus_create_nessus_agent
        self.cat.api.agents.delete_agent(agent_id=agent_id[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        agents_list = self.cat.api.agents.agents_list()['agents']

        assert agents_list is None or agent_id not in [agent['id'] for agent in agents_list], \
            'Agent with id "%s" has not been deleted' % agent_id

    # NES-8900
    # API_Tested# GET /scanners/{scanner_id}/agents/{agent_id:int}
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_agent_details(self, nessus_create_nessus_agent):
        """
        NES-8900: Create tests for scanners GET /scanners/{scanner_id}/agents/{agent_id:int}

        Scenarios tested:
            [x] Successfully get agent details
        """
        agent_id = nessus_create_nessus_agent[0]
        agent_details = self.cat.api.scanners.agent_details(1, agent_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        assert agent_id == agent_details['id'], 'Agent detail is incorrect'

    # API_Tested DELETE /directives/{directive_id}
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_delete_directive(self, nessus_create_nessus_agent):
        """
        STA-110 - Implement test case for DELETE /directives/{directive_id} endpoint.

        Scenarios tested:
        [x] Successfully delete directive
        """
        agent_id = nessus_create_nessus_agent[0]

        self.cat.api.agents.create_log_request_directive(agent_id=agent_id, data={})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        directive_id = self.cat.api.agents.get_agent_details(agent_id)['logRequest']['id']
        self.cat.api.agents.delete_directive(directives_id=directive_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        log_request = self.cat.api.agents.get_agent_details(agent_id)['logRequest']

        assert log_request is None, 'Log request is still present.'

    @pytest.mark.parametrize('nessus_create_nessus_agent', [
        [1, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json'), 'full']], indirect=True)
    def test_agent_details_last_connect(self, nessus_create_nessus_agent):
        """
            Tests that getting the agent details updates the last_connect time, even if you
            do not get the /agents list first.

            Scenarios tested:
              [x] Test that getting /agents/:id updates last_connect appropriately.
        """

        agents = self.cat.api.agents.agents_list(
            filters='filter.0.quality=eq&filter.0.filter=groups&filter.0.value=three_agents_group')['agents']
        agent = nessus_create_nessus_agent[0]
        agent['last_connect'] = agents[0]['last_connect']

        # sleep for a second.
        sleep(1, reason="Waiting for time to go by so last_connect will change on the next faked GET /jobs.")

        agent_api = NessusAPI()
        agent_api.add_header({'ms-agent': 'token=' + agent['token']})
        agent_api.remote.get_remote_agent_jobs()

        # Now get *only* the agent detail page, and make sure the last_connect has updated.
        agent_after = self.cat.api.agents.get_agent_details(agent_id=agent['id'])

        assert agent_after['last_connect'] > agent['last_connect'], \
            'last_connect was not updated when getting the agent details page.'

    @pytest.mark.parametrize('nessus_create_nessus_agent', [
        [1, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json'), 'full']], indirect=True)
    def test_agent_list_last_connect(self, nessus_create_nessus_agent):
        """
            Tests that getting the agent list updates the last_connect time

            Scenarios tested:
              [x] Test that getting /agents updates last_connect appropriately.
        """

        agents = self.cat.api.agents.agents_list(
            filters='filter.0.quality=eq&filter.0.filter=groups&filter.0.value=three_agents_group')['agents']
        agent = nessus_create_nessus_agent[0]
        agent['last_connect'] = agents[0]['last_connect']

        # sleep for a second.
        sleep(1, reason="Waiting for time to go by so last_connect will change on the next faked GET /jobs.")

        agent_api = NessusAPI()
        agent_api.add_header({'ms-agent': 'token=' + agent['token']})
        agent_api.remote.get_remote_agent_jobs()

        # Now get *only* the agent detail page, and make sure the last_connect has updated.
        agent_after = self.cat.api.agents.agents_list(
            filters='filter.0.quality=eq&filter.0.filter=groups&filter.0.value=three_agents_group')['agents'][0]

        assert agent_after['last_connect'] > agent['last_connect'], \
            'last_connect was not updated when getting the agent details page.'

    # API_Tested# POST agents/export
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[
        3, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json')]], indirect=True)
    def test_verify_agents_list_export(self, nessus_create_nessus_agent):
        """
        NES-12160 : [API] Verify Agent list export

        Scenario Tested:
            [x] Verify that linked agent list can be exported in CSV format and all linked agents are present in file.
        """
        added_agent_ids = nessus_create_nessus_agent

        agents = self.cat.api.agents.agents_list()['agents']

        added_agent_names = [agent['name'] for agent in agents if agent['id'] in added_agent_ids]

        # Verify that linked agents are present in Nessus Manager
        assert set(added_agent_ids).issubset(set([agent['id'] for agent in agents])), \
            "Linked agents are not present in NM."

        export_agents = self.cat.api.agents.export_agents(export_format=API.Agents.ExportFormats.FORMAT_CSV)

        # Verify that Agents list exported successfully.
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        # Verify that token in present in export agents API response.
        assert export_agents['token'], "Token to download agent export file is not present in response."

        export_agents_token_id = export_agents['token']

        def wait_till_export_agents_token_ready():
            """Wait for the token to download agent list export file become ready"""
            try:
                return self.cat.api.tokens.status(token_id=export_agents_token_id)['status'] == 'ready'
            except HTTPError:
                return False

        # Verify that token status is ready for download
        try:
            wait(lambda: wait_till_export_agents_token_ready(), timeout_seconds=TIME_SIXTY_SECONDS)
        except TimeoutExpired:
            raise AssertionError("Export agents token is not ready for download within one minute of time.")

        file_contents = self.cat.api.tokens.download_file(token_id=export_agents_token_id).decode('utf-8')
        agents_list_from_file_contents = [agent_record.split(",")[0].strip('"') for agent_record in
                                          file_contents.split("\n")[1:-1]]

        # Verify that newly linked agent names are present in agent list export file.
        assert set(added_agent_names).issubset(agents_list_from_file_contents), \
            "Linked agents are not present in exported file for agents list."

    # API_Tested# POST /remote/agent
    @pytest.mark.parametrize("agent_uuid", [True, False])
    def test_agent_with_duplicate_or_no_uuid_throws_error(self, agent_uuid):
        """
        NES-12180: [Negative] Verify Agent with duplicate uuid throws 409

        Scenarios tested:
            [x] Verify Agent with duplicate or no uuid throws 409 error.
        """
        linking_key = self.cat.api.scanners.get_linking_key()['key']
        random_uuid = str(randint(10000000, 99999999)) + "-0000-0000-0000-" + str(randint(100000, 999999)) + str(
            randint(100000, 999999))
        uuid = random_uuid if agent_uuid else ""
        os_platform, distro, _ = choose_agent_info()

        agent_data = {"name": random_name(prefix="automation-"), "groups": ["All", None], "distro": distro,
                      "platform": os_platform, "key": linking_key, "uuid": uuid,
                      "ips": {"v4": ".".join(str(randint(0, 255)) for _ in range(4)), "v6": []}}

        if agent_uuid:
            self.cat.api.agents.add_agents(agent_info=agent_data)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

            updated_agent_data = {"name": random_name(prefix="automation-"),
                                  "ips": {"v4": ".".join(str(randint(0, 255)) for _ in range(4)), "v6": []}}
            agent_data.update(updated_agent_data)

        with pytest.raises(HTTPError):
            self.cat.api.agents.add_agents(agent_info=agent_data)

            assert self.cat.api.http_status_code == HTTPStatus.CONFLICT, \
                'Expected 409, got %s instead' % self.cat.api.http_status_code



@pytest.mark.nessus_mat
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentSettingsEndpoints:
    """ Test Cases for Nessus Agent settings Endpoints """

    cat = None

    def enable_disable_track_unlinked_agent_option(self, enable: bool = False) -> None:
        """
        Enables/Disables "Track unlinked agents" options

        :param bool enable: True if enable "Track unlinked agents" option else False
        :return: None
        """
        data = {"auto_delete": {"enabled": False}, "track_unlinked_agents": enable,
                "auto_unlink": {"enabled": False}}

        self.cat.api.agents.edit_config(data=data)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    def test_edit_and_verify_config_page(self):
        """
        #STA-8: Add endpoints to agents.py.
        Verifies that config details can be retrieved and edited

        Scenarios tested:
        [X] Get agent config details

        Note: Verify the data retrieved is expected (e.g. empty list, or null)
        """
        data = {"auto_unlink": {"expiration": 30, "enabled": False}, "track_unlinked_agents": True,
                "auto_delete": {"expiration": 30, "enabled": False}, "software_update": True}

        edit_config = self.cat.api.agents.edit_config(data=data)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        config_details = self.cat.api.agents.get_config()

        assert edit_config == config_details, 'Agent settings is not saved properly'

    # DELETE /agents/unlink
    @pytest.mark.usefixtures('nessus_api_login', 'agent_config_settings', 'nessus_create_nessus_agent')
    @pytest.mark.parametrize("agent_config_settings", [{"payload": {"track_unlinked_agents": True}}], indirect=True)
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_agent_unlink(self, nessus_create_nessus_agent):
        """
        STA-115: Add test cases for Agents - DELETE /agents/unlink endpoint.

        Scenarios tested:
        [X] Successfully unlink agent
        """
        agent_id = nessus_create_nessus_agent[0]

        self.cat.api.agents.create_log_request_directive(agent_id=agent_id, data={})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        self.cat.api.agents.agent_unlink(agent_id=agent_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)

        assert agent_details['status'] == 'unlinked', 'Agent has not been unlinked yet'

    # NES-8900
    # API_Tested# GET /scanners/{scanner_id}/agents/config
    def test_get_agent_settings(self, add_scanner_locally):
        """
        NES-8900: Create tests for scanners GET /scanners/{scanner_id}/agents/config

        Scenarios tested:
            [x] Successfully get the agent settings
        """
        scanner_id = add_scanner_locally['id']
        agent_settings = self.cat.api.scanners.get_agent_settings(scanner_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert agent_settings, "Agent setting was not returned."

    # NES-8900
    # API_Tested# PUT /scanners/{scanner_id}/agents/config
    def test_edit_agent_settings(self, add_scanner_locally):
        """
        NES-8900: Create tests for scanners PUT /scanners/{scanner_id}/agents/config

        Scenarios tested:
            [x] Successfully edit the agent settings
        """
        scanner_id = add_scanner_locally['id']
        orig_settings = self.cat.api.scanners.get_agent_settings(scanner_id)

        data = {"auto_unlink": {"expiration": 38, "enabled": False}, "track_unlinked_agents": True,
                "bw_permanent_blackout_window": True, "bw_prevent_core_updates": False}

        self.cat.api.scanners.edit_agent_settings(scanner_id, data)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        agent_settings = self.cat.api.scanners.get_agent_settings(scanner_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert all([agent_settings['track_unlinked_agents'] is True, agent_settings['auto_unlink']['expiration'] == 38,
                    agent_settings['auto_unlink']['enabled'] is False,
                    agent_settings['bw_permanent_blackout_window'] is True,
                    agent_settings['bw_prevent_core_updates'] is False]), "Agent config setting not edited successfully"

        self.cat.api.scanners.edit_agent_settings(scanner_id, orig_settings)
        agent_settings = self.cat.api.scanners.get_agent_settings(scanner_id)

        assert agent_settings['bw_permanent_blackout_window'] == orig_settings['bw_permanent_blackout_window'], \
            "Agent settings did not reset"

    @pytest.mark.parametrize('permanent_bw_settings', [
        {"bw_permanent_blackout_window": True, "bw_prevent_core_updates": True, "bw_prevent_plugin_updates": False,
         "bw_prevent_agent_scans": False},
        {"bw_permanent_blackout_window": True, "bw_prevent_core_updates": False, "bw_prevent_plugin_updates": True,
         "bw_prevent_agent_scans":False},
        {"bw_permanent_blackout_window": True, "bw_prevent_core_updates": False, "bw_prevent_plugin_updates": False,
         "bw_prevent_agent_scans": True},
        {"bw_permanent_blackout_window": True, "bw_prevent_core_updates": True, "bw_prevent_plugin_updates": True,
         "bw_prevent_agent_scans": True}])
    @pytest.mark.usefixtures('nessus_api_login', 'add_agent_locally')
    def test_verify_permanent_bw_combinations_for_agents(self, permanent_bw_settings, add_agent_locally):
        """
        NES-12163 : [API] Verify permanent blackout window combinations
        Scenario Tested:
            [x] Verify GET remote/agent/updates response when core updates are disabled. (permanent blackout window)
            [x] Verify GET remote/agent/updates response when plugin updates are disable. (permanent blackout window)
            [x] Verify GET remote/agent/job response when scans are disabled. (permanent blackout window)
            [x] Verify all two responses 1. GET remote/agent/updates 2. GET remote/agent/job
                when 'core updates', 'plugin updates' and 'scans' are disabled (permanent blackout window)
        """
        self.cat.api.agents.edit_config(permanent_bw_settings)
        try:
            agent_configs = self.cat.api.agents.get_config()

            # Verify that agent settings are set and reflected in Nessus.
            for setting_key in permanent_bw_settings.keys():
                assert agent_configs[setting_key] == permanent_bw_settings.get(setting_key), \
                    "Agent setting does not set for '{}' ".format(setting_key)

            self.cat.api.add_header({"ms-agent": "token=" + add_agent_locally["token"]})

            # Verify the GET /remote/agent/updates response (When core updates disabled in permanent blackout window)
            if permanent_bw_settings['bw_prevent_core_updates']:
                agent_updates = self.cat.api.remote.get_remote_agent_updates(params={"platform": "WINDOWS",
                                                                                     "distro": "win-x86-64"})
                assert agent_updates["blackout_window_core"], \
                    "GET /remote/agent/updates response does not have 'blackout_window_core' value set as True " \
                    "when core updates are disabled by permanent blackout window."

            # Verify the GET /remote/agent/job response (When scans are disabled in permanent blackout window)
            if permanent_bw_settings['bw_prevent_agent_scans']:
                agent_jobs = self.cat.api.remote.get_remote_agent_jobs()
                assert agent_jobs['blackout_window_scans'], \
                    "GET /remote/agent/job response does not have 'blackout_window_scans' value set as True " \
                    "when scan jobs are disabled by permanent blackout window."

            # Verify GET remote/agent/updates response (When plugin updates disabled in permanent blackout window)
            if permanent_bw_settings['bw_prevent_plugin_updates']:
                agent_updates = self.cat.api.remote.get_remote_agent_updates(params={"platform": "WINDOWS",
                                                                                     "distro": "win-x86-64"})
                assert agent_updates["blackout_window_plugins"], \
                    "GET /remote/agent/updates response does not have 'blackout_window_plugins' value set as True " \
                    "when plugin updates are disabled by permanent blackout window."
        finally:
            self.cat.api.remove_header(key='ms-agent')
            reset_permanent_bw = {"bw_permanent_blackout_window": False, "bw_prevent_core_updates": False,
                                  "bw_prevent_plugin_updates": False, "bw_prevent_agent_scans": False}
            self.cat.api.agents.edit_config(reset_permanent_bw)

    # API_Tested# PUT /agents/config
    @pytest.mark.parametrize('expiration_days', [-1, 0, 366])
    def test_remove_inactive_agents_days_not_allowed_less_than_1_and_greater_than_365_days(self, expiration_days):
        """
        NES-12167: [Negative] Verify "Remove agents that have been inactive for X days" doesn't allow int greater
                   than 365 or less than 1	

        Scenarios tested:
            [x] Verify "Remove agents that have been inactive for X days" doesn't allow int greater than 365 or less
                than 1 days
        """
        value_msg = None
        data = {"track_unlinked_agents": False, "auto_delete": {"enabled": True, "expiration": expiration_days},
                "auto_unlink": {"enabled": False}}

        with pytest.raises(HTTPError):
            self.cat.api.agents.edit_config(data=data)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        if expiration_days < 1:
            value_msg = "minimum value is: 1"
        elif expiration_days > 365:
            value_msg = "maximum value is: 365"

        expected_error_msg = "Invalid 'auto_delete' field: expiration(expiration) -> {}".format(value_msg)
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    # API_Tested# PUT /agents/config
    @pytest.mark.parametrize('expiration_days', [-1, 0, 29, 91, 365])
    def test_unlink_inactive_agents_days_not_allowed_less_than_30_and_greater_than_90_days(self, expiration_days):
        """
        NES-12168: [Negative] Verify "Unlink inactive agents after X days" doesn't allow int greater than 90 or less
                   than 30

        Scenarios tested:
            [x] Verify "Unlink inactive agents after X days" doesn't allow int greater than 90 or less than 30 days
        """
        value_msg = None
        data = {"track_unlinked_agents": True, "auto_delete": {"enabled": False},
                "auto_unlink": {"enabled": True, "expiration": expiration_days}}

        with pytest.raises(HTTPError):
            self.cat.api.agents.edit_config(data=data)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        if expiration_days < 30:
            value_msg = "minimum value is: 30"
        elif expiration_days > 90:
            value_msg = "maximum value is: 90"

        expected_error_msg = "Invalid 'auto_unlink' field: expiration(expiration) -> {}".format(value_msg)
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    # API_Tested# PUT /agents/config
    # API_Tested# DELETE /agents/unlink
    # API_Tested# DELETE /agents/{agent_id}/unlink
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None'], [5, 'None']], indirect=True)
    def test_unlink_single_and_multiple_agents_without_enabling_track_unlinked_agents_option(
            self, nessus_create_nessus_agent):
        """
        NES-12227: [API] [Negative] Agent unlinking

        Scenarios tested:
            [x] Verify trying to unlink Agent without "track unlinked agents" option enabled throws error
            [x] Verify trying to unlink multiple Agents at once without "track unlinked agents" option enabled throws
                error
        """
        linked_agent_ids = nessus_create_nessus_agent
        agent_config_details = self.cat.api.agents.get_config()

        if agent_config_details['track_unlinked_agents']:
            self.enable_disable_track_unlinked_agent_option()

        with pytest.raises(HTTPError):
            if len(linked_agent_ids) > 1:
                self.cat.api.agents.unlink_multiple_agents(agent_ids=linked_agent_ids)
            else:
                self.cat.api.agents.agent_unlink(agent_id=linked_agent_ids[0])

        assert self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR, \
            'Expected 500, got %s instead' % self.cat.api.http_status_code

        unlink_agents = "agent(s)" if len(linked_agent_ids) > 1 else "agent"
        expected_error_msg = "could not unlink {}, 'Track unlinked agents' disabled".format(unlink_agents)
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

        for agent_id in linked_agent_ids:
            agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)

            assert agent_details['status'] != Nessus.Agents.AgentStatus.UNLINKED.lower(), \
                'Agent has not been unlinked yet'

    # API_Tested# PUT /agents/config
    # API_Tested# DELETE /agents/unlink
    # API_Tested# DELETE /agents/{agent_id}/unlink
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None'], [5, 'None']], indirect=True)
    def test_unlink_single_and_multiple_agents_that_are_unlinked_already(self, nessus_create_nessus_agent):
        """
        NES-12227: [API] [Negative] Agent unlinking

        Scenarios tested:
            [x] Verify trying to unlink already unlinked agent throws error
            [x] Verify trying to unlink multiple Agents at once which are already unlinked does not throw error
        """
        agent_details = {}
        linked_agent_ids = nessus_create_nessus_agent
        agent_config_details = self.cat.api.agents.get_config()

        if not agent_config_details['track_unlinked_agents']:
            self.enable_disable_track_unlinked_agent_option(enable=True)

        if len(linked_agent_ids) > 1:
            self.cat.api.agents.unlink_multiple_agents(agent_ids=linked_agent_ids)
        else:
            self.cat.api.agents.agent_unlink(agent_id=linked_agent_ids[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        for agent_id in linked_agent_ids:
            agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)

            assert agent_details['status'] == Nessus.Agents.AgentStatus.UNLINKED.lower(), \
                'Agent has not been unlinked yet'

        if len(linked_agent_ids) > 1:
            self.cat.api.agents.unlink_multiple_agents(agent_ids=linked_agent_ids)
        else:
            with pytest.raises(HTTPError):
                self.cat.api.agents.agent_unlink(agent_id=linked_agent_ids[0])

        expected_response_code = HTTPStatus.OK if len(linked_agent_ids) > 1 else HTTPStatus.BAD_REQUEST

        assert self.cat.api.http_status_code == expected_response_code, \
            'Expected %s, got %s instead' % (expected_response_code, self.cat.api.http_status_code)

        if len(linked_agent_ids) == 1:
            expected_error_msg = "Agent {} already unlinked".format(agent_details['name'])
            error_msg_from_response = json.loads(self.cat.api.http_text)['error']

            assert error_msg_from_response == expected_error_msg, \
                "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

    # API_Tested# PUT /agents/config
    # API_Tested# DELETE /agents/unlink
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[5, 'None']], indirect=True)
    def test_unlink_multiple_agents_with_track_unlinked_agents_option_enabled(self, nessus_create_nessus_agent):
        """
        NES-12227: [API] [Negative] Agent unlinking

        Scenarios tested:
            [x] Verify trying to unlink multiple Agents at once with "Track unlinked agents" is enabled and are not
                unlinked, gives no error, and unlink all agents successfully.
        """
        linked_agent_ids = nessus_create_nessus_agent
        agent_config_details = self.cat.api.agents.get_config()

        if not agent_config_details['track_unlinked_agents']:
            self.enable_disable_track_unlinked_agent_option(enable=True)

        self.cat.api.agents.unlink_multiple_agents(agent_ids=linked_agent_ids)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        for agent_id in linked_agent_ids:
            agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)

            assert agent_details['status'] == Nessus.Agents.AgentStatus.UNLINKED.lower(), \
                'Agent has not been unlinked yet'
