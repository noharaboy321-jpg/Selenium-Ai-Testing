"""
Test cases for Agent's update channels Endpoints

:copyright: Tenable Network Security, 2022
:date: May 1, 2022
:last_modified: May 1, 2022
:author: @krpatel
"""
import time

import pytest
from waiting import wait

from catium.lib.const import TIME_SIXTY_SECONDS, WAIT_SHORT, HTTPStatus, TIME_TEN_MINUTES, TIME_FIVE_MINUTES
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.license import remove_nessus_registration
from nessus.helpers.nessuscli.helper import get_agent_version_from_feed_server, get_nessus_cli
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import Nessus
from nessus.lib.const.constants import API
from nessus.tests.ui.software_update import test_software_update

log = create_logger()


def payload(agent_channel: str) -> dict:
    return {
        "agent_updates_from_feed": True,
        "agent_update_channel": f"{agent_channel}"
    }


def reset_license_and_register_as_new():
    try:
        remove_nessus_registration()
    except:
        log.error(msg="Unable to reset the existing license")

    try:
        test_software_update.register_nessus_with_no_update(license_type='Nessus Manager')
        try:
            with SSH() as ssh:
                ssh.execute("{} update --plugins-only".format(get_nessus_cli()), timeout=TIME_FIVE_MINUTES)
            wait_for_scanner_to_be_ready(api=NessusAPI())
        except:
            log.error(msg="Unable to load the plugins successfully")
    except:
        log.error(msg="Unable to register the Nessus Manager")

@pytest.mark.nessus_mat
@pytest.mark.nessus_manager
@pytest.mark.incompatible
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentUpdateChannels:
    """ Test cases for Agent's update channels Endpoints"""

    """
    
    # API Tested GET /agents/update-channels
    # API Tested GET /info (feed server)
    # API Tested GET /agents/update-channels/latest
    # API Tested PUT /agents/update-channels
    
    """
    cat = None

    @pytest.mark.xray(test_key='NES-15766')
    @pytest.mark.xray(test_key='NES-15765')
    @pytest.mark.xray(test_key='NES-15764')
    @pytest.mark.parametrize('channel', [Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                         Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                         Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION])
    def test_correctness_of_agent_update_channel_versions(self, channel):
        """
        NES-15764 : Verify the version for 'General Availability' is same with feed server.
        NES-15765 : Verify the version for 'Early Access' is same with feed server.
        NES-15766 : Verify the version for 'Stable' is same with feed server.

        Scenario Tested:
        [x] Agent versions from feed server and manager should be same.
        """
        wait(lambda: self.cat.api.agents.get_latest_agent_update_channels_endpoint(),
             timeout_seconds=TIME_SIXTY_SECONDS, sleep_seconds=WAIT_SHORT,
             waiting_for='waiting for file gets downloaded and updated in downloaded list')

        latest_channel = self.cat.api.agents.get_latest_agent_update_channels_endpoint()
        log.info(f"latest Agent version is {latest_channel}")

        agent_channel_info = self.cat.api.agents.get_agent_update_channels_info_from_manager()
        agent_version = agent_channel_info["agent_channel_versions"][channel]["version"]
        log.info(f"Agent version in feed server for {channel} is {get_agent_version_from_feed_server(channel)}")
        log.info(f"Agent version in update-channels endpoint for {channel} is {agent_version}")
        assert agent_version == get_agent_version_from_feed_server(
            channel), f"Agent version is not matched for {channel}"

    @pytest.mark.xray(test_key='NES-15964')
    def test_default_api_value_for_agent_updates_from_feed(self):
        """
        NES-15964 : [API]: Verify "agent_updates_from_feed" is by default true for fresh NM.

        Scenario Tested:
        [x] Default API value for agent_updates_from_feed.
        """
        agent_channel_info = self.cat.api.agents.get_agent_update_channels_info_from_manager()
        agent_actual_value = agent_channel_info["agent_updates_from_feed"]

        assert agent_actual_value == Nessus.Agents.AgentsUpdates.DEFAULT_FEED_VALUE, \
            "Expected value for agent_updates_from_feed is {}, got {} instead.".format(
                Nessus.Agents.AgentsUpdates.DEFAULT_FEED_VALUE, agent_actual_value)

    @pytest.mark.xray(test_key='NES-15967')
    def test_default_value_for_channel_info_attribute(self):
        """
        NES-15967 : [API]: Verify "allowable value > default" attribute has "ga" value.

        Scenario Tested:
        [x] Default API value is set to GA.
        """
        agent_channel_info = self.cat.api.agents.get_agent_update_channels_info_from_manager()
        agent_actual_value = agent_channel_info["agent_update_channel_info"]["default"]

        assert agent_actual_value == Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION, \
            "Expected value for 'allowable value > default' is {}, got {} instead.".format(
                Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION, agent_actual_value)

    @pytest.mark.xray(test_key='NES-15968')
    @pytest.mark.parametrize('agent_channel', [Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION])
    @pytest.mark.incompatible
    def test_agent_channel_can_be_updated_via_api_endpoint(self, agent_channel):
        """
        NES-15968 : [API]: PUT request by changing "agent_update_channel" to ea/ga/stable can change the API data.

        Scenario Tested:
        [x] update the agent channel to ea from api and check the change.
        [x] update the agent channel to ga from api and check the change
        [x] update the agent channel to stable from api and check the change
        """
        agent_channel_payload = payload(f'{agent_channel}')
        self.cat.api.agents.put_agent_update_channels_from_manager(payload=agent_channel_payload)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected {}, got {} instead.'.format(HTTPStatus.OK, self.cat.api.http_status_code)
        agent_channel_info = self.cat.api.agents.get_agent_update_channels_info_from_manager()
        agent_actual_value = agent_channel_info["agent_update_channel"]
        assert agent_actual_value == agent_channel, \
            'Expected value for agent_update_channel is {}, got {} instead.'.format(agent_channel, agent_actual_value)

    @pytest.mark.xray(test_key='NES-15969')
    @pytest.mark.parametrize('agent_channel', [Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION])
    @pytest.mark.incompatible
    def test_default_agent_channel_after_updating_channel_via_api_endpoint(self, agent_channel):
        """
        NES-15969 : [API]: Verify "agent_update_channel_info > default" remains "ga" even after changing the agent update channel values.

        Scenario Tested:
        [x] update the agent channel to ea from api and check the default agent channel value should be ga.
        [x] update the agent channel to ga from api and check the default agent channel value should be ga.
        [x] update the agent channel to stable from api check the default agent channel value should be ga.
        """
        agent_channel_payload = payload(f'{agent_channel}')
        self.cat.api.agents.put_agent_update_channels_from_manager(payload=agent_channel_payload)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        agent_channel_info = self.cat.api.agents.get_agent_update_channels_info_from_manager()
        agent_actual_value = agent_channel_info["agent_update_channel_info"]["default"]
        assert agent_actual_value == Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION, \
            f"API value for default agent_update_channel is not remaining as GA when change to {agent_channel}"

    @pytest.mark.xray(test_key='NES-15972')
    def test_update_channel_latest_endpoint_gives_correct_value(self):
        """
        NES-15972 : [API]: Verify the api endpoint /agents/update-channels/latest gives correct value.

        Scenario Tested:
        [x] functioning of update-channels/latest endpoint.
        """
        last_check = self.cat.api.agents.get_agent_update_channels_info_from_manager()["agent_last_channel_check"]
        current_check = self.cat.api.agents.get_latest_agent_update_channels_endpoint()["agent_last_channel_check"]
        current_time = time.time()
        assert int(current_check) == int(current_time), "Channel check time is not updated."
        assert int(last_check) != int(current_check), "previous channel check and current channel check times are same!"

    @pytest.mark.xray(test_key='NES-15970')
    @pytest.mark.parametrize('bool_value', [False, True])
    def test_advance_setting_changes_reflected_on_agent_update_tab(self, bool_value):
        """
        NES-15970 : [API]: Verify advanced setting "agent_updates_from_feed" reflect on agent/update-channels API data.

        Scenario Tested:
        [x] advanced settings changes reflected on update-channels endpoint.
        """
        uncheck_channel_payload = {"setting.0.id": "4e58cfcdd3b9a3b8096cc3675fe9e548",
                                   "setting.0.name": "agent_updates_from_feed",
                                   "setting.0.value": f"{bool_value}", "setting.0.action": "edit"}
        self.cat.api.settings.update(uncheck_channel_payload)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected {}, got {} instead.'.format(HTTPStatus.OK, self.cat.api.http_status_code)
        actual_value = self.cat.api.agents.get_agent_update_channels_info_from_manager()["agent_updates_from_feed"]
        assert bool_value == actual_value, "Advanced setting changes are not reflected on update_channels api."

        self.cat.api.server.restart()
        wait_for_scanner_status(api=self.cat.api, timeout=TIME_TEN_MINUTES, status=API.Status.READY,
                                msg='Waiting for server to be in locked state after successful service restart.')

    @pytest.mark.xray(test_key='NES-15966')
    def test_default_value_of_agent_update_channel_attribute_in_api(self):
        """
        NES-15966 : [API]: Verify "agent_update_channel" attribute has "ga" value by default.

        Scenario Tested:
        [x] Default value of agent_update_channel after installing the NM.
        """
        reset_license_and_register_as_new()
        self.cat.api.login()
        agent_channel_info = self.cat.api.agents.get_agent_update_channels_info_from_manager()
        agent_actual_value = agent_channel_info["agent_update_channel"]

        assert agent_actual_value == Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION, \
            'Expected default value of agent_update_channel for fresh install NM is {}, got {} instead.'.format(
                Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION, agent_actual_value)
