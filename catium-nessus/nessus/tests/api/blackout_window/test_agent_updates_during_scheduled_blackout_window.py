"""
Test cases for verifying agent updates when scheduled freeze window is active.

:copyright: Tenable Network Security, 2020
:date: Nov 05, 2020
:last_modified: Dec 07, 2020
:author: @vsoni, @kpanchal
"""
from http import HTTPStatus

import pytest

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS
from catium.lib.log.log import create_logger
from nessus.helpers.agents import choose_agent_info
from nessus.helpers.server import expect_http_error

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.skip_nessustc
@pytest.mark.usefixtures('nessus_api_login', 'delete_all_exclusions', 'agent_config_settings',
                         'create_scheduled_blackout_window_and_wait_till_activated', 'add_agent_locally')
@pytest.mark.parametrize('create_scheduled_blackout_window_and_wait_till_activated', [{'bw_duration_minutes': 10}],
                         indirect=True)
class TestAgentUpdatesInScheduledBW:
    """Tests for verifying agent updates when scheduled freeze window is active."""

    cat = None

    @pytest.mark.parametrize('agent_config_settings', [
        {'payload': {"bw_permanent_blackout_window": False, "bw_prevent_core_updates": True,
                     "bw_prevent_plugin_updates": False, "bw_prevent_agent_scans": False}}], indirect=True)
    @pytest.mark.parametrize('core_update', [True, False])
    def test_agent_updates_when_schedule_blackout_window_is_active(self, add_agent_locally, core_update):
        """
        NES-12244 : [API] Verify Agent plugin/core updates

        Scenario Tested:
            [x] Verify that core update is disabled during active freeze window
            [x] Verify agent update response during active freeze window
        """
        sleep(TIME_THIRTY_SECONDS, reason="Agents to get in sync and Scheduled freeze window to come into action")

        self.cat.api.add_header({'MS-Agent': "token={}".format(add_agent_locally["token"])})

        if core_update:
            # Verify that core update is disabled during active freeze window
            with expect_http_error(code=HTTPStatus.SERVICE_UNAVAILABLE,
                                   look_for="Core updates disabled due to an active freeze window"):
                self.cat.api.remote.get_remote_agent_core(distro="es8-x86-64",
                                                          platform="LINUX", sleep_time=10, ui_version="8.1.0",
                                                          stream=True)
        else:
            # Verify that 'blackout_window_core' and 'blackout_window_plugin' tags are not present
            # in agent update response when schedule freeze window is active.
            agent_updates = self.cat.api.remote.get_remote_agent_updates(params={"platform": "WINDOWS",
                                                                                 "distro": "win-x86-64"})
            assert not set.intersection({'blackout_window_core', 'blackout_window_plugins'}, set(agent_updates)), \
                "'blackout_window_core' and/or 'blackout_window_plugin' present in " \
                "agent updates during active freeze window."

        self.cat.api.remove_header(key='MS-Agent')

    @pytest.mark.parametrize('agent_config_settings', [
        {'payload': {"bw_permanent_blackout_window": False, "bw_prevent_core_updates": False,
                     "bw_prevent_plugin_updates": True, "bw_prevent_agent_scans": False}}], indirect=True)
    @pytest.mark.parametrize('diff_update', [True, False])
    def test_agent_plugin_updates_when_schedule_blackout_window_is_active(self, add_agent_locally, diff_update):
        """
        NES-12244 : [API] Verify Agent plugin/core updates

        Scenario Tested:
            [x] Verify that agent plugin diff update is disabled during active freeze window.
            [x] Verify that agent plugin update is disabled during active freeze window.
        """

        sleep(TIME_THIRTY_SECONDS, reason="Agents to get in sync and Scheduled freeze window to come into action")
        agent_token = add_agent_locally["token"]

        self.cat.api.add_header({'MS-Agent': "token={}".format(agent_token)})
        if diff_update:
            # Verify that agent plugin diff update is disabled during active freeze window.
            os_platform, distro, _ = choose_agent_info()
            target_feed_id = self.cat.api.remote.get_remote_agent_updates(params={"platform": os_platform,
                                                                                  "distro": distro})['plugin_feed_id']
            with expect_http_error(code=HTTPStatus.SERVICE_UNAVAILABLE,
                                   look_for="Plugin diff updates disabled due to an active freeze window"):
                self.cat.api.remote.get_differential_updates(platform_distro=os_platform,
                                                             target_feed_id=target_feed_id,
                                                             current_feed_id="201810220259", formats="db.gz",
                                                             remote_agent_token=agent_token, stream=True)
        else:
            # Verify that agent plugin update is disabled during active freeze window.
            with expect_http_error(code=HTTPStatus.SERVICE_UNAVAILABLE,
                                   look_for="Plugin updates disabled due to an active freeze window"):
                self.cat.api.remote.get_remote_agent_plugins(params={'platform': 'LINUX', 'distro': 'es8-x86-64',
                                                                     'sleep_time': 10, 'ui_version': '8.1.0'},
                                                             stream=True)
        self.cat.api.remove_header(key='MS-Agent')
