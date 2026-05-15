"""
Blackout window related tests (When agent is linked to Nessus Manager via cluster node)

:copyright: Tenable Network Security, 2019
:date: Aug 14, 2020
:last_modified: Dec 14, 2020
:author: @vsoni, @kpanchal
"""
import subprocess
from contextlib import contextmanager

import pytest
from waiting import wait

from catium.lib.const.base_constants import TIME_THIRTY_SECONDS, TIME_TEN_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessus_agent import get_latest_log_file_entries
from nessus.lib.const.constants import Nessus, NessusAgentFilePath
from nessus.lib.message.messages import Messages
from nessus.pageobjects.agents.agent_blackout_windows_page import AgentBlackoutWindowsPage, AgentBlackoutWindowList
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.tests.ui.agents.test_agent_blackout_window import \
    create_agent_scan_and_verify_scan_behavior_for_created_blackout_window

log = create_logger()
PLUGINS_BLOCKED_BW = "Plugin updates disabled due to an active permanent blackout window"
CORE_UPDATES_BLOCKED_BW = "Core updates disabled due to an active permanent blackout window"


@contextmanager
def create_agent_group_and_add_cluster_agent(cluster_agent: dict) -> tuple:
    """
    This context manager creates agent group and add cluster agent in the group.
    :param dict cluster_agent: Linked cluster agent
    :return: agent group name and agent ip
    :rtype: tuple
    """
    api = NessusAPI()
    api.login()

    subprocess.check_output("docker exec {} supervisorctl restart nessusd".format(
        api.agents.get_agent_details(cluster_agent['id'])['node_name']).split(), stderr=subprocess.PIPE).decode('utf-8')
    # Wait till agent become online
    wait(lambda: api.agents.get_agent_details(cluster_agent['id'])['status'] == 'online',
         timeout_seconds=TIME_TEN_MINUTES * 2, sleep_seconds=TIME_THIRTY_SECONDS,
         waiting_for='Cluster agent to get online status!!')

    agent_group_name = random_name(prefix="agent-group")
    agent_group = api.agent_groups.create(scanner_id=1, name=agent_group_name)
    try:
        api.agent_groups.add_agent(scanner_id=1, group_id=agent_group['id'], agent_id=cluster_agent['id'])
        yield agent_group_name, cluster_agent['ip']
    finally:
        api.agent_groups.delete(scanner_id=1, group_id=agent_group['id'])
        api.logout()


@pytest.mark.cluster_manager
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 1}], indirect=True)
@pytest.mark.usefixtures('create_manager_cluster')
class TestBlackoutWindowForClusterAgent:
    """Blackout window related tests (When agent is linked to Nessus Manager via cluster node)"""

    @pytest.mark.parametrize('configure_agent_settings_options',
                             [{'setting_options_list': [
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_SCAN, 'setting_action': 'enable'},
                                 {'setting_name': Nessus.Agents.Settings.PERMANENT_BLACKOUT_WINDOW,
                                  'setting_action': 'enable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_CORE_UPDATES,
                                  'setting_action': 'disable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_PLUGIN_UPDATES,
                                  'setting_action': 'disable'}]}],
                             indirect=True)
    @pytest.mark.usefixtures('login', 'configure_agent_settings_options')
    def test_cluster_agent_scan_in_permanent_blackout_window(self, create_manager_cluster):
        """
        NES-11118 : Create automation testing specific to cluster env using blackout windows
        Scenario Tested:
            [x] Verify that cluster agent scan disabled when permanent blackout window is enabled.
        Steps:
        1. Enable cluster in Nessus manager , link one node and one agent to cluster manager.
        2. Enable option for "permanent blackout window" from agent settings.
        3. Enable "Prevent agent scan" option from agent settings.
        4. Wait till agent become online and add the cluster agent to agent group.
        5. Create a agent scan and launch it.
        6. Verify that scan is disabled due to active blackout window in agent backend.log.
        7. Disable Permanent blackout window
        8. Verify scan gets launched and completed successfully once the blackout window is inactive.
        """
        cluster_agent = create_manager_cluster['agents'][0]

        assert create_manager_cluster['agents'][0]['node_id'] is not None, \
            "Agent is not linked to Manager via cluster node."

        with create_agent_group_and_add_cluster_agent(cluster_agent=cluster_agent) as agent_details:
            HeaderBasePage().scan_link.click()
            create_agent_scan_and_verify_scan_behavior_for_created_blackout_window(
                bw_type="permanent", agent_group=agent_details[0], agent_ip=agent_details[1])

    @pytest.mark.parametrize('configure_agent_settings_options',
                             [{'setting_options_list': [
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_SCAN, 'setting_action': 'enable'},
                                 {'setting_name': Nessus.Agents.Settings.PERMANENT_BLACKOUT_WINDOW,
                                  'setting_action': 'disable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_CORE_UPDATES,
                                  'setting_action': 'disable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_PLUGIN_UPDATES,
                                  'setting_action': 'disable'}]}],
                             indirect=True)
    @pytest.mark.parametrize('create_new_blackout_window_and_wait_till_activation', [{'is_time_set': True,
                                                                                      'bw_duration': 15}],
                             indirect=True)
    @pytest.mark.usefixtures('login', 'configure_agent_settings_options',
                             'create_new_blackout_window_and_wait_till_activation')
    def test_cluster_agent_scan_in_scheduled_blackout_window(self, create_new_blackout_window_and_wait_till_activation,
                                                             create_manager_cluster):
        """
        NES-11118 : Create automation testing specific to cluster env using blackout windows
        Scenario Tested:
            [x] Verify that cluster agent scan disabled when scheduled blackout window is active.
        Steps:
        1. Enable cluster in Nessus manager , link one node and one agent to cluster manager.
        2. Create a blackout window and wait till it gets activated.
        3. Enable "Prevent agent scan" option from agent settings.
        4. Wait till agent become online and add the cluster agent to agent group.
        5. Create a agent scan and launch it.
        6. Verify that scan is disabled due to active blackout window in agent backend.log.
        7. Wait till blackout window gets disabled.
        8. Verify scan gets launched and completed successfully once the blackout window is inactive
        """

        # Checking if blackout window is created successfully and populated in blackout windows list
        AgentBlackoutWindowsPage().open()
        blackout_window_name = create_new_blackout_window_and_wait_till_activation
        bw_list = AgentBlackoutWindowList()

        assert blackout_window_name in bw_list.blackout_window_all_names, \
            "Scheduled Blackout window was not created successfully"

        cluster_agent = create_manager_cluster['agents'][0]

        assert create_manager_cluster['agents'][0]['node_id'] is not None, \
            "Agent is not linked to Manager via cluster node."

        with create_agent_group_and_add_cluster_agent(cluster_agent=cluster_agent) as agent_details:
            HeaderBasePage().scan_link.click()
            create_agent_scan_and_verify_scan_behavior_for_created_blackout_window(
                bw_type="scheduled", agent_group=agent_details[0],
                agent_ip=agent_details[1], bw_name=blackout_window_name)

    @pytest.mark.parametrize('configure_agent_settings_options',
                             [{'setting_options_list': [
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_SCAN, 'setting_action': 'disable'},
                                 {'setting_name': Nessus.Agents.Settings.PERMANENT_BLACKOUT_WINDOW,
                                  'setting_action': 'enable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_CORE_UPDATES,
                                  'setting_action': 'enable'},
                                 {'setting_name': Nessus.Agents.Settings.PREVENT_PLUGIN_UPDATES,
                                  'setting_action': 'enable'}]}],
                             indirect=True)
    @pytest.mark.usefixtures('login', 'configure_agent_settings_options')
    def test_plugin_and_core_updates_blocked_during_permanent_blackout_window(self, create_manager_cluster):
        """
        NES-11118 : Create automation testing specific to cluster env using blackout windows
        Scenario Tested:
            [x] Verify that core updates and plugin updates for cluster agent gets disabled during blackout window.
        Steps:
        1. Enable cluster in Nessus manager , link one node and one agent to cluster manager.
        2. Enable permanent blackout window
        3. Enable "Prevent software update", and "Prevent Plugin updates" options from agent settings.
        4. Verify nessus agent's backend.log that core updates and plugin updates disabled due to blackout window.
        """
        assert create_manager_cluster['agents'][0]['node_id'] is not None, \
            "Agent is not linked to Manager via cluster node."

        api = NessusAPI()
        api.login()

        try:
            agent_ip = create_manager_cluster['agents'][0]['ip']
        finally:
            api.logout()

        assert wait(lambda: [True for log_line in get_latest_log_file_entries(
            agent_ip=agent_ip, no_of_entries=50, file=NessusAgentFilePath.NESSUS_AGENT_BACKEND_LOGS) if any(
            [log_message in log_line for log_message in [Messages.NessusAgent.PLUGINS_BLOCKED,
                                                         PLUGINS_BLOCKED_BW]])]), \
            "Plugin updates blocked message is missing in Nessus agent's backend.log ."

        assert wait(lambda: [True for log_line in get_latest_log_file_entries(
            agent_ip=agent_ip, no_of_entries=50, file=NessusAgentFilePath.NESSUS_AGENT_BACKEND_LOGS) if any(
            [log_message in log_line for log_message in [
                Messages.NessusAgent.CORE_UPDATES_BLOCKED, CORE_UPDATES_BLOCKED_BW]])]), \
            "Core updates blocked message is missing in Nessus agent's backend.log ."

        backend_logs = get_latest_log_file_entries(agent_ip=agent_ip, no_of_entries=50, file=NessusAgentFilePath.
                                                   NESSUS_AGENT_BACKEND_LOGS)
        log.debug("Logs from backend.log file :: {}".format(backend_logs))
