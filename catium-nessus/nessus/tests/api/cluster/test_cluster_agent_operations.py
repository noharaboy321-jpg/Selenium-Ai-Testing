"""
Nessus Agent Cluster Setup Tests

:copyright: Tenable Network Security, 2020
:date: Dec 02, 2020
:last_modified: Jan 06, 2021
:author: @pdave, @kpanchal, @krpatel
"""
import os
import re
from http import HTTPStatus

import pytest
from waiting import TimeoutExpired, wait

from catium.lib.config import Config
from catium.lib.const import TIME_TWO_MINUTES, TIME_TEN_SECONDS, TIME_THREE_MINUTES, TIME_TEN_MINUTES, \
    TIME_FIVE_SECONDS, TIME_FIVE_MINUTES
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from catium.lib.util.util import random_name
from nessus.apiobjects.endpoints.scanners import random_alphanumeric_string_for_linking_key
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import get_agent_id_from_list, check_agent_linked
from nessus.helpers.nessus_agent import wait_for_agent_status_to_get_matched_in_manager, \
    wait_for_specific_entry_in_log_file, modify_remote_agent_settings, wait_for_agent_to_get_online_in_cluster, \
    reinstall_nessus_agent_on_docker, is_log_entries
from nessus.helpers.nessuscli.helper import get_nessus_log_dir
from nessus.lib.const import Nessus
from nessus.lib.const.constants import API
from nessus.lib.const.constants import NessusAgentFilePath
from nessus.tests.api.cluster.test_cluster_manager_upgrade_downgrade import TestClusterManagerUpgradeDowngrade
from nessus.tests.conftest import link_child_node_to_parent_node, link_agent_to_parent_node
from tenableio.lib.agent_shell import PlatformServiceCommands, ProductConfigs

log = create_logger()


@pytest.mark.cluster_manager
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 0}], indirect=True)
class TestAgentLinking:
    """ Test for linking/Un-linking Agent with cluster-setup """

    cat = None

    @staticmethod
    def verify_asked_to_relink_logs_from_agent_backend_log(nessus_api: NessusAPI, agent_ip: str, agent_id: int,
                                                           node_id: int, verify_node_changed: bool = True) -> None:
        """
        Verifies the logs from backend.log file of given ip of agent

        :param NessusAPI nessus_api: Nessus API object
        :param str agent_ip: IP of linked agent
        :param int agent_id: Linked agent id
        :param int node_id: Associated node id
        :param bool verify_node_changed: True if need to verify that node has moved or False
        :return: None
        """
        required_logs = ["Asked to relink", "Linking successful; now linked to"]

        for log_msg in required_logs:
            assert is_log_entries(agent_ip=agent_ip, no_of_entries=10, file=NessusAgentFilePath.
                                  NESSUS_AGENT_BACKEND_LOGS, message=log_msg), \
                "'{}' message is missing or mismatch while moving node from one to other cluster group.".format(log_msg)

        if verify_node_changed:
            try:
                wait(lambda: nessus_api.agents.get_agent_details(agent_id=agent_id)['node_id'] != node_id,
                     timeout_seconds=TIME_FIVE_MINUTES, waiting_for="New Node-ID to change in Agent details")
            except TimeoutExpired:
                raise AssertionError("waited too long to get the new changes node-id in agent details")

    @pytest.mark.parametrize('link_agent_to_cluster', [{'is_link': False}], indirect=True)
    @pytest.mark.usefixtures('nessus_api_login', 'link_agent_to_cluster')
    def test_link_agent_to_cluster_setup(self, create_manager_cluster, link_agent_to_cluster):
        """
        AGENT-2061: [API] Link Agent to NM cluster-setup

        Scenarios tested:
        [X] Verify Agent can be linked and comes online in NM cluster via child node
        [x] Verify child node details in agent details
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        cluster_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
        cluster_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
        linking_key = self.cat.api.scanners.get_agent_linking_key()['key']
        agent_ssh = SSH(port=agent_port, banner_timeout=200)

        agent_ssh.execute("{} --name={} --host={} --port={} --key={}".format(
            PlatformServiceCommands.NessusAgent.LINK, agent_name, cluster_host, cluster_port, linking_key))

        # wait for Agent to show in the Agent list
        try:
            wait(lambda: check_agent_linked(agent_name=agent_name, api=self.cat.api),
                 timeout_seconds=TIME_TEN_MINUTES, sleep_seconds=TIME_TEN_SECONDS,
                 waiting_for="Agent to get available in Cluster's Agent-list")
        except TimeoutExpired:
            raise AssertionError('Either the Agent is not linked properly or Agent is not available on cluster-setup')

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_details = self.cat.api.agents.get_agent_details(agent_id=get_agent_id_from_list(api=self.cat.api,
                                                                                              agent_name=agent_name)[0])

        assert cluster_node['name'] == [value for key, value in agent_details.items() if 'node_name' in key][0], \
            "Node name in Agent details doesn't match"

        agent_status = agent_ssh.execute(PlatformServiceCommands.NessusAgent.LINK_STATUS)

        assert len([status for status in agent_status if Nessus.Agents.AgentStatus.LINK_STATUS_LINKED_TO.format(
            cluster_host, cluster_node['port']) in status or
                    Nessus.Agents.AgentStatus.LINK_STATUS_CONNECTED_TO_NM.format(cluster_host, cluster_node['port'])
                    in status]) == 2, 'Agent status shows agent is not linked after linking to the cluster-setup'

    @pytest.mark.parametrize('link_agent_to_cluster', [{'is_unlink': False}], indirect=True)
    @pytest.mark.usefixtures('nessus_api_login', 'link_agent_to_cluster')
    def test_unlink_agent_from_cluster_setup(self, create_manager_cluster, link_agent_to_cluster):
        """
        AGENT-2062: [API] unlink Agent from NM cluster-setup

        Scenarios tested:
        [X] Verify Agent can be un-linked from NM cluster via child node
        [x[ Verify Agent shows unlink info in Agent status
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        with SSH(port=agent_port) as ssh:
            unlink_cmd_output = ssh.execute(PlatformServiceCommands.NessusAgent.UNLINK)

            assert Nessus.Agents.AgentStatus.SUCCESSFULLY_UNLINKED in unlink_cmd_output[0], \
                "Unlinking Agent wasn't successful with unlink command output as:{}".format(unlink_cmd_output)

            agent_status = ssh.execute(PlatformServiceCommands.NessusAgent.LINK_STATUS)

            assert any([Nessus.Agents.AgentStatus.CONNECTION_WITH_CONTROLLER in status for status in
                        agent_status]), "Unlink information isn't available in agent status:{}".format(agent_status)

    @pytest.mark.parametrize('link_agent_to_cluster', [{'is_unlink': False}], indirect=True)
    @pytest.mark.parametrize("agent_config_settings", [{"payload": {"track_unlinked_agents": True}}], indirect=True)
    @pytest.mark.usefixtures('nessus_api_login', 'link_agent_to_cluster', 'agent_config_settings')
    def test_verify_agent_gets_401_after_unlinked_from_cluster_manager(self, create_manager_cluster,
                                                                       link_agent_to_cluster):
        """
        AGENT-2063: [API] Agent gets 401 when unlinked from NM UI

        Scenarios tested:
        [X] Verify Agent can be un-linked from NM cluster via parent node
        [x[ Verify that Agent-status in Parent node is Unlinked
        [x[ Verify Agent shows 401 error in backend.log
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']
        backend_log_file_path = os.path.join(ProductConfigs.NessusAgent.File.LOGS_DIR,
                                             ProductConfigs.NessusAgent.File.BACKEND_LOG)

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_id = get_agent_id_from_list(api=self.cat.api, agent_name=agent_name)[0]

        self.cat.api.agents.agent_unlink(agent_id=agent_id)

        assert wait_for_agent_status_to_get_matched_in_manager(
            nessus_api=self.cat.api, agent_name=agent_name, timeout=TIME_THREE_MINUTES,
            sleep_timeout=TIME_TEN_SECONDS, status_to_be_matched=Nessus.Agents.AgentStatus.UNLINKED.lower()), \
            "Either the Agent isn't unlinked or still unlinking is in progress"

        assert wait_for_specific_entry_in_log_file(
            ssh_instance=SSH(port=agent_port), log_file_path=backend_log_file_path, sleep_timeout=TIME_TEN_SECONDS,
            log_entry_to_be_verified=Nessus.Agents.AgentLogMessages.FAILED_WITH_STATUS_401,
            timeout=TIME_TEN_MINUTES), "Waited long for log entry: '{}' to be found in backend.log".format(
            Nessus.Agents.AgentLogMessages.FAILED_WITH_STATUS_401)

    @pytest.mark.usefixtures('nessus_api_login', 'add_node_in_cluster_manager', 'add_new_cluster_group',
                             'link_agent_to_cluster')
    def test_agent_relinked_when_asked_by_parent_node(self, create_manager_cluster, add_node_in_cluster_manager,
                                                      add_new_cluster_group, link_agent_to_cluster):
        """
        AGENT-2064: [API] Verify Agent can be re-linked when asked to re-link by parent node

        Scenarios tested:
        [X] Verify Agent can be re-linked from NM cluster via parent node
        [x[ Verify Agent shows relink log in backend.log
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']
        backend_log_file_path = os.path.join(ProductConfigs.NessusAgent.File.LOGS_DIR,
                                             ProductConfigs.NessusAgent.File.BACKEND_LOG)

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_details = self.cat.api.agents.get_agent_details(agent_id=get_agent_id_from_list(
            api=self.cat.api, agent_name=agent_name)[0])
        agent_linked_node_id, agent_linked_node_name = agent_details['node_id'], agent_details['node_name']

        try:
            self.cat.api.clustergroups.assign_node(cluster_group_id=add_new_cluster_group['id'],
                                                   node_id=agent_linked_node_id)

            assert self.cat.api.nodes.get(agent_linked_node_id)['cluster_group_id'] == add_new_cluster_group[
                'id'] and any([agent_linked_node_name in node['name'] for node in self.cat.api.clustergroups.
                              get(add_new_cluster_group['id'])['cluster_group']['nodes']]), \
                "Either Child-node is not assigned to new cluster group or failed to add Child-node in new cluster " \
                "group"

            assert wait_for_specific_entry_in_log_file(
                ssh_instance=SSH(port=agent_port), log_file_path=backend_log_file_path, sleep_timeout=TIME_TEN_SECONDS,
                log_entry_to_be_verified=Nessus.Agents.AgentLogMessages.ASKED_TO_RELINK_BY_PARENT_NODE,
                timeout=TIME_TEN_MINUTES), "Waited long for log entry: '{}' to be found in backend.log".format(
                Nessus.Agents.AgentLogMessages.ASKED_TO_RELINK_BY_PARENT_NODE)
        finally:
            self.cat.api.clustergroups.assign_node(cluster_group_id=API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID,
                                                   node_id=agent_linked_node_id)

    @pytest.mark.parametrize('backend_log_level_value', ['verbose', 'debug', 'normal'])
    @pytest.mark.usefixtures('nessus_api_login', 'link_agent_to_cluster')
    def test_agent_log_level_via_remote_settings_in_cluster(self, create_manager_cluster, link_agent_to_cluster,
                                                            backend_log_level_value):
        """
        AGENT-2065: [API] Verify Agent log level can be changed via remote agent config in clustered NM

        Scenarios tested:
        [X] Verify Agent log level can be changed via remote agent config in clustered NM
        """
        cluster_node, agent_settings_name = create_manager_cluster['nodes'][0], 'backend_log_level'
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_id = get_agent_id_from_list(api=self.cat.api, agent_name=agent_name)[0]
        default_value = [setting['default'] for setting in self.cat.api.agents.get_remote_settings(agent_id=agent_id)[
            'settings']['available'] if 'backend_log_level' in setting['setting']][0]
        log.info("default_setting_value:{}".format(default_value))
        try:
            modify_remote_agent_settings(nessus_api=self.cat.api, agent_settings_name=agent_settings_name,
                                         agent_id=agent_id, new_setting_value=backend_log_level_value)

            assert "The current value for '{}' is '{}'.".format(agent_settings_name, backend_log_level_value) in \
                   SSH(port=agent_port).execute('{} {}'.format(PlatformServiceCommands.NessusAgent.FIX_GET,
                                                               agent_settings_name)), \
                "{} remote agent settings isn't applied".format(backend_log_level_value)
        finally:
            if backend_log_level_value != default_value:
                modify_remote_agent_settings(nessus_api=self.cat.api, agent_id=agent_id,
                                             agent_settings_name=agent_settings_name, new_setting_value=default_value)

    @pytest.mark.usefixtures('nessus_api_login', 'create_manager_cluster', 'link_agent_to_cluster')
    def test_agent_log_retrieval_in_cluster_manager(self, create_manager_cluster, link_agent_to_cluster):
        """
        AGENT-2070: [API] Agent remote log retrieval in clustered NM
        Scenarios tested:
        [X] Verify Agent log retrieval in clustered NM
        [x[ Verify log file size is not empty
        [x[ Verify log file size is available in Nessus log directory
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_id = get_agent_id_from_list(api=self.cat.api, agent_name=agent_name)[0]

        # Generate agent logs in NM
        self.cat.api.agents.create_log_request_directive(agent_id=int(agent_id), data={})

        wait(lambda: len(self.cat.api.agents.get_agent_details(agent_id=int(agent_id))['logs']) > 0,
             sleep_seconds=TIME_FIVE_SECONDS, timeout_seconds=TIME_FIVE_MINUTES, waiting_for="Logs file to generate")

        log.debug('Agent log details : {}'.format(self.cat.api.agents.get_agent_details(agent_id=int(agent_id))))

        # Verify that logs are generated in NM
        log_file_size = self.cat.api.agents.get_agent_details(agent_id=int(agent_id))['logs'][0][
                            'size'] / float(1 << 10)

        assert log_file_size > 1, 'Log file size not sufficient {}'.format(
            self.cat.api.agents.get_agent_details(agent_id=int(agent_id))['logs'][0]['size'])

        agent_log_file_name = self.cat.api.agents.get_agent_details(agent_id=int(agent_id))['logs'][0]['file']
        agent_log_file_loc = os.path.join(get_nessus_log_dir(), 'remote', agent_log_file_name.split('.')[0],
                                          agent_log_file_name)

        assert SSH().path_is_file(agent_log_file_loc), 'Report log file not generated in NM'

    @pytest.mark.usefixtures('nessus_api_login', 'add_new_cluster_group', 'link_agent_to_cluster')
    def test_agent_works_fine_when_moved_it_across_the_cluster_groups(self, create_manager_cluster,
                                                                      add_new_cluster_group, link_agent_to_cluster):
        """
        NES-12414: [API] Verify Agent is working fine when moved to different cluster groups during lifecycle

        Steps:
        1. Link agent to node n1 in default cluster
        2. Make sure it scans fine
        3. Move Agent to cluster group cg2
        4. Make sure it re-links to node in cg2
        5. Make sure it scans fine
        6. Create a new cluster group cg3
        7. Move Agent to cg3 --> it will link to one of the node in cg3
        8. Make sure scan is working fine
        9. Move agent back to default cluster group --> make sure it re-links to n1
        10. Make sure scan is working fine.

        Scenario Tested:
        [x] Verify Agent is working fine when moved to different cluster groups during lifecycle.
        """
        # Link agent to node n1 in default cluster
        child_node_1 = create_manager_cluster['nodes'][0]
        cluster_group_2_id = add_new_cluster_group['id']
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=child_node_1['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_id = get_agent_id_from_list(api=self.cat.api, agent_name=agent_name)[0]

        log.info("Create and launch the scan for linked agent with node n1")
        # Verifies that scan launched and completed successfully
        TestClusterManagerUpgradeDowngrade().verify_scan_launched_successfully_after_upgrade_downgrade(
            api=self.cat.api, agents_ids=[agent_id])

        # Add new child node n2 to parent node
        child_node_2 = link_child_node_to_parent_node()

        # Assign child node n2 to new created cluster group cg2
        self.cat.api.clustergroups.assign_node(cluster_group_id=cluster_group_2_id, node_id=child_node_2['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        log.info("Move agent into cluster group cg2")
        # Move agent to new created cluster group cg2
        self.cat.api.clustergroups.assign_agents(cluster_group_id=cluster_group_2_id, agent_ids=[agent_id])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)

        log.info("Verify re-link successful to new child node n2")
        self.verify_asked_to_relink_logs_from_agent_backend_log(nessus_api=self.cat.api, agent_ip=agent_details['ip'],
                                                                agent_id=agent_id, node_id=child_node_1['id'])

        log.info("Create and launch the scan for linked agent with node n2")
        # Verifies that scan launched and completed successfully after moving agent into cg2
        TestClusterManagerUpgradeDowngrade().verify_scan_launched_successfully_after_upgrade_downgrade(
            api=self.cat.api, agents_ids=[agent_id])

        log.info("Create new cluster group cg3")
        # Creates a new cluster group cg3
        cluster_group_3_id = self.cat.api.clustergroups.add({'name': random_name(prefix="cluster_group")})[
            'cluster_group_id']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Add new child node n3 to parent node
        child_node_3 = link_child_node_to_parent_node()

        # Assign child node n3 to new created cluster group cg3
        self.cat.api.clustergroups.assign_node(cluster_group_id=cluster_group_3_id, node_id=child_node_3['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        log.info("Move agent into cluster group cg3")
        # Move agent to new created cluster group cg3
        self.cat.api.clustergroups.assign_agents(cluster_group_id=cluster_group_3_id, agent_ids=[agent_id])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        log.info("Verify re-link successful to new child node n3")
        self.verify_asked_to_relink_logs_from_agent_backend_log(nessus_api=self.cat.api, agent_ip=agent_details['ip'],
                                                                agent_id=agent_id, node_id=child_node_2['id'])

        log.info("Create and launch the scan for linked agent with node n3")
        # Verifies that scan launched and completed successfully after moving agent into cg3
        TestClusterManagerUpgradeDowngrade().verify_scan_launched_successfully_after_upgrade_downgrade(
            api=self.cat.api, agents_ids=[agent_id])

        log.info("Move agent back to default cluster group")
        # Moves agent back to default cluster group
        self.cat.api.clustergroups.assign_agents(cluster_group_id=API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID,
                                                 agent_ids=[agent_id])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        log.info("Verify re-link successful with the child node into default cluster group")
        self.verify_asked_to_relink_logs_from_agent_backend_log(nessus_api=self.cat.api, agent_ip=agent_details['ip'],
                                                                agent_id=agent_id, node_id=child_node_3['id'])

        log.info("Create and launch the scan for linked agent into default cluster group")
        # Verifies that scan launched and completed successfully after moving agent into default cluster group
        TestClusterManagerUpgradeDowngrade().verify_scan_launched_successfully_after_upgrade_downgrade(
            api=self.cat.api, agents_ids=[agent_id])

        for node_id in [child_node_2['id'], child_node_3['id']]:
            log.debug("Destroying child node :: {}".format(node_id))
            self.cat.api.nodes.delete(node_id=node_id)

        self.cat.api.clustergroups.delete(cluster_group_id=cluster_group_3_id)


@pytest.mark.cluster_manager
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 0}], indirect=True)
class TestAgentRelinking:
    """ Test for re-linking of Agent with cluster-setup """

    cat = None

    @staticmethod
    def clean_up_backend_log_file(agent_port: int) -> None:
        """
        This method clear existing log files so only new and fresh logs can be verified.
        """
        SSH(port=agent_port).execute("echo > {}".format(NessusAgentFilePath.NESSUS_AGENT_BACKEND_LOGS))

    def test_verify_agent_going_into_relinking_loop(self, create_manager_cluster, add_node_in_cluster_manager):
        """
        NES-12415: [API] Automated test case for NES-12081

        Prerequisite:
        - 1 parent node
        - 2 child nodes (set capacity to be 3 Agents each)
        - 3 Agents (a, b, c)

        Steps:
        1. Link child nodes n1, n2 to parent > Both will end be in default cluster group (cg1)
        2. Link 3 Agents (assume 2 Agents (a, b) will be connected n1, 1 Agent (c) will be connected to n2)
        3. Wait for agents to come online
        4. Move node n2 to cluster group (cg2) > wait for Agent (c) to relink to n1
        5. At this point, move Agent c to cg2
        6. Wait for Agent c to relink to node n2 in cg2
        7. Unlink Agent c via `/opt/nessus_agent/sbin/nessuscli agent unlink`
        8. Link it back
        9. Monitor Agent logs, will loop into linking across n1 and n2 one after the other

        Scenario Tested:
        [x] Verify that Agent should remain linked steadily, when node is up and running.
        """
        linked_agent_details, linked_node_details = {}, {}
        linked_agents, default_group_list = [], []

        log.info("Set node capacity to be max 3 agents")
        for node_id in [node['id'] for node in [create_manager_cluster['nodes'][0], add_node_in_cluster_manager]]:
            self.cat.api.nodes.settings(node_id=node_id, settings={'max_agents': 3})

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

        try:
            log.info("Link 3 agents")
            for _ in range(3):
                agent_detail = link_agent_to_parent_node()
                linked_agents.append(agent_detail)

            cluster_group_ids = [group['id'] for group in self.cat.api.clustergroups.list()['cluster_groups']]
            default_group_list = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(
                group_id)['cluster_group']['is_default'] == 1]

            default_cluster_group_details = self.cat.api.clustergroups.get(default_group_list[0])['cluster_group']
            log.debug("Default cluster group info :: {}".format(default_cluster_group_details))

            assigned_cluster_agents = self.cat.api.clustergroups.get_assigned_cluster_group_agents(
                default_group_list[0])
            log.debug("Assigned cluster agents detail :: {}".format(assigned_cluster_agents))

            linked_node_details = [node for node in default_cluster_group_details['nodes'] if node[
                'agent_count'] == 1][0]

            linked_agent_details = [agent for agent in assigned_cluster_agents['agents'] if agent['node_id'] ==
                                    linked_node_details['id']][0]

            assert wait_for_agent_to_get_online_in_cluster(
                nessus_api=self.cat.api, agent_name=linked_agent_details['name'],
                cluster_child_node_name=create_manager_cluster['nodes'][0]['name']), \
                "Either Agent did not reflected in NM or waited long to get Agent online"

            log.debug("Create new cluster group")
            cluster_group_id = self.cat.api.clustergroups.add({'name': random_name(prefix="cluster_group")})[
                'cluster_group_id']

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            log.info("Assign node to new created cluster group")
            self.cat.api.clustergroups.assign_node(cluster_group_id=cluster_group_id, node_id=linked_node_details['id'])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            log.info("Verify 'Asked to relink' and 'Link successful' logs in 'backend.log' file of linked agent "
                     "while trying to relink to existing node from default cluster group")
            TestAgentLinking.verify_asked_to_relink_logs_from_agent_backend_log(
                nessus_api=self.cat.api, agent_ip=linked_agent_details['ip'], agent_id=linked_agent_details['id'],
                node_id=linked_node_details['id'])

            agent_port = [agent['agent_port'] for agent in linked_agents if agent['id'] ==
                          linked_agent_details['id']][0]
            self.clean_up_backend_log_file(agent_port=agent_port)

            log.info("Move agent to new created cluster group")
            self.cat.api.clustergroups.assign_agents(cluster_group_id=cluster_group_id,
                                                     agent_ids=[linked_agent_details['id']])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            log.info("Verify 'Asked to relink' and 'Link successful' logs in 'backend.log' file of linked agent "
                     "while trying to relink to the node from new created cluster group")
            TestAgentLinking.verify_asked_to_relink_logs_from_agent_backend_log(
                nessus_api=self.cat.api, agent_ip=linked_agent_details['ip'], agent_id=linked_agent_details['id'],
                node_id=linked_node_details['id'], verify_node_changed=False)

            log.info("Unlink the agent")
            unlink_output = SSH(port=agent_port).execute("{}".format(PlatformServiceCommands.NessusAgent.UNLINK))
            log.debug("Agent Unlink output :: {}".format(unlink_output))

            assert any([Nessus.Agents.AgentStatus.SUCCESSFULLY_UNLINKED in log_line for log_line in unlink_output]), \
                "Unlinking Agent wasn't successful with unlink command output as:{}".format(unlink_output)

            cluster_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
            cluster_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
            linking_key = self.cat.api.scanners.get_agent_linking_key()['key']

            log.info("Re-link the agent back")
            link_output = SSH(port=agent_port).execute("{} --name={} --host={} --port={} --key={}".format(
                PlatformServiceCommands.NessusAgent.LINK, linked_agent_details['name'], cluster_host, cluster_port,
                linking_key))
            log.debug("Agent re-link output :: {}".format(link_output))

            assert any([Nessus.Agents.AgentStatus.LINK_SUCCESSFUL in log_line for log_line in link_output]), \
                "Failed to link agent to cluster manager."

            assert is_log_entries(agent_ip=linked_agent_details['ip'], no_of_entries=10, file=NessusAgentFilePath.
                                  NESSUS_AGENT_BACKEND_LOGS, message="Starting Nessus Agent"), \
                "Expected log messages are missing or mismatch after linking agent back to parent node."
        finally:
            for agent_id in [agent['id'] for agent in linked_agents]:
                self.cat.api.agents.delete_agent(agent_id=agent_id)
                log.debug("Deleted agent id :: {}".format(agent_id))

            log.info("reverting the node capacity")
            for node_id in [node['id'] for node in create_manager_cluster['nodes']]:
                self.cat.api.nodes.settings(node_id=node_id, settings={'max_agents': 10000})

            if default_group_list and linked_node_details:
                log.info("Assign node to default cluster group")
                self.cat.api.clustergroups.assign_node(cluster_group_id=default_group_list[0],
                                                       node_id=linked_node_details['id'])

    @pytest.mark.usefixtures('nessus_api_login', 'add_node_in_cluster_manager', 'add_new_cluster_group',
                             'link_agent_to_cluster')
    def test_relinking_the_reinstalled_agent_gets_failed_with_410(
            self, create_manager_cluster, add_node_in_cluster_manager, add_new_cluster_group, link_agent_to_cluster):
        """
        AGENT-2068: [API] Verify Agent with duplicate uuid throws 410 when trying to link with clustered NM
        Scenarios tested:

        [X] Verify Agent linked Agent can be re-linked to Clustered NM after re-installation of agent.
        [x] Verify that Agent gets 410 bad agent error after re-linking
        """
        cluster_node = create_manager_cluster['nodes'][0]
        cluster_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
        cluster_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
        linking_key = self.cat.api.scanners.get_agent_linking_key()['key']
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']
        backend_log_file_path = os.path.join(ProductConfigs.NessusAgent.File.LOGS_DIR,
                                             ProductConfigs.NessusAgent.File.BACKEND_LOG)

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_details = self.cat.api.agents.get_agent_details(agent_id=get_agent_id_from_list(
            api=self.cat.api, agent_name=agent_name)[0])

        ssh_instance = SSH(port=agent_port)
        reinstall_nessus_agent_on_docker(ssh_instance=ssh_instance)
        self.cat.api.nodes.settings(node_id=agent_details['node_id'], settings={'enabled': '0'})

        try:
            link_output = ssh_instance.execute("{} --name={} --host={} --port={} --key={}".format(
                PlatformServiceCommands.NessusAgent.LINK, agent_name, cluster_host, cluster_port, linking_key))

            assert any([Nessus.Agents.AgentStatus.LINK_SUCCESSFUL in log_line for log_line in link_output]), \
                "Failed to link agent to cluster manager."

            # wait for Agent to show in the Agent list
            try:
                wait(lambda: check_agent_linked(agent_name=agent_name, api=self.cat.api),
                     timeout_seconds=TIME_TWO_MINUTES, sleep_seconds=TIME_TEN_SECONDS,
                     waiting_for="Agent to get available in Cluster's Agent-list")
            except TimeoutExpired:
                raise AssertionError("'Either the Agent is not linked properly or Agent isn't available")

            assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                           cluster_child_node_name=cluster_node['name']), \
                "Either Agent did not reflected in NM or waited long to get Agent online"

            assert wait_for_specific_entry_in_log_file(
                ssh_instance=ssh_instance, log_file_path=backend_log_file_path, sleep_timeout=TIME_TEN_SECONDS,
                log_entry_to_be_verified=Nessus.Agents.AgentLogMessages.RECEIVED_401_FROM_MANAGER,
                timeout=TIME_TEN_MINUTES), "Waited long for log entry: '{}' to be found in backend.log".format(
                Nessus.Agents.AgentLogMessages.RECEIVED_401_FROM_MANAGER)

            agent_status = ssh_instance.execute(PlatformServiceCommands.NessusAgent.LINK_STATUS)

            assert [Nessus.Agents.AgentLogMessages.NOT_LINKED_TO_MANAGER in output for output in agent_status], \
                "The bad agent must not be linked to manager, instead it got agent-status as: {}".format(agent_status)
        finally:
            self.cat.api.nodes.settings(node_id=agent_details['node_id'], settings={'enabled': '1'})

    @pytest.mark.parametrize("agent_config_settings", [{"payload": {"track_unlinked_agents": True}}], indirect=True)
    @pytest.mark.usefixtures('nessus_api_login', 'link_agent_to_cluster', 'agent_config_settings')
    def test_unlinked_agent_can_be_relinked_to_clustered_nm(self, create_manager_cluster, link_agent_to_cluster):
        """
        AGENT-2067: Verify Agent unlinked Agent can be re-linked to Clustered NM

        Steps:
        1. "Track unlinked Agent" = yes in parent node
        2. Unlink the Agent
        3. Wait for 401 on Agent side
        4. Link Agent back
        5. Verify Link is successful
        6. Wait the same Agent comes online in NM parent node

        Scenarios tested:
        [X] Verify Agent unlinked Agent can be re-linked to Clustered NM.
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']
        backend_log_file_path = os.path.join(ProductConfigs.NessusAgent.File.LOGS_DIR,
                                             ProductConfigs.NessusAgent.File.BACKEND_LOG)

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_id = get_agent_id_from_list(api=self.cat.api, agent_name=agent_name)[0]
        self.cat.api.agents.agent_unlink(agent_id=agent_id)

        assert wait_for_agent_status_to_get_matched_in_manager(
            nessus_api=self.cat.api, agent_name=agent_name, timeout=TIME_THREE_MINUTES,
            sleep_timeout=TIME_TEN_SECONDS, status_to_be_matched=Nessus.Agents.AgentStatus.UNLINKED.lower()), \
            "Either the Agent isn't unlinked or still unlinking is in progress"

        assert wait_for_specific_entry_in_log_file(
            ssh_instance=SSH(port=agent_port), log_file_path=backend_log_file_path, sleep_timeout=TIME_TEN_SECONDS,
            log_entry_to_be_verified=Nessus.Agents.AgentLogMessages.FAILED_WITH_STATUS_401,
            timeout=TIME_TEN_MINUTES), "Waited long for log entry: '{}' to be found in backend.log".format(
            Nessus.Agents.AgentLogMessages.FAILED_WITH_STATUS_401)

        unlink_output = SSH(port=agent_port).execute("{}".format(PlatformServiceCommands.NessusAgent.UNLINK))
        log.debug("Agent Unlink output :: {}".format(unlink_output))

        assert any([Nessus.Agents.AgentStatus.SUCCESSFULLY_UNLINKED in log_line for log_line in unlink_output]), \
            "Unlinking Agent wasn't successful with unlink command output as:{}".format(unlink_output)

        cluster_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
        cluster_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
        linking_key = self.cat.api.scanners.get_agent_linking_key()['key']

        link_output = SSH(port=agent_port).execute("{} --name={} --host={} --port={} --key={}".format(
            PlatformServiceCommands.NessusAgent.LINK, agent_name, cluster_host, cluster_port, linking_key))
        log.debug("Agent re-link output :: {}".format(link_output))

        assert any([Nessus.Agents.AgentStatus.LINK_SUCCESSFUL in log_line for log_line in link_output]), \
            "Failed to link agent to cluster manager."

        # wait for Agent to show in the Agent list
        try:
            wait(lambda: check_agent_linked(agent_name=agent_name, api=self.cat.api),
                 timeout_seconds=TIME_TWO_MINUTES, sleep_seconds=TIME_TEN_SECONDS,
                 waiting_for="Agent to get available in Cluster's Agent-list")
        except TimeoutExpired:
            raise AssertionError('Either the Agent is not linked properly or Agent is not available on cluster-setup')

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_details = self.cat.api.agents.get_agent_details(agent_id=get_agent_id_from_list(
            api=self.cat.api, agent_name=agent_name)[0])

        assert cluster_node['name'] == [value for key, value in agent_details.items() if 'node_name' in key][0], \
            "Node name in Agent details doesn't match"

    @pytest.mark.parametrize('link_agent_to_cluster', [{'is_unlink': False}], indirect=True)
    @pytest.mark.usefixtures('nessus_api_login', 'add_node_in_cluster_manager', 'add_new_cluster_group',
                             'link_agent_to_cluster')
    def test_relinking_the_reinstalled_agent_gets_failed_with_duplicate_agent(self, create_manager_cluster,
                                                                              link_agent_to_cluster):
        """
        AGENT-2117: [API] 409 is thrown when trying to link the same agent again
        Scenarios tested:

        [X] Verify Agent linked Agent cannot be re-linked to Clustered NM after re-installation of agent.
        [x] Verify that Agent gets 409 bad agent error after re-linking
        """
        cluster_node = create_manager_cluster['nodes'][0]
        cluster_host = re.sub(r'.*//(.*):.*', r'\1', Config.CAT_URL)
        cluster_port = int(re.sub(r'.*:(\d+).*', r'\1', Config.CAT_URL))
        linking_key = self.cat.api.scanners.get_agent_linking_key()['key']
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        ssh_instance = SSH(port=agent_port)
        reinstall_nessus_agent_on_docker(ssh_instance=ssh_instance)

        link_output = ssh_instance.execute("{} --name={} --host={} --port={} --key={}".format(
            PlatformServiceCommands.NessusAgent.LINK, agent_name, cluster_host, cluster_port, linking_key))
        log.info("re-link output: {}".format(link_output))

        assert any([Nessus.Agents.AgentLogMessages.DUPLICATE_AGENT_FOUND in log_line for log_line in link_output]), \
            "Duplicate agent error not found while linking to cluster manager."

        assert any([Nessus.Agents.AgentStatus.LINK_FAILED in log_line for log_line in link_output]), \
            "Either duplicate agent got deleted from cluster or ."

        agent_status = ssh_instance.execute(PlatformServiceCommands.NessusAgent.LINK_STATUS)

        assert [Nessus.Agents.AgentLogMessages.NOT_LINKED_TO_MANAGER in output for output in agent_status], \
            "The bad agent must not be linked to manager, instead it got agent-status as: {}".format(agent_status)

    @pytest.mark.xray(test_key='NES-17431')
    @pytest.mark.usefixtures('nessus_api_login')
    def test_set_linking_key_for_child_node_API(self, create_manager_cluster):
        """
        NES-17431 : Validate child node Linking Keys in API.

        Scenario Tested:
        [x] Verify able to set linking key for child node using API.

        Steps:
        1. Setting up Nessus Manager and convert cluster manager
        2. Taking random 64 characters key to set
        3. using the set method of child node linking key

        """
        # Generating random 64 character keys
        node_key = random_alphanumeric_string_for_linking_key(64)

        # setting the new agent linking key to nessus manager
        self.cat.api.agent_groups.set_child_node_linking_key(node_key=node_key)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.xray(test_key='NES-16272')
    @pytest.mark.usefixtures('nessus_api_login')
    def test_set_and_get_linking_key_for_child_node__API(self, create_manager_cluster):
        """
        NES-16272 : Validate ability to set linking keys through API for child node.

        Scenario Tested:
        [x] Verify API linking keys are updated after change.

        Steps:
        1. Setting up Nessus Manager and enable cluster
        2. Taking random 64 characters key to set
        3. using the set method of agent linking key
        4. using the get method of agent linking key.
        5. Verify both the result is same
        """

        # Generating random 64 character keys
        node_key = random_alphanumeric_string_for_linking_key(64)

        # setting the new agent linking key to nessus manager
        self.cat.api.agent_groups.set_child_node_linking_key(node_key=node_key)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        linking_key = self.cat.api.scanners.get_node_linking_key()['key']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify newly set linking key via API is reflected on API
        assert node_key == linking_key, "Linking key is not matched."


@pytest.mark.cluster_manager
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1, 'total_agents': 0}], indirect=True)
class TestAgentProxyLinking:
    """ Test for linking Agent with cluster-setup via proxy """

    cat = None

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('link_agent_to_cluster', [{'is_proxy': True}], indirect=True)
    @pytest.mark.usefixtures('nessus_api_login', 'create_manager_cluster', 'link_agent_to_cluster')
    def test_linking_agent_to_cluster_manager_via_proxy(self, create_manager_cluster, link_agent_to_cluster):
        """
        AGENT-2207: [API] Verify agent can link to clustered NM with Proxy.
        Scenarios tested:
        [X] Verify Agent links to cluster-setup via proxy.
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name = link_agent_to_cluster['agent_name']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_details = self.cat.api.agents.get_agent_details(agent_id=get_agent_id_from_list(api=self.cat.api,
                                                                                              agent_name=agent_name)[0])

        assert cluster_node['name'] == [value for key, value in agent_details.items() if 'node_name' in key][0], \
            "Node name in Agent details doesn't match"
