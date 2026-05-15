'''
Tests of cluster-group rebalancing APIs
'''
# pylint: disable=bare-except

import re
import pytest
from waiting import wait

from catium.lib.const import TIME_TEN_MINUTES, TIME_FIFTEEN_MINUTES
from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.server import expect_http_error


log = create_logger()


@pytest.fixture()
def rebalance_starting_state():
    '''
    Create the following scenario:
    node 1 is in "Cluster Group" and has 2 agents
    node 2 is in "Cluster Group" and has 0 agents
    node 3+ is in "Other Group" and has 2+ agents
    all agents are online
    '''
    api = NessusAPI()
    api.login()


    # wait for all agents to come online
    log.info('Waiting for all agents to come online')
    agent_ids = sorted([a['id'] for a in api.agents.agents_list()['agents']])
    def is_agent_online(agent_id):
        try:
            return api.agents.get_agent_details(agent_id)['status'] == 'online'
        except:
            return None
    for id in agent_ids:
        wait(lambda: is_agent_online(id), timeout_seconds = TIME_FIFTEEN_MINUTES,
             waiting_for='agent %s to appear online' % id)


    def find_or_create_cluster_group(name):
        for cluster_group in api.clustergroups.list()['cluster_groups']:
            if cluster_group['name'] == name:
                return cluster_group['id']
        return api.clustergroups.add({'name': name})['cluster_group_id']

    group1_id = find_or_create_cluster_group('Cluster Group')
    group2_id = find_or_create_cluster_group('Other Group')


    # assign all nodes to group2 except first node to group1
    log.info('Assigning all nodes except one to the second group')
    node_ids = sorted([n['id'] for n in api.nodes.list()['nodes']])
    if api.nodes.get(node_ids[0])['cluster_group_id'] != group1_id:
        api.clustergroups.assign_node(group1_id, node_ids[0])
    for node_id in node_ids[1:]:
        api.clustergroups.assign_node(group2_id, node_id)


    # assign agents according to comment at top of func
    log.info('Assigning all agents except two to the second group')
    group1_agent_ids = agent_ids[:2]
    group2_agent_ids = agent_ids[2:]
    api.clustergroups.assign_agents(group1_id, group1_agent_ids)
    api.clustergroups.assign_agents(group2_id, group2_agent_ids)


    def agents_linked_to_node(node_id):
        def is_agent_in_node(agent_id):
            return api.agents.get_agent_details(agent_id)['node_id'] == node_id
        return list(filter(is_agent_in_node, agent_ids))

    # wait for agents to link as follows:
    ## first two agents on first node
    ## rest of agents across remaining nodes
    log.info('Waiting for first two agents to link to first node')
    def is_first_two_agents_first_node():
        return set(agents_linked_to_node(node_ids[0])) == set(agent_ids[:2])
    wait(is_first_two_agents_first_node, timeout_seconds = TIME_TEN_MINUTES,
         waiting_for='first agents to link to node 0, rest to link elsewhere')

    # assign second node back to group 1
    api.clustergroups.assign_node(group1_id, node_ids[1])

    # wait for second node to become empty
    log.info('Waiting for the second node to become empty')
    def is_second_node_empty():
        return agents_linked_to_node(node_ids[1]) == []
    wait(is_second_node_empty, timeout_seconds = TIME_TEN_MINUTES,
         waiting_for='second node to become empty')

    # now the comment at top of function should be true, but test that
    assert set(agents_linked_to_node(node_ids[0])) == set(agent_ids[:2]), \
        'first two agents are no longer on first node'
    assert agents_linked_to_node(node_ids[1]) == [], 'second node is no longer empty'

    log.info('Cluster is ready for rebalance tests')
    yield {
        'cluster_group_ids': [group1_id, group2_id],
        'node_ids': node_ids,
        'agent_ids': agent_ids
    }


@pytest.mark.sensor_manager
@pytest.mark.usefixtures('create_manager_cluster', 'nessus_api_login')
class TestClusterGroupRebalance:
    ''' Test Cluster Group Rebalancing '''
    cat = None


    def test_capacity_warnings(self, rebalance_starting_state):
        '''
        Based on the starting scenario of rebalance_starting_state, test the following:
        - set 'Cluster Group' total capacity to 2
        - cluster group 'Cluster Group' shows a utilization warning
        - cluster group 'Cluster Group' shows a failover warning
        - set 'Cluster Group' total capacity to 20
        - cluster group 'Cluster Group' shows no utilization warning
        - cluster group 'Cluster Group' shows no failover warning
        - cluster group 'Other Group' shows a failover warning due to 1 node
        - cluster group 'Other Group' shows no utilization warning
        '''
        node0_id = rebalance_starting_state['node_ids'][0]
        node1_id = rebalance_starting_state['node_ids'][1]

        def find_critical_alert(regex):
            for notification in self.cat.api.server.get_notifications()['notifications']:
                if re.search(regex, notification['message']):
                    return True
            return False
        def find_health_alert(regex):
            for alert in self.cat.api.settings.health_alerts():
                if re.search(regex, alert['description']):
                    return True
            return False

        def list_critical_alerts():
            return [n['message'] for n in self.cat.api.server.get_notifications()['notifications']]
        def all_health_alerts():
            return [a['description'] for a in self.cat.api.settings.health_alerts()]

        assert not find_critical_alert(r'Cluster Group.*There is insufficient capacity'), list_critical_alerts()
        assert not find_health_alert(r'Cluster Group.*agent capacity'), all_health_alerts()

        self.cat.api.nodes.settings(node0_id, {'max_agents': 1})
        self.cat.api.nodes.settings(node1_id, {'max_agents': 1})

        assert find_critical_alert(r'Cluster Group.*There is insufficient capacity'), list_critical_alerts()
        assert find_health_alert(r'Cluster Group.*agent capacity'), all_health_alerts()

        self.cat.api.nodes.settings(node0_id, {'max_agents': 100})
        self.cat.api.nodes.settings(node1_id, {'max_agents': 100})

        assert not find_critical_alert(r'Cluster Group.*There is insufficient capacity'), list_critical_alerts()
        assert not find_health_alert(r'Cluster Group.*agent capacity.*% utilized'), all_health_alerts()

        assert not find_critical_alert(r'Other Group.*There is insufficient capacity'), list_critical_alerts()
        assert find_health_alert(r'Other Group.*There is insufficient capacity'), all_health_alerts()
        assert not find_health_alert(r'Other Group.*agent capacity.*% utilized'), all_health_alerts()

    def test_rebalance_no_id(self, rebalance_starting_state):
        '''
        Test that the 'rebalance' API endpoint requires a cluster group id on SM.
        '''
        with expect_http_error(code=400, look_for='No cluster_group_id provided'):
            self.cat.api.nodes.rebalance()

    def test_rebalance(self, rebalance_starting_state):
        '''
        Based on the starting scenario of rebalance_starting_state, test the following:
        - cluster group 'Cluster Group' shows as unbalanced
        - cluster group 'Cluster Group' can be balanced successfully
        - cluster group 'Cluster Group' then shows as balanced
        '''
        agent0_id = rebalance_starting_state['agent_ids'][0]
        agent1_id = rebalance_starting_state['agent_ids'][1]
        node0_id = rebalance_starting_state['node_ids'][0]
        node1_id = rebalance_starting_state['node_ids'][1]
        cluster_group_id = rebalance_starting_state['cluster_group_ids'][0]

        cginfo = self.cat.api.clustergroups.get(cluster_group_id)['cluster_group']
        assert cginfo['balance']['balanced'] is False, "Cluster Group is showing as balanced, shouldn't be"

        self.cat.api.nodes.rebalance(cluster_group_id)

        def is_cg_balanced():
            return self.cat.api.clustergroups.get(cluster_group_id)['cluster_group']['balance']['balanced']

        wait(is_cg_balanced, sleep_seconds=3, timeout_seconds=TIME_TEN_MINUTES,
             waiting_for='cluster group %d to balance' % cluster_group_id)

        agent0_node_id = self.cat.api.agents.get_agent_details(agent0_id)['node_id']
        agent1_node_id = self.cat.api.agents.get_agent_details(agent1_id)['node_id']
        assert agent0_node_id != agent1_node_id, "agents aren't on different nodes after 50/50 rebalance"
        assert agent0_node_id in [node0_id, node1_id], "agent 0 isn't linked to the expected nodes"
        assert agent1_node_id in [node0_id, node1_id], "agent 1 isn't linked to the expected nodes"
