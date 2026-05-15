"""
Nessus Cluster Group feature related tests
:copyright: Tenable Network Security, 2020
:date: Sep 29, 2020
:last_modified: Jan 15, 2021
:author: @vsoni.ctr, @kpanchal
"""
import json
import os
import subprocess
from http import HTTPStatus
from random import randint

import pytest
from requests import HTTPError
from waiting import wait
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_TEN_MINUTES, TIME_THIRTY_MINUTES, TIME_FIVE_MINUTES, \
    TIME_SIXTY_SECONDS, TIME_TEN_SECONDS, TIME_TWO_MINUTES, TIME_THIRTY_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.ssh import SSH
from catium.lib.util.util import random_name, generate_request_uuid
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import get_agent_id_from_list
from nessus.helpers.nessus_agent import is_log_entries, wait_for_specific_entry_in_log_file, \
    wait_for_agent_to_get_online_in_cluster, enable_debug_logs_for_agent
from nessus.helpers.nessuscli import fix
from nessus.helpers.scan import create_scan_helper
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.software_update import clean_up_log_files_before_software_update
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import Nessus
from nessus.lib.const.constants import API, NessusAgentFilePath
from nessus.lib.message.messages import Messages
from nessus.models.scan import ScanModel
from nessus.tests.api.cluster.test_cluster_manager_upgrade_downgrade import TestClusterManagerUpgradeDowngrade
from nessus.tests.conftest import link_child_node_to_parent_node, link_agent_to_parent_node
from tenableio.lib.agent_shell import ProductConfigs

log = create_logger()

BASIC_AGENT_SCAN_FILE = "nessus/tests/api/scan/test_data/test_basic_agent_scan.json"
ADVANCED_AGENT_SCAN_FILE = "nessus/tests/api/scan/test_data/test_advanced_agent_scan.json"
SCAN_DISABLED_IN_BW = "Scans disabled due to an active blackout window"


@pytest.mark.cluster_manager
@pytest.mark.usefixtures('create_manager_cluster', 'nessus_api_login')
class TestClusterGroupFeatures:
    """Tests related to cluster group feature in Nessus Manager (Cluster Manager)"""
    cat = None

    def verify_node_assigned_to_cluster_group(self, group_id: int, node_id: int, node_name: str) -> None:
        """
        Verifies that child node assigned to given cluster group
        :param group_id: cluster group id
        :param node_id: child node id to be moved
        :param node_name: child node name
        :return: None
        """
        self.cat.api.clustergroups.assign_node(cluster_group_id=group_id, node_id=node_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert node_name in [node['name'] for node in self.cat.api.clustergroups.get(group_id)[
            'cluster_group']['nodes']] and self.cat.api.nodes.get(node_id)['cluster_group_id'] == group_id, \
            "Node is not assigned to new cluster group."

    # API_Tested# GET /cluster-groups
    # API_Tested# GET /cluster-groups/{cluster_group_id}
    # API_Tested# GET /agents?{cluster_group_id}
    def test_default_cluster_group_in_cluster_manager(self, create_manager_cluster):
        """
        NES-12073 : API automation for cluster group features
        NES-12329 : [API] Verify Default cluster group is created when clustering is enabled
        Scenarios Tested:
            [x] Verify that only one default cluster group is present in cluster manager
            [x] Verify that nodes and agents assigned to default group.
        """
        node_names = [node['name'] for node in create_manager_cluster['nodes']]
        agent_names = [agent['name'] for agent in create_manager_cluster['agents']]

        cluster_group_ids = [group['id'] for group in self.cat.api.clustergroups.list()['cluster_groups']]
        default_group_list = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(group_id)[
            'cluster_group']['is_default'] == 1]

        # Verify that one default group is present in cluster manager
        assert len(default_group_list) == 1, "Default group is not present or more than one default group is " \
                                             "present in cluster manager"

        default_cluster_group_nodes = [node['name'] for node in self.cat.api.clustergroups.get(
            default_group_list[0])['cluster_group']['nodes']]

        default_cluster_group_agents = [agent['name'] for agent in self.cat.api.clustergroups.get_cluster_group_agents(
            cluster_group_id=default_group_list[0])['agents']]

        # Verify that nodes are assigned to default cluster group.
        assert set(node_names).issubset(default_cluster_group_nodes), "Nodes did not assign to default group."

        # Verify that agents are assigned to default cluster group.
        assert set(agent_names).issubset(default_cluster_group_agents), "Agents did not assign to default group."

    # API_Tested# PUT /cluster-groups/member/{node_id}
    # API_Tested# GET /nodes/{node_id}
    @pytest.mark.usefixtures('nessus_api_login', 'add_new_cluster_group', 'add_node_in_cluster_manager')
    def test_assigned_node_to_new_cluster_group(self, add_new_cluster_group, add_node_in_cluster_manager):
        """
        NES-12073 : API automation for cluster group features
        NES-12331 : [API] Verify custom cluster group can be created
        Scenarios Tested:
            [x] Verify node can be assigned to newly created cluster group.
        """
        cluster_group_id = add_new_cluster_group['id']

        cluster_groups = self.cat.api.clustergroups.list()['cluster_groups']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert cluster_group_id in [group['id'] for group in cluster_groups], 'Failed to create custom cluster group...'

        new_node = add_node_in_cluster_manager
        node_name, node_id = new_node['name'], new_node['id']

        assert node_name in [node['name'] for node in self.cat.api.clustergroups.get(
            API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID)['cluster_group']['nodes']] and self.cat.api.nodes.get(
            node_id)['cluster_group_id'] == API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID, \
            "Node is not assigned to default cluster group."

        self.verify_node_assigned_to_cluster_group(group_id=cluster_group_id, node_id=node_id, node_name=node_name)

    # API_Tested# PUT /cluster-groups/{cluster_group_id}/agents
    @pytest.mark.usefixtures('nessus_api_login', 'add_new_cluster_group', 'add_node_in_cluster_manager')
    def test_assign_agent_to_new_cluster_group(self, create_manager_cluster, add_new_cluster_group,
                                               add_node_in_cluster_manager):
        """
        NES-12073 : API automation for cluster group features
        Scenarios Tested:
            [x] Verify that agent can be assigned to new cluster group after node is assigned.
        """
        cluster_group_id = add_new_cluster_group['id']
        new_node = add_node_in_cluster_manager
        node_name, node_id = new_node['name'], new_node['id']
        assign_agent = [agent for agent in create_manager_cluster['agents']][0]

        self.verify_node_assigned_to_cluster_group(group_id=cluster_group_id, node_id=node_id, node_name=node_name)

        self.cat.api.clustergroups.assign_agents(cluster_group_id=cluster_group_id, agent_ids=[assign_agent['id']])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        try:
            assert assign_agent['name'] in [agent['name'] for agent in
                                            self.cat.api.clustergroups.get_cluster_group_agents
                                            (cluster_group_id=cluster_group_id)['agents']], \
                "Agent is not assigned to new cluster group."

            assert self.cat.api.agents.get_agent_details(agent_id=assign_agent['id'])[
                       'cluster_group_id'] == cluster_group_id, \
                "Associated cluster group is not reflected in agent details."
        finally:
            self.cat.api.clustergroups.assign_agents(cluster_group_id=API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID,
                                                     agent_ids=[assign_agent['id']])

    # API_Tested# PUT /cluster-groups/{cluster_group_id}
    @pytest.mark.usefixtures('nessus_api_login', 'add_new_cluster_group', 'add_node_in_cluster_manager')
    def test_make_new_cluster_group_as_default_group(self, add_new_cluster_group, add_node_in_cluster_manager):
        """
        NES-12073 : API automation for cluster group features
        NES-12333 : [API][Negative] Verify a custom cluster group can be set as default
        Scenarios Tested:
            [x] Verify that cluster group can not be set as default when there is not any node present in cluster group
            [x] Verify that any cluster group can be set as default cluster group
                when there is at least one node is present.
        """
        new_node = add_node_in_cluster_manager
        node_name, node_id = new_node['name'], new_node['id']
        cluster_group_id = add_new_cluster_group['id']

        assert self.cat.api.clustergroups.get(cluster_group_id)['cluster_group']['is_default'] == 0, \
            "Newly created cluster group become default group!"

        try:
            self.cat.api.clustergroups.update(cluster_group_id, {"is_default": True})
        except HTTPError:
            assert self.cat.api.http_status_code == HTTPStatus.CONFLICT and self.cat.api._text == API.ClusterGroup. \
                ErrorMessages.SET_GROUP_AS_DEFAULT_ERROR, \
                "Mismatch in error message/code while setting cluster group as default while no nodes assigned to it."

        self.verify_node_assigned_to_cluster_group(group_id=cluster_group_id, node_id=node_id, node_name=node_name)

        self.cat.api.clustergroups.update(cluster_group_id, {"is_default": True})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        try:
            assert self.cat.api.clustergroups.get(cluster_group_id)['cluster_group']['is_default'] == 1, \
                "Not able to make the new cluster group as default cluster group!"
        finally:
            self.cat.api.clustergroups.update(API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID, {"is_default": True})

    # API_Tested# PUT /cluster-groups/member/{node_id} (409 Error)
    # API_Tested# DELETE /nodes/{node_id} (400 Error)
    @pytest.mark.usefixtures('nessus_api_login', 'add_new_cluster_group', 'add_node_in_cluster_manager')
    @pytest.mark.parametrize('cluster_folder_type', ['default', 'custom'])
    @pytest.mark.parametrize('node_operation', ['move', 'delete'])
    def test_user_can_not_move_or_delete_node_when_agent_is_present_in_cluster_group(
            self, add_new_cluster_group, add_node_in_cluster_manager, create_manager_cluster, cluster_folder_type,
            node_operation):
        """
        NES-12073 : API automation for cluster group features
        NES-12342 : [API] [Negative] Verify the last node in a default cluster group can not be removed
        Scenarios Tested:
            [x] Verify that node can not be removed from cluster group when agent is present inside.
            [x] Verify that last node can not be deleted from the cluster group when agent is present inside.
        """
        try:
            new_node = add_node_in_cluster_manager
            node_name, node_id = new_node['name'], new_node['id']
            cluster_group_id = add_new_cluster_group['id']
            assign_agent = [agent for agent in create_manager_cluster['agents']][1]

            self.verify_node_assigned_to_cluster_group(group_id=cluster_group_id, node_id=node_id, node_name=node_name)

            self.cat.api.clustergroups.assign_agents(cluster_group_id=cluster_group_id, agent_ids=[assign_agent['id']])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            if cluster_folder_type == 'default':
                self.cat.api.clustergroups.update(cluster_group_id, {"is_default": True})

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code

            try:
                with pytest.raises(HTTPError):
                    if node_operation == 'move':
                        self.cat.api.clustergroups.assign_node(
                            cluster_group_id=API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID, node_id=node_id)
                    else:
                        self.cat.api.nodes.delete(node_id=node_id)

                expected_response_code = HTTPStatus.CONFLICT if node_operation == 'move' else HTTPStatus.BAD_REQUEST

                assert self.cat.api.http_status_code == expected_response_code, \
                    'Expected %s, got %s instead.' % (expected_response_code, self.cat.api.http_status_code)

                error_msg_from_response = json.loads(self.cat.api.http_text)['error']

                expected_last_node_move_error = "Cannot move the last node in the default cluster group." if \
                    cluster_folder_type == 'default' else API.ClusterGroup.ErrorMessages.NODE_REMOVE_ERROR

                expected_last_node_delete_error = "Cannot delete the last node in the default cluster group." if \
                    cluster_folder_type == 'default' else API.ClusterGroup.ErrorMessages.LAST_NODE_DELETE_ERROR

                expected_error_message = expected_last_node_move_error if node_operation == 'move' else \
                    expected_last_node_delete_error

                assert error_msg_from_response == expected_error_message, \
                    "Expected '{}' error msg, got '{}' instead.".format(expected_error_message, error_msg_from_response)
            finally:
                self.cat.api.clustergroups.assign_agents(cluster_group_id=API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID,
                                                         agent_ids=[assign_agent['id']])
        finally:
            self.cat.api.clustergroups.update(API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID, {"is_default": True})

    # API_Tested# PUT /cluster-groups/{cluster_group_id}/agents (409 Error)
    @pytest.mark.usefixtures('nessus_api_login', 'add_new_cluster_group')
    def test_user_can_not_assign_agent_to_cluster_group_when_node_is_not_present(self, add_new_cluster_group,
                                                                                 create_manager_cluster):
        """
        NES-12073 : API automation for cluster group features
        Scenarios Tested:
            [x] Verify that agent can not be assigned to cluster group while there is not any node present inside it.
        """
        cluster_group = add_new_cluster_group
        assign_agent = [agent for agent in create_manager_cluster['agents']][1]

        try:
            self.cat.api.clustergroups.assign_agents(cluster_group_id=cluster_group['id'],
                                                     agent_ids=[assign_agent['id']])
        except HTTPError:
            assert self.cat.api.http_status_code == HTTPStatus.CONFLICT and self.cat.api._text == API.ClusterGroup. \
                ErrorMessages.AGENT_ASSIGN_ERROR, \
                "Mismatch in error message/code while agent to cluster group having no node present."

    @pytest.mark.parametrize('cluster_group_name', [random_name(prefix="cluster_group-"), '', None])
    def test_duplicate_or_empty_cluster_group_name_not_allowed_while_creating(self, cluster_group_name):
        """
        NES-12332: [API][Negative] Verify trying to create a cluster group with duplicate name throws error
        NES-12338: [API] [Negative] Verify trying to create a cluster group with blank name throws error
        Scenario Tested:
        [x] Verify duplicate or empty cluster group names are not allowed.
        """
        cluster_group_details = {}

        if cluster_group_name:
            cluster_group_details = self.cat.api.clustergroups.add({'name': cluster_group_name})

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

        with pytest.raises(HTTPError):
            self.cat.api.clustergroups.add({'name': cluster_group_name})

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        expected_error_msgs = "The cluster group '{}' exists already.".format(cluster_group_name) if \
            cluster_group_name else "Invalid cluster group name specified."
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msgs, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msgs, error_msg_from_response)

        if cluster_group_name:
            self.cat.api.clustergroups.delete(cluster_group_id=cluster_group_details['cluster_group_id'])

    def test_duplicate_cluster_group_name_not_allowed_while_editing(self, add_new_cluster_group):
        """
        NES-12332: [API][Negative] Verify trying to create a cluster group with duplicate name throws error
        Scenario Tested:
        [x] Verify duplicate cluster group names are not allowed while edit.
        """
        cluster_group_name = random_name(prefix="cluster_group-")

        cluster_group_details = self.cat.api.clustergroups.add({'name': cluster_group_name})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        with pytest.raises(HTTPError):
            cluster_group_payload = {"name": cluster_group_name}
            self.cat.api.clustergroups.update(add_new_cluster_group['id'], cluster_group_payload)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        expected_error_msgs = "The cluster group '{}' exists already.".format(cluster_group_name)
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msgs, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msgs, error_msg_from_response)

        self.cat.api.clustergroups.delete(cluster_group_id=cluster_group_details['cluster_group_id'])

    def test_default_cluster_group_can_not_be_deleted(self):
        """
        NES-12334: [API][Negative] Verify Default cluster group can not be deleted
        Scenario Tested:
        [x] Verify Default cluster group can not be deleted.
        """
        cluster_groups = self.cat.api.clustergroups.list()['cluster_groups']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        cluster_group_ids = [group['id'] for group in cluster_groups]

        default_group_id = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(group_id)[
            'cluster_group']['is_default'] == 1][0]

        with pytest.raises(HTTPError):
            self.cat.api.clustergroups.delete(cluster_group_id=default_group_id)

        assert self.cat.api.http_status_code == HTTPStatus.CONFLICT, \
            'Expected 409, got %s instead.' % self.cat.api.http_status_code

        expected_error_msgs = "Cannot delete cluster group that has nodes assigned to it. Move the nodes to another " \
                              "cluster group and try again."
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msgs, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msgs, error_msg_from_response)

    def test_rename_default_and_custom_cluster_group_names(self, add_new_cluster_group):
        """
        NES-12335: [API] Verify Default and custom cluster groups can be renamed
        Scenario Tested:
        [x] Verify Default and custom cluster groups name can be renamed.
        """
        custom_cluster_group_info = add_new_cluster_group

        cluster_groups = self.cat.api.clustergroups.list()['cluster_groups']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        cluster_group_ids = [group['id'] for group in cluster_groups]

        default_group_id = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(group_id)[
            'cluster_group']['is_default'] == 1][0]

        default_cluster_group_name = self.cat.api.clustergroups.get(default_group_id)['cluster_group']['name']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        try:
            for cluster_group_id in [default_group_id, custom_cluster_group_info['id']]:
                cluster_group_payload = {"name": random_name(prefix="cluster_group-")}

                self.cat.api.clustergroups.update(cluster_group_id, cluster_group_payload)

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code

                cluster_group_info = self.cat.api.clustergroups.get(cluster_group_id)

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code

                assert cluster_group_info['cluster_group']['name'] == cluster_group_payload['name'], \
                    'Failed to rename the cluster group name...'
        finally:
            self.cat.api.clustergroups.update(default_group_id, {"name": default_cluster_group_name})

    def test_generate_parent_node_linking_key(self):
        """
        NES-12336: [API] Verify parent node linking key can be regenerated
        Scenario Tested:
        [x] Verify parent node linking key can be regenerated successfully
        """
        original_key = self.cat.api.settings.get_key()['key']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        try:
            response = self.cat.api.settings.rekey()

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert 'key' in response, 'Missing field "key" from response'

            assert len(response['key']) > 0, 'Expected key to be present, got empty key instead'

            wait_for_scanner_to_be_ready(api=self.cat.api)
        finally:
            self.cat.api.settings.rekey(payload={'key': original_key})

            wait_for_scanner_to_be_ready(api=self.cat.api)

    @pytest.mark.parametrize('valid_linking_key', [True, False])
    def test_change_parent_node_linking_key_to_custom_key(self, valid_linking_key):
        """
        NES-12337: [API] Verify custom parent node linking key can be placed
        Scenario Tested:
        [x] Verify custom parent node linking key can be placed successfully
        """
        original_key = self.cat.api.settings.get_key()['key']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        custom_key = generate_request_uuid() * 2

        try:
            if valid_linking_key:
                response = self.cat.api.settings.rekey(payload={'key': custom_key})

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code

                # Verify that the linking key is updated to new custom key.
                assert all(['key' in response, len(response['key']) > 0]), \
                    'Missing field "key" from response or got empty key instead'

                assert all([response['key'] != original_key, len(response['key']) == len(original_key)]), \
                    'Linking key in response should not be same as the original linking key.'

                assert self.cat.api.settings.get_key()['key'] == custom_key != original_key, \
                    "Linking key should be updated to new linking key."

                wait_for_scanner_to_be_ready(api=self.cat.api)
            else:
                with pytest.raises(HTTPError):
                    self.cat.api.settings.rekey(payload={'key': custom_key[10::]})

                # Verify that the linking key is not updated and it's invalid linking key.
                assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                    "Expected 400, got {} instead".format(self.cat.api.http_status_code)

                expected_error_msgs = "The key must be a 64 character alphanumeric string."
                error_msg_from_response = json.loads(self.cat.api.http_text)['error']

                assert error_msg_from_response == expected_error_msgs, \
                    "Expected '{}' error msg, got '{}' instead.".format(expected_error_msgs, error_msg_from_response)

                assert self.cat.api.settings.get_key()['key'] == original_key != custom_key, \
                    "Key expected to be same, got updated"
        finally:
            self.cat.api.settings.rekey(payload={'key': original_key})

            wait_for_scanner_to_be_ready(api=self.cat.api)

    def test_get_cluster_group_details(self, create_manager_cluster):
        """
        NES-12339: [API] Verify cluster group details can be retrieved [GET /cluster-groups/{cluster_group_id}]
        Scenario Tested:
        [x] Verify cluster group details can be retrieved
        [x] Verify that details shows correct nodes count, agents count and usage statistics.
        """
        node_names = [node['name'] for node in create_manager_cluster['nodes']]
        agent_names = [agent['name'] for agent in create_manager_cluster['agents']]

        cluster_groups = self.cat.api.clustergroups.list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        cluster_group_ids = [group['id'] for group in cluster_groups['cluster_groups']]

        default_group_id = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(group_id)[
            'cluster_group']['is_default'] == 1][0]

        default_cluster_group_info = self.cat.api.clustergroups.get(default_group_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert default_cluster_group_info['cluster_group'], 'Failed to get cluster group details...'

        default_cluster_group_nodes = [node['name'] for node in default_cluster_group_info['cluster_group']['nodes']]

        assert set(node_names).issubset(default_cluster_group_nodes), 'Got invalid associated cluster nodes names...'

        agent_count = sum([node['agent_count'] for node in default_cluster_group_info['cluster_group']['nodes']])

        assert agent_count == len(agent_names), 'Got invalid linked cluster agents count...'

    def test_get_linked_agents_details_from_cluster_group(self, create_manager_cluster):
        """
        NES-12340: [API] Verify cluster group Agents list can be retrieved
                   [GET /cluster-groups/{cluster_group_id}/agents]
        Scenario Tested:
        [x] Verify cluster group Agents list can be retrieved [GET /cluster-groups/{cluster_group_id}/agents]
        """
        agent_names = [agent['name'] for agent in create_manager_cluster['agents']]

        cluster_group_ids = [group['id'] for group in self.cat.api.clustergroups.list()['cluster_groups']]

        default_group_id = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(group_id)[
            'cluster_group']['is_default'] == 1][0]

        count = 0
        agents = self.cat.api.clustergroups.get_assigned_cluster_group_agents(cluster_group_id=default_group_id)
        agent_count = sum([count + 1 for agent in agents['agents'] if agent['node_id']])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert all([agents['agents'], agent_count == len(agent_names)]), \
            'Failed to fetch linked agents from cluster group'

    def test_child_node_always_links_to_default_cluster_group(self):
        """
        NES-12341: [API] Verify new child node always links to a default cluster group
        Scenario Tested:
        [x] Verify new child node always links to a default cluster group
        """
        new_child_node = {}

        try:
            cluster_group_ids = [group['id'] for group in self.cat.api.clustergroups.list()['cluster_groups']]

            default_group_id = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(group_id)[
                'cluster_group']['is_default'] == 1][0]

            nodes_before_link = self.cat.api.clustergroups.get_cluster_group_nodes(
                cluster_group_id=default_group_id)['nodes']

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            new_child_node = link_child_node_to_parent_node()

            nodes_after_link = self.cat.api.clustergroups.get_cluster_group_nodes(
                cluster_group_id=default_group_id)['nodes']

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert len(nodes_after_link) == len(nodes_before_link) + 1, \
                'New child node was not linked to default cluster group.'
        finally:
            self.cat.api.nodes.delete(node_id=new_child_node['id'])

    def test_set_child_node_capacity(self, add_node_in_cluster_manager):
        """
        NES-12330: [API] Verify cluster child node capacity can be set / adjusted
        Scenario Tested:
        [x] Verify cluster child node capacity can be set / adjusted.
        """
        max_agent_value = randint(1000, 9999)
        node_id = add_node_in_cluster_manager['id']

        self.cat.api.nodes.settings(node_id=node_id, settings={'max_agents': max_agent_value})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        node_details = self.cat.api.nodes.get(node_id=node_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert node_details['max_agents'] == max_agent_value, "Failed to update max agents value."

    def test_move_node_across_the_cluster_groups(self, add_new_cluster_group, add_node_in_cluster_manager):
        """
        NES-12343: [API] Verify node can be moved across cluster groups
        Scenario Tested:
        [x] Verify node can be moved across cluster groups.
        """
        cluster_group_2_name = random_name(prefix="cluster_group")
        cluster_group_1_id = add_new_cluster_group['id']
        node_details = add_node_in_cluster_manager
        node_name, node_id = node_details['name'], node_details['id']

        self.verify_node_assigned_to_cluster_group(group_id=cluster_group_1_id, node_id=node_id, node_name=node_name)

        cluster_group_2_id = self.cat.api.clustergroups.add({'name': cluster_group_2_name})['cluster_group_id']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        self.verify_node_assigned_to_cluster_group(group_id=cluster_group_2_id, node_id=node_id, node_name=node_name)

        self.verify_node_assigned_to_cluster_group(group_id=cluster_group_1_id, node_id=node_id, node_name=node_name)

    def test_agent_always_links_to_default_cluster_group_node(self):
        """
        NES-12344: [API] Verify new Agent always links to a node in default cluster group
        Scenario Tested:
        [x] Verify new Agent always links to a node in default cluster group.
        """
        new_agent = {}

        try:
            cluster_group_ids = [group['id'] for group in self.cat.api.clustergroups.list()['cluster_groups']]

            default_group_id = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(group_id)[
                'cluster_group']['is_default'] == 1][0]

            agents_details_before_link = self.cat.api.clustergroups.get_assigned_cluster_group_agents(
                cluster_group_id=default_group_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            agents_before_link = agents_details_before_link["agents"][0]["total_agents"]

            new_agent = link_agent_to_parent_node()

            agents_details_after_link = self.cat.api.clustergroups.get_assigned_cluster_group_agents(
                cluster_group_id=default_group_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            agents_after_link = agents_details_after_link["agents"][0]["total_agents"]

            assert agents_after_link == agents_before_link + 1, \
                'New agent was not linked to default cluster group node.'
        finally:
            self.cat.api.agents.delete_agent(agent_id=new_agent['id'])

    def test_agent_asked_to_relink_while_moving_node(self, create_manager_cluster, add_new_cluster_group):
        """
        NES-12345: [API] Verify Agent is asked to re-link when the node is moved to other cluster group
        Scenario Tested:
        [x] Verify that "Asked to relink" message should be in nessus agent's backend.log file when we move node from
            one cluster group to other.
        [x] Verify that Agent scan is working normal.
        """
        node_name = None
        node_id = 0
        agent_ids = [agent['id'] for agent in create_manager_cluster['agents']]

        cluster_group_ids = [group['id'] for group in self.cat.api.clustergroups.list()['cluster_groups']]

        default_group_id = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(group_id)[
            'cluster_group']['is_default'] == 1][0]

        default_cluster_group_info = self.cat.api.clustergroups.get(default_group_id)
        log.debug("Default cluster group info :: {}".format(default_cluster_group_info))

        for node in default_cluster_group_info['cluster_group']['nodes']:
            if node['agent_count'] > 0:
                node_name, node_id = node['name'], node['id']
                log.debug("Associated Node name :: {} and Id :: {}".format(node_name, node_id))
                break

        try:
            clean_up_log_files_before_software_update()

            self.verify_node_assigned_to_cluster_group(group_id=add_new_cluster_group['id'], node_id=node_id,
                                                       node_name=node_name)

            sleep(sleep_time=TIME_SIXTY_SECONDS, reason='Sometimes, it takes a little bit time to get logs.')
            required_logs = ["Asked to relink", "Linking successful; now linked to"]

            for log_msg in required_logs:
                assert is_log_entries(agent_ip=create_manager_cluster['agents'][0]['ip'], no_of_entries=10,
                                      file=NessusAgentFilePath.NESSUS_AGENT_BACKEND_LOGS, message=log_msg), \
                    "'Asked to relink' message is missing or mismatch while moving node from one to other cluster group"

            TestClusterManagerUpgradeDowngrade().verify_scan_launched_successfully_after_upgrade_downgrade(
                api=self.cat.api, agents_ids=agent_ids)
        finally:
            self.cat.api.clustergroups.assign_node(cluster_group_id=API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID,
                                                   node_id=node_id)

    def test_agent_asked_to_relink_while_moving_it_across_cluster_groups(
            self, create_manager_cluster, add_new_cluster_group, add_node_in_cluster_manager):
        """
        NES-12347: [API] Verify Agent is asked to re-link when it is moved across the cluster groups
        Scenario Tested:
        [x] Verify that "Asked to relink" message should be in nessus agent's backend.log file when we move node from
            one cluster group to other.
        [x] Verify that Agent scan is working normal.
        """
        cluster_group_id = add_new_cluster_group['id']
        new_node = add_node_in_cluster_manager
        node_name, node_id = new_node['name'], new_node['id']
        agent_ids = [agent['id'] for agent in create_manager_cluster['agents']]

        self.verify_node_assigned_to_cluster_group(group_id=cluster_group_id, node_id=node_id, node_name=node_name)

        clean_up_log_files_before_software_update()

        try:
            self.cat.api.clustergroups.assign_agents(cluster_group_id=cluster_group_id, agent_ids=[agent_ids[0]])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            sleep(sleep_time=TIME_SIXTY_SECONDS, reason='Sometimes, it takes a little bit time to get logs.')
            required_logs = ["Asked to relink", "Linking successful; now linked to"]

            for log_msg in required_logs:
                assert is_log_entries(agent_ip=create_manager_cluster['agents'][0]['ip'], no_of_entries=10,
                                      file=NessusAgentFilePath.NESSUS_AGENT_BACKEND_LOGS, message=log_msg), \
                    "'Asked to relink' message is missing or mismatch while moving node to other cluster group."

            TestClusterManagerUpgradeDowngrade().verify_scan_launched_successfully_after_upgrade_downgrade(
                api=self.cat.api, agents_ids=agent_ids)
        finally:
            self.cat.api.clustergroups.assign_agents(cluster_group_id=API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID,
                                                     agent_ids=[agent_ids[0]])

    @pytest.mark.parametrize('is_node_name_empty', [True, False])
    def test_duplicate_or_empty_node_names_not_allowed_while_editing(self, create_manager_cluster, is_node_name_empty,
                                                                     add_node_in_cluster_manager):
        """
        NES-12400: [API] Verify node name can not be set empty when editing
        NES-12401: [API] Verify duplicate node name is not allowed while editing
        Scenario Tested:
        [x] Verify node name can not be set empty when editing.
        [x] Verify duplicate node name is not allowed while editing.
        """
        node_names = [node['name'] for node in create_manager_cluster['nodes']]
        node_id = add_node_in_cluster_manager['id']

        edited_node_name = node_names[0] if is_node_name_empty else ''

        with pytest.raises(HTTPError):
            self.cat.api.nodes.settings(node_id=node_id, settings={'name': edited_node_name})

        expected_status_code = HTTPStatus.CONFLICT if is_node_name_empty else HTTPStatus.BAD_REQUEST

        assert self.cat.api.http_status_code == expected_status_code, \
            'Expected %s, got %s instead.' % (expected_status_code, self.cat.api.http_status_code)

        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        expected_error_message = "Node with name {} already exists".format(node_names[0]) if is_node_name_empty else \
            "Node name must not be empty."

        assert error_msg_from_response == expected_error_message, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_message, error_msg_from_response)

    def test_last_node_can_not_be_disabled_in_default_cluster_group(self, create_manager_cluster, add_new_cluster_group,
                                                                    add_node_in_cluster_manager):
        """
        NES-12402: [API] Verify last node in the default cluster group can not be disabled
        Scenario Tested:
        [x] Verify last node in the default cluster group can not be disabled.
        """
        cluster_group_ids = [group['id'] for group in self.cat.api.clustergroups.list()['cluster_groups']]

        default_group_id = [group_id for group_id in cluster_group_ids if self.cat.api.clustergroups.get(group_id)[
            'cluster_group']['is_default'] == 1][0]

        assign_agent = [agent for agent in create_manager_cluster['agents']][0]
        cluster_group_id = add_new_cluster_group['id']
        node_details = add_node_in_cluster_manager
        node_name, node_id = node_details['name'], node_details['id']

        self.verify_node_assigned_to_cluster_group(group_id=cluster_group_id, node_id=node_id, node_name=node_name)

        try:
            self.cat.api.clustergroups.assign_agents(cluster_group_id=cluster_group_id, agent_ids=[assign_agent['id']])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            self.cat.api.clustergroups.update(cluster_group_id, {"is_default": True})

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            with pytest.raises(HTTPError):
                self.cat.api.nodes.settings(node_id=node_id, settings={"enabled": 0})

            assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                'Expected 400, got %s instead.' % self.cat.api.http_status_code

            error_msg_from_response = json.loads(self.cat.api.http_text)['error']
            expected_error_message = "Cannot disable the last node in the default cluster group."

            assert error_msg_from_response == expected_error_message, \
                "Expected '{}' error msg, got '{}' instead.".format(expected_error_message, error_msg_from_response)
        finally:
            self.cat.api.clustergroups.update(default_group_id, {"is_default": True})

            self.cat.api.clustergroups.assign_agents(cluster_group_id=API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID,
                                                     agent_ids=[assign_agent['id']])

    def test_child_node_can_be_disabled(self, add_node_in_cluster_manager):
        """
        NES-12411: [API] Verify child node can be disabled

        Scenario Tested:
        [x] Verify child node can be disabled.
        [x] Verify that status changes to "Idle" after disable the node.
        """
        node_details = add_node_in_cluster_manager
        node_name, node_id = node_details['name'], node_details['id']

        self.cat.api.nodes.settings(node_id=node_id, settings={"enabled": 0})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Wait till node gets disable
        wait(lambda: self.cat.api.nodes.get(node_id=node_id)['enabled'] == 0, sleep_seconds=TIME_THIRTY_SECONDS,
             timeout_seconds=TIME_TEN_MINUTES, waiting_for='Cluster agent to get online status!!')

        linked_node_details = self.cat.api.nodes.get(node_id=node_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert linked_node_details['enabled'] == 0, "Failed to disabled the child node."

    def test_verify_child_node_details_in_parent_node(self, add_node_in_cluster_manager):
        """
        NES-12412: [API] Verify child node details in parent node

        Scenario Tested:
        [x] Verify child node details in parent node.
        """
        last_connect_values = []
        node_details = add_node_in_cluster_manager
        node_name, node_id = node_details['name'], node_details['id']

        linked_node_details = self.cat.api.nodes.get(node_id=node_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert linked_node_details, "Failed to get child node details."

        assert all([linked_node_details['status'] == 'online', linked_node_details['max_agents'] == 10000]), \
            "Failed to get the node status and capacity (max agents) value from child node details."

        for _ in range(5):
            details = self.cat.api.nodes.get(node_id=node_id)
            log.debug("Last connect :: {}".format(details['last_connect']))

            last_connect_values.append(details['last_connect'])
            sleep(TIME_SIXTY_SECONDS, reason="waiting for last connect time gets updated")

        assert all([item != last_connect_values[0] for item in last_connect_values[1:len(last_connect_values)]]), \
            "Last connection time is not updated every one minute."


@pytest.mark.usefixtures('disable_cluster_parent_node', 'create_manager_cluster')
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1}], indirect=True)
@pytest.mark.cluster_manager
class TestNodeAgentScan:
    """Tests to verify agent scan when agent is linked to cluster manager via node"""
    cat = None
    backend_log_file_path = os.path.join(ProductConfigs.NessusAgent.File.LOGS_DIR,
                                         ProductConfigs.NessusAgent.File.BACKEND_LOG)

    @staticmethod
    def create_and_lauch_agent_scan(nessus_api: NessusAPI, agent_name: str, scan_file: str = BASIC_AGENT_SCAN_FILE,
                                    template_name: str = "agent_basic", staggered_start_mins: int = 0):
        """
        Helper method to verify agent-scan gets_created and successfully completes
        :param NessusAPI nessus_api: instance of NessusAPI
        :param str agent_name:name of agent
        :param str scan_file: scan-file path
        :param str template_name: scan template name
        :param int staggered_start_mins: adds staggered_start_mins in scan
        """
        agent_scan = create_scan_helper(nessus_api, file_name=scan_file, template_title=template_name,
                                        staggered_start_mins=staggered_start_mins, change_scan_name=True,
                                        **{'agent_name': agent_name, 'agent_status_check': False})[0]

        # Verify that agent scan created successfully
        assert agent_scan['scan']['name'] in [scan['name'] for scan in nessus_api.scans.get_scans()['scans']], \
            "Agent scan was not created successfully when agent linked via node."

        log.info("Agent scan details are : {}".format(agent_scan))
        agent_scan_id = agent_scan['scan']['id']

        nessus_api.scans.launch(scan_id=agent_scan_id)

        return agent_scan_id

    @staticmethod
    def verify_scan_results_after_agent_scan_gets_completed(
            nessus_api: NessusAPI, agent_name: str, cluster_node_id: str, agent_id: str, agent_scan_id: int):
        """
        Helper method to verify agent-scan gets_created and successfully completes
        :param NessusAPI nessus_api: instance of NessusAPI
        :param str agent_name:name of agent
        :param str cluster_node_id: ID of child-node
        :param int agent_scan_id: ID of agent-scan
        :param str agent_id: ID of agent
        """
        agent_details = nessus_api.agents.get_agent_details(agent_id)

        # Verify that agent scan entry gets reflected in node details when agent scan launched
        try:
            wait(lambda: nessus_api.nodes.get(cluster_node_id)['scans'] and nessus_api.nodes.get(
                cluster_node_id)['scans'][0]['status'] == API.Scan.Status.PENDING, timeout_seconds=TIME_FIVE_MINUTES,
                 waiting_for="Scan to get appeared in node details as 'pending' state.")
        except TimeoutExpired:
            raise AssertionError("Scan entry with 'pending' status does not populated in scan details for node.")

        wait_scan_state(api=nessus_api, scan_id=agent_scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)
        scan_details = nessus_api.scans.details(scan_id=agent_scan_id)

        # Verify that agent scan completed successfully.
        assert scan_details['info']['status'] == API.Scan.Status.COMPLETED, "Scan status is not 'completed' yet."

        log.debug("Agent scan details after scan completion are : {}".format(scan_details))

        # Verify that scan_type is 'node'.
        assert scan_details['info']['scan_type'] == "node", "Scan type is not node."

        # Verify that total_nodes count is one
        assert json.loads(scan_details['info']['scan_counts'])['total_from_nodes'] == 1, \
            "Total node agent count should be one."

        # Verify agent scan history count
        assert len(scan_details['history']) == 1, "There should be only one scan history in scan details."

        scan_history_details = [history for history in scan_details['history'] if history['node_name']][0]

        # Verify that schedule_type is 'node' for given scan history details.
        assert scan_history_details['schedule_type'] == "node", "schedule type is not node"

        # Verify that node_id, node_name and node_host details are same as those associated with agent.
        assert scan_history_details['node_id'] == str(
            agent_details['node_id']) and scan_history_details['node_name'] == agent_details[
            'node_name'] and scan_history_details['node_host'] == agent_details['node_host'], \
            "Node_id, Node_name and/or Node_host values are not correct."

        scan_result = nessus_api.scans.get_scan_result_history(agent_scan_id, scan_history_details['history_id'])

        log.debug("Scan result for given history is : {}".format(scan_result))

        # Verify that agent scan vulnerabilities are not empty.
        assert scan_result['vulnerabilities'], "Vulnerabilities are empty."

        # Verify host details in agent scan result for given history details.
        assert len(scan_result['hosts']) == 1 and scan_result['hosts'][0]['hostname'] == agent_name, \
            "Hosts are more than one or hostname is not same as agent name."

    @pytest.mark.xfail(reason="Refer JIRA ID: NES-12098")
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize(('template_name', 'scan_file'), [
        ("agent_basic", BASIC_AGENT_SCAN_FILE), ("agent_advanced", ADVANCED_AGENT_SCAN_FILE)])
    def test_agent_scan_when_agent_linked_via_node(self, create_manager_cluster, link_agent_to_cluster, template_name,
                                                   scan_file):
        """
        NES-12097 : [API Automation] : Create and verify an agent scan when agent is linked to cluster manager via node
        Scenarios Tested:
            [x] Verify that node agent scan can be created, launched and completed successfully.
            [x] Verify that node agent scan result details are non-empty.
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_id = get_agent_id_from_list(api=self.cat.api, agent_name=agent_name)[0]
        agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)

        agent_scan_id = self.create_and_lauch_agent_scan(nessus_api=self.cat.api, agent_name=agent_name,
                                                         scan_file=scan_file, template_name=template_name)

        self.verify_scan_results_after_agent_scan_gets_completed(
            nessus_api=self.cat.api, agent_name=agent_name, cluster_node_id=agent_details['node_id'],
            agent_id=agent_id, agent_scan_id=agent_scan_id)

    @pytest.mark.xfail(reason="Refer JIRA ID: NES-12098")
    @pytest.mark.usefixtures('nessus_api_login', 'add_node_in_cluster_manager', 'link_agent_to_cluster',
                             'add_new_cluster_group')
    def test_agent_can_scan_after_asked_to_relink_by_parent_node(
            self, create_manager_cluster, add_node_in_cluster_manager, add_new_cluster_group, link_agent_to_cluster):
        """
        AGENT-2071: [API] Verify Agent scanning works fine after asked to re-link
        Scenarios tested:
        [X] Verify Agent can be re-linked from NM cluster via parent node
        [x[ Verify Agent shows relink log in backend.log
        [x] Verify that node agent scan can be created, launched and completed successfully.
        [x] Verify that node agent scan result details are non-empty.
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_id = get_agent_id_from_list(api=self.cat.api, agent_name=agent_name)[0]
        agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)
        agent_linked_node_id, agent_linked_node_name = agent_details['node_id'], agent_details['node_name']

        try:
            self.cat.api.clustergroups.assign_node(cluster_group_id=add_new_cluster_group['id'],
                                                   node_id=agent_linked_node_id)

            assert self.cat.api.nodes.get(agent_linked_node_id)['cluster_group_id'] == add_new_cluster_group['id'] and \
                any([agent_linked_node_name in node['name'] for node in self.cat.api.clustergroups.get(
                        add_new_cluster_group['id'])['cluster_group']['nodes']]), \
                "Either Child-node is not assigned to new cluster group or failed to add Child-node in new " \
                "cluster group"

            assert wait_for_specific_entry_in_log_file(
                ssh_instance=SSH(port=agent_port), log_file_path=self.backend_log_file_path, timeout=TIME_TEN_MINUTES,
                log_entry_to_be_verified=Nessus.Agents.AgentLogMessages.ASKED_TO_RELINK_BY_PARENT_NODE,
                sleep_timeout=TIME_TEN_SECONDS), "Waited long for log entry: '{}' to be found in backend.log".format(
                Nessus.Agents.AgentLogMessages.ASKED_TO_RELINK_BY_PARENT_NODE)

            try:
                wait(lambda: self.cat.api.agents.get_agent_details(agent_id=agent_id)['node_id'] !=
                     agent_linked_node_id, timeout_seconds=TIME_FIVE_MINUTES,
                     waiting_for="New Node-ID to change in Agent details")
            except TimeoutExpired:
                raise AssertionError("waited too long to get the newly changed node-id in agent's details.")

            agent_linked_to_new_node_id = self.cat.api.agents.get_agent_details(agent_id=agent_id)['node_id']
            agent_scan_id = self.create_and_lauch_agent_scan(nessus_api=self.cat.api, agent_name=agent_name)

            self.verify_scan_results_after_agent_scan_gets_completed(
                nessus_api=self.cat.api, agent_name=agent_name, cluster_node_id=agent_linked_to_new_node_id,
                agent_id=agent_id, agent_scan_id=agent_scan_id)
        finally:
            self.cat.api.clustergroups.assign_node(cluster_group_id=API.ClusterGroup.DEFAULT_CLUSTER_GROUP_ID,
                                                   node_id=agent_linked_node_id)

    @pytest.mark.xfail(reason="Refer JIRA ID: NES-12098")
    @pytest.mark.usefixtures('nessus_api_login', 'link_agent_to_cluster')
    @pytest.mark.parametrize('staggered_start_mins', [5])
    def test_staggered_scan_in_cluster_setup(self, create_manager_cluster, link_agent_to_cluster, staggered_start_mins):
        """
        AGENT-2094: [API] Verify Agent honors staggering scan delay in clustering
        Scenarios tested:
        [X] Verify staggering scan delay can be performed in clustering
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        ssh = SSH(port=agent_port)
        enable_debug_logs_for_agent(ssh_instance=ssh)

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        agent_id = get_agent_id_from_list(api=self.cat.api, agent_name=agent_name)[0]
        agent_details = self.cat.api.agents.get_agent_details(agent_id=agent_id)

        agent_scan_id = self.create_and_lauch_agent_scan(nessus_api=self.cat.api, agent_name=agent_name,
                                                         staggered_start_mins=staggered_start_mins)

        assert wait_for_specific_entry_in_log_file(
            ssh_instance=ssh, log_file_path=self.backend_log_file_path, timeout=TIME_TEN_MINUTES,
            log_entry_to_be_verified=Nessus.Agents.AgentLogMessages.STAGGERED_START_CALCULATION,
            sleep_timeout=TIME_TEN_SECONDS), "Waited long for log entry: '{}' to be found in backend.log".format(
            Nessus.Agents.AgentLogMessages.STAGGERED_START_CALCULATION)

        self.verify_scan_results_after_agent_scan_gets_completed(
            nessus_api=self.cat.api, agent_name=agent_name, cluster_node_id=agent_details['node_id'],
            agent_id=agent_id, agent_scan_id=agent_scan_id)

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("restart_service", [True, False])
    def test_agent_scan_not_end_up_with_aborted_status(self, restart_service):
        """
        NES-12446: Automated tests for Cluster scan abort issue

        Scenario Tested:
        [x] Verify that Scan should not end up with abort status if Scan lasts longer than the node “timeout” period
        """
        is_node_restart = False
        agent_scan_id = None
        group_details = {}

        scanner_id = self.cat.api.scanners.get_list()['scanners'][0]['id']
        agent_details = self.cat.api.agents.get_agents(scanner_id=scanner_id)['agents']
        last_connected_agents = sorted([agent['last_connect'] for agent in agent_details], reverse=True)[:2]

        linked_agents_id = [agent['id'] for agent in agent_details if agent['last_connect'] in last_connected_agents]
        associated_node_name = self.cat.api.agents.get_agent_details(linked_agents_id[0])['node_name']

        for agent in agent_details:
            if agent['status'] != 'online':
                node_restart = subprocess.check_output("docker exec {} supervisorctl restart nessusd".format(
                    associated_node_name).split(), stderr=subprocess.PIPE).decode('utf-8')
                log.debug("Node restart output is : {}".format(node_restart))

                is_node_restart = True
                break

        # Wait till agent become online
        if is_node_restart:
            for agent in agent_details:
                wait(lambda: self.cat.api.agents.get_agent_details(agent['id'])['status'] == 'online',
                     timeout_seconds=TIME_TEN_MINUTES * 2, sleep_seconds=TIME_THIRTY_SECONDS,
                     waiting_for='Cluster agent to get online status!!')

        scan_cutoff_output = fix.set(key="agent_cluster_scan_cutoff", value="300")
        log.debug("'agent_cluster_scan_cutoff' command output :: {}".format(scan_cutoff_output))

        try:
            group_details = self.cat.api.agent_groups.create(scanner_id=scanner_id,
                                                             name=random_name(prefix='agent-group_'))

            for agent_id in linked_agents_id:
                self.cat.api.agent_groups.add_agent(scanner_id=scanner_id, group_id=group_details['id'],
                                                    agent_id=agent_id)

            scan_model = ScanModel()
            scan_model.name = random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_AGENT))
            scan_model.default_template = Nessus.TemplateNames.ADVANCED_AGENT
            scan_model.agent_group_id = [group_details['id']]
            agent_scan = self.cat.api.scans.create(scan_model)

            # Verify that agent scan created successfully
            assert agent_scan['scan']['name'] in [scan['name'] for scan in self.cat.api.scans.get_scans()['scans']], \
                "Agent scan was not created successfully when agent linked via node."

            agent_scan_id = agent_scan['scan']['id']
            self.cat.api.scans.launch(scan_id=agent_scan_id)

            ssh = SSH()

            if restart_service:
                restart_nessus_op = ssh.execute(command="supervisorctl restart nessusd")
                log.info("Restart Nessus service output :: {}".format(restart_nessus_op))

                wait_for_scanner_to_be_ready(api=self.cat.api)

            assert wait_scan_state(api=self.cat.api, scan_id=agent_scan_id, end_state=API.Scan.Status.COMPLETED,
                                   timeout=TIME_FIVE_MINUTES), "Scan is not getting completed within given time frame."

            scan_details = self.cat.api.scans.details(scan_id=agent_scan_id)

            # Verify that agent scan completed successfully.
            assert scan_details['info']['status'] == API.Scan.Status.COMPLETED, "Scan status is not 'completed' yet."

            backend_log = ssh.execute("cat /opt/nessus/var/nessus/logs/backend.log")
            log.debug("Logs from backend.log file :: {}".format(backend_log))

            assert [True for output in backend_log if "Aborting scan" not in output], \
                "Expected error message is detected in backend.log file"
        finally:
            self.cat.api.agent_groups.delete(scanner_id=scanner_id, group_id=group_details['id'])

            self.cat.api.scans.delete(scan_id=agent_scan_id)


@pytest.mark.usefixtures('disable_cluster_parent_node', 'create_manager_cluster')
@pytest.mark.parametrize('create_manager_cluster', [{'total_nodes': 1}], indirect=True)
@pytest.mark.cluster_manager
class TestNodeBlackoutWindow:
    """Tests to verify blackout window when agent is linked to cluster manager via node"""
    cat = None
    backend_log_file_path = os.path.join(ProductConfigs.NessusAgent.File.LOGS_DIR,
                                         ProductConfigs.NessusAgent.File.BACKEND_LOG)

    def create_agent_scan_and_verify_scan_behavior_for_created_blackout_window(self, nessus_api: NessusAPI,
                                                                               agent_name: str, ssh_instance: SSH):
        """
        Helper method to verify agent-scan gets_created and successfully completes
        :param NessusAPI nessus_api: instance of NessusAPI
        :param str agent_name:name of agent
        :param SSH ssh_instance: instance of SSH
        """
        agent_scan = create_scan_helper(nessus_api, file_name=BASIC_AGENT_SCAN_FILE, template_title="agent_basic",
                                        change_scan_name=True, **{'agent_name': agent_name,
                                                                  'agent_status_check': False})[0]
        # Verify that agent scan created successfully
        assert agent_scan['scan']['name'] in [scan['name'] for scan in nessus_api.scans.get_scans()['scans']], \
            "Agent scan was not created successfully when agent linked via node."

        agent_scan_id = agent_scan['scan']['id']
        nessus_api.scans.launch(scan_id=agent_scan_id)

        try:
            wait(lambda: nessus_api.scans.details(scan_id=agent_scan_id) and
                 nessus_api.scans.details(scan_id=agent_scan_id)['info'] and nessus_api.scans.get_status(
                 scan_id=agent_scan_id) != API.Scan.Status.PENDING, timeout_seconds=TIME_TWO_MINUTES,
                 waiting_for="Scan remains in 'pending' state, since bw_permanent_blackout_window is enabled")
        except TimeoutExpired:
            assert nessus_api.scans.get_status(scan_id=agent_scan_id) == API.Scan.Status.PENDING, \
                "Scan entry with 'pending' status does not populated in scan details for node."

        assert wait_for_specific_entry_in_log_file(
            ssh_instance=ssh_instance, log_file_path=self.backend_log_file_path, sleep_timeout=TIME_TEN_SECONDS,
            log_entry_to_be_verified='{}|{}'.format(SCAN_DISABLED_IN_BW, Messages.NessusAgent.SCAN_DISABLED_IN_FREEZE),
            timeout=TIME_TEN_MINUTES), "Waited long for log entry: '{}' to be found in backend.log".format(
            Messages.NessusAgent.SCAN_DISABLED_IN_FREEZE)

    @pytest.mark.usefixtures('nessus_api_login', 'link_agent_to_cluster')
    def test_verify_scanning_gets_blocked_when_enabled_permanent_blackout(self, create_manager_cluster,
                                                                          link_agent_to_cluster):
        """
        AGENT-2066 : [API Automation] : Verify Agent honors permanent blackout window scanning in clustered mode
        Scenarios Tested:
            [x] Verify that permanent blackout window can be created
            [x] Verify that newly created agent scan remains in "pending" state
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        default_config_settings = self.cat.api.agents.get_config()
        payload = {"bw_permanent_blackout_window": True}
        try:
            edit_config_settings = self.cat.api.agents.edit_config(data=payload)

            assert edit_config_settings["bw_permanent_blackout_window"] == payload.get(
                "bw_permanent_blackout_window"), "Agent setting does not set for bw_permanent_blackout_window"

            self.create_agent_scan_and_verify_scan_behavior_for_created_blackout_window(
                nessus_api=self.cat.api, agent_name=agent_name, ssh_instance=SSH(port=agent_port))
        finally:
            self.cat.api.agents.edit_config(default_config_settings)
            wait_for_scanner_to_be_ready(api=self.cat.api)

    @pytest.mark.usefixtures('nessus_api_login', 'create_scheduled_blackout_window_and_wait_till_activated',
                             'link_agent_to_cluster')
    @pytest.mark.parametrize("create_scheduled_blackout_window_and_wait_till_activated", [{'bw_duration_minutes': 7}],
                             indirect=True)
    def test_verify_scanning_gets_blocked_when_enabled_scheduled_blackout(
            self, create_manager_cluster, create_scheduled_blackout_window_and_wait_till_activated,
            link_agent_to_cluster):
        """
        AGENT-2066 : [API Automation] : Verify Agent scanning is blocked when scheduled scan blackout is enabled in
                                        parent node
        Scenarios Tested:
            [x] Verify that newly created agent scan remains in "pending" state
        """
        cluster_node = create_manager_cluster['nodes'][0]
        agent_name, agent_port = link_agent_to_cluster['agent_name'], link_agent_to_cluster['agent_port']

        assert wait_for_agent_to_get_online_in_cluster(nessus_api=self.cat.api, agent_name=agent_name,
                                                       cluster_child_node_name=cluster_node['name']), \
            "Either Agent did not reflected in NM or waited long to get Agent online"

        self.create_agent_scan_and_verify_scan_behavior_for_created_blackout_window(
            nessus_api=self.cat.api, agent_name=agent_name, ssh_instance=SSH(port=agent_port))
