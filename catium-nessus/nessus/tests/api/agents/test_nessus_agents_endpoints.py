"""
Nessus Agents Endpoints Unit Test

:copyright: Tenable Network Security, 2018
:date: June, 2017
:last_modified: July 15, 2020
:author: @smadan, @kpanchal

Uses /scanners/{scanner_id}/agent-groups endpoint
"""
from http import HTTPStatus

import pytest
from waiting import TimeoutExpired

from catium.lib.const import WAIT_NORMAL, TIME_THREE_MINUTES
from catium.lib.util import util
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.metadata.agent import get_agent_id
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import API, Scanner


@pytest.fixture()
def check_server_status():
    """Checks the server status if it is in ready state or not."""
    try:
        wait_for_scanner_status(api=NessusAPI(), status=API.Status.READY, timeout=TIME_THREE_MINUTES,
                                msg=Scanner.Strings.AVAILABILITY_OF_SCANNER, sleep_interval=WAIT_NORMAL)
    except TimeoutExpired:
        pytest.xfail(reason='Nessus server is not available.')


@pytest.mark.nessus_mat
@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusAgentEndpoint:
    """Tests for Nessus agent Endpoint"""
    cat = None

    # API_Tested# POST /agent-groups
    def test_create_agent_group(self, create_agent_group):
        """
        Verifies that an agent group can be created

        Scenarios tested:
        [X] Create an agent group
        [ ] Invalid values for agent groups (duplicate agent group names)

        note:: #NQA-859(Agent-Groups - Create)
        """
        # Create a agent-group for a particular scanner and get its ID
        agent_group_id = create_agent_group['id']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get list of agent-group
        groups = self.cat.api.agent_groups.get_list(1)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        group = groups['groups']
        found = False
        for items in group:
            if items['id'] == agent_group_id:
                found = True
                break

        # Verifies agent-group created
        assert found, "Agent id's does not match"

    @pytest.mark.parametrize('nessus_create_nessus_agent_group', [[2]], indirect=True)
    # API_Tested# GET /agent-groups/{group_id}
    def test_get_agent_groups(self, nessus_create_nessus_agent_group):
        """
        Verifies that details of agent group retrieved

        Scenarios tested:
        [X] Get agent group details
        [ ] Get details for a group that doesn't exist

        note:: #NQA-865(Agent-Groups - List agent groups)
        """
        groups = self.cat.api.agent_groups.get_list(1)
        returned_agent_group_ids = []
        for item in groups['groups']:
            returned_agent_group_ids.append(item['id'])
        created_group_ids = []
        for item in nessus_create_nessus_agent_group:
            created_group_ids.append(item)

        assert set(created_group_ids).issubset(set(returned_agent_group_ids)), \
            "Created group names do not match with returned group names"
        assert len(groups['groups']) > 0, 'No groups returned'
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# PUT /agent-groups/{group_id}/agents/{agent_id}
    def test_add_agent(self, create_agent_group, add_agent_locally):
        """
        Verifies if a new agent is added

        Scenarios tested:
        [X] Create new agent in agent group
        [ ] Add agent to a group that does not exist
        [ ] Add agent that does not exist to a group

        note:: #NQA-860(Agent-Groups - Add-Agent )
        """
        # Create a agent-group for a particular scanner and get its ID
        group_id = create_agent_group['id']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get agent id and add a fake agent to the group
        agent_id = get_agent_id(self.cat.api.agents.get_agents(1), add_agent_locally['name'])
        self.cat.api.agent_groups.add_agent(1, group_id, agent_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verifies if agent added to the group
        details = self.cat.api.agent_groups.details(scanner_id=1, group_id=group_id)
        agents = details['agents']
        found = False
        for items in agents:
            if items['id'] == agent_id:
                found = True
                break

        assert found, "Agent not added successfully"

        # Deletes the fake agent
        self.cat.api.agents.delete(1, agent_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# DELETE /scanners/{scanner_id}/agents/{agent_id}
    def test_delete_agent(self, add_agent_locally):
        """
        Verifies an agent is deleted from list

        Scenarios tested:
        [X] Delete agent from list
        [ ] Delete non-existent agent from list

        note:: #NQA-867(Agents - Delete an agent)
        """
        # Get agent id and add a fake agent to the group
        agent_name = add_agent_locally['name']
        agent_id = get_agent_id(self.cat.api.agents.get_agents(1), agent_name)
        # Delete fake agent
        self.cat.api.agents.delete(1, agent_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verifies agent deleted successfully
        details = self.cat.api.agents.get_agents(1)
        agent = details['agents']

        found = False
        if agent is None:
            found = False
        else:
            for items in agent:
                if items['id'] == agent_id:
                    found = True
                    break

        assert not found, 'Agent "%s" has not been deleted successfully' % agent_name

    # API_Tested# DELETE /agent-groups/{group_id}/agents/{agent_id}
    def test_delete_agent_from_agent_groups(self, create_agent_group, add_agent_locally):
        """
        Verifies if agent is deleted from an agent group

        Scenarios tested:
        [X] Delete agent from a group
        [ ] Delete non-existent agent from group ID
        [ ] Delete non-existent agent from non-existent group ID

        note:: #NQA-863(Agent-Groups - Delete-Agent)
        """
        # Get agent id and add a fake agent to the group
        agent_id = get_agent_id(self.cat.api.agents.get_agents(1), add_agent_locally['name'])
        group_id = create_agent_group['id']
        self.cat.api.agent_groups.add_agent(1, group_id, agent_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Deletes agent from agent group
        self.cat.api.agent_groups.delete_agent(1, group_id, agent_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get Details of agent group
        details = self.cat.api.agent_groups.details(1, group_id)
        agents = details['agents']

        # Verifies agent deleted
        assert agents is None, 'Agent "%s" from agent-group has not been deleted successfully' % agent_id

    # API_Tested# DELETE /agent-groups/{group_id}
    def test_delete_agent_groups(self, create_agent_group):
        """
        Verifies that an agent group can be deleted

        Scenarios tested:
        [X] Delete agent group
        [ ] Delete agent group that does not exist
        [ ] Delete empty list of IDs
        [ ] Delete IDs that include an invalid ID

        note:: #NQA-862(Agent-Groups - Delete)
        """
        # Create a random agent-group
        agent_group_id = create_agent_group['id']
        # Delete that agent-group
        self.cat.api.agent_groups.delete(1, agent_group_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get list of agent-groups
        details = self.cat.api.agent_groups.get_list(1)
        agent_groups = details['groups']

        found = False
        if agent_groups is None:
            found = False
        else:
            for items in agent_groups:
                if items['id'] == agent_group_id:
                    found = True
                    break

        # Verifies if agent-group has been deleted
        assert not found, 'Agent "%s" has not been deleted successfully from the group' % agent_group_id

    # API_Tested# GET /scanners/{scanner_id}/agents
    def test_get_agents(self, check_server_status, add_agent_locally):
        """
        Verifies that a list of agents can be retrieved

        Scenarios tested:
        [X] Get a list of agents
        [ ] Get a list of agents from a scanner ID that does not exist

        note:: #NQA-868(Agents - List agents)
        """
        agents = self.cat.api.agents.get_agents(1)
        assert 'agents' in agents, 'Expected "agents" field to be present in response'
        found = False
        for agent in agents['agents']:
            if agent.get('name') == add_agent_locally['name']:
                found = True
                break
        assert found, 'Agent "%s" not found in agent list' % add_agent_locally['name']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# GET /scanners/{scanner_id}/agent-groups/{group_id}
    def test_details_group(self, create_agent_group):
        """
        Verifies the details of agent groups

        Scenarios tested:
        [X] Get agent group details

        Note: Verify the data retrieved is expected (e.g. empty list, or null)

        note:: #NQA-864(Agent-Groups - List details)
        """
        # Get newly created agent-group details
        details = self.cat.api.agent_groups.details(1, create_agent_group['id'])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verifies that list of agent-group details exist
        assert len(details) > 0, 'Agent-group details does not exist'

    # API_Tested# PUT /scanners/{scanner_id}/agent-groups/{group_id}
    def test_configure_agent_groups(self, create_agent_group):
        """
        Verifies that an agent group can be configured

        Scenarios tested:
        [X] Configured an agent group
        [ ] Configure with invalid values

        note:: #NQA-861(Agent-Groups - Configure )
        """
        group_id = create_agent_group['id']
        agent_name = util.random_name('agent_group-')
        self.cat.api.agent_groups.configure(1, group_id, agent_name)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get details of agent-group
        details = self.cat.api.agent_groups.details(1, group_id)

        # Verifies agent name has been updated
        assert details['name'] == agent_name, 'Agent name "%s" has not been updated' % agent_name

    @pytest.mark.parametrize("num_of_agent_groups", [2], indirect=True)
    def test_agent_link_with_groups(self, nessus_api_handler: NessusAPI, create_list_of_agent_groups):
        """
        Verifies that when an agent is linked with a mixture of valid and invalid groups, that the link works as much
        as possible, and that we receive a warning about some groups not being added.
        TODO: Check the log message on splunk when the infrastructure is available to do so

        Scenarios tested:
        [X] Link an agent with valid and invalid groups (only the valid parts should work)
        """

        group_names = [g["name"] for g in create_list_of_agent_groups]
        dne_group_names = ["ThisGroupDoesNotExist1", "ThisGroupDoesNotExist2"]

        # Add the agent.  It should be added successfully, and we should get an warning messages about the DNE groups
        agent = nessus_api_handler.agents.add_fake_agent(groups=group_names + dne_group_names)

        assert self.cat.api.http_status_code == HTTPStatus.OK
        assert "msg" in agent
        assert all(dne_group_name in agent["msg"] for dne_group_name in dne_group_names), \
            "DNE group was not in the returned message (msg=\"{}\")".format(agent["msg"])
        assert all(group_name not in agent["msg"] for group_name in group_names), \
            "Existing group was in the returned message (msg={}, existing_groups={})".format(agent["msg"], group_names)

        # Get each group and and verify that the agent is in each one
        for group in create_list_of_agent_groups:
            group_details = nessus_api_handler.agent_groups.details(1, group['id'])
            assert self.cat.api.http_status_code == HTTPStatus.OK
            assert group_details["agents"][0]["uuid"] == agent["agent_uuid"]
