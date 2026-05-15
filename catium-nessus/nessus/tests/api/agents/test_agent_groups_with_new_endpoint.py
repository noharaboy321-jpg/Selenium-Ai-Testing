"""
Nessus Agent Groups Endpoints Unit Test

:copyright: Tenable Network Security, 2018
:date: August 17, 2018
:last_modified: Nov 09, 2020
:author: @jamreliya, @kpanchal

Uses /agents endpoint

"""
import json
from http import HTTPStatus

import pytest
from requests.exceptions import HTTPError

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import load_testdata
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from nessus.helpers.metadata.agent import get_agent_id
from nessus.helpers.server import expect_http_error

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentGroupsEndpoint:
    """
    Test for New Agent Group Endpoint. STA-7
    """

    cat = None

    # API_Tested# GET /agent-groups/
    # API_Tested# POST /agent-groups/
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_create_agent_group(self, create_agent_group_with_new_endpoint):
        """
        Verifies that an agent group can be created

        Scenarios tested:
        [X] Get agent groups
        [X] Create agent group
        [ ] Try creating an agent group with a name that already exists (should fail)

        note:: #STA-7
        """
        group_list = self.cat.api.agent_groups.agent_group_list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert create_agent_group_with_new_endpoint[0]['id'] in [group['id'] for group in group_list['groups']], \
            'Agent Group is not created successfully.'

    # API_Tested# DELETE /agent-groups/
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),
                                                                       random_name(prefix='agent-group-'))],
                             indirect=True)
    def test_delete_agent_groups(self, create_agent_group_with_new_endpoint):
        """
        Verifies that an agent groups can be deleted in bulk

        Scenarios tested:
        [X] Delete agent groups in bulk
        [ ] Delete empty list of IDs
        [ ] Delete IDs that include an invalid ID
        [ ] Delete agent group that does not exist

        note:: #STA-7
        """
        # group ids of created agent groups
        created_group_ids = [group['id'] for group in create_agent_group_with_new_endpoint]
        self.cat.api.agent_groups.delete_groups(id_list=created_group_ids)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # verify agent group deleted successfully
        group_list = self.cat.api.agent_groups.agent_group_list()

        if group_list['groups']:
            group_ids = [group['id'] for group in group_list['groups']]
            assert not any(deleted_id in group_ids for deleted_id in created_group_ids), \
                'Agent Group is not deleted successfully.'

    # API_Tested# PUT /agent-groups/{group_id}
    # API_Tested# GET /agent-groups/{group_id}
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_edit_agent_group(self, create_agent_group_with_new_endpoint):
        """
        Verifies that an agent group can be edited

        Scenarios tested:
        [X] Agent group edited
        [ ] Try to update agent group with invalid data
        [ ] Try to update an agent group and change it's name to a name that already exists

        note:: #STA-7
        """
        # verify created group exist in list
        group_id = create_agent_group_with_new_endpoint[0]['id']
        group_list = self.cat.api.agent_groups.agent_group_list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert group_id in [group['id'] for group in group_list['groups']], \
            'Agent Group is not created successfully.'

        # edit group name
        payload = {"name": random_name(prefix='edited-agent-group-')}
        self.cat.api.agent_groups.update_agent_group(group_id=group_id, data=payload)

        edited_group_details = self.cat.api.agent_groups.get_agent_group(group_id=group_id)

        assert edited_group_details['name'] == payload['name'], 'Unable to edit group details'

    # API_Tested# DELETE /agent-groups/{group_id}
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_delete_agent_group(self, create_agent_group_with_new_endpoint):
        """
        Verifies that an agent group can be deleted

        Scenarios tested:
        [X] Agent group deleted
        [ ] Delete an agent group that does not exist

        note:: #STA-7
        """
        # verify created group exist in list
        created_group_id = create_agent_group_with_new_endpoint[0]['id']
        group_list = self.cat.api.agent_groups.agent_group_list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert created_group_id in [group['id'] for group in group_list['groups']], \
            'Agent Group is not created successfully.'

        self.cat.api.agent_groups.delete_agent_group(group_id=created_group_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # verify agent group deleted successfully
        group_list = self.cat.api.agent_groups.agent_group_list()['groups']

        if group_list:
            group_ids = [group['id'] for group in group_list]
            assert created_group_id not in group_ids, 'Agent Group is not deleted successfully.'

    # API_Tested# GET /agent-groups/{group_id}/agents/
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_get_agent(self, create_agent_group_with_new_endpoint, add_agent_locally):
        """
        Verifies agents details can be retrieved from agent groups

        Scenarios tested:
        [X] Get agent details from agent groups
        [ ] Get agent details for group that does not exist

        Note: Verify the data retrieved is expected (e.g. empty list, or null)

        note:: #STA-7
        """
        # Create a agent-group for a particular scanner and get its ID
        group_id = create_agent_group_with_new_endpoint[0]['id']

        # Get agent id and add a fake agent to the group
        agent_id = get_agent_id(self.cat.api.agents.get_agents(1), add_agent_locally['name'])
        self.cat.api.agent_groups.add_agent(1, group_id, agent_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        agent_list = self.cat.api.agent_groups.list_agents(group_id=group_id)

        assert (agent_list['agents']), 'No Agent found from Agent Group'

        assert agent_list['agents'][0]['id'] == agent_id, \
            'Agent ID  retrieved from Agent Group mismatched from agent id of  added agent'

        # delete created agent
        self.cat.api.agents.delete_agent(agent_id=agent_id)

    # API_Tested# DELETE /agent-groups/{group_id}/agents/{agent_id}
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_del_agent_using_new_endpoint(self, create_agent_group_with_new_endpoint, add_agent_locally):
        """
        Verifies agents can be deleted from agent groups

        Scenarios tested:
        [X] Delete agents from agent groups
        [ ] Delete an agent that does not exist
        [ ] Delete an agent from a group that does not exist

        note:: #STA-7
        """
        # Create a agent-group for a particular scanner and get its ID
        group_id = create_agent_group_with_new_endpoint[0]['id']

        # Get agent id and add a fake agent to the group
        agent_id = get_agent_id(self.cat.api.agents.get_agents(1), add_agent_locally['name'])
        self.cat.api.agent_groups.add_agent(1, group_id, agent_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        self.cat.api.agent_groups.delete_this_agent(group_id=group_id, agent_id=agent_id)
        agent_list = self.cat.api.agent_groups.list_agents(group_id=group_id)['agents']

        if agent_list:
            available_agent_ids = [agent['id'] for agent in agent_list]

            assert agent_id not in available_agent_ids, 'Agent is not deleted successfully.'

        # delete created agents
        self.cat.api.agents.delete_agent(agent_id=agent_id)

    # API_Tested# PUT /agent-groups/{group_id}/agents/{agent_id}
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_add_agent_to_agent_group(self, create_agent_group_with_new_endpoint, add_agent_locally):
        """
        Verifies agents can be added to agent groups

        Scenarios tested:
        [X] Agents added to agent groups
        [ ] Add agent to a group that does not exist
        [ ] Add agent that does not exist to a group

        note:: #STA-7
        """
        # Create a agent-group and get its ID
        group_id = create_agent_group_with_new_endpoint[0]['id']

        # create fake agent and get its id
        agent_id = get_agent_id(self.cat.api.agents.get_agents(1), add_agent_locally['name'])

        # add agent to agent-group
        self.cat.api.agent_groups.update_agent(group_id=group_id, agent_id=agent_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # get list of agents from created agent group
        agent_list = self.cat.api.agent_groups.list_agents(group_id=group_id)

        assert (agent_list['agents']), 'No Agent found from Agent Group'

        assert agent_list['agents'][0]['id'] == agent_id, \
            'Agent ID  retrieved from Agent Group mismatched from agent id of  added agent'

        # delete created agent
        self.cat.api.agents.delete_agent(agent_id=agent_id)

    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_verify_last_modify_time_for_agent_group(self, create_agent_group_with_new_endpoint,
                                                     add_agent_locally):
        """
        NES-12162 : [API] Verify when Agent group is edited, "Last Modified" time is updated
        Scenario Tested:
            [x] Verify that last modify time gets updated for agent group
                if group name is modified or agent gets added to agent group.
        """
        group_id = create_agent_group_with_new_endpoint[0]['id']
        last_modify_time_after_creation = self.cat.api.agent_groups.details(scanner_id=1, group_id=group_id)[
            'last_modification_date']

        sleep(1, reason="Waiting for one second to make sure the time difference "
                        "between agent group creation and update.")

        # Modify Agent group name
        self.cat.api.agent_groups.update_agent_group(group_id=group_id,
                                                     data={"name": random_name(prefix='edited-agent-group-')})
        last_modify_time_after_name_update = self.cat.api.agent_groups.details(scanner_id=1, group_id=group_id)[
            'last_modification_date']

        # Verify that "Last Modified" time is updated for agent group after updating agent group name.
        assert last_modify_time_after_name_update > last_modify_time_after_creation, \
            "'Last Modify' time not updated after updating agent group name."

        sleep(1, reason="Waiting for one second to make sure the time difference between these events :"
                        "agent group name modify and adding agents to agent group.")

        # Add agent to agent-group
        self.cat.api.agent_groups.update_agent(group_id=group_id, agent_id=get_agent_id(self.cat.api.agents.get_agents(
            1), add_agent_locally['name']))

        last_modify_time_after_adding_agent = self.cat.api.agent_groups.details(scanner_id=1, group_id=group_id)[
            'last_modification_date']

        # Verify that "Last Modified" time is updated after adding agent to agent group
        assert last_modify_time_after_adding_agent > last_modify_time_after_name_update > \
               last_modify_time_after_creation, "'Last Modify' time not updated after adding agent to agent group."

    # API_Tested# PUT /agent-groups/agents
    @pytest.mark.parametrize('nessus_create_nessus_agent',
                             [[3, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json')]],
                             indirect=True)
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    @pytest.mark.parametrize('filter_dict', [
        {"filter.0.filter": "name", "filter.0.quality": "match", "filter.0.value": "three"}])
    def test_agents_added_to_agent_group_using_filters(self, nessus_create_nessus_agent,
                                                       create_agent_group_with_new_endpoint, filter_dict):
        """
        NES-12232 : [API] Verify bulk Agent addition/deletion in an Agent group

        Scenario Tested:
            [x] Verify that agents can be added to agent group using the filter
        """
        agent_ids = nessus_create_nessus_agent
        agent_group_id = create_agent_group_with_new_endpoint[0]['id']

        self.cat.api.agent_groups.add_agents_using_filter(group_id=agent_group_id, filter_dict=filter_dict)

        assert set([agent['id'] for agent in self.cat.api.agent_groups.get_agent_group(group_id=agent_group_id)[
            'agents']]) == set(agent_ids), "Agents are not added in agent group using filters"

    # API_Tested# PUT /agent-groups/agents
    @pytest.mark.parametrize('nessus_create_nessus_agent',
                             [[3, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json')]],
                             indirect=True)
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    @pytest.mark.parametrize('test_data', [
        {'filter': {"filter.0.filter": "name", "filter.0.quality": "match", "filter.0.value": "nessus"},
         "group_id": True, 'response': {"error_code": HTTPStatus.NOT_FOUND, "look_for": "No agents found."}},
        {'filter': {"filter.0.filter": "status", "filter.0.quality": "eq", "filter.0.value": "online"},
         "group_id": False, 'response': {"error_code": HTTPStatus.BAD_REQUEST, "look_for": "Missing groups."}}])
    def test_agents_added_to_agent_group_with_empty_filter_output_or_incorrect_group_id(
            self, nessus_create_nessus_agent, create_agent_group_with_new_endpoint, test_data):
        """
        NES-12232 : [API] Verify bulk Agent addition/deletion in an Agent group

        Scenarios Tested:
            [x] Verify that agents add to agent group gives error when
                it uses filter which has no agents as output
            [x] Verify that agents add to agent group gives error when there is not any group id given.
        """
        agent_group_id = create_agent_group_with_new_endpoint[0]['id'] if test_data['group_id'] else 0

        # Verify that adding bulk agents to agent group gives error
        # when the filter has zero agents as output or group id does not given in API request.
        with expect_http_error(code=test_data['response']['error_code'], look_for=test_data['response']['look_for']):
            self.cat.api.agent_groups.add_agents_using_filter(group_id=agent_group_id,
                                                              filter_dict=test_data['filter'])

    # API_Tested# DELETE /agent-groups/{agent_group_id}/agents
    @pytest.mark.parametrize('nessus_create_nessus_agent',
                             [[3, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json')]],
                             indirect=True)
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    @pytest.mark.parametrize('filter_dict', [
        {"filter.0.filter": "status", "filter.0.quality": "eq", "filter.0.value": "online"}])
    def test_bulk_agents_removed_from_agent_group(self, nessus_create_nessus_agent,
                                                  create_agent_group_with_new_endpoint, filter_dict):
        """
        NES-12232 : [API] Verify bulk Agent addition/deletion in an Agent group

        Scenarios Tested:
            [x] Verify that bulk agents can be deleted from agent group using filter
        """
        agent_ids = nessus_create_nessus_agent
        agent_group_id = create_agent_group_with_new_endpoint[0]['id']
        self.cat.api.agent_groups.add_agents(group_id=agent_group_id, agent_ids=agent_ids)

        # Verify that agent added successfully in agent group
        assert set([agent['id'] for agent in self.cat.api.agent_groups.get_agent_group(group_id=agent_group_id)[
            'agents']]) == set(agent_ids), "Agents are not added in agent group using filters"

        self.cat.api.agent_groups.delete_agents_using_filter(group_id=agent_group_id, filter_dict=filter_dict)

        # Verify that agent removed from agent group using filter
        assert not self.cat.api.agent_groups.get_agent_group(group_id=agent_group_id)['agents'], \
            "Agent/s did not get deleted from agent group using filter."

    # NES-8900
    # API_Tested# GET /scanners/{scanner_id}/agent-groups/{group_id}/agents
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[2, 'None']], indirect=True)
    def test_get_agents_from_agent_group(self, nessus_create_nessus_agent, create_agent_group):
        """
            NES-8900: Create tests for scanners GET /scanners/{scanner_id}/agent-groups/{group_id}/agents

            Scenarios tested:
            [x] Successfully get the list of agents from agent group
        """
        group_id = create_agent_group['id']
        added_agent_ids = nessus_create_nessus_agent

        self.cat.api.agent_groups.add_agents(group_id=group_id, agent_ids=added_agent_ids)
        agent_list = self.cat.api.scanners.get_agent_list_from_agent_group(group_id)["agents"]

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        agent_ids = [agent['id'] for agent in agent_list]

        for added_agent in added_agent_ids:
            assert added_agent in agent_ids, 'Agent is not in the list of agents'

    # API_Tested# POST /agent-groups/
    # API_Tested# DELETE /agent-groups/{group_id}
    def test_duplicate_or_empty_agent_group_name_not_allowed(self):
        """
        NES-12158: [Negative][API] Verify duplicate Agent group names are not allowed

        Scenarios tested:
        [X] Verify duplicate and empty Agent group names are not allowed.
        """
        agent_group_name = random_name(prefix='agent-group-')

        create_agent_group_details = {}

        if agent_group_name and agent_group_name != 'None':
            create_agent_group_details = self.cat.api.agent_groups.create_agent_group(name=agent_group_name)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

        with pytest.raises(HTTPError):
            self.cat.api.agent_groups.create_agent_group(name=agent_group_name)

        expected_status_code = HTTPStatus.BAD_REQUEST if agent_group_name is None else HTTPStatus.CONFLICT

        assert self.cat.api.http_status_code == expected_status_code, \
            'Expected %s, got %s instead.' % (expected_status_code, self.cat.api.http_status_code)

        if agent_group_name is None:
            expected_error_msg = "Invalid 'name' field: missing"
        elif agent_group_name != 'None':
            expected_error_msg = "An agent group with that name already exists"
        else:
            expected_error_msg = "\"\" is a reserved agent group name."

        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)

        if agent_group_name and agent_group_name != 'None':
            self.cat.api.agent_groups.delete_agent_group(group_id=create_agent_group_details['id'])
