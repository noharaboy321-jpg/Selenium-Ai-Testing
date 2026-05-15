"""
:copyright: Tenable Network Security, 2017
:date: June 19, 2017
:last_modified: Mar 16, 2022
:author: @cdombrowski, @kpanchal
"""
from http import HTTPStatus

import pytest

from catium.lib.log import create_logger
from nessus.lib.config import NessusConfig

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/nessus_qa/test_data/test_nessus_agents.json'])
@pytest.mark.usefixtures('nessus_api_login', 'load_test_data')
class TestNessusAgents(object):
    """
    Class to handle testing Nessus Agents.  This includes tests such as creating, editing, and deleting an agent.
    """

    cat = None

    # API_Tested# DELETE /agents
    @pytest.mark.parametrize('nessus_create_nessus_agent',
                             [[2, NessusConfig.CAT_NESSUS_MANAGER_LINKING_KEY]], indirect=True)
    def test_nessus_agents_delete_multiple(self, nessus_create_nessus_agent):
        """
        Tests that we are able to delete multiple agents from Nessus Manager at once.

        See: https://<NessusID>:8834/api#/resources/agents/delete-multiple
        """
        old_agent_list = self.cat.api.agents.get_agents(scanner_id=1)

        self.cat.api.agents.delete_multiple(agent_ids=nessus_create_nessus_agent)

        new_agent_list = self.cat.api.agents.get_agents(scanner_id=1)

        assert old_agent_list != new_agent_list, \
            'Unable to delete multiple Nessus Agents.'

    # API_Tested# POST /agent-groups/{group_id}/agents
    @pytest.mark.parametrize('nessus_create_nessus_agent',
                             [[2, NessusConfig.CAT_NESSUS_MANAGER_LINKING_KEY]], indirect=True)
    @pytest.mark.parametrize('nessus_create_nessus_agent_group', [[1]], indirect=True)
    def test_nessus_agents_add_agents(self, nessus_create_nessus_agent, nessus_create_nessus_agent_group):
        """
        Tests that we are able to add a list of Agent IDs to a group.

        See: https://<NessusID>:8834/api#/resources/agent-groups/add-agents
        """
        self.cat.api.agent_groups.add_agents(group_id=nessus_create_nessus_agent_group[0],
                                             agent_ids=nessus_create_nessus_agent)

        group_details = self.cat.api.agent_groups.details(scanner_id=1, group_id=nessus_create_nessus_agent_group[0])
        num_group_members = len(group_details['agents'])

        assert self.cat.api.http_status_code == HTTPStatus.OK and num_group_members == 2, \
            "Adding multiple agents to group failed."

    # API_Tested# DELETE /agent-groups/{group_id}/agents
    @pytest.mark.parametrize('nessus_create_nessus_agent',
                             [[2, NessusConfig.CAT_NESSUS_MANAGER_LINKING_KEY]], indirect=True)
    @pytest.mark.parametrize('nessus_create_nessus_agent_group', [[1]], indirect=True)
    def test_nessus_agents_delete_agents(self, nessus_create_nessus_agent, nessus_create_nessus_agent_group):
        """
        Tests that we are able to delete a list of Agent IDs from a group.

        See: https://<NessusID>:8834/api#/resources/agent-groups/delete-agents
        """
        self.cat.api.agent_groups.add_agents(group_id=nessus_create_nessus_agent_group[0],
                                             agent_ids=nessus_create_nessus_agent)

        old_group_details = self.cat.api.agent_groups.details(scanner_id=1,
                                                              group_id=nessus_create_nessus_agent_group[0])['agents']

        self.cat.api.agent_groups.delete_agents(group_id=nessus_create_nessus_agent_group[0],
                                                agent_ids=nessus_create_nessus_agent)

        new_group_details = self.cat.api.agent_groups.details(scanner_id=1,
                                                              group_id=nessus_create_nessus_agent_group[0])['agents']

        assert self.cat.api.http_status_code == HTTPStatus.OK and old_group_details != new_group_details, \
            "Deleting multiple agents from group {0} failed.".format(nessus_create_nessus_agent_group[0])
