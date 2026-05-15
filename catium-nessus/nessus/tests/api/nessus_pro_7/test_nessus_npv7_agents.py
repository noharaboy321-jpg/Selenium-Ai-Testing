"""
:copyright: Tenable Network Security, 2017
:date: October 2, 2017
:author: @pellsworth
"""
import sys
from http import HTTPStatus

import pytest
from requests import HTTPError

from catium.lib.log import create_logger
from nessus.helpers.server import expect_http_error

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login', 'no_automation_api_key')
class TestNessusAgentsPro7:
    """
    Class to handle testing Nessus Agents and Agent Groups, which should be disallowed in 
    Nessus Pro 7.
    """

    cat = None

    # API_Tested# POST /scanners/{scanner_id}/agent-groups
    def test_nessus_agent_groups_create(self):
        """Tests Agent Group Creation"""
        with expect_http_error(code=403):
            try:
                self.cat.api.agent_groups.create(scanner_id=1, name='bogus group', stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    # API_Tested# DELETE /scanners/{scanner_id}/agent-groups/group_id
    def test_nessus_agent_groups_delete(self):
        """Tests Agent Group deletion"""
        with expect_http_error(code=403):
            self.cat.api.agent_groups.delete(scanner_id=1, group_id=1, stream=True)

    # API_Tested# PUT /scanners/{scanner_id}/agent-groups/{group_id}
    def test_nessus_agent_groups_configure(self):
        """Tests Agent Group configuration"""
        with expect_http_error(code=403):
            try:
                self.cat.api.agent_groups.configure(scanner_id=1, group_id=1, name='bogus group', stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    # API_Tested# GET /scanners/{scanner_id}/agent-groups/{group_id}
    def test_nessus_agent_groups_details(self):
        """Tests Agent Group Details"""
        with expect_http_error(code=403):
            self.cat.api.agent_groups.details(scanner_id=1, group_id=1, stream=True)

    # API_Tested# GET /scanners/{scanner_id}/agent-groups
    def test_nessus_agent_groups_get_list(self):
        """Tests Agent Group Listing"""
        with expect_http_error(code=403):
            self.cat.api.agent_groups.get_list(scanner_id=1, stream=True)

    # details configure get_list
    # API_Tested# GET /scanners/{scanner_id}/agents
    def test_nessus_agents_get(self):
        """Tests retrieving Agents"""
        with expect_http_error(code=403):
            self.cat.api.agents.get_agents(scanner_id=1, stream=True)

    # API_Tested# DELETE /agents
    def test_nessus_agents_delete_multiple(self):
        """Tests deleting multiple Agents"""
        with expect_http_error(code=403):
            try:
                self.cat.api.agents.delete_multiple(agent_ids=[1, 2, 3, 4, 5], stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    # API_Tested# PUT /agent-groups/{group_id}/agents
    def test_nessus_agents_add_agents(self):
        """Tests adding Agents"""
        with expect_http_error(code=403):
            try:
                self.cat.api.agent_groups.add_agents(group_id=5,
                                                     agent_ids=[1, 2, 3, 4, 5], stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    # API_Tested# DELETE /agent-groups/{group_id}/agents
    def test_nessus_agents_delete_agents(self):
        """Tests deleting Agents"""
        with expect_http_error(code=403):
            try:
                self.cat.api.agent_groups.delete_agents(group_id=5, agent_ids=[1, 2, 3, 4, 5], stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))
