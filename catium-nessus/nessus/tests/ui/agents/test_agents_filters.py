"""
Test cases related to Agents Filters

:copyright: Tenable Network Security, 2017
:date: July 25, 2017
:last_modified: May 09, 2023
:author: @smadan, @rdutta, @ntarwani, @kpanchal, @krpatel.ctr, sacharya.ctr
"""

import time

import pytest
from catium.lib.const import WAIT_NORMAL
from catium.lib.log.log import create_logger
from nessus.helpers.agents import add_multiple_agents
from nessus.lib.const.constants import Nessus
from nessus.pageobjects.agents.agents_filter_page import FilterWindow
from nessus.pageobjects.agents.agents_page import AgentsList
from nessus.pageobjects.agents.agents_page import AgentsPage
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()

@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestAgentsFilters:
    """
    Test Agent Filters
    """
    cat = None

    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    def test_agent_profile_filter(self, nessus_api_login, create_valid_profile_endpoint):
        """
        Agents filter by profile name or profile uuid
        """
        profile = create_valid_profile_endpoint
        profile_name = profile['name']
        profile_uuid = profile['profile_uuid']

        agents_page = AgentsPage()
        agents_page.open()

        with add_multiple_agents(nessus_api_login, 10):
            agents_page.refresh()
            LoadingCircle(WAIT_NORMAL)
            agent_list = AgentsList()

            profile_agents = []
            no_profile_agents = []
            for row, agent in enumerate(agent_list.rows, start=0):
                if row < 5:
                    profile_agents.append(agent.data_id)
                else:
                    no_profile_agents.append(agent.data_id)
            self.cat.api.profiles.add_profile_members(profile_uuid, None, profile_agents)
            self.cat.api.profiles.bulk_remove_profile_members(None, no_profile_agents)

            # Test filter with profile_name, profile_uuid and profile_uuid is None
            items = [{'filter': {'match_type': Nessus.Filter.FilterMatch.ALL,
                                 'filter_key': Nessus.Agents.Filter.PROFILE_NAME,
                                 'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO,
                                 'filter_value': profile_name},
                      'value': profile_agents},
                     {'filter': {'match_type': Nessus.Filter.FilterMatch.ALL,
                                 'filter_key': Nessus.Agents.Filter.PROFILE_UUID,
                                 'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO,
                                 'filter_value': profile_uuid},
                      'value': profile_agents},
                     {'filter': {'match_type': Nessus.Filter.FilterMatch.ALL,
                                 'filter_key': Nessus.Agents.Filter.PROFILE_UUID,
                                 'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': 'None'},
                      'value': no_profile_agents}
                     ]
            for item in items:
                agent_filter_window = FilterWindow()
                agent_filter_window.add_and_apply_filter(**item['filter'])

                filtered_agents = agent_list.get_all_agents_by_id()
                assert set(item['value']) == set(filtered_agents)

