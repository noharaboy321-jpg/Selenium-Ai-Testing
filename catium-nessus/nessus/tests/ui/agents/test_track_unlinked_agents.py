"""
Test cases related to Agents Page and Blackout Windows

:copyright: Tenable Network Security, 2019
:date: April 25, 2019
:last_modified: Dec 14, 2020
:author: @ntarwani, @kpanchal
"""
import time

import pytest

from catium.lib.const import WAIT_NORMAL, TIME_SIXTY_SECONDS, TIME_FIVE_MINUTES
from catium.lib.webium.wait import wait
from nessus.helpers.agents import get_agent_name
from nessus.lib.const import Nessus
from nessus.pageobjects.agents.agent_settings_page import AgentSettingsPage
from nessus.pageobjects.agents.agents_filter_page import FilterWindow
from nessus.pageobjects.agents.agents_page import AgentsPage, AgentsList, AgentDetail
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
@pytest.mark.usefixtures('nessus_api_login')
class TestTrackUnlinkedAgents:
    """ This class contains tests related to Tracking unlinked agents on Nessus Manager"""

    cat = None

    def test_verify_option_to_track_unlinked_agent(self):
        """
        AGENT-804: As a user, I need to know agents that are linked and unlinked

        1. Navigate to agent settings page
        2. Verify checkbox for Track Unlink Agent is available

        Scenarios tested:
        [X] Verify that Track unlink agent checkbox is available under agent settings page
        """
        agent_settings_page = AgentSettingsPage()
        agent_settings_page.open()

        LoadingCircle(WAIT_NORMAL)

        assert agent_settings_page.is_element_present('track_unlinked_agent_checkbox'), \
            'Track Unlink Agent checkbox should be available'

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize('track_unlinked_agent', [{'enable_tracking': True}], indirect=True)
    def test_agent_unlink_status_in_agent_list(self, nessus_create_nessus_agent, track_unlinked_agent):
        """
        AGENT-804: As a user, I need to know agents that are linked and unlinked

        1. Link an agent to the Nessus Manager
        2. Enable track unlinked agents under Agent Settings Page.
        3. Unlink the agent that was linked in 1st step
        4. Navigate to Agents Page
        5. Verify the status of agent has changed to 'Unlinked'

        Scenarios tested:
        [X] Verify that the Agents list view lists unlinked agents if "Track unlinked agents" is enabled.
        """
        agent_id = nessus_create_nessus_agent[0]
        agent_name = get_agent_name(api=self.cat.api, agent_id=agent_id)

        self.cat.api.agents.agent_unlink(agent_id)
        wait(lambda: [value for value in self.cat.api.agents.get_agents(1)['agents']
                      if value['name'] == agent_name][0]['status'] == Nessus.Agents.AgentStatus.UNLINKED.lower(),
             sleep_seconds=TIME_SIXTY_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
             waiting_for="Agent status to unlinked")

        AgentsPage().open()
        LoadingCircle(WAIT_NORMAL)

        agent_list = AgentsList()
        assert agent_list.get_agent_by_name(agent_name).agent_status.text == Nessus.Agents.AgentStatus.UNLINKED, \
            'Agent status is not changed to unlinked'

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize('track_unlinked_agent', [{'enable_tracking': True}], indirect=True)
    def test_agent_unlink_status_in_agent_detail(self, nessus_create_nessus_agent, track_unlinked_agent):
        """
        AGENT-804: As a user, I need to know agents that are linked and unlinked

        1. Link an agent to the Nessus Manager
        2. Enable track unlinked agents under Agent Settings Page.
        3. Unlink the agent that was linked in 1st step
        4. Navigate to Agents Page
        5. Click on the unlinked agent
        6. Verify the value of  status is 'Unlinked' and value of Unlinked On at has a timestand between
           time before unlink and time after unlink

        Scenarios tested:
        [X] Verify that the status of an unlinked agent and the time the agent was unlinked are reported in the Agent
            detail view if "Track unlinked agents" is enabled.
        """
        agent_id = nessus_create_nessus_agent[0]
        agent_name = get_agent_name(api=self.cat.api, agent_id=agent_id)
        unlinked_from = int(time.time())

        self.cat.api.agents.agent_unlink(agent_id)

        AgentsPage().open()
        agent_list = AgentsList()
        agent_list.loaded()

        wait(lambda: [value for value in self.cat.api.agents.get_agents(scanner_id=1)['agents']
                      if value['name'] == agent_name][0]['status'] == Nessus.Agents.AgentStatus.UNLINKED.lower(),
             sleep_seconds=TIME_SIXTY_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
             waiting_for="Agent status to unlinked")

        unlinked_to = int(time.time())
        agent_list.get_agent_by_name(agent_name).click()

        agent_detail = AgentDetail()
        wait(lambda: agent_detail.is_element_present('unlinked_on'),
             waiting_for='Agent details page to get loads properly')

        assert agent_detail.status.text == Nessus.Agents.AgentStatus.UNLINKED, \
            'Agent status is not Unlinked under agent detail view'

        unlinked_at = int(self.cat.api.agents.get_agent_details(agent_id)['unlinked_on'])

        assert unlinked_from <= unlinked_at <= unlinked_to, "Agent unlinked at(%d) should be in between '" \
                                                            "%d and %d" % (unlinked_at, unlinked_from, unlinked_to)

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize('track_unlinked_agent', [{'enable_tracking': True}], indirect=True)
    def test_verify_unlinked_agent_listed_with_filter(self, nessus_create_nessus_agent, track_unlinked_agent):
        """
        AGENT-804: As a user, I need to know agents that are linked and unlinked

        1. Link an agent to the Nessus Manager
        2. Enable track unlinked agents under Agent Settings Page.
        3. Unlink the agent that was linked in 1st step
        4. Navigate to Agents Page
        5. Apply a filter to list unlinked agents
        6. Verify the status of listed agents is unlinked.

        Scenarios tested:
        [X] Verify that an unlinked agent can be queried using the Agent advanced search filter if
            "Track unlinked agents" is enabled (apply filter "Status is equal to Unlinked").
        """
        agent_id = nessus_create_nessus_agent[0]
        agent_name = get_agent_name(api=self.cat.api, agent_id=agent_id)

        self.cat.api.agents.agent_unlink(agent_id)

        wait(lambda: [value for value in self.cat.api.agents.get_agents(1)['agents']
                      if value['name'] == agent_name][0]['status'] == Nessus.Agents.AgentStatus.UNLINKED.lower(),
             sleep_seconds=TIME_SIXTY_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
             waiting_for="Agent status to unlinked")

        AgentsPage().open()
        LoadingCircle(WAIT_NORMAL)

        agent_list = AgentsList()
        filter_agent = FilterWindow()

        filter_agent.add_and_apply_filter(filter_operator=Nessus.Agents.Filter.IS_EQUAL_TO,
                                          match_type=Nessus.Agents.Filter.ALL,
                                          filter_key=Nessus.Agents.Filter.STATUS,
                                          filter_value=Nessus.Agents.AgentStatus.UNLINKED)

        assert agent_name in agent_list.get_all_agents_by_name(), \
            "Unlinked agent is not in list after filter status=Unlinked is applied"

        for agent in agent_list.rows:
            assert agent.agent_status.text == Nessus.Agents.AgentStatus.UNLINKED, \
                'Only agent with Unlinked status should be listed'

    @pytest.mark.xfail(reason='NES-7691, "Unlinked" Agents are displayed under ‘Linked Agent’ list even though '
                              '"Track unlinked agents" check-box is not checked from Agent Settings')
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize('track_unlinked_agent', [{'enable_tracking': False}], indirect=True)
    def test_unlinked_agents_with_track_unlinked_agent_disabled(self, nessus_create_nessus_agent, track_unlinked_agent):
        """
        AGENT-804: As a user, I need to know agents that are linked and unlinked

        1. Link an agent to the Nessus Manager
        2. Disable track unlinked agents under Agent Settings Page.
        3. Unlink the agent that was linked in 1st step
        4. Navigate to Agents Page
        5. Verify unlinked agents are not in the list

        Scenarios tested:
        [X] Verify that the Agents list view does not lists unlinked agents if "Track unlinked agents" is disabled.
        """
        agent_id = nessus_create_nessus_agent[0]
        agent_name = get_agent_name(api=self.cat.api, agent_id=agent_id)

        self.cat.api.agents.agent_unlink(agent_id)
        wait(lambda: [value for value in self.cat.api.agents.get_agents(1)['agents']
                      if value['name'] == agent_name][0]['status'] == Nessus.Agents.AgentStatus.UNLINKED.lower(),
             sleep_seconds=TIME_SIXTY_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
             waiting_for="Agent status to unlinked")

        AgentsPage().open()
        LoadingCircle(WAIT_NORMAL)

        agent_list = AgentsList()
        assert agent_name not in agent_list.get_all_agents_by_name(), \
            'Unlinked agent should not be present in the Agent list'
