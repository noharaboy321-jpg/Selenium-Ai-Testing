"""
Nessus agent profile in agent details view

:copyright: Tenable Network Security, 2024
:date: July 19, 2024
:last_modified: July 19, 2024
:author: @xxia @mdabra
"""

import random
import re
import pytest
from datetime import datetime
from catium.lib.const import WAIT_SHORT, WAIT_NORMAL
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from nessus.pageobjects.agents.agents_page import AgentsPage, AgentsList, AgentDetail
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.profiles.profiles_page import ProfileList, ProfilesPage


log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentDetailsProfile:
    """Test cases to cover UI functionality related to agent profile in agent details page."""
    cat = None

    @staticmethod
    def create_valid_profiles(api, count):
        """
        create count of valid profiles
        """
        versions = api.settings.agent_versions()
        profiles = []
        for key in versions["versions_in_feed"]:
            version = versions["versions_in_feed"][key]
            if "eol" in version:
                eol_date = datetime.fromisoformat(re.sub(r'\..*', '', version["eol"]))
                if eol_date < datetime.now():
                    continue
            if "release_date" in version:
                eol_date = datetime.fromisoformat(re.sub(r'\..*', '', version["release_date"]))
                eol_date = eol_date.replace(year=eol_date.year + 2)
                if eol_date < datetime.now():
                    continue

            profile = api.profiles.create(name=random_name(prefix='agent-profile-'),
                                                         description="testing version in feed",
                                                         config={"version": key})
            profiles.append(profile)
            if len(profiles) >= count:
                break
        return profiles

    @staticmethod
    def create_multiple_profiles(api, count):
        """
        create count of Agent profiles using API Endpoint
        """
        versions = api.settings.agent_versions()
        profiles = []
        key = versions["versions_for_selection"][0]
        for n in range(count):
            profile = api.profiles.create(name='agent-profile-' + str(n),
                                                         description=str(n),
                                                         config={"version": key})
            profiles.append(profile)
            if len(profiles) >= count:
                break
        return profiles

    @pytest.mark.usefixtures('login', 'nessus_api_login', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    def test_agent_group_details_profile(self, create_agents):
        """
        Scenario Tested:
            [x] Verify user can add the profile in the  agent details page
            [x] Verify user can remove the profile in the  agent details page
            [x] Verify user can update the profile in the  agent details page
        """
        agent_id = [agent['id'] for agent in self.cat.api.agents.get_agents(scanner_id=1)['agents'] if agent[
            'name'] == create_agents[0]][0]
        agent_name = create_agents[0]

        profiles = self.create_valid_profiles(self.cat.api, 2)

        agents_page = AgentsPage()
        agents_page.open()
        agent_list = AgentsList()
        agent_list.loaded()

        agent_list.click_on_agent(agent_name=agent_name)
        LoadingCircle(WAIT_SHORT)

        agent_details = AgentDetail()
        agent_details.add_profile_to_agent(profile_name=profiles[0]["name"])
        LoadingCircle(WAIT_NORMAL)

        agent = self.cat.api.agents.get_agent_details(agent_id)
        assert agent["profile_uuid"] == profiles[0]["profile_uuid"]

        agent_details.update_agent_profile(profiles[1]["name"])
        LoadingCircle(WAIT_NORMAL)
        agent = self.cat.api.agents.get_agent_details(agent_id)
        assert agent["profile_uuid"] == profiles[1]["profile_uuid"]

        agent_details.remove_agent_profile()
        LoadingCircle(WAIT_NORMAL)

        agent = self.cat.api.agents.get_agent_details(agent_id)
        assert not agent["profile_uuid"]

        self.cat.api.profiles.delete_profiles([profiles[0]["profile_uuid"], profiles[1]["profile_uuid"]])

    @pytest.mark.xray(test_key='NES-18102')
    @pytest.mark.usefixtures('login', 'nessus_api_login')
    def test_profile_creation_limit(self):
        """
        Scenario Tested:
            NES-18102: [E2E] Validate the configuration of 51st Agent Profile will return an error
            [x] Verify user should not be able to add the extra profile beyond 50 limit.
        """
        try:
            ###Creating 51 Declarative Agent Profiles
            profiles = self.create_multiple_profiles(self.cat.api, 51)
        except Exception as e:
            assert "400 Client Error" in str(e), "The Server Response error should be 400 Client Error"
        finally:
            profiles_page = ProfilesPage()
            profiles_page.open()
            profiles_page.delete_all_profiles()
