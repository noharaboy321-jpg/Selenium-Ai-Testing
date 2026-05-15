"""
Nessus Declarative Agent tab related test cases

:copyright: Tenable Network Security, 2024
:date: Jul 19, 2024
:last modified: Aug 05, 2024
:author: @mdabra
"""

import pytest

from catium.lib.const import TIME_TEN_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.lib.const import Nessus
from nessus.pageobjects.profiles.profiles_page import ProfileList, ProfilesPage
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.sidenav.sidenav import SideNav
from catium.helpers.sleep_lib import sleep
from catium.lib.util import random_name

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login', 'nessus_api_login')
class TestAgentProfilesPage:
    """ Test cases to cover UI functionality related to agents profiles tab under NM Sensors tab"""

    cat = None

    @pytest.mark.xray(test_key='NES-18098')
    def test_visibility_and_navigation_of_agent_profiles_tab(self):
        """
            NES-18098 : [E2E] Validate Agent Profiles tab visibility in Sensors page in NM
            Scenario tested:
            [x] Install Nessus 10.8.0 as a Nessus Manager product
            [x] Let the plugins compile
            [x] Go to Sensors Tab
            [x] Check agent-profiles tab available on the left panel
            [x] Click on agent-profiles tab available on the left panel and verify
        """
        HeaderBasePage().sensors_tab.click()
        wait(lambda: HeaderBasePage().is_element_present('linking_key_on_sensors_tab'),
             waiting_for="Linking key on sensors page to get loaded.",
             timeout_seconds=TIME_TEN_SECONDS)

        side_nav = SideNav()
        assert Nessus.Agents.AgentsProfiles.AGENT_PROFILES_TAB in side_nav.get_all_sidenav_links(), \
            "Agent profiles tab is not visible"

        side_nav.agent_profiles_tab.click()
        agent_profiles_page = ProfilesPage()

        # Verify the page loads successfully
        wait(lambda: agent_profiles_page.is_element_present('agent_profiles_header'),
             waiting_for="Agent Profiles page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        assert agent_profiles_page.is_element_present('agent_profiles_header'), \
            "Header of Agent Profiles page is not loaded."

        # Verify the url is correct for agent profiles page
        assert Nessus.Agents.AgentsProfiles.AGENT_PROFILES_ROUTE in get_driver_no_init().current_url, \
            'URL for Agent Profiles page is not matched.'

    @pytest.mark.xray(test_key='NES-18104')
    @pytest.mark.xray(test_key='NES-18100')
    @pytest.mark.xray(test_key='NES-18099')
    def test_create_agent_profile(self):
        """
            NES-18099 : [E2E] Validate "Create a new agent profile" button in agent profile page
            NES-18100 : [E2E] Validate User is able to configure Agent Profile/s
            NES-18104 : [E2E] Validate deletion of an Agent Profile should be successful
            Scenario tested:
            [x] Install Nessus 10.8.0 as a Nessus Manager product
            [x] Let the plugins compile
            [x] Go to Sensors Tab
            [x] Check agent-profiles tab available on the left panel
            [x] Click on agent-profiles tab available on the left panel and verify cancel option
            [x] Agent Profile Modal should open with three options: name, version and description
            [x] Delete that particular agent profile
        """
        try:
            HeaderBasePage().sensors_tab.click()
            side_nav = SideNav()
            agent_profiles_page = ProfilesPage()
            side_nav.agent_profiles_tab.click()
            agent_profiles_page.new_profile_button.click()

            # Verify the page loads successfully
            wait(lambda: agent_profiles_page.is_element_present('add_agent_profile_config'),
                 waiting_for="Agent Profiles page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
            assert agent_profiles_page.is_element_present('add_agent_profile_config'), \
                "Header of Agent Profiles page is not loaded."
            agent_profiles_page.agent_profiles_cancel_button.click()
            sleep(1, reason="waiting for modal to close")
            new_profile_name = random_name(prefix='AgentProfileName-')
            new_profile_description = random_name(prefix='AgentProfileDescription-')
            agent_profiles_page.create_agent_profile(profile_name=new_profile_name,
                                                     profile_description=new_profile_description)
            sleep(1, reason="waiting for profile to load")
        finally:
            agent_profile_list = ProfileList()
            agent_profile_list.delete_profile(new_profile_name)

    @pytest.mark.xray(test_key='NES-18105')
    @pytest.mark.xray(test_key='NES-18101')
    def test_create_fifty_agent_profiles_hit_limit(self, number_of_profiles=50):
        """
            NES-18101 : [E2E] Validate the configuration of fifty Agent Profiles to hit the limit
            NES-18105: [E2E] Validate deletion of multiple Agent Profiles should be successful
            Scenario tested:
            [x] Install Nessus 10.8.0 as a Nessus Manager product
            [x] Go to Sensors Tab
            [x] Check agent-profiles tab available on the left panel
            [x] create fifty agent profiles
            [x] Fetch the Agent profile count and validate it with fifty.
        """
        try:
            HeaderBasePage().sensors_tab.click()
            side_nav = SideNav()
            agent_profiles_page = ProfilesPage()
            side_nav.agent_profiles_tab.click()
            sleep(1, reason="waiting for profile to load")
            agent_profile_list = ProfileList()
            for num in range(number_of_profiles):
                new_profile_name = 'AgentProfileName-' + str(num)
                new_profile_description = 'AgentProfileDescription-' + str(num)
                sleep(1, reason="waiting for profile to load")
                agent_profiles_page.create_agent_profile(profile_name=new_profile_name,
                                                         profile_description=new_profile_description)
            log.log(level=20, msg="Validating the Profile count total")
            assert agent_profiles_page.agent_profiles_count == number_of_profiles, \
                "Fifty profiles aren't available in the Profile record table"
        finally:
            agent_profile_list.delete_all_profiles()
            log.log(level=20, msg="Deleted all Profiles")

