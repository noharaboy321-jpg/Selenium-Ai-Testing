""""
Nessus test cases related to Agent-> Profiles

:copyright: Tenable Network Security, 2024
:date: February 15, 2024
:last_modified: February 15, 2024
:author: @xxia, @dcoppock, @tkeyser, @tdavis
"""

import json
from datetime import datetime, timedelta
import pytest
from requests.exceptions import HTTPError
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_NORMAL, TIME_TEN_SECONDS, TIME_FIVE_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import get_agent_id_from_list
from nessus.helpers.nessuscli import fix
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.pageobjects.agents.agents_page import AgentsPage, AgentsList
from nessus.pageobjects.cluster.cluster_agent_page import AgentDetailsPage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.profiles.profiles_page import ProfilesPage, ProfileList, ProfileDetails, ProfileAgentsList, \
    AddAgentProfileList, AddProfileModal

log = create_logger()


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentProfiles:
    """Test cases to cover UI functionality related to agents profiles."""

    @pytest.fixture()
    def navigate_to_agent_profiles_tab(request: 'SubRequest'):
        profiles_page = ProfilesPage()
        HeaderBasePage().sensors_tab.click()
        wait(lambda: visibility_of_element_located(AgentsPage().linking_key_text),
             waiting_for="Sensors page to load properly")
        profiles_page.open()
        wait(lambda: ProfilesPage().is_element_present('profiles_left_nav'), waiting_for='Agent Profiles to get loaded')

        assert visibility_of_element_located((profiles_page.profiles_left_nav.we_by,
                                              profiles_page.profiles_left_nav.we_value))(get_driver_no_init()), \
            "Agent Profiles lef-nav is not visible."

    @pytest.fixture()
    def create_profile_with_agents(self, create_valid_profile_with_agents, request: 'SubRequest'):
        profile = create_valid_profile_with_agents
        assert profile['profile_uuid']

    @pytest.fixture()
    def create_profile(self, create_valid_profile_endpoint, request: 'SubRequest'):
        profile = create_valid_profile_endpoint
        assert profile['profile_uuid']
        yield profile

    @pytest.fixture()
    def add_fake_agent(self, nessus_api_login):
        """
        This fixture create a new fake agent and deletes it after the test case is completed

        :return: dictionary containing agent_name, token and agent_uuid

        Note: The existing fixture in /nessus/plugins/fixtures/agents.py returns agent_id only and modification will affect
        existing test cases. So we have created this new fixture which returns agent_name, agent_uuid and token
        """
        try:
            agent = nessus_api_login.agents.add_fake_agent(agent_name=random_name(prefix="automation-"))
        except HTTPError:
            raise HTTPError("Agent could not be created")
        else:
            yield agent
        finally:
            agent_id, agent_status = get_agent_id_from_list(api=nessus_api_login, agent_name=agent['name'])
            try:
                nessus_api_login.agents.delete_agent(agent_id=agent_id)
            except Exception as exc:
                create_logger().debug('Fixture failed to delete Agent: %s', exc)

    cat = None

    @pytest.mark.xray(test_key='NES-18003')
    @pytest.mark.nessus_smoke
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[10, 'None']], indirect=True)
    def test_visibility_of_agent_profiles_tab(self, create_profile_with_agents, navigate_to_agent_profiles_tab):
        """
        NES-18003: Verify profiles page
        Test "Agent Profiles left-nav is present/visible
        1. Navigate to Sensors page under Settings.
        2. Verify visibility of "Agent Profiles" tab.
        """

        profiles_page = ProfilesPage()

        assert visibility_of_element_located((profiles_page.profiles_left_nav.we_by,
                                              profiles_page.profiles_left_nav.we_value))(get_driver_no_init()), \
            "Agent Profiles lef-nav is not visible."

    @pytest.mark.xray(test_key='NES-17809')
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.usefixtures('nessus_api_login')
    def test_profile_with_no_agents(self, create_profile, navigate_to_agent_profiles_tab):
        """
        NES-17809: Verify profile with no agents available to add
        Test Agents list in profile
        1. Navigate to agent profiles details to show no agents
        """
        profiles_list = ProfileList()
        profile_details = ProfileDetails()

        profile_names = profiles_list.get_all_profile_names()
        profiles_list.click_on_profile(profile_name=profile_names[0])

        profile_details.agents_tab.click()
        assert not (ProfileAgentsList().add_agents_button.is_displayed() and
                    ProfileAgentsList().add_agents_link.is_displayed()), "Add agents link and button are not visible"
        assert ProfileAgentsList().no_agents_added_text.is_displayed(), "Add agents text is not visible"

    @pytest.mark.xray(test_key='NES-18156')
    @pytest.mark.xray(test_key='NES-17809')
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.usefixtures('nessus_api_login')
    def test_profile_with_no_agents_added(self, create_profile, navigate_to_agent_profiles_tab, add_fake_agent):
        """
        NES-17809: Verify profiles agents tab with no agents added to profile
        Test Agents list in profile
        1. Navigate to agent profiles details to show no agents
        NES-18156: [E2E] Validate 'Add Agents' buttons in newly added Agent Profile
        1. Go to Agent Profile > Agents tab
        2. Validate both "add agents" to a profile buttons are clickable.
        3. check the close and cancel buttons working
        """

        profiles_list = ProfileList()
        profile_details = ProfileDetails()
        profile_agents_list = ProfileAgentsList()

        profile_name = profiles_list.get_all_profile_names()
        profiles_list.click_on_profile(profile_name=profile_name[0])

        profile_details.agents_tab.click()
        assert (profile_agents_list.add_agents_button.is_displayed() and
                profile_agents_list.add_agents_link.is_displayed()), "Add agents link and button are not visible"
        #Validating the working of both Add Agents buttons
        profile_agents_list.add_agents_button.click()
        wait(lambda: profile_agents_list.is_element_present('add_agents_modal'),
             waiting_for='waiting for modal to get loaded', timeout_seconds=10)
        assert profile_agents_list.add_agents_modal.is_displayed(), "Add agents modal is not visible or not clickable."
        #validate close button
        profile_agents_list.modal_close_button.click()
        ActionCloseModal().wait_for_modal_closed()
        profile_agents_list.add_agents_link.click()
        wait(lambda: profile_agents_list.is_element_present('add_agents_modal'),
             waiting_for='waiting for modal to get loaded', timeout_seconds=10)
        assert profile_agents_list.add_agents_modal.is_displayed(), "Add agents modal is not visible or not clickable."
        #validate cancel button
        profile_agents_list.modal_cancel_button.click()
        ActionCloseModal().wait_for_modal_closed()


    @pytest.mark.xray(test_key='NES-17809')
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[10, 'None']], indirect=True)
    def test_list_agents_in_profile(self, create_profile_with_agents, navigate_to_agent_profiles_tab):
        """
        NES-17809: Verify list of agents assigned to profile
        Test Agents list in profile
        1. Navigate to agent profiles details to list agents assigned
        """

        profiles_list = ProfileList()
        profile_details = ProfileDetails()

        profile_name = profiles_list.get_all_profile_names()
        profiles_list.click_on_profile(profile_name=profile_name[0])

        profile_details.agents_tab.click()
        ProfileAgentsList().loaded()

        assert len(ProfileAgentsList().get_all_agents()) > 0, "Profile list is empty."

    @pytest.mark.xray(test_key='NES-18157')
    @pytest.mark.xray(test_key='NES-18003')
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager', 'create_agents')
    @pytest.mark.parametrize("create_agents", [{'no_of_agents': 1}], indirect=True)
    def test_add_agent_to_profile_works_fine(self, create_agents, create_profile, navigate_to_agent_profiles_tab):
        """
        NES-18003: Verify profile with no agents available to add
        NES-18157: [E2E] Validate a user is able to add agent/s to agent profile using UI add agent button
        Test Agents list in profile
        1. Navigate to agent profiles details to show no agents
        2. click on agents tab
        3. Click on "No agents have been added. Add Agent." button to check whether working fine or not.
        4. verify whether agent gets linked to the profile.
        5. Now try another "Add Agent" button on top right corner of the agents tab.
        6. repease step 4.
        """
        profiles_list = ProfileList()
        profile_details = ProfileDetails()
        profile_names = profiles_list.get_all_profile_names()
        profiles_list.click_on_profile(profile_name=profile_names[0])
        profile_details.agents_tab.click()
        #verify "Add Agent." button works fine on top right corner in the agents tab
        profile_details.add_agents_button.click()
        add_agent_profile_list = AddAgentProfileList()
        wait(lambda: add_agent_profile_list.is_element_present('modal_agent_rows'),
             waiting_for='waiting for list to get loaded', timeout_seconds=20)
        profiles_list.select_all_checkbox.click()
        profiles_list.accept_action()
        wait(lambda: add_agent_profile_list.is_element_present('rows'),
             waiting_for='waiting for list to get loaded', timeout_seconds=20)
        all_available_agents = add_agent_profile_list.get_all_agent_names()
        assert create_agents == all_available_agents, 'Agents not available in list'
        profile_details.select_all_checkbox.click()
        profile_details.remove_agents_button.click()
        ActionCloseModal().accept_action()
        ActionCloseModal().wait_for_modal_closed()
        #verify "No agents have been added. Add Agent." shows up when no agent is linked to a profile
        profile_details.add_agents_fresh_profile_button.click()
        wait(lambda: add_agent_profile_list.is_element_present('modal_agent_rows'),
             waiting_for='waiting for list to get loaded', timeout_seconds=20)
        profile_details.select_all_checkbox.click()
        profiles_list.accept_action()
        wait(lambda: add_agent_profile_list.is_element_present('rows'),
             waiting_for='waiting for list to get loaded', timeout_seconds=20)
        all_available_agents = add_agent_profile_list.get_all_agent_names()
        assert create_agents == all_available_agents, 'Agents not available in list'

    @pytest.mark.xray(test_key='NES-17811')
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager')
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    def test_remove_agent_in_profile(self, create_profile_with_agents, navigate_to_agent_profiles_tab):
        """
        NES-17811: Verify remove agents from profile
        Test Agents list in profile
        1. Navigate to agent profiles details to list agents assigned
        2. Select all agents and click remove agent titlebar button
        """

        profiles_list = ProfileList()
        profile_details = ProfileDetails()
        profiles_agent_list = ProfileAgentsList()

        profile_name = profiles_list.get_all_profile_names()
        profiles_list.click_on_profile(profile_name=profile_name[0])

        profile_details.agents_tab.click()
        ProfileAgentsList().loaded()
        profile_details.select_all_checkbox.click()
        profile_details.remove_agents_button.click()
        ActionCloseModal().accept_action()
        wait(lambda: profiles_agent_list.is_element_present('no_agents_added_text'),
             waiting_for='waiting for list to get loaded', timeout_seconds=10)

        assert not len(ProfileAgentsList().get_all_agents()) > 0, "Profile list is empty."

    @pytest.mark.xray(test_key='NES-17810')
    @pytest.mark.usefixtures('login', 'nessus_api_login')
    def test_add_profile_ui(self, navigate_to_agent_profiles_tab):
        """
        NES-17810: Verify add profile from UI
        """
        profiles_page = ProfilesPage()
        profiles_page.new_profile_button.click()
        add_profile_modal = AddProfileModal()
        add_profile_modal.create_profile()
        wait(lambda: visibility_of_element_located(ProfilesPage().search_profiles),
             waiting_for="Profiles page to load properly")
        assert profiles_page.agent_profiles_count > 0, 'No profiles'
        profiles_page.delete_all_profiles()

    @pytest.mark.xray(test_key='NES-17810')
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager')
    def test_edit_profile_ui(self, create_profile, navigate_to_agent_profiles_tab):
        """
        NES-17810: Verify editing profile from UI
        """
        profiles_page = ProfilesPage()
        profiles_list = ProfileList()
        profile_details = ProfileDetails()
        profile_names = profiles_list.get_all_profile_names()
        profiles_list.click_on_profile(profile_name=profile_names[0])

        profile_details.edit_profile_button.click()
        edit_profile_modal = AddProfileModal()
        edit_profile_modal.description_input.value = 'Edit Profile'
        edit_profile_modal.action_button.click()
        profile_details.back_to_agent_profiles.click()
        wait(lambda: visibility_of_element_located(ProfilesPage().search_profiles),
             waiting_for="Profiles page to load properly")
        assert profiles_list.get_description_for_profile(profile_names[0]) == 'Edit Profile'
        profiles_page.delete_all_profiles()

    @pytest.mark.xray(test_key='NES-18002')
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'nessus_api_login',
                             'nessus_create_nessus_agent', 'create_profile', 'login')
    def test_add_agent_to_profile_from_manage_dropdown(self, nessus_create_nessus_agent, create_profile,
                                                       navigate_to_agent_profiles_tab):
        """
        NES-18002 : Verify assign agent profile from manage dropdown
        1. Navigate to agent profiles details to list agents assigned
        2. Select an agent and click Add Profile in Manage dropdown
        """
        profiles_list = ProfileList()
        profile_names = profiles_list.get_all_profile_names()

        HeaderBasePage().sensors_tab.click()
        wait(lambda: visibility_of_element_located(AgentsPage().linking_key_text),
             waiting_for="Sensors page to load properly")
        agents_page = AgentsPage()
        agents_page.open()
        agents_list = []

        agent_list = AgentsList()
        for row, agent in enumerate(agent_list.rows, start=1):
            if row < 25:
                agents_list.append(agent.agent_name.text)
            else:
                break
        agent_list.select_deselect_agents(agents_list=agents_list)
        agents_page.manage_button.click()
        wait(lambda: visibility_of_element_located(AgentsPage().add_to_profile_manage_button),
             waiting_for="Manage dropdown to load properly")
        agents_page.add_to_profile_manage_button.click()
        ActionCloseModal().accept_action()
        agent_list.loaded()
        agent_name = agent_list.get_all_agents_by_name()[0]
        wait(lambda: agent_list.get_profile_name_by_agent(agent_name=agent_name),
             waiting_for='templates to update')

        assert agent_list.get_profile_name_by_agent(agent_name=agent_name) == profile_names[0]

    @pytest.mark.xray(test_key='NES-18002')
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'nessus_api_login',
                             'nessus_create_nessus_agent', 'create_profile', 'login')
    def test_add_agent_to_profile_from_agent_details(self, nessus_create_nessus_agent, create_profile, navigate_to_agent_profiles_tab):
        """
        NES-18002 : Verify assign agent profile from manage dropdown
        1. Click on an agent
        2. Click "add" icon next to profile and add to profile
        """
        profiles_list = ProfileList()
        profile_names = profiles_list.get_all_profile_names()
        agents_page = AgentsPage()
        agents_page.open()
        agents_list = AgentsList()
        agent_name = agents_list.get_all_agents_by_name()[0]
        agents_list.click_on_agent(agent_name=agent_name)
        agent_details = AgentDetailsPage()
        wait(lambda: visibility_of_element_located(agent_details.agent_details_tab),
             waiting_for='waiting for Agent details page to get loaded')
        agent_details.add_to_profile_icon.click()
        ActionCloseModal().accept_action()
        wait(lambda: visibility_of_element_located(agent_details.current_agent_profile_name),
             waiting_for='waiting for Agent details page to get loaded')
        assert agent_details.get_profile_name() == profile_names[0]

    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.usefixtures('nessus_api_login', 'login', 'create_profile')
    def test_eol_icons_in_agent_details_page(self, create_profile):
        profile = create_profile
        nessus_api = NessusAPI()
        feed_versions_str = fix.get_value("agent_versions_in_feed", True)
        feed_versions = json.loads(feed_versions_str)
        profile_version = profile["config"]["version"]
        expired_date = datetime.now()
        expired_date = expired_date.replace(year=expired_date.year - 1) - timedelta(days=2)
        expired_date = expired_date.strftime("%Y-%m-%dT%H:%M:%S.%f")
        feed_versions[profile_version]["release_date"] = expired_date

        eol_date = datetime.now()
        eol_date = eol_date - timedelta(days=2)
        eol_date = eol_date.strftime("%Y-%m-%dT%H:%M:%S.%f")
        feed_versions[profile_version]["eol"] = eol_date

        test_feed_versions_str = "'" + json.dumps(feed_versions) + "'"

        # Testing EOL icon
        try:
            fix.set("agent_versions_in_feed", test_feed_versions_str, True)
            sleep(WAIT_NORMAL, reason="For preference change to take effect")

            wait_for_scanner_to_be_ready(api=nessus_api)

        finally:
            profiles_page = ProfilesPage()
            HeaderBasePage().sensors_tab.click()
            wait(lambda: visibility_of_element_located(AgentsPage().linking_key_text),
                 waiting_for="Sensors page to load properly")
            profiles_page.open()
            wait(lambda: profiles_page.is_element_present('profiles_left_nav'), waiting_for='Agent Profiles to get loaded')

        assert profiles_page.eol_icon.is_displayed()

        del feed_versions[profile_version]["eol"]
        test_feed_versions_str = "'" + json.dumps(feed_versions) + "'"

        # Testing almost EOL icon
        try:
            fix.set("agent_versions_in_feed", test_feed_versions_str, True)
            sleep(WAIT_NORMAL, reason="For preference change to take effect")

            wait_for_scanner_to_be_ready(api=nessus_api)

        finally:
            profiles_page = ProfilesPage()
            HeaderBasePage().sensors_tab.click()
            wait(lambda: visibility_of_element_located(AgentsPage().linking_key_text),
                 waiting_for="Sensors page to load properly")
            profiles_page.open()
            wait(lambda: profiles_page.is_element_present('profiles_left_nav'),
                 waiting_for='Agent Profiles to get loaded')

        assert profiles_page.eol_warning_icon.is_displayed()

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[2, 'None']], indirect=True)
    @pytest.mark.parametrize("version_digits", [pytest.param(3, id="3_digit_version")])
    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'nessus_api_login',
                             'nessus_create_nessus_agent', 'create_profile', 'login')
    def test_remove_agent_from_profile_from_manage_dropdown(self, create_profile_with_agents):
        """
        NES-18000 : Verify bulk remove agent profile from manage dropdown
        1. Navigate to agent profiles
        2. Select all agents and click Remove Profile in Manage dropdown
        """

        HeaderBasePage().sensors_tab.click()
        wait(lambda: visibility_of_element_located(AgentsPage().linking_key_text),
             waiting_for="Sensors page to load properly")
        agents_page = AgentsPage()
        agents_page.open()
        agents_list = []

        agent_list = AgentsList()
        for row, agent in enumerate(agent_list.rows, start=1):
            if row < 25:
                agents_list.append(agent.agent_name.text)
            else:
                break
        agent_list.select_deselect_agents(agents_list=agents_list)
        agents_page.manage_button.click()
        wait(lambda: visibility_of_element_located(AgentsPage().add_to_profile_manage_button),
             waiting_for="Manage dropdown to load properly")
        agents_page.remove_from_profile_manage_button.click()
        ActionCloseModal().accept_action()
        ActionCloseModal().wait_for_modal_closed()
        all_agents_names = agent_list.get_all_agents_by_name()
        wait(lambda: agent_list.get_all_agents_by_name(), sleep_seconds=TIME_TEN_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
             waiting_for='templates to update')
        agent_list.loaded()

        # Assert that the name of each agent is empty
        for agent_name in all_agents_names:
            assert agent_list.get_profile_name_by_agent(agent_name=agent_name) == ""
