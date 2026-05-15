"""
Nessus Agent Updates tab related test cases

:copyright: Tenable Network Security, 2022
:date: June 6, 2022
:last modified: Aug 22, 2022
:author: @krpatel
"""
from datetime import datetime

import pytest

from catium.lib import const
from catium.lib.const import TIME_TEN_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.lib.const import Nessus
from nessus.pageobjects.agents.agent_updates_page import AgentUpdatesPage
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login', 'nessus_api_login')
class TestAgentUpdatesPage:
    """ Test cases to cover UI functionality related to agents Updates tab under Sensors """

    cat = None

    @pytest.mark.xray(test_key='NES-15753')
    @pytest.mark.xray(test_key='NES-15752')
    def test_visibility_and_navigation_of_agent_update_tab(self):
        """
            NES-15752 : Verify the visibility of 'Agents Updates' tab under the 'Sensors' tab
            NES-15753 : Verify the navigation to the 'Agents Updates' tab

            Scenario tested:
            [x] Agent update option is visible on sidenav-bar under agents section.
            [x] User navigate to agent updates page successfully from sensors page.
            [x] Checked URL for Agent updates page
        """
        HeaderBasePage().sensors_tab.click()
        wait(lambda: HeaderBasePage().is_element_present('linking_key_on_sensors_tab'),
             waiting_for="Linking key on sensors page to get loaded.",
             timeout_seconds=TIME_TEN_SECONDS)

        side_nav = SideNav()
        assert Nessus.Agents.AgentsUpdates.AGENT_UPDATE_TAB in side_nav.get_all_sidenav_links(), \
            "Agent update tab is not visible"

        side_nav.agent_updates_tab.click()
        agent_update_page = AgentUpdatesPage()

        # Verify the page loads successfully
        wait(lambda: agent_update_page.is_element_present('agent_update_header'),
             waiting_for="Agent update page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        assert agent_update_page.is_element_present('agent_update_header'), \
            "Header of agent update page is not loaded."

        # Verify the url is correct for agent update page
        assert Nessus.Agents.AgentsUpdates.AGENT_UPDATES_ROUTE in get_driver_no_init().current_url, \
            'url for agent updates page is not matched.'

    @pytest.mark.xray(test_key='NES-15759')
    @pytest.mark.xray(test_key='NES-15754')
    def test_ui_components_for_agent_updates_page(self):
        """
            NES-15754 : Verify the UI Components/Sections into the 'Agents Updates' page
            NES-15759 : Verify the 'Agent Update Plan' Section.

            Scenario tested:
            [x] Checked all the required UI components are available on page
            [x] Section of agent update plan
        """
        agent_update_page = AgentUpdatesPage()
        agent_update_page.open()
        wait(lambda: agent_update_page.is_element_present('agent_updates_logo'),
             waiting_for="Agent update page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        assert agent_update_page.is_element_present('agent_update_header'), "Header of Agent update page is not loaded."

        # Verify all the required components of page
        assert all([agent_update_page.is_element_present("agent_updates_logo"),
                    agent_update_page.is_element_present("agent_updates_description"),
                    agent_update_page.is_element_present("enable_agent_updates"),
                    agent_update_page.is_element_present("agent_update_title"),
                    agent_update_page.is_element_present("selected_agent_update_option"),
                    agent_update_page.is_element_present("agent_update_save_button"),
                    agent_update_page.is_element_present("feed_box_rows"),
                    agent_update_page.is_element_present("manual_agent_update_button"),
                    agent_update_page.is_element_present("update_option_labels"),
                    agent_update_page.is_element_present("agent_update_cancel_button")]), \
            "Components of agent update page might be missing."

    @pytest.mark.xray(test_key='NES-15755')
    def test_instruction_on_agent_updates_page(self):
        """
            NES-15755 : Verify the instruction under the 'Agents Updates' page

            Scenario tested:
            [x] Instruction of agents update page
        """
        agent_update_page = AgentUpdatesPage()
        agent_update_page.open()
        wait(lambda: agent_update_page.is_element_present('agent_update_header'),
             waiting_for="Agent update page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)

        assert Nessus.Agents.AgentsUpdates.AGENT_UPDATES_DESCRIPTION == agent_update_page.agent_updates_description.text, \
            "Expected Instruction of Agent updates page is {}, but got {} instead.".format(
                Nessus.Agents.AgentsUpdates.AGENT_UPDATES_DESCRIPTION, agent_update_page.agent_updates_description.text)

    @pytest.mark.xray(test_key='NES-15758')
    @pytest.mark.xray(test_key='NES-15757')
    @pytest.mark.xray(test_key='NES-15756')
    def test_default_selection_for_automatic_updates_of_agents(self):
        """
            NES-15756 : Verify the default selection for 'Automatic Updates' section under the 'Agents Updates' page.
            NES-15757 : Verify the default selection of the 'Agent Update Plan'.
            NES-15758 : Verify the 'Automatic Updates' section.

            Scenario tested:
            [x] Default selection for automatic updates checkbox is selected
            [x] Default selection for agent update plan is selected
            [x] text of enabled agent update
        """
        agent_update_page = AgentUpdatesPage()
        agent_update_page.open()
        wait(lambda: agent_update_page.is_element_present('agent_update_header'),
             waiting_for="Agent update page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        assert agent_update_page.enable_agent_updates_text.text == Nessus.Agents.AgentsUpdates.ENABLE_AGENT_UPDATE_TEXT, \
            "Expected Enable agent update text is {}, but got {} instead.".format(
                Nessus.Agents.AgentsUpdates.ENABLE_AGENT_UPDATE_TEXT, agent_update_page.enable_agent_updates_text.text)
        assert agent_update_page.enable_agent_updates.is_selected(), "Enable agent updates checkbox is not selected."
        assert agent_update_page.default_update_plan_ga.is_selected(), "Agent update plan GA is not selected by default"

    @pytest.mark.xray(test_key='NES-15768')
    @pytest.mark.xray(test_key='NES-15767')
    def test_last_checked_refresh_icon_is_working(self):
        """
        NES-15768 : Verify that the refresh icon is functional for the 'Last checked available versions'.
        NES-15767 : Verify 'Last checked available versions' should display the correct time.

        Scenario Tested:
        [x] Refresh icon for the 'Last checked available versions'.
        [x] Refresh icon shows correct time.
        """
        agent_update_page = AgentUpdatesPage()
        agent_update_page.open()
        wait(lambda: agent_update_page.is_element_present('last_checked'),
             waiting_for="Agent update page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        current_time = datetime.today().strftime("%I:%M %p")[1:]
        last_checked = self.cat.api.agents.get_latest_agent_update_channels_endpoint()["agent_last_channel_check"]
        time_for_compare = agent_update_page.last_checked.text
        assert "Today at " in time_for_compare, \
            "Current day is not matched with latest checked day."
        # To Validate the time with difference in minutes (refer: ESQO-1176)
        assert current_time.split(":")[0] == time_for_compare.split(":")[0][-2:] if len(
            current_time.split(":")[0]) == 2 else current_time.split(":")[0] in time_for_compare.split(":")[0][-2:], \
            "Time is not matched."
        assert current_time[-2:] in time_for_compare[-2:], "AM and PM is not matched."

    @pytest.mark.xray(test_key='NES-15763')
    @pytest.mark.parametrize('label_name', [Nessus.Agents.AgentsUpdates.GA_FEED_BOX_LABEL,
                                            Nessus.Agents.AgentsUpdates.EA_FEED_BOX_LABEL,
                                            Nessus.Agents.AgentsUpdates.STABLE_FEED_BOX_LABEL,
                                            Nessus.Agents.AgentsUpdates.LAST_CHECKED_FEED_BOX_LABEL,
                                            Nessus.Agents.AgentsUpdates.UPDATED_FEED_BOX_LABEL,
                                            Nessus.Agents.AgentsUpdates.DOWNLOADED_VERSION_FEED_BOX_LABEL])
    def test_info_of_feed_box_labels_on_agent_update_page(self, label_name):
        """
        NES-15763 : Verify the information under the 'The Tenable feed is currently serving these Nessus agent channel
        versions:' section.
        Scenario Tested:
        [x] Labels and values of 'The Tenable feed is currently serving these Nessus agent channel versions:' section.
        """
        agent_update_page = AgentUpdatesPage()
        agent_update_page.open()
        wait(lambda: agent_update_page.is_element_present('agent_update_header'),
             waiting_for="Agent update page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)

        wait(lambda: len(agent_update_page.get_list_of_feed_box_labels_or_values()) != 0,
             timeout_seconds=const.WAIT_NORMAL, sleep_seconds=const.WAIT_SHORT,
             waiting_for="Waiting for labels to be added to list")
        expected_feed_box_labels = agent_update_page.get_list_of_feed_box_labels_or_values()
        log.info(expected_feed_box_labels)
        assert label_name in expected_feed_box_labels, \
            "Feed box label or labels may not exactly matched to expected naming."

    @pytest.mark.xray(test_key='NES-15762')
    @pytest.mark.xray(test_key='NES-15761')
    @pytest.mark.xray(test_key='NES-15760')
    @pytest.mark.parametrize('tip_toggle', [Nessus.Agents.AgentsUpdates.TOOLTIP_FOR_EA,
                                            Nessus.Agents.AgentsUpdates.TOOLTIP_FOR_GA,
                                            Nessus.Agents.AgentsUpdates.TOOLTIP_FOR_STABLE])
    def test_tip_toggle_of_agent_update_options(self, tip_toggle):
        """
            NES-15760 : Verify the info overlay while hovering over the '?' for 'GA releases (Default)' option.
            NES-15761 : Verify the info overlay while hovering over the '?' for 'Early Access releases' option.
            NES-15762 : Verify the info overlay while hovering over the '?' for 'Stable releases' option.

            Scenario tested:
            [x] Tool-tip text for all the agent update plan
        """
        agent_update_page = AgentUpdatesPage()
        agent_update_page.open()
        wait(lambda: agent_update_page.is_element_present('agent_update_header'),
             waiting_for="Agent update page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        assert tip_toggle == agent_update_page.get_text_of_tip_toggle_for_specific_channel(tip_toggle), \
            f"{tip_toggle} not matched on UI"

    @pytest.mark.xray(test_key='NES-15769')
    def test_currently_downloaded_agent_version_on_agent_updates_page(self):
        """
        NES-15769 : Verify the 'Currently downloaded version'
        Scenario tested:
        [x] Currently downloaded version
        """
        agent_update_page = AgentUpdatesPage()
        agent_update_page.open()
        wait(lambda: agent_update_page.is_element_present('agent_update_header'),
             waiting_for="Agent update page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_channel_info = self.cat.api.agents.get_agent_update_channels_info_from_manager()
        actual_cached_version = agent_channel_info['agent_cached']
        expected_downloaded_version = agent_update_page.get_value_of_specific_feed_box_label(
            label_name=Nessus.Agents.AgentsUpdates.DOWNLOADED_VERSION_FEED_BOX_LABEL)
        log.info(f"Agent cached version is {actual_cached_version} and downloaded agent "
                 f"version is {expected_downloaded_version}")
        if actual_cached_version is None and expected_downloaded_version == "N/A":
            pass
        else:
            assert actual_cached_version == expected_downloaded_version, "Currently downloaded version on UI " \
                                                                         "is not matched with API."

    @pytest.mark.xray(test_key='NES-15963')
    @pytest.mark.xray(test_key='NES-15962')
    @pytest.mark.xray(test_key='NES-15961')
    @pytest.mark.parametrize('channel', [Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                         Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                         Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION])
    def test_info_of_feed_box_versions_and_builds_on_agent_update_page(self, channel):
        """
            NES-15961 : Verify the version for 'General Availability' on the page with agents/update-channels API.
            NES-15962 : Verify the version for 'Early Access' on the page with agents/update-channels API.
            NES-15963 : Verify the version for 'Stable'  on the page with agents/update-channels API.

            Scenario tested:
            [x] UI checks of agent versions on page with compare to update-channels endpoints.
            [x] UI checks of agent builds on page with compare to update-channels endpoints
        """

        agent_update_page = AgentUpdatesPage()
        agent_update_page.open()
        self.cat.api.agents.get_latest_agent_update_channels_endpoint()
        wait(lambda: agent_update_page.is_element_present('agent_update_header'),
             waiting_for="Agent update page to get loaded.", timeout_seconds=TIME_TEN_SECONDS)
        agent_channel_info = self.cat.api.agents.get_agent_update_channels_info_from_manager()
        actual_version = agent_channel_info["agent_channel_versions"][channel]["version"]
        actual_build = agent_channel_info["agent_channel_versions"][channel]["build"]
        expected_build_version = agent_update_page.get_agent_version_from_feed_box_labels(channel)

        assert actual_version in expected_build_version, \
            f"Agent version for {channel} is incorrect on either UI or API."

        assert str(actual_build) in expected_build_version, \
            f"Agent build for {channel} is incorrect on either UI or API."
