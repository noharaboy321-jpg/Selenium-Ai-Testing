"""
Test cases related to Agents Page and Blackout Windows

:copyright: Tenable Network Security, 2017
:date: July 25, 2017
:last_modified: May 09, 2023
:author: @smadan, @rdutta, @ntarwani, @kpanchal, @krpatel.ctr, sacharya.ctr
"""
import csv
import os
import pathlib
import time
from operator import eq

import pytest
from catium.lib import const
from selenium.common.exceptions import InvalidElementStateException
from selenium.webdriver import ChromeOptions
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import load_testdata
from catium.helpers.util import get_browser_download_file_path
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.config import Config
from catium.lib.const import WAIT_NORMAL, WAIT_SHORT, TIME_TWO_MINUTES, GRID_BROWSER_DOWNLOAD_PATH, \
    TIME_FIFTEEN_SECONDS, TIME_FIVE_SECONDS
from nessus.apiobjects import routes
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS, WAIT_LONG, TIME_TEN_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.util import random_name, re
from catium.lib.webium.driver import get_driver, get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.apiobjects.endpoints.scanners import random_alphanumeric_string_for_linking_key
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import sorting, add_multiple_agents, create_freeze_window_via_api
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.helpers.utility import get_downloaded_files_chrome
from nessus.lib.const import SortOrder
from nessus.lib.const.constants import API, Nessus, NessusCli, Prefixes
from nessus.lib.message.messages import Messages
from nessus.pageobjects.agents.agent_blackout_windows_page import AgentBlackoutWindowsPage, AgentBlackoutWindowList, \
    AgentBlackoutWindowColumn, AgentBlackoutWindowSettingsPage
from nessus.pageobjects.agents.agent_cluster_page import AgentClusterPage, AgentClusterNodeList, AgentClusterNodePage, \
    AgentClusterNodeSettingsPage, AgentClusterNodeDetailsPage
from nessus.pageobjects.agents.agent_settings_page import AgentSettingsPage
from nessus.pageobjects.agents.agents_filter_page import FilterWindow
from nessus.pageobjects.agents.agents_page import AgentsList, AgentDetail, AgentSettingsTab
from nessus.pageobjects.agents.agents_page import AgentsPage
from nessus.pageobjects.agents.create_agent_blackout_window_page import CreateBlackoutWindowPage
from nessus.pageobjects.cluster.cluster_agent_page import AgentClusterMigration, AgentDetailsPage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanHistoryList
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()

timestamped_path = 'exported csv' + str(int(time.time()))  # use timestamp to differentiate test


@pytest.fixture()
def chrome_options():
    """Set download path for Chrome."""
    options = ChromeOptions()

    if Config.CAT_USE_GRID:
        directory = os.path.join(GRID_BROWSER_DOWNLOAD_PATH, timestamped_path)
    else:
        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path)

    prefs = {'download.default_directory': directory}
    options.add_experimental_option('prefs', prefs)
    return options


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestAgentsFreezeWindow:
    """Agent Blackout Window Related Test Cases"""
    cat = None

    @staticmethod
    def create_disabled_freeze_window() -> str:
        """
        This method creates disabled freeze window in Nessus Manager.
        :return: Name of freeze window created
        :rtype: str
        """
        freeze_window = AgentBlackoutWindowsPage()
        freeze_window.open()
        freeze_window.new_button.click()
        create_freeze_window = CreateBlackoutWindowPage()
        create_freeze_window.enable_toggle_button.click()
        freeze_window_name = random_name(prefix=Nessus.FreezeWindows.FREEZE_WINDOW + "-")
        create_freeze_window.name_field.value = freeze_window_name
        return freeze_window_name

    @staticmethod
    def save_and_verify_freeze_window_created_or_edited_successfully(freeze_window_name: str, success_message: str,
                                                                     disabled: bool = False) -> bool:
        """
        This method save the freeze window and verifies whether freeze window created or edited successfully.
        :param str freeze_window_name: Name of freeze window
        :param str success_message: Success message to be verified after freeze window created/edited.
        :param bool disabled: True if freeze window is of 'Disabled' category else False
        :return : None
        """
        create_freeze_window = CreateBlackoutWindowPage()
        freeze_windows_list = AgentBlackoutWindowList()
        create_freeze_window.save_button.click()
        notifications = Notifications()
        assert notifications.successes[-1] == success_message, \
            "Missing notification while creating/editing freeze window."
        freeze_windows_list.loaded()
        freeze_window_name_in_list = "Disabled\n" + freeze_window_name if disabled else freeze_window_name
        wait(lambda: AgentBlackoutWindowsPage().is_element_present('search_window'))
        assert freeze_window_name_in_list in freeze_windows_list.blackout_window_all_names, \
            "Created/Edited freeze window is not present in list."

    def test_set_invalid_time_settings(self):
        """
        Agent Settings - Ensure it is not possible to set inactive agent time less than 30 days - NQA- 570
        Test updated according to https://jira.corp.tenablesecurity.com/browse/CS-18192
        """
        agent_settings_page = AgentSettingsPage()
        agent_settings_page.open()
        LoadingCircle(WAIT_SHORT)

        try:
            agent_settings_page.set_inactive_agent_time(days=366)

            assert Notifications().errors[-1] == Messages.NotificationMessages.invalid_time_integer, \
                "Validation for minimum days not working"

            assert 'error' in agent_settings_page.unlink_input.get_css_classes(), \
                'Remove inactive agent input field is not highlighted with \'Red\' color border.'
        except InvalidElementStateException:
            log.warning('Unlink agents have already been enabled')

    @pytest.mark.parametrize("create_blackout_window", API.Schedule.Frequencies.VALID_FREQUENCIES,
                             indirect=True)
    def test_enable_disable_blackout_window(self, create_blackout_window):
        """
        Agent - Blackout Windows - Ensure it is possible disable and enable agent blackout window - NQA-420

        1. Create agent blackout window with particular frequency.
        2. Disable newly created blackout window.
        3. Enable the disabled blackout window.
        4. Repeat for each frequency.
        """
        new_blackout_window_name = create_blackout_window
        LoadingCircle(WAIT_SHORT)
        AgentBlackoutWindowsPage().toggle_agent_blackout_window(blackout_window_name=new_blackout_window_name,
                                                                option=API.Status.DISABLE)

        disable_blackout_window_name = API.Status.DISABLED + "\n" + new_blackout_window_name

        agent_blackout_list = AgentBlackoutWindowList()
        for disabled_list in agent_blackout_list.rows:
            if disabled_list.record_name_element.text == disable_blackout_window_name:
                assert not disabled_list.blackout_enabled, "Agent Blackout Window not disabled"

        AgentBlackoutWindowsPage().toggle_agent_blackout_window(blackout_window_name=disable_blackout_window_name,
                                                                option=API.Status.ENABLE)
        for enabled_list in agent_blackout_list.rows:
            if enabled_list.record_name_element.text == new_blackout_window_name:
                assert enabled_list.blackout_enabled, "Agent Blackout Window not enabled"

        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("sort", (["desc", "asc"]))
    @pytest.mark.parametrize("create_blackout_window_list", [{'freq': API.Schedule.Frequencies.VALID_FREQUENCIES,
                                                              'shouldwait': False}], indirect=True)
    def test_blackout_window_sorting_name(self, create_blackout_window_list, sort):
        """
        Agent - Blackout Windows - Ensure it is possible sort agent blackout window on the basis of name - NQA-420

        1. Create a list of agent-blackout-window with different frequencies.
        2. Click on the arrow attached with name tab for descending order.
        3. Verify list sorted in descending manner.
        4. Again Click on the arrow attached if its downwards for ascending order.
        5. Verify list sorted in ascending manner.
        """
        agent_blackout_list = AgentBlackoutWindowList()
        name_column = AgentBlackoutWindowColumn()
        if eq(sort, "desc"):
            name_column.col_name.sort_descending()
            blackout_name_list = agent_blackout_list.blackout_window_all_names

            desc_sorted_list = sorted(blackout_name_list, key=lambda s: s.lower(), reverse=True)
            assert blackout_name_list == desc_sorted_list, "Names are not sorted in descending order"
        elif eq(sort, "asc"):
            name_column.col_name.sort_ascending()
            blackout_name_list = agent_blackout_list.blackout_window_all_names

            asc_sorted_list = sorted(blackout_name_list, key=lambda s: s.lower())
            assert blackout_name_list == asc_sorted_list, "Names are not sorted in ascending order"

    @pytest.mark.parametrize("create_blackout_window_list", [{'freq': API.Schedule.Frequencies.VALID_FREQUENCIES,
                                                              'shouldwait': True}], indirect=True)
    @pytest.mark.parametrize("sort", (["desc", "asc"]))
    def test_blackout_window_sorting_last_modified(self, create_blackout_window_list, sort):
        """
        Agent - Blackout Windows - Ensure it is possible sort agent blackout
        window on the basis of last modified column - NQA-420

        1. Create a list of agent-blackout-window with different frequencies.
        2. Click on the last modified column to unhide the arrow attached with the column
        3. Click on the arrow for descending order.
        4. Verify list sorted in descending manner.
        5. Again Click on the arrow attached if its downwards for ascending order.
        6. Verify list sorted in ascending manner.
        """
        agent_blackout_list = AgentBlackoutWindowList()
        last_modified_column = AgentBlackoutWindowColumn()
        if eq(sort, "desc"):
            last_modified_column.col_date.sort_descending()
            blackout_last_modified_list = agent_blackout_list.blackout_window_last_modified_list

            desc_sorted_list = sorted(blackout_last_modified_list, key=sorting, reverse=True)
            assert blackout_last_modified_list == desc_sorted_list, "Names are not sorted in descending order"
        elif eq(sort, "asc"):
            last_modified_column.col_date.sort_ascending()
            blackout_last_modified_list = agent_blackout_list.blackout_window_last_modified_list

            asc_sorted_list = sorted(blackout_last_modified_list, key=sorting)
            assert blackout_last_modified_list == asc_sorted_list, "Names are not sorted in descending order"

    @pytest.mark.parametrize("create_blackout_window", [API.Schedule.Frequencies.FREQ_ONCE],
                             indirect=True)
    def test_duplicate_blackout_name(self, create_blackout_window):
        """
        Agent - Blackout Windows - Ensure it is not possible to create
        two agent blackout windows with same name - NQA-420
        """
        AgentBlackoutWindowsPage().new_button.click()
        CreateBlackoutWindowPage().new_blackout_window(
            name=create_blackout_window, frequency=API.Schedule.Frequencies.FREQ_ONCE.title())

        assert Notifications().errors[-1] == Messages.NotificationMessages.duplicate_name, \
            "Failed, can create duplicate name blackout-window"
        get_driver().back()

    @pytest.mark.parametrize("create_blackout_window_list", [{'freq': API.Schedule.Frequencies.VALID_FREQUENCIES,
                                                              'shouldwait': False}], indirect=True)
    def test_delete_agent_blackout_window(self, create_blackout_window_list):
        """
        Agent - Blackout Windows - Ensure it is possible to delete agent blackout window NQA-420

        1. Create a list of agent-blackout-window with different frequencies.
        2. Click on X- icon of first row to delete the agent blackout window
        3. Click on select-all checkbox to delete all the agent blackout windows left
        4. Verify list does not exist anymore.
        """
        wait(lambda: AgentBlackoutWindowsPage().is_element_present('search_window'))
        agent_blackout_list = AgentBlackoutWindowList()
        blackout_window_names = agent_blackout_list.blackout_window_all_names
        first_blackout_window_name = blackout_window_names[0]
        agent_blackout_list.delete_blackout_windows(first_blackout_window_name)

        if first_blackout_window_name not in agent_blackout_list.blackout_window_all_names:
            assert True, "Unable to delete blackout window using X icon"

        LoadingCircle(WAIT_NORMAL)

        AgentBlackoutWindowsPage().delete_blackout_window_list()
        LoadingCircle(WAIT_NORMAL)
        if not agent_blackout_list.exists():
            assert True, 'Unable to delete blackout window using select-all checkbox'

    @pytest.mark.parametrize("create_blackout_window", [API.Schedule.Frequencies.FREQ_ONCE],
                             indirect=True)
    def test_blackout_once_window_edit(self, create_blackout_window):
        """
        Agent - Blackout Windows - Ensure it is possible edit agent blackout window with once frequency - NQA-420

        1. Create a agent-blackout-window whose frequency is once.
        2. Click on the created blackout window to edit it.
        3. Change tha name of the blackout window.
        4. Save the changes.
        5. Retrieve the list to verify if the name changed exist or not.
        6. Delete the created agent-blackout-window.
        """
        edit_name = random_name(prefix="blackout-window-")

        new_blackout_window_name = create_blackout_window

        agent_blackout_list = AgentBlackoutWindowList()
        agent_blackout_list.click_on_created_window(new_blackout_window_name)

        CreateBlackoutWindowPage().new_blackout_window(name=edit_name,
                                                       frequency=API.Schedule.Frequencies.FREQ_ONCE.title())

        assert edit_name in agent_blackout_list.blackout_window_all_names, \
            'Unable to edit blackout window with name "%s" ' % edit_name

        agent_blackout_list.delete_blackout_windows(blackout_window_name=edit_name)
        try:
            if edit_name in agent_blackout_list.blackout_window_all_names:
                log.warning('Unable to delete edited blackout window')
        except Exception as e:
            log.warning("Agent Blackout List is empty, Exception is :: {}".format(e))

    @pytest.mark.parametrize("create_blackout_window", [API.Schedule.Frequencies.FREQ_DAILY],
                             indirect=True)
    def test_blackout_daily_window_edit(self, create_blackout_window):
        """
        Agent - Blackout Windows - Ensure it is possible edit agent blackout window with daily frequency - NQA-420

        1. Create a agent-blackout-window whose frequency is daily.
        2. Click on the created blackout window to edit it.
        3. CLick on the repeat every dropdown and select any option.
        4. Save the changes.
        5. Retrieve the list to verify if the changes are done in the created blackout window.
        """
        days = "3 Days"

        new_blackout_window_name = create_blackout_window

        agent_blackout_list = AgentBlackoutWindowList()
        agent_blackout_list.click_on_created_window(new_blackout_window_name)

        edit_blackout_page = CreateBlackoutWindowPage()
        edit_blackout_page.select_save_frequency(edit_blackout_page.repeat_every, days)

        notifications = Notifications()
        success_notification = notifications.successes[-1]

        assert success_notification == Messages.NotificationMessages.edit_success, \
            "Missing notification for edited blackout window"

        result = agent_blackout_list.get_schedule_summary_of_created_window(
            edit_blackout_window_name=new_blackout_window_name, frequency=days)
        assert result, 'Unable to edit blackout window with frequency "%s" ' % days

    @pytest.mark.parametrize("create_blackout_window", [API.Schedule.Frequencies.FREQ_WEEKLY],
                             indirect=True)
    def test_blackout_weekly_window_edit(self, create_blackout_window):
        """
        Agent - Blackout Windows - Ensure it is possible edit agent blackout window with weekly frequency - NQA-420

        1. Create a agent-blackout-window whose frequency is weekly.
        2. Click on the created blackout window to edit it.
        3. Choose any day of the repeat on list.
        4. Save the changes.
        5. Retrieve the list to verify if the changes are done in the created blackout window.
        """
        selected_day = "M"
        selected_day_value = "Monday"

        new_blackout_window_name = create_blackout_window

        agent_blackout_list = AgentBlackoutWindowList()
        agent_blackout_list.click_on_created_window(new_blackout_window_name)

        CreateBlackoutWindowPage().select_week_day(selected_day)

        notifications = Notifications()
        success_notification = notifications.successes[-1]

        assert success_notification == Messages.NotificationMessages.edit_success, \
            "Missing notification for edited blackout window"

        result = agent_blackout_list.get_schedule_summary_of_created_window(
            edit_blackout_window_name=new_blackout_window_name, frequency=selected_day_value)
        assert result, 'Unable to edit blackout window with frequency "%s" ' % selected_day_value

    @pytest.mark.parametrize("create_blackout_window", [API.Schedule.Frequencies.FREQ_MONTHLY],
                             indirect=True)
    def test_blackout_monthly_window_edit(self, create_blackout_window):
        """
        Agent - Blackout Windows - Ensure it is possible edit agent
        blackout window with monthly frequency - NQA- 420

        1. Create a agent-blackout-window whose frequency is monthly.
        2. Click on the created blackout window to edit it.
        3. CLick on the repeat every and repeat by dropdown and select any option in both the dropdown.
        4. Save the changes.
        5. Retrieve the list to verify if the changes are done in the created blackout window.
        """
        repeat_month = "3 Months"

        new_blackout_window_name = create_blackout_window

        agent_blackout_list = AgentBlackoutWindowList()
        agent_blackout_list.click_on_created_window(new_blackout_window_name)

        edit_blackout_page = CreateBlackoutWindowPage()
        edit_blackout_page.select_save_frequency(edit_blackout_page.repeat_every, repeat_month)

        assert Notifications().successes[-1] == Messages.NotificationMessages.edit_success, \
            "Missing notification for edited blackout window"

        result = agent_blackout_list.get_schedule_summary_of_created_window(
            edit_blackout_window_name=new_blackout_window_name, frequency=repeat_month)
        assert result, 'Unable to edit blackout window with frequency "%s" ' % repeat_month

    @pytest.mark.parametrize("create_blackout_window", [API.Schedule.Frequencies.FREQ_YEARLY],
                             indirect=True)
    def test_blackout_yearly_window_edit(self, create_blackout_window):
        """
        Agent - Blackout Windows - Ensure it is possible edit agent blackout window with yearly frequency - NQA-420

        1. Create a agent-blackout-window whose frequency is yearly.
        2. Click on the created blackout window to edit it.
        3. CLick on the repeat every dropdown and select any option.
        4. Save the changes.
        5. Retrieve the list to verify if the changes are done in the created blackout window.
        """
        year = "3 Years"

        new_blackout_window_name = create_blackout_window

        agent_blackout_list = AgentBlackoutWindowList()
        agent_blackout_list.click_on_created_window(new_blackout_window_name)

        edit_blackout_page = CreateBlackoutWindowPage()
        edit_blackout_page.select_save_frequency(edit_blackout_page.repeat_every, year)

        assert Notifications().successes[-1] == Messages.NotificationMessages.edit_success, \
            "Missing notification for edited blackout window"

        result = agent_blackout_list.get_schedule_summary_of_created_window(
            edit_blackout_window_name=new_blackout_window_name, frequency=year)
        assert result, 'Unable to edit blackout window with frequency "%s" ' % year

    @pytest.mark.parametrize("setting, preference", [("permanent blackout", NessusCli.BWPreferences.PERMANENT_BLACKOUT),
                                                     ("core updates", NessusCli.BWPreferences.CORE_UPDATES),
                                                     ("plugin updates", NessusCli.BWPreferences.PLUGIN_UPDATES),
                                                     ("agent scans", NessusCli.BWPreferences.AGENT_SCANS)])
    @pytest.mark.parametrize("checkbox_value", [True, False])
    def test_verify_preference_value_for_checkbox(self, setting, preference, checkbox_value):
        """
        AGENT-1555: agent blackout windows testing: stand-alone test automation
        Verify that the each checkbox under Agent Settings Page related to blackout window
        saves to the correct preference database value.
        Steps:
        1. Navigate to Agent settings page
        2. Check/uncheck permanent blackout checkbox
        3. verify through nessus cli that the setting is yes/no as per the checkbox value
        4. Repeat above steps for plugin updates, core updates and agent scans
        """
        agent_bw_setting_page = AgentBlackoutWindowSettingsPage()
        agent_bw_setting_page.open()
        LoadingCircle(WAIT_NORMAL)
        agent_bw_setting_page.get_checkbox_element_for_blackout_window(data_name=setting).set_checked(checkbox_value)
        agent_bw_setting_page.save_button.click()

        wait(lambda: visibility_of_element_located(agent_bw_setting_page.get_checkbox_element_for_blackout_window(
            data_name=setting)), waiting_for="Freeze Window settings page to get loaded on UI.")
        assert agent_bw_setting_page.get_checkbox_element_for_blackout_window(
            data_name=setting).is_selected() == checkbox_value, 'Checkbox value on UI is incorrect'

        output = [execute(get_nessus_cli(), ['fix', '--get', preference])['stdout']]

        value_dict = dict()
        config_keyvalue_pair = re.compile(r"'(\w+)'")

        for item in output:
            match = config_keyvalue_pair.findall(item)
            if match and len(match) > 1:
                key = match[0].strip()
                value_dict[key] = match[1].strip()
            elif len(match) <= 1 and "Could not retrieve value for" in match[0]:
                log.debug("Configuration setting not present in list: %s", ("\n".join(match[0])))

        if output != '':
            log.debug("Configuration setting command returned message: %s", ("\n".join(output)))

        expected_value = "yes" if checkbox_value else 'no'
        assert value_dict[preference] == expected_value, "Expected setting for {} to be {}".format(preference,
                                                                                                   expected_value)

    def test_full_day_blackout_window_saves_and_loads_properly(self):
        """
        NES-11218 : Confirm an all-day blackout window schedule saves and loads properly
        Steps:
            1. While creating blackout window, verify that end_time has a option with label as "24:00" and
                corresponding value as "23:59:59"
            2. Create a full day blackout window and verify that it saved properly without any issues.
        Scenarios Tested:
            [X] Verify full day blackout window saves and loads properly.
        """
        blackout_window_name = random_name(prefix="Blackout_window-")
        create_blackout_window = CreateBlackoutWindowPage()
        blackout_window_list = AgentBlackoutWindowList()
        create_blackout_window.open()
        wait(lambda: create_blackout_window.is_element_present("end_time"), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for="Blackout window creation page to load properly.")
        create_blackout_window.configure_full_day_blackout_window(name=blackout_window_name, save_bw=False)
        bw_end_time_options = create_blackout_window.end_time.option_values

        # Verify that end_time has a option with label as "24:00" and  corresponding value as "23:59:59"
        assert any(option['label'] == "24:00" and option['value'] == "23:59:59" for option in bw_end_time_options), \
            "Inside 'End time' dropdown, option with label as '24:00' and value as '23:59:59' not found. "
        create_blackout_window.save_button.click()
        try:
            wait(lambda: AgentBlackoutWindowsPage().is_element_present("search_window"),
                 timeout_seconds=TIME_THIRTY_SECONDS, waiting_for="Blackout window list to get loaded.")

            # Verify that blackout window with full day saved successfully.
            assert blackout_window_name in blackout_window_list.blackout_window_all_names, \
                "Blackout window does not saved."
        finally:
            blackout_window_list.delete_blackout_windows(blackout_window_name=blackout_window_name)

    def test_verify_available_frequencies_while_creating_freeze_window(self):
        """
        NES-12593 : [UI Automation] Verify available frequencies while creating freeze window

        Scenarios Tested:
            [X] Verify available frequencies while creating freeze window
        """
        create_blackout_window = CreateBlackoutWindowPage()
        create_blackout_window.open()
        wait(lambda: create_blackout_window.is_element_present("end_time"), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for="Blackout window creation page to load properly.")
        available_frequencies = create_blackout_window.frequency.option_values

        # Verify available frequencies while creating freeze window.
        assert set([frequency.title() for frequency in API.Schedule.Frequencies.VALID_FREQUENCIES]) == set(
            [frequency.get('label') for frequency in available_frequencies]), \
            "Expected frequencies are not available while creating freeze window."

    @pytest.mark.xray(test_key='NES-15382')
    @pytest.mark.xray(test_key='NES-14872')
    @pytest.mark.parametrize('create_users_using_api', [
        [API.Permissions.User.SYSTEM_ADMINISTRATOR, API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_freeze_window_page_in_nessus_manager(self, nessus_api_login, create_users_using_api,
                                                  delete_all_exclusions):
        """
        NES-12649 : [UI-Automation] Verify Blackout window is replaced with Freeze window in all over UI
        NES-13039 : [Automation]: Verify inclusive language changes of Freeze window with different users
        NES-15382 : Verify UI of Freeze window
        NES-14872 : Verify Freeze window in URL when you access the freeze window link from the side menu of the sensor tab.


        Scenario Tested:
            [x] Verify that 'Freeze window' tab is available in side navigation bar.
            [x] Verify that create new freeze window link is present and has expected text.
            [x] Verify that Freeze window page has freeze window tab and settings tab.
            [x] Verify that Freeze window page title and description is correct.
            [x] Verify that Freeze window page url is correct.
        """
        created_user = create_users_using_api

        for user_detail in created_user:
            UserMenu().logout()
            LoginPage().login_with_credentials(username=user_detail['name'], password=user_detail['password'])

            HeaderBasePage().sensors_tab.click()
            freeze_window_page = AgentBlackoutWindowsPage()
            side_nav = SideNav()

            try:
                wait(lambda: side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.FREEZE_WINDOWS),
                     waiting_for="'Freeze Windows' tab to get loaded")
            except TimeoutExpired:
                raise AssertionError("Freeze Windows' tab is not present in side navigation bar.")

            side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.FREEZE_WINDOWS).click()
            wait(lambda: freeze_window_page.is_element_present('new_button'),
                 waiting_for="Freeze Window page to get loaded.")

            # Verify Freeze window UI is populated with correct Tabs/URL/Title text/Link text
            assert freeze_window_page.is_element_present('freeze_window_tab') and freeze_window_page. \
                is_element_present('freeze_window_settings_tab'), "Freeze window and Settings tab are not present."

            assert freeze_window_page.freeze_window_description.text == Nessus.FreezeWindows. \
                FREEZE_WINDOW_DESCRIPTION, "Freeze window description is incorrect."

            assert freeze_window_page.freeze_window_title.text == Nessus.FreezeWindows.FREEZE_WINDOW_TITLE, \
                "Freeze window page title is incorrect"

            assert freeze_window_page.create_new_freeze_window.text == Nessus.FreezeWindows.CREATE_FREEZE_WINDOW, \
                "Create new freeze window link URL is incorrect."

            assert freeze_window_page.freeze_window_tab.text == Nessus.FreezeWindows.FREEZE_WINDOW_TAB, \
                "Freeze Window tab text is not correct."

            assert Nessus.FreezeWindows.AGENT_FREEZE_WINDOW in freeze_window_page.current_url, \
                "'{}' is not present in Freeze window page URL.".format(Nessus.FreezeWindows.AGENT_FREEZE_WINDOW)

    @pytest.mark.parametrize('create_users_using_api', [
        [API.Permissions.User.SYSTEM_ADMINISTRATOR, API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_verify_name_field_placeholder_while_creating_freeze_window(self, nessus_api_login, create_users_using_api):
        """
        NES-12649 : [UI-Automation] Verify Blackout window is replaced with Freeze window in all over UI
        NES-13039 : [Automation]: Verify inclusive language changes of Freeze window with different users

        Scenario Tested:
            [x] Verify that name field while creating freeze window has placeholder as "Freeze Window".
        """
        created_user = create_users_using_api

        for user_detail in created_user:
            UserMenu().logout()
            LoginPage().login_with_credentials(username=user_detail['name'], password=user_detail['password'])

            freeze_windows_page = AgentBlackoutWindowsPage()
            freeze_windows_page.open()
            freeze_windows_page.new_button.click()

            assert Nessus.FreezeWindows.FREEZE_WINDOW in CreateBlackoutWindowPage().name_field.get_attribute(
                'placeholder'), "Schedule Freeze window name field's place holder is incorrect."

    @pytest.mark.parametrize('create_users_using_api', [
        [API.Permissions.User.SYSTEM_ADMINISTRATOR, API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_verify_options_in_settings_tab_of_freeze_windows(self, nessus_api_login, create_users_using_api):
        """
        NES-12649 : [UI-Automation] Verify Blackout window is replaced with Freeze window in all over UI
        NES-13039 : [Automation]: Verify inclusive language changes of Freeze window with different users

        Scenario Tested:
            [x] Verify that freeze window settings tab options are properly populated.
        """
        created_user = create_users_using_api

        for user_detail in created_user:
            UserMenu().logout()
            LoginPage().login_with_credentials(username=user_detail['name'], password=user_detail['password'])

            freeze_windows_page = AgentBlackoutWindowsPage()
            freeze_windows_page.open()

            freeze_windows_page.freeze_window_settings_tab.click()
            wait(lambda: freeze_windows_page.is_element_present('setting_options'),
                 waiting_for="Freeze Windows Settings tab to get loaded.")

            assert [option.text for option in freeze_windows_page.setting_options] == \
                   Nessus.FreezeWindows.FREEZE_WINDOW_SETTING_OPTIONS

    @pytest.mark.parametrize('create_users_using_api', [
        [API.Permissions.User.SYSTEM_ADMINISTRATOR, API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_verify_freeze_window_creation(self, nessus_api_login, create_users_using_api):
        """
        NES-12649 : [UI-Automation] Verify Blackout window is replaced with Freeze window in all over UI
        NES-13040 [Automation]: Verify Freeze window in notification.

        Scenario Tested:
            [x] Verify that page url has "freeze-window' while creating freeze window.
            [x] Verify success notification for freeze window creation.
        """
        created_user = create_users_using_api

        for user_detail in created_user:
            UserMenu().logout()
            LoginPage().login_with_credentials(username=user_detail['name'], password=user_detail['password'])

            freeze_windows_page = AgentBlackoutWindowsPage()
            freeze_windows_page.open()

            freeze_windows_page.new_button.click()
            create_freeze_window = CreateBlackoutWindowPage()

            # Verify that page url has "freeze-window' while creating freeze window.
            assert Nessus.FreezeWindows.NEW_FREEZE_WINDOW in create_freeze_window.current_url, \
                "'freeze-window' is not present in page url while creating new freeze window."

            freeze_window_name = random_name(prefix="FreezeWindow-")
            create_freeze_window.new_blackout_window(freeze_window_name, API.Schedule.Frequencies.FREQ_ONCE.title())

            # Verify success notification for freeze window creation.
            assert Notifications().successes[-1] == Messages.NotificationMessages.freeze_window_create_success, \
                "Missing notification for freeze window creation"

            wait(lambda: freeze_windows_page.is_element_present('search_window'),
                 waiting_for="Freeze Window list get loaded")

            assert freeze_window_name in AgentBlackoutWindowList().blackout_window_all_names, \
                "Failed to create '{}' freeze window.".format(freeze_window_name)

    @pytest.mark.parametrize('create_users_using_api', [
        [API.Permissions.User.SYSTEM_ADMINISTRATOR, API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_verify_delete_freeze_window(self, nessus_api_login, create_users_using_api):
        """
        NES-12649 : [UI-Automation] Verify Blackout window is replaced with Freeze window in all over UI
        NES-13040 [Automation]: Verify Freeze window in notification.

        Scenario Tested:
            [x] Verify the pop up details while deleting schedule freeze window
            [x] Verify that delete freeze window operation has expected notification.
        """
        created_user = create_users_using_api
        user_menu = UserMenu()

        for user_detail in created_user:
            user_menu.logout()
            LoginPage().login_with_credentials(username=user_detail['name'], password=user_detail['password'])

            freeze_windows_page = AgentBlackoutWindowsPage()
            freeze_windows_page.open()
            wait(lambda: freeze_windows_page.is_element_present('new_button'),
                 waiting_for="Freeze Window page to get loaded.")

            nessus_api = NessusAPI()
            nessus_api.login(username=user_detail['name'], password=user_detail['password'])
            freeze_window_name = create_freeze_window_via_api(api=nessus_api)

            agent_freeze_window_list = AgentBlackoutWindowList()
            agent_freeze_window_list.refresh()
            wait(lambda: freeze_window_name in agent_freeze_window_list.blackout_window_all_names,
                 waiting_for="Created freeze window to be appear in list")

            agent_freeze_window_list.delete_blackout_windows(freeze_window_name, close_modal=False)
            delete_fw_pop_up = ActionCloseModal()

            # Verify Delete freeze window pop up details
            assert delete_fw_pop_up.modal_title.text == Nessus.FreezeWindows.DELETE_FW_POP_UP_TITLE, \
                "Freeze window delete pop up title is incorrect."

            assert delete_fw_pop_up.modal_content.text == Nessus.FreezeWindows.DELETE_FW_POP_UP_TEXT, \
                "Freeze window delete pop up text is incorrect."

            delete_fw_pop_up.accept_action()
            delete_fw_pop_up.wait_for_modal_closed()

            # Verify the notification message for deleting freeze window.
            notifications = Notifications()

            assert notifications.successes[-1] == Messages.NotificationMessages.freeze_window_delete_success, \
                "Missing notification for deleting freeze window"

            wait(lambda: freeze_windows_page.is_element_present('freeze_window_description'),
                 waiting_for="Freeze Window list get loaded")

            assert freeze_window_name not in agent_freeze_window_list.blackout_window_all_names, \
                "Failed to delete '{}' freeze window.".format(freeze_window_name)

        user_menu.logout()
        login_page = LoginPage()
        wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)

        login_page.login_with_defaults()
        user_menu.loaded()

    @pytest.mark.parametrize('create_users_using_api', [
        [API.Permissions.User.SYSTEM_ADMINISTRATOR, API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_verify_edit_freeze_window(self, nessus_api_login, create_users_using_api):
        """
        NES-13040 [Automation]: Verify Freeze window in notification.

        Scenario Tested:
            [x] Verify that edit freeze window operation has expected notification.
        """
        created_user = create_users_using_api

        for user_detail in created_user:
            UserMenu().logout()
            LoginPage().login_with_credentials(username=user_detail['name'], password=user_detail['password'])

            freeze_windows_page = AgentBlackoutWindowsPage()
            freeze_windows_page.open()
            wait(lambda: freeze_windows_page.is_element_present('new_button'),
                 waiting_for="Freeze Window page to get loaded.")

            nessus_api = NessusAPI()
            nessus_api.login(username=user_detail['name'], password=user_detail['password'])

            created_freeze_window_name = create_freeze_window_via_api(api=nessus_api)
            edited_freeze_window_name = "Edited {}".format(created_freeze_window_name)

            agent_freeze_window_list = AgentBlackoutWindowList()
            agent_freeze_window_list.refresh()
            wait(lambda: created_freeze_window_name in agent_freeze_window_list.blackout_window_all_names,
                 waiting_for="Created freeze window to be appear in list")

            agent_freeze_window_list.click_on_created_window(created_freeze_window_name)
            edit_blackout_page = CreateBlackoutWindowPage()
            wait(lambda: edit_blackout_page.is_element_present('frequency'),
                 waiting_for="Create Freeze Window page to get loaded.")

            edit_blackout_page.name_field.clear()
            edit_blackout_page.name_field.value = edited_freeze_window_name
            edit_blackout_page.select_save_frequency(edit_blackout_page.frequency,
                                                     API.Schedule.Frequencies.FREQ_ONCE.title())

            notifications = Notifications()

            assert notifications.successes[-1] == Messages.NotificationMessages.edit_success, \
                "Missing notification for edited blackout window"

            wait(lambda: freeze_windows_page.is_element_present('search_window'),
                 waiting_for="Freeze Window list get loaded")

            assert edited_freeze_window_name in agent_freeze_window_list.blackout_window_all_names, \
                "Failed to edit '{}' freeze window.".format(created_freeze_window_name)

    def test_schedule_freeze_window_page_elements_visibility(self):
        """
        NES-13066 : [UI - Automation] : Automate 'schedule freeze window' elements visibility and
                    search button for freeze window

        Scenario Tested:
            [x] Verify that all elements appears on created schedule freeze window screen.
        """
        freeze_window = AgentBlackoutWindowsPage()
        freeze_window.open()
        create_freeze_window = CreateBlackoutWindowPage()
        freeze_window.new_button.click()
        try:
            wait(lambda: create_freeze_window.is_element_present('frequency'),
                 waiting_for="Schedule freeze window creation page to get loaded.", timeout_seconds=TIME_FIVE_SECONDS)
        except TimeoutExpired:
            raise AssertionError("'Frequency' element is not present on create schedule freeze window page.")
        assert create_freeze_window.is_element_present('name_field'), \
            "Name field is not present create schedule freeze window page."
        assert create_freeze_window.is_element_present('enable_toggle_button'), \
            "Enable/Disable toggle button is not present on create schedule freeze window page."
        assert create_freeze_window.is_element_present('start_time'), \
            "Start time is not present on create schedule freeze window page."
        assert create_freeze_window.is_element_present('start_date'), \
            "Start date is not present on create schedule freeze window page."
        assert create_freeze_window.is_element_present('end_time'), \
            "End time is not present on create schedule freeze window page."
        assert create_freeze_window.is_element_present('end_date'), \
            "End date is not present on create schedule freeze window page."
        assert create_freeze_window.is_element_present('time_zone'), \
            "Time-zone is not present on create schedule freeze window page."
        assert create_freeze_window.is_element_present('summary'), \
            "Summary is not present on create schedule freeze window page."

    @pytest.mark.xray(test_key='NES-15471')
    @pytest.mark.parametrize('create_freeze_windows_with_new_endpoint', [
        (random_name(prefix='freeze-window-'), random_name(prefix='freeze-window-'),
         random_name(prefix='freeze-windows-'), random_name(prefix='freeze-windows-'),
         random_name(prefix='freeze-windows-'))], indirect=True)
    @pytest.mark.parametrize('search_freeze_window', ['freeze-window-', 'freeze-windows-'])
    @pytest.mark.usefixtures('nessus_api_login', 'delete_all_exclusions', 'create_freeze_windows_with_new_endpoint')
    def test_verify_freeze_window_search_works_properly(self, create_freeze_windows_with_new_endpoint,
                                                        search_freeze_window):
        """
        NES-13066 : [UI - Automation] : Automate 'schedule freeze window' elements visibility and
                    search button for freeze window
        NES-15471 : Verify search for Freeze window

        Scenario Tested:
            [x] Verify that freeze window search functions properly.
        """
        freeze_windows = [freeze_window['name'] for freeze_window in create_freeze_windows_with_new_endpoint]
        freeze_window = AgentBlackoutWindowsPage()
        freeze_window.open()
        wait(lambda: freeze_window.is_element_present('new_button'),
             waiting_for="Schedule freeze window creation page to get loaded.", timeout_seconds=TIME_FIVE_SECONDS)
        freeze_window_list = AgentBlackoutWindowList()
        freeze_window_list.loaded()
        freeze_window.search_window.value = search_freeze_window

        # Verify that only searched freeze windows get populated.
        try:
            wait(lambda: set(freeze_window_list.blackout_window_all_names) == set(
                [freeze_window for freeze_window in freeze_windows if search_freeze_window in freeze_window]),
                 timeout_seconds=TIME_FIVE_SECONDS)
        except AssertionError:
            raise AssertionError("Freeze windows populated in table are not as per search input given by user.")

    @pytest.mark.usefixtures('nessus_api_login', 'delete_all_exclusions')
    def test_verify_disabled_freeze_window_creation(self):
        """
        NES-13143 : [UI - Automation] : Automate different scenarios for freeze window creation page

        Scenario Tested:
            [x] Verify that disabled freeze window can be created by providing only freeze window name.
        """
        freeze_windows_list = AgentBlackoutWindowList()
        create_freeze_window = CreateBlackoutWindowPage()
        freeze_window_name = self.create_disabled_freeze_window()
        assert not create_freeze_window.is_element_present('frequency'), \
            "Frequency field is present on disabled freeze window creation screen."
        assert not create_freeze_window.is_element_present('start_date'), \
            "Start date field is present on disabled freeze window creation screen."
        assert not create_freeze_window.is_element_present('start_time'), \
            "Start time field is present on disabled freeze window creation screen."
        assert not create_freeze_window.is_element_present('end_time'), \
            "End time field is present on disabled freeze window creation screen."
        assert not create_freeze_window.is_element_present('end_date'), \
            "End date field is present on disabled freeze window creation screen."
        assert not create_freeze_window.is_element_present('summary'), \
            "Summary field is present on disabled freeze window creation screen."
        try:
            # Verify that disabled freeze window can be created successfully.
            self.save_and_verify_freeze_window_created_or_edited_successfully(
                freeze_window_name=freeze_window_name,
                success_message=Messages.NotificationMessages.freeze_window_create_success, disabled=True)
        finally:
            freeze_windows_list.delete_blackout_windows(blackout_window_name="Disabled\n" + freeze_window_name)

    @pytest.mark.xray(test_key='NES-15502')
    @pytest.mark.usefixtures('nessus_api_login', 'delete_all_exclusions')
    def test_verify_creating_disabled_freeze_window(self):
        """
        NES-15502 : Verify by creating disabled freeze window

        Scenario Tested:
            [x] Verify that disabled freeze window can be created and labeled is correct.
        """
        freeze_windows_list = AgentBlackoutWindowList()
        freeze_window_name = self.create_disabled_freeze_window()

        try:
            # Verify that disabled freeze window can be created successfully.
            self.save_and_verify_freeze_window_created_or_edited_successfully(
                freeze_window_name=freeze_window_name,
                success_message=Messages.NotificationMessages.freeze_window_create_success, disabled=True)
        finally:
            freeze_windows_list.delete_blackout_windows(blackout_window_name="Disabled\n" + freeze_window_name)

    @pytest.mark.usefixtures('nessus_api_login', 'delete_all_exclusions')
    def test_verify_disabled_freeze_window_can_be_edited(self):
        """
        NES-13143 : [UI - Automation] : Automate different scenarios for freeze window creation page

        Scenario Tested:
            [x] Verify that disabled freeze window can be edited by modifying freeze window name.
        """
        new_freeze_window_name = random_name(prefix=Nessus.FreezeWindows.FREEZE_WINDOW + "-")
        freeze_windows_list = AgentBlackoutWindowList()
        freeze_window_name = self.create_disabled_freeze_window()

        try:
            self.save_and_verify_freeze_window_created_or_edited_successfully(
                freeze_window_name=freeze_window_name,
                success_message=Messages.NotificationMessages.freeze_window_create_success, disabled=True)

            freeze_windows_list.click_on_created_window("Disabled\n" + freeze_window_name)
            CreateBlackoutWindowPage().name_field.value = new_freeze_window_name

            # Verify that disabled freeze window can be edited successfully.
            self.save_and_verify_freeze_window_created_or_edited_successfully(
                freeze_window_name=new_freeze_window_name,
                success_message=Messages.NotificationMessages.freeze_window_edit_success, disabled=True)
        finally:
            freeze_windows_list.delete_blackout_windows(blackout_window_name="Disabled\n" + new_freeze_window_name)

    @pytest.mark.xray(test_key='NES-15486')
    @pytest.mark.usefixtures('nessus_api_login', 'delete_all_exclusions')
    def test_UI_while_creating_new_freeze_window(self):
        """
        NES-15486 : Verify UI of scheduling Freeze window

        Scenario Tested:
            [x] Verify UI of creating freeze window page
        """
        freeze_window = AgentBlackoutWindowsPage()
        freeze_window.open()
        wait(lambda: freeze_window.is_element_present('create_new_freeze_window'))
        freeze_window.new_button.click()
        wait(lambda: freeze_window.is_element_present('summary_field'), waiting_for='freeze window page to get load')
        assert all([freeze_window.is_element_present("freeze_window_title"),
                    freeze_window.is_element_present("back_to_freeze_window"),
                    freeze_window.is_element_present("name_field"),
                    freeze_window.is_element_present("enabled_toogle_field"),
                    freeze_window.is_element_present("enabled_toogle_button"),
                    freeze_window.is_element_present("start_time_dropdown"),
                    freeze_window.is_element_present("end_time_dropdown"),
                    freeze_window.is_element_present("frequency_dropdown"),
                    freeze_window.is_element_present("start_date_dropdown"),
                    freeze_window.is_element_present("end_date_dropdown"),
                    freeze_window.is_element_present("timezone_dropdown"),
                    freeze_window.is_element_present("save_button"),
                    freeze_window.is_element_present("cancel_button")]), "Something is missing on the page"

    @pytest.mark.usefixtures('nessus_api_login', 'delete_all_exclusions')
    def test_create_new_freeze_window_link(self):
        """
        NES-13143 : [UI - Automation] : Automate different scenarios for freeze window creation page

        Scenario Tested:
            [x] Verify that 'create a new freeze window' link works properly
        """
        freeze_window = AgentBlackoutWindowsPage()
        freeze_window.open()
        wait(lambda: freeze_window.is_element_present('create_new_freeze_window'))
        freeze_window.create_new_freeze_window.click()
        # Verify that 'Create a new freeze window' link redirects to proper Page.
        assert Nessus.FreezeWindows.NEW_FREEZE_WINDOW in freeze_window.current_url, \
            "'freeze-window' is not present in page url while creating new freeze window."
        assert Nessus.FreezeWindows.NEW_FREEZE_WINDOW_TITLE in CreateBlackoutWindowPage().page_title.text, \
            "'New Freeze Window' title is not present in page url while creating new freeze window."

    @pytest.mark.xray(test_key='NES-15278')
    @pytest.mark.usefixtures('nessus_api_login', 'delete_all_exclusions')
    def test_verify_edit_disabled_freeze_window(self):
        """
        NES-15278 : Verify to edit disabled freeze window

        Scenario Tested:
            [x] Verify freeze window can be edited successfully.
        """
        freeze_windows_list = AgentBlackoutWindowList()
        freeze_window_name = self.create_disabled_freeze_window()

        try:
            self.save_and_verify_freeze_window_created_or_edited_successfully(
                freeze_window_name=freeze_window_name,
                success_message=Messages.NotificationMessages.freeze_window_create_success, disabled=True)

            freeze_windows_list.click_on_created_window("Disabled\n" + freeze_window_name)
            new_freeze_window_name = random_name(prefix=Nessus.FreezeWindows.FREEZE_WINDOW + "-")
            CreateBlackoutWindowPage().name_field.value = new_freeze_window_name

            self.save_and_verify_freeze_window_created_or_edited_successfully(
                freeze_window_name=new_freeze_window_name,
                success_message=Messages.NotificationMessages.freeze_window_edit_success, disabled=True)
        finally:
            freeze_windows_list.delete_blackout_windows(blackout_window_name="Disabled\n" + new_freeze_window_name)


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestAgentsPage:
    """Tests related to Agents Page in Nessus Manager"""

    cat = None

    @staticmethod
    def add_agents_to_group(group_name: str) -> None:
        """
        Add agents into group

        :param str group_name: Group name
        :return: None
        """
        AgentsPage().add_to_groups_button.click()
        agent_detail = AgentDetail()
        agent_detail.get_member_group_element(agent_group_name=group_name).click()
        agent_detail.accept_action()
        agent_detail.wait_for_modal_closed()

    @staticmethod
    def verify_visibility_of_options_under_agents_and_scanners_section(is_visible: bool, section_options: dict) -> None:
        """
        Verifies the visibility of options available under Agents/Scanners section and those are clickable after
        clicking on 'Hide/Show' link

        :param bool is_visible: True if options should be visible else False
        :param dict section_options: options details that to be visible there
        :return: None
        """
        side_nav = SideNav()

        for option_name, option_endpoint in section_options.items():
            option_element = side_nav.get_sidenav_element(element_name=option_name)

            if is_visible:
                assert visibility_of_element_located(option_element), \
                    "'{}' option is not visible after clicking on 'Show' link.".format(option_name)

                option_element.click()
                wait(lambda: visibility_of_element_located(side_nav.header_title), waiting_for="Page to be loaded")

                title_name = "Cluster Setup" if option_name == Nessus.SideNavResources.AGENT_CLUSTERING else option_name

                assert all([get_driver_no_init().current_url.endswith(option_endpoint),
                            side_nav.header_title.text == title_name]), \
                    "'{}' option is not clickable.".format(option_name)
            else:
                assert invisibility_of_element_located(option_element), \
                    "'{}' option is still visible after clicking on 'Hide' link.".format(option_name)

    @staticmethod
    def sort_given_column_in_agent_table(sort: str, column_name: str, agents_list: AgentsList):
        """
        Sort given column in Agent table.
        :param str sort: Order of sorting : ascending/descending
        :param str column_name: Name of column which needs to be sorted in ascending/descending order
        :param AgentsList agents_list: Instance of AgentsList class
        :return : None
        """
        column_class_name = agents_list.get_column_header_element(column_name=column_name).get_attribute('class')
        if (SortOrder.DESCENDING in column_class_name and sort == SortOrder.ASCENDING) or (
                SortOrder.ASCENDING in column_class_name and sort == SortOrder.DESCENDING):
            agents_list.get_column_header_element(column_name=column_name).click()
            agents_list.loaded()
        elif column_class_name == "pointer":
            for i in range(2 if sort == SortOrder.DESCENDING else 1):
                agents_list.get_column_header_element(column_name=column_name).click()
                agents_list.loaded()

    @pytest.mark.parametrize('section_name', [Nessus.SideNavResources.AGENTS, Nessus.SideNavResources.SCANNERS])
    def test_visibility_of_hide_and_show_links_in_sensors_sidebar(self, section_name):
        """
        NES-13016: [Automation]: Verify "Hide" and "Show" link for Agents and Scanners under Sensors tab

        Scenario Tested:
        [x] Verify the 'Hide' option should be shown on side bar
        [x] Verify the 'Show' option should be shown on side bar
        """
        HeaderBasePage().sensors_tab.click()
        wait(lambda: visibility_of_element_located(AgentsPage().linking_key_text),
             waiting_for="Sensors page to load properly")

        side_nav_sub_option = Nessus.SideNavResources.LINKED_AGENTS if section_name == Nessus.SideNavResources.AGENTS \
            else Nessus.SideNavResources.SCANNERS

        show_hide_link_element = SideNav().get_section_show_hide_link(section_name=section_name,
                                                                      side_nav_sub_option=side_nav_sub_option)

        try:
            assert visibility_of_element_located((show_hide_link_element.we_by, show_hide_link_element.we_value)), \
                "'Hide' link is missing in '{}' section under sensors tab.".format(section_name)

            # Verify show/hide title
            if section_name == Nessus.SideNavResources.AGENTS:
                AgentsPage().linked_agents.location_once_scrolled_into_view
                AgentsPage().linked_agents.click()
            else:
                AgentsPage().linked_scanner.location_once_scrolled_into_view
                AgentsPage().linked_scanner.click()

            assert show_hide_link_element.text == "Hide", "Show hide link text is different"

            show_hide_link_element.click()

            assert visibility_of_element_located((show_hide_link_element.we_by, show_hide_link_element.we_value)), \
                "'Show' link is missing in '{}' section under sensors tab.".format(section_name)

            # Verify show/hide title
            assert show_hide_link_element.text == "Show", "Show hide link text is different"
        finally:
            if show_hide_link_element.text == "Show":
                show_hide_link_element.click()

    @pytest.mark.parametrize('section_name', [Nessus.SideNavResources.AGENTS, Nessus.SideNavResources.SCANNERS])
    def test_options_available_under_agents_section_are_clickable_in_sensors_sidebar(self, section_name):
        """
        NES-13017: [Automation]: Verify that options available under "Agents" section are clickable
        NES-13018: [Automation]: Verify that options available under "Scanners" section are clickable

        Scenario Tested:
        [x] Verify options of Agents section is clickable
        [x] Verify 'Show' will expand the agents section
        [x] Verify 'Hide' will collapse the agents section
        [x] Verify options of Scanners section is clickable
        [x] Verify 'Show' will expand the scanners section
        [x] Verify 'Hide' will collapse the scanners section
        """
        agents_section_options = {Nessus.SideNavResources.LINKED_AGENTS: "/sensors/agents",
                                  Nessus.SideNavResources.AGENT_GROUPS: "/sensors/agent-groups",
                                  Nessus.SideNavResources.AGENT_CLUSTERING: "/sensors/agent-cluster-migration",
                                  Nessus.SideNavResources.FREEZE_WINDOWS: "/sensors/agent-freeze-windows"}

        scanners_section_options = {Nessus.SideNavResources.SCANNERS: "/sensors/scanners"}

        HeaderBasePage().sensors_tab.click()
        wait(lambda: visibility_of_element_located(AgentsPage().linking_key_text),
             waiting_for="Sensors page to load properly")

        side_nav_sub_option = Nessus.SideNavResources.LINKED_AGENTS if section_name == Nessus.SideNavResources.AGENTS \
            else Nessus.SideNavResources.SCANNERS

        show_hide_link_element = SideNav().get_section_show_hide_link(section_name=section_name,
                                                                      side_nav_sub_option=side_nav_sub_option)

        if section_name == Nessus.SideNavResources.AGENTS:
            AgentsPage().linked_agents.location_once_scrolled_into_view
            AgentsPage().linked_agents.click()
        else:
            AgentsPage().linked_scanner.location_once_scrolled_into_view
            AgentsPage().linked_scanner.click()

        if show_hide_link_element.text == "Show":
            show_hide_link_element.click()

        section_options = agents_section_options if section_name == Nessus.SideNavResources.AGENTS else \
            scanners_section_options

        show_hide_link_element.click()
        self.verify_visibility_of_options_under_agents_and_scanners_section(is_visible=False,
                                                                            section_options=section_options)

        show_hide_link_element.click()
        self.verify_visibility_of_options_under_agents_and_scanners_section(is_visible=True,
                                                                            section_options=section_options)

    @pytest.mark.usefixtures('nessus_api_login')
    def test_distinct_linking_key_for_agent(self):
        """
        NES-17414 : Validate Distinct Linking Keys for agent in UI.

        Scenario Tested:
        [x] Verify API and UI linking keys are same.

        Steps:
        1. Setting up Nessus Manager
        2. Taking random 64 characters key to set
        3. using the set method of agent linking key
        4. Opening the sensors tab in browser UI
        5. Go to agent page and checking the keys
        6. Comparing the UI and API keys.
        """
        agent_page = AgentsPage()

        # Generating random 64 character keys
        agent_key = random_alphanumeric_string_for_linking_key(64)

        # setting the new agent linking key to nessus manager
        self.cat.api.agent_groups.set_agent_linking_key(agent_key=agent_key)

        HeaderBasePage().sensors_tab.click()
        wait(lambda: visibility_of_element_located(agent_page.linking_key_text),
             waiting_for="Sensors page to load properly")
        HeaderBasePage().refresh()

        # going to linked agents page
        wait(lambda: visibility_of_element_located(agent_page.linking_key_text),
             waiting_for="Sensors page to load properly")
        key = agent_page.linking_key_text.text

        # Verify newly set linking key via API is reflected on UI
        assert agent_key in key, "Linking key is not updated."

    @pytest.mark.usefixtures('nessus_api_login')
    def test_distinct_linking_key_for_scanner(self):
        """
        NES-17414 : Validate Distinct Linking Keys for scanner in UI.

        Scenario Tested:
        [x] Verify API and UI linking keys are same.

        Steps:
        1. Setting up Nessus Manager
        2. Taking random 64 characters key to set
        3. using the set method of scanner linking key
        4. Opening the sensors tab in browser UI
        5. Go to scanner page and checking the keys
        6. Comparing the UI and API keys.
        """
        agent_page = AgentsPage()

        # Generating random 64 character keys
        scanner_key = random_alphanumeric_string_for_linking_key(64)

        # Setting new scanner linking key via API
        self.cat.api.agent_groups.set_scanner_linking_key(scanner_key=scanner_key)

        HeaderBasePage().sensors_tab.click()
        wait(lambda: visibility_of_element_located(agent_page.linking_key_text),
             waiting_for="Sensors page to load properly")
        HeaderBasePage().linked_scanner.click()

        # going to linked scanner page
        wait(lambda: visibility_of_element_located(agent_page.linking_key_text),
             waiting_for="Sensors page to load properly")
        key = agent_page.linking_key_text.text

        # Verify the newly set linking key is reflected on UI
        assert scanner_key in key, "Linking key is not updated."

    @pytest.mark.browser_file_download
    @pytest.mark.parametrize('nessus_create_nessus_agent_group', [[1]], indirect=True)
    def test_export_csv_for_linked_agents(self, nessus_api_login, nessus_create_nessus_agent_group, chrome_options):
        """
        AGENT-771: Export list of Agents in Nessus Manager - multiple filters applied
        1. Add 1000 plus agents
        2. Navigate to Agents page
        3. Apply multiple filters
        4. Export list of agents after filters applied
        5. Open the file and verify number of agents listed matches number of agents in Nessus Manager UI.
        6. Verify Columns displaying data for:
            -Agent Name
            -Status
            -IP Address
            -Platform
            -Groups
            -Version
            -Last Plugin Update
            -Last Scanned

        Scenarios Tested:
        [X] Verify that after export, the list of agents in the file matches the list of agents on Nessus Manager UI
        [X] Verify the columns display data for 'Agent Name', 'Status', 'IP Address', 'Platform', 'Groups', 'Version',
            'Last Plugin Update', 'Last Scanned'
        """

        agents_page = AgentsPage()
        agents_page.open()

        with add_multiple_agents(nessus_api_login, 1010):
            agents_page.refresh()
            LoadingCircle(WAIT_NORMAL)

            agents_list = []

            agent_list = AgentsList()
            for row, agent in enumerate(agent_list.rows, start=1):
                if row < 25:
                    agents_list.append(agent.agent_name.text)
                else:
                    break
            group_name = random_name(prefix="Agents-group-")
            agent_list.select_deselect_agents(agents_list=agents_list)

            agents_page.js_scroll_into_view(agents_page.new_group_button)
            agents_page.create_group(group_name=group_name)
            wait(lambda: agents_page.is_element_present('filter_link'), waiting_for="filter link to be visible",
                 timeout_seconds=TIME_TWO_MINUTES)

            SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.LINKED_AGENTS).click()
            agent_list.loaded()

            filters = [{'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.MEMBER_OF_GROUP,
                        'filter_operator': Nessus.Agents.Filter.IS_EQUAL_TO, 'filter_value': group_name},
                       {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.PLATFORM,
                        'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': "Win"},
                       {'match_type': Nessus.Filter.FilterMatch.ALL, 'filter_key': Nessus.Agents.Filter.NAME,
                        'filter_operator': Nessus.Agents.Filter.CONTAINS, 'filter_value': '2'}]

            agent_filter_window = FilterWindow()

            for filter in filters:
                agent_filter_window.add_and_apply_filter(**filter)

            filtered_agents = agent_list.get_all_agents_by_name()

            agents_page.export_button.click()
            sleep(sleep_time=TIME_FIFTEEN_SECONDS * 3, reason="Waiting for file to be downloaded")

            downloaded_file_name = get_downloaded_files_chrome(filename="agents")
            file_name = downloaded_file_name[0].split('//')[1]
            file_name = file_name.split('/')[-1]
            log.info("File: " + file_name)

            directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)

            log.info("Directory is {}".format(directory))
            source_path = get_browser_download_file_path(directory)
            assert pathlib.Path(source_path).exists()

            count = 0
            with open(file=source_path, mode='rt') as csv_file:
                raw_data = csv.reader(csv_file, delimiter=',')

                assert next(raw_data, None), 'Exported scan CSV file should not be blank.'

                for _ in raw_data:
                    count += 1

                assert count == len(filtered_agents), \
                    'The count of filtered agents in CSV does not match the count on UI'

            with open(file=source_path, mode='rt') as csv_file:
                raw_data = csv.reader(csv_file, delimiter=',')

                assert list(raw_data)[0] == ['Agent Name', 'Status', 'IP Address', 'Platform', 'Groups', 'Version',
                                             'Last Plugin Update', 'Last Scanned'], 'One or more columns are missing'

    def test_export_icon_visibility(self):
        """
        AGENT-770: [Test Automation] Export list of Agents in Nessus Manager - Export button existence
        Steps:
        1. Navigate to Agents Page from Resources>Agents>Linked Agents
        2. Verify that export button is present on right upper corner of the page
        3. Navigate to Agents Groups page
        4. Verify that export button does not exists
        5. Repeat 3 and 4 for Blackout Windows and Agent Settings

        Scenarios Tested:
        [X] Verify that export button exists on Linked Agents tab and not present on Agent Groups,
            Blackout Windows and Agent Settings tab
        """
        agents_page = AgentsPage()
        agents_page.open()

        # Verifies 'Export' button is present on Linked Agents tab
        assert agents_page.is_element_present('export_button'), 'Export button is not visible on Linked Agents tab'

        agents_page.agent_settings_tab_link.click()

        # Verifies 'Export' button is not present on Agents Settings tab
        assert not agents_page.is_element_present('export_button'), 'Export button is visible on Agents Settings tab'

        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.GROUPS).click()

        # Verifies 'Export' button is not present on Agents Groups tab
        assert not agents_page.is_element_present('export_button'), 'Export button is visible on Agents Groups tab'

        side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.FREEZE_WINDOWS).click()

        # Verifies 'Export' button is not present on Blackout Windows tab
        assert not agents_page.is_element_present('export_button'), 'Export button is visible on Blackout Windows tab'

        agents_page.bw_settings_tab_link.click()

        # Verifies 'Export' button is not present on Blackout Windows settings tab
        assert not agents_page.is_element_present('export_button'), \
            'Export button is visible on Blackout Windows Settings tab'

    @pytest.mark.xfail(reason="We don't have an automated cluster setup for Bamboo plan.")
    @pytest.mark.parametrize('max_agent', [20, 25])
    def test_max_agent_setting(self, max_agent):
        """
        NES-9353: Cluster Automation - UI - Node Listing and Details

        Steps:
        4. Visit the Settings tab in the Node details page
        5. Update the "max agents" setting
        6. Verify that the new setting is correctly shown in the node details page after changing it.
        """
        agents_page = AgentsPage()
        agents_page.open()
        agents_page.cluster_tab_link.click()
        wait(lambda: visibility_of_element_located(AgentClusterPage().search_box), waiting_for='cluster page to load')

        cluster_node_list = AgentClusterNodeList()
        cluster_node_list.click_on_cluster_node(node_name=cluster_node_list.cluster_nodes_all_name[0])

        cluster_node_page = AgentClusterNodePage()
        cluster_node_page.node_settings_link.click()

        node_setting_page = AgentClusterNodeSettingsPage()
        node_setting_page.set_max_agent(agent=max_agent)

        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster.node_updated, \
            "Success message for updating max agent is mismatched or missing."

        cluster_node_page.node_details_link.click()

        # Verify 'Agents' count in node details after setting 'Max Agents' count in node settings
        assert AgentClusterNodeDetailsPage().total_agents_count == max_agent, \
            "Agents count is not updated after setting 'Max Agents' in node settings page."

    @pytest.mark.xfail(reason='We don\'t have an automated cluster setup for Bamboo plan.')
    @pytest.mark.parametrize('set_max_agent', [
        {'agent': 'less_agent', 'usage_color': 'rgba(212, 63, 58, 1)', 'color': 'Red', 'usage_warning':
            Nessus.Agents.Cluster.MAX_AGENTS_EXCEEDED},
        {'agent': 'equal_agent', 'usage_color': 'rgba(212, 63, 58, 1)', 'color': 'Red', 'usage_warning':
            Nessus.Agents.Cluster.MAX_AGENTS},
        {'agent': 'more_agent', 'usage_color': 'rgba(238, 147, 54, 1)', 'color': 'Orange', 'usage_warning':
            Nessus.Agents.Cluster.NEAR_MAX_AGENTS}])
    def test_node_usage_of_agent_cluster_node(self, set_max_agent):
        """
        NES-9353: Cluster Automation - UI - Node Listing and Details

        Scenario Tested:
        [x] Verify that Node usage progress bar color should be 'Red' and displayed with '(Max Agents)' warning message
            when we linked agents similar to max agents.
        [x] Verify that Node usage progress bar color should be 'Orange' and displayed with '(Near Max Agents)' warning
            message when linked agent reaches near to max agents.
        [x] Verify that Node usage progress bar color should be 'Red' and displayed with '(Max Agents Exceeded)' warning
            message when linked agents exceeds the max agents limit.
        """
        # Going to cluster tab under Agents
        agents_page = AgentsPage()
        agents_page.open()
        agents_page.cluster_tab_link.click()
        wait(lambda: visibility_of_element_located(AgentClusterPage().search_box), waiting_for='cluster page to load')

        cluster_node_list = AgentClusterNodeList()
        node_name = cluster_node_list.cluster_nodes_all_name[0]
        cluster_node_list.click_on_cluster_node(node_name=node_name)

        # Get linked agents count
        linked_agents = AgentClusterNodeDetailsPage().linked_agents_count

        if set_max_agent['agent'] == 'less_agent':
            linked_agents -= 1
        elif set_max_agent['agent'] == 'more_agent':
            linked_agents += 1

        AgentClusterNodePage().node_settings_link.click()

        node_setting_page = AgentClusterNodeSettingsPage()
        node_setting_page.set_max_agent(agent=linked_agents)

        # Verify success notification after updating max agents count
        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster.node_updated, \
            'Getting incorrect notification message, expected is {}'.format(Messages.NotificationMessages.Agents.
                                                                            AgentCluster.node_updated)

        node_setting_page.back_to_cluster_link.click()
        wait(lambda: visibility_of_element_located(AgentClusterPage().search_box), waiting_for='cluster page to load')

        # Get node usage color of node from node list under cluster tab
        node_usage_color = cluster_node_list.get_node_usage_color(node_name=node_name)

        # Get node usage warning message of node from node list under cluster tab
        node_usage_warning = cluster_node_list.get_node_usage_warning(node_name=node_name)[0].split('%')[1].lstrip()

        # Verify Node usage progress bar color while we set max agents count is less than, more than or equal to linked
        # agents count
        assert node_usage_color == set_max_agent['usage_color'], 'Node usage progress bar is not displayed in ' \
                                                                 '{} color.'.format(set_max_agent['color'])

        # Verify Node usage warning message while we set max agents count is less than, more than or equal to linked
        # agents count
        assert node_usage_warning == set_max_agent['usage_warning'], \
            'Getting incorrect notification message, expected is {}'.format(set_max_agent['usage_warning'])

        # Verify 'Rebalanced Node' button is displayed on top right corner
        assert AgentClusterPage().is_element_present('rebalance_button'), '\'Rebalance node\' button is not displayed' \
                                                                          ' on top right corner.'

    @pytest.mark.xfail(reason='We don\'t have an automated cluster setup for Bamboo plan.')
    def test_enable_disable_node_of_agent_cluster(self):
        """
        NES-9353: Cluster Automation - UI - Node Listing and Details

        Scenario Tested:
        [x] Verify that user should be able to enable/disable node.
        [x] Verify that 'Enable' button should be display on top right corner after selecting disable node.
        [x] Verify that only 'Delete' button should be display when we select all enable and disable nodes from node
            list under cluster tab.
        """
        # Going to cluster tab under Agents
        agents_page = AgentsPage()
        agents_page.open()
        agents_page.cluster_tab_link.click()
        wait(lambda: visibility_of_element_located(AgentClusterPage().search_box), waiting_for='cluster page to load')

        # Disable cluster node
        node_list = AgentClusterNodeList()
        node_name = node_list.cluster_nodes_all_name[0]
        node_list.enable_disable_cluster_node(node_name=node_name, enable=False)

        # Verify success notification after disabling cluster node
        notification = Notifications()
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster.node_disabled, \
            'Getting incorrect notification message, expected is {}'.format(
                Messages.NotificationMessages.Agents.AgentCluster.node_disabled)

        # Verify cluster node is getting disable after click on 'Disable' link
        assert node_list.get_enable_disable_tool_tip_text(node_name=node_name) == Nessus.Agents.Cluster.ENABLE, \
            'Cluster node is not getting disable after click on \'Disable\' link.'

        node_list.select_cluster_node(node_name=node_name)
        cluster_page = AgentClusterPage()

        # Verify 'Enable' and 'Delete' buttons are displayed on top right corner
        assert all([cluster_page.is_element_present('enable_button'),
                    cluster_page.is_element_present('delete_button')]), \
            '\'Disable\' and \'Delete\' buttons are not displayed on top right corner after selecting all nodes.'

        node_list.select_cluster_node(node_name=node_name)
        node_list.select_all_checkbox.click()

        # Verify 'Enable' button is not displayed when we select all enable and disable nodes and only 'Delete' button
        # is displayed
        assert all([not cluster_page.is_element_present('enable_button'),
                    cluster_page.is_element_present('delete_button')]), \
            '\'Disable\' and \'Delete\' buttons are not displayed on top right corner after selecting all nodes.'

        # Enable cluster node
        node_list.select_all_checkbox.click()
        node_list.select_cluster_node(node_name=node_name)
        node_list.enable_cluster_node()

        # Verify success notification after enabling cluster node
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster.node_enabled, \
            'Getting incorrect notification message, expected is {}'.format(
                Messages.NotificationMessages.Agents.AgentCluster.node_enabled)

        # Verify cluster node is getting enabled after clicking on 'Enable' button
        assert node_list.get_enable_disable_tool_tip_text(node_name=node_name) == Nessus.Agents.Cluster.DISABLE, \
            'Cluster node is not getting enabled after clicking on \'Enable\' link.'

    @pytest.mark.xfail(reason='We don\'t have an automated cluster setup for Bamboo plan.')
    @pytest.mark.parametrize('create_agent_groups', [{'agent_group_details': [
        {'agent_group_name': Prefixes.AGENT_GROUP}]}], indirect=True)
    @pytest.mark.parametrize('create_scans', [
        {'scans_details': [{'scan_template': Nessus.TemplateNames.ADVANCED_AGENT,
                            'scan_type': Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                            'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED_AGENT)),
                            'add_configuration': True}]}], indirect=True)
    def test_agent_scan_with_cluster_node(self, create_agent_groups, create_scans):
        """
        NES-9353: Cluster Automation - UI - Node Listing and Details

        Scenario Tested:
        [x] Verify that node status should display 'Scanning' when user run the scan and that running scan should be
            visible under node details.
        [x] Verify that user can see the 'Node' dropdown and 'Agent Details' section like agent group, number of
            cluster node and reported agents in scan results page.
        [x] Verify that user should be able to export individual node's scan results.
        [x] Verify that user should be able to delete individual node's scan history.
        """
        # Create scan with agent group
        scan_form = NewScanForm()
        agent_group_name = create_agent_groups[0]
        scan_form.fill_new_scan_detail(agent_group=agent_group_name)
        scan_form.save_button.click()

        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Getting incorrect notification message, expected is {}'.format(Messages.NotificationMessages.save_scan)

        # Get linked agent list
        agent_page = AgentsPage()
        agent_page.open()
        agent_list = AgentsList()
        linked_agent_list = agent_list.get_all_agents_by_name()

        # Add agents to created agent group
        SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.LINKED_AGENTS).click()
        wait(lambda: visibility_of_element_located(agent_page.filter_link), waiting_for='Agent page to load')
        agent_list.select_deselect_agents(agents_list=linked_agent_list[:2])
        TestAgentsPage().add_agents_to_group(group_name=agent_group_name)

        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentGroups. \
            agents_added_to_groups, 'Getting incorrect notification message, expected is {}'.format(
            Messages.NotificationMessages.Agents.AgentGroups)

        scan_name = create_scans[0]
        header_page = HeaderBasePage()
        header_page.scan_link.click()

        # Launch created scan
        scan_page = ScansPage()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')
        scan_page.launch_scan(scan_list=scan_name, select_all=False)

        scan_page.refresh()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')

        agent_page.open()
        agent_page.cluster_tab_link.click()
        wait(lambda: visibility_of_element_located(AgentClusterPage().search_box), waiting_for='cluster page to load')

        node_list = AgentClusterNodeList()
        node = node_list.rows[0]

        # Verify scan status of cluster node
        assert node.agent_cluster_node_status == Nessus.Agents.Cluster.SCANNING, \
            '\'Scanning\' status is not displayed in node list after launching scan.'

        # Verify scan count of cluster node
        assert node.agent_cluster_node_scans == 1, '\'Scans\' count in node list is not displayed or mismatched.'

        node.click()
        node_details_page = AgentClusterNodeDetailsPage()
        wait(lambda: visibility_of_element_located(node_details_page.search_box), waiting_for='Node details to load')

        # Verify scan search box under node details
        assert node_details_page.is_element_present('search_box'), 'Scan search box is not displayed.'

        # Verify scan is displayed under node details
        assert len(AgentClusterNodeList().rows), 'Scan is not displayed under node details.'

        header_page.scan_link.click()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='Scan page to load')

        # Waiting for scan to be completed
        scan_list = ScanList()
        scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, launch_scan=False)
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present('header_element', timeout=TIME_THIRTY_SECONDS),
             waiting_for='Scan header to become visible')

        # Verify 'Node' dropdown under scan results page
        assert scan_view_page.is_element_present('node_dropdown'), '\'Node\' dropdown is not displayed in ' \
                                                                   'Scan results page.'

        # Verify 'Agent Details' header is displayed in scan results page
        assert scan_view_page.is_element_present('agent_details_column_header'), \
            '\'Agent Details\' column header is not displayed in Scan results page.'

        # Verify 'Agent Details' section is displayed in scan results page
        assert scan_view_page.is_element_present('agent_details_section'), \
            '\'Agent Details\' section is not displayed in Scan results page.'

        agent_details = {Nessus.Scan.Results.AgentDetailsLevels.AGENT_GROUPS: agent_group_name,
                         Nessus.Scan.Results.AgentDetailsLevels.AGENT_CLUSTER: '2 nodes',
                         Nessus.Scan.Results.AgentDetailsLevels.REPORTED: '2 of 2 agents'}

        for level in Nessus.Scan.Results.AgentDetailsLevels.DEFAULT_LEVELS:
            agent_detail_value = agent_details[level]
            expected_agent_detail_value = scan_view_page.get_levels_value_of_details_section(level).text

            # Verify agent details in 'Agent Details' section
            assert agent_detail_value == expected_agent_detail_value, \
                'Getting incorrect notification message, expected is {}'.format(expected_agent_detail_value)

        for format_type in [API.Scan.UIExportFormats.FORMAT_PDF, API.Scan.UIExportFormats.FORMAT_CSV,
                            API.Scan.UIExportFormats.FORMAT_HTML]:
            scan_view_page.export_scan_in_format(format_type=format_type)

            wait(lambda: not WindowsHandler().is_alert_present(), timeout_seconds=TIME_THIRTY_SECONDS,
                 sleep_seconds=WAIT_NORMAL)
            assert not WindowsHandler().is_alert_present(), 'Export has failed.'

            sleep(WAIT_LONG, reason='Waiting for file to download')
            downloaded_file = get_downloaded_files_chrome()

            log.debug('Downloaded pcap file is :: {}'.format(downloaded_file))
            file_name = scan_name.split(".")[0]

            assert file_name in downloaded_file[0], 'Scan results did not export successfully.'

        scan_view_page.history_tab.click()
        history_list = ScanHistoryList()

        # Delete scan history
        history_list.select_all_checkbox.click()
        history_list.rows[0].remove.click()
        ActionCloseModal().accept_action()

        # Verify success notification after deleting scan history
        assert Notifications().successes[-1] == Messages.NotificationMessages.ScanResults.history_deleted, \
            'Getting incorrect notification message, expected is {}'.format(Messages.NotificationMessages.ScanResults.
                                                                            history_deleted)

    @pytest.mark.xfail(reason='We don\'t have an automated cluster setup for Bamboo plan.')
    def test_rebalancing_node_of_cluster(self):
        """
        NES-9353: Cluster Automation - UI - Node Listing and Details

        Scenario Tested:
        [x] Verify that user should be able to rebalance node by clicking on 'Rebalance Node' button.
        [x] Verify that user can see the rebalancing node notice message above the node search box.
        """
        # Going to cluster tab under Agents
        agents_page = AgentsPage()
        agents_page.open()
        agents_page.cluster_tab_link.click()

        cluster_page = AgentClusterPage()
        wait(lambda: visibility_of_element_located(cluster_page.search_box), waiting_for='cluster page to load')

        # Disable cluster node
        node_list = AgentClusterNodeList()
        node_name = node_list.cluster_nodes_all_name[0]
        node_list.enable_disable_cluster_node(node_name=node_name, enable=False)

        notification = Notifications()

        # Verify success notification after disabling cluster node
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster.node_disabled, \
            'Getting incorrect notification message, expected is {}'.format(
                Messages.NotificationMessages.Agents.AgentCluster.node_disabled)

        sleep(TIME_TEN_SECONDS, reason='Waiting for nodes to balance')
        node_list.refresh()
        wait(lambda: visibility_of_element_located(cluster_page.search_box), waiting_for='Node list to populate')

        # Enable cluster node
        node_list.enable_disable_cluster_node(node_name=node_name, enable=True)

        # Verify success notification after enabling cluster node
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster.node_enabled, \
            'Getting incorrect notification message, expected is {}'.format(
                Messages.NotificationMessages.Agents.AgentCluster.node_enabled)

        # Verify 'Rebalanced Node' button is displayed on top right corner
        assert cluster_page.is_element_present('rebalance_button'), '\'Rebalance node\' button is not displayed on ' \
                                                                    'top right corner.'

        # Click on 'Rebalanced Node' button
        cluster_page.rebalance_cluster_nodes()

        # Verify success notification after rebalancing cluster node
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.AgentCluster.rebalance_node, \
            'Getting incorrect notification message, expected is {}'.format(
                Messages.NotificationMessages.Agents.AgentCluster.rebalance_node)

        wait(lambda: visibility_of_element_located(cluster_page.rebalance_node_notice),
             waiting_for='Rebalancing node notice message')

        # Verify rebalancing node notice message is displayed
        assert cluster_page.is_element_present('rebalance_node_notice'), 'Rebalancing node notice message is not ' \
                                                                         'displayed above node search box.'

        # Verify rebalancing node notice message
        assert cluster_page.rebalance_node_notice.text == Messages.NotificationMessages.Agents.AgentCluster. \
            rebalancing_node_status_pending, 'Getting incorrect notification message, expected is {}'. \
            format(Messages.NotificationMessages.Agents.AgentCluster.rebalancing_node_status_pending)

    def test_verify_linked_agents_tab(self):
        """
        NES-12953: [UI-Automation] : Verify the UI of 'Linked Agents' tab

        Scenario Tested:
            [x] Verify that on 'Sensors' > 'Linked Agents' tab, linking key, regenerate icon,
                pencil icon for edit linking key, 'setup instructions' hyperlink are present.
        """
        agents_page = AgentsPage()
        agents_page.open()
        assert agents_page.linked_agents_description.text == Nessus.Agents.LINK_AGENT_DESCRIPTION, \
            "'Linked Agents' tab description is not as expected."
        assert agents_page.is_element_present('linking_key_text'), "Linking key is not present on 'Linked Agents' tab."
        assert len(agents_page.linking_key_text.text) == 64, "Linking key length is not 64."
        assert agents_page.is_element_present('regenerate_key'), \
            "Regenerate linking key icon is not present on 'Linked Agents' tab UI."
        assert agents_page.is_element_present('pencil_icon'), "Pencil Icon is not present on 'Linked Agents' tab UI."
        assert agents_page.is_element_present('agents_setup_instructions'), \
            "Setup Instructions hyperlink is not present on 'Linked Agents' tab."
        agents_page.agents_setup_instructions.click()
        setup_instructions_modal = ActionCloseModal()
        assert setup_instructions_modal.is_element_present('modal'), \
            "Modal did not appear for setup instruction after clicking on it."
        assert setup_instructions_modal.modal_title.text == Nessus.Agents.AGENT_SETUP_INSTRUCTION, \
            "Setup instructions modal title is incorrect."
        setup_instructions_modal.close_button.click()
        setup_instructions_modal.wait_for_modal_closed()

    @pytest.mark.xray(test_key='NES-13809')
    def test_agent_linking_key_regenerate(self):
        """
        NES-13809 : Verify regenerate linking key

        Scenario tested:
        [x] Verified notification appears after key generation is successfull
        [x] Verified both old and new keys are not same
        """

        agent_page = AgentsPage()
        agent_page.open()
        wait(lambda: visibility_of_element_located(agent_page.linking_key_text),
             waiting_for='waiting for linking key to be appear')
        old_key = agent_page.linking_key_text.text
        agent_page.regenerate_key.click()
        regenerate_warning_modal = ActionCloseModal()
        regenerate_warning_modal.action_button.click()

        notification = Notifications()

        # Verify success notification after Regenrating key
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.key_changed_success, \
            'Getting incorrect notification message, expected is {}'.format(
                Messages.NotificationMessages.Agents.key_changed_success)

        new_key = agent_page.linking_key_text.text

        # Verify key is changes and compare both
        assert new_key != old_key, 'New linking key is not generated'

    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'login')
    def test_verify_linked_agents_tab_when_no_agents_linked(self, delete_all_agents_in_nessus_manager):
        """
        NES-12953: [UI-Automation] : Verify the UI of 'Linked Agents' tab

        Scenario Tested:
            [x] Verify that 'No agents have been linked.' watermark is present on 'Linked Agents' tab
                when there is no agent linked.
        """
        agents_page = AgentsPage()
        agents_page.open()
        assert agents_page.is_element_present('empty_agent_list'), \
            "No agents linked text is not present when any agent is not linked."
        assert agents_page.empty_agent_list.text == Nessus.Agents.NO_AGENTS_LINKED, \
            "No agents linked text is incorrect."

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[60, 'None']], indirect=True)
    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'nessus_create_nessus_agent', 'login')
    def test_verify_linked_agents_tab_when_agents_linked(self, nessus_create_nessus_agent):
        """
        NES-12953: [UI-Automation] : Verify the UI of 'Linked Agents' tab

        Scenario Tested:
            [x] Verify that agent search box, filter link, agents list with appropriate columns, agents pagination
                are present when there are agents linked
        """
        agents_page = AgentsPage()
        agents_page.open()
        assert agents_page.is_element_present('search_agent_input'), \
            "Agent search box is not present on 'Linked Agents' tab."
        assert agents_page.is_element_present('filter_link'), \
            "Agents filter link is not present on 'Linked Agents' tab."
        agents_list = AgentsList()
        assert Nessus.Agents.AGENT_TABLE_COLUMNS.issubset(set([column.text for column in agents_list.columns])), \
            "Agents columns are not present on "
        agents_page.js_scroll_to_bottom()
        assert agents_page.is_element_present('next_agents_page'), "Next agents pagination link is not available on " \
                                                                   "'Linked Agents' tab when there are more than 50 " \
                                                                   "agents have been linked."
        assert agents_page.is_element_present('last_agents_page'), "Last agents pagination link is not available on " \
                                                                   "'Linked Agents' tab when there are more than 50 " \
                                                                   "agents have been linked."

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'nessus_create_nessus_agent', 'login')
    def test_delete_agent_from_the_linked_agents_list(self):
        """
        NES-12954: [UI- Automation]: Verify the delete/unlink agent operation from UI

        Scenario Tested:
            [x] Verify that an agent can be deleted from agent list in 'Linked Agents' tab.
        """
        agents_page = AgentsPage()
        agents_page.open()
        agents_list = AgentsList()
        agent_name = agents_list.get_all_agents_by_name()[0]
        agents_list.delete_agent(agent_name=agent_name, accept_delete_modal=True)
        notification = Notifications()

        # Verify success notification after deleting agent
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.delete_agent, \
            'Getting incorrect notification message, expected is {}'.format(
                Messages.NotificationMessages.Agents.delete_agent)

        # Verify that agent got deleted from agents list
        assert agent_name not in agents_list.get_all_agents_by_name(), \
            "After deleting, agent is still present in agent list."

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'nessus_create_nessus_agent', 'login')
    def test_verify_delete_agent_popup(self):
        """
        NES-12954: [UI- Automation]: Verify the delete/unlink agent operation from UI

        Scenario Tested:
            [x] Verify 'Delete Agent' pop up while deleting agent.
        """
        agents_page = AgentsPage()
        agents_page.open()
        agents_list = AgentsList()
        agent_name = agents_list.get_all_agents_by_name()[0]
        agents_list.delete_agent(agent_name=agent_name)
        delete_modal = ActionCloseModal()
        try:
            # Verify 'Delete Agent' popup
            assert delete_modal.modal_title.text == Nessus.Agents.DELETE_AGENT, \
                "'Delete Agent' popup title is incorrect."
            assert delete_modal.modal_content.text == Nessus.Agents.DELETE_AGENT_WARNING, \
                "'Delete Agent' popup content is incorrect."
        finally:
            delete_modal.close_button.click()
            delete_modal.wait_for_modal_closed()

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize("agent_config_settings", [{"payload": {"track_unlinked_agents": True}}], indirect=True)
    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'nessus_api_login',
                             'agent_config_settings', 'nessus_create_nessus_agent', 'login')
    def test_unlink_agent_from_the_linked_agents_list(self):
        """
        NES-12954: [UI- Automation]: Verify the delete/unlink agent operation from UI

        Scenario Tested:
            [x] Verify that an agent can be unlinked from agent list in 'Linked Agents' tab.
        """
        agents_page = AgentsPage()
        agents_page.open()
        agents_list = AgentsList()
        agent_name = agents_list.get_all_agents_by_name()[0]
        agents_list.unlink_agent(agent_name=agent_name, accept_unlink_modal=True)
        notification = Notifications()

        # Verify success notification after unlinking agent
        assert notification.successes[-1] == Messages.NotificationMessages.Agents.unlink_agent, \
            'Getting incorrect notification message, expected is {}'.format(
                Messages.NotificationMessages.Agents.unlink_agent)

        assert agents_list.get_agent_status_by_agent(agent_name=agent_name) == Nessus.Agents.AgentStatus.UNLINKED, \
            "Agent status is not 'Unlinked'."

    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize("agent_config_settings", [{"payload": {"track_unlinked_agents": True}}], indirect=True)
    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'nessus_api_login',
                             'agent_config_settings', 'nessus_create_nessus_agent', 'login')
    def test_verify_unlink_agent_popup(self):
        """
        NES-12954: [UI- Automation]: Verify the delete/unlink agent operation from UI

        Scenario Tested:
            [x] Verify 'Unlink Agent' pop up while unlinking agent.
        """
        agents_page = AgentsPage()
        agents_page.open()
        agents_list = AgentsList()
        agent_name = agents_list.get_all_agents_by_name()[0]
        agents_list.unlink_agent(agent_name=agent_name)
        unlink_modal = ActionCloseModal()
        try:
            # Verify 'Unlink Agent' popup
            assert unlink_modal.modal_title.text == Nessus.Agents.UNLINK_AGENT, \
                "'Unlink Agent' popup title is incorrect."
            assert unlink_modal.modal_content.text == Nessus.Agents.UNLINK_AGENT_WARNING, \
                "Unlink Agent popup content is incorrect."
        finally:
            unlink_modal.close_button.click()
            unlink_modal.wait_for_modal_closed()

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["Name", "Version", "Status", "IP", "Platform"])
    @pytest.mark.usefixtures('login', 'nessus_api_login', 'delete_all_agents_in_nessus_manager',
                             'nessus_create_nessus_agent')
    @pytest.mark.parametrize('nessus_create_nessus_agent', [
        [3, 'None', load_testdata('nessus/tests/api/agents/test_data/three_agents.json')]], indirect=True)
    def test_sorting_in_agent_table(self, sort, column_to_sort):
        """
        NES-13065: [UI-Automation] : Verify sorting works for all tables under sensors tab

        Scenario Tested:
            [x] Verify that all these columns in agents table can be sorted in ascending/descending order:
                "Name", "Version", "Status", "IP", "Platform"
        """
        agents_page = AgentsPage()
        agents_page.open()
        agents_list = AgentsList()
        agents_list.loaded()

        column_mapping = {"Name": "name", "Version": "core_version", "Status": "status", "IP": "ip",
                          "Platform": "platform"}
        map_attribute = column_mapping[column_to_sort]

        expected_agents_list = sorted([getattr(agent, map_attribute) for agent in agents_list.rows],
                                      key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))
        self.sort_given_column_in_agent_table(sort=sort, column_name=map_attribute, agents_list=agents_list)

        sorted_agent_list_on_ui = [getattr(agent, map_attribute) for agent in agents_list.rows]

        assert expected_agents_list == sorted_agent_list_on_ui, \
            "Agents list did not sorted for {}".format(column_to_sort)

    def test_visibility_of_options_on_settings_page_under_linked_agents(self):
        """
        NES-13079 [Automation]: Verify visibility of required elements on "Agent Clustering" and "Linked Agents" page

        Scenario Tested:
        [x] Verify that below options are and "Remove inactive agents" checkboxes are present on linked agents
            settings page.
            - Track unlinked agents (Checkbox)
            - Remove inactive agents (Checkbox)
            - Save (Button)
        [x] Verify that "Inactive time" days field is disabled by default.
        """
        agents_page = AgentsPage()
        agents_page.open()
        wait(lambda: agents_page.is_element_present("agent_settings_tab_link"),
             waiting_for="linked agents page gets loaded")

        agents_page.agent_settings_tab_link.click()

        agent_setting_tab = AgentSettingsTab()
        wait(lambda: agent_setting_tab.is_element_present('track_unlinked_agents_checkbox'),
             waiting_for='Agent settings tab page to load properly')

        assert all([agent_setting_tab.is_element_present('track_unlinked_agents_checkbox'),
                    agent_setting_tab.is_element_present('remove_inactive_agents_checkbox'),
                    agent_setting_tab.is_element_present('inactive_time_field'),
                    agent_setting_tab.is_element_present('save_button'),
                    'disabled' in agent_setting_tab.inactive_time_field.get_css_classes()]), \
            "Expected options are missing on settings page under linked agents."

    def test_visibility_of_options_on_agent_clustering_page(self):
        """
        NES-13079 [Automation]: Verify visibility of required elements on "Agent Clustering" and "Linked Agents" page

        Scenario Tested:
        [x] Verify "Agent Clustering" page header title.
        [x] Verify that below tabs are present under "Agent Clustering" page.
            - Settings
            - Cluster Migration
        """
        HeaderBasePage().sensors_tab.click()

        side_nav = SideNav()
        wait(lambda: Nessus.SideNavResources.AGENT_CLUSTERING in side_nav.get_all_sidenav_links(),
             waiting_for="page gets loaded")

        side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.AGENT_CLUSTERING).click()
        agent_cluster_migration = AgentClusterMigration()

        assert side_nav.header_title.text == "Cluster Setup", \
            "'Agent Clustering' page header title is missing or mismatch."

        assert all([agent_cluster_migration.is_element_present("settings_tab"),
                    agent_cluster_migration.is_element_present("cluster_migration_link")]), \
            "'Settings' or 'Cluster Migration' tab is missing under agent clustering page."

    @pytest.mark.xray(test_key='NES-15339')
    def test_verify_tabs_in_agent_clustering_page(self):
        """
        NES-15339 : Verify UI of 'Agent Clustering' tab
        """
        HeaderBasePage().sensors_tab.click()

        side_nav = SideNav()
        wait(lambda: Nessus.SideNavResources.AGENT_CLUSTERING in side_nav.get_all_sidenav_links(),
             waiting_for="page gets loaded")

        side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.AGENT_CLUSTERING).click()
        agent_cluster_migration = AgentClusterMigration()

        assert side_nav.header_title.text == "Cluster Setup", \
            "'Agent Clustering' page header title is missing or mismatch."

        assert all([agent_cluster_migration.is_element_present('settings_tab'),
                    agent_cluster_migration.is_element_present('cluster_migration_tab')])

    @pytest.mark.xray(test_key='NES-15538')
    @pytest.mark.parametrize('nessus_create_nessus_agent', [[1, 'None']], indirect=True)
    @pytest.mark.parametrize("agent_config_settings", [{"payload": {"track_unlinked_agents": True}}], indirect=True)
    @pytest.mark.usefixtures('delete_all_agents_in_nessus_manager', 'nessus_api_login',
                             'agent_config_settings', 'nessus_create_nessus_agent', 'login')
    def test_remote_setting_tab_does_not_appear_for_unlinked_agent(self):
        """
        NES-15538 : Verify 'remote setting' tab should not appear

        Scenario Tested:
        [x] Verify Remote Settings tab is not available for Unlinked agent
        """
        agents_page = AgentsPage()
        agents_page.open()
        agents_list = AgentsList()
        agent_name = agents_list.get_all_agents_by_name()[0]
        agents_list.unlink_agent(agent_name=agent_name)
        unlink_modal = ActionCloseModal()
        unlink_modal.action_button.click()
        unlink_modal.wait_for_modal_closed()

        agents_list.click_on_agent(agent_name=agent_name)
        agent_details = AgentDetailsPage()
        wait(lambda: visibility_of_element_located(agent_details.agent_details_tab),
             waiting_for='waiting for Agent details page to get loaded')
        assert not agent_details.is_element_present(
            'remote_settings_tab'), 'Remote Settings tab is still visible after agent is unlinked'


@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestVPRTabInNormalAgentScan:
    """ Tests related to VPR Top Threats tab in normal agent scan result page """

    cat = None

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_-_Basic.nessus',
                                                      'file_path': 'nessus/tests/ui/agents/test_data/'}], indirect=True)
    def test_vpr_tab_not_present_in_normal_agent_scan(self, import_scan_via_api):
        """
        NES-12709: [UI-Automation] Verify VPR details should NOT be visible for Agent scans in Clustered and 
                    Non-Clustered NM

        Scenario Tested:
        [x] Verify that VPR Top Threats tab should not be present in normal agent scan.
        """
        scan_list = ScanList()
        scan_list.refresh()
        scan_list.loaded()

        scan_list.click_on_scan(scan_name=import_scan_via_api[0])

        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
             waiting_for='Vulnerabilities to get loads')

        assert not scan_view_page.is_element_present('threat_level_tab'), \
            "'VPR Top Threats' tab is present in scan results."

        HeaderBasePage().scan_link.click()
        scan_list.loaded()
        scan_list.delete_scan(scan_name=import_scan_via_api[0])

