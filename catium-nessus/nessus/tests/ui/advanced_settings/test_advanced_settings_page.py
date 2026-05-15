"""
Nessus advanced settings related test cases

Test cases to verify that add and edit advanced settings have
their impact after restart

:copyright: Tenable Network Security, 2017
:date: Aug 21, 2017
:last_modified: Sep 06, 2022
:author: @smadan, @ntarwani, @vsoni, @kpanchal, @sacharya, @mdabra
"""
import os
import random
import string

import pytest
from requests import RequestException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_THIRTY_SECONDS, TIME_FIVE_SECONDS
from catium.lib.const import WAIT_NORMAL
from catium.lib.const.base_constants import TIME_FIVE_MINUTES, WAIT_SHORT, TIME_TWENTY_SECONDS, API, TIME_THREE_SECONDS, \
    TIME_THIRTY_MINUTES
from catium.lib.const.base_constants import WAIT_LONG
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.advanced_settings import change_default_value_from_setting_dropdown
from nessus.helpers.nessus_ui.settings import delete_advanced_setting as delete_advanced_setting_helper, \
    required_for_settings_effective
from nessus.helpers.nessus_ui.settings import modify_existing_advanced_setting
from nessus.helpers.nessuscli.helper import start_nessus, stop_nessus
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.system import get_nessus_type_using_api, is_manager, is_home
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.config.environment_variables import NESSUS_LOGS_DIR, NESSUS_CONF_DIR
from nessus.lib.const import Nessus, SortOrder, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import About
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AdvancedSettingsList, \
    AddAdvancedSettingModal
from nessus.pageobjects.generic.generic_modals import ActionCloseModal, UnsavedChangesModal
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScansHostList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.fixture()
def handle_unexpected_initialize_nessus_screen():
    """ This function will handle unwanted 'Established connection' popup """
    api = NessusAPI()
    try:
        wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIVE_MINUTES,
                                msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)
    except TimeoutExpired:
        try:
            if api.server.status().get('status') == 'loading':
                wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIVE_MINUTES * 3,
                                        msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)
        except RequestException:
            stop_nessus()
            start_nessus()
            wait_for_scanner_to_be_ready(api)


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestAdvancedSettings:
    """Advance Settings Related Test Cases """

    @pytest.mark.parametrize('add_advanced_setting', [
        {"name": 'acas_classification', "value": "CUSTOM_VALUE"},
        {"name": 'acas_classification', "value": "SECRET"}, {"name": 'acas_classification', "value": "UNCLASSIFIED"},
        {"name": 'acas_classification', "value": "CONFIDENTIAL"}], indirect=True)
    def test_add_acas_classification(self, add_advanced_setting):
        """
        Test the ability to change or add the acas classification color settings
        NQA- 428 - ACAS classification colors
        NQA-1062 - Advanced Settings
        NES-8715 - [Testing] Automation testing for New Advance setting UI

        Scenarios tested:
          [x] Able to create new setting and should be displayed in custom tab once saved

        Steps:
        1. Add setting with name "acas_classification".
        2. Set a value from options.
        3. Ensure it has a defined color heading with data name on the header and footer both.
        4. Delete the created custom setting.
        5. Perform the above steps for each options.
        """
        setting_name, setting_value = add_advanced_setting[0:2]
        login_page = LoginPage()

        if login_page.is_element_present('username_field', timeout=TIME_TWENTY_SECONDS):
            login_page.login_with_defaults()
            LoadingCircle(WAIT_LONG)

        header_text = get_driver_no_init().find_element(By.CSS_SELECTOR, ".acas").text
        footer_text = get_driver_no_init().find_element(By.CSS_SELECTOR, ".acas.footer").text

        # Verify the header and footer text with setting value given in fixture.
        for text in [header_text, footer_text]:
            assert text == setting_value, \
                'Footer and header name with "%s" with value "%s" does not exist' % (setting_name, setting_value)

        AdvancedSettingsPage().open()
        advanced_setting = AdvancedSettingsList()
        wait(lambda: advanced_setting.is_element_present('custom_tab'))

        advanced_setting.custom_tab.click()
        advanced_setting.delete_custom_setting(setting_name=setting_name)

    @pytest.mark.xray(test_key='NES-14073')
    @pytest.mark.parametrize("update_settings", [{'setting_name': Nessus.AdvancedSettings.LOG_ADDITIONAL_SCAN_DETAILS,
                                                  "setting_value": "Yes", "dropdown": True}])
    def test_verify_log_details_adv_setting(self, update_settings):
        """
        NES-14073: Verify log_details setting
        1. Go to 'settings tab > advanced setting > Logging' page
        2. Go to Log additional scan details
        3. Select log_details
        4. Set the value to Yes and save it
        5. Observe
        """
        try:
            AdvancedSettingsPage().open()
            add_advanced_setting = AddAdvancedSettingModal()
            advanced_setting_list = AdvancedSettingsList()
            wait(lambda: advanced_setting_list.is_element_present("logging_tab", timeout=TIME_THIRTY_SECONDS),
                 waiting_for="Logging tab to be visible")
            add_advanced_setting.select_value_from_setting_dropdown(setting_tab=Nessus.AdvancedSettings.LOGGING_TAB,
                                                                    setting_name=update_settings["setting_name"],
                                                                    setting_value=update_settings["setting_value"])
            wait(lambda: Notifications().successes, waiting_for="Notification list to populate")
            wait(lambda: advanced_setting_list.get_settings_value(
                setting_name=update_settings["setting_name"]) == [update_settings["setting_value"]])
            assert advanced_setting_list.get_settings_value(setting_name=update_settings["setting_name"]) == [
                update_settings["setting_value"]], "Setting %s with %s is not updated correctly" % (
                update_settings["setting_name"], update_settings["setting_value"])

            add_advanced_setting.find_specific_setting_name(setting_name='log_details').click()
            try:
                wait(lambda: add_advanced_setting.is_element_present('modal'),
                     waiting_for='Modal to appear for changing log_details setting.')
            except TimeoutExpired:
                raise AssertionError("Log_details pop up is not visible after clicking on setting.")

            assert add_advanced_setting.modal_title.text == Nessus.AdvancedSettings.LOG_ADDITIONAL_SCAN_DETAILS_NAME, \
                "Log Additional Scan Details pop up title is incorrect."
            assert add_advanced_setting.setting_description.text == 'When enabled, scan logs include username, ' \
                                                                    'scan name, ' \
                                                                    'and current plugin ID in addition to the base ' \
                                                                    'information. ' \
                                                                    'You may not see these additional details unless ' \
                                                                    'log_whole_attack is also enabled.'
            add_advanced_setting.action_button.click()
        finally:
            AddAdvancedSettingModal().reset_setting_banner(setting_name=update_settings["setting_name"])
            LoadingCircle(WAIT_SHORT)

    @pytest.mark.skip(reason="Can cause remaining tests to fail")
    @pytest.mark.parametrize('add_advanced_setting', [{"name": Nessus.AdvancedSettings.LOGIN_BANNER,
                                                       "value": "my login banner"}], indirect=True)
    def test_edit_advanced_setting(self, add_advanced_setting):
        """
        Test the ability to edit advanced setting
        NQA-1062 - Advanced Settings

        1. Add setting with name "login_banner".
        2. Set a value "my login banner".
        3. Restart Nessus.
        4. Logout from Nessus.
        5. Login and ensure that a popup comes up having the value assigned to the setting.
        6. Accept the popup
        7. Edit the setting and change the value
        8. Restart Nessus
        9. Verify the value has been changed
        10. Delete the setting
        """
        ActionCloseModal().accept_action()
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()
        setting_name = add_advanced_setting[0]
        LoadingCircle(WAIT_NORMAL)

        advanced_setting.get_dynamic_element_for_setting_name(Nessus.AdvancedSettings.LOGIN_BANNER).click()
        LoadingCircle(WAIT_NORMAL)
        assert UnsavedChangesModal().unsaved_changes_title.text == "Edit Setting"
        AddAdvancedSettingModal().change_setting(setting_value='changed custom banner')

        LoadingCircle(WAIT_NORMAL)
        required_for_settings_effective()

        get_driver_no_init().refresh()
        sleep(sleep_time=TIME_FIVE_SECONDS, reason="waiting for page to load")
        get_driver_no_init().refresh()
        login_page = LoginPage()
        if login_page.is_element_present('username_field', timeout=TIME_THIRTY_SECONDS):
            login_page.refresh()
            login_page.login_with_defaults()
            LoadingCircle(WAIT_NORMAL)

        advanced_setting.open()
        advanced_setting_list = AdvancedSettingsList()
        assert setting_name in advanced_setting_list.get_all_settings_name(), 'Banner property does not exist'
        # assert 'changed custom banner' in advanced_setting_list.get_all_settings_value(),
        # "Setting value did not change"

    def test_search_under_advanced_settings(self):
        """
        Test the ability to search advanced setting
        NQA-1062 - Advanced Settings

        1. Navigate to Advanced Setting
        2. In a search box type "xmlrpc_"
        3. Verify settings with string containing "xmlrpc_" are listed
        """
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()

        advanced_setting_list = AdvancedSettingsList()
        wait(lambda: advanced_setting_list.is_element_present("user_interface_tab", timeout=TIME_THIRTY_SECONDS),
             waiting_for="User Interface tab to visible")

        assert advanced_setting.search_textbox.get_attribute('placeholder') == "Search Settings", \
            "Placeholder text is not as expected"

        advanced_setting.search_textbox.value = Nessus.AdvancedSettings.XMLRPC_LISTEN_PORT[0:6]
        advanced_setting.is_element_present("search_result_count")

        assert Nessus.AdvancedSettings.XMLRPC_LISTEN_PORT in advanced_setting_list.get_setting_identifiers_by_tab(), \
            "Search does not work correctly."

    @pytest.mark.parametrize('add_advanced_setting', [{"name": "xmlrpc_fake", "value": "test"}], indirect=True)
    def test_search_after_add_setting(self, add_advanced_setting):
        """
        Test the ability to search setting after new setting added
        NQA-1062 - Advanced Settings

        1. Add setting with name "xmlrpc_fake".
        2. In a search box type "xmlrpc_"
        3. Verify settings with string containing "xmlrpc_" are listed and the fake setting is present in the list
        4. Delete the setting
        """
        setting_name = add_advanced_setting[0]

        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()

        advanced_setting_list = AdvancedSettingsList()
        wait(lambda: advanced_setting_list.is_element_present("user_interface_tab", timeout=TIME_THIRTY_SECONDS),
             waiting_for="User Interface tab to visible")

        assert advanced_setting_list.is_element_present("custom_tab"), \
            "Custom tab is not visible even after adding new custom setting."

        advanced_setting.search_textbox.value = Nessus.AdvancedSettings.XMLRPC_LISTEN_PORT[0:6]
        advanced_setting.is_element_present("search_result_count")
        sleep(sleep_time=TIME_THREE_SECONDS, reason="waiting for click to happen")
        advanced_setting_list.custom_tab.click()

        assert setting_name in advanced_setting_list.get_all_settings_name(), "Setting not added successfully"

        delete_advanced_setting_helper(setting_name=setting_name)
        advanced_setting.refresh()
        wait(lambda: advanced_setting_list.is_element_present("user_interface_tab", timeout=TIME_THIRTY_SECONDS),
             waiting_for="User Interface tab to visible")

        if not advanced_setting_list.is_element_present("custom_tab"):
            assert True, "Custom tab is still visible even after deleting added custom setting."
        else:
            advanced_setting_list.custom_tab.click()
            advanced_setting.search_textbox.value = setting_name
            sleep(WAIT_NORMAL, reason="setting list takes bit time to get loaded.")

            assert setting_name not in advanced_setting_list.get_all_settings_name(), \
                "Failed to delete added custom setting."

    @pytest.mark.xray(test_key='NES-14106')
    def test_search_results_with_count_for_each_tab_under_advanced_settings(self):
        """
        NES-14106: Verify and compare the counts of search advanced setting

        Scenarios Tested:
        [x] Verify that it should list out all relevant advance settings from all the tabs
        [x] Verify searching functionality with single char, word, special characters
        [x] Setting search should be work correctly and should show exact count result for each tab
        [x] Applied filter should be applicable on each tab.
        """
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()

        advanced_setting_list = AdvancedSettingsList()
        wait(lambda: visibility_of_element_located(advanced_setting_list.user_interface_tab),
             waiting_for='advanced settings list to load')

        assert advanced_setting_list.is_element_present('user_interface_tab'), 'User interface tab is not visible'

        for search_value in [random.sample("abcghjklmopqrstvwxyz", k=1)[0], "port",
                             random.sample(string.digits, k=1)[0], ".", "server"]:
            advanced_setting.search_textbox.clear()
            advanced_setting.search_textbox.value = search_value
            advanced_setting.is_element_present("search_result_count")
            setting_tab_list = advanced_setting.get_list_of_all_tabs_name()
            total_count = 0

            for setting_tab in setting_tab_list:
                tab = advanced_setting.get_settings_tab_element(setting_tab=setting_tab)
                wait(lambda: visibility_of_element_located(tab), timeout_seconds=TIME_THIRTY_MINUTES,
                     waiting_for="Waiting for scan to be in {} status")
                tab.location_once_scrolled_into_view
                tab.click()
                actual_count = int(advanced_setting.get_setting_counts_after_applying_filter_each_tab(
                    setting_tab=setting_tab))

                # Verify the count displayed in sub tab should be equal to the number of setting displaying in each tab
                assert actual_count == len(advanced_setting_list.get_settings_names_by_tab(setting_tab=setting_tab)), \
                    'Count is different for \'{}\' tab'.format(setting_tab)

                settings_value_list = [row.text.lower() for row in advanced_setting_list.rows]

                # Verify the advanced setting search results are displayed according to search value
                assert all([search_value in setting_value for setting_value in settings_value_list]), \
                    'Advanced setting search results are not showing properly according to search value.'

                total_count += actual_count

            assert total_count == int(advanced_setting.search_result_count.text), \
                "Total setting search results count and sum of search result count in each tab is getting mismatch."

    @pytest.mark.xray(test_key='NES-17526')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize("update_settings",
                             [{'setting_name': Nessus.AdvancedSettings.SCAN_HISTORY_EXPIRATION_DAYS_ID,
                               "setting_value": "1", "dropdown": False}])
    def test_verify_scan_history_expiration_days_adv_setting(self, update_settings):
        """
        NES-17526: Nessus UI accepts 1 for scan_history_expiration_days
        1. Go to 'settings tab > advanced setting > scan_history_expiration_days' page
        2. Go to scan_history_expiration_days
        3. Set the value to 1 and save it
        5. Verify the value get saved
        """
        try:
            AdvancedSettingsPage().open()
            add_advanced_setting = AddAdvancedSettingModal()
            advanced_setting_list = AdvancedSettingsList()
            wait(lambda: advanced_setting_list.is_element_present("logging_tab", timeout=TIME_THIRTY_SECONDS),
                 waiting_for="Logging tab to be visible")
            add_advanced_setting.fill_existing_setting_banner(setting_tab=Nessus.AdvancedSettings.MISCELLANEOUS_TAB,
                                                              setting_name=update_settings["setting_name"],
                                                              setting_value=update_settings["setting_value"])
            wait(lambda: Notifications().successes, waiting_for="Notification list to get populated")
            wait(lambda: advanced_setting_list.get_settings_value(
                setting_name=update_settings["setting_name"]) == [update_settings["setting_value"]])
            assert advanced_setting_list.get_settings_value(setting_name=update_settings["setting_name"]) == [
                update_settings["setting_value"]], "Setting %s with %s is not updated correctly" % (
                update_settings["setting_name"], update_settings["setting_value"])
        finally:
            AddAdvancedSettingModal().reset_setting_banner(setting_name=update_settings["setting_name"])
            LoadingCircle(WAIT_SHORT)

    @pytest.mark.xray(test_key='NES-17541')
    @pytest.mark.parametrize("update_settings",
                             [{'setting_name': Nessus.AdvancedSettings.SCAN_HISTORY_EXPIRATION_DAYS_ID,
                               "setting_value": "1", "dropdown": False}])
    def test_verify_scan_history_expiration_days_summary(self, update_settings):
        """
        NES-17541: Verify summary of the setting should get updated
        1. Go to 'settings tab > advanced setting > scan_history_expiration_days' page
        2. Go to scan_history_expiration_days
        3. click and verify the name and description of the setting.
        """
        AdvancedSettingsPage().open()
        add_advanced_setting = AddAdvancedSettingModal()
        advanced_setting_list = AdvancedSettingsList()
        wait(lambda: advanced_setting_list.is_element_present("miscellaneous_tab", timeout=TIME_THIRTY_SECONDS),
             waiting_for="Logging tab to be visible")

        AdvancedSettingsPage().search_textbox.value = 'scan_history_expiration_days'
        sleep(WAIT_SHORT, reason="It takes little bit time to search the setting.")
        AddAdvancedSettingModal().find_specific_setting_name(setting_name='scan_history_expiration_days').click()
        sleep(WAIT_SHORT, reason="It takes little bit time to load the setting.")
        assert add_advanced_setting.modal_title.text == Nessus.AdvancedSettings.SCAN_HISTORY_EXPIRATION_DAYS_NAME, \
            "The title name of setting 'User Scan Result Deletion Threshold' mismatched"
        assert add_advanced_setting.setting_description.text == 'The number of days after which scan history and data' \
                                                                ' for completed scans is permanently deleted.' \
                                                                ' A value of 0 means all history is retained.'
        add_advanced_setting.accept_action()


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_home
@pytest.mark.usefixtures('handle_unexpected_initialize_nessus_screen', 'login')
class TestAdvancedSettingsParameters:

    @pytest.mark.parametrize('advanced_setting', [
        pytest.param({'name': 'send_telemetry', 'display_name': 'Send Telemetry', 'value': 'Yes', 'not_present_in': [
            'Nessus Essentials']}, marks=(pytest.mark.nessus_manager, pytest.mark.nessus_pro, pytest.mark.nessus_home)),
        pytest.param({'name': 'disable_guides', 'display_name': 'Disable User Guides', 'value': 'No',
                      'not_present_in': ['Nessus Essentials', 'Nessus Manager']}, marks=(
                pytest.mark.nessus_manager, pytest.mark.nessus_home)),
        pytest.param({'name': 'portscanner.max_ports', 'display_name': 'Maximum Ports Reported by Portscanner Plugins',
                      'value': '1024', 'not_present_in': []}, marks=(
                pytest.mark.nessus_manager, pytest.mark.nessus_home, pytest.mark.nessus_pro))])
    def test_advanced_settings_parameters(self, advanced_setting):
        """
        NES-12482: [Automation] Verify Nessus sends telemetry by default
        NES-12495: [Automation] Verify default values of "send_telemetry" and "disable_guides"
                   across different Nessus types
        NES-12496: [Automation] Verify telemetry and guides can not be disabled in Nessus Essential
        SCE-3409: [Automation] Verify portscanner.max_ports is a default setting

        Scenario Tested:
            [x] Verify that the given advanced settings populated with correct value
        """
        advanced_setting_page = AdvancedSettingsPage()
        advanced_setting_page.open()
        wait(lambda: advanced_setting_page.is_element_present('search_textbox'),
             waiting_for="Advanced settings page to get loaded.")
        advanced_setting_page.search_textbox.value = advanced_setting.get('name')
        advanced_setting_list = AdvancedSettingsList()

        if get_nessus_type_using_api() not in advanced_setting['not_present_in']:
            try:
                wait(lambda: advanced_setting.get('display_name') in advanced_setting_list.get_all_settings_name(),
                     waiting_for='"{}" advanced setting to get loaded.'.format(advanced_setting.get('display_name')))
            except TimeoutExpired:
                raise AssertionError("'{}' does not found in advanced settings.".format(
                    advanced_setting.get('display_name')))
            assert advanced_setting_list.get_specific_setting_value(advanced_setting.get('name')).text == \
                   advanced_setting['value'], "'{}' default value is not set as '{}'.".format(
                advanced_setting.get('name'), advanced_setting.get('value'))
        else:
            try:
                wait(lambda: not advanced_setting_list.get_all_settings_name(),
                     waiting_for="Empty Advanced setting to get loaded with '{}' search".format(
                         advanced_setting.get('name')))
            except TimeoutExpired:
                raise AssertionError("Found advanced setting with '{}' name.".format(advanced_setting.get('name')))

    @pytest.mark.xray(test_key='NES-18251')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_severity_base_pop_up_on_advanced_settings_page(self):
        """
        NES-12675: [UI-Automation] Verify advanced settings page for changing severity base
        NES-18251: [E2E][UI] Verify advanced setting 'severity_basis' should have cvss_v4 as a new value

        Scenario Tested:
            [x] Verify that severity_basis is available in advanced setting and its pop up UI is proper.
        """
        advanced_setting_page = AdvancedSettingsPage()
        advanced_setting_page.open()
        wait(lambda: advanced_setting_page.is_element_present('search_textbox'),
             waiting_for="Advanced settings page to get loaded.")
        advanced_setting_page.search_textbox.value = 'severity_basis'
        advanced_setting_list = AdvancedSettingsList()
        try:
            wait(lambda: Nessus.AdvancedSettings.SEVERITY_BASIS in advanced_setting_list.get_all_settings_name(),
                 waiting_for='"{}" advanced setting to get loaded.'.format(Nessus.AdvancedSettings.SEVERITY_BASIS))
        except TimeoutExpired:
            raise AssertionError("'{}' does not found in advanced settings.".format(
                Nessus.AdvancedSettings.SEVERITY_BASIS))
        setting_modal = AddAdvancedSettingModal()
        setting_modal.find_specific_setting_name(setting_name='severity_basis').click()
        try:
            wait(lambda: setting_modal.is_element_present('modal'),
                 waiting_for='Modal to appear for changing severity base setting.')
        except TimeoutExpired:
            raise AssertionError("Severity base pop up is not visible after clicking on setting.")

        assert setting_modal.modal_title.text == Nessus.AdvancedSettings.SEVERITY_BASIS, \
            "Severity base pop up title is incorrect."
        assert setting_modal.setting_description.text == 'All presentation of scan severities, by default, ' \
                                                         'will be based upon this scoring scheme.'
        severity_base_option_values = setting_modal.allow_post_scan_edit_dropdown.option_values
        assert set([option.get('value') for option in severity_base_option_values]) == {'cvss_v2', 'cvss_v3',
                                                                                        'cvss_v4'}, \
            "Severity base values are incorrect on pop up."
        assert setting_modal.is_element_present('action_button') and setting_modal.is_element_present(
            'cancel_button'), "Save and close buttons are not visible on severity base pop up."

    @pytest.mark.xray(test_key='NES-18311')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_edit_severity_base_advanced_setting(self):
        """
        NES-18311: [E2E][UI] Verify advanced setting 'severity_basis' can be changed to cvss_v4

        Scenario Tested:
            [x] Verify that severity_basis is changed to cvss3 to cvss4.
            [x] Verify that severity_basis is changed to cvss4 to cvss3.
        """
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()
        advanced_setting_list = AdvancedSettingsList()
        setting_tab = Nessus.AdvancedSettings.SCANNING_TAB
        setting_value_before_change = advanced_setting_list.get_settings_value(setting_tab=setting_tab,
                                                                               setting_name='severity_basis')

        wait(lambda: advanced_setting.is_element_present('search_textbox'),
             waiting_for="Advanced settings page to get loaded.")
        advanced_setting.search_textbox.value = 'severity_basis'

        try:
            wait(lambda: Nessus.AdvancedSettings.SEVERITY_BASIS in advanced_setting_list.get_all_settings_name(),
                 waiting_for='"{}" advanced setting to get loaded.'.format(Nessus.AdvancedSettings.SEVERITY_BASIS))
        except TimeoutExpired:
            raise AssertionError("'{}' does not found in advanced settings.".format(
                Nessus.AdvancedSettings.SEVERITY_BASIS))
        setting_modal = AddAdvancedSettingModal()
        setting_modal.find_specific_setting_name(setting_name='severity_basis').click()
        try:
            wait(lambda: setting_modal.is_element_present('modal'),
                 waiting_for='Modal to appear for changing severity base setting.')
        except TimeoutExpired:
            raise AssertionError("Severity base pop up is not visible after clicking on setting.")

        if setting_value_before_change[0] == Nessus.AdvancedSettings.CVSS_V4:

            setting_modal.allow_post_scan_edit_dropdown.select_by_visible_text(Nessus.AdvancedSettings.CVSS_V3)
            setting_modal.action_button.click()
            setting_modal.wait_for_modal_closed()
            sleep(WAIT_NORMAL, reason="Setting value takes little bit time to get updated.")

            assert setting_value_before_change[
                       0] != Nessus.AdvancedSettings.CVSS_V3, 'CVSS v4 value is not updated to CVSS v3 after change.'

            setting_modal.find_specific_setting_name(setting_name='severity_basis').click()
            try:
                wait(lambda: setting_modal.is_element_present('modal'),
                     waiting_for='Modal to appear for changing severity base setting.')
            except TimeoutExpired:
                raise AssertionError("Severity base pop up is not visible after clicking on setting.")

        setting_modal.allow_post_scan_edit_dropdown.select_by_visible_text(Nessus.AdvancedSettings.CVSS_V4)
        setting_modal.action_button.click()
        setting_modal.wait_for_modal_closed()
        sleep(WAIT_NORMAL, reason="Setting value takes little bit time to get updated.")

        setting_value_after_change = advanced_setting_list.get_settings_value(setting_tab=setting_tab,
                                                                              setting_name='severity_basis')

        assert setting_value_after_change[
                   0] == Nessus.AdvancedSettings.CVSS_V4, 'CVSS v4 value is not updated from CVSS v3 to v4 after change.'

    @pytest.mark.xray(test_key='NES-14420')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    def test_add_login_banner(self):
        """
        Test the ability to add login banner
        NQA- 429- Custom Login Banners
        NQA-1062 - Advanced Settings
        NES-14420 : Verify login_banner setting


        1. Edit setting with name "login_banner".
        2. Set a value "my custom banner".
        3. Restart Nessus.
        4. Logout from Nessus.
        5. Login and ensure that a popup comes up having the value assigned to the setting.
        6. Accept the popup and delete the setting.
        """
        setting_name = Nessus.AdvancedSettings.LOGIN_BANNER
        setting_value = "my custom banner"

        advanced_setting = AdvancedSettingsPage()
        advanced_settings_list = AdvancedSettingsList()
        action_modal = ActionCloseModal()
        advanced_setting.open()

        add_advance_setting_modal = AddAdvancedSettingModal()
        add_advance_setting_modal.find_specific_setting_name(setting_name=setting_name).click()
        add_advance_setting_modal.add_setting_value(setting_value=setting_value)
        sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for banner text to get populated in list')
        assert setting_value in advanced_settings_list.get_settings_value(), 'Banner property not added'

        login_page = LoginPage()
        UserMenu().logout()
        login_page.login_with_defaults()
        wait(lambda: action_modal.is_element_present('modal'), timeout=TIME_THIRTY_SECONDS)

        assert action_modal.modal_content.text == setting_value, 'Login Banner text mismatch'
        action_modal.accept_action()
        advanced_setting.open()

        assert setting_value in advanced_settings_list.get_settings_value(), 'Banner property not added'

        AddAdvancedSettingModal().reset_setting_banner(setting_name=setting_name)

        assert setting_value not in advanced_settings_list.get_settings_value(), "Login Banner Settings not deleted"

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Setting', 'Identifier'])
    def test_sort_settings_list_on_columns_values(self, sort, column_to_sort):
        """
        NES-13067 [Automation]: Verify sorting functionality for the columns in each tab of Advanced settings

        Scenario Tested:
        [x] Verify sorting functionality for 'Setting' and 'Identifier' column in each tab of Advanced settings.
        """
        advanced_setting_page = AdvancedSettingsPage()
        advanced_setting_page.open()
        wait(lambda: advanced_setting_page.is_element_present("setting_search_box", timeout=TIME_THIRTY_SECONDS),
             waiting_for="setting search box visible")

        expected_settings_tab = [Nessus.AdvancedSettings.USER_INTERFACE_TAB, Nessus.AdvancedSettings.SCANNING_TAB,
                                 Nessus.AdvancedSettings.LOGGING_TAB, Nessus.AdvancedSettings.PERFORMANCE_TAB,
                                 Nessus.AdvancedSettings.SECURITY_TAB, Nessus.AdvancedSettings.MISCELLANEOUS_TAB]

        if is_manager():
            expected_settings_tab.extend([Nessus.AdvancedSettings.AGENTS_AND_SCANNERS_TAB])

        for setting_tab in expected_settings_tab:
            log.debug("Verifies for '{}' setting tab...".format(setting_tab))
            advanced_setting_page.get_settings_tab_element(setting_tab=setting_tab).click()
            sleep(WAIT_NORMAL, reason="It takes little bit time to change the settings list.")

            column_mapping = {"Setting": "setting_name", "Identifier": "setting_identifier"}
            map_attribute = column_mapping[column_to_sort]

            settings_list = AdvancedSettingsList()
            expected_settings_list = sorted([getattr(setting, map_attribute) for setting in settings_list.rows],
                                            key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

            rendered_settings_list = sort_on_column_values(page_class_instance=settings_list, sort=sort,
                                                           column_name=column_to_sort)

            assert expected_settings_list == [getattr(scan, map_attribute) for scan in rendered_settings_list], \
                "{} is not sorted in {} order".format(column_to_sort, sort)

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Setting', 'Identifier'])
    def test_sorting_on_columns_values_for_search_setting_results(self, sort, column_to_sort):
        """
        NES-13070 [Automation]: Verify that sorting is working on search advanced settings results

        Scenario Tested:
        [x] Verify sorting functionality for 'Setting' and 'Identifier' column in each tab for searched advanced
            setting results.
        """
        advanced_setting_page = AdvancedSettingsPage()
        advanced_setting_page.open()
        wait(lambda: advanced_setting_page.is_element_present("setting_search_box", timeout=TIME_THIRTY_SECONDS),
             waiting_for="setting search box visible")

        assert advanced_setting_page.search_textbox.get_attribute('placeholder') == "Search Settings", \
            "Placeholder text is missing or mismatch in advanced setting search box."

        for search_keyword in [random.choice(string.ascii_lowercase.replace('f', '')), "No",
                               random.choice(string.punctuation)]:
            advanced_setting_page.search_textbox.value = search_keyword
            sleep(WAIT_SHORT, reason="It takes little bit time to change the settings list.")

            expected_setting_tabs = advanced_setting_page.get_list_of_visible_tabs_name()
            settings_list = AdvancedSettingsList()

            if len(expected_setting_tabs) == 0:
                assert invisibility_of_element_located(advanced_setting_page.setting_tabs_section), \
                    "Settings tab section is visible even if there is not search matches found."

                assert int(advanced_setting_page.search_result_count.text) == 0, \
                    "Search setting result count is missing or mismatch even though there is no search matches."

                assert advanced_setting_page.no_record_found.text == Messages.NotificationMessages.AdvancedSettings. \
                    no_record_found, "'No records found.' message is missing or mismatch when no search results found."
            else:
                for setting_tab in expected_setting_tabs:
                    advanced_setting_page.get_settings_tab_element(setting_tab=setting_tab).click()
                    sleep(WAIT_NORMAL, reason="It takes little bit time to change the settings list.")

                    search_result_count_element = advanced_setting_page.get_setting_search_results_count(setting_tab)

                    assert visibility_of_element_located((search_result_count_element.we_by,
                                                          search_result_count_element.we_value))(
                        get_driver_no_init()), "Setting search result count is not visible after applying search."

                    column_mapping = {"Setting": "setting_name", "Identifier": "setting_identifier"}
                    map_attribute = column_mapping[column_to_sort]

                    expected_settings_list = sorted([getattr(setting, map_attribute) for setting in settings_list.rows],
                                                    key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

                    rendered_settings_list = sort_on_column_values(page_class_instance=settings_list, sort=sort,
                                                                   column_name=column_to_sort)

                    assert expected_settings_list == [getattr(scan, map_attribute) for scan in
                                                      rendered_settings_list], \
                        "{} is not sorted in {} order".format(column_to_sort, sort)

            advanced_setting_page.search_textbox_remove_icon.click()
            sleep(sleep_time=WAIT_NORMAL, reason='it takes little bit time to reset.')

            assert advanced_setting_page.setting_tabs_section.is_displayed(), \
                "Settings tab section is not visible even after removing the search keyword."

            assert not advanced_setting_page.is_element_present("no_record_found"), \
                "'No records found.' message is still present on UI even after removing search keyword."

            for setting_tab in advanced_setting_page.get_list_of_visible_tabs_name():
                search_result_count_element = advanced_setting_page.get_setting_search_results_count(setting_tab)

                assert invisibility_of_element_located(search_result_count_element), \
                    "Setting search result count is still visible after removing applied search."

                advanced_setting_page.get_settings_tab_element(setting_tab=setting_tab).click()
                sleep(WAIT_SHORT, reason="It takes little bit time to change the settings list.")

                assert len(settings_list.rows) > 0, "Settings are not visible even after clearing the search field."

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("setting_identifier", [Nessus.AdvancedSettings.SEND_TELEMETRY,
                                                    Nessus.AdvancedSettings.DISABLE_GUIDES])
    def test_user_able_to_configure_send_telemetry_and_disable_guides_setting(self, setting_identifier):
        """
        NES-13616 [Automation]: Verify "send_telemetry" setting in NM and NP UI
        NES-13617 [Automation]: Verify "disable_guides" setting in NP UI

        Scenario Tested:
        [x] Verify that "send_telemetry" setting should be visible in NM and NP UI
        [x] Verify that user can configure "send_telemetry" to "no" from UI
        [x] Verify that user can configure "send_telemetry" to "yes" from UI.
        [x] Verify that "disable_guides" setting should be visible in NM and NP UI
        [x] Verify that user can configure "disable_guides" to "no" from UI
        [x] Verify that user can configure "disable_guides" to "yes" from UI.
        """
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()

        advanced_setting_list = AdvancedSettingsList()
        wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
             waiting_for='Advanced settings list to load.')

        setting_tab = Nessus.AdvancedSettings.MISCELLANEOUS_TAB

        if setting_identifier == Nessus.AdvancedSettings.SEND_TELEMETRY:
            split_setting_identifier = setting_identifier.split("_")
            setting_name = " ".join([split_setting_identifier[0].capitalize(),
                                     split_setting_identifier[1].capitalize()])
        else:
            setting_name = Nessus.AdvancedSettings.DISABLE_USER_GUIDES

        all_miscellaneous_settings = advanced_setting_list.get_all_settings_name(setting_tab=setting_tab)

        if is_home():
            assert setting_name not in all_miscellaneous_settings, \
                "'{}' setting name is present under '{}' tab in Nessus Essentials.".format(setting_name, setting_tab)
        else:
            if is_manager() and setting_name == Nessus.AdvancedSettings.DISABLE_USER_GUIDES:
                assert setting_name not in all_miscellaneous_settings, \
                    "'{}' setting name is present under '{}' tab in Nessus Manager.".format(setting_name, setting_tab)
            else:
                assert setting_name in all_miscellaneous_settings, \
                    "'{}' setting name is either missing or mismatched under '{}' tab.".format(setting_name,
                                                                                               setting_tab)

                assert setting_identifier in advanced_setting_list.get_setting_identifiers_by_tab(
                    setting_tab=setting_tab), "'{}' setting identifier is either missing or mismatched " \
                                              "under '{}' tab.".format(setting_identifier, setting_tab)

                for _ in range(2):
                    add_advanced_setting_modal = AddAdvancedSettingModal()
                    add_advanced_setting_modal.find_specific_setting_name(setting_name=setting_identifier).click()

                    selected_value = add_advanced_setting_modal.allow_post_scan_edit_dropdown.get_text_selected()
                    new_setting_value = [option['label'] for option in
                                         add_advanced_setting_modal.allow_post_scan_edit_dropdown.option_values if
                                         selected_value != option['label']][0]

                    add_advanced_setting_modal.allow_post_scan_edit_dropdown.select_by_visible_text(new_setting_value)
                    add_advanced_setting_modal.action_button.click()
                    add_advanced_setting_modal.wait_for_modal_closed()
                    sleep(WAIT_NORMAL, reason="Setting value takes little bit time to get updated.")

                    assert all([advanced_setting.is_element_present(
                        "warn_message_for_restart", timeout=TIME_THIRTY_SECONDS), advanced_setting.is_element_present(
                        "service_restart_link")]), "'Restart Now' link is not visible along with warning message " \
                                                   "after modifying the setting value."

                    assert advanced_setting.warn_message_for_restart.text == Messages.NotificationMessages. \
                        AdvancedSettings.server_restart_message, "Warning message for Nessus web server restart is " \
                                                                 "either missing or mismatched."

                    current_setting_value = advanced_setting_list.get_settings_value(setting_tab=setting_tab,
                                                                                     setting_name=setting_identifier)[0]

                    assert current_setting_value == new_setting_value, \
                        "Failed to change setting value for '{}' setting name under '{}' setting tab.".format(
                            setting_name, setting_tab)

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("setting_tab", Nessus.AdvancedSettings.SETTING_TABS[:-1])
    def test_user_able_to_reset_the_default_setting_value(self, setting_tab):
        """
        NES-13069 [Automation]: Verify that user is able to reset the setting value to default value

        Scenarios Tested:
        [x] Verify that user is able to reset the advanced setting value to default value for particular setting(s)
            after clicking on reset icon.
        """
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()

        advanced_setting_list = AdvancedSettingsList()
        wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
             waiting_for='Advanced settings list to load.')

        if setting_tab in advanced_setting.get_list_of_all_tabs_name() and setting_tab is not "Scanning":
            normal_setting_name_list = advanced_setting_list.get_setting_identifiers_by_tab(setting_tab=setting_tab)
            normal_setting_to_be_reset = random.sample(normal_setting_name_list, k=1)[0]
            log.debug("Verifies for '{}' normal setting.".format(normal_setting_to_be_reset))

            restart_setting_name_list = advanced_setting_list.get_setting_name_requires_restart()
            restart_setting_to_be_reset = random.sample(restart_setting_name_list, k=1)[0]
            log.debug("Verifies for '{}' restart setting.".format(restart_setting_to_be_reset))

            add_advanced_setting_modal = AddAdvancedSettingModal()

            for setting_name in [normal_setting_to_be_reset, restart_setting_to_be_reset]:
                if setting_name == "rules":
                    add_advanced_setting_modal.reset_setting_banner(setting_name=setting_name)
                    sleep(WAIT_LONG, reason="Setting value takes little bit time to get updated.")

                default_setting_value = advanced_setting_list.get_settings_value(setting_name=setting_name)[0]
                log.debug("Default '{}' setting value :: {}".format(setting_name, default_setting_value))
                new_setting_value = change_default_value_from_setting_dropdown(
                    setting_name=setting_name, default_value=default_setting_value)

                if setting_name == restart_setting_to_be_reset:
                    # Verify that 'Restart Now' link is displayed after modifying the setting value
                    assert advanced_setting.is_element_present('service_restart_link', timeout=TIME_THIRTY_SECONDS), \
                        '\'Restart Now\' link is not visible after modifying the setting value.'

                # Verify the setting value is updated with the new setting value
                assert advanced_setting_list.get_settings_value(setting_name=setting_name)[0] == new_setting_value, \
                    'Setting value is not getting updated with new value for \'{}\' setting.'.format(setting_name)

                add_advanced_setting_modal.reset_setting_banner(setting_name=setting_name)

                # Verify success notification message after resetting the setting value
                assert Notifications().successes[-1] == Messages.NotificationMessages.save_settings, \
                    "Successful notification was missing for saving settings"

                sleep(WAIT_LONG, reason="Setting value takes little bit time to get updated.")

                # Verify the setting value is getting default after resetting
                if setting_name == "rules":
                    assert default_setting_value in [os.path.join(NESSUS_LOGS_DIR, 'nessusd.rules'),
                                                     os.path.join(NESSUS_CONF_DIR, 'nessusd.rules')], \
                        "Setting value haven't changed for 'rules' after resetting it."
                else:
                    assert default_setting_value == advanced_setting_list.get_settings_value(
                        setting_name=setting_name)[0], "Setting value haven't changed for '{}' after resetting " \
                                                       "it.".format(setting_name)

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("setting_details", [
        {"setting_tab": Nessus.AdvancedSettings.LOGGING_TAB, "setting_name": "logfile_msec", "default_value": "No"}])
    @pytest.mark.xray(test_key='NES-16909')
    def test_verify_default_advanced_setting_value(self, setting_details):
        """
        NES-13069 [Automation]: Verify that user is able to reset the setting value to default value

        Scenario Tested:
        [x] Verify that default setting value of "logfile_msec" setting identifier is "No".
        """
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()

        advanced_setting_list = AdvancedSettingsList()
        wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
             waiting_for='Advanced settings list to load.')

        setting_identifier = setting_details["setting_name"]
        current_setting_value = advanced_setting_list.get_settings_value(setting_tab=setting_details["setting_tab"],
                                                                         setting_name=setting_identifier)[0]
        expected_setting_value = setting_details["default_value"]

        assert current_setting_value == expected_setting_value, \
            "Got incorrect default setting value for '{}' setting, Expected value should be :: '{}'".format(
                setting_identifier, expected_setting_value)

    @pytest.mark.xray(test_key='NES-14167')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_agent_and_scanner_tab_not_visible(self):
        """
        NES-14167 : For Nessus professional/Essentials, verify that "Agents and scanner" tab is not visible under advanced settings.
        """
        advanced_settings = AdvancedSettingsPage()
        advanced_settings.open()
        advanced_list = AdvancedSettingsList()
        wait(lambda: advanced_list.is_element_present("user_interface_tab"),
             waiting_for='Advanced settings list to load.')

        all_tabs = advanced_settings.get_list_of_all_tabs_name()
        assert Nessus.AdvancedSettings.AGENTS_AND_SCANNERS_TAB not in all_tabs, f'Agent and Scanner tab is visible in {get_nessus_type_using_api()}'

    @pytest.mark.xray(test_key='NES-13781')
    def test_available_settings_for_home(self):
        """
        NES-13781 :For Nessus essential, verify that "Remote link/upgrade assistance" options are not available in settings header sidebar.

        Tested Scenario:
        [x] verified that Remote Link and Upgrade assistance options under Settings not available for Nessus Essentials
        """
        about_page = About()
        about_page.open()
        side_nav = SideNav()
        all_settings = side_nav.get_all_sidenav_links()
        assert Nessus.SideNavSettings.REMOTE_LINK and Nessus.SideNavSettings.UPGRADE_ASSISTANT not in all_settings, f'{Nessus.SideNavSettings.REMOTE_LINK}/{Nessus.SideNavSettings.UPGRADE_ASSISTANT} is visible in {get_nessus_type_using_api()} '

    @pytest.mark.xray(test_key='NES-14069')
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.MULTIPLE_TARGETS}]}], indirect=True)
    @pytest.mark.parametrize('setting_details', [
        {"setting_tab": Nessus.AdvancedSettings.PERFORMANCE_TAB, "setting_name": 'max_hosts', "setting_value": "1"}])
    def test_max_concurrent_hosts_per_scan(self, create_scans, setting_details):
        """
        NES-14069: Verify 'Max concurrent hosts per scan' advanced settings gets honored
        Tested Scenario:
        1. Set the 'Max concurrent hosts per scan' setting value to 1
        2. Verify that the 'Max concurrent hosts per scan' value is set to 1 only
        3. Create a scan with two hosts and launch the scan.
        4. Verify that only one host gets scanned.
        5. Reset the value to default
        """

        scan_list = ScanList()
        adv_sett = AdvancedSettingsPage()
        adv_sett_modal = AddAdvancedSettingModal()
        adv_sett_list = AdvancedSettingsList()

        try:
            adv_sett.open()
            modify_existing_advanced_setting(setting_name=setting_details['setting_name'], \
                                             setting_value=setting_details['setting_value'], \
                                             setting_tab=setting_details['setting_tab'])
            wait(lambda: Notifications().successes, waiting_for="Notification list to populate")
            adv_sett.open()
            adv_sett.search_textbox.clear()
            advanced_setting_list = AdvancedSettingsList()
            current_setting_value = advanced_setting_list.get_settings_value(setting_tab=setting_details['setting_tab'], \
                                                                             setting_name=setting_details[
                                                                                 'setting_name'])
            assert setting_details['setting_value'] == current_setting_value[0], "The setting value is unexpected"
            sleep(WAIT_SHORT, reason="It takes little bit time to change the settings list.")
            scan_page = ScansPage()
            scan_page.my_scans_tab.click()
            sleep(WAIT_NORMAL, reason="It takes little bit time to change the settings list.")
            scan_list.launch_scan_and_wait_for_status(scan_name=create_scans[0])
            scan_result_page = ScanViewPage()
            ScanList().click_on_scan(scan_name=create_scans[0])
            scan_result_page.host_tab.click()
            wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")
            host_list = ScansHostList()
            assert host_list.get_total_rows() == 2, "Unexpected hosts were scanned"

        finally:
            adv_sett.open()
            adv_sett_list.performance_tab.click()
            adv_sett.search_textbox.value = 'Max Concurrent Hosts Per Scan'
            adv_sett_modal.reset_setting_banner(setting_name=setting_details['setting_name'])
            LoadingCircle(WAIT_SHORT)


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('handle_unexpected_initialize_nessus_screen', 'login')
class TestAdvancedSettingsforManager:
    @pytest.mark.xray(test_key='NES-14522')
    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix=API.User.Users.BASIC_USER + ' - '), 'full_name': 'Basic user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.BASIC, 'do_login': False},
        {'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '), 'full_name': 'Standard user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.STANDARD, 'do_login': False}],
                             indirect=True)
    def test_login_banner_for_all_type_of_users(self, create_user):
        """
        NES-14522 : Verify that login banner gets reflected for all types of users in nessus manager
        """
        setting_name = Nessus.AdvancedSettings.LOGIN_BANNER
        setting_value = "my custom banner"

        advanced_setting = AdvancedSettingsPage()
        advanced_settings_list = AdvancedSettingsList()
        action_modal = ActionCloseModal()
        advanced_setting.open()

        add_advance_setting_modal = AddAdvancedSettingModal()
        add_advance_setting_modal.find_specific_setting_name(setting_name=setting_name).click()
        add_advance_setting_modal.add_setting_value(setting_value=setting_value)
        sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for banner text to get populated in list')
        assert setting_value in advanced_settings_list.get_settings_value(), 'Banner property not added'

        login_page = LoginPage()
        UserMenu().logout()
        username, password = create_user
        login_page.login_with_credentials(username=username, password=password)
        wait(lambda: action_modal.is_element_present('modal'), timeout=TIME_THIRTY_SECONDS)

        assert action_modal.modal_content.text == setting_value, 'Login Banner text mismatch'
        action_modal.accept_action()
        wait(lambda: ScansPage().is_element_present('my_scans'), waiting_for="waiting for page to get fully loaded")

        NotificationActions().remove_all()
        UserMenu().logout()

        login_page.login_with_defaults()
        advanced_setting.open()

        assert setting_value in advanced_settings_list.get_settings_value(), 'Banner property not added'

        add_advance_setting_modal.reset_setting_banner(setting_name=setting_name)

        assert setting_value not in advanced_settings_list.get_settings_value(), "Login Banner Settings not deleted"
