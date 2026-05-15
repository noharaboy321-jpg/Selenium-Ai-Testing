"""
Nessus Software Update related test cases

:copyright: Tenable Network Security, 2017
:date: February 19, 2017
:last_modified: Apr 26, 2023
:author: @smadan, @ntarwani, @kpanchal, @mdabra
"""

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting import TimeoutExpired

from catium.lib.config.environment_variables import CommonConfig
from catium.lib.const import TIME_FIVE_MINUTES, TIME_TEN_MINUTES
from catium.lib.const.base_constants import HOST_PLUGIN_FEED
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessus_ui.settings import manage_server_restart_task
from nessus.helpers.nessuscli import fix
from nessus.helpers.nessuscli.helper import get_nessus_cli, stop_nessus, start_nessus
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.settings import handle_connection_popup
from nessus.lib.const.constants import Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import SoftwareUpdate, About
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AddAdvancedSettingModal, \
    AdvancedSettingsList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import NotificationActions
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.fixture()
def enable_nessus_auto_update_setting():
    """Enable software update by setting fix parameter auto_update to 'yes'."""

    with SSH() as ssh:
        ssh.execute("{} fix --set auto_update=yes".format(get_nessus_cli()))

    stop_nessus()
    start_nessus()
    wait_for_scanner_to_be_ready(api=NessusAPI())


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('enable_nessus_auto_update_setting', 'login')
class TestSoftwareUpdate:
    """
    Covers About- Software Update related test cases.
    # NQA-1055 : Automation tests for About- Software Update.
    """

    @pytest.mark.xray(test_key='NES-14201')
    @pytest.mark.ie
    def test_save_change_automatic_update_settings(self):
        """
        NES-14201: Verify about page
        NQA- 1055 - About- Software Update.

        1. Navigate to Software update tab under About
        2. Select update plugins option
        3. Click Save button
        4. Verify that update plugins is checked
        """
        about_software_update = SoftwareUpdate()
        about_software_update.open()
        wait(lambda: about_software_update.is_element_present('update_server'),
             waiting_for='Software update page to get loads properly')

        about_software_update.update_plugins.click()

        assert 'checked' in about_software_update.update_plugins.get_css_classes(), 'Update Plugins is not checked'

        about_software_update.save_button.click()

        try:
            handle_connection_popup(timeout_to_appear=TIME_TEN_MINUTES, timeout_to_disappear=TIME_FIVE_MINUTES)
        except TimeoutExpired:
            log.debug("Connection pop up took more time to appear or disappear")

        assert 'checked' in about_software_update.update_plugins.get_css_classes(), 'Update Plugins is not checked'

    @pytest.mark.ie
    def test_pencil_icon_for_update_frequency(self):
        """
        NQA- 1055 - About- Software Update.

        1. Navigate to Software update tab under About
        2. Click on update frequency custom tip
        3. Verify hours label is displayed
        4. Verify update frequency default tip (cross icon) is present
        5. Click on update frequency default tip(cross icon)
        """
        if fix.get(key="auto_update_delay")['stdout'] != "The current value for 'auto_update_delay' is '24'.":
            fix.set(key="auto_update_delay", value="24")

        about_software_update = SoftwareUpdate()
        about_software_update.open()
        wait(lambda: about_software_update.is_element_present('update_server'),
             waiting_for='Software update page to get loads properly')

        assert about_software_update.update_frequency_custom_tip.is_displayed(), "Pencil icon is not present"

        about_software_update.update_frequency_custom_tip.click()

        assert about_software_update.hours_label.is_displayed(), "Hours label is not present"

        assert about_software_update.update_frequency_default_tip.is_displayed(), "Cross icon is not present"

        about_software_update.update_frequency_default_tip.click()

        assert about_software_update.update_frequency_custom_tip.is_displayed(), "Pencil icon is not present"

    @pytest.mark.ie
    def test_change_update_frequency_option(self):
        """
        NQA- 1055 - About- Software Update.

        1. Navigate to Software update tab under About
        2. Change frequency settings to Weekly and save
        3. Navigate to overview tab
        4. Navigate back to Software update tab
        5. Verify the frequency is set to Weekly
        """
        about_software_update = SoftwareUpdate()
        about_software_update.open()
        wait(lambda: about_software_update.is_element_present('update_server'),
             waiting_for='Software update page to get loads properly')

        about_software_update.change_software_update_settings \
            (frequency_option='Weekly', server_value='plugins-internal-staging.cloud.aws.tenablesecurity.com')

        assert about_software_update.update_frequency.get_text_selected() == 'Weekly', 'Frequency should be weekly'

        # revert frequency to some other option
        about_software_update.change_software_update_settings(frequency='Daily')

        try:
            handle_connection_popup(timeout_to_appear=TIME_TEN_MINUTES, timeout_to_disappear=TIME_FIVE_MINUTES)
        except TimeoutExpired:
            log.debug("Connection pop up took more time to appear or disappear")

        assert about_software_update.update_frequency.get_text_selected() == 'Daily', 'Frequency should be Daily'

    @pytest.mark.ie
    def test_change_update_server(self):
        """
        NQA- 1055 - About- Software Update.

        1. Navigate to Software update tab under About
        2. Change update server from 'plugins-internal-staging.cloud.aws.tenablesecurity.com'
        to 'plugins-internal-prod.cloud.aws.tenablesecurity.com' and save
        3. Navigate to overview tab
        4. Navigate back to Software update tab
        5. Verify the update server field is set to plugins-internal-prod.cloud.aws.tenablesecurity.com
        """
        about_software_update = SoftwareUpdate()
        about_software_update.open()
        wait(lambda: about_software_update.is_element_present('update_server'),
             waiting_for='Software update page to get loads properly')

        if about_software_update.is_element_present('update_frequency_default_tip'):
            about_software_update.update_frequency_default_tip.click()

        new_plugin_feed_server = Nessus.Scan.Target.STAGING_FEED_SERVER_HOST
        about_software_update.change_software_update_settings(server_value=new_plugin_feed_server)

        assert about_software_update.update_server.value == new_plugin_feed_server, \
            "Expected update server value: {}".format(new_plugin_feed_server)

        # revert update server to actual value
        plugin_feed_server = Nessus.Scan.Target.STAGING_FEED_SERVER_HOST
        about_software_update.change_software_update_settings(server=plugin_feed_server)

        try:
            handle_connection_popup(timeout_to_appear=TIME_TEN_MINUTES, timeout_to_disappear=TIME_FIVE_MINUTES)
        except TimeoutExpired:
            log.debug("Connection pop up took more time to appear or disappear")

        assert about_software_update.update_server.value == plugin_feed_server, \
            "Expected update server value: {}".format(plugin_feed_server)

    def test_visibility_of_default_update_frequency_options(self):
        """
        NES-9394: UI Automation: About | Verify that Software Updates are working properly for set Update frequency

        Steps:
        1. In NM/NP, navigate to Settings-> About-> Software Updates page
            - By default 'Daily' is selected as a Update frequency and also 'Weekly' and 'Monthly' options are
              available in dropdown

        Scenario tested:
        [x] Verify that 'Daily' option is selected by default as a Update frequency.
        [x] Verify that 'Daily', 'Weekly' and 'Monthly' options are available in Update frequency dropdown.
        """
        # Go to software update tab under About page
        about_software_update = SoftwareUpdate()
        about_software_update.open()
        wait(lambda: about_software_update.is_element_present('update_server'),
             waiting_for='Software update page to get loads properly')

        # Verify 'Daily' option is selected by default
        assert about_software_update.update_frequency.get_text_selected() == Nessus.About.SoftwareUpdate.DAILY, \
            '\'Daily\' option is not selected by default as a Update frequency.'

        about_software_update.update_frequency.click()

        # Verify 'Daily', 'Weekly' and 'Monthly' options are available in Update frequency dropdown
        assert all([option.text == Nessus.About.SoftwareUpdate.UPDATE_FREQUENCY_OPTIONS for option in
                    about_software_update.update_frequency.get_options()]), \
            '\'Daily\', \'Weekly\' and \'Monthly\' options are not available in Update frequency dropdown.'

    @pytest.mark.parametrize('change_update_frequency', [{'frequency': '3'}], indirect=True)
    @pytest.mark.parametrize('operation', ["navigate", "refresh", "re-login"])
    def test_update_frequency_in_hours(self, change_update_frequency, operation):
        """
        NES-9398: UI Automation: About | saved changes should be retained even after re-login and switching the tabs

        Steps:
        1. Navigate to Settings-> About-> Software Updates page
        2. Change Updates frequency = 1 Hour
        3. Save changes
        4. Now navigate to any other page (eg. MysScan page) or refresh / re-login into instance
        5. Verify the Update frequency value that was changed before

        Scenario Tested:
        [x] Verify that Update frequency value should remain same as lastly saved i.e. 1 hour.
        """
        # Verify the success message after updating software update frequency value.
        assert Notifications().successes[-1] == Messages.NotificationMessages.About.settings_saved, \
            'Getting incorrect notification, Expected is \'{}\''.format(Messages.NotificationMessages.About.
                                                                        settings_saved)

        about_software_update = SoftwareUpdate()

        # Switch to another page
        if operation == "navigate":
            header_page = HeaderBasePage()
            header_page.scan_link.click()
            header_page.settings_link.click()

            about_page = About()
            about_page.software_update_tab.click()

        # Refresh the current page
        elif operation == "refresh":
            about_software_update.refresh()

        # Re-login and navigate to software update page
        elif operation == "re-login":
            UserMenu().logout()
            LoginPage().login_with_defaults()
            about_software_update.open()
            wait(lambda: about_software_update.is_element_present('update_server'),
                 waiting_for='Software update page to get loads properly')

        # Verify the software update frequency value
        assert about_software_update.update_frequency_in_hours.value == change_update_frequency, \
            "'Update Frequency' value didn't matched."

        # Verify 'hours' label next to 'Update Frequency' input field
        assert about_software_update.is_element_present('hours_label'), '\'hours\' label is not displayed next to ' \
                                                                        '\'Update Frequency\' input box.'

        # Verify 'x' icon next to 'hours' label
        assert about_software_update.is_element_present('update_frequency_remove_icon'), \
            '\'Update Frequency\' remove icon is not displayed.'

    @pytest.mark.parametrize('hour_value', ['1.5', '2', 'a', '1a'])
    def test_custom_update_frequency_under_software_update(self, hour_value):
        """
        NES-9397: UI Automation: About | Verify validation for SW update frequency eg. fraction value as an hours will
                  highlight the box in Red

        Steps:
        1. In NM/NP, Navigate to Settings->About->Software Updates page
        2. Click on edit icon(Custom Update frequency) available next to 'Update Frequency'
            - It will enable a Textbox to enter a value for update frequency and will show up 'hours' label
        3. Enter any fraction value in Textbox i.e 2.5
            - It will highlight textBox with Red Color
        4. Click on 'Save' button
            - It will show up a validation message: " Error: Please correct all form errors to continue."

        Scenario Tested:
        [x] Verify, on entering a fraction value as an hours under SW update frequency, the input box should be turned
            to Red color.
        [x] Verify the error message "Error: Please correct all form errors to continue." as well after saving the hour
            value as a fraction value.
        """
        # Go to Software Update tab under About page
        about_software_update = SoftwareUpdate()
        about_software_update.open()
        wait(lambda: visibility_of_element_located(about_software_update.update_server),
             waiting_for='Software update page to load')

        if about_software_update.is_element_present('update_frequency_custom_tip'):
            about_software_update.update_frequency_custom_tip.click()

        # Verify input field for custom update frequency hours is displayed
        assert about_software_update.is_element_present('update_frequency_in_hours'), \
            'Input field for Custom update frequency is not displayed.'

        # Verify 'hours' label next to 'Update Frequency' input field
        assert about_software_update.is_element_present('hours_label'), '\'hours\' label is not displayed next to ' \
                                                                        '\'Update Frequency\' input box.'

        # Verify 'x' icon next to 'hours' label
        assert about_software_update.is_element_present('update_frequency_remove_icon'), \
            '\'Update Frequency\' remove icon is not displayed.'

        # Enter value in custom update frequency input field
        about_software_update.update_frequency_in_hours.value = hour_value

        if not hour_value.isdigit():
            # Verify input box for custom update frequency hours is getting in red color
            assert 'error' in about_software_update.update_frequency_in_hours.get_css_classes(), \
                'Input box has not turned to red color after entering fraction value as an hour.'

        about_software_update.save_button.click()
        notification = Notifications()

        if hour_value.isdigit():
            # Verify the success message after updating software update frequency value.
            assert notification.successes[-1] == Messages.NotificationMessages.About.settings_saved, \
                'Getting incorrect success notification, Expected is \'{}\''.format(Messages.NotificationMessages.
                                                                                    About.settings_saved)
        else:
            # Verify the error message after entering fraction value as an hour
            assert notification.errors[-1] == Messages.NotificationMessages.continue_button_code, \
                'Getting incorrect error notification, Expected is \'{}\''.format(Messages.NotificationMessages.
                                                                                  continue_button_code)

    @pytest.mark.parametrize("server_value", [" ", "plugins-internal-staging.cloud.aws.tenablesecurity.com ",
                                              " plugins-internal-staging.cloud.aws.tenablesecurity.com",
                                              " plugins-internal-staging.cloud.aws.tenablesecurity.com ",
                                              "test with space in between", HOST_PLUGIN_FEED,
                                              CommonConfig.CAT_PLUGIN_FEED_HOST])
    def test_update_server_with_invalid_values(self, server_value):
        """
        NES-9503 - NES-9160 Nessus Professional 8.X.X Content Injection Vulnerability.

        Scenarios:
        [x] It should give error when user inputs invalid value in server.
        [x] It should give success message when user inputs valid value in server.

        Steps:
        1. Navigate to Software update tab under About
        2. Change update server from 'plugins-internal-staging.cloud.aws.tenablesecurity.com' to the server_value and save
        3. Verify the errors when inputs some invalid values.
        4. Verify the success messages when inputs some valid values.
        """
        about_software_update = SoftwareUpdate()
        about_software_update.open()
        wait(lambda: about_software_update.is_element_present('update_server'),
             waiting_for='software update page get loads properly')

        if about_software_update.is_element_present('update_frequency_in_hours'):
            about_software_update.update_frequency_remove_icon.click()

        about_software_update.change_software_update_settings(server_value=server_value)
        notification = Notifications()

        if server_value == CommonConfig.CAT_PLUGIN_FEED_HOST or server_value == HOST_PLUGIN_FEED:
            # Verify the success message for valid values.
            assert notification.successes[-1] == Messages.NotificationMessages.About.settings_saved, \
                'Success message is different than expected, it should be {}'.format(Messages.NotificationMessages.
                                                                                     About.settings_saved)
        else:
            # Verify the error message for invalid values
            assert notification.errors[-1] == Messages.NotificationMessages.update_server_error, \
                'Error found is different than expected, it should be {}'.format(Messages.NotificationMessages.
                                                                                 update_server_error)

    def test_advanced_settings_value_for_automatic_updates(self):
        """
        NES-9396 :  About | verify that if user has set auto_update= no from adv settings then under software updates,
                    automatic updates should set to disable.

        Steps:
        1. Go to the About-> Settings -> Software Updates and verify the default selected Software update type under
           Automatic Updates.
                - 'Update all components' is selected by default
        2. Now go to Settings->Advanced settings and set auto_update=no
        3. Now navigate again to Software Update page and verify selected option for automatic updates.
                - 'Disabled' is selected under automatic updates
        4. Now select 'Update all components' from Software update page and save the changes.
                - Successful message will show up
        5. Now check the value of auto_update settings.
                - It will reflect the changes in advanced setting also i.e. auto_update=yes

        Scenario tested:
        [x] If user has set Automatic Update(auto_update) = no  from adv settings then under About->Settings->Software
            updates, Automatic updates should set to 'disable'.
        """
        # Go to software update tab under About page
        about_software_update = SoftwareUpdate()
        about_software_update.open()
        wait(lambda: about_software_update.is_element_present('update_server'),
             waiting_for='Software update page to get loads properly')

        # Verify 'Update all components' option under 'Automatic Updates' is selected by default
        assert about_software_update.update_all_components.is_selected(), \
            '\'Update all components\' option under \'Automatic Updates\' is not selected by default.'

        # Click on 'Advanced' from side navigation panel
        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=Nessus.SideNavSettings.ADVANCED).click()

        # Update the value of 'Auto Updates' setting
        advanced_setting = AdvancedSettingsPage()
        add_advanced_settings = AddAdvancedSettingModal()
        add_advanced_settings.select_value_from_setting_dropdown(setting_name=Nessus.AdvancedSettings.AUTO_UPDATE,
                                                                 setting_tab=Nessus.AdvancedSettings.MISCELLANEOUS_TAB,
                                                                 setting_value='No')

        notification = Notifications()

        # Verify the success message after updating the advanced setting value.
        assert notification.successes[-1] == Messages.NotificationMessages.save_settings, \
            'Success message is different than expected, it should be {}'.format(Messages.NotificationMessages.
                                                                                 save_settings)

        NotificationActions().remove_all()
        wait(lambda: visibility_of_element_located(advanced_setting.service_restart_link),
             waiting_for='restart link')

        # Click on 'Restart server' link and wait for sever to be ready
        advanced_setting.service_restart_link.click()
        manage_server_restart_task()
        handle_connection_popup(timeout_to_appear=TIME_FIVE_MINUTES, timeout_to_disappear=TIME_TEN_MINUTES)

        about_software_update.open()
        wait(lambda: about_software_update.is_element_present('update_server'),
             waiting_for='Software update page to get loads properly')

        # Verify 'Disabled' option is selected after updating the setting "auto_update=No"
        assert about_software_update.disabled.is_selected(), \
            '\'Disabled\' option under \'Automatic Updates\' is not selected after saving "auto_update=No" from ' \
            'advanced settings.'

        # Select 'Update all components' option under 'Automatic Updates'
        about_software_update.update_all_components.click()
        about_software_update.save_button.click()

        # Verify the success message after updating software update value.
        assert notification.successes[-1] == Messages.NotificationMessages.About.settings_saved, \
            'Success message is different than expected, it should be {}'.format(Messages.NotificationMessages.
                                                                                 About.settings_saved)

        # Click on 'Advanced' from side navigation panel and navigate to 'Miscellaneous' tab
        side_nav.get_sidenav_element(element_name=Nessus.SideNavSettings.ADVANCED).click()
        advanced_setting.get_settings_tab_element(setting_tab=Nessus.AdvancedSettings.MISCELLANEOUS_TAB).click()

        setting_value = AdvancedSettingsList().get_specific_setting_value(
            setting_name=Nessus.AdvancedSettings.AUTO_UPDATE).text

        # Verify advanced setting value after selecting 'Update all components' option
        assert setting_value == 'Yes', 'Getting different setting value after selecting \'Update all components\' ' \
                                       'option under \'Automatic Updates\'.'

    @pytest.mark.xray(test_key='NES-14453')
    def test_verify_manual_software_update_modal(self):
        """
        NES-14453 : Verify 'manual software update' is clickable
        """
        software_update = SoftwareUpdate()
        software_update.open()

        wait(lambda: software_update.is_element_present("manual_software_update"),
             waiting_for="Manual Software Update button to get visible")

        software_update.manual_software_update.click()
        manual_update_modal = ActionCloseModal()
        wait(lambda: manual_update_modal.is_element_present("modal"),
             waiting_for="Manual Software Update modal to get visible")

        assert manual_update_modal.modal_title.text == "Manual Software Update", "Manual Software Update title is missing"

        all_radio = manual_update_modal.get_modal_radio_labels(element=manual_update_modal.modal_content_radio)

        assert all_radio, "Update options not visible"
