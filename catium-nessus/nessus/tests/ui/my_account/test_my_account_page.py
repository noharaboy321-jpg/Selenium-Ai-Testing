""""
Nessus test cases related to My Account page

:copyright: Tenable Network Security, 2017
:date: January 08, 2018
:last_modified: Sept 06, 2019
:author: @rdutta, @smadan, @kpanchal
"""
import re

import pytest
from requests import HTTPError
from selenium.common.exceptions import StaleElementReferenceException, NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located

from catium.lib.const import WAIT_SHORT, TIME_TEN_SECONDS
from catium.lib.const import WAIT_TINY, HTTPStatus
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_SIXTY_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver, get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.lib.config import NessusConfig
from nessus.lib.const import API
from nessus.lib.const.constants import Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.my_account.my_account_page import AccountSettings
from nessus.pageobjects.my_account.my_account_page import MyAccount, APIKeys, GenerateAPIKeysModal
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestMyAccount:
    """
    Covers My Account page related test cases.
    # NQA-1053 : Automation tests for Settings - My Account.
    """
    cat = None

    def test_generate_and_verify_visibility_of_api_keys(self):
        """
        1. Click the tab API Keys, verify /settings/my-account/api-keys is correct.
        2. Click generate, verify pop up.
        3. Click generate, Verify Access key and Secret Key are displayed
        4. Navigate to Account Settings tab
        5. Navigate back to API Keys, verify keys are not displayed
        """
        # Navigate to MyAccount page
        my_account_page = MyAccount()
        my_account_page.open()

        # Click API Keys tab, verify /settings/my-account/api-keys is correct.
        my_account_page.api_keys_tab.click()
        page_url = get_driver().current_url
        assert page_url.split('#')[1] == my_account_page.api_keys_tab.get_attribute('href').split('#')[1], \
            "Current page url and UI route doesn't match."

        # Click generate button, verify pop up is present
        api_keys_page = APIKeys()
        api_keys_page.generate_button.click()
        popup_window = GenerateAPIKeysModal()
        assert popup_window.get_modal_title == 'Generate API Keys', "Popup to generate api keys doesn't came up."
        popup_window.cancel_button.click()

        # Click generate, Verify Access key and Secret Key are displayed
        api_keys_page.generate_api_keys()
        LoadingCircle(WAIT_SHORT)
        assert visibility_of_element_located((api_keys_page.access_key_field.we_by,
                                              api_keys_page.access_key_field.we_value))(get_driver()), "Access key " \
                                                                                                       "is invisible."
        assert visibility_of_element_located((api_keys_page.secret_key_field.we_by,
                                              api_keys_page.secret_key_field.we_value))(get_driver()), "Secret key " \
                                                                                                       "is invisible."
        # Navigate to other page (e.g. Account Settings tab)
        my_account_page.account_settings_tab.click()
        LoadingCircle(WAIT_SHORT)

        # Navigate back to API Keys, verify keys are not displayed
        my_account_page.api_keys_tab.click()
        assert invisibility_of_element_located((api_keys_page.access_key_field.we_by,
                                                api_keys_page.access_key_field.we_value))(get_driver()), "Access key" \
                                                                                                         " is visible."
        LoadingCircle(WAIT_SHORT)
        assert invisibility_of_element_located((api_keys_page.secret_key_field.we_by,
                                                api_keys_page.secret_key_field.we_value))(get_driver()), "Secret key" \
                                                                                                         " is visible."

    def test_regenerate_api_keys(self):
        """
        1. Click generate, Verify Access key and Secret Key are displayed
        2. Repeat step 1
        3. Verify key changes.
        """
        # Click generate, Verify Access key and Secret Key are displayed
        api_keys_page = APIKeys()
        api_keys_page.open()
        api_keys_page.generate_api_keys()
        LoadingCircle(WAIT_SHORT)
        assert (api_keys_page.access_key_field.is_displayed()
                and api_keys_page.secret_key_field.is_displayed()), "Access key and secret key not displayed."

        assert (api_keys_page.access_key.isalnum() and api_keys_page.secret_key.isalnum() and
                (len(api_keys_page.access_key) == API.User.API_KEYS_LENGTH) and
                (len(api_keys_page.secret_key) == API.User.API_KEYS_LENGTH)), "Invalid key generated."

        # store the keys
        access_key = api_keys_page.access_key
        secret_key = api_keys_page.secret_key
        LoadingCircle(WAIT_TINY)

        # Regenerate the keys and verify they have changed from previous
        api_keys_page.generate_api_keys()
        LoadingCircle(WAIT_SHORT)
        assert (api_keys_page.access_key_field.is_displayed()
                and api_keys_page.secret_key_field.is_displayed()), "Access key and secret key not displayed."

        assert (api_keys_page.access_key.isalnum() and api_keys_page.secret_key.isalnum() and
                (len(api_keys_page.access_key) == API.User.API_KEYS_LENGTH) and
                (len(api_keys_page.secret_key) == API.User.API_KEYS_LENGTH)), "Invalid key generated."

        assert ((api_keys_page.access_key != access_key)
                and (api_keys_page.secret_key != secret_key)), "Keys were not changed after regeneration."

    def test_accessibility_of_api_documentation_link(self, nessus_api_login):
        """
        1. Click "API Documentation" link.
        2. Verify new browser tab is opened to https://<IP:PORT>/api#/authorization
        3. Verify that Nessus version is correct in "API Documentation" page. (NES-13062)
        """
        # navigate to ApiKeys tab and click api documentation link
        api_keys_page = APIKeys()
        api_keys_page.open()
        host_url = api_keys_page.current_url.split("/#")[0]
        api_keys_page.api_documentation_link.click()

        # switch to newly opened tab and verify url
        windows_handler = WindowsHandler()
        windows_handler.switch_to_window(window_handle=windows_handler.handles[1])
        page_url = windows_handler._driver.current_url
        assert page_url == '{}/api#/authorization'.format(host_url), "Browser tab opened with wrong URL."

        # Verify that Nessus version is correct in "API Documentation" page.
        wait(lambda: visibility_of_element_located((By.CSS_SELECTOR, "h1 + span"))(get_driver_no_init()),
             timeout_seconds=TIME_TEN_SECONDS)
        api_documentation_text = get_driver_no_init().find_element(By.CSS_SELECTOR, "h1 + span").text
        nessus_version = re.search(r'\d{1,2}.\d{1,2}.\d{1,2}', api_documentation_text).group()
        assert nessus_version in self.cat.api.server.properties()['nessus_ui_version'], \
            "Nessus version is not correct on API documentation page."

        windows_handler.switch_to_window(window_handle=windows_handler.handles[0])

    @pytest.mark.ie
    def test_change_user_name(self):
        """
        Verify on changing full name, it gets updated at the top-right corner Step-1.

        NES-9689: UI Automation: My Account | Verify User Info and Password settings

        Scenario Tested:
        [x] Verify that after removing custom Full Name, it will change the name as username at top right corner of UI.
        """

        def get_notification_message():
            notification_message = None
            attempts = 0

            while attempts < 5:
                try:
                    notification_message = notification.successes[-1]
                    break
                except (StaleElementReferenceException, NoSuchElementException, IndexError):
                    log.warning('Notification message did not found.')

                attempts = attempts + 1

            return notification_message

        my_account_setting = AccountSettings()
        my_account_setting.open()

        LoadingCircle(WAIT_NORMAL)
        changed_user_name = random_name("User" + "-")
        my_account_setting.change_full_name(name=changed_user_name)

        notification = Notifications()
        success_message = get_notification_message()
        header_page = HeaderBasePage()

        if not success_message:
            notifications_dict = header_page.get_all_notifications_from_notification_box()
            header_page.notification_box_close_button.click()

            success_message = notifications_dict['Success'][0]

        # Verify success notification message after changing user's full name
        assert success_message == Messages.NotificationMessages.save_change_password, \
            'Getting incorrect error notification. Expected is \'{}\''.format(
                Messages.NotificationMessages.save_change_password)

        # Verify user's full name is updated after changing
        assert header_page.user_name_text.text == changed_user_name, \
            "User name has not been changed at top right corner"

        my_account_setting.change_full_name(name=Nessus.USERNAME)

    def test_save_invalid_email(self):
        """Verify error message on entering invalid email address Step-2,3."""
        my_account_setting = AccountSettings()
        my_account_setting.open()
        wait(lambda: visibility_of_element_located(my_account_setting.full_name),
             waiting_for='My account settings page to load')

        my_account_setting.save_email(email_value="qa@.com")

        assert Notifications().errors[-1] == Messages.NotificationMessages.invalid_email, \
            "Error notification is missing"

    @pytest.mark.ie
    @pytest.mark.jira('NES-7597')
    def test_save_valid_email(self):
        """Verify  email getting stored on entering valid email - Step-2,3."""
        my_account_setting = AccountSettings()
        my_account_setting.open()

        LoadingCircle(WAIT_NORMAL)

        valid_email = "qa@qa.com"
        my_account_setting.save_email(email_value=valid_email)
        LoadingCircle(WAIT_NORMAL)

        SideNav().click_by_link_text(Nessus.SideNavSettings.ABOUT)
        SideNav().click_by_link_text(Nessus.SideNavAccounts.MY_ACCOUNT)

        LoadingCircle(WAIT_NORMAL)

        assert my_account_setting.email.value == valid_email, "Email did not save successfully."

    @pytest.mark.parametrize('password', ['#', 'admin'])
    def test_password_mismatched_values(self, password):
        """
        Verifies that on entering mismatched password value, error pop-up shows up - Step-4,5.

        NES-9689: UI Automation: My Account | Verify User Info and Password settings

        Steps:
        6. Now in 'Change Password' section, set same password in current password and new password > Save
        7. Verify validation message should be displayed - 'Error: New password can not match the current password'

        Scenario Tested:
        [x] Verify validation message should be displayed - 'Error: New password can not match the current password' 
            for entering same value
        """
        my_account_settings = AccountSettings()
        my_account_settings.open()

        LoadingCircle(WAIT_SHORT)
        my_account_settings.change_password(current_password=password, new_password='admin')

        notification = Notifications()

        if password == '#':
            # Verify error notification message for invalid password
            assert notification.errors[-1] == Messages.NotificationMessages.invalid_current_password, \
                'Getting incorrect error notification. Expected is \'{}\''.format(Messages.NotificationMessages.
                                                                                  invalid_current_password)
        else:
            # Verify error notification message for current and new password mismatched
            assert notification.errors[-1] == Messages.NotificationMessages.new_and_current_password_mismatch, \
                'Getting incorrect error notification. Expected is \'{}\''.format(Messages.NotificationMessages.
                                                                                  new_and_current_password_mismatch)

    def test_password_blank_values(self):
        """Verifies that on entering blank password value, error pop-up shows up - Step-4,5."""
        my_account_settings = AccountSettings()
        my_account_settings.open()

        LoadingCircle(WAIT_SHORT)

        my_account_settings.change_password(current_password="admin", new_password='')
        wait(lambda: len(Notifications().errors[-1]) > 0, waiting_for='Notification list to populate.')

        assert Notifications().errors[-1] == Messages.NotificationMessages.new_password_blank, \
            "Error notification is missing"

    def test_change_valid_password(self):
        """Verifies that password can be changed successfully - Step-6."""
        new_password = 'p@ssw0rd1234'

        my_account_settings = AccountSettings()
        my_account_settings.open()
        wait(lambda: my_account_settings.is_element_present("full_name"), waiting_for="Account setting gets loaded")

        try:
            my_account_settings.current_password.send_keys(NessusConfig.CAT_NESSUS_PASSWORD)
            my_account_settings.show_password_eye.click()

            assert not my_account_settings.show_password_enabled(), "Show password eye is not enabled"

            my_account_settings.new_password.send_keys(new_password)

            assert my_account_settings.new_password.get_attribute('value') == new_password, "Password is not visible"

            my_account_settings.save_button.click()
            notifications = Notifications()

            assert notifications.successes[-1] == Messages.NotificationMessages.save_change_password, \
                "Password changed but, notification was missing"
        finally:
            # Changing the admin password to default set in environment variable
            my_account_settings.change_password(current_password=new_password,
                                                new_password=NessusConfig.CAT_NESSUS_PASSWORD)

    @pytest.mark.parametrize("username", ["istrator", ""])
    def test_edit_and_remove_full_name_of_user(self, username):
        """
        NES-9689: Verify that settings under My Account page works fine

        Steps:
        1.Navigate to My Account page from Settings
        2.Verify that username is displayed as 'Full Name' in text-box by default
        3.Verify Full Name can be removed (Can be left blank)
        5.Change Full name and Save - Verify it won't affect password settings. Password should be unchanged

        Scenarios Tested:
        [x] Verify that user should be able to set/remove/edit Full Name
        [x] Verify that user should be able to change password
        [x] Verify that user should not be allowed to set existing password as new password
        """
        my_account_setting = AccountSettings()
        my_account_setting.open()
        wait(lambda: visibility_of_element_located(my_account_setting.full_name),
             waiting_for='My account settings page to load')

        default_full_name = my_account_setting.full_name.value

        try:
            # Verify 'Full name' textfield is displayed in 'My Account' setting page
            assert all([my_account_setting.is_element_present('full_name'), default_full_name == Nessus.USERNAME]), \
                '\'Full Name\' input field is not displayed with default user name.'

            if username == "istrator":
                my_account_setting.full_name.send_keys(username)
            else:
                my_account_setting.full_name.clear()

            my_account_setting.save_button.click()

            # Verify success notification message after updating user's full name
            assert Notifications().successes[-1] == Messages.NotificationMessages.save_change_password, \
                'Getting incorrect error notification. Expected is \'{}\''.format(
                    Messages.NotificationMessages.save_change_password)

            header_page = HeaderBasePage()

            if username == "istrator":
                # Verify that user name is updated on top right corner after updating 'Full name'
                assert header_page.user_name_text.text == default_full_name + username, \
                    "User name has not been changed at top-right corner after editing full name of user."
            else:
                # Verify that user name is getting default name on top right corner after leaving 'Full name' blank
                assert header_page.user_name_text.text == default_full_name, \
                    "User name is not getting as default user name while leaving full name blank."

            my_account_setting.change_full_name(name=Nessus.USERNAME)
        finally:
            UserMenu().logout()
            login_page = LoginPage()

            if login_page.is_element_present('username_field', timeout=TIME_SIXTY_SECONDS):
                login_page.login_with_defaults()

            my_account_setting.open()
            wait(lambda: visibility_of_element_located(my_account_setting.full_name),
                 waiting_for='My account settings page to load')

            my_account_setting.change_full_name(name=Nessus.USERNAME)

    @pytest.mark.xray(test_key='NES-14462')
    def test_navigation_to_my_account_page(self):
        """
        NES-14462 : Verify that clicking on My account button user can navigate to proper page.

        Scenarios Tested:
        [x] Verify that User is navigated to My Account page
        [x] Verify URL of My account page
        """
        my_account_page = MyAccount()
        my_account_page.open()
        my_account_settings = AccountSettings()
        wait(lambda: visibility_of_element_located(my_account_settings.save_button),
             waiting_for='My account settings page to load properly')
        assert Nessus.Accounts.MY_ACCOUNT_TITLE == my_account_settings.my_account_title.text
        assert 'settings/my-account' in get_driver_no_init().current_url


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestMyAccountWithUserTab:
    """
    Covers My Account page related test cases.
    # NQA-1053 : Automation tests for Settings - My Account.
    sub-part: As Nessus professional doesn't have "Users" tab in settings.
    """

    def test_login_with_generated_api_keys(self):
        """
        1. Click to generate Access key and Secret Key
        2. Verify that keys can be used with the API login
            Format: curl -H "X-ApiKeys: accessKey={accessKey}; secretKey={secretKey}" https://localhost:8834/login
        """
        # Click to generate Access key and Secret Key
        api_keys_page = APIKeys()
        api_keys_page.open()
        api_keys_page.generate_api_keys()
        LoadingCircle(WAIT_SHORT)

        # verify keys can be used with the API login session
        nessus_api = NessusAPI()
        nessus_api.set_api_keys(access_key=api_keys_page.access_key, secret_key=api_keys_page.secret_key)

        try:
            resp = nessus_api.users.get_users()
        except HTTPError:
            if nessus_api.http_status_code != HTTPStatus.OK:
                pytest.fail("Unable to authenticate API Keys generated from UI.")
        assert resp and nessus_api.http_status_code == HTTPStatus.OK, "Unable to authenticate with API Keys."
