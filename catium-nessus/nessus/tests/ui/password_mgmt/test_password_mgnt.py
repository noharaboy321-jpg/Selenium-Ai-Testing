""""
Nessus test cases related to Password Management page under Settings

:copyright: Tenable Network Security, 2019
:date: May 21, 2018
:last_modified: Jan 31, 2022
:author: @rdutta, @yshah, @kpanchal
"""

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.config import Config
from catium.lib.const import TIME_TEN_SECONDS
from catium.lib.const.base_constants import TIME_TWO_MINUTES, TIME_THIRTY_SECONDS
from catium.lib.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.nessus_ui.settings import login_helper_after_server_restart
from nessus.helpers.nessuscli.helper import stop_nessus, start_nessus
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.lib.const.constants import Nessus, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.my_account.my_account_page import MyAccount, AccountSettings
from nessus.pageobjects.password_mgmt.password_management_page import PasswordManagement
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('revert_password_settings_to_default', 'login')
class TestPasswordManagement:
    """Covers password management related test cases under Settings tab."""
    cat = None

    @staticmethod
    def navigate_to_password_management_page_and_modify_settings(modify_settings: bool = False,
                                                                 settings_details: dict = None) -> None:
        """
        Go to Settings and navigate to "Password Mgmt" page and
        save the settings after modify according to specified parameter.
        :param bool modify_settings: If false then only navigate to the page else specified settings will modify
        :param dict settings_details: Settings to modify.
        :return: None
        """
        HeaderBasePage().settings_link.click()
        SideNav().get_sidenav_element(element_name=Nessus.SideNavSettings.PASSWORD_MGMT).click()

        if modify_settings:
            PasswordManagement().modify_password_settings(**settings_details)

    @staticmethod
    def set_pwd_mgmt_settings_to_default():
        """ Reset the password management settings to default """
        if LoginPage().is_element_present('username_field'):
            login_helper_after_server_restart()

        default_setting_payload = {'password_complexity': False, 'session_timeout': '30', 'max_login_attempts': '',
                                   'min_passwd_length': '', 'login_notification': False}

        TestPasswordManagement.navigate_to_password_management_page_and_modify_settings(
            modify_settings=True, settings_details=default_setting_payload)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_visibility_of_default_elements(self):
        """
        Test to verify the page title and default elements
        #NQA-1191: Test Password Complexity UI (Step-1)
        1. Navigate to “Password Mgmt” page under Settings.
        2. Verify page having title as “Password Management”.
        3. Also verify visibility of default elements and “Save”/”Cancel” button.
        """
        passwd_mgmt_page = PasswordManagement()
        passwd_mgmt_page.open()
        wait(lambda: visibility_of_element_located(passwd_mgmt_page.cancel_button),
             waiting_for="", timeout_seconds=TIME_TEN_SECONDS)

        assert passwd_mgmt_page.page_header == 'Password Management', \
            "Page title is missing or mismatched with expected value."

        assert all([passwd_mgmt_page.is_element_present('password_complexity_switch'),
                    passwd_mgmt_page.is_element_present('session_timeout_minutes'),
                    passwd_mgmt_page.is_element_present('max_login_attempts'),
                    passwd_mgmt_page.is_element_present('min_password_length'),
                    passwd_mgmt_page.is_element_present('login_notification_switch'),
                    passwd_mgmt_page.is_element_present('save_button'),
                    passwd_mgmt_page.is_element_present('cancel_button')]), "Any of the default element is missing."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('test_data', [{
        'password_complexity': True, 'session_timeout': '40', 'max_login_attempts': '7', 'min_passwd_length': '10',
        'login_notification': True}])
    def test_saved_values_retained_after_logout(self, test_data):
        """
        Test to verify saved values are retained after logout.
        #NQA-1191: Test Password Complexity UI (Step-2)
        1. Navigate to “Password Mgmt” page under Settings.
        2. Modify some values and click “Save” and verify success notification.
        3. Logout the user.
        4. Login and verify above saved values are retained.
        """
        try:
            self.__class__.navigate_to_password_management_page_and_modify_settings(modify_settings=True,
                                                                                    settings_details=test_data)

            assert Notifications().successes[-1] == Messages.NotificationMessages.PasswordManagement.settings_updated, \
                "Success notifications for password settings updated is mismatched or missing."

            UserMenu().logout()
            LoginPage().login_with_defaults()
            self.__class__.navigate_to_password_management_page_and_modify_settings(modify_settings=False)

            assert PasswordManagement().get_saved_data() == test_data, "Saved values doesn't retained after logout."
        finally:
            self.__class__.set_pwd_mgmt_settings_to_default()

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('test_data', [
        {'session_timeout': 'aaa'}, {'session_timeout': '30.5'}, {'max_login_attempts': 'rr'},
        {'max_login_attempts': '7.9'}, {'min_passwd_length': 'd'}, {'min_passwd_length': '10.6'}])
    def test_save_values_with_invalid_data(self, test_data):
        """
        Test to verify invalid data doesnt allow to save the values.
        #NQA-1191: Test Password Complexity UI (Step-3)
        1. Navigate to “Password Mgmt” page under Settings.
        2. Give an alphabetic data value against ‘Min Password Length’ field and hit “Save” button.
        3. Verify it throws an error notification as “Please correct all form errors to continue.”
        4. Verify same with a floating value.
        5. Repeat above steps for ‘Max Login Attempts’ and ‘Session Timeout (mins)’ feature.
        """
        try:
            self.__class__.navigate_to_password_management_page_and_modify_settings(modify_settings=True,
                                                                                    settings_details=test_data)

            assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
                "Error notifications for form error with invalid data for password settings is mismatched or missing."
        finally:
            NotificationActions().remove_all()
            self.__class__.set_pwd_mgmt_settings_to_default()

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('test_data', [{'password_complexity': True, 'min_passwd_length': 7}])
    def test_min_password_length_should_8_or_greater_when_password_complexity_enabled(self, test_data):
        """
        Test to verify ‘Password Complexity’ feature restrict ‘Min Password Length’ feature to greater than 8.
        #NQA-1191: Test Password Complexity UI (Step-4)
        1. Navigate to “Password Mgmt” page under Settings.
        2. Toggle on password complexity feature.
        3. Set ‘Min Password Length’ field as less than 8.
        4. Click “Save” button and verify error notification as
            “Error: When complexity is enabled minimum password length must be 8 or greater.”
        """
        try:
            self.__class__.navigate_to_password_management_page_and_modify_settings(modify_settings=True,
                                                                                    settings_details=test_data)

            assert Notifications().errors[-1] == Messages. \
                NotificationMessages.PasswordManagement.min_passwd_length_error_with_complexity, \
                "Error notifications for form error with invalid data for password settings is mismatched or missing."
        finally:
            self.__class__.set_pwd_mgmt_settings_to_default()

    @pytest.mark.xray(test_key='NES-14469')
    @pytest.mark.parametrize("create_users", [{"user_details": {"System Administrator": {
        'user_name': random_name(prefix='{} - '.format(API.User.Users.SYS_ADMIN_USER)), 'full_name': 'SysAdmin user',
        'email': API.User.Users.TEST_EMAIL, 'password': 'SysAdmin_P@ssw0rd',
        'role': API.User.Role.SYS_ADMIN}}, 'check_login': False}], indirect=True)
    @pytest.mark.parametrize('test_data', [{'password_complexity': True, 'min_passwd_length': 10}])
    @pytest.mark.parametrize('passwords_to_test', [{'invalid_according_to_complexity': 'admin12345'},
                                                   {'valid_according_to_complexity': 'Admin@1234'}])
    def test_save_password_according_to_password_complexity(self, create_users, test_data, passwords_to_test):
        """
        Test to verify password complexity feature doesnt allow you to save a password without matching
        complexion level when feature is enable.
        #NQA-1191: Test Password Complexity UI (Step-5)
        NES-14469: Verify 'password complexity' toggle
        1. Navigate to “Password Mgmt” page under Settings.
        2. Toggle on password complexity feature.
        3. Click “Save” button and verify success notification as “Password setting updated successfully.”
        4. Go to “My Account” page and change password.
        5. Set password which doesn't match password complexity level(e.g. 'admin12345')
            should give you error notification.
        6. Set password which match password complexity level(e.g. 'Admin@1234')should save with a
            success notification as “Account settings updated successfully.”
        """
        user_name = create_users.get(API.User.Role.SYS_ADMIN).get('user_name')
        password = create_users.get(API.User.Role.SYS_ADMIN).get('password')

        UserMenu().logout()
        LoginPage().login_with_credentials(username=user_name, password=password)

        try:
            self.__class__.navigate_to_password_management_page_and_modify_settings(modify_settings=True,
                                                                                    settings_details=test_data)
            notification = Notifications()

            assert notification.successes[-1] == Messages.NotificationMessages.PasswordManagement.settings_updated, \
                "Success notifications for password settings updated is mismatched or missing."

            NotificationActions().remove_all()
            MyAccount().open()
            AccountSettings().change_password(current_password=password,
                                              new_password=list(passwords_to_test.values())[0])

            if passwords_to_test.get('valid_according_to_complexity'):
                assert notification.successes[-1] == Messages.NotificationMessages.save_change_password, \
                    "Success notifications for changed password is mismatched or missing."
            else:
                assert notification.errors[-1] == Messages.NotificationMessages.PasswordManagement. \
                    passwd_complexity_error, "Error notifications for password complexity is mismatched or missing."
        finally:
            self.__class__.set_pwd_mgmt_settings_to_default()

    @pytest.mark.parametrize("create_users", [{"user_details": {"System Administrator": {
        'user_name': random_name(prefix='{} - '.format(API.User.Users.SYS_ADMIN_USER)), 'full_name': 'SysAdmin user',
        'email': API.User.Users.TEST_EMAIL, 'password': 'SysAdmin_P@ssw0rd',
        'role': API.User.Role.SYS_ADMIN}}, 'check_login': False}], indirect=True)
    @pytest.mark.parametrize('test_data', [{'password_complexity': False, 'min_passwd_length': 10}])
    @pytest.mark.parametrize('passwords_to_test', [{'invalid_according_to_minimum_length': 'admin1'},
                                                   {'valid_according_to_minimum_length': 'admin12345'}])
    def test_save_password_according_to_minimum_password_length(self, create_users, passwords_to_test, test_data):
        """
        Test to verify ‘Min Password Length’ feature doesnt allow you to save a password value
        whose length less than the value set against ‘Min Password Length’.
        #NQA-1191: Test Password Complexity UI (Step-6)
        1. Navigate to “Password Mgmt” page under Settings.
        2. Set ‘Min Password Length’ count as 10.
        3. Click “Save” button and verify success notification as “Password setting updated successfully.”
        4. Go to “My Account” page and change password.
        5. Set password which doesn't match password complexity level(e.g. 'admin1') should give you error notification.
        6. Set password which match password complexity level(e.g. 'admin12345')should save with a
            success notification as “Account settings updated successfully.”
        """
        user_name = create_users.get(API.User.Role.SYS_ADMIN).get('user_name')
        password = create_users.get(API.User.Role.SYS_ADMIN).get('password')

        UserMenu().logout()
        LoginPage().login_with_credentials(username=user_name, password=password)

        try:
            self.__class__.navigate_to_password_management_page_and_modify_settings(modify_settings=True,
                                                                                    settings_details=test_data)
            notification = Notifications()

            assert notification.successes[-1] == Messages.NotificationMessages.PasswordManagement.settings_updated, \
                "Success notifications for password settings updated is mismatched or missing."
            wait(lambda: len(notification.successes) == 0, waiting_for='Notification list to clear.')

            MyAccount().open()
            AccountSettings().change_password(current_password=password,
                                              new_password=list(passwords_to_test.values())[0])
            notification = Notifications()
            if passwords_to_test.get('valid_according_to_minimum_length'):

                assert notification.successes[-1] == Messages.NotificationMessages.save_change_password, \
                    "Success notifications for changed password is mismatched or missing."
            else:

                assert notification.errors[-1] == Messages.NotificationMessages. \
                    PasswordManagement.min_passwd_length_error.format(test_data.get('min_passwd_length')), \
                    "Error notifications for minimum password length is mismatched or missing."
        finally:
            self.__class__.set_pwd_mgmt_settings_to_default()

    @pytest.mark.xray(test_key='NES-14485')
    @pytest.mark.parametrize('test_data', [{
        'password_complexity': True, 'session_timeout': '40', 'max_login_attempts': '7', 'min_passwd_length': '8'}])
    def test_password_requirement_on_my_account_page(self, test_data):
        """
        NES-14485 : Verify by enabling toggle 'password requirement' will appear on my account page
        """

        self.navigate_to_password_management_page_and_modify_settings(modify_settings=True,
                                                                      settings_details=test_data)

        notification = Notifications()

        try:
            assert notification.successes[-1] == Messages.NotificationMessages.PasswordManagement.settings_updated, \
                "Success notifications for password settings updated is mismatched or missing."

        finally:

            get_driver_no_init().refresh()

            account = AccountSettings()
            account.open()
            wait(lambda: account.is_element_present('new_password'), waiting_for='waiting for account page to load')

            assert account.password_title.text == Messages.NotificationMessages.PasswordManagement.password_req_title, "Password requirement title missing or not matching"
            assert account.password_description.text == Messages.NotificationMessages.PasswordManagement.password_req_description, "Password requirement description missing or not matching"

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.disable_logout
    @pytest.mark.parametrize('test_data', [{'login_notification': True}, {'login_notification': False}])
    def test_login_notification_gives_every_login_details(self, test_data):
        """
        Test to verify ‘Login Notification’ feature gives you every login information when the feature turned on.
        #NQA-1191: Test Password Complexity UI (Step-8)
        NES-9750: Verify all type of login notifications are displayed

        Steps:
        1. Navigate to “Password Mgmt” page under Settings.
        2. Toggle on ‘Login Notification’ feature.
        3. Click “Save” button and verify success notification as “Password setting updated successfully.”
        4. Logout the current user and login with invalid credentials.
        5. Again login with valid credentials.
        6. After login verify it shows you every login attempts information.
        7. Verify vice-verse when feature is turned off.

        Scenarios Tested:
        [x] Verified that notification is displayed on top and in bell icon for all type of notifications
        """
        passwords_to_login = ['test', '123456', 'admin1111']

        try:
            self.navigate_to_password_management_page_and_modify_settings(modify_settings=True,
                                                                          settings_details=test_data)
            notification = Notifications()

            assert notification.successes[-1] == Messages.NotificationMessages.PasswordManagement. \
                settings_updated, 'Success notifications for saved setting is mismatched or missing.'

            UserMenu().logout()
            login_page = LoginPage()

            for password_attempts in passwords_to_login:
                login_page.login_with_credentials(username=Config.CAT_USERNAME, password=password_attempts)

                assert notification.errors[-1] == Messages.NotificationMessages.Users.invalid_credentials, \
                    'Error notifications for invalid credentials is mismatched or missing.'

            login_page.login_with_defaults()
            header_base_page = HeaderBasePage()
            wait(lambda: visibility_of_element_located(header_base_page.scan_link),
                 waiting_for='Page gets load properly.')

            if test_data.get('login_notification'):
                assert visibility_of_element_located(notification.results), 'Login notifications not found.'
            else:
                assert invisibility_of_element_located((By.CSS_SELECTOR, '#notifications > div.notification')
                                                       )(get_driver_no_init()), "Login notifications found."

            NotificationActions().remove_all()
            wait(lambda: invisibility_of_element_located(notification.errors),
                 waiting_for='Notification messages gets removed.')

            notifications_dict = header_base_page.get_all_notifications_from_notification_box()
            header_base_page.notification_box_close_button.click()
            wait(lambda: visibility_of_element_located(locator=ScansPage().new_scan_button),
                 waiting_for='Notification history box gets closed.')

            if test_data.get('login_notification'):
                assert len(notifications_dict['Error']) == len(passwords_to_login) and \
                       all([True if Messages.NotificationMessages.failed_to_login in notification_error else False
                            for notification_error in notifications_dict['Error']]), 'No previous login ' \
                                                                                     'notifications found'
            else:
                assert len(notifications_dict['Error']) == 0 and len(notifications_dict['Success']) == 0, \
                    'Previous login notifications found.'
        finally:
            self.__class__.set_pwd_mgmt_settings_to_default()

    @pytest.mark.parametrize("create_users", [{"user_details": {"System Administrator": {
        'user_name': random_name(prefix='{} - '.format(API.User.Users.SYS_ADMIN_USER)), 'full_name': 'SysAdmin user',
        'email': API.User.Users.TEST_EMAIL, 'password': 'SysAdmin_P@ssw0rd', 'role': API.User.Role.SYS_ADMIN}},
        'unique_username': True, 'check_login': False}], indirect=True)
    @pytest.mark.parametrize('test_data', [{'password_complexity': True, 'max_login_attempts': 3,
                                            'min_passwd_length': 8}])
    def test_exceeding_max_login_attempts_locked_current_user_account(self, create_users, test_data):
        """
        Test to verify max login attempt feature locked out your account if you exceeds its count of login
        with invalid credentials.
        #NQA-1191: Test Password Complexity UI (Step-9)
        1. Navigate to “Password Mgmt” page under Settings.
        2. Set ‘max login attempt’ count as 3.
        3. Click “Save” button and verify success notification.
        4. Logout current user.
        5. Login with invalid credentials for greater than set count times (e.g. 3+1=4).
        6. Verify error notification as “Account Locked out.” When you try to login
            after exceeding ‘max login attempts’.
        """
        user_name = create_users.get(API.User.Role.SYS_ADMIN).get('user_name')
        password = create_users.get(API.User.Role.SYS_ADMIN).get('password')

        user_menu = UserMenu()
        user_menu.logout()
        login_page = LoginPage()
        wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)

        login_page.login_with_credentials(username=user_name, password=password)

        try:
            self.__class__.navigate_to_password_management_page_and_modify_settings(modify_settings=True,
                                                                                    settings_details=test_data)
            notification = Notifications()

            assert notification.successes[-1] == Messages. \
                NotificationMessages.PasswordManagement.settings_updated, \
                "Success notifications for password settings updated is mismatched or missing."

            wait(lambda: len(notification.successes) == 0, waiting_for='Notification list to clear.')
            user_menu.logout()

            for attempts in range(0, test_data.get('max_login_attempts') + 1):
                login_page.login_with_credentials(username=user_name, password=password[0:4])

                if attempts == test_data.get('max_login_attempts'):
                    assert notification.errors[-1] == Messages.NotificationMessages.PasswordManagement. \
                        max_login_attempts_error, "Error notifications for locked account after exceeding max " \
                                                  "login limit is mismatched or missing."
                else:
                    assert notification.errors[-1] == Messages.NotificationMessages.Users.invalid_credentials, \
                        "Error notifications for invalid credentials is mismatched or missing."
        finally:
            self.__class__.set_pwd_mgmt_settings_to_default()

    @pytest.mark.skip(reason="Skipping as it causes remaining tests to fail.")
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('test_data', [{'password_complexity': False, 'session_timeout': 2}])
    def test_session_timeout_from_password_management_page(self, test_data):
        """
        Test to verify “Session Timeout” feature allow the user to expire the current session
        after saved value against “Session Timeout” feature over any saved advanced settings of product.
        #NQA-1191: Test Password Complexity UI (Step-7)
        1. Navigate to “Password Mgmt” page under Settings.
        2. Set ‘Session Timeout’ value in minutes (e.g. 2 min).
        3. Click “Save” button and verify success notification as “Password setting updated successfully.”
        4. Logout the current user and login again.
        5. Verify your current session gets expire and shows error notification as “Session expired”
            after waiting for set minutes against ‘Session Timeout’ feature
        """
        try:
            self.__class__.navigate_to_password_management_page_and_modify_settings(modify_settings=True,
                                                                                    settings_details=test_data)
            notification = Notifications()

            assert notification.successes[-1] == Messages. \
                NotificationMessages.PasswordManagement.settings_updated, \
                "Success notifications for password settings updated is mismatched or missing."

            with polling_ui():
                stop_nessus()
                start_nessus()
                wait_for_scanner_to_be_ready(api=self.cat.api)

            get_driver_no_init().refresh()
            wait(lambda: visibility_of_element_located(LoginPage().username_field))

            login_page = LoginPage()
            login_page.login_with_defaults()
            sleep(sleep_time=TIME_TWO_MINUTES, reason='Waiting for session to gets expire.')

            assert notification.errors[-1] == Messages.NotificationMessages.Users.session_expired, \
                "Error notifications for session expired is mismatched or missing."

            wait(lambda: visibility_of_element_located(login_page.username_field), waiting_for="Login Page",
                 timeout_seconds=TIME_TEN_SECONDS)
        finally:
            self.__class__.set_pwd_mgmt_settings_to_default()
