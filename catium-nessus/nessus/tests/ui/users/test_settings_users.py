""""
Nessus test cases related to Settings-> Users

:copyright: Tenable Network Security, 2017
:date: February 26, 2018
:last_modified: Aug 23, 2022
:author: @mameta, @jchavda, @kpanchal, @krpatel, @sacharya
"""
import random
import re
import time

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.const import WAIT_NORMAL, WAIT_SHORT, TIME_THREE_SECONDS
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS, TIME_THIRTY_MINUTES, TIME_SIXTY_SECONDS, \
    TIME_FIVE_MINUTES, TIME_NINETY_SECONDS, TIME_TEN_SECONDS
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessus_ui.settings import login_helper_after_server_restart, handle_connection_popup
from nessus.helpers.nessuscli import fetch
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.server import expect_http_error
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.config import NessusConfig
from nessus.lib.const import API, random_name
from nessus.lib.const.constants import Nessus, SortOrder
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView, About
from nessus.pageobjects.generic.generic_modals import ActionCloseModal, UnsavedChangesModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.my_account.my_account_page import AccountSettings, APIKeys, GenerateAPIKeysModal
from nessus.pageobjects.plugin_rules.plugin_rules_page import PluginRulesList, PluginRulesPage
from nessus.pageobjects.policies.policies_page import PolicyList
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.pageobjects.users.users_page import UsersPage, NewUserForm, UserList
from nessus.tests.ui.about.test_about_overview_page import close_wizard

log = create_logger()


@pytest.mark.nessus_settings_2
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_legacy
@pytest.mark.usefixtures('login')
class TestUsers:
    """
    Covers Users related test cases
    NQA-1059 : Automation tests for Settings-Users
    NQA-1293 : Automation test for Creating user with different role under users page.
    """

    @staticmethod
    def verify_scan_and_owner_name_in_scan_list(side_nav_element: str, scan_name: str, transfer: bool,
                                                user: str = NessusConfig.CAT_USERNAME) -> None:
        """
        Verifies the scan name and scan owner name in scan list

        :param str side_nav_element: Folder name from side navigation panel
        :param str scan_name: scan name
        :param bool transfer: before/after transfer ownership action
        :param str user: owner name to be verify
        :return: None
        """
        # Click on 'My Scans/All Scans' from side navigation panel
        SideNav().get_sidenav_element(element_name=side_nav_element).click()
        wait(lambda: ScansPage().is_element_present("scan_searchbox"), waiting_for="scans gets loaded")

        scan_list = ScanList()
        scan_list.loaded()

        assert [True for scan in scan_list.get_all_scans() if scan_name in scan.split("\n")], \
            'Admin can not see \'{}\' scan in scan list under \'My Scans/All Scans\''.format(scan_name)

        # Verify the owner name of created scan under 'My Scans/All Scans' before transferring the ownership
        assert scan_list.get_scan_owner_name(scan_name=scan_name) == user, \
            'Getting Incorrect scan owner name, Expected scan owner name should be \'{}\'.'.format(user)

        if side_nav_element == Nessus.Scan.Folder.ALL_SCANS and not transfer:
            # Verify tooltip message of 'User Scan' label displayed next to scan name
            assert scan_list.get_user_scan_tool_tip_text(scan_name=scan_name) == 'Owned by {}'.format(user), \
                'Getting incorrect tooltip message, Expected is \'{}\''.format(user)

    @staticmethod
    def verify_policy_name_in_policy_list(side_nav_element: str, policy_name: str, transfer: bool) -> None:
        """
        Verifies the policy name in policy list

        :param str side_nav_element: Folder name from side navigation panel
        :param str policy_name: policy name
        :param bool transfer: before/after transfer ownership action
        :return: None
        """
        # Click on 'Policies' from side navigation panel
        SideNav().get_sidenav_element(element_name=side_nav_element).click()
        policy_list = PolicyList()
        policy_list.loaded()

        if transfer:
            # Verify admin can see the policy in policy list under 'Policies' after transferring the ownership
            assert policy_name in policy_list.get_all_policies(), \
                'Admin can not see \'{}\' policy in policy list under \'Policies\' after transferring the ' \
                'ownership.'.format(policy_name)
        else:
            # Verify admin can not see the policy in policy list under 'Policies' before transferring the ownership
            assert policy_name not in policy_list.get_all_policies(), \
                'Admin can see \'{}\' policy in policy list under \'Policies\' before transferring the ' \
                'ownership.'.format(policy_name)

    @staticmethod
    def verify_plugin_rule_in_plugin_rule_list(side_nav_element: str, plugin_id: str, transfer: bool) -> None:
        """
        Verifies the plugin rule id in plugin rule list

        :param str side_nav_element: Folder name from side navigation panel
        :param str plugin_id: plugin rule id
        :param bool transfer: before/after transfer ownership action
        :return: None
        """
        # Click on 'Plugin Rules' from side navigation panel
        SideNav().get_sidenav_element(element_name=side_nav_element).click()
        plugin_rule_list = PluginRulesList()

        if transfer:
            # Verify admin can see the plugin rule in plugin rule list under 'Plugin Rules' after transferring
            # the ownership
            assert plugin_id in plugin_rule_list.get_plugin_id(), \
                'Admin can not see \'{}\' plugin rule in plugin rule list under \'Plugin Rules\' after ' \
                'transferring the ownership.'.format(plugin_id)
        else:
            # Verify admin can not see the plugin rule in plugin rule list under 'Plugin Rules' before transferring
            # the ownership
            assert plugin_id not in plugin_rule_list.get_plugin_id(), \
                'Admin can see \'{}\' plugin rule in plugin rule list under \'Plugin Rules\' before ' \
                'transferring the ownership.'.format(plugin_id)

    @pytest.mark.ie
    def test_users_page(self):
        """
        Verify that a user list exists, consisting of a row having role 'System administrator' and name 'admin'.

        Verify 'New User' button exists on top-right corner and on clicking 'New User' button it navigates to url
        having path /settings/users/new
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        assert UserList().get_all_users(), "user list is not available"

        assert "admin" in UserList().get_all_users(), "admin user not available in user list"

        assert UserList().get_user_role('admin') == "System Administrator", \
            "System Administrator role is not available for admin user"

        assert user_page.new_user_button.is_displayed(), "New User button is not visible"

        user_page.new_user_button.click()

        assert '#/settings/users/new' in get_driver_no_init().current_url, 'Current url is incorrect.'

    def test_username_field(self):
        """
        Verify that username is a required field and it must have a required badge, fill all other details,
        click on save button, error should pop-up.
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        new_user_form = NewUserForm()
        user_page.new_user_button.click()

        assert new_user_form.username_field.get_attribute('aria-required'), "username field is not a required field"

        assert new_user_form.required_badge, "required badge is not present on ui"

        new_user_form.fill_user_form(full_name="tenable user", email="test@tenable.com", password="admin")
        notifications = Notifications()

        assert notifications.errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "did not get error message"

    def test_password_field(self):
        """
        Verify that password is a required field and it must have a required badge, fill all other details,
        click on save button, error should pop-up.

        Verify that password field contains a show password eye, on clicking the eye it must get disabled and
        the password entered must become visible
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        new_user_form = NewUserForm()
        user_page.new_user_button.click()

        assert new_user_form.password_field.get_attribute('aria-required'), "password field is not a required field"

        assert new_user_form.required_badge, "not present"

        new_user_form.fill_user_form(user_name="tenable user", full_name="tenable user", email="test@tenable.com")
        notifications = Notifications()

        assert notifications.errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "Notification error message is missing"

        assert new_user_form.password_toggle_eye, "toggle eye is not present on UI"

        new_user_form.password_field.value = "tenable"

        assert new_user_form.password_field.get_attribute('type') == "password", "password is invisible"

        new_user_form.password_toggle_eye.click()
        sleep(WAIT_NORMAL, reason="It takes little bit time to show thw text")

        assert new_user_form.password_field.get_attribute('type') == "text", "password is visible"

    def test_invalid_username(self):
        """
        verify invalid username
        Enter invalid username (say '.') and password, and click on save button, User will not be created and a
        notification will come “Invalid ‘username’ field.”
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        user_page.add_new_user(user_name=".", full_name="tenable user", email="test@tenable.com",
                               password="admin")

        notifications = Notifications()

        assert notifications.errors[-1] == Messages.NotificationMessages.Users.invalid_username, \
            "Notification for invalid username field is missing"

    def test_invalid_email(self):
        """
        verify invalid email
        Enter invalid email say ‘qa@.com’ and click on save button, it should throw an error that
        ‘Error: Please correct all form errors to continue.’
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        user_page.add_new_user(user_name="tenable user", full_name="tenable user", email="qa@.com",
                               password="admin")

        notifications = Notifications()

        assert notifications.errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "Notification for invalid email field is missing"

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.SYS_ADMIN,
                                              'do_login': True}], indirect=True)
    def test_duplicate_username(self, create_user):
        """
        verify duplicate username
        Enter a duplicate username, click on save button, it should throw an error of “Error: Duplicate username”
        """
        username, password = create_user

        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        new_user_form = NewUserForm()
        user_page.new_user_button.click()

        new_user_form.fill_user_form(user_name=username, full_name="admin", email="test@tenable.com",
                                     password=password)

        notifications = Notifications()

        assert notifications.errors[-1] == Messages.NotificationMessages.Users.duplicate_username, \
            "Notification for duplicate username field is missing"

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.STANDARD,
                                              'do_login': False}], indirect=True)
    def test_username_update(self, create_user):
        """
        Click on the user having any role except System Administrator and change its full name,
        user should be updated successfully and log out and log in again with the user just edited, the edited name
        must appear in the top-right corner
        """
        username, password = create_user
        edited_full_name = 'edited standard user'

        user_list = UserList()
        user_list.click_on_user(username)

        account_setting = AccountSettings()
        account_setting.full_name.clear()
        account_setting.full_name.value = edited_full_name
        account_setting.user_edit_save_button.click()

        notifications = Notifications()

        assert notifications.successes[-1] == Messages.NotificationMessages.Users.user_updated, \
            "Notification for updated username is missing"

        NotificationActions().remove_all()
        UserMenu().logout()
        LoginPage().login_with_credentials(username=username, password=password)

        assert HeaderBasePage().user_name_text.text == edited_full_name, \
            "edited name is not appear in the top-right corner"

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.STANDARD,
                                              'do_login': False}], indirect=True)
    def test_password_update(self, create_user):
        """
        Click on already created user, 'Change Password' heading should be present having 'New Password' field.
        Enter a new password and click on save button, user should be updated successfully.
        """
        username, password = create_user
        new_password_value = "p@ssw0rd1234"

        user_list = UserList()
        user_list.click_on_user(username)
        account_setting = AccountSettings()

        assert account_setting.new_password.is_displayed(), "new password field is not available"

        notification_action = NotificationActions()
        notification_action.remove_all()
        account_setting.new_password.value = new_password_value
        account_setting.user_edit_save_button.click()

        notifications = Notifications()

        assert notifications.successes[-1] == Messages.NotificationMessages.Users.user_updated, \
            "Notification for updated password is missing"

        notification_action.remove_all()
        modal_window = UnsavedChangesModal()

        if modal_window.is_element_present('modal') and modal_window.unsaved_changes_title.text == \
                'Regenerate API Keys recommended':
            modal_window.cancel_button.click()
            modal_window.wait_for_modal_closed()

        UserMenu().logout()
        LoginPage().login_with_credentials(username=username, password=new_password_value)
        wait(lambda: ScansPage().is_element_present('title_in_header'),
             waiting_for="My Scans page to load properly", timeout_seconds=TIME_SIXTY_SECONDS)

        assert '#/scans/folders/my-scans' in get_driver_no_init().current_url, \
            'password is not updated, as user can not logged in'

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.STANDARD,
                                              'do_login': False}], indirect=True)
    def test_email_and_role_update(self, create_user):
        """
        verify Update Email and Role fields for an existing user, and verify that data is updated correctly.
        """
        username = create_user[0]
        edit_email = "test@example.in"

        user_list = UserList()
        user_list.click_on_user(username)

        account_setting = AccountSettings()
        account_setting.is_element_present("full_name")
        account_setting.email.value = edit_email
        account_setting.role.select_by_visible_text(API.User.Role.SYS_ADMIN)
        account_setting.user_edit_save_button.click()
        wait(lambda: Notifications().successes[-1], waiting_for="success notification")

        account_setting.back_to_users_link.click()
        sleep(WAIT_NORMAL, reason="It takes little bit time to get content display on page")

        assert user_list.get_user_role(user_name=username) == API.User.Role.SYS_ADMIN, \
            "role did not updated for created user"

        user_list.click_on_user(username)
        account_setting.is_element_present("full_name")

        assert account_setting.email.get_attribute('value') == edit_email, "email not updated"

    @pytest.mark.parametrize("create_user", [{'username': API.User.Users.SYS_ADMIN_USER, 'password': 'password',
                                              'role': API.User.Role.SYS_ADMIN, 'do_login': True}], indirect=True)
    def test_sys_admin_user(self, create_user):
        """
        Log in as a different System Administrator, and verify the currently logged in user cannot be deleted,
        but the original admin can be deleted.
        """
        username = create_user[0]

        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        user_list = UserList()

        # verify removed icon is not available for logged in user
        assert invisibility_of_element_located(
            user_list.get_specific_user_remove(username=API.User.Users.SYS_ADMIN_USER)), \
            "Remove icon is visible for logged in user."

        # verify removed icon is available for actual admin user
        assert user_list.get_specific_user_remove(username=NessusConfig.CAT_NESSUS_USERNAME).is_displayed(), \
            "remove button is not available for actual admin user"

        user_list.click_on_user(user_name=username)

        assert '#/settings/my-account' in get_driver_no_init().current_url, \
            'Current url is incorrect for update the current user info'

    @pytest.mark.ie
    def test_user_filter(self):
        """
        Verify Search user box is present at the top of the list and just next to the box are present the total
        number of users in the list.

        Enter any role in the search box and verify it shows ‘No result found’, searching is available only
        on the name field.
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        assert user_page.search_box.is_displayed(), "search box is not available for users page"

        assert user_page.total_user_record.is_displayed(), "total number of user count box is not " \
                                                           "present for users page"

        user_page.search_box.value = API.User.Role.SYS_ADMIN
        wait(lambda: user_page.is_element_present("search_user_result"))

        for user_data_row in UserList().rows:
            assert API.User.Role.SYS_ADMIN in user_data_row.text, \
                "Unable to search user from available users using it's role."

    @pytest.mark.parametrize("create_user", [
        {'username': API.User.Users.BASIC_USER, 'password': 'admin1234', 'role': API.User.Role.BASIC,
         'do_login': True, 'unique_username': True},
        {'username': API.User.Users.STANDARD_USER, 'password': 'admin1234', 'role': API.User.Role.STANDARD,
         'do_login': True, 'unique_username': True}], indirect=True)
    def test_verify_setting_page_for_non_admin_user(self, create_user):
        """
        NES-10648 - Verify setting page loads properly for Basic and standard user created on Nessus Manager

        Scenario Tested:
            [x] Verify setting page loads properly for Basic and standard user created on Nessus Manager

        Steps:
        1. Login to Nessus.
        2. Create user with basic/standard role
        3. Login with new user created above
        4. Verify settings page loads properly with basic details of plugins and nessus version.
        5. Logout from Nessus
        """
        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('plugins_labels'), timeout_seconds=10)

        assert visibility_of_element_located((overview_page.overview_tab.we_by,
                                              overview_page.overview_tab.we_value))(get_driver_no_init()), \
            "Overview tab is invisible for non-admin user"

        plugins_labels = overview_page.get_about_page_labels(element=overview_page.plugins_labels)

        assert Nessus.About.NON_ADMIN_USER_PLUGINS_LABELS == plugins_labels, \
            "Plugins labels are missing or incorrect for non-admin user."

        product_labels = overview_page.get_about_page_labels(element=overview_page.product_labels)

        assert Nessus.About.NON_ADMIN_USER_NM_LABLES == product_labels, \
            "Product labels are missing or incorrect for created non-admin user."

    @pytest.mark.xray(test_key='NES-13982')
    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.ADMIN_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.ADMIN,
                                              'do_login': True}], indirect=True)
    def test_user_cannot_claim_data_of_higher_authority(self, create_user):
        """
        NES-13982 : Verify that user can’t claim or transfer the data manually of its higher authority
        """
        users_page = UsersPage()
        users_page.open()
        users_list = UserList()
        wait(lambda: users_list.loaded(), timeout_seconds=WAIT_SHORT, waiting_for='waiting for all users to get loaded')

        assert eval(users_list.get_admin_sys_admin_checkbox_element(permission=API.User.Role.SYS_ADMIN).
                    get_attribute(
            'aria-disabled').capitalize()), f'For administrator user, Checkbox of {API.User.Role.SYS_ADMIN} is enabled'


@pytest.mark.nessus_settings_2
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login', 'delete_all_scans_in_nessus')
class TestUsersOnNessusManager:
    """
    test users related tests on Nessus Manager
    """
    test_data = {
        "user_details": {"Basic": {'user_name': random_name(prefix=API.User.Users.BASIC_USER + ' - '),
                                   'full_name': 'Basic user', 'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                   'role': API.User.Role.BASIC},
                         "Standard": {'user_name': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                      'full_name': 'Standard user', 'email': API.User.Users.TEST_EMAIL,
                                      'password': 'admin', 'role': API.User.Role.STANDARD},
                         "Administrator": {'user_name': random_name(prefix=API.User.Users.ADMIN_USER + ' - '),
                                           'full_name': 'Admin user', 'email': API.User.Users.TEST_EMAIL,
                                           'password': 'admin', 'role': API.User.Role.ADMIN},
                         "System Administrator": {'user_name': random_name(prefix=API.User.Users.
                                                                           SYS_ADMIN_USER + ' - '),
                                                  'full_name': 'SysAdmin user', 'email': API.User.Users.TEST_EMAIL,
                                                  'password': 'admin', 'role': API.User.Role.SYS_ADMIN}},
        'unique_username': True, "check_login": False}

    @staticmethod
    def validate_time_format(login_time: str) -> bool:
        """
        This function will validate the format of given login time

        :param str login_time: login time in HH:mm format
        :return: True if valid format else False
        :rtype: bool
        """
        return bool(re.search(re.compile("^([01]?[0-9]):[0-5][0-9]$"), login_time)) if login_time else False

    @pytest.mark.ie
    def test_users_roles(self):
        """
        For 'Nessus Manager', it contains four types of role(System Administrator, Admin, Basic, Standard)
        with Standard as default
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        new_user_form = NewUserForm()
        user_page.new_user_button.click()

        assert API.User.Role.ROLE_LIST_MANAGER == new_user_form.get_user_role_options(), \
            "all the options are not available in role"

        assert new_user_form.role_dropdown.text == API.User.Role.STANDARD, \
            "role value is not set 'Standard' by default"

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_multiple_users_in_user_list(self, create_users):
        """
        Create all allowed types of users by providing data into required fields and
        verify that the users are created successfully
        """
        wait(lambda: UsersPage().is_element_present("search_box"), waiting_for="User page get loaded")
        users = UserList().get_all_users()

        for user in create_users.keys():
            assert create_users.get(user).get('user_name') in users, \
                "User type" + create_users.get(user).get('user_name') + "is not created"

    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix=API.User.Users.BASIC_USER + ' - '), 'full_name': 'Basic user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.BASIC, 'do_login': False},
        {'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '), 'full_name': 'Standard user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.STANDARD, 'do_login': False}],
                             indirect=True)
    def test_visibility_of_users_tab(self, create_user):
        """
        verify Log out from the system and Login with Standard user credentials, user must not see the Users tab
        under settings Account
        """
        username, password = create_user

        UserMenu().logout()
        LoginPage().login_with_credentials(username=username, password=password)
        HeaderBasePage().settings_link.click()

        assert 'Users' not in SideNav().get_all_sidenav_links(), \
            "users tab is available in side navigation for standard user"

    @pytest.mark.xray(test_key='NES-13792')
    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix=API.User.Users.BASIC_USER + ' - '), 'full_name': 'Basic user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.BASIC, 'do_login': False},
        {'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '), 'full_name': 'Standard user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.STANDARD, 'do_login': False}],
                             indirect=True)
    def test_visibility_of_about_and_notification_tab(self, create_user):
        """
        NES-13792 :For Basic/standard user, verify that only "About/notifications" tab should be visible on sidebar
        under settings sid nav header.
        """
        username, password = create_user
        UserMenu().logout()
        LoginPage().login_with_credentials(username=username, password=password)
        HeaderBasePage().settings_link.click()

        available_settings = ['About', 'Notifications']

        assert set(available_settings).issubset(SideNav().get_all_sidenav_links())

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.ADMIN_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.ADMIN, 'do_login': True}],
                             indirect=True)
    def test_administrator_user(self, create_user):
        """
        Log in with Administrator (not System Administrator) user, and verify:
        User can see the Users tab, and view list of all users
        """
        HeaderBasePage().settings_link.click()
        side_nav = SideNav()

        assert 'Users' in side_nav.get_all_sidenav_links(), \
            "users tab is not available in side navigation for administrator user"

        side_nav.click_by_link_text(Nessus.Accounts.USERS)

        assert UserList().get_all_users(), "user list is not available for administrator user"

    @pytest.mark.parametrize("create_user", [{'username': API.User.Users.ADMIN_USER, 'password': 'password',
                                              'role': API.User.Role.ADMIN, 'do_login': True}], indirect=True)
    def test_create_edit_and_delete_users(self, create_user):
        """
        verify:
        1. User can edit or delete all users except System Administrators.
        2. User can create new users, but not with a System Administrator role.
        3. when editing a user, the System Administrator role is not shown.
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        user_list = UserList()
        account_setting = AccountSettings()

        user_details = {"Basic": {'user_name': random_name(prefix=API.User.Users.BASIC_USER + ' - '),
                                  'password': "admin", 'role': API.User.Role.BASIC},
                        "Standard": {'user_name': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                     'password': "admin", 'role': API.User.Role.STANDARD},
                        "Administrator": {'user_name': random_name(prefix=API.User.Users.ADMIN_USER + ' - '),
                                          'password': "admin", 'role': API.User.Role.ADMIN}}

        for user in user_details:
            username = user_details.get(user).get('user_name')
            user_page.add_new_user(user_name=username,
                                   password="admin",
                                   role=user_details.get(user).get('role'))

            notifications = Notifications()

            assert notifications.successes[-1] == Messages.NotificationMessages.Users.create_user, \
                "Notification for create user is missing"

            NotificationActions().remove_all()
            UserList().click_on_user(username)

            account_setting.email.value = 'test@tenable.com'
            account_setting.user_edit_save_button.click()

            assert notifications.successes[-1] == Messages.NotificationMessages.Users.user_updated, \
                "Notification for edit user is missing"

            SideNav().click_by_link_text(Nessus.Accounts.USERS)
            user_list.delete_user(username)

            assert username not in user_list.get_all_users(), \
                "user is still available in user list"

    @pytest.mark.xray(test_key='NES-14139')
    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix=API.User.Users.BASIC_USER + ' - '), 'full_name': 'Basic user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.BASIC, 'do_login': False},
        {'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '), 'full_name': 'Standard user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.STANDARD, 'do_login': False},
        {'username': random_name(prefix=API.User.Users.ADMIN_USER + ' - '), 'full_name': 'Admin user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.ADMIN, 'do_login': False}],
                             indirect=True)
    def test_visibility_of_encryption_password_and_software_update_tab(self, create_user):
        """
        NES-14139 : For Basic/standard/administrator user, verify that user can not see "Encyption password/Software update"
        """
        username, password = create_user

        UserMenu().logout()
        LoginPage().login_with_credentials(username=username, password=password)

        about_page = About()
        about_page.open()

        # verify Encryption password tab is not visible
        assert not about_page.is_element_present('encryption_password_tab')

        # verify Software update tab is not visible
        assert not about_page.is_element_present('software_update_tab')

    def test_create_delete_sys_admin_user(self):
        """
        Verify admin user cannot create and delete user which have System Administrator role

        NES-9768: UI Automation: Users | Verify that admin user(default) can't be removed

        Scenario Tested:
        [x] Verify that admin user(default) can't be removed from UI i.e. it can't be selected like other users.
        """
        admin_username = random_name(prefix=API.User.Users.ADMIN_USER + ' - ')
        sys_admin_username = random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - ')
        password = "admin"
        user_page = UsersPage()
        user_page.open()

        user_details = {"System Administrator": {'user_name': sys_admin_username, 'password': password,
                                                 'role': API.User.Role.SYS_ADMIN},
                        "Administrator": {'user_name': admin_username, 'password': password,
                                          'role': API.User.Role.ADMIN}}

        for user in user_details:
            username = user_details.get(user).get('user_name')
            user_page.add_new_user(user_name=username,
                                   password=password,
                                   role=user_details.get(user).get('role'))

        for user in [admin_username, sys_admin_username]:
            UserMenu().logout()
            LoginPage().login_with_credentials(username=user, password=password)

            user_page.open()
            wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")
            user_page.new_user_button.click()

            new_user_form = NewUserForm()
            new_user_form.username_field.value = sys_admin_username
            new_user_form.password_field.value = password

            if user == admin_username:
                assert "System Administrator" not in new_user_form.get_user_role_options(), \
                    "System Administrator role is available for administrator account."
            else:
                assert "System Administrator" in new_user_form.get_user_role_options(), \
                    "System Administrator role is available for system administrator account."

            SideNav().click_by_link_text(Nessus.Accounts.USERS)
            wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")
            user_list = UserList()

            if user == admin_username:
                assert invisibility_of_element_located(user_list.get_specific_user_remove(
                    username=sys_admin_username)), 'For system administrator user, Remove icon is visible to ' \
                                                   'administrator user.'

                assert invisibility_of_element_located(user_list.get_specific_user_remove(
                    username=user)), 'For administrator user, Remove icon is visible to administrator user.'

                assert eval(user_list.get_admin_sys_admin_checkbox_element(permission=API.User.Role.ADMIN).
                            get_attribute('aria-disabled').capitalize()), 'For administrator user, Checkbox is ' \
                                                                          'selectable.'
            else:
                assert invisibility_of_element_located(user_list.get_specific_user_remove(username=user)), \
                    'For system administrator user, Remove icon is visible to system administrator user.'

                assert user_list.get_specific_user_remove(username=admin_username).is_displayed(), \
                    "For administrator user, Remove icon is not visible to system administrator user."

                assert eval(user_list.get_admin_sys_admin_checkbox_element(permission=API.User.Role.SYS_ADMIN).
                            get_attribute('aria-disabled').capitalize()), 'For system administrator user, Checkbox ' \
                                                                          'is selectable.'

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_select_all_users(self, create_users):
        """
        Click on select-all checkbox. Delete button must appear at the top with the New User button.
        Click on the Delete button and verify the confirmation pop-up. Click 'Cancel' on the pop-up and verify
        the users are not deleted. Repeat, clicking 'Delete' and the confirmation popup, and verify all the
        users except admin user are deleted.
        """
        user_page = UsersPage()
        user_page.select_all_checkbox.click()
        user_list = UserList()

        assert user_page.delete_button.is_enabled(), "delete button is disabled for all selected users"

        user_page.delete_button.click()
        action_close_modal = ActionCloseModal()

        assert action_close_modal.modal.is_displayed(), \
            'confirmation pop is not displayed after clicking on delete button'

        action_close_modal.cancel_button.click()
        users = user_list.get_all_users()

        for user in create_users.keys():
            assert create_users.get(user).get('user_name') in users, \
                "User type " + create_users.get(user).get('user_name') + " is not created"

    current_epoch = str(int(time.time()))
    basic_username = current_epoch + '-' + API.User.Users.BASIC_USER
    standard_username = current_epoch + '-' + API.User.Users.STANDARD_USER

    @pytest.mark.parametrize("create_users", [
        {"user_details": {"Basic": {'user_name': basic_username, 'full_name': 'Basic user',
                                    'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                    'role': API.User.Role.BASIC},
                          "Standard": {'user_name': standard_username, 'full_name': 'Standard user',
                                       'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                       'role': API.User.Role.STANDARD},
                          "Administrator": {'user_name': random_name(prefix=API.User.Users.ADMIN_USER + ' - '),
                                            'full_name': 'Admin user', 'email': API.User.Users.TEST_EMAIL,
                                            'password': 'admin', 'role': API.User.Role.ADMIN},
                          "System Administrator": {'user_name': random_name(prefix=API.User.Users.
                                                                            SYS_ADMIN_USER + ' - '),
                                                   'full_name': 'SysAdmin user', 'email': API.User.Users.TEST_EMAIL,
                                                   'password': 'admin', 'role': API.User.Role.SYS_ADMIN}},
         "check_login": False}], indirect=True)
    def test_search_user(self, create_users):
        """
        Enter any substring from the user, and verify that the list shows all the users that contain substring
        entered and count also gets updated next to search box.
        """
        user_page = UsersPage()
        user_page.search_box.value = self.current_epoch
        user_list = UserList().get_all_users()

        assert len(user_list) == int(user_page.search_user_result.text), \
            "Count did not get updated after searching substring"

        assert [self.basic_username, self.standard_username] == user_list, \
            "searched users are not in user list"

    @pytest.mark.xray(test_key='NES-15357')
    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_sort_user_list_by_available_columns(self, create_users, sort):
        """
        NES-13104 [Automation]: Verify that user is able to sort the details with available columns
        NES-15357 : Verify that users are able to sorted by 'Last login'

        Scenario Tested:
        [x] Verify that 'Names', 'Roles' and 'Last Login' under list are present in ascending order and on clicking
            the columns list will get change to descending order.
        [x] Verify that 'Last login' value should be display in correct date format like 'Today at 4.40 PM'.
        """
        user_menu = UserMenu()
        login_page = LoginPage()

        for user_role in [API.User.Role.STANDARD, API.User.Role.SYS_ADMIN, API.User.Role.ADMIN, API.User.Role.BASIC]:
            user_menu.logout()
            wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)

            user_name, password = create_users[user_role]["user_name"], create_users[user_role]["password"]
            login_page.login_with_credentials(username=user_name, password=password)

            NotificationActions().remove_all()
            sleep(TIME_SIXTY_SECONDS, reason="Waiting for 1 min after user login to get the different login time.")

        user_menu.logout()
        login_page.login_with_defaults()
        user_menu.loaded()

        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        column_mapping = {"Name": "name", "Role": "user_role", "Last Login": "users_last_login"}
        users_list = UserList()
        users_list.loaded()

        for user_role in [API.User.Role.STANDARD, API.User.Role.SYS_ADMIN, API.User.Role.ADMIN, API.User.Role.BASIC]:
            login_time = users_list.get_last_login_time_of_users(user_name=create_users[user_role]["user_name"])[0]

            assert all(["Today at" in login_time, self.validate_time_format(login_time=login_time.split()[2])]), \
                "Last login time is missing or mismatched due to invalid format."

        for column_to_sort in ["Name", "Role", "Last Login"]:
            map_attribute = column_mapping[column_to_sort]
            users_list.loaded()

            expected_users_list = sorted([getattr(user, map_attribute) for user in users_list.rows],
                                         key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

            rendered_users_list = sort_on_column_values(page_class_instance=users_list, column_name=column_to_sort,
                                                        sort=sort)

            assert expected_users_list == [getattr(user, map_attribute) for user in rendered_users_list], \
                "'{}' column values are not properly sorted in '{}' order".format(column_to_sort, sort)

    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix=API.User.Users.BASIC_USER + ' - '), 'full_name': 'Basic user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.BASIC, 'do_login': False},
        {'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '), 'full_name': 'Standard user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.STANDARD, 'do_login': False},
        {'username': random_name(prefix=API.User.Users.ADMIN_USER + ' - '), 'full_name': 'Admin user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.ADMIN, 'do_login': False},
        {'username': random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - '), 'full_name': 'SysAdmin user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.SYS_ADMIN, 'do_login': False}],
                             indirect=True)
    def test_api_key_generation_for_users(self, create_user):
        """
        Create all types of users and Verify that User list is updated. Perform below steps for all the users created.
        a. Click on each created user and Verify that the ‘API Keys’ tab exist.
        b. Click on ‘Generate’ button and Verify that a pop-up appears having title ‘Generate API Keys’,
        accept it and Verify that ‘Access Key’ and ‘Secret Key’ Exist.
        c. Click on ‘back to Users’ link and again on click on the user row and Verify that no ‘Access Key’ and
        ‘Secret Key’ exist. Click on ‘Generate’ button and Verify that ‘admin’ can regenerate the keys.
        """
        username = create_user[0]

        UserList().click_on_user(username)
        account_setting = AccountSettings()

        assert account_setting.api_keys_tab.is_displayed(), "api keys tab is not displayed for user"

        account_setting.api_keys_tab.click()
        api_keys_page = APIKeys()
        wait(lambda: api_keys_page.is_element_present("generate_button"))

        api_keys_page.generate_button.click()
        popup_window = GenerateAPIKeysModal()

        assert popup_window.get_modal_title == 'Generate API Keys', "Popup to generate api keys doesn't came up."

        popup_window.action_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.api_keys_generation, \
            "did not get message for api keys generation"

        handle_connection_popup(timeout_to_appear=TIME_NINETY_SECONDS, timeout_to_disappear=TIME_FIVE_MINUTES)

        assert visibility_of_element_located((api_keys_page.access_key_field.we_by,
                                              api_keys_page.access_key_field.we_value))(get_driver_no_init()), \
            "Access key is invisible."
        assert visibility_of_element_located((api_keys_page.secret_key_field.we_by,
                                              api_keys_page.secret_key_field.we_value))(get_driver_no_init()), \
            "Secret key is invisible."

        account_setting.account_settings_tab.click()
        account_setting.api_keys_tab.click()

        # Navigate back to API Keys, verify keys are not displayed
        assert invisibility_of_element_located((api_keys_page.access_key_field.we_by,
                                                api_keys_page.access_key_field.we_value))(get_driver_no_init()), \
            "Access key is visible."

        assert invisibility_of_element_located((api_keys_page.secret_key_field.we_by,
                                                api_keys_page.secret_key_field.we_value))(get_driver_no_init()), \
            "Secret key is visible."

        account_setting.back_to_users_link.click()

        api_keys_page.open()
        api_keys_page.generate_api_keys()

        assert (api_keys_page.access_key_field.is_displayed()
                and api_keys_page.secret_key_field.is_displayed()), "Access key and secret key not displayed."

        assert (api_keys_page.access_key.isalnum() and api_keys_page.secret_key.isalnum() and
                (len(api_keys_page.access_key) == API.User.API_KEYS_LENGTH) and
                (len(api_keys_page.secret_key) == API.User.API_KEYS_LENGTH)), "Invalid key generated."

        # store the keys
        access_key = api_keys_page.access_key
        secret_key = api_keys_page.secret_key

        # Regenerate the keys and verify they have changed from previous
        api_keys_page.generate_api_keys()

        assert (api_keys_page.access_key_field.is_displayed()
                and api_keys_page.secret_key_field.is_displayed()), "Access key and secret key not displayed."

        assert (api_keys_page.access_key.isalnum() and api_keys_page.secret_key.isalnum() and
                (len(api_keys_page.access_key) == API.User.API_KEYS_LENGTH) and
                (len(api_keys_page.secret_key) == API.User.API_KEYS_LENGTH)), "Invalid key generated."

        assert ((api_keys_page.access_key != access_key)
                and (api_keys_page.secret_key != secret_key)), "Keys did not get changed after regeneration."

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_create_users_with_diff_role(self, create_users):
        """
        NQA-1293 : Automation test for Creating user with different role under users page.
        1. Navigate to 'Users' tab under 'Settings'
        2. Create a new user with 'System Administrator' role and fill all other required fields
        3. Hit 'Save' and verify success notification as 'User created successfully'.
        4. Also verify created user is listed under users_page.
        5. Logout the current user and login with created user
        6. Verify successful login
        7. Repeat above steps for other user roles. (Basic/Standard/Administrator)
        """
        user_details = create_users

        # Verify created user is present in User List.
        users_list = UserList()

        for user in user_details.keys():
            _user = user_details.get(user)
            username = _user.get('user_name')

            assert all([username in users_list.get_all_users(), _user.get('role') == users_list.get_user_role(
                user_name=username)]), 'User is not available in user list'

        user_menu = UserMenu()

        # Verify login by created user.
        for user in user_details.keys():
            user_menu.logout()
            login_page = LoginPage()
            wait(lambda: login_page.is_element_present('username_field'), waiting_for="login page get displayed")

            _user = user_details.get(user)
            login_page.login_with_credentials(username=_user.get('user_name'), password=_user.get('password'))
            user_menu.loaded()

            assert HeaderBasePage().user_name_text.text == _user.get('full_name'), 'Login Failed!'

    @pytest.mark.parametrize('create_users', [test_data], indirect=True)
    def test_visibility_of_transfer_data_button_and_modal(self, create_users):
        """
        NES-9798: [AUTOMATION] UI Test for User Data Transfer

        Scenario Tested:
        [x] Verify that "Transfer Data" button should be displayed on selecting single or multiple users.
        [x] Verify "Transfer User Data" pop-up after clicking on "Transfer Data" button.(for single and multiple users)
        """
        created_users = [create_users.get(user).get('user_name') for user in create_users.keys()]

        user_page = UsersPage()
        user_list = UserList()

        for operation in ['single_user', 'multiple_user']:
            if operation == 'single_user':
                user_list.get_specific_user_checkbox(user_name=created_users[0]).check()
            else:
                for user in created_users:
                    user_list.get_specific_user_checkbox(user_name=user).click()

            assert user_page.is_element_present('transfer_data_button'), \
                '\'Transfer Data\' button is not displayed next to \'Delete\' button after selecting single user.'

            user_page.transfer_data_button.click()
            transfer_data_modal = ActionCloseModal()

            assert transfer_data_modal.is_element_present('modal'), \
                '\'Transfer User Data\' modal is not getting open after clicking on \'Transfer Data\' button.'

            if operation == 'single_user':
                assert transfer_data_modal.modal_title.text == Nessus.SideNavAccounts.Users.TRANSFER_USER_DATA, \
                    'Getting Incorrect modal title, Expected is \'{}\'.'.format(Nessus.SideNavAccounts.Users.
                                                                                TRANSFER_USER_DATA)
            else:
                modal_title_for_multiple_users = 'Transfer Data for {} Users'.format(len(created_users))

                assert transfer_data_modal.modal_title.text == modal_title_for_multiple_users, \
                    'Getting Incorrect modal title, Expected is \'{}\'.'.format(modal_title_for_multiple_users)

            assert transfer_data_modal.modal_content.text == Nessus.SideNavAccounts.Users.TRANSFER_USER_DATA_WARNING, \
                'Getting Incorrect modal content, Expected is \'{}\'.'.format(Nessus.SideNavAccounts.Users.
                                                                              TRANSFER_USER_DATA_WARNING)

            assert all([transfer_data_modal.is_element_present('action_button'),
                        transfer_data_modal.is_element_present('cancel_button')]), \
                '\'Transfer\' and \'Cancel\' button is not present on \'Transfer User Data\' modal.'

            transfer_data_modal.cancel_button.click()
            user_list.select_all_checkbox.click()

    @pytest.mark.parametrize('create_users', [test_data], indirect=True)
    def test_visibility_of_delete_button_and_modal(self, create_users):
        """
        NES-9798: [AUTOMATION] UI Test for User Data Transfer

        Scenario Tested:
        [x] Verify that "Delete" button should be display on selecting single or multiple users.
        [x] Verify "Delete User" pop-up after clicking on "Delete" button.(for single and multiple users)
        """
        created_users = [create_users.get(user).get('user_name') for user in create_users.keys()]

        user_page = UsersPage()
        user_list = UserList()

        for operation in ['single_user', 'multiple_user']:
            if operation == 'single_user':
                user_list.get_specific_user_checkbox(user_name=created_users[0]).check()
            else:
                for user in created_users:
                    user_list.get_specific_user_checkbox(user_name=user).click()

            assert user_page.is_element_present('delete_button'), \
                '\'Delete\' button is not displayed next to \'Transfer Data\' button after selecting single user.'

            user_page.delete_button.click()
            transfer_data_modal = ActionCloseModal()

            assert transfer_data_modal.is_element_present('modal'), \
                '\'Transfer User Data\' modal is not getting open after clicking on \'Transfer Data\' button.'

            if operation == 'single_user':
                assert transfer_data_modal.modal_title.text == Nessus.SideNavAccounts.Users.DELETE_SINGLE_USER, \
                    'Getting Incorrect modal title, Expected is \'{}\'.'.format(Nessus.SideNavAccounts.Users.
                                                                                DELETE_SINGLE_USER)

                assert transfer_data_modal.modal_content.text == Nessus.SideNavAccounts.Users. \
                    DELETE_SINGLE_USER_WARNING, 'Getting Incorrect modal content, Expected is \'{}\'.'. \
                    format(Nessus.SideNavAccounts.Users.DELETE_SINGLE_USER_WARNING)
            else:
                assert transfer_data_modal.modal_title.text == Nessus.SideNavAccounts.Users.DELETE_MULTIPLE_USER, \
                    'Getting Incorrect modal title, Expected is \'{}\'.'.format(Nessus.SideNavAccounts.Users.
                                                                                DELETE_MULTIPLE_USER)

                assert transfer_data_modal.modal_content.text == Nessus.SideNavAccounts.Users. \
                    DELETE_MULTIPLE_USER_WARNING, 'Getting Incorrect modal content, Expected is \'{}\'.'. \
                    format(Nessus.SideNavAccounts.Users.DELETE_MULTIPLE_USER_WARNING)

            assert user_page.is_element_present('transfer_ownership_checkbox'), \
                'Transfer ownership checkbox is not present on \'Delete User\' pop-up.'

            assert user_page.transfer_ownership_checkbox.is_selected(), 'Transfer ownership checkbox is not ' \
                                                                        'selected by Default.'

            assert all([transfer_data_modal.is_element_present('action_button'),
                        transfer_data_modal.is_element_present('cancel_button')]), \
                '\'Delete\' and \'Cancel\' button is not present on \'Transfer User Data\' modal.'

            transfer_data_modal.cancel_button.click()
            user_list.select_all_checkbox.click()

    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix=API.User.Users.ADMIN_USER + ' - '), 'password': 'admin',
         'role': API.User.Role.ADMIN, 'do_login': True, 'unique_username': True},
        {'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '), 'password': 'admin',
         'role': API.User.Role.STANDARD, 'do_login': True, 'unique_username': True}], indirect=True)
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": API.Permissions.Types.SCANNER,
         "scan_name": random_name(prefix=Nessus.TemplateNames.ADVANCED), "target_ip": Nessus.Scan.Target.LOCALHOST}]}],
                             indirect=True)
    def test_transfer_data_ownership_of_single_user(self, create_user, create_scans):
        """
        NES-9798: [AUTOMATION] UI Test for User Data Transfer

        Scenario Tested:
        [x] Verify that scans created by users should be transfer properly to the admin level user after clicking on
            "Transfer Data" button. (For single user only)
        """
        scan_name = create_scans[0]
        created_user = create_user
        scan_list = ScanList()

        # Verify created scan is available in scan list
        assert scan_name in scan_list.get_all_scans(), 'Scan \'{}\' is not created successfully'.format(scan_name)

        # Logout with created user and Login with admin user
        user_menu = UserMenu()
        user_menu.logout()

        login_page = LoginPage()
        wait(lambda: login_page.is_element_present('username_field'), waiting_for="login page get displayed")

        login_page.login_with_defaults()
        wait(lambda: visibility_of_element_located(HeaderBasePage().scan_link), waiting_for='scan list to load')

        # Verify admin can not see the scan in scan list before transferring the ownership
        assert scan_name not in scan_list.get_all_scans(), 'Admin can see \'{}\' scan in scan list under \'My Scans\'' \
                                                           ' before transferring the ownership.'.format(scan_name)

        test_users = TestUsers()
        test_users.verify_scan_and_owner_name_in_scan_list(
            side_nav_element=Nessus.Scan.Folder.ALL_SCANS, scan_name=scan_name, user=created_user[0], transfer=False)

        # Go to 'Settings' tab and click on 'Users' from side navigation panel
        header_page = HeaderBasePage()
        header_page.settings_link.click()
        SideNav().get_sidenav_element(element_name=Nessus.SideNavAccounts.USERS).click()

        # Select created user
        UserList().get_specific_user_checkbox(user_name=created_user[0]).check()

        # Transfer the ownership of user data by clicking on 'Transfer Data' button
        UsersPage().transfer_data_button.click()
        ActionCloseModal().accept_action()

        # Verify success message after transferring the ownership of user data
        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.success_transfer_data, \
            "Success message for transferring user data is mismatched or missing."

        # Go to 'Scans' tab
        header_page.scan_link.click()
        wait(lambda: visibility_of_element_located(ScansPage().scan_searchbox), waiting_for='scan list to load')

        # Verify the owner name of created scan under 'My Scans' after transferring the ownership
        assert scan_list.get_scan_owner_name(scan_name=scan_name) == NessusConfig.CAT_NESSUS_USERNAME, \
            'Getting Incorrect scan owner name, Expected scan owner name should be \'{}\'.'.format(
                NessusConfig.CAT_NESSUS_USERNAME)

        for folder_name in [Nessus.Scan.Folder.MY_SCANS, Nessus.Scan.Folder.ALL_SCANS]:
            test_users.verify_scan_and_owner_name_in_scan_list(side_nav_element=folder_name, scan_name=scan_name,
                                                               transfer=True)

        user_menu.logout()
        wait(lambda: login_page.is_element_present('username_field'), waiting_for="login page get displayed")
        login_page.login_with_credentials(username=created_user[0], password=created_user[1])

        # Verify created user can not see the scan in scan list after transferring the ownership
        assert scan_name not in scan_list.get_all_scans(), \
            '\'{}\' user can see \'{}\' scan in scan list under \'My Scans\' after transferring the ownership.'.format(
                created_user[0], scan_name)

        NotificationActions().remove_all()
        user_menu.logout()
        wait(lambda: login_page.is_element_present('username_field'), waiting_for="login page get displayed")
        login_page.login_with_defaults()

    @pytest.mark.parametrize('create_users', [test_data], indirect=True)
    def test_transfer_scan_policy_plugin_rule_data_ownership_of_multiple_user(self, create_data_for_different_users):
        """
        NES-9798: [AUTOMATION] UI Test for User Data Transfer

        Scenario Tested:
        [x] Verify that scans created by users should be transfer properly to the admin level user after clicking on
            "Transfer Data" button. (For multiple user only)
        """
        # Create data like scan, policy and plugin rule for different users
        user_data = create_data_for_different_users
        users = user_data.keys()

        # Login with default credentials (Admin user)
        LoginPage().login_with_defaults()
        header_page = HeaderBasePage()
        wait(lambda: visibility_of_element_located(header_page.scan_link), waiting_for='scan list to load')

        test_user = TestUsers()

        # Verification before transferring the ownership
        for user in users:
            scan_name = user_data.get(user).get('scan')

            # Verify admin can not see the scan in scan list before transferring the ownership
            assert scan_name not in ScanList().get_all_scans(), \
                'Admin can see \'{}\' scan in scan list under \'My Scans\' before transferring the ownership.'.format(
                    scan_name)

            test_user.verify_scan_and_owner_name_in_scan_list(side_nav_element=Nessus.Scan.Folder.ALL_SCANS,
                                                              scan_name=scan_name, user=user, transfer=False)

            if API.User.Role.ADMIN[:5] == user.split("-")[1].strip():
                policy_name = user_data.get(user).get('policy')
                test_user.verify_policy_name_in_policy_list(side_nav_element=Nessus.SideNavResources.POLICIES,
                                                            policy_name=policy_name, transfer=False)

            if API.User.Role.STANDARD == user.split("-")[1].strip():
                plugin_id = user_data.get(user).get('plugin')
                test_user.verify_plugin_rule_in_plugin_rule_list(side_nav_element=Nessus.SideNavResources.PLUGIN_RULES,
                                                                 plugin_id=str(plugin_id), transfer=False)

        # Go to 'Settings' tab
        header_page.settings_link.click()

        # Click on 'Users' from side navigation panel
        SideNav().get_sidenav_element(element_name=Nessus.SideNavAccounts.USERS).click()
        user_list = UserList()

        # Select all created users
        for user in users:
            user_list.get_specific_user_checkbox(user_name=user).click()

        # Click on "Transfer Data" button
        UsersPage().transfer_data_button.click()
        ActionCloseModal().accept_action()

        # Verify success message after transferring the ownership of user data
        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.success_transfer_data, \
            "Success message for transferring user data is mismatched or missing."

        # Go to 'Scans' tab
        header_page.scan_link.click()
        wait(lambda: visibility_of_element_located(ScansPage().scan_searchbox), waiting_for='scan list to load')

        # Verification after transferring the ownership
        for user in users:
            scan_name = user_data.get(user).get('scan')

            for folder_name in [Nessus.Scan.Folder.MY_SCANS, Nessus.Scan.Folder.ALL_SCANS]:
                test_user.verify_scan_and_owner_name_in_scan_list(side_nav_element=folder_name, scan_name=scan_name,
                                                                  transfer=True)

            if API.User.Role.ADMIN[:5] == user.split("-")[1].strip():
                policy_name = user_data.get(user).get('policy')
                test_user.verify_policy_name_in_policy_list(side_nav_element=Nessus.SideNavResources.POLICIES,
                                                            policy_name=policy_name, transfer=True)

            if API.User.Role.STANDARD == user.split("-")[1].strip():
                plugin_id = user_data.get(user).get('plugin')
                test_user.verify_plugin_rule_in_plugin_rule_list(side_nav_element=Nessus.SideNavResources.PLUGIN_RULES,
                                                                 plugin_id=str(plugin_id), transfer=True)

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_user", [
        {'username': API.User.Users.ADMIN_USER, 'password': 'admin',
         'role': API.User.Role.ADMIN, 'do_login': True, 'unique_username': True},
        {'username': API.User.Users.STANDARD_USER, 'password': 'admin',
         'role': API.User.Role.STANDARD, 'do_login': True, 'unique_username': True}], indirect=True)
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": API.Permissions.Types.SCANNER,
         "scan_name": random_name(prefix=Nessus.TemplateNames.ADVANCED),
         "target_ip": Nessus.Scan.Target.AWS_LINUX_TARGET_1}]}], indirect=True)
    @pytest.mark.parametrize('user_delete', [True, False])
    def test_transfer_data_on_single_user_deletion(self, create_user, create_scans, user_delete):
        """
        NES-9721: UI Automation: User Deletion | Verify that admin user should be offered checkbox to acquire deleted
                  user's data

        Scenario Tested:
        [x] Verify that when an admin deletes a user, the confirmation dialog should offer a checkbox to allow for the
            conditional transfer of the departing user's data to the admins ownership.
        """
        scan_name = create_scans[0]
        created_user = create_user

        # Launch created scan and wait for scan to be completed
        scan_list = ScanList()
        scan_list.loaded()

        with polling_ui():
            scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)

        # Create plugin rule
        plugin_rule = PluginRulesPage()
        plugin_rule.open()
        wait(lambda: plugin_rule.is_element_present("plugin_rule_description"),
             waiting_for="plugin rules page gets loaded properly")

        plugin_id = random.randint(10000, 20000)
        plugin_rule.add_new_plugin_rule(plugin_id=plugin_id, severity=Nessus.Scan.Severity.CRITICAL)

        # Logout with created user and Login with admin user
        user_menu = UserMenu()
        user_menu.logout()
        login = LoginPage()
        login.login_with_defaults()
        header_page = HeaderBasePage()
        wait(lambda: visibility_of_element_located(header_page.scan_link), waiting_for='scan list to load')

        test_users = TestUsers()
        test_users.verify_scan_and_owner_name_in_scan_list(side_nav_element=Nessus.Scan.Folder.ALL_SCANS,
                                                           scan_name=scan_name, user=created_user[0], transfer=False)

        # Go to 'Settings' tab and click on 'Users' from side navigation panel
        header_page.settings_link.click()
        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=Nessus.SideNavAccounts.USERS).click()

        # Select created user
        user_list = UserList()
        user_list.get_specific_user_checkbox(user_name=created_user[0]).check()

        # Transfer the ownership of user data by clicking on 'Delete' button
        user_page = UsersPage()
        user_page.delete_button.click()

        # Check the transfer ownership checkbox if True else uncheck
        if user_delete:
            user_page.transfer_ownership_checkbox.check()
        else:
            user_page.transfer_ownership_checkbox.uncheck()

        # Click on 'Delete' button from 'Delete User' pop-up
        ActionCloseModal().accept_action()

        # Verify success message after deleting user
        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.delete_user, \
            "Success message for deleting user is mismatched or missing."

        # Verify created user is not display in user list after deleting
        assert created_user not in user_list.get_all_users(), 'Created user \'{}\' is not deleted successfully.'. \
            format(created_user[0])

        # Go to 'Scans' tab
        header_page.scan_link.click()
        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
            "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")

        if user_delete:
            # Verify admin can see the scan in scan list under 'My Scans/All Scans' after transferring the
            # ownership of deleted user
            for folder_name in [Nessus.Scan.Folder.MY_SCANS, Nessus.Scan.Folder.ALL_SCANS]:
                test_users.verify_scan_and_owner_name_in_scan_list(side_nav_element=folder_name, scan_name=scan_name,
                                                                   transfer=user_delete)
        else:
            # Verify admin can not see the scan in scan list under 'My Scans' after deleting the user
            assert scan_name not in scan_list.get_all_scans(), \
                'Admin can see \'{}\' scan in scan list under \'My Scans\' after  deleting the user.'.format(scan_name)

            # Click on 'All Scans' from side navigation panel
            side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.ALL_SCANS).click()
            wait(lambda: scan_page.is_element_present('create_a_new_scan_link') or scan_page.is_element_present(
                'scan_searchbox'), waiting_for='All Scan page to load properly')

            # Verify admin can not see the scan in scan list under 'All Scans' after deleting the user
            assert [True for scan in scan_list.get_all_scans() if scan_name not in scan.split("\n")] or not \
                scan_list.get_all_scans(), \
                'Admin can see \'{}\' scan in scan list under \'All Scans\' after deleting the user'.format(scan_name)

        # Verify admin can not see the plugin rule in plugin rule list under 'Plugin Rules' after deleting the user
        test_users.verify_plugin_rule_in_plugin_rule_list(side_nav_element=Nessus.SideNavResources.PLUGIN_RULES,
                                                          plugin_id=str(plugin_id), transfer=user_delete)

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.ALL_SCANS).click()

    @pytest.mark.parametrize('create_users', [
        {"user_details": {"Basic": {'user_name': random_name(prefix=API.User.Users.BASIC_USER + ' - '),
                                    'full_name': 'Basic user', 'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                    'role': API.User.Role.BASIC},
                          "Standard": {'user_name': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                       'full_name': 'Standard user', 'email': API.User.Users.TEST_EMAIL,
                                       'password': 'admin', 'role': API.User.Role.STANDARD},
                          "Administrator": {'user_name': random_name(prefix=API.User.Users.ADMIN_USER + ' - '),
                                            'full_name': 'Admin user', 'email': API.User.Users.TEST_EMAIL,
                                            'password': 'admin', 'role': API.User.Role.ADMIN}},
         'unique_username': True, "check_login": False}], indirect=True)
    @pytest.mark.parametrize('user_delete', [True, False])
    def test_transfer_data_on_multiple_user_deletion(self, create_data_for_different_users, user_delete):
        """
        NES-9721: UI Automation: User Deletion | Verify that admin user should be offered checkbox to acquire deleted
                  user's data

        Scenario Tested:
        [x] Verify that when an admin deletes multiple users, the confirmation dialog should offer a checkbox to allow
            for the conditional transfer of the departing user's data to the admins ownership.
        """
        # Create data like scan, policy and plugin rule for different users
        user_data = create_data_for_different_users
        users = user_data.keys()

        # Login with default credentials (Admin user)
        LoginPage().login_with_defaults()
        header_page = HeaderBasePage()
        wait(lambda: visibility_of_element_located(header_page.scan_link), waiting_for='scan list to load')

        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
            "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")

        test_user = TestUsers()
        side_nav = SideNav()
        scan_list = ScanList()

        # Verification before transferring the ownership
        for user in users:
            scan_name = user_data.get(user).get('scan')

            side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

            # Verify admin can not see the scan in scan list before transferring the ownership
            assert scan_name not in scan_list.get_all_scans(), \
                'Admin can see \'{}\' scan in scan list under \'My Scans\' before transferring the ownership.'.format(
                    scan_name)

            test_user.verify_scan_and_owner_name_in_scan_list(side_nav_element=Nessus.Scan.Folder.ALL_SCANS,
                                                              scan_name=scan_name, user=user, transfer=False)

            if API.User.Role.ADMIN[:5] == user.split("-")[1].strip():
                policy_name = user_data.get(user).get('policy')
                test_user.verify_policy_name_in_policy_list(side_nav_element=Nessus.SideNavResources.POLICIES,
                                                            policy_name=policy_name, transfer=False)

            if API.User.Role.STANDARD == user.split("-")[1].strip():
                plugin_id = user_data.get(user).get('plugin')
                test_user.verify_plugin_rule_in_plugin_rule_list(side_nav_element=Nessus.SideNavResources.PLUGIN_RULES,
                                                                 plugin_id=str(plugin_id), transfer=False)

        # Go to 'Settings' tab and click on 'Users' from side navigation panel
        header_page.settings_link.click()
        side_nav.get_sidenav_element(element_name=Nessus.SideNavAccounts.USERS).click()
        user_list = UserList()

        # Select all created users
        for user in users:
            user_list.get_specific_user_checkbox(user_name=user).click()

        # Transfer the ownership of user data by clicking on 'Delete' button
        NotificationActions().remove_all()
        user_page = UsersPage()
        user_page.delete_button.click()

        # Check the transfer ownership checkbox if True else uncheck
        if user_delete:
            user_page.transfer_ownership_checkbox.check()
        else:
            user_page.transfer_ownership_checkbox.uncheck()

        # Click on 'Delete' button from 'Delete User' pop-up
        ActionCloseModal().accept_action()
        notification = Notifications()

        # Verify success message after deleting user
        assert notification.successes[-1] == Messages.NotificationMessages.Users.delete_bulk_user, \
            "Success message for deleting user is mismatched or missing."

        # Verify created users are not displayed in user list after deleting
        assert all([user not in user_list.get_all_users() for user in users]), 'Created user \'{}\' is not deleted ' \
                                                                               'successfully.'.format(users)

        # Go to 'Scans' tab
        header_page.scan_link.click()

        for user in users:
            scan_name = user_data.get(user).get('scan')

            for folder_name in [Nessus.Scan.Folder.MY_SCANS, Nessus.Scan.Folder.ALL_SCANS]:
                if user_delete:
                    test_user.verify_scan_and_owner_name_in_scan_list(side_nav_element=folder_name, scan_name=scan_name,
                                                                      transfer=user_delete)
                else:
                    # Click on 'My Scans' from side navigation panel
                    side_nav.get_sidenav_element(element_name=folder_name).click()
                    scan_page.loaded()

                    # Verify admin can not see the scan in scan list under 'My Scans/All Scans' after deleting the user
                    assert scan_name not in ScanList().get_all_scans(), \
                        'Admin can see \'{}\' scan in scan list under \'{}\' after deleting the user'.format(
                            scan_name, folder_name)

            if API.User.Role.ADMIN[:5] == user.split("-")[1].strip():
                policy_name = user_data.get(user).get('policy')
                test_user.verify_policy_name_in_policy_list(side_nav_element=Nessus.SideNavResources.POLICIES,
                                                            policy_name=policy_name, transfer=user_delete)

            if API.User.Role.STANDARD == user.split("-")[1].strip():
                plugin_id = user_data.get(user).get('plugin')
                test_user.verify_plugin_rule_in_plugin_rule_list(side_nav_element=Nessus.SideNavResources.PLUGIN_RULES,
                                                                 plugin_id=str(plugin_id), transfer=user_delete)

    @pytest.mark.xray(test_key='NES-14512')
    @pytest.mark.xray(test_key='NES-14116')
    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix=API.User.Users.BASIC_USER + ' - '), 'full_name': 'Basic user',
         'email': API.User.Users.TEST_EMAIL, 'password': 'admin', 'role': API.User.Role.BASIC, 'do_login': False}],
                             indirect=True)
    def test_verify_basic_user_can_not_create_plugin_rule_policies_custom_reports(self, create_user):
        """
        NES-14116: Verify that Basic user can not create plugin rule
        NES-14512 :Verify that Basic user can not create policy

        Scenario Tested:
        [x] Verify that basic user can not create plugin rule.
        """
        username, password = create_user

        UserMenu().logout()
        LoginPage().login_with_credentials(username=username, password=password)

        options_not_to_be_shown = [Nessus.SideNavResources.POLICIES, Nessus.SideNavResources.PLUGIN_RULES,
                                   Nessus.SideNavResources.CUSTOMIZED_REPORTS]

        assert all([side_nav_option not in SideNav().get_all_sidenav_links() for side_nav_option in
                    options_not_to_be_shown]), "One of the option from '{}' is visible in side navigation for " \
                                               "basic user".format(options_not_to_be_shown)

    @pytest.mark.xray(test_key='NES-14367')
    @pytest.mark.xray(test_key='NES-14364')
    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.STANDARD,
                                              'do_login': True},
                                             {'username': random_name(prefix=API.User.Users.ADMIN_USER + ' - '),
                                              'password': 'password', 'role': API.User.Role.ADMIN,
                                              'do_login': True}
                                             ], indirect=True)
    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB}], indirect=True)
    def test_check_scan_owner_column(self, create_user, create_scan):
        """
        NES-14364 : Verify that Owner column name should be displayed for only sys admin user
        NES-14367 : Verify new column name(Owner) should be displayed on UI while multiuser existed in NM
        Scenario Tested:
            [x] Verify that Owner column is not visible to Standard users
            [x] Verify that Owner column is visible to System Admin users(Scan created by Standard User)
            [x] Verify that Owner column is visible to Administrator users(Scan created by Standard User)
        """
        scan_page = ScansPage()
        scan_page.save_button.click()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox),
             waiting_for="waiting for scan search to be appeared")
        if API.User.Users.STANDARD_USER in create_user[0]:
            assert invisibility_of_element_located(
                scan_page.owner_column), f'Owner column is visible for {API.User.Users.STANDARD_USER} ' \
                                         f'user, which should not be visible'
        else:
            assert visibility_of_element_located(
                scan_page.owner_column), f'Owner column is not visible for {API.User.Users.ADMIN_USER} ' \
                                         f'user, which should be visible'
        UserMenu().logout()
        wait(lambda: visibility_of_element_located(LoginPage().username_field), waiting_for="Login Page",
             timeout_seconds=TIME_TEN_SECONDS)

        # Login with System Admin User
        LoginPage().login_with_defaults()
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.ALL_SCANS).click()

        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox),
             waiting_for="waiting for scan search to be appeared")
        assert visibility_of_element_located(
            scan_page.owner_column), f'Owner column is not visible for {API.User.Users.SYS_ADMIN_USER} ' \
                                     f'user, which should be visible'

    @pytest.mark.xray(test_key='NES-15484')
    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_last_login_date_format_for_users_in_table(self, create_users):
        """
        NES-15484 : Verify that 'Last login' value should be Display in correct date format

        Scenario Tested:
        [x] Verify that 'Last login' value should be display in correct date format like 'Today at 6:33 AM'.
        """
        user_menu = UserMenu()
        login_page = LoginPage()

        for user_role in [API.User.Role.STANDARD, API.User.Role.SYS_ADMIN, API.User.Role.ADMIN, API.User.Role.BASIC]:
            user_menu.logout()
            wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)

            user_name, password = create_users[user_role]["user_name"], create_users[user_role]["password"]
            login_page.login_with_credentials(username=user_name, password=password)

            NotificationActions().remove_all()
            sleep(TIME_SIXTY_SECONDS, reason="Waiting for 1 min after user login to get the different login time.")

        user_menu.logout()
        login_page.login_with_defaults()
        user_menu.loaded()

        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page get loaded")

        users_list = UserList()
        users_list.loaded()

        for user_role in [API.User.Role.STANDARD, API.User.Role.SYS_ADMIN, API.User.Role.ADMIN, API.User.Role.BASIC]:
            login_time = users_list.get_last_login_time_of_users(user_name=create_users[user_role]["user_name"])[0]

            assert all(["Today at" in login_time, self.validate_time_format(login_time=login_time.split()[2])]), \
                "Last login time is missing or mismatched due to invalid format."

    @pytest.mark.xray(test_key='NES-15299')
    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_visibility_of_transfer_and_delete_button_after_deleting_all_users(self, create_users):
        """
        NES-15299 : Verify on deleting users by first selecting and then one by one by clicking 'x' sign, 'Transfer Data' and 'Delete' buttons should not be displayed on UI
        """
        user_page = UsersPage()

        user_page.select_all_checkbox.click()
        assert all([user_page.is_element_present('transfer_data_button'),
                    user_page.is_element_present('delete_button')]), 'Transfer and Delete buttons are not present'

        user_page.delete_button.click()
        action_modal = ActionCloseModal()
        assert user_page.transfer_ownership_checkbox.is_selected(), 'Transfer ownership checkbox is not selected'

        action_modal.action_button.click()
        action_modal.wait_for_modal_closed()
        user_page.select_all_checkbox.click()
        assert not all([user_page.is_element_present('transfer_data_button'),
                        user_page.is_element_present('delete_button')]), 'Transfer and Delete buttons are still present'


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_legacy
@pytest.mark.usefixtures('login')
class TestUsersOnNessusProLegacy:
    """
    test users related tests on Nessus Professional Legacy
    """
    test_data = {"user_details": {"Standard": {'user_name': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                               'full_name': 'Standard user',
                                               'email': API.User.Users.TEST_EMAIL,
                                               'password': 'admin',
                                               'role': API.User.Role.STANDARD},
                                  "System Administrator":
                                      {'user_name': random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - '),
                                       'full_name': 'SysAdmin user',
                                       'email': API.User.Users.TEST_EMAIL,
                                       'password': 'admin',
                                       'role': API.User.Role.SYS_ADMIN}}, "check_login": False}

    def test_users_roles_on_legacy(self):
        """
        For 'Nessus Manager', it contains four types of role(System Administrator, Admin, Basic, Standard)
        with Standard as default
        """
        user_page = UsersPage()
        user_page.open()
        LoadingCircle(WAIT_SHORT)

        new_user_form = NewUserForm()
        user_page.new_user_button.click()

        LoadingCircle(WAIT_SHORT)
        assert API.User.Role.ROLE_LIST_PROFESSIONAL == new_user_form.get_user_role_options(), \
            "all the options are not available in role"
        assert new_user_form.role_dropdown.text == API.User.Role.STANDARD, \
            "role value is not set 'Standard' by default"

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_multiple_users_in_user_list_on_legacy(self, create_users):
        """
        Create all allowed types of users by providing data into required fields and
        verify that the users are created successfully
        """
        LoadingCircle(WAIT_SHORT)

        users = UserList().get_all_users()
        for user in create_users.keys():
            LoadingCircle(WAIT_SHORT)
            assert create_users.get(user).get('user_name') in users, \
                "User type" + create_users.get(user).get('user_name') + "is not created"

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                              'full_name': 'Standard user', 'email': API.User.Users.TEST_EMAIL,
                                              'password': 'admin', 'role': API.User.Role.STANDARD,
                                              'do_login': False}], indirect=True)
    def test_visibility_of_users_tab_on_legacy(self, create_user):
        """
        verify Log out from the system and Login with Standard user credentials, user must not see the Users tab
        under settings Account
        """
        username, password = create_user
        LoadingCircle(WAIT_SHORT)
        UserMenu().logout()

        LoadingCircle(WAIT_SHORT)
        LoginPage().login_with_credentials(username=username, password=password)

        LoadingCircle(WAIT_SHORT)
        HeaderBasePage().settings_link.click()

        LoadingCircle(WAIT_SHORT)
        assert 'Users' not in SideNav().get_all_sidenav_links(), \
            "users tab is available in side navigation for standard user"

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_select_all_users_on_legacy(self, create_users):
        """
        Click on select-all checkbox. Delete button must appear at the top with the New User button.
        Click on the Delete button and verify the confirmation pop-up. Click 'Cancel' on the pop-up and verify
        the users are not deleted. Repeat, clicking 'Delete' and the confirmation popup, and verify all the
        users except admin user are deleted.
        """
        user_page = UsersPage()
        user_page.select_all_checkbox.click()
        LoadingCircle(WAIT_SHORT)

        action_close_modal = ActionCloseModal()
        user_list = UserList()

        assert user_page.delete_button.is_enabled(), "delete button is disabled for all selected users"
        LoadingCircle(WAIT_SHORT)
        user_page.delete_button.click()

        assert action_close_modal.modal.is_displayed(), \
            'confirmation pop is not displayed after clicking on delete button'

        action_close_modal.cancel_button.click()
        LoadingCircle(WAIT_SHORT)

        users = user_list.get_all_users()
        for user in create_users.keys():
            LoadingCircle(WAIT_SHORT)
            assert create_users.get(user).get('user_name') in users, \
                "User type " + create_users.get(user).get('user_name') + " is not created"

    current_epoch = str(int(time.time()))
    standard_username = current_epoch + '-' + API.User.Users.STANDARD_USER
    sys_admin_username = current_epoch + '-' + API.User.Users.SYS_ADMIN_USER

    @pytest.mark.parametrize("create_users", [
        {"user_details": {"Standard": {'user_name': standard_username, 'full_name': 'Standard user',
                                       'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                       'role': API.User.Role.STANDARD},
                          "System Administrator": {'user_name': sys_admin_username, 'full_name': 'SysAdmin user',
                                                   'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                                   'role': API.User.Role.SYS_ADMIN}},
         "System Administrator": {'user_name': API.User.Users.SYS_ADMIN_USER, 'full_name': 'SysAdmin user',
                                  'email': API.User.Users.TEST_EMAIL, 'password': 'admin',
                                  'role': API.User.Role.SYS_ADMIN}, "check_login": False}], indirect=True)
    def test_search_user_on_legacy(self, create_users):
        """
        Enter any substring from the user, and verify that the list shows all the users that contain substring
        entered and count also gets updated next to search box.
        """
        user_page = UsersPage()
        user_page.search_box.value = self.current_epoch

        LoadingCircle(WAIT_NORMAL)
        user_list = UserList().get_all_users()

        LoadingCircle(WAIT_SHORT)
        assert len(user_list) == int(user_page.search_user_result.text), \
            "Count did not get updated after searching substring"
        assert [self.standard_username, self.sys_admin_username] == user_list, \
            "searched users are not in user list"

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["Name", "Role"])
    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    def test_sort_user_list_by_name_and_role_legacy(self, create_users, sort, column_to_sort):
        """
        Test to sort list column values
        Verify that names under list are present in ascending order and on clicking the name column,
        list will get change to descending order.
        Verify that roles under list are present in ascending order and on clicking the Role column,
        list will get change to descending order.
        """
        column_mapping = {"Name": "name",
                          "Role": "user_role"}
        map_attribute = column_mapping[column_to_sort]

        users_list = UserList()
        LoadingCircle(WAIT_NORMAL)
        expected_users_list = sorted([getattr(user, map_attribute) for user in users_list.rows],
                                     key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

        rendered_users_list = sort_on_column_values(page_class_instance=users_list, column_name=column_to_sort,
                                                    sort=sort)
        LoadingCircle(WAIT_SHORT)
        assert expected_users_list == [getattr(user, map_attribute) for user in rendered_users_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                              'full_name': 'Standard user', 'email': API.User.Users.TEST_EMAIL,
                                              'password': 'admin', 'role': API.User.Role.STANDARD, 'do_login': False},

                                             {'username': random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - '),
                                              'full_name': 'SysAdmin user', 'email': API.User.Users.TEST_EMAIL,
                                              'password': 'admin', 'role': API.User.Role.SYS_ADMIN,
                                              'do_login': False}], indirect=True)
    def test_api_key_generation_for_users_on_legacy(self, create_user):
        """
        Create all types of users and Verify that User list is updated. Perform below steps for all the users created.
        a. Click on each created user and Verify that the ‘API Keys’ tab exist.
        b. Click on ‘Generate’ button and Verify that a pop-up appears having title ‘Generate API Keys’,
        accept it and Verify that ‘Access Key’ and ‘Secret Key’ Exist.
        c. Click on ‘back to Users’ link and again on click on the user row and Verify that no ‘Access Key’ and
        ‘Secret Key’ exist. Click on ‘Generate’ button and Verify that ‘admin’ can regenerate the keys.
        """
        api_keys_page = APIKeys()

        LoadingCircle(WAIT_NORMAL)
        username = create_user[0]
        UserList().click_on_user(username)

        account_setting = AccountSettings()

        assert account_setting.api_keys_tab.is_displayed(), "api keys tab is not displayed for user"

        account_setting.api_keys_tab.click()
        api_keys_page.generate_button.click()
        popup_window = GenerateAPIKeysModal()
        assert popup_window.get_modal_title == 'Generate API Keys', "Popup to generate api keys doesn't came up."

        popup_window.action_button.click()
        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.api_keys_generation, \
            "did not get message for api keys generation"

        assert visibility_of_element_located((api_keys_page.access_key_field.we_by,
                                              api_keys_page.access_key_field.we_value))(get_driver_no_init()), \
            "Access key is invisible."
        assert visibility_of_element_located((api_keys_page.secret_key_field.we_by,
                                              api_keys_page.secret_key_field.we_value))(get_driver_no_init()), \
            "Secret key is invisible."

        account_setting.account_settings_tab.click()
        LoadingCircle(WAIT_SHORT)

        # Navigate back to API Keys, verify keys are not displayed
        account_setting.api_keys_tab.click()

        assert invisibility_of_element_located((api_keys_page.access_key_field.we_by,
                                                api_keys_page.access_key_field.we_value))(get_driver_no_init()), \
            "Access key is visible."

        LoadingCircle(WAIT_SHORT)
        assert invisibility_of_element_located((api_keys_page.secret_key_field.we_by,
                                                api_keys_page.secret_key_field.we_value))(get_driver_no_init()), \
            "Secret key is visible."

        account_setting.back_to_users_link.click()

        api_keys_page.open()
        api_keys_page.generate_api_keys()
        assert (api_keys_page.access_key_field.is_displayed()
                and api_keys_page.secret_key_field.is_displayed()), "Access key and secret key not displayed."

        assert (api_keys_page.access_key.isalnum() and api_keys_page.secret_key.isalnum() and
                (len(api_keys_page.access_key) == API.User.API_KEYS_LENGTH) and
                (len(api_keys_page.secret_key) == API.User.API_KEYS_LENGTH)), "Invalid key generated."

        # store the keys
        access_key = api_keys_page.access_key
        secret_key = api_keys_page.secret_key
        LoadingCircle(WAIT_SHORT)

        # Regenerate the keys and verify they have changed from previous
        api_keys_page.generate_api_keys()
        assert (api_keys_page.access_key_field.is_displayed()
                and api_keys_page.secret_key_field.is_displayed()), "Access key and secret key not displayed."

        assert (api_keys_page.access_key.isalnum() and api_keys_page.secret_key.isalnum() and
                (len(api_keys_page.access_key) == API.User.API_KEYS_LENGTH) and
                (len(api_keys_page.secret_key) == API.User.API_KEYS_LENGTH)), "Invalid key generated."

        assert ((api_keys_page.access_key != access_key)
                and (api_keys_page.secret_key != secret_key)), "Keys did not get changed after regeneration."

    @pytest.mark.parametrize("create_users", [
        {'user_details': {"Standard": {'user_name': random_name(prefix=API.User.Users.STANDARD_USER + ' - '),
                                       'full_name': 'Standard user', 'email': API.User.Users.TEST_EMAIL,
                                       'password': 'Standard_P@ssw0rd', 'role': API.User.Role.STANDARD}}},
        {'user_details': {"System Administrator": {'user_name': random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - '
                                                                            ),
                                                   'password': 'SysAdmin_P@ssw0rd', 'email': API.User.Users.TEST_EMAIL,
                                                   'full_name': 'SysAdmin user', 'role': API.User.Role.SYS_ADMIN}}}],
                             indirect=True)
    def test_create_users_with_diff_role_for_legacy(self, create_users):
        """
        NQA-1293 : Automation test for Creating user with different role under users page.
        1. Navigate to 'Users' tab under 'Settings'
        2. Create a new user with 'System Administrator' role and fill all other required fields
        3. Hit 'Save' and verify success notification as 'User created successfully'.
        4. Also verify created user is listed under users_page.
        5. Logout the current user and login with created user
        6. Verify successful login
        7. Repeat above steps for other user roles.
        """
        user_details = create_users

        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.create_user, \
            'Notification for creating user is missing'

        # Verify created user is present in User List.
        LoadingCircle(WAIT_NORMAL)
        users_list = UserList()
        for user in user_details.keys():
            _user = user_details.get(user)
            username = _user.get('user_name')
            user_role = _user.get('role')
            assert all([username in users_list.get_all_users(), user_role == users_list.get_user_role(
                user_name=username)]), 'User is not available in user list'

        LoadingCircle(TIME_THREE_SECONDS)
        UserMenu().logout()

        # Verify login by created user.
        LoadingCircle(WAIT_SHORT)
        login_page = LoginPage()
        for user in user_details.keys():
            _user = user_details.get(user)
            username = _user.get('user_name')
            password = _user.get('password')
            full_name = _user.get('full_name')
            login_page.login_with_credentials(username=username, password=password)
            LoadingCircle(WAIT_NORMAL)
            assert HeaderBasePage().user_name_text.text == full_name, 'Login Failed!'
        LoadingCircle(WAIT_SHORT)


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestUsersOnPro7:
    """
    test users tab on Nessus Professional 7
    """

    def test_users_tab_for_pro7(self):
        """
        Navigate to settings page and verify that Users tab does not exist, i.e user creation is not allowed
        """
        if not invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()):
            log.info('welcome to Nessus Pro Pop up is visible')
            action_close_modal = ActionCloseModal()
            action_close_modal.close_button.click()
            action_close_modal.wait_for_modal_closed()

        HeaderBasePage().settings_link.click()

        LoadingCircle(WAIT_SHORT)
        assert 'Users' not in SideNav().get_all_sidenav_links(), \
            "users tab is available in side navigation for standard user"


@pytest.mark.nessus_settings_2
@pytest.mark.disable_logout
@pytest.mark.nessus_manager
@pytest.mark.license_change
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestUserAfterLicenseChange:
    """ Covers user related test after changing the License """

    cat = None

    @staticmethod
    def change_license_for_nm_and_np(api: NessusAPI, license_type: str) -> None:
        """
        Updates the Nessus type according to given license type (like NM to NP)

        :param NessusAPI api: Nessus API object
        :param str license_type: Nessus type like NM or NP
        :return: None
        """
        activation_code_generator = ActivationCodeGenerator()

        activation_code = activation_code_generator.generate_nessus_manager_code(
            expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS) if license_type == ActivationCodeGenerator.NESSUS_MANAGER \
            else activation_code_generator.generate_code(code_type=license_type,
                                                         expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)

        fetch.register(serial=activation_code)
        wait_for_scanner_to_be_ready(api=api)

    def test_user_creation_not_allowed_after_license_change(self):
        """
        NES-11633 - Automation: test a new user cannot be added after changing license to pro

        Scenario Tested:
        [x] New user creation should not be allowed after changing license from NM to Nessus Pro
        """
        nessus_api = NessusAPI()
        nessus_type_before_license_update = nessus_api.server.properties()['nessus_type']

        assert nessus_type_before_license_update == Nessus.Manager.NESSUS_MANAGER, \
            'Installed nessus type is not Manager.'

        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.is_element_present("nessus_version"), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='about overview page gets load properly.')

        # Verifies update activation code tip is visible on UI
        assert overview_page.is_element_present("update_activation_code_tip"), \
            'Update Activation code icon is invisible'

        try:
            log.info("Update Nessus Manager to Nessus Pro.")
            self.change_license_for_nm_and_np(api=nessus_api, license_type=ActivationCodeGenerator.NESSUS_PROFESSIONAL)

            wait_for_scanner_to_be_ready(api=nessus_api)
            login_helper_after_server_restart()

            try:
                wait(lambda: ActionCloseModal().is_element_present('modal'),
                     waiting_for='Get welcome banner after login', timeout_seconds=TIME_SIXTY_SECONDS)
                close_wizard()
            except TimeoutExpired:
                log.warning("Welcome banner was not present in Nessus Pro.")

            nessus_type_after_license_update = nessus_api.server.properties()['nessus_type']

            assert nessus_type_after_license_update == Nessus.Professional.NESSUS_PROFESSIONAL, \
                'Nessus Manager is not updated into Pro after updating license.'

            HeaderBasePage().settings_link.click()
            users_element = SideNav().get_sidenav_element(Nessus.SideNavAccounts.USERS)

            # Verifies 'Users' option is not present on side navigation panel
            assert invisibility_of_element_located(users_element), \
                "'Users' option is visible in side navigation panel under 'Accounts' for Nessus Pro."

            payload = {'username': random_name(prefix=API.User.Users.BASIC_USER + ' - '), 'password': 'admin@123',
                       'permissions': '16'}

            nessus_api.login()

            # Verifies response code 403 while creating user in Nessus Pro.
            with expect_http_error(code=403):
                try:
                    nessus_api.users.create(payload=payload, stream=True)
                except Exception as err:
                    log.warning("Some unknown connection error occurs: {}".format(err))

        finally:
            log.info("Update Nessus Pro to Nessus Manager.")
            code = ActivationCodeGenerator().generate_nessus_manager_code(
                expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)

            register_nessus_output = SSH().execute("{} fetch --register {}".format(get_nessus_cli(), code))
            log.debug("Register Nessus output :: {}".format(register_nessus_output))

            wait_for_scanner_status(api=nessus_api, timeout=TIME_THIRTY_MINUTES, status=API.Status.READY,
                                    msg='Waiting for server to be in ready state.', sleep_interval=TIME_THIRTY_SECONDS)

            wait_for_scanner_to_be_ready(api=nessus_api)
