""""
Nessus test cases related to User Login/Logout

:copyright: Tenable Network Security, 2017
:date: January 08, 2018
:last_modified: Apr 15, 2023
:author: @rdutta, @kpanchal, @sacharya, @mdabra
"""
from datetime import datetime
from http import HTTPStatus

import pytest
from requests import HTTPError
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located

from catium.lib.activation_code_generator import ActivationCodeGenerator
from catium.lib.const import WAIT_NORMAL, TIME_TEN_SECONDS, TIME_THIRTY_SECONDS
from catium.lib.const import WAIT_SHORT, STRING_NO
from catium.lib.const.base_constants import HOST_PLUGIN_FEED
from catium.lib.const.deployment import DOCKER_IMAGES
from catium.lib.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.scanner import restart_scanner
from nessus.helpers.system import get_nessus_type_using_api, is_manager, is_pro, is_home, is_expert
from nessus.lib.config import NessusConfig
from nessus.lib.const import API, Nessus
from nessus.lib.const.setup_wizard_constants import SetupWizardConst
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsList, NoticeAdvancedSettings
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.my_account.my_account_page import AccountSettings
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.setup.setup_page import AccountSetupPage, ProductRegistrationPage, AdvancedSettingsModal
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.users.users_page import UsersPage, UserList

log = create_logger()


@pytest.mark.nessus_settings_1
@pytest.mark.usefixtures('wizard_open')
@pytest.mark.standalone
# below markers are commented as these test do fresh install of NM on kubernet
# and because of that getting 'site not reachable error'
# @pytest.mark.nessus_pro
# @pytest.mark.nessus_expert
# @pytest.mark.nessus_legacy
# @pytest.mark.nessus_manager
class TestUserAutoLogin:
    """
    Covers User's Auto Login related test cases after fresh install.
    sub-part :- # NQA-1052 : Automation tests for User Login / Logout.

    1. After a new install verify Auto login with the initial admin account.
    2. Log out, confirm that you are dropped to the login page back with success notification.
    """

    @staticmethod
    def check_auto_login(product_activation_code: str) -> None:
        """
        1. After fresh install, put initial setup information.
        2. Put product activation key and Verify auto login is successful after activation.
        3. Verify page element and logout.

        :param str product_activation_code: product activation code
        """
        AccountSetupPage().setup_account(username=SetupWizardConst.NESSUS_SESSION_USERNAME,
                                         password=SetupWizardConst.NESSUS_SESSION_PASSWORD)

        registration_window = ProductRegistrationPage()
        registration_window.click_advanced_settings()
        settings_window = AdvancedSettingsModal()
        settings_window.plugin_feed.click()
        settings_window.custom_host_field.value = HOST_PLUGIN_FEED
        ActionCloseModal().accept_action()
        LoadingCircle(WAIT_SHORT)

        registration_window.activation_code_field.value = product_activation_code
        LoadingCircle(WAIT_SHORT)
        registration_window.continue_button.click()
        if not invisibility_of_element_located((By.CLASS_NAME, '.modal'))(get_driver_no_init()):
            modal_window = ActionCloseModal()
            modal_window.cancel_button.click()
            modal_window.wait_for_modal_closed()

        header_page = HeaderBasePage()
        LoadingCircle(WAIT_NORMAL)
        assert visibility_of_element_located((header_page.logo_link.we_by, header_page.logo_link.we_value)
                                             )(get_driver_no_init()), "Page Logo is invisible."

        LoadingCircle(WAIT_SHORT)
        UserMenu().logout()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.success_sign_out, \
            "Sign out is not successful."

    @pytest.mark.usefixtures("kube_deploy_nessus_remote_scanner", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config", [{"link": STRING_NO, "freshInstall": True,
                                                            "image": DOCKER_IMAGES['nessus']['es7']['release']}])
    def test_auto_login_with_initial_admin_account_in_new_install_for_nessus_pro7(self):
        """Test auto login for Nessus Professional 7."""

        activation_code = ActivationCodeGenerator().generate_nessus_professional(expiration_days=35)
        self.__class__.check_auto_login(product_activation_code=activation_code)

    @pytest.mark.usefixtures("kube_deploy_nessus_remote_scanner", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config", [{"link": STRING_NO, "freshInstall": True,
                                                            "image": DOCKER_IMAGES['nessus']['es7']['release']}])
    def test_auto_login_with_initial_admin_account_in_new_install_for_nessus_pro_legacy(self):
        """Test auto login for Nessus Professional Legacy."""

        activation_code = ActivationCodeGenerator().generate_nessus_professional_legacy()
        self.__class__.check_auto_login(product_activation_code=activation_code)

    @pytest.mark.usefixtures("kube_deploy_nessus_manager", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config", [{"link": STRING_NO, "freshInstall": True,
                                                            "image": DOCKER_IMAGES['nessus']['es7']['release']}])
    def test_auto_login_with_initial_admin_account_in_new_install_for_nessus_manager(self):
        """Test auto login for Nessus Manager."""

        activation_code = ActivationCodeGenerator().generate_nessus_manager_code(ips=256, scanners=5, agents=100)
        self.__class__.check_auto_login(product_activation_code=activation_code)


@pytest.mark.nessus_settings_1
@pytest.mark.usefixtures('login')
class TestUserLoginLogout:
    """
    Covers User Login/Logout related test cases.
    sub-part :- # NQA-1052 : Automation tests for User Login / Logout
    """
    cat = None

    @staticmethod
    def change_user_role(user_name: str, role: str) -> None:
        """
        Change the user role as specified in role parameter
        :param str user_name: user name
        :param str role: role which turned on.
        """
        # Navigate to user page and change the state of the user specified in state
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), timeout_seconds=TIME_THIRTY_SECONDS)

        user_page.edit_user_account_settings(user_name=user_name, role=role)
        user_page.back_to_users.click()

        user_list = UserList()
        wait(lambda: user_page.is_element_present("search_box"), timeout_seconds=TIME_THIRTY_SECONDS)

        if role == API.User.Role.DISABLED:
            assert "{}\n{}".format(API.User.Role.DISABLED, user_name) in \
                   [user.username.text for user in user_list.rows], "User is not in disabled state."
        else:
            assert user_name.split("\n")[1] in [user.username.text for user in
                                                user_list.rows], "Failed to enable user, it's still in disabled state."

    @staticmethod
    def change_advanced_settings(settings_name: str, settings_value: str) -> None:
        """
        Changing the advanced settings of idle timeout
        :param str settings_name: parameter name
        :param str settings_value: value to be set
        """
        AdvancedSettingsList().edit_or_add_setting(setting_name=settings_name, setting_value=settings_value)
        LoadingCircle(WAIT_NORMAL)
        NoticeAdvancedSettings().notice_restart.click()
        restart_scanner(api=__class__.cat.api)

        # Login after restart
        LoadingCircle(TIME_TEN_SECONDS)
        LoginPage().login_with_defaults()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.ie
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    def test_scans_page_url_on_login(self):
        """
        1. Login with admin username and password.
        2. Verify the Scan Page is displayed and the URL is correct #/scans/folders/my-scans
        """
        LoadingCircle(WAIT_NORMAL)
        assert '/#/scans/folders/my-scans' in get_driver_no_init().current_url, 'Current url is incorrect.'

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("invalid_credentials", (
            [{'username': '#', 'password': '#',
              'notification': Messages.NotificationMessages.Users.invalid_credentials},
             {'username': NessusConfig.CAT_NESSUS_USERNAME, 'password': '#',
              'notification': Messages.NotificationMessages.Users.invalid_credentials},
             {'username': NessusConfig.CAT_NESSUS_USERNAME, 'password': NessusConfig.CAT_NESSUS_PASSWORD.title(),
              'notification': Messages.NotificationMessages.Users.invalid_credentials},
             {'username': NessusConfig.CAT_NESSUS_USERNAME, 'password': '',
              'notification': Messages.NotificationMessages.continue_button_code},
             {'username': '', 'password': NessusConfig.CAT_NESSUS_PASSWORD,
              'notification': Messages.NotificationMessages.continue_button_code}]))
    def test_login_with_invalid_credentials(self, invalid_credentials):
        """
        Steps are covered as parameters passed in "invalid_credentials"
        1. Login with incorrect username and verify that you get an notification with incorrect login.
        2. Login with incorrect password and verify that you get an notification with incorrect login.
        3. Login with different case level passwords(If your password is password, try Password) and
           verify that the password is case sensitive and throw you an error.
        4. Login with correct user name but blank password, make sure you get an error.
        5. Login with blank username, but correct password, make sure you get an error.
        """
        LoadingCircle(WAIT_NORMAL)
        user_menu = UserMenu()
        user_menu.logout()

        login_page = LoginPage()
        login_page.login_with_credentials(username=invalid_credentials['username'],
                                          password=invalid_credentials['password'])

        assert Notifications().errors[-1] == invalid_credentials['notification'], \
            "Error notification for invalid credentials is missing or mismatched."

        login_page.do_login()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    def test_login_with_case_insensitive_username(self):
        """
        1. Try logging in with different case level username(If your username is admin, try Admin)
        2. Verify user name case-insensitive and you are able to login.
        """
        LoadingCircle(WAIT_NORMAL)
        user_menu = UserMenu()
        user_menu.logout()

        # Verify that the username is case insensitive
        LoginPage().login_with_credentials(username=NessusConfig.CAT_NESSUS_USERNAME.title(),
                                           password=NessusConfig.CAT_NESSUS_PASSWORD)
        LoadingCircle(WAIT_SHORT)
        assert (user_menu.loaded() and ScansPage().new_scan_button.is_displayed()), \
            "Unable to login with case insensitive username."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_legacy
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    def test_login_with_bookmarked_page_url(self):
        """
        1. Bookmark the Settings Page /#/settings/about.
        2. Logout, click the bookmark, verify it goes to the login page
        3. Verify it goes to the setting page directly after logging in.
        """
        # Bookmark the Settings Page
        HeaderBasePage().settings_link.click()
        LoadingCircle(WAIT_SHORT)
        page_bookmark = get_driver_no_init().current_url

        # Logout, click the bookmark, verify it goes to the login page
        LoadingCircle(WAIT_NORMAL)
        UserMenu().logout()
        wait(lambda: len(Notifications().successes) > 0, waiting_for='Notification list to populate.')
        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.success_sign_out, \
            "Sign out is unsuccessful."

        get_driver_no_init().get(page_bookmark)
        login_page = LoginPage()
        assert login_page.username_field.is_displayed(), "Clicking on bookmark does not navigate to login page."

        # Login and Verify it goes to the setting page directly
        login_page._do_login(username=NessusConfig.CAT_NESSUS_USERNAME,
                             password=NessusConfig.CAT_NESSUS_PASSWORD, open_page=False)
        LoadingCircle(WAIT_NORMAL)
        assert page_bookmark == get_driver_no_init().current_url, 'Current page is not bookmarked page.'

    @pytest.mark.nessus_legacy
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_user", [{'username': random_name(prefix='{} - '.format(API.User.Users.
                                                                                            SYS_ADMIN_USER)),
                                              'password': 'SysAdmin_P@ssw0rd',
                                              'role': API.User.Role.SYS_ADMIN, 'do_login': True}], indirect=True)
    def test_change_user_password(self, create_user):
        """
        1. Change password under Settings - Account
        2. Verify password is changed
        3. Log out, confirm that you are dropped to the login page back with success notification.
        4. Confirm password is changed
        """
        user_name, password = create_user
        new_password = "New_{}".format(password)

        # Change the password and verify
        my_account_settings = AccountSettings()
        my_account_settings.open()
        LoadingCircle(WAIT_SHORT)
        my_account_settings.change_password(current_password=password, new_password=new_password)

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_change_password, \
            "Password has changed but notification is missing."

        # Log out the current session
        LoadingCircle(WAIT_NORMAL)
        user_menu = UserMenu()
        user_menu.logout()

        assert Notifications().successes[-1] == "{}, {}.".format(
            Messages.NotificationMessages.Users.success_sign_out.split(',')[0], user_name), "Sign out is unsuccessful."

        # Confirm password has changed by login with new password
        LoginPage().login_with_credentials(username=user_name, password=new_password)
        LoadingCircle(WAIT_NORMAL)
        assert user_menu.loaded(), "Login failed with changed password."

        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("create_users", [{"user_details": {
        "Administrator": {'user_name': random_name(prefix='{} - '.format(API.User.Users.ADMIN_USER)),
                          'full_name': 'Admin user', 'email': API.User.Users.TEST_EMAIL, 'password': 'Admin_P@ssw0rd',
                          'role': API.User.Role.ADMIN}}, "unique_username": True, "check_login": True}], indirect=True)
    def test_login_with_disabled_admin_account(self, create_users):
        """
        1. Create standard, basic, sysadmin and 2nd admin user account
        2. Login with 2nd admin account and valid password, logout
        3. Repeat above step for standard, basic, sysadmin user account
        4. Login with primary admin account, disable 2nd admin account
        5. Login with 2nd admin account and verify it gives you 403 error.
        """
        # All type of users has created and checked log in with created user and user details are returned by fixture
        user_credentials = create_users

        try:
            # Disable 2nd admin account
            self.__class__.change_user_role(user_name=user_credentials.get(API.User.Role.ADMIN).get('user_name'),
                                            role=API.User.Role.DISABLED)

            # Login with disabled account and verify it gives you 403 error
            UserMenu().logout()
            NotificationActions().remove_all()

            try:
                login_with_disable = (
                    self.cat.api.session.create(username=user_credentials.get(API.User.Role.ADMIN).get('user_name'),
                                        password=user_credentials.get(API.User.Role.ADMIN).get('password')))

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

                self.cat.api.add_header({'X-Cookie': "token={}".format(login_with_disable)})

                self.cat.api.session.get()

                assert self.cat.api.http_status_code == HTTPStatus.FORBIDDEN, \
                    'Expecting HTTP {0}, got {1} instead'.format(HTTPStatus.FORBIDDEN, self.cat.api.http_status_code)

            except HTTPError as e:
                log.info('expecting 403, but  got {}'.format(e))
                return False

        finally:
            LoginPage().login_with_defaults()
            UserMenu().loaded()

            self.__class__.change_user_role(user_name="{}\n{}".format(API.User.Role.DISABLED, user_credentials.get(
                API.User.Role.ADMIN).get('user_name')), role=API.User.Role.ADMIN)

    @pytest.mark.nessus_legacy
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("create_users", [{"user_details": {
        "System Administrator": {'user_name': random_name(prefix='{} - '.format(API.User.Users.SYS_ADMIN_USER)),
                                 'full_name': 'SysAdmin user', 'email': API.User.Users.TEST_EMAIL,
                                 'password': 'SysAdmin_P@ssw0rd', 'role': API.User.Role.SYS_ADMIN}},
        "check_login": True}], indirect=True)
    def test_login_with_disabled_default_sysadmin_account(self, create_users):
        """
        1. Create standard, sysadmin user account
        2. Login with 2nd sysadmin account and disable primary admin account
        5. Login with primary admin account and verify it gives you 403 error.
        """
        # All type of users has created and checked log in with created user and user details are returned by fixture
        user_credentials = create_users

        try:
            user_menu = UserMenu()
            user_menu.logout()

            notification_action = NotificationActions()
            notification_action.remove_all()

            # Login with 2nd sysadmin account
            login_page = LoginPage()
            login_page.login_with_credentials(username=user_credentials.get(API.User.Role.SYS_ADMIN).get('user_name'),
                                              password=user_credentials.get(API.User.Role.SYS_ADMIN).get('password'))
            user_menu.loaded()

            # Disable default admin account
            self.__class__.change_user_role(user_name=NessusConfig.CAT_NESSUS_USERNAME, role=API.User.Role.DISABLED)

            # Login with default admin account and verify it gives you 403 error
            user_menu.logout()
            notification_action.remove_all()

            try:
                login_with_disable = (
                    self.cat.api.session.create(username=NessusConfig.CAT_NESSUS_USERNAME,
                                                password=NessusConfig.CAT_NESSUS_PASSWORD))

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

                self.cat.api.add_header({'X-Cookie': "token={}".format(login_with_disable)})

                self.cat.api.session.get()

                assert self.cat.api.http_status_code == HTTPStatus.FORBIDDEN, \
                    'Expecting HTTP {0}, got {1} instead'.format(HTTPStatus.FORBIDDEN, self.cat.api.http_status_code)

            except HTTPError as e:
                log.info('expecting 403, but  got {}'.format(e))
                return False

        finally:
            # Enable the default admin account
            if login_page.is_element_present("username_field"):
                login_page.login_with_credentials(username=user_credentials.get(API.User.Role.SYS_ADMIN).get(
                    'user_name'), password=user_credentials.get(API.User.Role.SYS_ADMIN).get('password'))
                user_menu.loaded()

            self.__class__.change_user_role(user_name="{}\n{}".format(
                API.User.Role.DISABLED, NessusConfig.CAT_NESSUS_USERNAME), role=API.User.Role.SYS_ADMIN)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_users", [{"user_details": {
        "Basic": {'user_name': random_name(prefix='{} - '.format(API.User.Users.BASIC_USER)),
                  'full_name': 'Basic user',
                  'email': API.User.Users.TEST_EMAIL,
                  'password': 'Basic_P@ssw0rd',
                  'role': API.User.Role.BASIC},
        "Standard": {'user_name': random_name(prefix='{} - '.format(API.User.Users.STANDARD_USER)),
                     'full_name': 'Standard user',
                     'email': API.User.Users.TEST_EMAIL,
                     'password': 'Standard_P@ssw0rd',
                     'role': API.User.Role.STANDARD},
        "Administrator": {'user_name': random_name(prefix='{} - '.format(API.User.Users.ADMIN_USER)),
                          'full_name': 'Admin user',
                          'email': API.User.Users.TEST_EMAIL,
                          'password': 'Admin_P@ssw0rd',
                          'role': API.User.Role.ADMIN},
        "System Administrator": {'user_name': random_name(prefix='{} - '.format(API.User.Users.SYS_ADMIN_USER)),
                                 'full_name': 'SysAdmin user',
                                 'email': API.User.Users.TEST_EMAIL,
                                 'password': 'SysAdmin_P@ssw0rd',
                                 'role': API.User.Role.SYS_ADMIN}}, "check_login": True}], indirect=True)
    def test_login_with_invalid_password_for_created_user_account(self, create_users):
        """
        1. Create standard, basic, sysadmin and 2nd admin user account
        2. Login with 2nd admin account and invalid password, verify notification error
        3. Repeat above step for standard, basic, sysadmin user account
        """
        # All type of users has created and user details are returned by fixture
        user_credentials = create_users
        user_menu = UserMenu()
        user_menu.logout()
        NotificationActions().remove_all()

        # Login each created user with invalid password and verify it fails
        login_page = LoginPage()
        wait(lambda: login_page.is_element_present('username_field'))

        for user in user_credentials.keys():
            login_page.login_with_credentials(username=user_credentials.get(user).get('user_name'), password='#$%')

            assert Notifications().errors[-1] == Messages.NotificationMessages.Users.invalid_credentials, \
                "Error notification is missing or mismatched for invalid password."

        login_page.login_with_defaults()
        user_menu.loaded()

    @pytest.mark.nessus_legacy
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix='{} - '.format(API.User.Users.STANDARD_USER)), 'password': 'Standard_P@ssw0rd',
         'role': API.User.Role.STANDARD, 'do_login': True, 'unique_username': True}], indirect=True)
    def test_change_password_for_standard_user_from_admin_user_account(self, create_user):
        """
        1. Create a standard user account
        2. Login as admin account and change the password for the standard account, logout
        3. Login as the standard account with the old password, verify you get an error
        4. Login as the standard account with the new password, verify you can login
        """
        user_name, password = create_user

        # Logout current user and login with default admin account
        LoadingCircle(WAIT_NORMAL)
        user_menu = UserMenu()
        user_menu.logout()

        login_page = LoginPage()
        login_page.login_with_defaults()
        LoadingCircle(WAIT_SHORT)

        # Change the password for the standard account and logout
        new_password = 'New_{}'.format(password)
        user_page = UsersPage()
        user_page.open()
        LoadingCircle(WAIT_NORMAL)
        user_page.edit_user_account_settings(user_name=user_name, password=new_password)

        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.user_updated, \
            "Password changed, but notification was missing."
        LoadingCircle(WAIT_NORMAL)

        if ActionCloseModal().modal.is_displayed():
            ActionCloseModal().close_button.click()
            LoadingCircle(WAIT_NORMAL)
        user_menu.logout()

        # Login as the standard account with the old password, verify you get an error
        login_page.login_with_credentials(username=user_name, password=password)

        assert Notifications().errors[-1] == Messages.NotificationMessages.Users.invalid_credentials, \
            "Error notification is missing or mismatched for invalid password."

        # Login as the standard account with the new password, verify you can login
        login_page.login_with_credentials(username=user_name, password=new_password)
        LoadingCircle(WAIT_NORMAL)
        assert user_menu.loaded(), "Login failed with new password."

        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.nessus_legacy
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix='{} - '.format(API.User.Users.STANDARD_USER)), 'password': 'Standard_P@ssw0rd',
         'role': API.User.Role.STANDARD, 'do_login': True}], indirect=True)
    def test_delete_standard_user_from_admin_user_account(self, create_user):
        """
        1. Create a standard user account
        2. Login as admin account and delete the standard user, logout
        3. Login with the standard account verify you can't login in with 403 error
        """
        user_name, password = create_user

        # Logout current user and login with default admin account
        LoadingCircle(WAIT_NORMAL)
        user_menu = UserMenu()
        user_menu.logout()

        # Login as default admin account
        login_page = LoginPage()
        login_page.login_with_defaults()
        LoadingCircle(WAIT_SHORT)

        # Delete the standard user and logout
        user_page = UsersPage()
        user_page.open()
        LoadingCircle(WAIT_NORMAL)
        UserList().delete_user(user_name=user_name)

        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.delete_user, \
            "Failed to delete user."
        LoadingCircle(WAIT_NORMAL)
        user_menu.logout()

        # Login with the standard account verify you can't login in with 403 error
        login_page.login_with_credentials(username=user_name, password=password)

        assert Notifications().errors[-1] == Messages.NotificationMessages.Users.invalid_credentials, \
            "Error notification is missing or mismatched for login with deleted user."

        login_page.login_with_defaults()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_essentials_plus
    @pytest.mark.nessus_essentials
    def test_css_class_for_nessus_logo(self):
        """
        NES-9067: UI test that the appropriate css class is set on the page

        Scenarios Tested:
        [x] Verify Nessus logo is appear properly as per the license type in Login page and top left corner of scan
            page.
        """
        nessus_type = get_nessus_type_using_api().split(' ', 1)[1].lower().replace(' ', '-')

        assert HeaderBasePage().logo_link.get_css_classes()[1] == nessus_type, \
            "Nessus logo is not appear as per the 'License type' on top left corner of scan page."

        UserMenu().logout()
        login_page = LoginPage()

        assert login_page.nessus_logo.get_css_classes()[0] == nessus_type, "Nessus logo is not appear as per the " \
                                                                           "'License type' on Login page."

        login_page.login_with_defaults()

    @pytest.mark.xray(test_key='NES-14210')
    @pytest.mark.parametrize('nessus_type', [pytest.param("professional", marks=pytest.mark.nessus_pro),
                                             pytest.param("essentials", marks=pytest.mark.nessus_home),
                                             pytest.param("manager", marks=pytest.mark.nessus_manager)])
    def test_elements_visibility_on_login_screen(self, nessus_type):
        """
        NES-12471: [UI] Verify elements on login screen
        NES-14210: Verify bottom tenable logo on login screen

        Steps:
        1. Launch Nessus URL
        2. Verify these elements on login screen: username, password, sign-in button, nessus log,
           nessus copyright year, tenable logo and nessus type.

        Scenario Tested:
        [x] Verify elements on login screen
        """
        login_page = LoginPage()
        NotificationActions().remove_all()
        user_menu = UserMenu()
        user_menu.logout()
        wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)
        # Verify all elements/ nessus type/ copyright year on login screen.
        assert login_page.is_element_present('username_field'), "Username field is not present on login screen."
        assert login_page.is_element_present('password_field'), "Password field is not present on login screen."
        assert login_page.is_element_present('sign_in_button'), "Sign-in button is not present on login screen."
        assert login_page.is_element_present('nessus_logo'), "Nessus logo is not present on login screen."
        assert login_page.is_element_present('copyright_year'), \
            "Nessus copyright year is not available on login screen."
        assert login_page.is_element_present('remember_me_checkbox'), \
            "Remember me checkbox is not present on login screen."
        assert login_page.nessus_logo.get_attribute('class').lower() == nessus_type.lower(), "Nessus type is incorrect."

        login_page.do_login()

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.nessus_manager
    def test_verify_elements_on_admin_user_popup_on_main_page(self):
        """
        NES-12473: [UI] Click on admin user on main page and verify popup

        Steps:
        1. Click on admin user on Nessus main page.
        2. Verify all the links, buttons,username and logo is visible on popup

        Scenario Tested:
        [x] Verify all the links, buttons,username and logo is visible on admin user popup on main page.
        """
        user_menu = UserMenu()
        user_menu.user_menu_dropdown.click()

        assert user_menu.is_element_present('user_profile_link'), \
            "User profile link is not available on pop up."

        assert user_menu.is_element_present('username'), "Username is not available on admin user popup"

        assert user_menu.is_element_present('sign_out_link'), "Sign out link is not available on user popup."

        assert user_menu.username.text == NessusConfig.CAT_NESSUS_USERNAME, "Incorrect username is displayed."

        user_menu.user_menu_dropdown.click()

    @pytest.mark.xray(test_key='NES-14221')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    def test_verify_copyright_year_on_login_page(self):
        """
        NES-14221 : Verify the year on login screen

        Scenario Tested:
        [x] Verify proper year is displayed on Login Page
        """
        login_page = LoginPage()
        NotificationActions().remove_all()
        UserMenu().logout()
        wait(lambda: login_page.is_element_present(element_name='username_field'),
             timeout_seconds=TIME_THIRTY_SECONDS)

        assert login_page.copyright_year.text.split()[1] == str(datetime.now().year), \
            f"Copyright Year is not correct. Expected {str(datetime.now().year)} but got " \
            f"{login_page.nessus_copy_right.text.split()[1]}"

        login_page.do_login()

    @pytest.mark.xray(test_key='NES-14064')
    @pytest.mark.xray(test_key='NES-14028')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    def test_verify_remember_me_checkbox(self):
        """
        NES-14064 Verify remember me check box
        NES-14028 Verify that "Remember Me" check box works properly on login page.

        Scenario Tested:
        [x] Verify Username is saved and visible in when Remember me checkbox is selected
        [x] Verify Remember Me checkbox remain checked after logout
        """

        login_page = LoginPage()
        NotificationActions().remove_all()
        UserMenu().logout()

        wait(lambda: login_page.is_element_present(element_name='remember_me_checkbox'),
             timeout_seconds=TIME_THIRTY_SECONDS)

        login_page.remember_me_checkbox.click()
        login_page.username_field.send_keys(NessusConfig.CAT_NESSUS_USERNAME)
        login_page.password_field.send_keys(NessusConfig.CAT_NESSUS_PASSWORD)
        login_page.sign_in_button.click()

        NotificationActions().remove_all()
        UserMenu().logout()
        wait(lambda: login_page.is_element_present(element_name='username_field'),
             timeout_seconds=TIME_THIRTY_SECONDS)
        assert login_page.username_field.value == NessusConfig.CAT_NESSUS_USERNAME, 'Username is not present or not valid'
        assert login_page.remember_me_checkbox.is_selected(), 'Remember me checkbox is not checked'


@pytest.mark.nessus_settings_1
@pytest.mark.usefixtures('login')
class TestLoginProduct:
    @pytest.mark.xray(test_key='NES-14355')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    def test_verify_product_name_on_login_page_for_all(self):
        """
        NES-14355 : Verify correct nessus product is initialized

        Scenario Tested:
        [x] Verify proper product name is displayed on login page after setup is complete
        """
        product_name = None
        if is_home():
            product_name = Nessus.Essentials.NESSUS_ESSENTIALS
        elif is_pro():
            product_name = Nessus.Professional.NESSUS_PROFESSIONAL
        elif is_manager():
            product_name = Nessus.Manager.NESSUS_MANAGER
        elif is_expert():
            product_name = Nessus.Manager.NESSUS_EXPERT

        overview = OverView()
        overview.open()
        wait(lambda: overview.is_element_present(element_name='product_labels'),
             timeout_seconds=TIME_THIRTY_SECONDS)
        assert product_name in overview.product_labels[
            0].text, f'Expected Product Name {product_name}, got {overview.product_labels[0].text} instead on Overview page '

        UserMenu().logout()
        login_page = LoginPage()
        wait(lambda: login_page.is_element_present(element_name='username_field'),
             timeout_seconds=TIME_THIRTY_SECONDS)
        assert login_page.nessus_logo.text in product_name, f'Expected Product Name {product_name}, got {login_page.nessus_logo.text} instead on Login page'
