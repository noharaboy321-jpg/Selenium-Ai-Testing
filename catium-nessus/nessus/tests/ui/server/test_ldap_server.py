"""
Nessus LDAP Server related test cases

:copyright: Tenable Network Security, 2017
:date: Jan 18, 2017
:last_modified: Dec 02, 2021
:author: @jamreliya, @rdutta, @kpanchal
"""

import pytest

from catium.lib.const.base_constants import TIME_FIVE_SECONDS, TIME_THREE_SECONDS
from nessus.helpers.server import aws_resource_required
from nessus.lib.const.constants import API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.server.ldapserver.ldap_server_page import LdapServerPage
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestLdapServer:
    """LDAP Test Cases"""

    @pytest.mark.parametrize('show_advanced_setting', [True, False])
    def test_ldap_server_screen(self, show_advanced_setting):
        """
        NES-13670 [Automation]: Verify LDAP server screen

        Scenario Tested:
        [x] Verify that Proxy server instruction should be shown with following fields:
            -> Default setting fields:
                - Host, Port, Username, Password, Base DN, Test LDAP Server button, Save and Cancel button
            -> Advanced setting fields:
                - Username Attribute, Email Attribute, Name Attribute, CA (PEM Format)
        """
        ldap_server = LdapServerPage()
        ldap_server.open()

        default_setting_fields = ["ldap_server_description_icon", "ldap_server_description", "host_field", "port_field",
                                  "username_field", "password_field", "base_dn_field", "test_ldap_server_btn",
                                  "show_advanced_settings", "save_button", "cancel_button", "username_attribute_field",
                                  "email_attribute_field", "name_attribute_field", "ca_field"]

        advanced_setting_fields = ["username_attribute_field", "email_attribute_field", "name_attribute_field",
                                   "ca_field"]

        if show_advanced_setting:
            ldap_server.show_advanced_settings.check()
        else:
            ldap_server.show_advanced_settings.uncheck()

        default_setting_fields.extend(advanced_setting_fields)

        for ldap_server_field in default_setting_fields:
            is_advanced_setting_visible = ldap_server.is_element_present(ldap_server_field)

            if ldap_server_field in advanced_setting_fields:
                expected_result = is_advanced_setting_visible if show_advanced_setting else not \
                    is_advanced_setting_visible
            else:
                expected_result = is_advanced_setting_visible

            assert expected_result, "'{}' field is not getting visible in LDAP server settings.".format(
                ldap_server_field)

    def test_ldap_server_connection_with_empty_setting_values(self):
        """
        NES-13670 [Automation]: Verify LDAP server screen

        Scenario Tested:
        [x] Verify that It should give an error message "Error: Failed to connect to the LDAP server: LDAP server not
            specified." while clicking on "Test LDAP Server" button with empty settings.
        """
        ldap_server_page = LdapServerPage()
        ldap_server_page.open()

        ldap_server_page.add_ldap_settings(host="", port="", username="", password="", base_dn="")
        ldap_server_page.test_ldap_server_btn.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.ldap_connection_error, \
            'Error notification messages is either missing or mismatch for testing LDAP server connection with ' \
            'empty setting values.'

    def test_verify_ldap_port(self):
        """
        verify LDAP port
        NQA - 1057 Automation tests for Settings - LDAP
        """
        # add LDAP server settings
        ldap_server_page = LdapServerPage()
        ldap_server_page.open()

        ldap_server_page.add_ldap_settings(host=API.Settings.Ldap.LDAP_HOST, port=636111,
                                           username=API.Settings.Ldap.LDAP_ADMINISTRATOR_USERNAME,
                                           password=API.Settings.Ldap.LDAP_ADMINISTRATOR_PASSWORD,
                                           base_dn=API.Settings.Ldap.LDAP_BASE_DN)

        ldap_server_page.save_button.click()

        assert Messages.NotificationMessages.continue_button_code in Notifications().errors[-1], \
            'LDAP server settings saved with invalid port'

        # clear notification history
        HeaderBasePage().clear_notification_history()
        LoadingCircle(TIME_THREE_SECONDS)

        # save setting with invalid port having four or more digit
        ldap_server_page.port_field.value = '00001'
        ldap_server_page.save_button.click()

        assert Messages.NotificationMessages.continue_button_code in Notifications().errors[-1], \
            'LDAP server settings saved with invalid port'

    @pytest.mark.parametrize("add_ldap_setting", [
        {'host': API.Settings.Ldap.LDAP_HOST, 'port': API.Settings.Ldap.LDAP_PORT,
         'username': API.Settings.Ldap.LDAP_ADMINISTRATOR_USERNAME, 'base_dn': API.Settings.Ldap.LDAP_BASE_DN,
         'password': API.Settings.Ldap.LDAP_ADMINISTRATOR_PASSWORD, 'test_connection': False}], indirect=True)
    def test_verify_ldap_settings(self, add_ldap_setting):
        """
        verify LDAP settings
        NQA - 1057 Automation tests for Settings - LDAP
        :param add_ldap_setting:  fixture that add ldap settings
        """
        AdvancedSettingsPage().open()
        LoadingCircle(TIME_THREE_SECONDS)

        # validate LDAP server settings persist
        ldap_server_page = LdapServerPage()
        ldap_server_page.open()

        assert all([(API.Settings.Ldap.LDAP_HOST == ldap_server_page.host_field.value),
                    (API.Settings.Ldap.LDAP_PORT == ldap_server_page.port_field.value),
                    (API.Settings.Ldap.LDAP_ADMINISTRATOR_USERNAME == ldap_server_page.username_field.value),
                    (API.Settings.Ldap.LDAP_BASE_DN == ldap_server_page.base_dn_field.value)]), \
            'All LDAP host/port/user/Base not saved successfully'

        # click on Show Advanced setting checkbox and verify details are visible
        ldap_server_page.show_advanced_settings.check()

        assert all([ldap_server_page.username_attribute_field.is_displayed(),
                    ldap_server_page.ca_field.is_displayed()]), "'username' and 'ca field' attribute is not present"

    @aws_resource_required
    @pytest.mark.parametrize("add_ldap_setting", [
        {'host': API.Settings.Ldap.LDAP_HOST, 'port': API.Settings.Ldap.LDAP_PORT,
         'username': API.Settings.Ldap.LDAP_ADMINISTRATOR_USERNAME, 'base_dn': API.Settings.Ldap.LDAP_BASE_DN,
         'password': API.Settings.Ldap.LDAP_ADMINISTRATOR_PASSWORD, 'test_connection': False}], indirect=True)
    @pytest.mark.parametrize("create_user", [
        {'username': API.Settings.Ldap.LDAP_ADMINISTRATOR_USERNAME, 'role': API.User.Role.STANDARD,
         'password': API.Settings.Ldap.LDAP_ADMINISTRATOR_PASSWORD, 'is_ldap_user': True, 'do_login': True,
         'account_type': 'LDAP'}], indirect=True)
    def test_add_ldap_user(self, add_ldap_setting, create_user):
        """
        add LDAP user and login with it
        NQA - 1057 Automation tests for Settings - LDAP
        :param add_ldap_setting:  fixture that add ldap settings
        :param create_user:  fixture that add ldap user
        :return: None
        """
        # verify login is successful or not
        assert UserMenu().loaded(), 'login failed'

        LoadingCircle(TIME_FIVE_SECONDS)

    @pytest.mark.parametrize("add_ldap_setting", [
        {'host': API.Settings.Ldap.LDAP_HOST, 'port': API.Settings.Ldap.LDAP_PORT,
         'username': API.Settings.Ldap.LDAP_ADMINISTRATOR_USERNAME, 'base_dn': API.Settings.Ldap.LDAP_BASE_DN,
         'password': API.Settings.Ldap.LDAP_ADMINISTRATOR_PASSWORD, 'test_connection': False}], indirect=True)
    def test_verify_ldap_advanced_settings(self, add_ldap_setting):
        """
        verify LDAP advanced settings
        NQA - 1057 Automation tests for Settings - LDAP
        :param add_ldap_setting:  fixture that add ldap settings
        """
        ldap_server_page = LdapServerPage()
        ldap_server_page.open()

        ldap_server_page.add_ldap_settings(host="", port="", username="", password="", base_dn="",
                                           attributes=API.Settings.Ldap.Attributes.WITHOUT_ATTRIBUTES)
        ldap_server_page.save_button.click()
        LoadingCircle(TIME_THREE_SECONDS)

        AdvancedSettingsPage().open()
        LoadingCircle(TIME_THREE_SECONDS)

        # validate LDAP server settings persist
        ldap_server_page = LdapServerPage()
        ldap_server_page.open()

        assert all([(ldap_server_page.host_field.value == ""), (ldap_server_page.port_field.value == ""),
                    (ldap_server_page.username_field.value == ""), (ldap_server_page.base_dn_field.value == "")]), \
            'LDAP host/port/user/Base DN not saved successfully'

        # check advanced settings
        ldap_server_page.show_advanced_settings.check()

        assert all([(ldap_server_page.username_attribute_field.value == ""), (ldap_server_page.ca_field.value == ""),
                    (ldap_server_page.email_attribute_field.value == ""),
                    (ldap_server_page.name_attribute_field.value == "")]), \
            "'username', 'ca field', 'email' and 'name' attribute is not saved successfully"
