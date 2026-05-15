"""
Nessus Proxy Server related test cases

:copyright: Tenable Network Security, 2017
:date: February 15, 2018
:last_modified: Dec 06, 2021
:author: @smadan @rdutta, @kpanchal
"""
from random import randint

import pytest

from catium.lib.const.base_constants import TIME_SIXTY_SECONDS
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.lib.const import Nessus
from nessus.lib.const.constants import API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.server.proxyserver.proxy_server_page import ProxyServer
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestProxyServer:
    """
    Covers Proxy Server related test cases.
    # NQA-1061 : Automation tests for Settings - Proxy Server.
    """

    def test_proxy_server_screen(self):
        """
        NES-13668 [Automation]: Verify proxy server screen

        Scenario Tested:
        [x] Verify that Proxy server instruction should be shown with following fields:
            - Host, Port, Username, Password, Auth Method, User-Agent, Test Proxy Server button, Save and Cancel button
        """
        proxy_server = ProxyServer()
        proxy_server.open()

        for proxy_server_field in ["proxy_server_description_icon", "proxy_server_description", "host", "port",
                                   "username", "password", "auth_method", "user_agent", "test_proxy_server",
                                   "save_button", "cancel_button"]:
            assert proxy_server.is_element_present(proxy_server_field), \
                "'{}' field is either missing in proxy server settings.".format(proxy_server_field)

    def test_verify_default_and_all_auth_method_option(self):
        """
        NES-13668 [Automation]: Verify proxy server screen

        Scenario Tested:
        [x] Verify that Default dropdown option for auth-method should be "AUTO DETECT".
        [x] Verify all options available in Auth method dropdown menu.
        """
        proxy_server = ProxyServer()
        proxy_server.open()

        actual_default_auth_method = proxy_server.auth_method.get_text_selected()
        expected_default_auth_method = API.Settings.ProxyServer.PROXY_AUTO_DETECT

        assert actual_default_auth_method == expected_default_auth_method, \
            "Got incorrect default auth method value :: '{}'. Expected value :: '{}'".format(
                actual_default_auth_method, expected_default_auth_method)

        available_auth_method_options = [option['label'] for option in proxy_server.auth_method.option_values]

        assert available_auth_method_options == API.Settings.ProxyServer.PROXY_AUTH_METHODS, \
            "Got incorrect options under auth method dropdown."

    @pytest.mark.parametrize('enter_value', [True, False])
    def test_proxy_server_blank_and_invalid_values(self, enter_value):
        """
        NQA- 1061 - Settings - Proxy Server
        NES-13669 [Automation]: Verify proxy server settings by entering invalid details

        1. Navigate to proxy server page under settings
        2. Enter blank values in host and port
        3. Click Test proxy server
        4. Verify error message

        Scenario Tested:
        [x] Verify that It should give connection error notification message while testing proxy server by entering
            invalid settings.
        """
        proxy_server = ProxyServer()
        proxy_server.open()

        host_value = Nessus.Scan.Target.LINUX_TARGET if enter_value else ''
        port_value = randint(11, 9999) if enter_value else ''

        proxy_server.fill_proxy_server_form(host=host_value, port=port_value)
        proxy_server.test_proxy_server.click()

        notification = Notifications()
        notification_msg_constant = Messages.NotificationMessages
        expected_connection_error = notification_msg_constant.ProxyServer.proxy_server_connection_error.format(
            host_value, port_value) if enter_value else notification_msg_constant.continue_button_code

        if enter_value:
            wait(lambda: notification.is_element_present("errors_msgs"), timeout_seconds=TIME_SIXTY_SECONDS,
                 waiting_for="Error notification message to be displayed")

        assert notification.errors[-1] == expected_connection_error, \
            "Error notification is either missing ot mismatch after testing with invalid or blank proxy server " \
            "settings."

    @pytest.mark.skip(reason='Port highlight only happens while typing in the field')
    def test_proxy_server_invalid_character_in_port(self):
        """
        NQA- 1061 - Settings - Proxy Server

        1. Enter invalid character e.g. special character or alphabet in port field
        2. Verify Red Box is shown around port field
        3. Click on Test Proxy Server
        4. Verify error message
        """
        proxy_server = ProxyServer()
        proxy_server.open()

        proxy_server.fill_proxy_server_form(port='@#$', host=API.Settings.ProxyServer.PROXY_HOST)

        assert 'error' in proxy_server.port.get_css_classes(), 'Port Field is not highlighted on entering invalid data.'

        proxy_server.test_proxy_server.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "Error notification for invalid port is missing"

    @pytest.mark.skip(reason='NES-9018, Not consistent and needs to be fixed')
    @pytest.mark.parametrize("proxy_server_settings", [
        {'host': API.Settings.ProxyServer.PROXY_HOST, 'port': API.Settings.ProxyServer.PROXY_PORT,
         'username': API.Settings.ProxyServer.PROXY_USERNAME, 'password': API.Settings.ProxyServer.PROXY_PASSWORD,
         'agent': API.Settings.ProxyServer.PROXY_USER_AGENT}], indirect=True)
    def test_save_and_test_proxy_server_valid_input_auth_none(self, proxy_server_settings):
        """
        NQA- 1061 - Settings - Proxy Server

        1. Enter valid inputs in all the fields
        2. Click on Test Proxy Server
        3. Verify success message
        4. Click on save
        5. Verify success message
        """
        proxy_server = ProxyServer()
        proxy_server.test_proxy_server.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.ProxyServer.proxy_successfully_connected \
               + " " + "'none'", "Notification for proxy server connection is missing"

        HeaderBasePage().clear_notification_history()
        proxy_server.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.ProxyServer.proxy_server_saved, \
            'Notification for proxy server saved is missing'

        assert proxy_server.get_proxy_server_settings() == proxy_server. \
            sanitize_proxy_server_settings(proxy_server_settings), 'Proxy server settings not saved'

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("proxy_server_settings", [
        {'host': API.Settings.ProxyServer.PROXY_HOST, 'port': API.Settings.ProxyServer.PROXY_PORT,
         'username': API.Settings.ProxyServer.PROXY_USERNAME, 'password': API.Settings.ProxyServer.PROXY_PASSWORD,
         'agent': API.Settings.ProxyServer.PROXY_USER_AGENT}], indirect=True)
    def test_clear_user_agent_field(self, proxy_server_settings):
        """
        NQA- 1061 - Settings - Proxy Server

        1. Clear user agent field
        2. Click Save
        3. Go to Advanced page
        4. Go back to Proxy Server Page
        5. Verify user agent field is not re-populated
        """
        proxy_server = ProxyServer()
        proxy_server.user_agent.clear()
        proxy_server.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.ProxyServer.proxy_server_saved, \
            'Proxy server settings not saved'

        wait_for_scanner_to_be_ready(api=NessusAPI())

        side_nav = SideNav()
        side_nav.click_by_link_text(link_text='Advanced')
        side_nav.click_by_link_text(link_text='Proxy Server')

        assert proxy_server.user_agent.value == '', "Expected empty user agent field"
