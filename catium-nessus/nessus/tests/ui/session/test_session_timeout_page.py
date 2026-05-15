"""
Nessus session timeout verification related test cases

:copyright: Tenable Network Security, 2017
:date: July 17, 2017
:last_modified: March 16, 2018
:author: @rdutta
"""

import pytest

from catium.helpers.sleep_lib import sleep
from catium.lib.config import Config as config
from catium.lib.const import TIME_FIVE_SECONDS
from catium.lib.const import TIME_SIXTY_SECONDS, WAIT_NORMAL, WAIT_SHORT
from catium.lib.webium.driver import get_driver
from catium.lib.webium.wait import wait
from nessus.helpers.scanner import restart_scanner
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import About
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AddAdvancedSettingModal, \
    AdvancedSettingsList, NoticeAdvancedSettings
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_settings_2
@pytest.mark.skipif(config.CAT_USE_GRID, reason="grid defaults to 60 seconds.")
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestSessionTimeout:
    """Tests for UI session timeout"""
    cat = None

    @pytest.mark.usefixtures('teardown')
    @pytest.mark.parametrize("session_timeout_sidebar_pages", (["Policies (P)",     # NQA-806, NQA-810
                                                                "Plugin Rules",     # NQA-807, NQA-812
                                                                "Scanners",         # NQA-808
                                                                "Agents"]))         # NQA-809
    def test_session_timeout_sidebar_pages(self, session_timeout_sidebar_pages):
        """Test to verify session timeout for Sidebar pages"""

        # Set session timeout parameter to 1
        self.set_session_timeout_parameter()

        # Restart Nessus service and after that login into it
        restart_scanner(self.cat.api)
        LoginPage.do_login()

        # Sidebar Pages
        sidenav = SideNav()
        sidenav.click_by_link_text(link_text=session_timeout_sidebar_pages)
        LoadingCircle(TIME_SIXTY_SECONDS)

        notifications = Notifications()
        error_notification = notifications.errors[-1]

        LoadingCircle(WAIT_NORMAL)
        assert error_notification == Messages.NotificationMessages.Users.session_expired, "Session not logged out."

        self.cat.api.login()
        LoginPage.do_login()

    @pytest.mark.usefixtures('teardown')
    @pytest.mark.parametrize("session_timeout_header_pages", (["Scans",
                                                               "Software Update",
                                                               "Master Password"]))    # NQA-804
    def test_session_timeout_header_pages(self, session_timeout_header_pages):
        """Test to verify session timeout for Header pages"""

        # Set session timeout parameter to 1
        self.set_session_timeout_parameter()

        # Restart Nessus service and after that login into it
        restart_scanner(self.cat.api)
        sleep(sleep_time=TIME_FIVE_SECONDS, reason='waiting for login screen')
        LoginPage.do_login()

        # Header Pages
        if session_timeout_header_pages == "Scans":
            HeaderBasePage().scan_link.click()
        else:
            about_page = About()
            about_page.open()
            if session_timeout_header_pages == 'Software Update':
                about_page.software_update_tab.click()
            elif session_timeout_header_pages == 'Master Password':
                about_page.encryption_password_tab.click()

        sleep(sleep_time=(TIME_FIVE_SECONDS*13), reason='waiting for session timeout')


        assert Notifications().errors[-1] == Messages.NotificationMessages.Users.session_expired,\
            "Session not logged out."
        self.cat.api.login()
        LoginPage.do_login()

    def set_session_timeout_parameter(self):
        """Set session timeout parameter from advanced setting"""

        setting_name = "xmlrpc_idle_session_timeout"

        header_base = HeaderBasePage()
        header_base.settings_link.click()

        side_nav = SideNav()
        side_nav.click_by_link_text(link_text="Advanced")

        settings_list = AdvancedSettingsList()
        setting_rows = settings_list.rows

        found = False
        for setting in setting_rows:
            if setting.setting_name_element.text == setting_name:
                setting.setting_name_element.click()
                found = True
                break

        if found:
            edit_setting = AddAdvancedSettingModal()
            edit_setting.advanced_setting_value.clear()
            LoadingCircle(WAIT_SHORT)
            edit_setting.advanced_setting_value.value = "1"
            edit_setting.action_button.click()

        else:
            advance_setting = AdvancedSettingsPage()
            advance_setting.new_button.click()
            add_setting = AddAdvancedSettingModal()
            add_setting.name.value = setting_name
            add_setting.advanced_setting_value.value = "1"
            add_setting.action_button.click()

        # Click on global save button
        notice = NoticeAdvancedSettings()
        LoadingCircle(WAIT_NORMAL)
        notice.notice_restart.click()

        get_driver().execute_script("window.history.go(-2)")
