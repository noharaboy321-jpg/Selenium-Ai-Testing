"""
Nessus "ui_theme" setting related test cases
:copyright: Tenable Network Security, 2017
:date: Jul 27, 2021
:last_modified: Sept 23, 2021
:author: @kpanchal.ctr
"""
import random

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import STRING_YES
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_SIXTY_SECONDS, TIME_THIRTY_SECONDS, WAIT_LONG
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.advanced_settings import get_color_code_of_ui_element
from nessus.helpers.agents import create_freeze_window_via_api
from nessus.helpers.nessus_ui.settings import modify_existing_advanced_setting, login_helper_after_server_restart
from nessus.helpers.nessuscli import fix
from nessus.helpers.nessuscli.helper import get_nessus_cli, start_nessus, stop_nessus, path_join, get_nessus_var_dir
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.system import is_manager, is_home
from nessus.lib.const import Nessus, NessusCli, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import About
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AdvancedSettingsList, \
    UIThemeSettingPage, AddAdvancedSettingModal
from nessus.pageobjects.agents.agent_blackout_windows_page import AgentBlackoutWindowsPage, AgentBlackoutWindowList
from nessus.pageobjects.agents.agent_group_page import AgentGroupsPage
from nessus.pageobjects.agents.agents_page import AgentsPage
from nessus.pageobjects.agents.create_agent_blackout_window_page import CreateBlackoutWindowPage
from nessus.pageobjects.cluster.cluster_agent_page import AgentClusterMigration
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.groups.groups_page import GroupsPage, GroupList
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, close_pendo_guide_container_banner_for_nessus_pro, NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.password_mgmt.password_management_page import PasswordManagement
from nessus.pageobjects.plugin_rules.plugin_rules_page import PluginRulesPage, PluginRulesList
from nessus.pageobjects.policies.policies_page import PoliciesPage, PolicyList
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, VulnerabilityList, ScanExportPage
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.server.ldapserver.ldap_server_page import LdapServerPage
from nessus.pageobjects.server.proxyserver.proxy_server_page import ProxyServer
from nessus.pageobjects.server.smtpserver.smtp_server_page import SmtpServerPage
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.pageobjects.upgrade_assistant.upgrade_assistant_page import UpgradeAssistantPage
from nessus.pageobjects.users.users_page import UsersPage

log = create_logger()


def reset_ui_theme_setting_value_to_default():
    """ Resets the setting value of given setting name to default value """
    if not get_driver_no_init().current_url.endswith('settings/advanced'):
        AdvancedSettingsPage().open()

        advanced_setting_list = AdvancedSettingsList()
        wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
             waiting_for='Advanced settings list to load.')

    add_advanced_setting_modal = AddAdvancedSettingModal()
    add_advanced_setting_modal.reset_setting_banner(setting_name=Nessus.AdvancedSettings.UI_THEME)
    sleep(WAIT_NORMAL, reason="It takes little bit time get theme effect")

    advanced_setting_list = AdvancedSettingsList()
    advanced_setting_list.refresh()
    wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
         waiting_for='Advanced settings list to load.')


@pytest.mark.nessus_settings_1
@pytest.mark.usefixtures('login')
class TestNessusDarkModeSetting:
    """ Covers "ui_theme" Setting related Test Cases """

    @staticmethod
    def verify_ui_theme_background_color_code(setting_name: str):
        """ Verifies the ui theme color after updating the setting value """
        ui_theme_setting_page = UIThemeSettingPage()

        dom_element_dict = {"side_nav_section": ui_theme_setting_page.side_nav_section,
                            "layout_section": ui_theme_setting_page.layout_section,
                            "header_section": ui_theme_setting_page.header}

        theme_color_dict = {
            Nessus.AdvancedSettings.LIGHT_MODE: {
                "side_nav_section": Nessus.AdvancedSettings.UIThemeColors.LightTheme.SIDE_NAV_SECTION_COLOR,
                "layout_section": Nessus.AdvancedSettings.UIThemeColors.LightTheme.LAYOUT_SECTION_COLOR,
                "header_section": Nessus.AdvancedSettings.UIThemeColors.LightTheme.HEADER_SECTION_COLOR},
            Nessus.AdvancedSettings.DARK_MODE: {
                "side_nav_section": Nessus.AdvancedSettings.UIThemeColors.DarkTheme.SIDE_NAV_SECTION_COLOR,
                "layout_section": Nessus.AdvancedSettings.UIThemeColors.DarkTheme.LAYOUT_SECTION_COLOR,
                "header_section": Nessus.AdvancedSettings.UIThemeColors.DarkTheme.HEADER_SECTION_COLOR}}

        for element_key in dom_element_dict.keys():
            expected_theme_color = theme_color_dict[setting_name][element_key]

            assert get_color_code_of_ui_element(element=dom_element_dict[element_key], css_property="background") == \
                   expected_theme_color, "Got different background color for '{}' in '{}' UI theme. Expected should " \
                                         "be :: '{}'".format(element_key, setting_name, expected_theme_color)

    def verify_ui_theme_color_inside_scan_sensors_and_settings_tabs(self, setting_value: str):
        """ Verifies the ui theme setting effect inside scan, sensors and settings tab """
        header_base_page = HeaderBasePage()
        header_tabs_element_list = [header_base_page.scan_link, header_base_page.settings_link]

        if is_manager():
            header_tabs_element_list.extend([header_base_page.sensors_tab])

        for header_element in header_tabs_element_list:
            header_element.click()
            sleep(WAIT_NORMAL, reason="waiting for page gets loaded properly")

            self.verify_ui_theme_background_color_code(setting_name=setting_value)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("setting_details", [
        {"setting_tab": Nessus.AdvancedSettings.USER_INTERFACE_TAB, "setting_name": Nessus.AdvancedSettings.UI_THEME,
         "default_value": "Sync with OS setting"}])
    def test_default_ui_theme_setting_value(self, setting_details):
        """
        NES-13236 [Automation]: Verify Default Mode for "ui_theme" setting after install nessus.

        Scenario Tested:
        [x] Verify the default setting value of "ui_theme" setting is "Sync with OS setting".
        """
        AdvancedSettingsPage().open()

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

    @pytest.mark.nessus_home
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('setting_value', [Nessus.AdvancedSettings.DARK_MODE, Nessus.AdvancedSettings.LIGHT_MODE])
    def test_verify_ui_theme_setting_functioning_as_per_selected_value(self, setting_value):
        """
        NES-13234 [Automation]: Verify Dark Mode theme setting in Advanced settings Preference.

        Scenario Tested:
        [x] Verify that background color should be changed to dark after selecting the setting value 'dark'.
        [x] Verify that background color should be changed to light after selecting the setting value 'light'.
        """
        try:
            modify_existing_advanced_setting(setting_tab=Nessus.AdvancedSettings.USER_INTERFACE_TAB,
                                             setting_name=Nessus.AdvancedSettings.UI_THEME,
                                             setting_value=setting_value)
            sleep(WAIT_NORMAL, reason="It takes little bit time get theme effect")
            close_pendo_guide_container_banner_for_nessus_pro()
            advanced_setting_list = AdvancedSettingsList()
            advanced_setting_list.refresh()
            wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
                 waiting_for='Advanced settings list to load.')

            updated_setting_value = advanced_setting_list.get_settings_value(
                setting_tab=Nessus.AdvancedSettings.USER_INTERFACE_TAB,
                setting_name=Nessus.AdvancedSettings.UI_THEME)[0]

            assert updated_setting_value == setting_value, "Failed to change the setting value."

            self.verify_ui_theme_color_inside_scan_sensors_and_settings_tabs(setting_value=setting_value)
        finally:
            reset_ui_theme_setting_value_to_default()

    @pytest.mark.parametrize('setting_value', [Nessus.AdvancedSettings.DARK_MODE, Nessus.AdvancedSettings.LIGHT_MODE])
    def test_verify_ui_theme_setting_functioning_via_cli(self, setting_value):
        """
        NES-13235 [Automation]: Verify Dark Mode theme setting from CLI

        Scenario Tested:
        [x] Verify that background color should be changed to dark after setting the value to 'dark' via CLI.
        [x] Verify that background color should be changed to light after setting the value 'light' via CLI.
        """
        user_menu = UserMenu()
        user_menu.logout()
        wait(lambda: LoginPage().is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)
        nessus_api = NessusAPI()

        try:
            fix.set(key="ui_theme", value=setting_value.lower())
            sleep(WAIT_NORMAL, reason="It takes little bit time get theme effect")

            stop_nessus()
            start_nessus()
            wait_for_scanner_to_be_ready(api=nessus_api)

            updated_setting_value = fix.get_value(key="ui_theme")

            assert updated_setting_value == setting_value.lower(), \
                "Failed to change the setting value via CLI command."

            wait_for_scanner_to_be_ready(api=nessus_api)
            login_helper_after_server_restart()
            wait(lambda: user_menu.is_element_present('user_menu_dropdown'), waiting_for="scans page gets loaded")

            self.verify_ui_theme_color_inside_scan_sensors_and_settings_tabs(setting_value=setting_value)
        finally:
            reset_ui_theme_setting_value_to_default()

    @pytest.mark.parametrize('setting_value', [Nessus.AdvancedSettings.DARK_MODE, Nessus.AdvancedSettings.LIGHT_MODE])
    def test_verify_ui_theme_setting_after_backup_and_restore_nessus(self, setting_value):
        """
        NES-13241 [Automation]: Verify the dark_mode settings and theme after Backup & Restore Nessus.

        Scenario Tested:
        [x] Verify the "ui_theme" setting value and theme after Backup & Restore Nessus.
        """
        user_menu = UserMenu()
        user_menu.logout()
        wait(lambda: LoginPage().is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)
        nessus_api = NessusAPI()

        try:
            fix.set(key="ui_theme", value=setting_value.lower())
            stop_nessus()
            start_nessus()
            wait_for_scanner_to_be_ready(api=nessus_api)

            with SSH() as ssh:
                ssh.execute("{} {} {}".format(get_nessus_cli(), NessusCli.BackupAndRestore.BACKUP_COMMAND,
                                              NessusCli.BackupAndRestore.BACKUP_FILE_NAME))

                backup_tar_file = path_join(path_dir_list=[get_nessus_var_dir(),
                                                           NessusCli.BackupAndRestore.BACKUP_FILE_NAME])

                assert ssh.path_exist(backup_tar_file), "Backup tar file was not created successfully!"

                stop_nessus()
                restore_backup_output = ssh.execute("{} {} {}".format(
                    get_nessus_cli(), NessusCli.BackupAndRestore.RESTORE_COMMAND, backup_tar_file))
                log.debug("'{}' command output is : {}".format(NessusCli.BackupAndRestore.RESTORE_COMMAND,
                                                               restore_backup_output))

                assert NessusCli.BackupAndRestore.DB_VERSION_CHECK_PASSED in restore_backup_output, \
                    "'{}' message is not present in 'backup --restore' command execution's output".format(
                        NessusCli.BackupAndRestore.DB_VERSION_CHECK_PASSED)

                start_nessus()
                wait_for_scanner_to_be_ready(api=nessus_api)

            updated_setting_value = fix.get_value(key="ui_theme")

            assert updated_setting_value == setting_value.lower(), \
                "Failed to change the setting value via CLI command."

            login_helper_after_server_restart()
            wait(lambda: UserMenu().is_element_present('user_menu_dropdown'), waiting_for="scans page gets loaded")

            self.verify_ui_theme_color_inside_scan_sensors_and_settings_tabs(setting_value=setting_value)
        finally:
            reset_ui_theme_setting_value_to_default()


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('login')
class TestScanResultsSeverityColors:
    """ Covers "ui_theme" Setting related Test Cases """

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('setting_value', [Nessus.AdvancedSettings.DARK_MODE, Nessus.AdvancedSettings.LIGHT_MODE])
    def test_verify_color_palette_of_vulnerabilities_in_scan_result(self, import_scan_via_api, setting_value):
        """
        NES-13240 [Automation]: Verify the color palette of Vulnerabilities in whole Nessus.

        Scenario Tested:
        [x] Verify that Vulnerabilities color pallet should as per define in JIRA Ticket NES-12855.
        """
        scan_name = import_scan_via_api[0]

        setting_detail_dict = {Nessus.AdvancedSettings.UI_THEME: setting_value,
                               Nessus.AdvancedSettings.USE_VULNERABILITY: STRING_YES.capitalize()}

        try:
            for setting_name, s_value in setting_detail_dict.items():
                modify_existing_advanced_setting(setting_tab=Nessus.AdvancedSettings.USER_INTERFACE_TAB,
                                                 setting_name=setting_name, setting_value=s_value)
                sleep(WAIT_NORMAL, reason="It takes little bit time get theme effect")
            close_pendo_guide_container_banner_for_nessus_pro()
            advanced_setting_list = AdvancedSettingsList()
            advanced_setting_list.refresh()
            wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
                 timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Advanced settings list to load.')

            HeaderBasePage().scan_link.click()
            scan_list = ScanList()
            scan_list.loaded()

            scan_list.click_on_scan(scan_name=scan_name)
            scan_result_page = ScanViewPage()
            wait(lambda: scan_result_page.is_element_present('vulnerability_tab'), waiting_for='Scan details to load')
            scan_result_page.vulnerability_tab.click()

            vulnerability_list = VulnerabilityList()
            vulnerability_list.loaded()
            vulnerability_list.vulnerability_setting.click()
            vulnerability_list.click_on_group_enable_disable(enable=False)

            severity_index_dict = {'0': Nessus.Scan.Severity.INFO, '1': Nessus.Scan.Severity.LOW,
                                   '2': Nessus.Scan.Severity.MEDIUM, '3': Nessus.Scan.Severity.HIGH,
                                   '4': Nessus.Scan.Severity.CRITICAL}

            severity_color_dict = {
                Nessus.AdvancedSettings.LIGHT_MODE: {
                    Nessus.Scan.Severity.CRITICAL: [Nessus.AdvancedSettings.UIThemeColors.LightTheme.CRITICAL,
                                                    Nessus.AdvancedSettings.UIThemeColors.WHITE_FONT_COLOR],
                    Nessus.Scan.Severity.HIGH: [Nessus.AdvancedSettings.UIThemeColors.LightTheme.HIGH,
                                                Nessus.AdvancedSettings.UIThemeColors.WHITE_FONT_COLOR],
                    Nessus.Scan.Severity.MEDIUM: [Nessus.AdvancedSettings.UIThemeColors.LightTheme.MEDIUM,
                                                  Nessus.AdvancedSettings.UIThemeColors.WHITE_FONT_COLOR],
                    Nessus.Scan.Severity.LOW: [Nessus.AdvancedSettings.UIThemeColors.LightTheme.LOW,
                                               Nessus.AdvancedSettings.UIThemeColors.BLACK_FONT_COLOR],
                    Nessus.Scan.Severity.INFO: [Nessus.AdvancedSettings.UIThemeColors.LightTheme.INFO,
                                                Nessus.AdvancedSettings.UIThemeColors.BLACK_FONT_COLOR]},
                Nessus.AdvancedSettings.DARK_MODE: {
                    Nessus.Scan.Severity.CRITICAL: [Nessus.AdvancedSettings.UIThemeColors.DarkTheme.CRITICAL,
                                                    Nessus.AdvancedSettings.UIThemeColors.WHITE_FONT_COLOR],
                    Nessus.Scan.Severity.HIGH: [Nessus.AdvancedSettings.UIThemeColors.DarkTheme.HIGH,
                                                Nessus.AdvancedSettings.UIThemeColors.BLACK_FONT_COLOR],
                    Nessus.Scan.Severity.MEDIUM: [Nessus.AdvancedSettings.UIThemeColors.DarkTheme.MEDIUM,
                                                  Nessus.AdvancedSettings.UIThemeColors.BLACK_FONT_COLOR],
                    Nessus.Scan.Severity.LOW: [Nessus.AdvancedSettings.UIThemeColors.DarkTheme.LOW,
                                               Nessus.AdvancedSettings.UIThemeColors.BLACK_FONT_COLOR],
                    Nessus.Scan.Severity.INFO: [Nessus.AdvancedSettings.UIThemeColors.DarkTheme.INFO,
                                                Nessus.AdvancedSettings.UIThemeColors.WHITE_FONT_COLOR]}}

            initial_severity_index = 0

            for row in vulnerability_list.rows:
                severity_index = row.get_attribute("data-severity")
                severity_bkg_color = severity_color_dict[setting_value][severity_index_dict[severity_index]][0]
                severity_font_color = severity_color_dict[setting_value][severity_index_dict[severity_index]][1]

                if int(severity_index) != initial_severity_index:
                    severity_indicator_element = scan_result_page.get_element_for_vpr_severity_from_table(
                        threat_index=str(severity_index))

                    # Verifies severity label's background color
                    assert get_color_code_of_ui_element(element=severity_indicator_element,
                                                        css_property='background') == \
                           severity_bkg_color, "Got different background color for '{}' severity index in '{}' " \
                                               "UI theme. Expected should be :: '{}'".format(
                        severity_index, setting_value, severity_bkg_color)

                    # Verifies severity label's font color
                    assert get_color_code_of_ui_element(element=severity_indicator_element, css_property='color') == \
                           severity_font_color, "Got different font color for '{}' severity index in '{}' UI theme. " \
                                                "Expected should be :: '{}'".format(severity_index, setting_value,
                                                                                    severity_font_color)

                    if initial_severity_index == int(severity_index):
                        break
                    else:
                        initial_severity_index = int(severity_index)
        finally:
            reset_ui_theme_setting_value_to_default()


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestNessusUIColorPalette:
    """ Covers "ui_theme" Setting related Test Cases """

    cat = None

    @staticmethod
    def verify_links_and_buttons_inside_my_scans_folder(scan_name: str, element_type: str, setting_value: str):
        """ Verifies color palette of links and buttons inside "My Scans" folder """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "color" if element_type == "Link" else "background"

        scan_page = ScansPage()
        scan_page.select_all_checkbox.check()

        if element_type == "Link":
            assert get_color_code_of_ui_element(element=scan_page.clear_selected_item_link,
                                                css_property=css_property) == element_color_dict[setting_value][0], ""
        else:
            assert get_color_code_of_ui_element(element=scan_page.new_scan_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, scan_page.new_scan_button, element_color_dict[setting_value][2])

            for web_element in [scan_page.more_button, scan_page.import_button, scan_page.new_folder_button]:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][1], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][1])

        scan_page.select_all_checkbox.uncheck()
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("vulnerability_tab"), waiting_for='Scan results page to load')

        if element_type == "Link":
            assert get_color_code_of_ui_element(element=scan_view_page.back_link, css_property=css_property) == \
                   element_color_dict[setting_value][0], "Got different color in '{}' ui theme for " \
                                                         "'Back to My Scans' link. Expected should be :: '{}'".format(
                setting_value, element_color_dict[setting_value][0])
        else:
            expected_elements = [
                scan_view_page.scan_result_button_bar] if setting_value == Nessus.AdvancedSettings.LIGHT_MODE \
                else [scan_view_page.configure_button, scan_view_page.audit_trail_button, scan_view_page.report_button,
                      scan_view_page.export_button]

            for web_element in expected_elements:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][1], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][1])
        NotificationActions().remove_all()
        scan_view_page.report_button.click()
        scan_view_page.get_element_for_report_format_radio_button(
            report_format=API.Scan.UIExportFormats.FORMAT_CSV).click()

        generate_report_modal = ActionCloseModal()
        wait(lambda: generate_report_modal.is_element_present("modal"), waiting_for='Export modal to open')
        scan_export_page = ScanExportPage()

        if element_type == "Link":
            for web_element in [scan_export_page.select_all_link, scan_export_page.clear_link,
                                scan_export_page.system_link]:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][0], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][0])
        else:
            assert get_color_code_of_ui_element(element=scan_export_page.generate_report_button,
                                                css_property=css_property) == element_color_dict[setting_value][2], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, scan_export_page.generate_report_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=scan_export_page.cancel_button, css_property=css_property) == \
                   expected_color, "Got different color in '{}' ui theme for '{}' element. Expected should " \
                                   "be :: '{}'".format(setting_value, scan_export_page.cancel_button, expected_color)

        generate_report_modal.cancel_button.click()
        scan_view_page.back_link.click()
        scan_list.loaded()

        scan_page.js_scroll_into_view(element=scan_page.new_scan_button)
        scan_page.new_scan_button.click()
        close_pendo_guide_container_banner_for_nessus_pro()
        wait(lambda: scan_page.is_element_present("back_to_folder"), waiting_for='scan templates gets loaded')

        if element_type == "Link":
            assert get_color_code_of_ui_element(element=scan_page.back_to_folder,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, scan_page.back_to_folder, element_color_dict[setting_value][0])

        scan_page.click_by_scan(scan_text=Nessus.TemplateNames.ADVANCED)
        scan_form = NewScanForm()
        wait(lambda: scan_form.is_element_present('name_field'), waiting_for='new scan form to load properly.')

        if element_type == "Link":
            for web_element in [scan_form.back_link, scan_form.add_file_link]:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][0], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][0])

            for element_name in [Nessus.Scan.SettingsBasicSubMenu.SCHEDULE,
                                 Nessus.Scan.SettingsBasicSubMenu.NOTIFICATIONS]:
                setting_link_element = BasicSetting().get_basic_setting_links_in_new_scan_form(
                    setting_name=API.PoliciesSettings.SettingsTypes.BASIC.capitalize(), link_name=element_name)

                assert get_color_code_of_ui_element(element=setting_link_element, css_property=css_property) == \
                       element_color_dict[setting_value][0], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][0])
        else:
            assert get_color_code_of_ui_element(element=scan_form.save_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, scan_form.save_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=scan_form.cancel_button, css_property=css_property) == \
                   expected_color, "Got different color in '{}' ui theme for '{}' element. Expected should " \
                                   "be :: '{}'".format(setting_value, scan_form.cancel_button, expected_color)

        HeaderBasePage().scan_link.click()
        scan_list.loaded()
        all_scans = scan_list.get_all_scans()

        for scan in all_scans:
            scan_list.delete_scan(scan_name=scan)

        if element_type == "Link":
            assert get_color_code_of_ui_element(element=scan_page.create_a_new_scan_link,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, scan_page.create_a_new_scan_link, element_color_dict[setting_value][0])

    @staticmethod
    def verify_links_and_buttons_inside_trash_folder(element_type: str, setting_value: str):
        """ Verifies color palette of links and buttons inside "Trash" folder """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "color" if element_type == "Link" else "background"

        scan_trash_page = ScansTrashPage()
        scan_trash_page.select_all_checkbox.check()

        if element_type == "Link":
            assert get_color_code_of_ui_element(element=scan_trash_page.clear_selected_item_link,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, scan_trash_page.clear_selected_item_link, element_color_dict[setting_value][0])
        else:
            for web_element in [scan_trash_page.more_button, scan_trash_page.empty_trash_button]:
                if web_element == scan_trash_page.empty_trash_button:
                    scan_trash_page.select_all_checkbox.uncheck()

                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][1], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][1])

    @staticmethod
    def verify_links_and_buttons_inside_policies_folder(policy_name: str, element_type: str, setting_value: str):
        """ Verifies color palette of links and buttons inside "Policies" folder """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "color" if element_type == "Link" else "background"

        policy_page = PoliciesPage()
        policy_list = PolicyList()
        policy_page.select_all_checkbox.check()

        if element_type == "Link":
            for web_element in [policy_page.scan_templates_link, policy_page.clear_selected_item_link]:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][0], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][0])

            policy_page.select_all_checkbox.uncheck()
            all_policies = policy_list.get_all_policies()

            for policy in all_policies:
                policy_list.delete_policy(policy_name=policy)

            assert get_color_code_of_ui_element(element=policy_page.create_a_new_policy_link,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][0])
        else:
            assert get_color_code_of_ui_element(element=policy_page.new_policy_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, policy_page.new_policy_button, element_color_dict[setting_value][2])

            for web_element in [policy_page.more_button, policy_page.import_button]:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][1], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][1])

            for policy in policy_list.rows:
                if policy.name.text == policy_name:
                    policy.remove.click()

            delete_policy_modal = ActionCloseModal()
            wait(lambda: delete_policy_modal.is_element_present("modal"), waiting_for="modal to open")

            assert get_color_code_of_ui_element(element=delete_policy_modal.action_button,
                                                css_property=css_property) == element_color_dict[setting_value][2], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, delete_policy_modal.action_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=delete_policy_modal.cancel_button,
                                                css_property=css_property) == expected_color, \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, delete_policy_modal.cancel_button, expected_color)

            delete_policy_modal.cancel_button.click()

    @staticmethod
    def verify_links_and_buttons_inside_plugin_rules_folder(element_type: str, setting_value: str):
        """ Verifies color palette of links and buttons inside "Plugin Rules" folder """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "color" if element_type == "Link" else "background"

        plugin_rule_page = PluginRulesPage()
        plugin_rule_page.select_all.check()
        plugin_rule_list = PluginRulesList()

        if element_type == "Link":
            assert get_color_code_of_ui_element(element=plugin_rule_list.clear_selected_items_link,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, plugin_rule_list.clear_selected_items_link, element_color_dict[setting_value][0])

            all_plugin_rules = plugin_rule_list.get_plugin_id()

            for plugin_rule_id in all_plugin_rules:
                plugin_rule_list.delete_plugin_rule(plugin_id=plugin_rule_id)

            assert get_color_code_of_ui_element(element=plugin_rule_page.new_plugin_rule_link,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, plugin_rule_page.new_plugin_rule_link, element_color_dict[setting_value][0])
        else:
            assert get_color_code_of_ui_element(element=plugin_rule_page.new_rule_button,
                                                css_property=css_property) == element_color_dict[setting_value][2], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, plugin_rule_page.new_rule_button, element_color_dict[setting_value][2])

            assert get_color_code_of_ui_element(element=plugin_rule_page.delete_button, css_property=css_property) == \
                   element_color_dict[setting_value][1], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, plugin_rule_page.delete_button, element_color_dict[setting_value][1])

            plugin_rule_page.delete_button.click()
            delete_plugin_rule_modal = ActionCloseModal()
            wait(lambda: delete_plugin_rule_modal.is_element_present("modal"), waiting_for="modal to open")

            assert get_color_code_of_ui_element(element=delete_plugin_rule_modal.action_button,
                                                css_property=css_property) == element_color_dict[setting_value][2], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, delete_plugin_rule_modal.action_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=delete_plugin_rule_modal.cancel_button,
                                                css_property=css_property) == expected_color, \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, delete_plugin_rule_modal.cancel_button, expected_color)

            delete_plugin_rule_modal.cancel_button.click()

    @staticmethod
    def verify_links_and_buttons_inside_linked_agents(element_type: str, setting_value: str):
        """ Verifies color palette of links and buttons inside "Linked Agents" folder """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "color" if element_type == "Link" else "background"
        linked_agents_page = AgentsPage()

        if element_type == "Link":
            expected_color = element_color_dict[setting_value][0]

            assert get_color_code_of_ui_element(element=linked_agents_page.agents_setup_instructions,
                                                css_property=css_property) == expected_color, \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, linked_agents_page.agents_setup_instructions, expected_color)
        else:
            assert get_color_code_of_ui_element(element=linked_agents_page.export_button,
                                                css_property=css_property) == element_color_dict[setting_value][1], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, linked_agents_page.export_button, element_color_dict[setting_value][1])

    @staticmethod
    def verify_links_and_buttons_inside_agent_groups(element_type: str, setting_value: str):
        """ Verifies color palette of links and buttons inside "Agent Groups" folder """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "color" if element_type == "Link" else "background"
        agent_group_page = AgentGroupsPage()

        if element_type == "Link":
            for web_element in [agent_group_page.new_group_link, agent_group_page.description_link]:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][0], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][0])
        else:
            assert get_color_code_of_ui_element(element=agent_group_page.new_group_button,
                                                css_property=css_property) == element_color_dict[setting_value][2], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, agent_group_page.new_group_button, element_color_dict[setting_value][2])

    @staticmethod
    def verify_links_and_buttons_inside_agent_clustering(element_type: str, setting_value: str):
        """ Verifies color palette of links and buttons inside "Agent Clustering" folder """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "color" if element_type == "Link" else "background"
        agent_cluster_page = AgentClusterMigration()

        if element_type == "Link":
            assert get_color_code_of_ui_element(element=agent_cluster_page.cluster_migration_link,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, agent_cluster_page.cluster_migration_link, element_color_dict[setting_value][0])
        else:
            assert get_color_code_of_ui_element(element=agent_cluster_page.save_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, agent_cluster_page.save_button, element_color_dict[setting_value][2])

    @staticmethod
    def verify_links_and_buttons_inside_freeze_windows(nessus_api: NessusAPI, element_type: str, setting_value: str):
        """ Verifies color palette of links and buttons inside "Freeze Windows" folder """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "color" if element_type == "Link" else "background"
        freeze_window = AgentBlackoutWindowsPage()

        freeze_window_list = nessus_api.agents.exclusions_list()['exclusions']
        existing_freeze_windows_id = [exclusion['id'] for exclusion in freeze_window_list]

        for freeze_window_id in existing_freeze_windows_id:
            nessus_api.agents.remove_exclusion(exclusion_id=freeze_window_id)

        if element_type == "Link":
            assert get_color_code_of_ui_element(element=freeze_window.create_new_freeze_window,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, freeze_window.create_new_freeze_window, element_color_dict[setting_value][0])
        else:
            assert get_color_code_of_ui_element(element=freeze_window.new_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, freeze_window.new_button, element_color_dict[setting_value][2])

            freeze_window.new_button.click()
            create_freeze_window = CreateBlackoutWindowPage()
            wait(lambda: create_freeze_window.is_element_present("enable_toggle_button"),
                 waiting_for="freeze window page gets loaded properly")

            create_freeze_window.name_field.value = random_name(prefix=Nessus.FreezeWindows.FREEZE_WINDOW + "-")

            assert get_color_code_of_ui_element(element=create_freeze_window.toggle_switch,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, create_freeze_window.toggle_switch, element_color_dict[setting_value][0])

            assert get_color_code_of_ui_element(element=create_freeze_window.save_button,
                                                css_property=css_property) == element_color_dict[setting_value][2], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, create_freeze_window.save_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=create_freeze_window.cancel_button,
                                                css_property=css_property) == expected_color, \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, create_freeze_window.cancel_button, expected_color)

            create_freeze_window.cancel_button.click()
            freeze_windows_list = AgentBlackoutWindowList()
            freeze_windows_list.loaded()

            create_freeze_window_via_api(api=nessus_api)
            freeze_windows_list.refresh()
            freeze_windows_list.loaded()
            freeze_windows_list.select_all_checkbox.check()

            expected_elements = [freeze_window.freeze_window_button_bar] if setting_value == Nessus.AdvancedSettings. \
                LIGHT_MODE else [freeze_window.disable_button, freeze_window.delete_button]

            for web_element in expected_elements:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][1], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][1])

                if setting_value == Nessus.AdvancedSettings.DARK_MODE:
                    web_element.click()
                    freeze_window_modal = ActionCloseModal()
                    wait(lambda: freeze_window_modal.is_element_present("modal"), waiting_for="modal to open")

                    assert get_color_code_of_ui_element(element=freeze_window_modal.action_button,
                                                        css_property=css_property) == \
                           element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' " \
                                                                 "element. Expected should be :: '{}'".format(
                        setting_value, freeze_window_modal.action_button, element_color_dict[setting_value][2])

                    expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                        DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

                    assert get_color_code_of_ui_element(element=freeze_window_modal.cancel_button,
                                                        css_property=css_property) == expected_color, \
                        "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                            setting_value, freeze_window_modal.cancel_button, expected_color)

                    freeze_window_modal.cancel_button.click()

    @staticmethod
    def verify_links_and_buttons_inside_user_groups(nessus_api: NessusAPI, element_type: str, setting_value: str):
        """ Verifies color palette of links and buttons inside "Groups" folder """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "color" if element_type == "Link" else "background"
        group_page = GroupsPage()

        if not group_page.is_element_present("create_a_new_group_link"):
            existing_groups = nessus_api.groups.get_groups()['groups']
            existing_groups_id = [group['id'] for group in existing_groups]
            nessus_api.groups.bulk_delete(group_list=existing_groups_id)

        group_page.refresh()
        wait(lambda: group_page.is_element_present("create_a_new_group_link"),
             waiting_for="'Create a new group' link gets displayed")

        if element_type == "Link":
            assert get_color_code_of_ui_element(element=group_page.create_a_new_group_link,
                                                css_property=css_property) == element_color_dict[setting_value][0], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, group_page.create_a_new_group_link, element_color_dict[setting_value][0])
        else:
            assert get_color_code_of_ui_element(element=group_page.new_group_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, group_page.new_group_button, element_color_dict[setting_value][2])

            nessus_api.groups.create(name=random_name(prefix='Group-'))
            group_page.refresh()

            group_list = GroupList()
            group_list.loaded()
            group_list.select_all_checkbox.check()

            for web_element in [group_page.edit_button, group_page.delete_button]:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][1], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][1])

            group_page.new_group_button.click()
            new_group_modal = ActionCloseModal()
            wait(lambda: new_group_modal.is_element_present("modal"), waiting_for="modal to open")

            assert get_color_code_of_ui_element(element=new_group_modal.action_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, new_group_modal.action_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=new_group_modal.cancel_button, css_property=css_property) == \
                   expected_color, "Got different color in '{}' ui theme for '{}' element. Expected should " \
                                   "be :: '{}'".format(setting_value, new_group_modal.cancel_button, expected_color)

            new_group_modal.cancel_button.click()

    @staticmethod
    def verify_buttons_inside_all_settings_side_navigation_options(side_nav_option: str, setting_value: str):
        """ Verifies color palette of buttons inside all side navigation options under "Settings" tab """
        element_color_dict = Nessus.AdvancedSettings.UIThemeColors.ELEMENT_COLOR_DICT
        css_property = "background"

        if side_nav_option == Nessus.SideNavSettings.ABOUT:
            about_page = About()

            assert get_color_code_of_ui_element(element=about_page.download_log, css_property=css_property) == \
                   element_color_dict[setting_value][1], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, about_page.download_log, element_color_dict[setting_value][1])

            about_page.download_log.click()
            download_logs_modal = ActionCloseModal()
            wait(lambda: download_logs_modal.is_element_present("modal"), waiting_for="modal to open")

            assert get_color_code_of_ui_element(element=about_page.download_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, about_page.download_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=about_page.download_cancel_button,
                                                css_property=css_property) == expected_color, \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, about_page.download_cancel_button, expected_color)

            about_page.download_cancel_button.click()

        elif side_nav_option == Nessus.SideNavSettings.ADVANCED:
            advanced_setting_page = AdvancedSettingsPage()

            assert get_color_code_of_ui_element(element=advanced_setting_page.new_button,
                                                css_property=css_property) == element_color_dict[setting_value][2], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, advanced_setting_page.new_button, element_color_dict[setting_value][2])

            advanced_setting_page.new_button.click()
            add_setting_modal = ActionCloseModal()
            wait(lambda: add_setting_modal.is_element_present("modal"), waiting_for="modal to open")

            assert get_color_code_of_ui_element(element=add_setting_modal.action_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, add_setting_modal.action_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=add_setting_modal.cancel_button, css_property=css_property) == \
                   expected_color, "Got different color in '{}' ui theme for '{}' element. Expected should " \
                                   "be :: '{}'".format(setting_value, add_setting_modal.cancel_button, expected_color)

            add_setting_modal.cancel_button.click()

        elif side_nav_option == Nessus.SideNavSettings.LDAP_SERVER:
            ldap_server_page = LdapServerPage()

            assert get_color_code_of_ui_element(element=ldap_server_page.save_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, ldap_server_page.save_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=ldap_server_page.cancel_button,
                                                css_property=css_property) == expected_color, \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, ldap_server_page.cancel_button, expected_color)

            assert get_color_code_of_ui_element(element=ldap_server_page.test_ldap_server_btn,
                                                css_property=css_property) == element_color_dict[setting_value][1], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, ldap_server_page.test_ldap_server_btn, element_color_dict[setting_value][1])

        elif side_nav_option == Nessus.SideNavSettings.PROXY_SERVER:
            proxy_server_page = ProxyServer()

            assert get_color_code_of_ui_element(element=proxy_server_page.save_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, proxy_server_page.save_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=proxy_server_page.cancel_button,
                                                css_property=css_property) == expected_color, \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, proxy_server_page.cancel_button, expected_color)

            assert get_color_code_of_ui_element(element=proxy_server_page.test_proxy_server,
                                                css_property=css_property) == element_color_dict[setting_value][1], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, proxy_server_page.test_proxy_server, element_color_dict[setting_value][1])

        elif side_nav_option == Nessus.SideNavSettings.SMTP_SERVER:
            smtp_server_page = SmtpServerPage()

            assert get_color_code_of_ui_element(element=smtp_server_page.save_settings, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, smtp_server_page.save_settings, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=smtp_server_page.cancel_button,
                                                css_property=css_property) == expected_color, \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, smtp_server_page.cancel_button, expected_color)

            assert get_color_code_of_ui_element(element=smtp_server_page.send_test_email,
                                                css_property=css_property) == element_color_dict[setting_value][1], \
                "Got different color in '{}' ui theme for '{}' element. Expected should be :: '{}'".format(
                    setting_value, smtp_server_page.send_test_email, element_color_dict[setting_value][1])

        elif side_nav_option == Nessus.SideNavSettings.UPGRADE_ASSISTANT:
            upgrade_assistance_page = UpgradeAssistantPage()

            for web_element in [upgrade_assistance_page.upgrade_now_button,
                                upgrade_assistance_page.sign_up_first_button]:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][2])

        elif side_nav_option == Nessus.SideNavSettings.PASSWORD_MGMT:
            pwd_mgmnt_page = PasswordManagement()
            pwd_mgmnt_page.password_complexity_switch.click()
            pwd_mgmnt_page.login_notification_switch.click()
            sleep(WAIT_NORMAL, reason="It takes little bit time to switch toggle buttons")

            assert get_color_code_of_ui_element(element=pwd_mgmnt_page.save_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, pwd_mgmnt_page.save_button, element_color_dict[setting_value][2])

            expected_color = element_color_dict[setting_value][1] if setting_value == Nessus.AdvancedSettings. \
                DARK_MODE else Nessus.AdvancedSettings.UIThemeColors.LightTheme.WHITE_BUTTON_COLOR

            assert get_color_code_of_ui_element(element=pwd_mgmnt_page.cancel_button, css_property=css_property) == \
                   expected_color, "Got different color in '{}' ui theme for '{}' element. Expected should " \
                                   "be :: '{}'".format(setting_value, pwd_mgmnt_page.cancel_button, expected_color)

            for web_element in [pwd_mgmnt_page.password_complexity_toggle, pwd_mgmnt_page.login_notification_toggle]:
                assert get_color_code_of_ui_element(element=web_element, css_property=css_property) == \
                       element_color_dict[setting_value][0], "Got different color in '{}' ui theme for '{}' element. " \
                                                             "Expected should be :: '{}'".format(
                    setting_value, web_element, element_color_dict[setting_value][0])

        elif side_nav_option == Nessus.Accounts.USERS:
            user_page = UsersPage()

            assert get_color_code_of_ui_element(element=user_page.new_user_button, css_property=css_property) == \
                   element_color_dict[setting_value][2], "Got different color in '{}' ui theme for '{}' element. " \
                                                         "Expected should be :: '{}'".format(
                setting_value, user_page.new_user_button, element_color_dict[setting_value][2])

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize("import_policy_via_api", [
        {"file_name": 'Advanced_all_plugIns_with_compliance.nessus', "file_path": 'nessus/tests/ui/scans/test_data/'}],
                             indirect=True)
    @pytest.mark.parametrize('create_plugin_rules', [{'plugin_list': [
        {"host": '127.0.0.1', "plugin_id": random.randint(1000, 2000), "type": "recast_critical"}]}], indirect=True)
    @pytest.mark.parametrize('setting_value', [Nessus.AdvancedSettings.DARK_MODE, Nessus.AdvancedSettings.LIGHT_MODE])
    @pytest.mark.parametrize('element_type', ["Link", "Button"])
    def test_verify_color_palette_of_links_and_buttons_in_nessus(self, import_scan_via_api, import_policy_via_api,
                                                                 create_plugin_rules, setting_value, element_type):
        """
        NES-13239 [Automation]: Verify the color palette of buttons and links in whole Nessus.

        Scenario Tested:
        [x] Verify the color palette for buttons and links in whole Nessus after changing "ui theme" value.
        """
        NotificationActions().remove_all()
        scan_name = import_scan_via_api[0]
        policy_name = import_policy_via_api

        modify_existing_advanced_setting(setting_tab=Nessus.AdvancedSettings.USER_INTERFACE_TAB,
                                         setting_name=Nessus.AdvancedSettings.UI_THEME, setting_value=setting_value)
        sleep(WAIT_LONG, reason="It takes little bit time to get impact of 'ui_theme' setting")

        NotificationActions().remove_all()

        header_base_page = HeaderBasePage()

        dom_element_dict = {
            "Scans": [Nessus.Scan.Folder.MY_SCANS, Nessus.Scan.Folder.TRASH, Nessus.SideNavResources.POLICIES,
                      Nessus.SideNavResources.PLUGIN_RULES],
            "Settings": [Nessus.SideNavSettings.ABOUT, Nessus.SideNavSettings.ADVANCED,
                         Nessus.SideNavSettings.PROXY_SERVER, Nessus.SideNavSettings.UPGRADE_ASSISTANT,
                         Nessus.SideNavSettings.SMTP_SERVER, Nessus.SideNavSettings.PASSWORD_MGMT]}

        manager_dom_element_dict = {
            "Sensors": [Nessus.SideNavResources.LINKED_AGENTS, Nessus.SideNavResources.AGENT_GROUPS,
                        Nessus.SideNavResources.AGENT_CLUSTERING, Nessus.SideNavResources.FREEZE_WINDOWS]}

        if is_manager():
            dom_element_dict.update(manager_dom_element_dict)
            dom_element_dict["Settings"].extend([Nessus.Accounts.USERS, Nessus.Accounts.GROUPS,
                                                 Nessus.SideNavSettings.LDAP_SERVER])

        if is_home():
            dom_element_dict["Settings"].remove(Nessus.SideNavSettings.UPGRADE_ASSISTANT)

        for module_name in dom_element_dict.keys():
            module_element_dict = {"Scans": header_base_page.scan_link, "Settings": header_base_page.settings_link}

            if is_manager():
                module_element_dict.update({"Sensors": header_base_page.sensors_tab})

            module_element_dict[module_name].click()
            sleep(WAIT_NORMAL, reason="Page gets loaded properly")

            for sub_module_name in list(dom_element_dict[module_name]):
                SideNav().get_sidenav_element(element_name=sub_module_name).click()
                sleep(WAIT_NORMAL, reason="Waiting for '{}' gets loaded properly".format(sub_module_name))

                if sub_module_name == Nessus.Scan.Folder.MY_SCANS:
                    self.verify_links_and_buttons_inside_my_scans_folder(scan_name=scan_name, element_type=element_type,
                                                                         setting_value=setting_value)

                elif sub_module_name == Nessus.Scan.Folder.TRASH:
                    self.verify_links_and_buttons_inside_trash_folder(element_type=element_type,
                                                                      setting_value=setting_value)

                elif sub_module_name == Nessus.SideNavResources.POLICIES:
                    self.verify_links_and_buttons_inside_policies_folder(
                        policy_name=policy_name, element_type=element_type, setting_value=setting_value)

                elif sub_module_name == Nessus.SideNavResources.PLUGIN_RULES:
                    self.verify_links_and_buttons_inside_plugin_rules_folder(element_type=element_type,
                                                                             setting_value=setting_value)

                elif sub_module_name == Nessus.SideNavResources.LINKED_AGENTS:
                    self.verify_links_and_buttons_inside_linked_agents(element_type=element_type,
                                                                       setting_value=setting_value)

                elif sub_module_name == Nessus.SideNavResources.AGENT_GROUPS:
                    self.verify_links_and_buttons_inside_agent_groups(element_type=element_type,
                                                                      setting_value=setting_value)

                elif sub_module_name == Nessus.SideNavResources.AGENT_CLUSTERING:
                    self.verify_links_and_buttons_inside_agent_clustering(element_type=element_type,
                                                                          setting_value=setting_value)

                elif sub_module_name == Nessus.SideNavResources.FREEZE_WINDOWS:
                    self.verify_links_and_buttons_inside_freeze_windows(
                        nessus_api=self.cat.api, element_type=element_type, setting_value=setting_value)

                elif sub_module_name in [Nessus.SideNavSettings.ABOUT, Nessus.SideNavSettings.ADVANCED,
                                         Nessus.SideNavSettings.LDAP_SERVER, Nessus.SideNavSettings.PROXY_SERVER,
                                         Nessus.SideNavSettings.SMTP_SERVER, Nessus.Accounts.USERS,
                                         Nessus.SideNavSettings.UPGRADE_ASSISTANT,
                                         Nessus.SideNavSettings.PASSWORD_MGMT]:
                    if element_type == "Button":
                        self.verify_buttons_inside_all_settings_side_navigation_options(
                            side_nav_option=sub_module_name, setting_value=setting_value)

                elif sub_module_name == Nessus.Accounts.GROUPS:
                    self.verify_links_and_buttons_inside_user_groups(nessus_api=self.cat.api, element_type=element_type,
                                                                     setting_value=setting_value)

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'file_path': 'nessus/tests/ui/scans/test_data/',
         'password': 'nessus', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('setting_value', [Nessus.AdvancedSettings.DARK_MODE, Nessus.AdvancedSettings.LIGHT_MODE])
    @pytest.mark.parametrize('element_type', ["Link", "Button"])
    def test_verify_color_palette_of_links_and_buttons_after_configuring_scan(self, import_scan_via_api, setting_value,
                                                                              element_type):
        """
        NES-13239 [Automation]: Verify the color palette of buttons and links in whole Nessus.

        Scenario Tested:
        [x] Verify the color palette for buttons and links after configuring scan.
        """
        NotificationActions().remove_all()
        modify_existing_advanced_setting(setting_tab=Nessus.AdvancedSettings.USER_INTERFACE_TAB,
                                         setting_name=Nessus.AdvancedSettings.UI_THEME, setting_value=setting_value)
        sleep(WAIT_LONG, reason="It takes little bit time to get impact of 'ui_theme' setting")

        NotificationActions().remove_all()

        HeaderBasePage().scan_link.click()

        scan_name = import_scan_via_api[0]
        ScanList().click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: visibility_of_element_located(scan_view_page.configure_button),
             waiting_for='Scan view page to load')

        NotificationActions().remove_all()
        scan_view_page.configure_button.click()
        scan_form_page = NewScanForm()
        wait(lambda: scan_form_page.is_element_present('name_field'), timeout_seconds=TIME_THIRTY_SECONDS,
             sleep_seconds=WAIT_NORMAL, waiting_for="Scan configure page to get loaded properly.")

        edited_scan_name = "Edited " + scan_name
        scan_form_page.name_field.clear()
        scan_form_page.name_field.value = edited_scan_name
        scan_form_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'There is no notification for editing shared scan'

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        sleep(WAIT_NORMAL, reason="Page gets loaded properly")

        self.verify_links_and_buttons_inside_my_scans_folder(scan_name=edited_scan_name, element_type=element_type,
                                                             setting_value=setting_value)
