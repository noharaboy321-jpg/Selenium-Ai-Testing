"""
Nessus UI Settings Helpers

:copyright: Tenable Network Security, 2017
:date: March 28, 2018
:last_modified: Feb 28, 2022
:author: @ntarwani, @yshah, @kpanchal
"""
import time

from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_NORMAL, TIME_FIVE_SECONDS, TIME_FIFTEEN_MINUTES, TIME_THIRTY_MINUTES
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS, WAIT_LONG, TIME_FIVE_MINUTES, \
    TIME_TEN_MINUTES, TIME_TEN_SECONDS, TIME_THIRTY_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import API
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AddAdvancedSettingModal, \
    AdvancedSettingsList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.setup.setup_page import SetupCommonPoints
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


def handle_connection_popup(timeout_to_appear: int, timeout_to_disappear: int) -> None:
    """If the connection pop up appears use a different strategy. DEPRECATED"""
    log.debug('handle_connection_popup: Sleeping for 0.5 seconds.')
    time.sleep(0.5)


def required_for_settings_effective():
    """Covers steps required for add or edit advanced settings to be effective"""
    LoadingCircle(WAIT_NORMAL)

    api = NessusAPI()
    api.login()
    api.server.restart()
    LoadingCircle(WAIT_NORMAL)

    handle_connection_popup(timeout_to_appear=TIME_FIFTEEN_MINUTES, timeout_to_disappear=TIME_THIRTY_MINUTES)

    # Wait till server is ready
    log.debug("Waiting for server to be READY")
    wait_for_scanner_status(api=api, status=API.Status.READY,
                            timeout=TIME_FIFTEEN_MINUTES, msg='Availability of Nessus scanner',
                            sleep_interval=TIME_FIVE_SECONDS)
    log.debug("Server is READY")


def add_advanced_setting(setting_name: str, setting_value: str) -> None:
    """
    Helper for add advanced setting on UI
    :param str setting_name: Setting name to be added
    :param str setting_value: Setting value to be set
    :return: None
    """
    advanced_setting_page = AdvancedSettingsPage()
    advanced_setting_page.js_scroll_into_view(element=advanced_setting_page.new_button)

    advanced_setting_page.new_button.click()
    wait(lambda: ActionCloseModal().is_element_present('modal'), waiting_for='add setting modal')

    AddAdvancedSettingModal().add_setting(setting_name=setting_name, setting_value=setting_value)


def delete_advanced_setting(setting_name: str) -> None:
    """
    Helper for delete advanced setting on UI
    :param str setting_name: name of the setting to be deleted
    :return: None
    """
    advanced_setting_list = AdvancedSettingsList()
    advanced_setting_list.loaded()
    advanced_setting_list.delete_custom_setting(setting_name)


def login_helper_after_server_restart() -> None:
    """ This function will login as per condition"""
    login_page = LoginPage()
    user_menu = UserMenu()

    if login_page.is_element_present('username_field', timeout=TIME_SIXTY_SECONDS):
        login_page.login_with_defaults()
    elif not user_menu.is_element_present('user_menu_dropdown', timeout=TIME_SIXTY_SECONDS):
        get_driver_no_init().refresh()
        login_page.login_with_defaults()
    else:
        user_menu.logout()
        login_page.login_with_defaults()

    user_menu.loaded()


def manage_server_restart_task() -> None:
    """ This function will handle server restart task """
    login_page = LoginPage()
    sleep(sleep_time=TIME_TEN_SECONDS, reason="waiting for reload to start")
    wait_for_scanner_status(api=NessusAPI(), timeout=TIME_THIRTY_MINUTES, status=API.Status.READY,
                            msg='Waiting for server to be in ready state.', sleep_interval=TIME_THIRTY_SECONDS)

    get_driver_no_init().refresh()

    if SetupCommonPoints().is_element_present("nessus_icon", timeout=TIME_THIRTY_SECONDS):
        login_page.is_element_present('username_field', timeout=TIME_SIXTY_SECONDS)

    get_driver_no_init().refresh()

    if login_page.is_element_present('username_field', timeout=TIME_SIXTY_SECONDS):
        login_helper_after_server_restart()


def modify_existing_advanced_setting(setting_tab: str, setting_name: str, setting_value: str) -> None:
    """
    Modifies existing advanced setting from given setting tab.

    :param str setting_tab: advanced setting tab name
    :param str setting_name: advanced setting name
    :param str setting_value: advanced setting value
    :return: None
    """
    advanced_setting_list = AdvancedSettingsList()

    if not get_driver_no_init().current_url.endswith("/settings/advanced"):
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()

        wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
             waiting_for='Advanced settings list to load.')
        advanced_setting.get_settings_tab_element(setting_tab=setting_tab).click()

    is_restart_required = setting_name in advanced_setting_list.get_setting_name_requires_restart(
        setting_tab=setting_tab)

    advanced_setting_modal = AddAdvancedSettingModal()
    advanced_setting_modal.reset_setting_banner(setting_name=setting_name)
    sleep(WAIT_LONG, reason="Setting value takes little bit time to get updated.")

    advanced_setting_modal.find_specific_setting_name(setting_name=setting_name).click()
    is_drop_down = advanced_setting_modal.is_element_present('allow_post_scan_edit_dropdown')

    if is_drop_down:
        advanced_setting_modal.allow_post_scan_edit_dropdown.select_by_visible_text(setting_value)
    else:
        advanced_setting_modal.input_field_setting_banner.clear()
        advanced_setting_modal.input_field_setting_banner.value = setting_value

    action_modal = ActionCloseModal()
    action_modal.accept_action()
    action_modal.wait_for_modal_closed()

    if is_restart_required:
        wait(lambda: advanced_setting.is_element_present('service_restart_link'),
             waiting_for='Service restart link to visible')
        advanced_setting.service_restart_link.click()
        manage_server_restart_task()
        sleep(sleep_time=WAIT_LONG, reason="Page takes little bit time to be stable")
