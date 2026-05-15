"""
Nessus advanced settings related helper functions

:copyright: Tenable Network Security, 2017
:date: June 04, 2021
:modified: June 09, 2021
:author: @kpanchal
"""
from random import randint

from selenium.webdriver.remote.webelement import WebElement

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import WAIT_LONG
from catium.lib.log.log import create_logger
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AddAdvancedSettingModal, \
    AdvancedSettingsList

log = create_logger()


def change_default_value_from_setting_dropdown(setting_name: str, default_value: str, setting_tab: str = None) -> str:
    """
    Helper function to select and change the dropdown value(other than the default value) in setting banner for given
    setting name in given setting tab.

    :param str setting_name: Name of the setting i.e. "login_banner".
    :param str default_value: Default value of setting
    :param str setting_tab: Setting sub tab name i.e. "Custom"
    :return: str
    """
    if setting_tab:
        AdvancedSettingsPage().get_settings_tab_element(setting_tab=setting_tab).click()

    add_advanced_setting_modal = AddAdvancedSettingModal()
    add_advanced_setting_modal.find_specific_setting_name(setting_name=setting_name).click()

    if add_advanced_setting_modal.is_element_present("allow_post_scan_edit_dropdown"):
        new_setting_value = [option['label'] for option in
                             add_advanced_setting_modal.allow_post_scan_edit_dropdown.option_values if
                             default_value != option['label']][0]
        add_advanced_setting_modal.allow_post_scan_edit_dropdown.select_by_visible_text(new_setting_value)
    else:
        if "/" in default_value or setting_name in ["path_to_java"]:
            add_advanced_setting_modal.advanced_setting_value.value = '/opt/nessus/test'
        elif default_value.isdigit() or setting_name in ["java_heap_size", "attached_report_maximum_size"] or \
                "port" in setting_name:
            value_to_be_enter = randint(26, 49) if setting_name == "attached_report_maximum_size" else 123

            add_advanced_setting_modal.advanced_setting_value.value = value_to_be_enter
        else:
            add_advanced_setting_modal.advanced_setting_value.value = 'TestValue'

    add_advanced_setting_modal.action_button.click()
    add_advanced_setting_modal.wait_for_modal_closed()
    sleep(WAIT_LONG, reason="Setting value takes little bit time to get updated.")

    return AdvancedSettingsList().get_settings_value(setting_name=setting_name)[0]


def convert_rgb_to_hex(rgb: str) -> str:
    """ Helper function to convert rgb color code (rgb(245, 245, 245)) to hex (#abcdef) """
    split_rgb = rgb[rgb.find('(') + 1:rgb.find(')')].split(", ")

    return "#{:02x}{:02x}{:02x}".format(int(split_rgb[0]), int(split_rgb[1]), int(split_rgb[2])).upper()


def get_color_code_of_ui_element(element: WebElement, css_property: str) -> str:
    """ Returns color code of given UI Web element """
    return convert_rgb_to_hex(rgb=element.value_of_css_property(css_property))
