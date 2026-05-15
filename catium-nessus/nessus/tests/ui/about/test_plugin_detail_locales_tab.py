"""
Nessus test cases related to Plugin Detail Locales tab

Test cases to verify plugin locales is downloaded and values can assign as per the requirements

:copyright: Tenable Network Security, 2024
:date: Aug 08, 2024
:author: @krpatel
"""

import pytest
from nessus.helpers.utility import get_downloaded_files_chrome
from catium.lib.log import create_logger

from nessus.pageobjects.scans.scans_page import ScanList, ScansPage

from nessus.pageobjects.scans.scan_view_page import ScanViewPage

from nessus.pageobjects.sidenav.sidenav import SideNav

from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located

from catium.lib.const import WAIT_SHORT, WAIT_TINY, WAIT_NORMAL
from catium.lib.ssh import SSH
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.lib.const import Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import PluginDetailLocale, About, OverView, get_plugin_locales_labels
from nessus.pageobjects.header.notifications import Notifications

log = create_logger()


@pytest.mark.serial
@pytest.mark.nessus_settings_1
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('login')
class TestPluginLocales:
    """
    Covers Plugin Locals tab related test cases in about page under Settings.
    """

    @pytest.mark.xray(test_key='NES-18467')
    @pytest.mark.serial
    def test_plugin_locales_tab_and_page(self):
        """
        [NES-18467] : Validate the plugin details locales tab and the page.

        Test covered :
            [x] Plugin detail locales tab is available
            [x] Plugin detail locales tab is Clickable
            [x] Elements of Plugin detail locales page is as per design.
        """
        plugin_locale_page = PluginDetailLocale()
        about_page = About()
        about_page.open()
        wait(lambda: OverView().is_element_present('update_activation_code_tip'), waiting_for='about page to get load')
        assert visibility_of_element_located((plugin_locale_page.plugin_locals_tab.we_by,
                                              plugin_locale_page.plugin_locals_tab.we_value))(get_driver_no_init()), \
            "plugin_locals tab is invisible."

        wait(lambda: expected_conditions.element_to_be_clickable(plugin_locale_page.plugin_locals_tab),
             timeout_seconds=WAIT_SHORT, sleep_seconds=WAIT_TINY), "plugin local tab is not clickable within a second."
        plugin_locale_page.plugin_locals_tab.click()

        wait(lambda: get_plugin_locales_labels(
            element=plugin_locale_page.page_lables) == Nessus.About.PluginLocales.TAB_HEADER,
             timeout_seconds=WAIT_NORMAL)
        assert all(
            [Nessus.About.PluginLocales.TAB_HEADER == get_plugin_locales_labels(element=plugin_locale_page.page_lables),
             plugin_locale_page.checkbox.is_displayed(),
             Nessus.About.PluginLocales.CHECKBOX_DESCRIPTION == plugin_locale_page.checkbox_description.text,
             Nessus.About.PluginLocales.LOCALES_HINT == plugin_locale_page.locales_hint.text]), \
            'Plugin locales information is not as expected.'

    @pytest.mark.xray(test_key='NES-18465')
    @pytest.mark.xray(test_key='NES-18462')
    @pytest.mark.xray(test_key='NES-17926')
    @pytest.mark.serial
    def test_enabling_the_plugin_locales_via_UI(self):
        """
        [NES-18462] : Validate enabling the plugin_locales checkbox on UI.
        [NES-17926] : Validate UI setting for plugin_detail_locale default value.
        [NES-18465] : Validate disabling the plugin_detail_locale

        Test covered :
            [x] Enable the checkbox of plugin locales.
            [x] disabled sections are accessible after enabling.
            [x] English is set as default language
            [x] disabled the plugin locales via UI

        """
        plugin_locale_page = PluginDetailLocale()
        plugin_locale_page.open()

        wait(lambda: plugin_locale_page.is_element_present("checkbox"), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        if 'checked' not in plugin_locale_page.checkbox.get_css_classes():
            plugin_locale_page.checkbox.click()

            assert not plugin_locale_page.is_element_present(
                "disabled_en"), "Plugin locales is not checked yet properly"

            plugin_locale_page.save_button.click()
            assert Notifications().successes[-1] \
                   == Messages.NotificationMessages.PluginLocales.locales_saved_successfully, \
                   'Successful message for plugin locales saved is mismatched or not shown.'
        assert all([plugin_locale_page.is_element_present('enabled_en'),
                    plugin_locale_page.is_element_present('select_locale_input')]), \
            "Disabled part is still not enabled even after enabling the plugin locales"
        assert 'checked' in plugin_locale_page.enabled_en.get_css_classes(), 'English language is not checked by default'

        plugin_locale_page.open()
        wait(lambda: plugin_locale_page.is_element_present("checkbox"), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        plugin_locale_page.checkbox.click()

        assert plugin_locale_page.is_element_present(
            "disabled_en"), "Plugin locales is not checked yet properly"

        plugin_locale_page.save_button.click()
        action_modal = ActionCloseModal()
        assert action_modal.is_element_present('modal'), 'warning modal is not available'

        action_modal.action_button.click()
        action_modal.wait_for_modal_closed(timeout_seconds=WAIT_NORMAL)

    @pytest.mark.xray(test_key='NES-17860')
    @pytest.mark.serial
    @pytest.mark.usefixtures('nessus_api_login', 'import_scan_via_api')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'cvssv4_test_plugin_scan.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    def test_dropdown_not_in_report_after_disabling_locales(self, import_scan_via_api):
        """
        [NES-17860] : Test UI: New dropdown in report modal to choose alternative locale for a single report

        Test covered :
            [x] Locales dropdown is not available on report modal until enable the locales.
        """
        plugin_locale_page = PluginDetailLocale()
        plugin_locale_page.open()

        wait(lambda: plugin_locale_page.is_element_present("checkbox"), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        if 'checked' in plugin_locale_page.checkbox.get_css_classes():
            plugin_locale_page.checkbox.click()
            assert plugin_locale_page.is_element_present(
                "disabled_en"), "Plugin locales is not checked yet properly"
            plugin_locale_page.save_button.click()
            action_modal = ActionCloseModal()
            assert action_modal.is_element_present('modal'), 'warning modal is not available'

            action_modal.action_button.click()
            action_modal.wait_for_modal_closed(timeout_seconds=WAIT_NORMAL)

        scan_name = import_scan_via_api[0]
        SideNav().scan_tab_on_header.click()
        scan_view_page = ScanViewPage()
        scan_list = ScanList()

        wait(lambda: visibility_of_element_located(scan_list.object_table),
             waiting_for='Wait for Scan lists to appear.')
        scan_list.click_on_scan(scan_name=scan_name)

        wait(lambda: visibility_of_element_located(scan_view_page.report_button),
             waiting_for='report button to appear on modal')
        scan_view_page.report_button.click()

        assert not plugin_locale_page.is_element_present(
            'report_modal_local_dropdown'), 'Plugin locales are available on report modal'

    @pytest.mark.xray(test_key='NES-18477')
    @pytest.mark.xray(test_key='NES-18464')
    @pytest.mark.serial
    def test_available_locales_and_entering_invalid_value_in_dropdown(self):
        """
        [NES-18464] : Validate plugin_detail_locale change to invalid value.
        [NES-18477] : Validate the locales available on dropdown.

        Test covered :
            [x] invalid values shows no results in dropdown.
            [x] 3 locales are available on dropdown.
        """
        plugin_locale_page = PluginDetailLocale()
        plugin_locale_page.open()

        wait(lambda: plugin_locale_page.is_element_present("locales_dropdown_textfield"), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        if 'checked' not in plugin_locale_page.checkbox.get_css_classes():
            plugin_locale_page.checkbox.click()
            assert not plugin_locale_page.is_element_present(
                "disabled_en"), "Plugin locales is not checked yet properly"

        plugin_locale_page.locales_dropdown_textfield.click()

        wait(lambda: plugin_locale_page.is_element_present("dropdown_area"), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)

        wait(lambda: get_plugin_locales_labels(
            element=plugin_locale_page.dropdown_labels) == Nessus.About.PluginLocales.AVAILABLE_LOCALES,
             timeout_seconds=WAIT_NORMAL)
        assert get_plugin_locales_labels(
            element=plugin_locale_page.dropdown_labels) == Nessus.About.PluginLocales.AVAILABLE_LOCALES, \
            "Expected 3 plugin locales are mismatched in dropdown"

        plugin_locale_page.locales_dropdown_textfield.value = random_name(prefix="xyz")
        wait(lambda: plugin_locale_page.is_element_present('no_result_dropdown'))

        assert plugin_locale_page.is_element_present('no_result_dropdown'), "Invalid string shows in dropdown"

    @pytest.mark.xray(test_key='NES-18478')
    @pytest.mark.xray(test_key='NES-18463')
    @pytest.mark.serial
    @pytest.mark.usefixtures('nessus_api_login', 'enable_plugin_locales')
    @pytest.mark.parametrize('locales_details', [
        pytest.param(['Japanese', 'ja']),
        pytest.param(['Chinese Simplified', 'zh_CN']),
        pytest.param(['Chinese Traditional', 'zh_TW'])])
    def test_selecting_valid_values_in_locales_dropdown(self, enable_plugin_locales, locales_details):
        """
        [NES-18463] : Validate selecting valid value from dropdown and check those are added as checkbox
        [NES-18478] : Validate warning popup when select valid value from dropdown save the default locales without changing radio button

        Test covered :
            [x] able to select the dropdown values in Locales.
            [x] selected value is showing as radio checkbox in default plugin locales section.
            [x] warning popup should have shown when selecting any locales
            [x] warning popup UI
        """

        plugin_locale_page = PluginDetailLocale()
        plugin_locale_page.open()

        plugin_locale_page.locales_dropdown_textfield.click()

        wait(lambda: plugin_locale_page.is_element_present("dropdown_area"), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        plugin_locale_page.select_dropdown_labels(element=locales_details[0])

        wait(lambda: plugin_locale_page.get_radio_buttons(element=locales_details[1]), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        assert plugin_locale_page.get_radio_buttons(
            element=locales_details[1]), "radio button for selected locales is not available."

        plugin_locale_page.save_button.click()
        action_modal = ActionCloseModal()
        assert action_modal.is_element_present('modal'), 'warning modal is not available'
        assert all([action_modal.modal_title.text == Nessus.About.PluginLocales.MODAL_TITLE,
                    action_modal.modal_content.text == Nessus.About.PluginLocales.MODAL_TEXT,
                    action_modal.is_element_present('modal_cancel'),
                    action_modal.is_element_present('close_button'),
                    action_modal.is_element_present('action_button')]), \
            "Warning popup elements are mismatched"

        action_modal.action_button.click()
        action_modal.wait_for_modal_closed(timeout_seconds=WAIT_NORMAL)
        assert Notifications().successes[-1] == Messages.NotificationMessages.PluginLocales.locales_saved_successfully, \
            'Successful message for plugin locales saved is mismatched or not shown.'

        wait(lambda: plugin_locale_page.is_element_present('remove_locales'), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        plugin_locale_page.remove_locales.click()
        wait(lambda: plugin_locale_page.is_element_present('select_locale_input'), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        plugin_locale_page.select_locale_input.click()
        plugin_locale_page.save_button.click()

        assert action_modal.is_element_present('modal'), 'warning modal is not available'
        action_modal.action_button.click()
        action_modal.wait_for_modal_closed(timeout_seconds=WAIT_NORMAL)
        assert Notifications().successes[-1] == Messages.NotificationMessages.PluginLocales.locales_saved_successfully, \
            'Successful message for plugin locales saved is mismatched or not shown.'

    @pytest.mark.xray(test_key='NES-18493')
    @pytest.mark.xray(test_key='NES-18482')
    @pytest.mark.xray(test_key='NES-18479')
    @pytest.mark.serial
    @pytest.mark.usefixtures('nessus_api_login', 'enable_plugin_locales', 'import_scan_via_api')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'cvssv4_test_plugin_scan.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.parametrize('locales_details', [
        pytest.param(['Japanese', 'ja', 'Japanese']),
        pytest.param(['Chinese Simplified', 'zh_CN', 'Chinese (Simplified)']),
        pytest.param(['Chinese Traditional', 'zh_TW', 'Chinese (Traditional)'])])
    def test_applying_selected_locales_as_default_and_check_on_report_page(self, enable_plugin_locales, locales_details, import_scan_via_api):
        """
        [NES-18479] : Validate applying selected locales as default and set back default to english.
        [NES-18482] : Validate warning popup when save the locales other than English language.
        [NES-18493] : Report modal is showing correct default locales after changing from settings.

        Test covered :
            [x] warning popup should have shown when apply any locales
            [x] locale should apply successfully
            [x] applied locales is showing as default on report modal page

        """
        plugin_locale_page = PluginDetailLocale()
        plugin_locale_page.open()

        wait(lambda: plugin_locale_page.is_element_present("locales_dropdown_textfield"), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)

        plugin_locale_page.locales_dropdown_textfield.click()

        wait(lambda: plugin_locale_page.is_element_present("dropdown_area"), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        plugin_locale_page.select_dropdown_labels(element=locales_details[0])

        wait(lambda: plugin_locale_page.get_radio_buttons(element=locales_details[1]), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        assert plugin_locale_page.get_radio_buttons(
            element=locales_details[1]), "radio button for selected locales is not available."

        plugin_locale_page.get_radio_buttons(element=locales_details[1]).click()

        plugin_locale_page.save_button.click()
        action_modal = ActionCloseModal()
        assert action_modal.is_element_present('modal'), 'warning modal is not available'
        assert all([action_modal.modal_title.text == Nessus.About.PluginLocales.MODAL_TITLE,
                    action_modal.modal_content.text == Nessus.About.PluginLocales.MODAL_TEXT1,
                    action_modal.is_element_present('modal_cancel'),
                    action_modal.is_element_present('close_button'),
                    action_modal.is_element_present('action_button')]), \
            "Warning popup elements are mismatched"

        action_modal.action_button.click()
        action_modal.wait_for_modal_closed(timeout_seconds=WAIT_NORMAL)
        assert Notifications().successes[-1] == Messages.NotificationMessages.PluginLocales.locales_saved_successfully, \
            'Successful message for plugin locales saved is mismatched or not shown.'

        scan_name = import_scan_via_api[0]
        SideNav().scan_tab_on_header.click()
        scan_view_page = ScanViewPage()
        scan_view_page.refresh()
        scan_list = ScanList()

        wait(lambda: visibility_of_element_located(scan_list.object_table),
             waiting_for='Wait for Scan lists to appear.')
        scan_list.click_on_scan(scan_name=scan_name)

        wait(lambda: visibility_of_element_located(scan_view_page.report_button),
             waiting_for='Vulnerability tab to appear on page')
        scan_view_page.report_button.click()

        wait(lambda: scan_view_page.is_element_present('locales_on_report_modal'),
             waiting_for="Report generation page to get load.")
        assert scan_view_page.is_element_present(
            'locales_on_report_modal'), 'locales dropdown is not available on report modal.'
        default_locale_on_report_page = plugin_locale_page.get_locale_on_report(locales_details[2])

        assert locales_details[
                   2] == default_locale_on_report_page.text, "default locale on report modal is not matched with actual setting."

        ScanList().refresh()
        ScanList().open()
        ScansPage().delete_all_scans()

        plugin_locale_page = PluginDetailLocale()
        plugin_locale_page.open()

        wait(lambda: plugin_locale_page.is_element_present('remove_locales'), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        plugin_locale_page.remove_locales.click()
        wait(lambda: plugin_locale_page.is_element_present('select_locale_input'), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)
        plugin_locale_page.select_locale_input.click()
        plugin_locale_page.save_button.click()

        assert action_modal.is_element_present('modal'), 'warning modal is not available'
        action_modal.action_button.click()
        action_modal.wait_for_modal_closed(timeout_seconds=WAIT_NORMAL)

    @pytest.mark.xray(test_key='NES-17860')
    @pytest.mark.serial
    @pytest.mark.usefixtures('nessus_api_login', 'enable_plugin_locales', 'import_scan_via_api')
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'cvssv4_test_plugin_scan.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.parametrize('locales_details', [
        pytest.param(['Japanese', 'ja', 'Japanese']),
        pytest.param(['Chinese Simplified', 'zh_CN', 'Chinese (Simplified)']),
        pytest.param(['Chinese Traditional', 'zh_TW', 'Chinese (Traditional)'])])
    def test_selecting_alternative_locales_for_report(self, enable_plugin_locales, locales_details, import_scan_via_api):
        """
        [NES-17860] : Test UI: New dropdown in report modal to choose alternative locale for a single report

        Test covered :
            [x] select the alternative locales on report modal page
            [x] able to download the report without error.
            TODO : downloaded report has selected language in it. can be done using API
        """
        plugin_locale_page = PluginDetailLocale()
        plugin_locale_page.open()
        locales = ['Chinese Simplified', 'Japanese', 'Chinese Traditional']

        wait(lambda: plugin_locale_page.is_element_present("locales_dropdown_textfield"), timeout_seconds=WAIT_NORMAL,
             sleep_seconds=WAIT_SHORT)

        plugin_locale_page.locales_dropdown_textfield.click()

        plugin_locale_page.select_dropdown_labels(element=locales[0])
        plugin_locale_page.save_the_locales()

        plugin_locale_page.locales_dropdown_textfield.click()
        plugin_locale_page.select_dropdown_labels(element=locales[1])
        plugin_locale_page.save_the_locales()

        plugin_locale_page.locales_dropdown_textfield.click()
        plugin_locale_page.select_dropdown_labels(element=locales[2])
        plugin_locale_page.save_the_locales()

        scan_name = import_scan_via_api[0]
        SideNav().scan_tab_on_header.click()
        scan_view_page = ScanViewPage()
        scan_list = ScanList()

        wait(lambda: visibility_of_element_located(scan_list.object_table),
             waiting_for='Wait for Scan lists to appear.')
        scan_list.click_on_scan(scan_name=scan_name)

        wait(lambda: visibility_of_element_located(scan_view_page.report_button),
             waiting_for='report button to appear on modal')
        scan_view_page.report_button.click()

        wait(lambda: visibility_of_element_located(plugin_locale_page.report_modal_local_dropdown),
             waiting_for='dropdown to appear on modal')
        plugin_locale_page.report_modal_local_dropdown.click()

        wait(lambda: visibility_of_element_located(plugin_locale_page.report_modal_locale_area),
             waiting_for='dropdown area to appear on modal')
        for dropdown_option in plugin_locale_page.dropdown_labels:
            if dropdown_option.text == locales_details[2]:
                dropdown_option.click()
                break
        plugin_locale_page.generate_report_button.click()
        ActionCloseModal().wait_for_modal_closed()

        downloaded_files = get_downloaded_files_chrome()

        log.info("Downloaded file path :: :: %s", downloaded_files)
        file_name = scan_name.split(".")[0]

        assert file_name in downloaded_files, "Scan results does not exported successfully."


@pytest.mark.serial
@pytest.mark.nessus_settings_1
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestPluginLocalesManager:
    """
    Covers Plugin Locals tab related test cases For Nessus Manager.
    """

    @pytest.mark.xray(test_key='NES-18466')
    def test_plugin_locales_tab_not_visible(self):
        """
        [NES-18466] : Validate setting is not available for Manager.

        Test covered :
            [x] Plugin detail locales tab not available.
        """
        about_page = About()
        about_page.open()

        wait(lambda: OverView().is_element_present('update_activation_code_tip'), waiting_for='about page to get load')
        tabs_of_page = OverView().get_about_page_labels(element=about_page.tabs_of_about)

        assert Nessus.About.PluginLocales.TAB_NAME not in tabs_of_page, \
            "plugin_locals tab is visible in Nessus Manager."
