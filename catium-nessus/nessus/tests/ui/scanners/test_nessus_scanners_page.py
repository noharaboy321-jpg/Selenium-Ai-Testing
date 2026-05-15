"""
Nessus Manager's linked scanners related test cases

:copyright: Tenable Network Security, 2021
:created: October 21, 2021
:last_modified: November 23, 2022
:author: @vsoni.ctr, @krpatel.ctr, sacharya.ctr
"""
import random
import time

import pytest
from packaging.version import parse
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located, invisibility_of_element, visibility_of
from waiting import TimeoutExpired

import nessus.lib.const
from catium.lib.const import TIME_FIVE_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver
from catium.lib.webium.wait import wait
from nessus.helpers.scanner import create_scanner, scanner_token
from nessus.helpers.sort import sort_on_column_values
from nessus.lib.const import SortOrder, API, Nessus, Prefixes
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.scanners.linked_scanners import ScannerPage, ScannerList
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestScannersPage:
    """Test class covers Scanners page related Test Cases"""

    cat = None

    @pytest.mark.xray(test_key='NES-15391')
    @pytest.mark.nessus_smoke
    def test_verify_setup_instructions_on_scanners_page(self):
        """
        NES-13569 : [UI-Automation]: Visibility of scanners page in NM
        NES-15391 : Verify that remote scanner setup instruction

        Scenario Tested:
            [x] Verify setup instructions on scanners page.
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        assert scanners_page.setup_description.text == nessus.lib.const.Nessus.Scanner.SCANNER_SETUP_DESCRIPTION, "Scanners page set up instructions is incorrect"

    def test_verify_linking_key_elements_visibility(self):
        """
        NES-13569 : [UI-Automation]: Visibility of scanners page in NM

        Scenario Tested:
            [x] Verify scanners linking key related elements on UI.
        """
        scanners_page = ScannerPage()
        scanners_page.open()

        assert scanners_page.is_element_present('linking_key_text'), "Linking key is not present on scanners page."
        assert scanners_page.is_element_present('edit_key'), \
            "Edit icon for linking key is not present on scanners page."
        assert scanners_page.is_element_present('regenerate_key'), \
            "Regenerate linking key icon is not present on scanners page."

    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_fake_scanners', 'login')
    @pytest.mark.parametrize('add_fake_scanners', [{'scanner_name_starts_with': ['automation-', 'automation-']}],
                             indirect=True)
    def test_verify_scanners_count(self, add_fake_scanners):
        """
        NES-13571 : [UI-Automation] : Verify scanner count and search box in NM

        Scenario Tested:
            [x] Verify that total linked scanners count displayed correctly on UI
        """
        scanners_page = ScannerPage
        scanners_page.open()
        assert scanners_page.total_scanners == len(add_fake_scanners) + 1, "Total scanners count is incorrect."

    @pytest.mark.xray(test_key='NES-15423')
    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_fake_scanners', 'login')
    @pytest.mark.parametrize('add_fake_scanners', [{'scanner_name_starts_with': ['automation-', 'nessus', 'scanner']}],
                             indirect=True)
    @pytest.mark.parametrize('search_input', ['automation', 'nessus', 'scanner', 'incorrect_string'])
    def test_verify_scanner_search_works_properly(self, add_fake_scanners, search_input):
        """
        NES-13571 : [UI-Automation] : Verify scanner count and search box in NM
        NES-15423 : Verify scanner can be searched from search box

        Scenario Tested:
            [x] Verify that scanner search box works properly.
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        scanners_list = ScannerList()
        all_scanners = scanners_list.get_all_scanners_in_nessus()
        scanners_page.scanners_search_box.send_keys(search_input)
        expected_scanners = [scanner for scanner in all_scanners if search_input.lower() in scanner.lower()]
        try:
            wait(lambda: scanners_list.get_all_scanners_in_nessus() == expected_scanners)
        except TimeoutExpired:
            raise Exception("Scanner search box is not working properly.")
        assert scanners_page.total_scanners == len(all_scanners), "Total scanners count is incorrect"
        assert scanners_page.selected_scanners == len(expected_scanners), "Searched scanners count is incorrect."

    @pytest.mark.xray(test_key='NES-15353')
    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_fake_scanners', 'login')
    @pytest.mark.parametrize('add_fake_scanners', [{'scanner_name_starts_with': ['automation-']}], indirect=True)
    def test_verify_clear_selected_item_works_for_scanners_list(self, add_fake_scanners):
        """
        NES-13571 : [UI-Automation] : Verify scanner count and search box in NM
        NES-15353 : Verify that selection is removed on clicking 'Clear Selected Items' link


        Scenario Tested:
            [x] Verify that 'clear selected item' link works properly.
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        scanners_list = ScannerList()
        scanners_list.select_scanners(add_fake_scanners)
        wait(lambda: scanners_page.is_element_present('clear_selected_item_link'))
        assert scanners_page.is_element_present('checked_scanners_count'), \
            "Selected/checked scanners count is not displayed after selecting scanners."
        scanners_page.clear_selected_item_link.click()
        assert not (scanners_page.is_element_present('clear_selected_item_link') and scanners_page.is_element_present(
            'checked_scanners_count')), "'Clear selected item' link is not working properly."

    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_fake_scanners', 'login')
    @pytest.mark.parametrize('add_fake_scanners', [{'scanner_name_starts_with': [
        'automation-', 'automation-', 'automation-scanner']}], indirect=True)
    @pytest.mark.parametrize('select_count', [random.randint(1, 3)])
    def test_verify_selected_scan_count_works_properly(self, add_fake_scanners, select_count):
        """
        NES-13571 : [UI-Automation] : Verify scanner count and search box in NM

        Scenario Tested:
            [x] Verify that selected scanners count works is displayed correctly.
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        scanners_list = ScannerList()
        scanners_list.select_scanners(add_fake_scanners[:select_count])
        wait(lambda: scanners_page.is_element_present('clear_selected_item_link'))
        assert scanners_page.checked_scanners == select_count, "Selected scanner count does not displayed correctly."

    @pytest.mark.xray(test_key='NES-15361')
    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Name', 'Status', 'Scans', 'Version', 'Linked On', 'Last Modified'])
    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'login')
    def test_sorting_of_scanners(self, column_to_sort, sort):
        """
        NES-13627 : [UI-Automation] : Verify sorting of scanners in Nessus Manager.
        NES-15361 : Verify that sorting of scanners

        Scenario Tested:
            [x] Verify that sorting for below columns on scanners page work properly.
                - 'Name'
                - 'Status'
                - 'Scans'
                - 'Version'
                - 'Linked On'
                - 'Last Modified'
        """
        scanners_page = ScannerPage()
        scanners_page.open()

        for _ in range(3):
            scanner_info = create_scanner(api=self.cat.api, is_multi_scanner=True)

            with scanner_token(self.cat.api, scanner_info['scanner_response']['reply']['contents']['token']):
                payload_data = {"id": scanner_info['id'], "uuid": scanner_info['suuid'], "platform": scanner_info[
                    'platform'], "engine_version": scanner_info['engine_version'], "ui_version": scanner_info[
                    'ui_version']}

                self.cat.api.multi_scanner.get_jobs(payload=payload_data)

        scanners_page.refresh()

        column_mapping = {'Name': 'scanner_name', 'Status': 'scanner_status', 'Scans': 'scanner_scans',
                          'Version': 'scanner_version', 'Linked On': 'linked_on_epoc_time',
                          'Last Modified': 'last_modified_epoc_time'}
        map_attribute = column_mapping[column_to_sort]

        scanners_list = ScannerList()
        scanners_list.loaded()
        sort_key = (lambda k: k.lower()) if (column_to_sort not in ['Version', 'Linked On', 'Last Modified']) else (
            lambda k: k)

        column_values = [parse(getattr(scanner, map_attribute)) if column_to_sort == 'Version' else getattr(
            scanner, map_attribute) for scanner in scanners_list.rows]

        expected_scanner_list = sorted(column_values, key=sort_key, reverse=(sort == SortOrder.DESCENDING))

        rendered_scanners_list = sort_on_column_values(page_class_instance=scanners_list, sort=sort,
                                                       column_name=column_to_sort)
        sorted_scanners_list = [parse(getattr(scan, map_attribute)) if column_to_sort == 'Version' else getattr(
            scan, map_attribute) for scan in rendered_scanners_list]

        # Verify that scanners got sorted as per the column and order selected by user.
        assert expected_scanner_list == sorted_scanners_list, \
            "Sorting is not working for {} column in scanners page.".format(column_to_sort)

    @pytest.mark.xray(test_key='NES-15503')
    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_fake_scanners', 'login')
    @pytest.mark.parametrize('add_fake_scanners', [{'scanner_name_starts_with': [
        'automation-', 'automation-', 'automation-scanner', 'nessus-', 'automation-nessus']}], indirect=True)
    def test_verify_scanners_count_for_multiple_scanner(self, add_fake_scanners):
        """
        NES-15503 : Verify that scanner count is displayed beside search box

        Scenario Tested:
            [x] Verify that linked scanners count is showing besides search box
            [x] Verify that number of scanner and scanner count is same.
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        wait(lambda: scanners_page.is_element_present("scanners_search_box"),
             waiting_for="Scanner Search box to be visible.")
        assert scanners_page.is_element_present(
            'total_scanners_count'), "Scanner count is not available beside the search box."
        assert scanners_page.total_scanners == len(add_fake_scanners) + 1, "Total scanners count is incorrect."

    @pytest.mark.xray(test_key='NES-15478')
    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_fake_scanners', 'login')
    @pytest.mark.parametrize('add_fake_scanners', [{'scanner_name_starts_with': [
        'automation-', 'automation-', 'automation-scanner', 'nessus-', 'automation-nessus']}], indirect=True)
    def test_verify_disable_and_delete_icons_for_scanners(self, add_fake_scanners):
        """
        NES-15478 : Verify that disable icon and delete icon for each remote scanner linked

        Scenario Tested:
            [x] Verify the disable icon
            [x] Verify the delete icon.
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        wait(lambda: scanners_page.is_element_present("scanners_search_box"),
             waiting_for="Scanner Search box to be visible.")
        scanner_name = add_fake_scanners
        assert len(scanner_name) + 1 == len(scanners_page.disable_buttons), "Disable icon is missing for any scanner."
        assert len(scanner_name) == len(scanners_page.delete_buttons), "delete icon is missing for any scanner."

    @pytest.mark.xray(test_key='NES-15452')
    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_fake_scanners', 'login')
    @pytest.mark.parametrize('add_fake_scanners', [{'scanner_name_starts_with': ['automation-']}], indirect=True)
    def test_verify_scanner_details_page(self, add_fake_scanners):
        """
        NES-15452 : Verify that remote scanner detail is displayed on scanner detail page

        Scenario Tested:
            [x] Scanner details and scanner permission tabs should be there.
            [x] Elements of Scanner details tab.
            [x] Elements of Scanner permission tab.
            [x] Scanner health message on page should be idle.
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        scanners_name = add_fake_scanners[0]
        scanners_page.open_scanner_details(scanners_name)
        wait(lambda: scanners_page.is_element_present("scanner_detail_empty_msg"),
             waiting_for="Scanner empty msg to be visible.")

        # Validation of Scanner condition message
        assert scanners_page.scanner_detail_empty_msg.text == API.Scanners.ScannerPage.IDLE_STATUS, "Scanner is not in idle condition message not shown"

        # Validation of Scanner details and scanner permission tab
        assert all([scanners_page.is_element_present("scanner_details_tab"),
                    scanners_page.is_element_present("scanner_permission_tab")]), \
            "scanner details and permission tab is missing"

        actual_labels = []
        for scanner in scanners_page.scanner_details_labels:
            actual_labels.append(scanner.text)
        print(actual_labels)

        # Validation of elements on scanner details page
        assert set(actual_labels) == set(API.Scanners.ScannerPage.LABELS)

        scanners_page.scanner_permission_tab.click()
        try:
            wait(lambda: scanners_page.is_element_present('add_user_group_input'),
                 timeout_seconds=TIME_FIVE_SECONDS)
        except TimeoutExpired:
            raise AssertionError("search user field is not available on 'permissions' tab.")

        # Validation of dropdown options for permission tab
        assert [option['label'] for option in scanners_page.select_user_permission.option_values] == \
               API.Scanners.ScannerPage.PERMISSION_OPTION, \
            "'No access' and 'Can use' options are not available on 'permissions' tab."

        # Validation for save and cancel button
        assert scanners_page.is_element_present('save_button'), 'Save button is visible'
        assert scanners_page.is_element_present('cancel_button'), 'Cancel button is not visible'

    @pytest.mark.xray(test_key='NES-15286')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.BASIC_NETWORK, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.BASIC_NETWORK)),
         'description': 'Created a {} scan for NES-15286.'.format(Nessus.TemplateNames.BASIC_NETWORK.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    def test_running_scan_count_in_linked_scanner(self, create_scans):
        """
        NES-15286 : Verify that running scan count is displayed in Scans column

        """
        scan_form = NewScanForm()
        scan_form.save_action_dropdown.click()
        scan_form.launch_option.click()

        time.sleep(10)
        scanner_page = ScannerPage()
        scanner_page.open()
        scanner_list = ScannerList()
        all_scanners = scanner_list.results
        assert all_scanners[0].scanner_scans == str(1), "Scan count doesn't match"

    @pytest.mark.xray(test_key='NES-15521')
    def test_linking_key_regeneration_for_scanner(self):
        """
        NES-15521 : Verify linking key is visible on scanners page.

        Scenario Tested:
            [x] Verify scanners linking key is regenerated.
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        assert scanners_page.is_element_present('linking_key_text'), "Linking key is not present on scanners page."
        assert scanners_page.is_element_present('edit_key'), \
            "Edit icon for linking key is not present on scanners page."
        assert scanners_page.is_element_present('regenerate_key'), \
            "Regenerate linking key icon is not present on scanners page."
        previous_linking_key = scanners_page.linking_key_text.text
        scanners_page.regenerate_key.click()
        scanners_page.regenerate_button.click()
        scanners_page.refresh()
        scanners_page.loaded()
        assert scanners_page.linking_key_text.text != previous_linking_key, "Linking Key is not updated"

    @pytest.mark.xray(test_key='NES-15396')
    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_fake_scanners', 'login')
    @pytest.mark.parametrize('add_fake_scanners', [{'scanner_name_starts_with': ['automation-']}],
                             indirect=True)
    def test_verify_scanner_can_be_removed_from_nm(self, add_fake_scanners):
        """
        NES-15396 : Verify that scanner can be removed from NM or T.io

        """
        scanners_page = ScannerPage()
        scanners_page.open()
        assert scanners_page.is_element_present('linking_key_text'), "Linking key is not present on scanners page."
        scanners_page.delete_buttons[0].click()
        remove_scanner = ActionCloseModal()
        remove_scanner.action_button.click()
        scanners_list = ScannerList()
        all_scanners = scanners_list.get_all_scanners_in_nessus()
        assert add_fake_scanners not in all_scanners, 'Scan is still not deleted'

    @pytest.mark.xray(test_key='NES-15331')
    @pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners', 'add_fake_scanners', 'login')
    @pytest.mark.parametrize('add_fake_scanners', [{'scanner_name_starts_with': ['automation-']}],
                             indirect=True)
    @pytest.mark.parametrize("create_groups", [{
        'group_details': [{"group_name": random_name(prefix=Prefixes.GROUP)}
                          ]}], indirect=True)
    @pytest.mark.parametrize("user_group", ['admin', 'group'])
    def test_add_user_and_verify_scanner_permission(self, add_fake_scanners, create_groups, user_group):
        """
        NES-15331 : Verify that scanner permission
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        scanners_name = add_fake_scanners[0]
        scanners_page.open_scanner_details(scanners_name)
        wait(lambda: scanners_page.is_element_present("scanner_detail_empty_msg"),
             waiting_for="Scanner empty msg to be visible.")

        scanners_page.scanner_permission_tab.click()
        try:
            wait(lambda: scanners_page.is_element_present('add_user_group_input'),
                 timeout_seconds=TIME_FIVE_SECONDS)
        except TimeoutExpired:
            raise AssertionError("search user field is not available on 'permissions' tab.")

        scanners_page.add_user_group_input.send_keys(user_group)
        wait(lambda: scanners_page.is_element_present('available_user'),
             waiting_for='waiting for matching user list to populate')
        scanners_page.available_user.click()

        assert scanners_page.added_user_permission.text == API.Scanners.ScannerPage.PERMISSION_OPTION[1]

    @pytest.mark.xray(test_key='NES-15385')
    def test_show_hide_link_for_scanner_sidebar(self):
        """
        NES-15385 : Verify Hide/Show hyperlink in Scanners section
        """
        scanners_page = ScannerPage()
        scanners_page.open()
        side_nav = SideNav()
        get_driver().execute_script('arguments[0].click();', side_nav.scanner_show_hide_link.element)
        assert invisibility_of_element(side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.SCANNERS))
        get_driver().execute_script('arguments[0].click();', side_nav.scanner_show_hide_link.element)
        assert visibility_of(side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.SCANNERS))




