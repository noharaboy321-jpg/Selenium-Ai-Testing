"""
Nessus Scans related test cases

:copyright: Tenable Network Security, 2017
:date: July 25, 2017
:last_modified: May 12, 2024
:author: @rdutta, @jamreliya, @smadan, @mameta, @ntarwani, @jchavda, @kpanchal, @krpatel.ctr
"""

import os
import random
import time
from collections import ChainMap
from datetime import datetime, timedelta
from random import randint

import pytest
import pytz
from _pytest.fixtures import SubRequest
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver import ChromeOptions
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path, load_testdata
from catium.lib.config import Config
from catium.lib.const.base_constants import WAIT_NORMAL, WAIT_SHORT, TIME_THREE_SECONDS, TIME_TWENTY_SECONDS, \
    TIME_THIRTY_SECONDS, TIME_FIVE_SECONDS, WAIT_LONG, GRID_BROWSER_DOWNLOAD_PATH, TIME_NINETY_SECONDS, \
    TIME_FIFTEEN_MINUTES, TIME_FIVE_MINUTES, TIME_TWO_MINUTES, TIME_THIRTY_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver, get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from catium.pageobjects.cat_basepage import CATBasePage
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.advanced_settings import get_color_code_of_ui_element
from nessus.helpers.nessuscli.fix import get_value
from nessus.helpers.nessuscli.helper import get_os_name
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import scan_save_launch_and_status_verification, get_scan_id, empty_trash_folder, \
    create_scan_helper
from nessus.helpers.system import is_manager, is_pro
from nessus.helpers.utility import get_downloaded_files_chrome
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import Nessus, API, OperatingSystems
from nessus.lib.message.messages import Messages
from nessus.models.scan import ScanModel
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.dynamic_plugins.dynamic_plugins_page import DynamicPlugin
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.basic_search import BasicSearch
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions, \
    close_pendo_guide_container_banner_for_nessus_pro
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.plugin_rules.plugin_rules_page import PluginRulesPage, PluginRulesList
from nessus.pageobjects.plugins.plugins_page import Plugin, PluginsList, PluginFamilyList
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import AssessmentSetting, BasicSetting
from nessus.pageobjects.scans.scan_basic_settings_page import ScanSettings, AdvancedSetting, DiscoverySetting
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanVulnerabilities, \
    ScansHostList, VulnerabilityList, ModifyVulnerability, VulnerabilityDescription
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.tests.ui.scans.test_created_scan_results_page import verify_plugin_debugging_log_output_table

log = create_logger()
timestamped_path = 'export_scan_diff' + str(int(time.time()))  # use timestamp to differentiate test


@pytest.fixture()
def chrome_options():
    """Set download path for Chrome."""
    options = ChromeOptions()

    if Config.CAT_USE_GRID:
        directory = os.path.join(GRID_BROWSER_DOWNLOAD_PATH, timestamped_path)
    else:
        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path)

    prefs = {'download.default_directory': directory}
    options.add_experimental_option('prefs', prefs)
    return options


@pytest.fixture()
def empty_trash_and_create_or_import_bulk_scan(request: 'SubRequest', create_new_folder):
    """
    Empty trash folder and create or import bulk scans (by default import scan will be done)
    """
    # Deletes all scans from trash folder and imports bulk scans
    empty_trash_folder()

    scan_count = request.param['scan_count']
    import_scan = request.param['import_scan'] if hasattr(request, 'param') and 'import_scan' in request.param else True
    response = None
    responses = []

    nessus_api = NessusAPI()
    nessus_api.login()

    try:
        folder_detail = create_new_folder
        log.info('Folder created successfully.')

        scans_details = {'name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
                         'text_targets': 'localhost', 'folder_id': folder_detail[0]}
        scan_name = scans_details['name']

        if import_scan:
            scan_file = get_file_path('nessus/tests/ui/scans/test_data/' + 'Test_Advanced_Scan_NES-8592.nessus')
            file_uploaded = nessus_api.file.upload(file=scan_file)

        for count in range(scan_count):
            if import_scan:
                response = nessus_api.scans.import_scan(file_uploaded, folder_id=folder_detail[0])
            else:
                scans_details['name'] += " - " + str(count)
                scan_model = ScanModel(**scans_details)
                responses.append(nessus_api.scans.create(model=scan_model))
                scans_details['name'] = scan_name

        log.info('Scans created successfully.')
        scan_page = ScansPage()
        scan_page.refresh()

        SideNav().get_sidenav_element(element_name=folder_detail[1]).click()
        ScanList().loaded()

        if import_scan:
            yield response['scan']['name'], folder_detail
        else:
            yield [response['scan']['name'] for response in responses], scan_count, folder_detail

    finally:
        scan_ids = [scan['id'] for scan in nessus_api.scans.get_scans()['scans']]
        [nessus_api.scans.stop(scan_id=scan_id) for scan_id in scan_ids if nessus_api.scans.get_status(
            scan_id=scan_id) == API.Scan.Status.RUNNING]
        sleep(TIME_TWO_MINUTES, reason="waiting for scans to get stopped")

        if scan_ids:
            nessus_api.scans.delete_bulk_scans(id_list=scan_ids)
        else:
            log.debug("Did not get any Scans. May be, It was deleted from test side.")

        nessus_api.logout()
        empty_trash_folder()


@pytest.mark.nessus_home
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login', 'login')
class TestScans:
    """Scans Related Test Cases"""
    cat = None
    policies_file_path = {"file_path": 'nessus/tests/ui/scans/test_data/'}
    folder_name = (random_name(prefix='NQA-391-'))[:20]
    plugin_id_for_dynamic_scan = '19506'

    @staticmethod
    def go_to_notification_of_scan_basic_setting(scan_name: str) -> None:
        """
        Go to notification tab of scan basic setting.

        :param str scan_name: Scan name
        :return: None
        """
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        scan_view_page.js_scroll_into_view(element=scan_view_page.configure_button)
        scan_view_page.configure_button.click()

        wait(lambda: visibility_of_element_located(NewScanForm().name_field), waiting_for='scan form to load')
        ScanSettings().click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                              link_text=Nessus.Scan.SettingsBasicSubMenu.NOTIFICATIONS)

    @staticmethod
    def verify_pagination_button() -> None:
        """
        Verify pagination buttons from scan and trash page.

        :return: None
        """
        scan_page = ScansPage()
        scan_page.js_scroll_into_view(scan_page.pagination_button_next)

        assert scan_page.is_element_present('pagination_button_next'), "Scan pagination button next '>' is not " \
                                                                       "visible on Scan/Trash page."

    @staticmethod
    def verify_pagination_after_delete_last_scan(pagination: str, scan_count: int) -> None:
        """
        Verify pagination buttons after deleting last scan from scan and trash page.

        :param str pagination: yes for pagination else no
        :param int scan_count: number of scan from scan list
        :return: None
        """
        scan_page = ScansPage()
        scan_list = ScanList()

        if pagination == 'yes':
            assert len(scan_list.get_all_scans()) and not scan_page.is_element_present('pagination_button_next'), \
                "Scan/Trash page is not navigate to it's previous page."
        else:
            assert len(scan_list.get_all_scans()) == scan_count - 1, "Scan/Trash page is navigate to it's prior page."

            assert scan_page.is_element_present('pagination_button_previous'), "Scan pagination button previous '<' " \
                                                                               "is not visible on Scan/Trash page."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'nqa-1012.db',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'password': 'password', "encrypted": True}], indirect=True)
    def test_scan_modify_plugins(self, import_scan_via_api):
        """
        Scans - Plugin Rules - Modify Plugins - NQA-1012
        1. Import a scan file and provide password.
        2. Open the imported scan and click on the first host from the list.
        3. Apply a filter with the plugin name Nessus Scan Information.
        4. Modify the vulnerability and set severity to Critical.
        5. Verify if the severity is changed only for the one target.
        """
        import_scan_name = import_scan_via_api[0]

        scan_page = ScansPage()
        scan_page.refresh()

        scan_list = ScanList()
        scan_list.loaded()
        scan_list.click_on_scan(scan_name=import_scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('vulnerability_tab'), waiting_for='Scan details to load')

        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        scan_vulnerability = ScanVulnerabilities()
        scan_vulnerability.apply_filter(key="Plugin Name", operator="is equal to",
                                        value=Nessus.Scan.Vulnerability.NESSUS_SCAN_INFO)

        sleep(sleep_time=WAIT_NORMAL, reason="Filter results takes some time to populate")
        scan_host_list = ScansHostList()
        sev_host_before_modification = scan_host_list.get_severity_host_list()

        host_value = scan_host_list.results[1].host_name
        scan_host_list.results[1].click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        modify_vulns = ModifyVulnerability()
        modify_vulns.modify_vulnerability(vulnerabilities_list=[Nessus.Scan.Vulnerability.NESSUS_SCAN_INFO],
                                          severity=Nessus.Scan.Severity.CRITICAL)
        ActionCloseModal().wait_for_modal_closed()
        wait(lambda: scan_vulnerability.is_element_present('back_link'),
             waiting_for="scan result page to get loaded after severity change.", sleep_seconds=WAIT_SHORT,
             timeout_seconds=TIME_THIRTY_SECONDS)

        scan_vulnerability.back_link.click()
        scan_page.refresh()
        wait(lambda: scan_page.is_element_present('back_link'), waiting_for="Scan result page to get loaded",
             sleep_seconds=WAIT_SHORT, timeout_seconds=TIME_THIRTY_SECONDS)

        scan_vulnerability.apply_filter(key="Plugin Name", operator="is equal to",
                                        value=Nessus.Scan.Vulnerability.NESSUS_SCAN_INFO)

        sev_host_after_modification = scan_host_list.get_severity_host_list()

        assert sev_host_after_modification[host_value] == Nessus.Scan.Severity.CRITICAL + ': 1 (100.00%)', \
            'Severity of host "%s" has not changed' % host_value

        sev_host_before_modification[host_value] = Nessus.Scan.Severity.CRITICAL + ': 1 (100.00%)'

        assert sev_host_before_modification == sev_host_after_modification, \
            "Severity of other hosts has been changed too"

        scan_vulnerability.back_link.click()

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'poc.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    def test_scan_security_for_link_click(self, import_scan_via_api):
        """
        Security - UI - Javascript code can be executed when clicking on a link NQA-145

        1. Import provided scan file.
        2. Open the imported scan.
        3. Verify the count should be 1 for both host and vulnerability.
        4. Open plugin with id 559003.
        5. Verify that the text written on See Also section is 'Invalid Link'.
        6. Verify no link is present under See Also section.
        """
        import_scan_name = import_scan_via_api[0]
        get_driver_no_init().refresh()

        scan_list = ScanList()
        scan_list.loaded()
        scan_list.click_on_scan(scan_name=import_scan_name)

        scan_result_page = ScanViewPage()
        wait(lambda: scan_result_page.is_element_present('host_tab'), waiting_for="Hosts page to properly load.")

        scan_result_page.host_tab.click()
        wait(lambda: scan_result_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        assert ScansHostList().get_total_rows() == 1, "More than 1 host exist"

        scan_result_page = ScanViewPage()
        scan_result_page.vulnerability_tab.click()
        vulnerability_list = VulnerabilityList()

        assert len(vulnerability_list.results) == 1, "More than 1 vulnerability exist"

        scan_vulnerability = ScanVulnerabilities()
        scan_vulnerability.apply_filter(key="Plugin ID", operator="is equal to", value="55903")
        LoadingCircle(WAIT_SHORT)
        vulnerability_list.results[0].click()

        vul_description = VulnerabilityDescription()
        LoadingCircle(WAIT_SHORT)
        assert vul_description.get_heading_data(heading_value="See Also") == "Invalid Link", \
            "Text under see also section is incorrect"

        assert not vul_description.get_heading_section_link(heading_value="See Also"), \
            "Javascript code can execute on clicking link "

        scan_vulnerability.back_link.click()
        scan_result_page.back_link.click()

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Advanced_Scan_NQA-379.db',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'password': 'password', "encrypted": True}], indirect=True)
    def test_scan_hide_plugin(self, import_scan_via_api):
        """
        Scans - Plugin Rules - Hide Plugins NQA-379

        1. Import a scan file with high amount of vulns and provide password.
        2. Open the imported scan and click on vulnerability tab.
        3. Click on select all checkbox.
        4. De-select even number of vulnerabilities.
        5. Click on modify tab and select hide this result option.
        6. Verify the list does not contain hidden plugin names.
        """
        scan_page = ScansPage()
        scan_page.refresh()
        import_scan_name = import_scan_via_api[0]
        LoadingCircle(WAIT_NORMAL)

        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=import_scan_name)

        LoadingCircle(WAIT_NORMAL)
        scan_view_page = ScanViewPage()
        scan_view_page.vulnerability_tab.click()

        vulnerability_list = VulnerabilityList()
        vulnerability_list.select_all_checkbox.click()

        selected_plugins = []
        for row, vulnerability in enumerate(vulnerability_list.results, start=0):
            if row % 2 == 0:
                vulnerability.checkbox.click()
                LoadingCircle(WAIT_SHORT)
            else:
                selected_plugins.append(vulnerability.plugin_name.text)

        LoadingCircle(WAIT_NORMAL)
        scan_view_page.js_scroll_into_view(element=scan_view_page.modify_button)
        scan_view_page.modify_button.click()

        modify_vulnerability = ModifyVulnerability()
        modify_vulnerability.severity.select_by_visible_text(Nessus.Scan.Severity.HIDE)
        modify_vulnerability.action_button.click()

        LoadingCircle(WAIT_NORMAL)

        scan_vulnerability = ScanVulnerabilities()
        scan_vulnerability.back_link.click()
        LoadingCircle(WAIT_NORMAL)
        scan_list.click_on_scan(scan_name=import_scan_name)
        LoadingCircle(WAIT_NORMAL)

        scan_view_page.vulnerability_tab.click()
        LoadingCircle(WAIT_NORMAL)
        existing_plugin = vulnerability_list.get_plugin_names()

        assert all([plugin not in existing_plugin for plugin in selected_plugins]), "Selected Plugins are not hidden"

        scan_vulnerability.back_link.click()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.scanning
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    @pytest.mark.usefixtures('create_new_folder')
    @pytest.mark.parametrize("import_policy", [
        ChainMap({"file_name": 'Advanced_all_plugIns_with_compliance.nessus'}, policies_file_path),
        ChainMap({"file_name": 'Advanced_Custom_PlugInSet.nessus'}, policies_file_path),
        ChainMap({"file_name": 'Advanced_All_PlugIns.nessus'}, policies_file_path),
        ChainMap({"file_name": 'Basic_Agent_Scan.nessus'}, policies_file_path),
        ChainMap({"file_name": 'Malware_Scan.nessus'}, policies_file_path)], indirect=True)
    def test_launch_scan_with_imported_policies_on_controller(self, create_new_folder, import_policy):
        """
        # NQA-391 : Short Cycle-Controller-Stage 2-Import policies and scans.
        sub-part: Test case to import policies and launch a scan with it
        1. Import policies files.
        2. Launch a scan with imported policies file.
        """
        folder_name = create_new_folder[1]
        imported_policy = import_policy
        configured_policy_name = "{} - Configured".format(imported_policy)
        scan_name = random_name(prefix="{} - ".format(configured_policy_name))

        policies_list = PolicyList()
        assert imported_policy in policies_list.get_all_policies(), "import failed."

        # Configured and save the imported policy
        LoadingCircle(WAIT_NORMAL)
        policies_list.click_on_policy(policy_name=imported_policy)
        policy_form = NewPolicyForm()
        policy_form.add_policy(policy_name=configured_policy_name,
                               policy_description='verifying {}'.format(configured_policy_name))
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)
        policy_form.save_button.click()
        LoadingCircle(WAIT_NORMAL)

        # verify imported policy is saved after configuration
        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)
        assert configured_policy_name in policies_list.get_all_policies(), "Configured policy not saved successfully."

        # Create a scan with imported configured policy
        side_nav = SideNav()
        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)
        ScansPage().create_new_scan(
            scan_type=Nessus.Scan.ScanTemplateTabs.USER_DEFINED_TAB, scan_template=configured_policy_name,
            scan_name=scan_name, folder=folder_name, target_ip=Nessus.Scan.Target.LOCALHOST)

        LoadingCircle(WAIT_NORMAL)
        side_nav.refresh()
        LoadingCircle(TIME_THREE_SECONDS)
        side_nav.get_sidenav_element(element_name=folder_name).click()
        scan_list = ScanList()
        assert scan_name in scan_list.get_all_scans(), "Scan not saved successfully."

        # Launch the created scan and verify its completed successfully.
        assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name), \
            'Scan has not been completed successfully yet.'
        LoadingCircle(WAIT_SHORT)

        # delete created scan
        scan_list.delete_scan(scan_name=scan_name)
        ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)
        LoadingCircle(WAIT_SHORT)
        assert scan_name not in scan_list.get_all_scans(), "Scan not deleted successfully."

    @pytest.mark.skipif(Config.CAT_USE_GRID, reason="grid defaults to 60 seconds.")
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('create_new_folder', [{'folder_name': folder_name}], indirect=True)
    @pytest.mark.parametrize("import_scan_file", [
        {"filename": 'System_Health_Discovery_-_100MB.db', "folder_name": folder_name,
         "scan_file_path": 'nessus/tests/ui/scans/test_data/', "password": 'Tenable123'},
        {"filename": 'Standard_TrustCc_Internal_Scan_-_600MB.db', "folder_name": folder_name,
         "scan_file_path": 'nessus/tests/ui/scans/test_data/', "password": 'Tenable123'},
        {"filename": 'PROD_FCC_Advanced_scan_-_900MB.db', "folder_name": folder_name,
         "scan_file_path": 'nessus/tests/ui/scans/test_data/', "password": '12345'},
        {"filename": 'EUC_-_4GB.nessus', "folder_name": folder_name,
         "scan_file_path": 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    def test_import_scans_on_controller(self, create_new_folder, import_scan_file):
        """
        # NQA-391 : Short Cycle-Controller-Stage 2-Import policies and scans.
        sub-part: Test case to import scan files of different size.
         1. Import scan files.
         2. Export scan files in different formats.
        """
        imported_scan_file = import_scan_file
        LoadingCircle(WAIT_NORMAL)

        ScanList().click_on_scan(scan_name=imported_scan_file)
        LoadingCircle(WAIT_NORMAL)

        scan_details_page = ScanViewPage()
        assert scan_details_page.page_header == imported_scan_file, "Scan results page is not visible."

        scan_details_page.back_link.click()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NQA-133.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    @pytest.mark.xray(test_key='SCE-4108')
    def test_check_default_performance_options_values(self, create_scans):
        """
        UI - Scans - Deleting value under "Performance Options" and saving scan will revert to original value NQA-133
        sub part - Check default value and with correct values
        """
        data_name_list = ['Network timeout (in seconds)', 'Max simultaneous checks per host',
                          'Max simultaneous hosts per scan', 'Max scan time per host (in minutes)']
        scan_name = create_scans[0]

        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(TIME_THREE_SECONDS)
        scan_view_page = ScanViewPage()
        scan_view_page.js_scroll_into_view(element=scan_view_page.configure_button)
        scan_view_page.configure_button.click()
        LoadingCircle(WAIT_SHORT)

        ScanSettings().click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ADVANCED)
        advanced_setting = AdvancedSetting()
        default_max_hosts = get_value(key='max_hosts') # get max_hosts from cli since it varies based on system running Nessus
        assert all([((advanced_setting.get_performance_option(data_name=data_name_list[0])) == '5'),
                    ((advanced_setting.get_performance_option(data_name=data_name_list[1])) == '5'),
                    ((advanced_setting.get_performance_option(data_name=data_name_list[2])) == default_max_hosts),
                    ((advanced_setting.get_performance_option(data_name=data_name_list[3])) == '')]), \
            'Incorrect default values'

        valid_values = ['0', '']
        for value_to_be_saved in valid_values:
            for data_name in data_name_list:
                advanced_setting.set_performance_option(data_name=data_name, value=value_to_be_saved)
            advanced_setting.save_button.click()

            # Raising Assertion Error if notification list is empty
            try:
                assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
                    "Scan Saved but, notification was missing"
            except TimeoutExpired:
                raise AssertionError('Notification did not display at all')

            if not value_to_be_saved:
                value_to_be_saved = '5'
                LoadingCircle(WAIT_SHORT)

            print((advanced_setting.get_performance_option(data_name=data_name_list[3])))
            assert all([((advanced_setting.get_performance_option(data_name=data_name_list[0])) == value_to_be_saved),
                        ((advanced_setting.get_performance_option(data_name=data_name_list[1])) == value_to_be_saved),
                        ((advanced_setting.get_performance_option(data_name=data_name_list[2])) in [value_to_be_saved, default_max_hosts]),
                        ((advanced_setting.get_performance_option(data_name=data_name_list[3])) is None)]), \
                'Incorrect default values'

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NQA-133.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    @pytest.mark.xray(test_key='SCE-4108')
    def test_check_invalid_performance_options_values(self, create_scans):
        """
        UI - Scans - Deleting value under "Performance Options" and saving scan will revert to original value NQA-133
        sub part - Check error on setting incorrect values
        """
        scan_name = create_scans[0]
        invalid_option_values = [['a', 'b', 'c', 'd'], ['#', '$', '%', '@'], ['-1', '-199', '-99', '-0'], ['5', '5', '-99', '0']]
        data_name_list = ['Network timeout (in seconds)', 'Max simultaneous checks per host',
                          'Max simultaneous hosts per scan', 'Max scan time per host (in minutes)']

        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(TIME_THREE_SECONDS)
        scan_view_page = ScanViewPage()
        scan_view_page.js_scroll_into_view(element=scan_view_page.configure_button)
        scan_view_page.configure_button.click()
        LoadingCircle(WAIT_NORMAL)

        ScanSettings().click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.ADVANCED)
        advanced_setting = AdvancedSetting()
        for invalid_value in invalid_option_values:
            for data_name, invalid_char in enumerate(invalid_value):
                advanced_setting.set_performance_option(data_name=data_name_list[data_name], value=invalid_char)
            LoadingCircle(WAIT_SHORT)
            advanced_setting.save_button.click()

            # Raising Assertion Error if notification list is empty
            try:
                assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
                    "Error notification is missing or mismatched"
                HeaderBasePage().clear_notification_history()
            except TimeoutExpired:
                raise AssertionError('Notification did not display at all')

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.scanning
    @pytest.mark.parametrize("launch_scan", ([True, False]))
    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NQA-141.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.PUB_TARGET_4, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_edit_scan_assessment_configuration(self, create_scans, launch_scan):
        """
        UI - Scans - Edit scan configuration input validation not clearing error when menu was toggled on - NQA-141
        sub part- Checking Assessment Settings
        """
        scan_name = create_scans[0]
        scan_page = ScansPage()
        LoadingCircle(WAIT_NORMAL)

        if launch_scan:
            if scan_save_launch_and_status_verification(scan_name=scan_name, navigate_to_scan_folder=False):
                ScanList().click_on_scan(scan_name=scan_name)
                LoadingCircle(TIME_THREE_SECONDS)
                scan_view_page = ScanViewPage()
                scan_view_page.js_scroll_into_view(element=scan_view_page.configure_button)
                scan_view_page.configure_button.click()
            else:
                # After 30 mins of wait api session gets invalid so perform api login before proceeding.
                self.cat.api.login()
                # Needs to login as session gets expire after 30 minutes of waiting for scan completion
                login_page = LoginPage()
                if login_page.is_element_present('sign_in_button'):
                    login_page.login_with_defaults()
                    LoadingCircle(WAIT_NORMAL)

                # Get the scan_id and stop it, if it still in running state
                scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)
                if self.cat.api.scans.get_status(scan_id=scan_id) == API.Scan.Status.RUNNING:
                    self.cat.api.scans.stop(scan_id=scan_id)

                wait(lambda: (self.cat.api.scans.get_status(scan_id=scan_id) in [API.Scan.Status.CANCELED,
                                                                                 API.Scan.Status.COMPLETED]),
                     waiting_for="Delete icon to be visible after stop/completion of scan",
                     timeout_seconds=TIME_TWENTY_SECONDS)

                # Skipping the test if scan took more than 30 minutes to be in completed state
                pytest.xfail('Scan running for more than 30 minutes and still not completed')

        LoadingCircle(WAIT_NORMAL)
        assessment_setting = AssessmentSetting()
        assessment_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                                  link_text="Web Applications")
        LoadingCircle(WAIT_NORMAL)
        assessment_setting.scan_web_app_switch.click()

        assessment_setting.set_scan_web_application_inputs(data_name='Maximum pages to crawl', value='100AB')
        max_page_crawl = assessment_setting.get_scan_web_application_inputs_element(data_name='Maximum pages to crawl')

        assert get_color_code_of_ui_element(element=max_page_crawl, css_property='border-color') in \
               ['#DD4B50', '#FF5959'], "Input box has not turned red"

        scan_page.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.invalid_max_crawl, \
            "Error notification is missing"

        header_page = HeaderBasePage()
        header_page.clear_notification_history()
        wait(lambda: not header_page.is_element_present("clear_notification"))
        assessment_setting.set_scan_web_application_inputs(data_name='Maximum pages to crawl', value='100')

        assert get_color_code_of_ui_element(element=max_page_crawl, css_property='border-color') in \
               ['#AAAAAA', '#00A5B5'], "Input box did not turn black"

        scan_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan Saved but, notification was missing"

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        wait(lambda: scan_page.is_element_present('create_a_new_scan_link') or scan_page.is_element_present(
            'scan_searchbox'), waiting_for='Scan page to load properly')

    @pytest.mark.scanning
    @pytest.mark.usefixtures('delete_all_scans_in_nessus')
    @pytest.mark.parametrize("launch_scan", ([True, False]))
    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NQA-141.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_edit_scan_discovery_configuration(self, create_scans, launch_scan):
        """
        UI - Scans - Edit scan configuration input validation not clearing error when menu was toggled on - NQA-141
        sub part- Checking Discovery Settings
        """
        scan_name = create_scans[0]
        scan_page = ScansPage()

        if launch_scan:
            Plugin().disable_all.click()
            LoadingCircle(WAIT_SHORT)
            if scan_save_launch_and_status_verification(scan_name=scan_name, navigate_to_scan_folder=False):
                ScanList().click_on_scan(scan_name=scan_name)
                LoadingCircle(WAIT_NORMAL)
                ScanViewPage().configure_button.click()
            else:
                # Needs to login as session gets expire after 30 minutes of waiting for scan completion
                login_page = LoginPage()

                if login_page.is_element_present('sign_in_button'):
                    login_page.login_with_defaults()
                    LoadingCircle(WAIT_NORMAL)

                nessus_api = NessusAPI()
                nessus_api.login()

                # Get the scan_id and stop it, if it still in running state
                scan_id = get_scan_id(api_object=nessus_api, scan_name=scan_name)
                if nessus_api.scans.get_status(scan_id=scan_id) == API.Scan.Status.RUNNING:
                    nessus_api.scans.stop(scan_id=scan_id)

                wait(lambda: (nessus_api.scans.get_status(scan_id=scan_id) in [API.Scan.Status.CANCELED,
                                                                               API.Scan.Status.COMPLETED]),
                     waiting_for="Delete icon to be visible after stop/completion of scan",
                     timeout_seconds=TIME_TWENTY_SECONDS)

                # Skipping the test if scan took more than 30 minutes to be in completed state
                pytest.xfail('Scan running for more than 30 minutes and still not completed')

        LoadingCircle(TIME_THREE_SECONDS)
        discovery_setting = DiscoverySetting()
        discovery_setting.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.DISCOVERY)
        LoadingCircle(WAIT_NORMAL)

        discovery_setting.ping_remote_switch.click()
        wait(lambda: not discovery_setting.is_element_present("test_local_nessus_host_checkbox"))
        scan_page.save_button.click()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan Saved but, notification was missing"

        if not launch_scan:
            scan_page.refresh()
            scan_list = ScanList()
            scan_list.click_on_scan(scan_name)
            LoadingCircle(WAIT_NORMAL)

            ScanViewPage().configure_button.click()
            LoadingCircle(WAIT_SHORT)
            discovery_setting.click_by_link_text(setting_value=API.PoliciesSettings.SettingsTypes.DISCOVERY)

        LoadingCircle(TIME_THREE_SECONDS)
        assert discovery_setting.ping_remote_switch.get_attribute('data-value') == 'no', \
            "`Ping the remote host` is still enabled"

        LoadingCircle(TIME_THREE_SECONDS)
        discovery_setting.ping_remote_switch.click()
        discovery_setting.max_retries.clear()
        discovery_setting.max_retries.send_keys('A')

        assert get_color_code_of_ui_element(element=discovery_setting.max_retries,
                                            css_property='border-color') in ['#DD4B50', '#FF5959'], \
            "Input box did not turn red"

        discovery_setting.max_retries.clear()
        discovery_setting.max_retries.send_keys('2')
        scan_page.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan Saved but, notification was missing"

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.xray(test_key='NES-18459')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created an {} for NES-18459.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("port_scan_range", [
        "all",
        "default, 1-1024, T:1024-65535, U:1025, 22-8888, 11111, 9001-55555",
        "1-1024, default, T:1024-65535, U:1025, 22-8888, 11111, 9001-55555",
        "T:1024-65535, U:1025, 22-8888, 11111, 9001-55555, default"])
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_scan_with_custom_port_scan_range(self, create_scans, port_scan_range):
        """
        NES-18459: Verify Port scan range attribute works fine with Default, Range/s, strings etc
        """
        scan_name = create_scans[0]
        discovery_setting = DiscoverySetting()
        discovery_setting.click_link_inside_link(setting_value="DISCOVERY", link_text="Port Scanning")
        discovery_setting.port_scan_range.value = port_scan_range
        # disable all plugins to speed up scan
        Plugin().disable_all.click()
        assert scan_save_launch_and_status_verification(scan_name, navigate_to_scan_folder=False), 'Scan has not been completed successfully.'


    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NQA-322.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_ui_scan_schedule_page_freq_calender(self, create_scans):
        """
        UI - Scans - Schedule Page - NQA -322
        sub part - checks frequency and datepicker fields
        """
        scan_name = create_scans[0]

        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(TIME_THREE_SECONDS)
        scan_view_page = ScanViewPage()
        scan_view_page.js_scroll_into_view(element=scan_view_page.configure_button)
        scan_view_page.configure_button.click()
        LoadingCircle(WAIT_SHORT)

        basic_setting = BasicSetting()
        basic_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                             link_text='Schedule')

        LoadingCircle(WAIT_SHORT)
        basic_setting.enable_schedule.click()
        assert all([(basic_setting.enable_schedule.get_attribute('data-value') == 'on'),
                    (basic_setting.get_all_option_values(basic_setting.frequency) == ([
                        frequency.title() for frequency in API.Schedule.Frequencies.VALID_FREQUENCIES])),
                    (visibility_of_element_located((basic_setting.starts_datepicker_field.we_by,
                                                    basic_setting.starts_datepicker_field.we_value)
                                                   )(get_driver_no_init()))
                    ]), "Schedule disabled, Missing frequency options and Datepicker field is absent."

        basic_setting.starts_datepicker_field.click()
        assert visibility_of_element_located((basic_setting.select_date.we_by,
                                              basic_setting.select_date.we_value))(get_driver()), \
            "Datepicker dialogue not opened"

        previous_day = (datetime.today() - timedelta(days=1))
        try:
            previous_date_element = basic_setting.select_date.select_day(previous_day.strftime('%e').strip())

            # Verify CSS class for previous disabled date
            assert all([css_class in previous_date_element.get_css_classes() for css_class in
                        ['ui-datepicker-unselectable', 'ui-state-disabled']]), \
                'Previous date is not clickable from date picker calender because it\'s getting disabled.'
        except NoSuchElementException:
            log.info('Can not select previous date')
        else:
            raise AssertionError('User is able to click on the date in the past')

        next_day = (datetime.today() + timedelta(days=1))
        if next_day.month > datetime.today().month:
            basic_setting.select_date.next_month()
            LoadingCircle(WAIT_SHORT)
        basic_setting.select_date.select_day(next_day.strftime('%e').strip())

        # Note: The timestamp in Nessus Product 8.1 and above will be according to International format i.e.
        # %Y-%m-%d %H:%M
        assert basic_setting.starts_datepicker_field.get_attribute('value') == next_day.strftime('%Y-%m-%d'), \
            "Next day not selected"

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NQA-322.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_ui_scan_schedule_page_start_time_dropdown(self, create_scans):
        """
        UI - Scans - Schedule Page - NQA -322
        sub part - checks start time dropdown field
        """
        scan_name = create_scans[0]

        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(TIME_THREE_SECONDS)
        scan_view_page = ScanViewPage()
        scan_view_page.js_scroll_into_view(element=scan_view_page.configure_button)
        scan_view_page.configure_button.click()
        LoadingCircle(WAIT_NORMAL)

        basic_setting = BasicSetting()
        basic_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                             link_text='Schedule')
        LoadingCircle(WAIT_SHORT)
        basic_setting.enable_schedule.click()
        assert all([(basic_setting.enable_schedule.get_attribute('data-value') == 'on'),
                    (basic_setting.start_time_dropdown_field.tag_name == 'select'),
                    (basic_setting.time_dropdown.is_displayed())]), \
            "Schedule not enabled and Time Dropdown with its field is absent."

        # get time list
        start_time_list = basic_setting.get_all_option_values(dropdown_element=basic_setting.time_dropdown)

        # format list values into HH::MM format
        start_time_format = [datetime.strptime(i, '%H:%M') for i in start_time_list]

        pytest.xfail(reason='NES-10079 duplicate entry in listing')
        # Verify list values have 1/2 hour increment
        assert all(start_time == timedelta(seconds=1800) for start_time in
                   [start_time_format[start_time + 1] - start_time_format[start_time]
                    for start_time in range(len(start_time_format) - 1)]), "Time interval is not in 1/2 hour increment."

        basic_setting.time_dropdown.click()
        current_time = (datetime.now().time()).strftime('%H:%M')

        # enter time in dropdown
        basic_setting.search_input.send_keys(current_time)
        basic_setting.search_input.send_keys(Keys.ENTER)
        assert basic_setting.time_dropdown.get_text_selected() == current_time, \
            "Unable to configure manually entered time."

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize('create_scans', [{'scans_details': [{
        'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
        'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
        'description': 'Created a {} for NQA-322.'.format(Nessus.TemplateNames.ADVANCED.lower()),
        'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_ui_scan_schedule_page_timezone_summary(self, create_scans):
        """
        UI - Scans - Schedule Page - NQA -322
        sub part - checks timezone dropdown and summary text fields
        """
        if get_os_name() == OperatingSystems.WINDOWS:
            pytest.xfail(reason="Refer JIRA ID : NES-10323")

        scan_name = create_scans[0]

        ScanList().click_on_scan(scan_name=scan_name)
        LoadingCircle(TIME_THREE_SECONDS)
        scan_view_page = ScanViewPage()
        scan_view_page.js_scroll_into_view(element=scan_view_page.configure_button)
        scan_view_page.configure_button.click()
        LoadingCircle(WAIT_NORMAL)

        basic_setting = BasicSetting()
        basic_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                             link_text=Nessus.Scan.SettingsBasicSubMenu.SCHEDULE)
        LoadingCircle(WAIT_SHORT)
        basic_setting.enable_schedule.click()
        assert basic_setting.enable_schedule.get_attribute('data-value') == 'on', "Schedule not enabled."

        timezone_list = self.cat.api.scans.timezones()
        for timezone in timezone_list['timezones']:
            if 'current' in timezone:
                assert basic_setting.timezone.get_text_selected() == timezone['name'].replace("_", " "), \
                    'Incorrect default value'
                break
        else:
            raise AssertionError('API did not return any current timezone value')

        # get scheduled date and time
        start_timestamp = '{} {}'.format(basic_setting.starts_datepicker_field.get_attribute('value'),
                                         basic_setting.time_dropdown.get_text_selected())

        # Note: The timestamp in Nessus Product 8.1 and above will be according to International format i.e.
        # %Y-%m-%d %H:%M
        summary_timestamp = datetime.strptime(start_timestamp, "%Y-%m-%d %H:%M")
        day_suffix = "th" if 4 <= summary_timestamp.day % 100 <= 20 else \
            {1: "st", 2: "nd", 3: "rd"}.get(summary_timestamp.day % 10, "th")

        formatted_summary_timestamp = summary_timestamp.strftime('%A, %B %-d{}, %Y at %-I:%M %p').format(day_suffix)
        summary_text = basic_setting.frequency.get_text_selected() + ' on ' + formatted_summary_timestamp
        assert basic_setting.summary.text == summary_text, "Summary is not populated with current settings"

        # enter any data in timezone dropdown to search
        basic_setting.timezone.click()
        basic_setting.search_input.send_keys("xyz")
        assert 'No results found' in [result.text for result in basic_setting.timezone.options], \
            "Unable to configure manually entered time"

        timezones = basic_setting.get_all_option_values(dropdown_element=basic_setting.timezone)
        basic_setting.timezone.click()
        LoadingCircle(WAIT_SHORT)

        sorted_time_zone_list = timezones
        sorted_time_zone_list.sort()
        assert sorted_time_zone_list == timezones, "Timezone list is not sorted"

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.parametrize('create_scans', [
        {'scans_details': [{
            'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED)),
            'description': 'Created a {} for NQA-335.'.format(Nessus.TemplateNames.ADVANCED.lower()),
            'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]},
        {'scans_details': [{
            'scan_template': Nessus.TemplateNames.AUDIT_PATCH, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            'scan_name': random_name(prefix='{} Scan - '.format(Nessus.TemplateNames.AUDIT_PATCH)),
            'description': 'Created a {} scan for NQA-335.'.format(Nessus.TemplateNames.AUDIT_PATCH.lower()),
            'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]},
        {'scans_details': [{
            'scan_template': Nessus.TemplateNames.MALWARE, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
            'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.MALWARE)),
            'description': 'Created a {} for NQA-335.'.format(Nessus.TemplateNames.MALWARE.lower()),
            'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_ui_scan_toggle_malware_setting(self, create_scans):

        """ UI - Policy - Toggle Enable/Disable Malware Scan - NQA-335 """
        scan_name = create_scans[0]
        LoadingCircle(WAIT_SHORT)
        assessment_setting = AssessmentSetting()
        assessment_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                                  link_text="Malware")

        if 'Malware' not in scan_name:
            assert assessment_setting.malware_switch.get_attribute('data-value') == 'no', \
                "Scan for malware switch is not disabled"
            assessment_setting.malware_switch.click()

        assert assessment_setting.malware_switch.get_attribute('data-value') == 'yes', \
            "Scan for malware switch is not enabled"

        assessment_setting.scan_file_system.click()
        assert assessment_setting.scan_file_system.get_attribute('data-value') == 'yes', \
            "Scan file system is not enabled"

        scan_page = ScansPage()
        scan_page.js_scroll_into_view(element=scan_page.credentials)
        LoadingCircle(WAIT_SHORT)
        scan_page.credentials.click()
        LoadingCircle(WAIT_SHORT)
        Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
            username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        scan_page.save_button.click()
        LoadingCircle(WAIT_SHORT)

        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)
        ScanViewPage().configure_button.click()
        LoadingCircle(WAIT_SHORT)
        assessment_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.ASSESSMENT,
                                                  link_text="Malware")

        assert all([(assessment_setting.malware_switch.get_attribute('data-value') == 'yes'),
                    (assessment_setting.scan_file_system.get_attribute('data-value') == 'yes')]), \
            "'Scan for malware switch' and 'Scan file system' is not enabled."

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.scanning
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    def test_scan_results_no_diff(self, create_scans):
        """
        NQA-375: Scans - Export - Scan diff results
        NES-8824: automated test - Scan Diff

        1. Login into NM/NP
        2. Navigate to Scans History
        3. Check two different history rows
        4. Click the Diff button to get the difference between the two scans. Choose scans that have same results.
        5. Look for the "Export" button to appear in top right and 'Hosts', 'Vulnerabilities' count should be 0.
        """
        scan_name = create_scans[0]
        scan_list = ScanList()

        # Launch scan and verify 200 response
        for scan_launch in range(2):
            scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)

        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()

        assert scan_view_page.history_tab.is_displayed(), "No history tab available"

        scan_view_page.history_tab.click()
        scan_list.rows[0].checkbox.click()
        scan_list.rows[1].checkbox.click()

        scan_view_page.diff_button.click()
        ActionCloseModal().action_button.click()

        try:
            assert scan_view_page.empty_result.text == 'No differences found.', 'Empty difference div not present'

            assert int(scan_view_page.scan_diff_host_count.text) == 0, "'Hosts' count should be 0."

            scan_view_page.vulnerability_tab.click()

            assert int(scan_view_page.scan_diff_vulnerabilities_count.text) == 0, "'Vulnerabilities' count should be 0."

            assert scan_view_page.no_record_found.text == Messages.NotificationMessages.Users.no_record_found, \
                "'No records found.' message is not displayed in scan diff vulnerabilities."

            assert scan_view_page.is_element_present('export_button'), \
                "'Export' button is not visible on scan diff page while we are getting 'No differences found'."
        except NoSuchElementException:
            try:
                scan_view_page.vulnerability_tab.click()
                vul_list = VulnerabilityList()
                assert all([(len(vul_list.rows) == 1), ('Netstat Portscanner (SSH)' in vul_list.get_plugin_names())]), \
                    "More than 1 vulnerability found, and More Differences found between the same scan launched twice."
            except NoSuchElementException:
                raise AssertionError('User not notified for no differences in scans')

        HeaderBasePage().scan_link.click()

    @pytest.mark.scanning
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_scan_results_diff_export(self, create_scans):
        """
        NES-8844: Automation for the Export Diff feature

        1. Login into NM/NP
        2. Navigate to Scans History
        3. Check two different history rows
        4. Click the Diff button to get the difference between the two scans. Choose scans that have different results,
           such that "Primary Result" choice has fewer results than the other.
        5. Look for the "Export" button to appear in top right, clicking it should generate a report representing the
           hosts & vulnerabilities in the diff.
        """
        scan_name = create_scans[0]
        scan_form = NewScanForm()
        scan_form.plugin.click()

        plugin_family_list = PluginFamilyList()
        plugin_family_list.toggle_plugin_family(plugin_family_list=plugin_family_list.get_all_plugin_families()[::2])
        scan_form.save_button.click()

        basic_search = BasicSearch()
        wait(lambda: basic_search.is_showing(), waiting_for="Waiting for scan list to populate")
        scan_list = ScanList()
        scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)

        scan_page = ScansPage()
        scan_page.refresh()
        wait(lambda: basic_search.is_showing(), waiting_for="Waiting for scan list to populate")

        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present('vulnerability_tab'))
        scan_view_page.configure_button.click()

        plugin = Plugin()
        wait(lambda: plugin.is_element_present("disable_all"))
        plugin.disable_all.click()

        CATBasePage().js_scroll_into_view(element=scan_form.save_button)
        scan_form.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notifications for saving scan is mismatched or missing."

        HeaderBasePage().scan_link.click()
        wait(lambda: basic_search.is_showing(), waiting_for="Waiting for scan list to populate")
        scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)

        scan_page.refresh()
        wait(lambda: basic_search.is_showing(), waiting_for="Waiting for scan list to populate")
        scan_list.click_on_scan(scan_name=scan_name)
        wait(lambda: scan_view_page.is_element_present('vulnerability_tab'))

        assert scan_view_page.history_tab.is_displayed(), "'History' tab is not visible."

        assert scan_view_page.is_element_present('export_button'), "'Export' button is not visible on top right " \
                                                                   "corner of scan history diff page."

        scan_view_page.history_tab.click()
        scan_list.rows[0].checkbox.click()
        scan_list.rows[1].checkbox.click()

        assert not scan_view_page.is_element_present('export_button'), \
            "'Export' button is visible on scan history page after selecting two scan history rows."

        scan_view_page.diff_button.click()
        primary_results_options = scan_view_page.primary_results_dropdown.option_values
        scan_view_page.primary_results_dropdown.select_by_visible_text(primary_results_options[1]['label'])

        primary_results_modal = ActionCloseModal()
        primary_results_modal.accept_action()
        primary_results_modal.wait_for_modal_closed()

        assert scan_view_page.is_element_present('export_button'), \
            "'Export' button is not visible on top right corner of scan history diff page."

        for format_type in API.Scan.UIExportFormats.VALID_FORMATS:
            scan_view_page.export_scan_in_format(format_type=format_type)

            wait(lambda: not WindowsHandler().is_alert_present(), timeout_seconds=TIME_THIRTY_SECONDS,
                 sleep_seconds=TIME_FIVE_SECONDS)
            assert not WindowsHandler().is_alert_present(), 'Export has failed.'

            LoadingCircle(TIME_FIVE_SECONDS)

            downloaded_file = get_downloaded_files_chrome()

            log.info("Downloaded file path :: :: %s", downloaded_file)
            file_name = scan_name.split(".")[0]

            assert file_name in downloaded_file, "Scan results does not exported successfully."

        scan_view_page.back_link.click()

    @pytest.mark.xfail(reason='SCE-827, an engine issue is causing issues')
    @pytest.mark.scanning
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'description': 'Created a {} scan for NQA-1301.'.format(Nessus.TemplateNames.ADVANCED.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST},
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'description': 'Created a {} scan for NQA-1301.'.format(Nessus.TemplateNames.ADVANCED_DYNAMIC.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_no_diff_in_scan_results_for_different_scan_templates_with_same_host_and_plugins(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 5)
        Test to verify no differences in scan results of 'Advanced Dynamic Scan' and 'Advanced Scan'
        if user choose same target and plugins for the scan.

        1. Create a Dynamic scan by applying some filters for specific target
        2. Create an Advanced Scan with enabling only those specific plugins which were filtered out in Dynamic Scan
            (NOT whole Plugin family) and also use the same target as dynamic scan
        3. Launch both the scans and compare both scan results
        4. For same target, result of Advanced Dynamic Scan and Advanced Scan should be same
            if user has configured it with same plugins for both
        """
        advanced_scan_name, advanced_dynamic_scan_name = create_scans
        plugins_filter_data_to_add = [
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'patch detection'},
            {Nessus.Filter.INDEX: 2, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_ID,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 395}]

        # Add dynamic plugins is mandatory for advanced dynamic scan
        applied_plugins = DynamicPlugin().manage_dynamic_plugins(add_plugins=True, preview_plugins=True,
                                                                 plugins_filter_list=plugins_filter_data_to_add)

        scan_form = NewScanForm()
        scan_form.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notification for saving scan is missing or mismatched."

        scan_list = ScanList()
        assert advanced_dynamic_scan_name in scan_list.get_all_scans(), 'Scan should be listed in current scan_list.'

        # Configure the created advanced scan with same plugins
        plugin_id_list_to_enable = []
        scan_list.click_on_scan(scan_name=advanced_scan_name)
        scan_results_page = ScanViewPage()
        scan_results_page.configure_button.click()

        Plugin().disable_all.click()
        sleep(sleep_time=TIME_THREE_SECONDS, reason='Waiting for all plugins get disabled')
        for (plugin_family, plugins_list) in applied_plugins.items():
            for plugin in plugins_list:
                plugin_id_list_to_enable.append(list(plugin)[0])

            LoadingCircle(TIME_THREE_SECONDS)
            PluginsList().toggle_plugins(plugin_family=plugin_family.split(' (')[0],
                                         plugin_id_list=plugin_id_list_to_enable)
            sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for selected plugins to be enabled')

        scan_form.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notification for saving scan is missing or mismatched."

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(TIME_THREE_SECONDS)
        assert advanced_scan_name in scan_list.get_all_scans(), 'Scan should be listed in current scan_list.'

        # Launch both the scan and wait for completion
        sleep(sleep_time=WAIT_NORMAL, reason='Waiting for page elements get loaded')
        ScansPage().launch_scan(scan_list=create_scans)
        for scan in create_scans:
            assert scan_list.launch_scan_and_wait_for_status(scan_name=scan, launch_scan=False), \
                'Scan has not been completed yet'

        # Get the scan results
        sleep(sleep_time=WAIT_NORMAL, reason='Waiting for page elements get loaded')
        advanced_scan_results, advanced_dynamic_scan_results = {}, {}
        for scan in create_scans:
            scan_list.click_on_scan(scan_name=scan)
            LoadingCircle(WAIT_NORMAL)
            if Nessus.TemplateNames.ADVANCED_DYNAMIC in scan:
                advanced_dynamic_scan_results.update({'Host': ScansHostList().get_host_names()})
            else:
                advanced_scan_results.update({'Host': ScansHostList().get_host_names()})

            scan_results_page.vulnerability_tab.click()
            sleep(sleep_time=WAIT_NORMAL, reason='Waiting for vulnerabilities list gets loaded')

            if Nessus.TemplateNames.ADVANCED_DYNAMIC in scan:
                advanced_dynamic_scan_results.update(
                    {'Vulnerabilities': VulnerabilityList().get_all_listed_plugins_with_severity()})
            else:
                advanced_scan_results.update(
                    {'Vulnerabilities': VulnerabilityList().get_all_listed_plugins_with_severity()})

            scan_results_page.back_link.click()

        # Confirm there are results for each scan
        assert len(advanced_dynamic_scan_results['Host']) > 0 and advanced_dynamic_scan_results['Host'][0] != '', \
            'No host found in dynamic scan results'
        assert len(advanced_scan_results['Host']) > 0 and advanced_scan_results['Host'][0] != '', \
            'No host found in advanced scan results'
        assert len(advanced_dynamic_scan_results['Vulnerabilities']) > 0 and advanced_dynamic_scan_results[
            'Vulnerabilities'] != '', \
            'No vulnerabilities found in dynamic scan results'
        assert len(advanced_scan_results['Vulnerabilities']) > 0 and advanced_scan_results['Vulnerabilities'] != 0, \
            'No vulnerabilities found in advanced scan results'

        # Compare both the scan results
        assert advanced_dynamic_scan_results == advanced_scan_results, 'Scan results are mismatched'

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'description': 'Created a {} scan for NQA-1301.'.format(Nessus.TemplateNames.ADVANCED_DYNAMIC.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST, 'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_scan_results_diff_in_advanced_dynamic_scan_for_different_host_with_same_plugins(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 6)
        Test to verify differences in scan results of 'Advanced Dynamic Scan'
        if user choose different target but same plugins for the scan.

        1. Create a Dynamic scan by applying some filters for specific target and run it
        2. Once it gets completed, open it and re-launch it as a Custom scan by selecting 'Custom' from Launch dropdown
        3. Give different target and Launch it
        4. Compare both scan results, result of Advanced Dynamic Scan with different host should be different
            if user has configured it with same plugins for both
        """
        scan_name = create_scans[0]
        scan_results_with_default_host, scan_results_with_custom_host = {}, {}

        # Add dynamic plugins is mandatory for advanced dynamic scan
        dynamic_plugin_page = DynamicPlugin()
        dynamic_plugin_page.manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'patch detection'}])

        dynamic_plugin_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notification for saving scan is missing or mismatched."

        # Launch the scan and navigate to scan results page after completion
        scan_list = ScanList()
        scan_list.loaded()

        assert scan_list.launch_scan_and_wait_for_status(scan_name), 'Scan has not been completed successfully.'

        if is_pro():
            close_pendo_guide_container_banner_for_nessus_pro()

        scan_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)

        # Get scan results for default host
        scan_host_list = ScansHostList()
        scan_results_with_default_host.update({'Host': scan_host_list.get_host_names()})
        sleep(sleep_time=TIME_THREE_SECONDS, reason='Giving time for page elements get loaded')
        scan_results_page = ScanViewPage()
        scan_results_page.vulnerability_tab.click()
        scan_vulnerabilities = VulnerabilityList()
        scan_results_with_default_host.update(
            {'Vulnerabilities': scan_vulnerabilities.get_all_listed_plugins_with_severity()})

        # Re-launch the scan with custom host and navigate to scan results page after completion
        scan_results_page.launch_scan(launch_type=Nessus.Scan.Results.LaunchTypes.CUSTOM,
                                      scan_targets=Nessus.Scan.Target.AWS_LINUX_TARGET_1)

        sleep(sleep_time=TIME_THREE_SECONDS, reason='Giving time to scan gets launched properly')
        scan_results_page.back_link.click()
        assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, launch_scan=False), \
            'Scan has not been completed successfully.'

        scan_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)

        # Get scan results for custom host
        scan_results_with_custom_host.update({'Host': scan_host_list.get_host_names()})
        sleep(sleep_time=TIME_THREE_SECONDS, reason='Giving time for page elements get loaded')
        scan_results_page.vulnerability_tab.click()
        scan_results_with_custom_host.update(
            {'Vulnerabilities': scan_vulnerabilities.get_all_listed_plugins_with_severity()})

        # Compare both scan results
        assert scan_results_with_default_host != scan_results_with_custom_host, \
            'Scan results for advanced dynamic scan are matched while scanning with different host.'

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'description': 'Created a {} scan for NQA-1301.'.format(Nessus.TemplateNames.ADVANCED_DYNAMIC.lower()),
         'target_ip': '{}, {}'.format(Nessus.Scan.Target.PUB_TARGET_3, Nessus.Scan.Target.AWS_LINUX_TARGET_1),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_apply_plugin_rule_on_advanced_dynamic_scan(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 18)
        Test to apply plugin rule on 'Advanced Dynamic Scan'
        1. Create an Advanced Dynamic scan by applying some plugin filters for specific target(default host) and run it
        2. Create a plugin rule with below details:
            {'rule-1': {Plugin ID : 19506, Severity : Hide this result}}
        3. Launch the scan again, and verify the plugin's gets hidden against host in scan result.
        4. Create another plugin rule as below:
            {'rule-2': {Host : 10.255.4.92, Plugin ID : 19506, Severity : Hide this result}}
        5. Launch the scan again, and verify the plugin's gets hidden against host in scan result.
            e.g. - rule-1:  Verify that mentioned plugin (Plugin ID=19506) should get hidden from scan results
                            which are launched after plugin rule-1 is created
                   rule-2:  Verify that mentioned plugin (Plugin ID=19506) should get hidden only from scan result
                            with host mentioned in rule
                   rule-2:  Verify that mentioned plugin (Plugin ID=19506) should not get hidden
                            from other scan result with host other than mentioned
        """
        scan_name = create_scans[0]

        # Add dynamic plugins is mandatory for advanced dynamic scan
        dynamic_plugin_page = DynamicPlugin()
        dynamic_plugin_page.manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'ne'}])

        dynamic_plugin_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notification for saving scan is missing or mismatched."

        # Launch the scan and navigate to scan results page after completion
        scan_list = ScanList()

        try:
            assert scan_list.launch_scan_and_wait_for_status(
                scan_name=scan_name), 'Scan has not been completed successfully.'
        finally:
            self.cat.api.login()
            scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)
            log.info("Scan details are : {}".format(self.cat.api.scans.details(scan_id)))

        # Create a plugin rule with above plugin id, launch the scan and get results
        # Again create another plugin rule, launch the scan and get results
        close_pendo_guide_container_banner_for_nessus_pro()
        plugin_rules_to_be_scanned = [
            {'data_for_rule_1': {'severity': Nessus.Scan.Severity.HIDE,
                                 'plugin_id': TestScans.plugin_id_for_dynamic_scan}},
            {'data_for_rule_2': {'host': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'severity': Nessus.Scan.Severity.HIDE,
                                 'plugin_id': TestScans.plugin_id_for_dynamic_scan}}]

        plugin_rule_page = PluginRulesPage()

        for plugin_rule_data in plugin_rules_to_be_scanned:
            plugin_rule_page.open()
            plugin_rule_page.add_new_plugin_rule(**list(plugin_rule_data.values())[0])
            plugin_rule_list = PluginRulesList()

            assert TestScans.plugin_id_for_dynamic_scan in plugin_rule_list.get_plugin_id(), \
                'Plugin rule has not been created successfully'

            # Launch the scan again and get the scan results with different host
            side_nav = SideNav()
            side_nav.click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
            wait(lambda: visibility_of_element_located(ScansPage().scan_searchbox), waiting_for='scan page to load')

            assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, verify_running=True), \
                'Scan on custom host has not been completed yet.'

            scan_list.click_on_scan(scan_name=scan_name)
            ScanViewPage().host_tab.click()

            ScanVulnerabilities().apply_filter(key='Plugin ID', operator='is equal to',
                                               value=TestScans.plugin_id_for_dynamic_scan)
            ActionCloseModal().wait_for_modal_closed()
            scan_host_list = ScansHostList()

            for key, data in plugin_rule_data.items():
                if key == 'data_for_rule_1':
                    assert len(scan_host_list.get_host_names()) == 0, 'Plugin id is not hidden is one or all hosts'
                elif key == 'data_for_rule_2':
                    assert all([Nessus.Scan.Target.AWS_LINUX_TARGET_1 not in scan_host_list.get_host_names(),
                                Nessus.Scan.Target.PUB_TARGET_3 in scan_host_list.get_host_names()]), \
                        'Plugin id is not hidden in mentioned host or is hidden in the host not mentioned'

            # Clean up code
            plugin_rule_page.open()
            plugin_rule_list.delete_plugin_rule(plugin_id=TestScans.plugin_id_for_dynamic_scan)

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED_DYNAMIC, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED_DYNAMIC)),
         'description': 'Created a {} scan for NQA-1301.'.format(Nessus.TemplateNames.ADVANCED_DYNAMIC.lower()),
         'target_ip': '{}, {}'.format(Nessus.Scan.Target.LOCALHOST, Nessus.Scan.Target.AWS_LINUX_TARGET_1),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_modify_plugin_rule_on_advanced_dynamic_scans(self, create_scans):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 19)
        Test to modify plugin rule on 'Advanced Dynamic Scan'

        1. Create an Advanced Dynamic scan by applying some plugin filters for specific target(default host) and run it
        2. Create a plugin rule with below details:
             Host : 10.255.4.92, Plugin ID : 19506, Severity : High
        3. Launch the scan again, and verify the plugin's severity against 10.255.4.92 is High and severity against
           Localhost is not High.
        4. Modify the above created plugin rule as below:
            Host : Localhost, Plugin ID : 19506, Severity : Critical
        5. Launch the scan again, and verify the plugin's severity against Localhost is Critical and severity against
           10.255.4.92 is not Critical.
        """
        scan_name = create_scans[0]

        # Add dynamic plugins is mandatory for advanced dynamic scan
        dynamic_plugin_page = DynamicPlugin()
        dynamic_plugin_page.manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
            {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
             Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'ne'}])

        dynamic_plugin_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Success notification for saving scan is missing or mismatched."

        # Launch the scan and navigate to scan results page after completion
        scan_list = ScanList()
        assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name), \
            'Scan has not been completed successfully.'

        if is_pro():
            close_pendo_guide_container_banner_for_nessus_pro()

        scan_list.click_on_scan(scan_name=scan_name)
        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("vulnerability_tab"))

        # Get plugin ID to create a plugin rule
        scan_view_page.vulnerability_tab.click()
        scan_vulnerabilities = VulnerabilityList()

        # Create a plugin rule with above plugin id, launch the scan and get results
        # Again modify the above created rule, launch the scan and get results
        plugin_rules_to_be_scanned = [
            {'data_to_add': {'host': Nessus.Scan.Target.AWS_LINUX_TARGET_1, 'severity': Nessus.Scan.Severity.HIGH,
                             'plugin_id': TestScans.plugin_id_for_dynamic_scan}},
            {'data_to_modify': {'host': Nessus.Scan.Target.LOCALHOST, 'severity': Nessus.Scan.Severity.CRITICAL,
                                'plugin_id': TestScans.plugin_id_for_dynamic_scan}}]

        plugin_rule_page = PluginRulesPage()
        for plugin_rule_data in plugin_rules_to_be_scanned:
            plugin_rule_page.open()
            LoadingCircle(WAIT_NORMAL)
            for key, data in plugin_rule_data.items():
                if key == 'data_to_add':
                    plugin_rule_page.add_new_plugin_rule(**data)
                else:
                    plugin_rule_page.edit_plugin_rule(**data)

            plugin_rule_list = PluginRulesList()
            assert TestScans.plugin_id_for_dynamic_scan in plugin_rule_list.get_plugin_id(), \
                'Plugin rule has not been created successfully'

            # Launch the scan again and get the scan results with different host
            side_nav = SideNav()
            side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
            assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, verify_running=True), \
                'Scan has not been completed yet.'

            scan_list.click_on_scan(scan_name=scan_name)
            wait(lambda: scan_view_page.is_element_present('vulnerability_tab'), waiting_for='Scan details to load')

            scan_view_page.host_tab.click()
            wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

            ScanVulnerabilities().apply_filter(key='Plugin ID', operator='is equal to',
                                               value=TestScans.plugin_id_for_dynamic_scan)

            for key, data in plugin_rule_data.items():
                for host in ScansHostList().results:
                    if host == Nessus.Scan.Target.AWS_LINUX_TARGET_1:
                        host.click()
                        if key == "data_to_add":
                            assert scan_vulnerabilities.check_severity_against_plugin(
                                plugin_list=[TestScans.plugin_id_for_dynamic_scan],
                                severity=Nessus.Scan.Severity.HIGH), 'Severity of selected host is incorrect'
                        else:
                            assert not scan_vulnerabilities.check_severity_against_plugin(
                                plugin_list=[TestScans.plugin_id_for_dynamic_scan],
                                severity=Nessus.Scan.Severity.CRITICAL), \
                                'Severity of the host not selected has been changed'

                    elif host == Nessus.Scan.Target.LOCALHOST:
                        host.click()
                        if key == "data_to_add":
                            assert not scan_vulnerabilities.check_severity_against_plugin(
                                plugin_list=[TestScans.plugin_id_for_dynamic_scan],
                                severity=Nessus.Scan.Severity.HIGH), \
                                'Severity of the host not selected has been changed'
                        else:
                            assert scan_vulnerabilities.check_severity_against_plugin(
                                plugin_list=[TestScans.plugin_id_for_dynamic_scan],
                                severity=Nessus.Scan.Severity.CRITICAL), \
                                'Severity of selected host is incorrect'

        # Clean up code
        plugin_rule_page.open()
        LoadingCircle(TIME_THREE_SECONDS)
        plugin_rule_list.delete_plugin_rule(plugin_id=TestScans.plugin_id_for_dynamic_scan)
        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(TIME_THREE_SECONDS)

    @pytest.mark.xfail(reason='Refer JIRA ID NES-8910')
    @pytest.mark.scanning
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_scan_results_diff_filter(self, create_scans):
        """
        NES-8937: Create Automation Test: Filter is not working on scan results diff

        At least two scan histories should be available in history tab.

        1.Login into NM/NP with valid credential.
        2.Go to History tab, and select any two scan history and click on “Diff” button.
        3.Now apply filter from Vulnerabilities tab on obtained diff result
        4.verify the filtered result
        """
        scan_name = create_scans[0]
        scan_form = NewScanForm()
        scan_form.plugin.click()
        plugin_family_list = PluginFamilyList()
        plugin_family_list.toggle_plugin_family(plugin_family_list=plugin_family_list.get_all_plugin_families()[::2])
        scan_form.save_button.click()

        wait(lambda: BasicSearch().is_showing(), waiting_for="Waiting for scan list to populate")
        scan_list = ScanList()
        scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        scan_view_page.configure_button.click()
        Plugin().disable_all.click()
        CATBasePage().js_scroll_into_view(element=scan_form.save_button)
        scan_form.save_button.click()

        HeaderBasePage().scan_link.click()
        scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)
        scan_list.click_on_scan(scan_name=scan_name)

        scan_view_page.history_tab.click()
        scan_list.rows[0].checkbox.click()
        scan_list.rows[1].checkbox.click()

        scan_view_page.diff_button.click()
        primary_results_options = scan_view_page.primary_results_dropdown.option_values
        scan_view_page.primary_results_dropdown.select_by_visible_text(primary_results_options[1]['label'])
        ActionCloseModal().action_button.click()
        LoadingCircle(WAIT_LONG)

        scan_view_page.vulnerability_tab.click()

        for severity in Nessus.Scan.Severity.SEVERITY_LEVELS:
            if severity == Nessus.Scan.Severity.INFO:
                continue
            scan_view_page.apply_filter(key=Nessus.Filter.FilterKeys.SEVERITY,
                                        operator=Nessus.Filter.FilterOperators.EQUAL_TO, value=severity)
            LoadingCircle(WAIT_NORMAL)

            assert VulnerabilityList().check_severity_name(severity=severity), 'Filter is not working properly.'

            scan_view_page.clear_filter()

        scan_view_page.back_link.click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET}]}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_visibility_of_filter(self, create_scans):
        """
        CS-28987: UI test for CS-28264

        1. Create a scan
        2. Go to Configure -> Basic -> Notifications -> Result Filters -> Add Filter
        3. Add a date filter (Plugin Publication Date / later than / 2020-01-01)
        4. Click Save
        5. Test that the filter is still present on page revisit, can be edited, etc.
        """
        scan_name = create_scans[0]
        ScanList().loaded()
        self.go_to_notification_of_scan_basic_setting(scan_name=scan_name)

        basic_setting = BasicSetting()
        basic_setting.set_filter_value(key=Nessus.Filter.FilterKeys.PLUGIN_PUBLICATION_DATE,
                                       operator=Nessus.Filter.FilterOperators.LATER_THAN,
                                       value=(datetime.today().date() + timedelta(days=700)))

        scan_page = ScansPage()
        scan_page.save_button.click()
        LoadingCircle(WAIT_NORMAL)

        header_page = HeaderBasePage()
        header_page.scan_link.click()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='scan list to load')

        self.go_to_notification_of_scan_basic_setting(scan_name=scan_name)

        assert basic_setting.is_element_present('match_dropdown'), 'Result filter match dropdown is not visible.'

        assert basic_setting.is_element_present('filter'), 'Applied Result filter is not visible.'

        header_page.scan_link.click()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='scan list to load')

    @pytest.mark.parametrize('pagination', [
        'yes', pytest.param('no', marks=pytest.mark.xfail(reason='Refer JIRA ID NES-11536'))])
    @pytest.mark.parametrize('empty_trash_and_create_or_import_bulk_scan', [{'scan_count': 51}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_pagination_of_scan_list_in_scan_and_trash_page(self, empty_trash_and_create_or_import_bulk_scan,
                                                            pagination):
        """
        CS-29458: Write UI automation test for CS-28479
        """
        scan_detail = empty_trash_and_create_or_import_bulk_scan
        scan_page = ScansPage()

        if pagination == 'no':
            scan_file = get_file_path('nessus/tests/ui/scans/test_data/' + 'Test_Advanced_Scan_NES-8592.nessus')
            self.cat.api.scans.import_scan(self.cat.api.file.upload(file=scan_file), folder_id=scan_detail[1][0])

            scan_page.refresh()

        # Verify pagination button '>'(next) in Scan page
        self.verify_pagination_button()
        scan_page.pagination_button_next.click()
        scan_list = ScanList()
        current_scan_count = len(scan_list.get_all_scans())
        scan_list.delete_scan(scan_name=scan_detail[0])

        # Verify pagination buttons '<'(previous) and '>'(next) after deleting last scan in Scan page
        self.verify_pagination_after_delete_last_scan(pagination, current_scan_count)

        if pagination == 'no':
            scan_list.delete_scan(scan_name=scan_detail[0])

        # Moves all scans to trash folder
        scan_page.move_scan_to_selected_folder(folder_name=Nessus.Scan.Folder.TRASH, select_all=True, scan_list=[])

        while not scan_page.is_element_present('create_a_new_scan_link'):
            sleep(WAIT_NORMAL, reason='waiting for scans to be moved')

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.TRASH).click()

        # Verify pagination button '>'(next) in Trash page
        self.verify_pagination_button()
        scan_page.pagination_button_next.click()
        ScansTrashPage().delete_scan_from_trash(scan_name=scan_detail[0])

        # Verify pagination buttons '<'(previous) and '>'(next) after deleting last scan in Trash page
        self.verify_pagination_after_delete_last_scan(pagination, current_scan_count)

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_filter_value_persist_under_vulnerability_tab(self, import_scan_via_api):
        """
        NES-9256: Create UI automation test to validate NES-9124 fix

        Steps:
        1. Login into NM/NP with valid credential.
        2. Open completed scan and go to Vulnerabilities tab.
        3. Open filter and set filter (eg. Host Name = 1)
        4. Add new filter after click on add sign and set like Severity = High
        5. Now Delete previously created filter ( Host Name) and try to add new filter after Severity filter
        6. Verify that user should able to persist previously set filter even after removing other filters.
        """
        # Import scan and go to imported scan
        import_scan_name = import_scan_via_api[0]
        get_driver_no_init().refresh()

        ScanList().click_on_scan(scan_name=import_scan_name)

        # Go to vulnerabilities tab and click on filter
        scan_view_page = ScanViewPage()
        scan_view_page.vulnerability_tab.click()
        scan_view_page.filter_link.click()

        # Set filter values under vulnerabilities tab
        filter_values = {Nessus.Filter.FilterKeys.HOSTNAME: Nessus.Scan.Target.LOCALHOST,
                         Nessus.Filter.FilterKeys.SEVERITY: Nessus.Scan.Severity.HIGH}

        for filter_key, filter_value in filter_values.items():
            scan_view_page.apply_filter(key=filter_key, operator=Nessus.Filter.FilterOperators.EQUAL_TO,
                                        value=filter_value, apply=False)

        # Fetch values from filter and removes previously filled filter
        before_filter_value = scan_view_page.get_filter_value_text(index=scan_view_page.applied_filter_count)
        scan_view_page.remove_specific_filter(index_value=(scan_view_page.applied_filter_count - 1))

        scan_view_page.add_filter.click()
        after_filter_value = scan_view_page.get_filter_value_text(index=(scan_view_page.applied_filter_count - 1))

        assert before_filter_value == after_filter_value, 'User can not persist previously set filter values after ' \
                                                          'removing other filters'

        scan_view_page.clear_filter_link.click()

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'folder': Nessus.Scan.Folder.MY_SCANS.split(' (')[0], 'target_ip': Nessus.Scan.Target.PUB_TARGET_2,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED))}]}], indirect=True)
    @pytest.mark.nessus_manager
    def test_scan_results_host_tab_if_diff_applied_for_different_host(self, create_scans):
        """
        NES-9429: Verify that after apply Diff host tab should be displayed

        Steps:
        1. Log in NM/NP with the valid credential.
        2. Created one scan and launch it.
        3. After completed successfully above created scan then relaunch with different target host which one not used
           on the first time.
        4. Go to the History tab and select both of history
        5. "Diff" option has appeared on top of the web page.
        6. Click on "Diff" button and select one history and click on Continue button

        Scenario tested:
        [x] Verify that Right target host should be displayed under the hosts tab
        [x] Verify the detail of vulnerabilities should be displaying after applying Diff like port no, number of
            hosts, etc. for Diff function for comparing two history
        """
        scan_name = create_scans[0]
        scan_list = ScanList()
        scan_list.loaded()

        # Launch created scan and wait to be completed
        assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name), \
            'Either it took soo long or failed to launch the scan'

        scan_list.click_on_scan(scan_name)
        scan_view_page = ScanViewPage()
        scan_view_page.configure.click()

        scans_page = ScansPage()
        new_host = Nessus.Scan.Target.PUB_TARGET_4
        scans_page.targets_textarea.value = scans_page.targets_textarea.text + ", " + new_host
        scans_page.save_button.click()

        # Verify success notification after configuring the scan
        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Modification in scan wasn't successful"

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        scan_list.loaded()

        # Launch created scan and wait to be completed
        assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name), \
            'Either it took soo long or failed to relaunch the scan after modifications'

        scan_list.click_on_scan(scan_name)
        wait(lambda: scan_view_page.is_element_present('host_tab'), waiting_for="Hosts page to properly load.")

        scan_view_page.host_tab.click()
        wait(lambda: scan_view_page.is_element_present('search_box'), waiting_for="Hosts page to properly load.")

        scan_host_list = ScansHostList()
        wait(lambda: visibility_of_element_located(scan_view_page.search_icon), waiting_for='Host list to populate')

        # Verify that added new host is displayed in host list
        assert new_host in scan_host_list.get_host_names(), 'The new host isn\'t available in host-tab details'

        # Verify 'History' tab is displayed in scan results
        assert scan_view_page.is_element_present("history_tab"), 'History tab isn\'t available'

        scan_view_page.history_tab.click()

        assert all([True if not row.checkbox.check() else False for row in scan_list.rows]), \
            "Selecting both the histories wasn't successful"

        # Verify 'Diff' button is displayed on top right corner after selecting history
        assert scan_view_page.is_element_present("diff_button"), 'Diff button isn\'t available'

        scan_view_page.diff_button.click()
        primary_results_modal = ActionCloseModal()
        primary_results_modal.accept_action()
        primary_results_modal.wait_for_modal_closed()

        # Verify 'Host' tab is displayed after applying diff between history
        assert scan_view_page.is_element_present("host_tab"), 'Host tab isn\'t available'

        # Verify that added new host is displayed in host list after applying diff between history
        assert new_host in scan_host_list.get_host_names(), \
            'The new host isn\'t available in host-tab details after applying diff'

        scan_view_page.vulnerability_tab.click()

        # Verify vulnerability tab and results are displayed after applying diff between history
        assert len(VulnerabilityList().results), 'Vulnerabilities are empty'
        HeaderBasePage().scan_link.click()

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_visibility_of_permissions_link_under_scans_basic_settings(self):
        """
        NES-13103 [Automation]: Verify that "Permissions" tab is not visible for Scans/Policies in Nessus
                                professional/Home

        Scenario Tested:
        [x] Verify that "Permissions" tab should not be visible for Scans in Nessus professional/Home.
        """
        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present('create_a_new_scan_link') or scan_page.is_element_present(
            'scan_searchbox'), waiting_for='Scan page to load properly')

        scan_page.new_scan_button.click()
        wait(lambda: scan_page.is_element_present('vuln_template_section'),
             waiting_for='Waiting for vulnerabilities section to get populated')

        scan_page.select_scan_type(type_of_scan=API.Permissions.Types.SCANNER)
        scan_page.click_by_scan(scan_text=Nessus.TemplateNames.ADVANCED)
        wait(lambda: NewScanForm().is_element_present('name_field'), waiting_for='new scan form to load properly.')

        is_permission_tab_visible = BasicSetting().is_element_present("permissions")

        if is_manager():
            assert is_permission_tab_visible, "'Permissions' tab is missing in Nessus Manager."
        else:
            assert not is_permission_tab_visible, "'Permissions' tab is visible in Nessus Professional/Home."

    @pytest.mark.xray(test_key='NES-15579')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_manager
    def test_verify_debugging_log_report_showing_in_list_view_in_schedule_scan(self):
        """
        NES-15579: Verify list view in all types of scans

        Scenario Tested:
        [x] Verify 'Debugging Log Report' should be appear in list/table view in schedule scan results.
        """
        api_object, scan_target, timezone = self.cat.api, Nessus.Scan.Target.PUB_TARGET_4, 'America/New_York'
        payload = load_testdata(get_file_path('nessus/tests/api/scan/test_data/test_scan_with_packet_capture.json'))

        scan_details_dict = {"enable_plugin_debugging": "yes", "text_targets": scan_target,
                             "name": random_name(prefix='Automated-Scan-'), "enabled": True,
                             "starttime": (pytz.utc.localize(datetime.utcnow()) + timedelta(minutes=2)).astimezone(
                                 pytz.timezone(timezone)).strftime("%Y%m%dT%H%M00"), "timezone": timezone,
                             "launch": "ONETIME", "rrules": "FREQ=ONETIME"}

        payload.get('settings').update(scan_details_dict)
        scan_details = create_scan_helper(api_handler=api_object, file_name="", payload=payload,
                                          template_title='basic')[0]['scan']

        scan_id, scan_name = scan_details['id'], scan_details['name']
        api_object.scans.launch(scan_id=scan_id)

        assert wait_scan_state(api=api_object, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                               timeout=TIME_FIVE_MINUTES), "Schedule scan is not getting launched successfully."

        with polling_ui():
            is_scan_completed = wait_scan_state(api=api_object, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                                timeout=TIME_THIRTY_MINUTES)

        assert is_scan_completed, "Failed to get completed the scan with plugin debugging enabled."

        verify_plugin_debugging_log_output_table(scan_name=scan_name, scan_target=scan_target)

    @pytest.mark.parametrize('scan_type', ['imported_scan', 'created_scan'])
    def test_cvss_temporal_score_accepts_non_decimal_integer_value(self, scan_type):
        """
        NES-15722 [UI-Automation]: Verify that CVSS temporal scores accepts the non-decimal integer values too while
                                   filtering results (unlike the base score)

        Scenario Tested:
        [x] Verify that CVSS temporal scores accepts the non-decimal integer values too while filtering results
            (unlike the base score)
        """
        scan_name = None
        scan_page = ScansPage()
        scan_list = ScanList()

        try:
            if scan_type == "created_scan":
                scan_details = create_scan_helper(self.cat.api, file_name=get_file_path(
                    'nessus/tests/api/scan/test_data/test_advanced_scan.json'), template_title='advanced')

                scan_name = scan_details[0]['scan']['name']

                # Launching created scan and waiting to be completed
                assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name), \
                    "launch of created scan wasn't successful"
            else:
                scan_file = get_file_path(
                    'nessus/tests/ui/scans/test_data/' + 'Basic_Network_Scan_for_NES-13053_pfx4mo.nessus')

                file_uploaded = self.cat.api.file.upload(file=scan_file, encrypted=True)
                imported_scan_response = self.cat.api.scans.import_scan(file_uploaded)

                scan_page.refresh()
                wait(lambda: scan_page.is_element_present("scan_searchbox"))

                scan_name = imported_scan_response['scan']['name']

            # Click on scan and go to vulnerability tab
            scan_list.click_on_scan(scan_name=scan_name)
            scan_view_page = ScanViewPage()
            wait(lambda: visibility_of_element_located(scan_view_page.vulnerability_tab),
                 waiting_for='Vulnerabilities to get loads')

            scan_view_page.vulnerability_tab.click()
            time.sleep(6)
            get_driver_no_init().refresh()

            key_labels = ['CVSS v2.0 Base Score', 'CVSS v2.0 Temporal Score', 'CVSS v3.0 Base Score',
                          'CVSS v3.0 Temporal Score']

            if scan_type == "created_scan":
                key_labels.pop()

            for label in key_labels:
                value_to_be_enter = [round(random.uniform(1.0, 9.0), 1), randint(1, 10)]

                for value in value_to_be_enter:
                    scan_view_page.clear_filter()
                    scan_view_page.filter_link.click()

                    action_modal = ActionCloseModal()
                    wait(lambda: action_modal.is_element_present('modal'))

                    scan_view_page.apply_filter(key=label, operator=Nessus.Filter.FilterOperators.EQUAL_TO,
                                                value=str(value), apply=False)

                    assert "error" not in scan_view_page.get_filter_value_text_element(index_value=1).get_css_classes(), \
                        "Filter value input field does not accept non-decimal integer value yet for '{}'.".format(label)

                    scan_view_page.clear_filter_link.click()
                    action_modal.wait_for_modal_closed()

            scan_view_page.back_link.click()
            wait(lambda: scan_page.is_element_present("scan_searchbox"))
        finally:
            scan_list.delete_scan(scan_name=scan_name)


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestBulkScanOperation:
    """
    Test case for common functionality like copy, move, launch with bulk scans.

    NES-9427: UI Automation: Scans | Verify that user should be able to select scan in bulk like 200 to 300, and
              perform all function like a copy, move, launch, etc with bulk data
    """

    @staticmethod
    def launch_or_stop_scans(operation: str, select_all_records: bool = False) -> None:
        """
        Launch or Stop all scan(s)

        :param str operation: scan operations like Launch or Stop
        :param bool select_all_records: if true then it will select all the checkbox of all the scans present
        :return: None
        """
        scan_page = ScansPage()
        scan_page.select_all_checkbox.check()

        if select_all_records:
            ScanViewPage().select_all_records.click()

        LoadingCircle(WAIT_NORMAL)
        scan_page.js_scroll_into_view(element=scan_page.more_button)
        scan_page.more_button.click()

        if operation == 'Launch':
            scan_page.launch_option.click()
        elif operation == 'Stop':
            scan_page.stop_option.click()

        ActionCloseModal().accept_action()

    @pytest.mark.parametrize("empty_trash_and_create_or_import_bulk_scan", [{'scan_count': 250, 'import_scan': False}],
                             indirect=True)
    def test_copy_scans_to_folder(self, empty_trash_and_create_or_import_bulk_scan):
        """
        Scenario Tested:
        [x] Verify that user should be able to copy scan in bulk like 200 to 300.
        """
        scans_page = ScansPage()
        side_nav = SideNav()
        notification_actions = NotificationActions()

        scan_details = empty_trash_and_create_or_import_bulk_scan
        scan_count = scan_details[1]
        test_copy_folder = random_name(prefix="bulk-scans-")[:20]

        if notification_actions.is_element_present('remove_notifications'):
            notification_actions.remove_all()

        scans_page.create_new_folder(folder_name=test_copy_folder)

        # Verify success notification message after creating new folder
        assert Notifications().successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_added, \
            "Success notification for creating folder is missing or mismatched."

        # Verify created folder is displayed in side navigation panel
        assert test_copy_folder in side_nav.get_all_sidenav_folders_name(), "Test copy folder was not created"

        scans_page.copy_scan_to_selected_folder(scan_list=scan_details[0], folder_name=test_copy_folder,
                                                select_all=True, select_all_records=True)
        action_close_modal = ActionCloseModal()
        action_close_modal.wait_for_modal_closed(timeout_seconds=TIME_FIVE_MINUTES)

        side_nav.click_by_link_text(test_copy_folder + " ")
        copied_scan_records = ScanList().get_bulk_scan_records()
        copied_scans = [scan.split("Copy of ")[1] for scan in copied_scan_records]

        # Verify that copy bulk scan operation is performed successfully
        assert len(set.intersection(set(copied_scans), set(scan_details[0]))) == scan_count and [
            "Copy of " + scan in copied_scan_records for scan in scan_details[0]], "Copy of bulk scans was unsuccessful"

        side_nav.get_sidenav_element(element_name=test_copy_folder).click()
        side_nav.delete_custom_folder(folder_name=test_copy_folder)
        action_close_modal.wait_for_modal_closed()
        wait(lambda: side_nav.is_element_present('sidenav_links'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for="Side-navigation links to load properly")

        # Verify created folder is not displayed after deleting the folder
        assert test_copy_folder not in side_nav.get_all_sidenav_folders_name(), "Test copy folder was not deleted"

    @pytest.mark.parametrize("empty_trash_and_create_or_import_bulk_scan", [{'scan_count': 250, 'import_scan': False}],
                             indirect=True)
    def test_move_scans_to_folder(self, empty_trash_and_create_or_import_bulk_scan):
        """
        Scenario Tested:
        [x] Verify that user should be able to move scan in bulk like 200 to 300.
        """
        scan_details = empty_trash_and_create_or_import_bulk_scan
        scan_count = scan_details[1]
        test_move_folder = "move-test-folder"

        scans_page = ScansPage()
        scans_view_page = ScanViewPage()
        side_nav = SideNav()
        notification_actions = NotificationActions()

        if notification_actions.is_element_present('remove_notifications'):
            notification_actions.remove_all()

        scans_page.refresh()
        scan_list = ScanList()
        scan_list.loaded()

        scans_page.create_new_folder(folder_name=test_move_folder)
        notification = Notifications()

        # Verify success notification after creating new folder
        assert notification.successes[-1] == Messages.NotificationMessages.SideNavFolders.folder_added, \
            "Success notification for creating folder is missing or mismatched."

        # Verify created folder is displayed in side navigation panel
        assert test_move_folder in side_nav.get_all_sidenav_folders_name(), "Test move folder was not created"

        scans_page.move_scan_to_selected_folder(scan_list=scan_details[0], folder_name=test_move_folder,
                                                select_all=True, select_all_records=True)
        wait(lambda: scans_view_page.empty_result.text == Messages.NotificationMessages.
             Scans.empty_scan_page_message, timeout_seconds=TIME_FIVE_MINUTES,
             waiting_for="no scans present in {} folder".format(scan_details[2][1]))

        # Verify success notification message after moving all scans
        assert notification.successes[-1] == Messages.NotificationMessages.Scans.scans_moved, \
            "Success notifications for scans moved to selected folder is mismatched or missing."

        side_nav.click_by_link_text(test_move_folder + " ")
        wait(lambda: scans_page.is_element_present('scan_searchbox'), waiting_for="My Scans page to load properly",
             timeout_seconds=TIME_THIRTY_SECONDS)
        moved_scans = scan_list.get_bulk_scan_records()

        # Verify that move bulk scan operation is performed successfully
        assert len(set.intersection(set(moved_scans), set(scan_details[0]))) == scan_count and [
            scan in moved_scans for scan in scan_details[0]], "Moving of bulk scans to My Scans folder was unsuccessful"

        side_nav.delete_custom_folder(folder_name=test_move_folder)

        # Verify success notification message after deleting custom folder
        assert notification.successes[-1] == Messages.NotificationMessages.SideNavFolders.delete_folder, \
            "Success notifications for folder deletion is mismatched or missing."

        # Verify created folder is not displayed after deleting the folder
        assert test_move_folder not in side_nav.get_all_sidenav_folders_name(), "Test move folder was not deleted"

    @pytest.mark.parametrize("empty_trash_and_create_or_import_bulk_scan", [{'scan_count': 250, 'import_scan': False}],
                             indirect=True)
    def test_delete_scans_to_folder(self, empty_trash_and_create_or_import_bulk_scan):
        """
        Scenario Tested:
        [x] Verify that user should be able to delete scan in bulk like 200 to 300.
        """
        scan_details = empty_trash_and_create_or_import_bulk_scan
        scan_count = scan_details[1]

        scans_page = ScansPage()
        scans_view_page = ScanViewPage()
        side_nav = SideNav()

        scans_page.refresh()
        scan_list = ScanList()
        scan_list.loaded()

        scans_page.move_scan_to_selected_folder(scan_list=scan_details[0], folder_name=Nessus.Scan.Folder.TRASH,
                                                select_all=True, select_all_records=True)
        wait(lambda: scans_view_page.empty_result.text == Messages.NotificationMessages.Scans.
             empty_scan_page_message, timeout_seconds=TIME_NINETY_SECONDS)

        wait(lambda: side_nav.is_element_present('sidenav_links'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for="Side-navigation links to load properly")

        side_nav.click_by_link_text(Nessus.Scan.Folder.TRASH + " ")
        wait(lambda: scans_page.is_element_present('scan_searchbox'), waiting_for="My Scans page to load properly",
             timeout_seconds=TIME_THIRTY_SECONDS)
        deleted_scans = scan_list.get_bulk_scan_records()

        # Verify that delete bulk scan operation is performed successfully
        assert len(set.intersection(set(deleted_scans), set(scan_details[0]))) == scan_count and [
            scan in deleted_scans for scan in scan_details[0]], "Moving of bulk scans to Trash was unsuccessful"

    @pytest.mark.parametrize("empty_trash_and_create_or_import_bulk_scan", [{'scan_count': 100, 'import_scan': False}],
                             indirect=True)
    def test_launch_bulk_scans(self, empty_trash_and_create_or_import_bulk_scan, nessus_api_login):
        """
        Scenario Tested:
        [x] Verify that user should be able to launch scan in bulk like 200 to 300.
        """
        scan_details = empty_trash_and_create_or_import_bulk_scan
        scan_count = scan_details[1]
        notification_actions = NotificationActions()

        if notification_actions.is_element_present('remove_notifications'):
            notification_actions.remove_all()

        scan_ids = [scan['id'] for scan in nessus_api_login.scans.get_scans()['scans'] if scan['name'] in
                    scan_details[0]]

        self.launch_or_stop_scans(operation='Launch', select_all_records=True)
        wait(lambda: not ActionCloseModal().is_element_present('modal'), waiting_for='Modal is closed',
             timeout_seconds=TIME_FIFTEEN_MINUTES * 4)

        launch_scan_details = [True for scan_id in scan_ids if nessus_api_login.scans.get_status(
            scan_id=scan_id) != API.Scan.Status.EMPTY]

        # Verify that launch bulk scan operation is performed successfully
        assert len(launch_scan_details) == scan_count, "Failed to launch all bulk scans."

