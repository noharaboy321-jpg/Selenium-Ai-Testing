"""
Tests related "Packet capture" settings under advanced setting of scan configuration

:copyright: Tenable Network Security, 2017
:date: Sep 21, 2021
:last_modified: Oct 12, 2021
:author: @kpanchal.ctr, @krpatel.ctr
"""
import os
import random
from random import randint

import pytest
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_THIRTY_SECONDS, TIME_THIRTY_MINUTES, \
    TIME_FIFTEEN_SECONDS, TIME_FIVE_MINUTES, WAIT_SHORT
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util.util import random_name, random_string
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_nessus_log_dir, delete_file_from_nessus_directory, \
    get_file_list_from_nessus_directory
from nessus.helpers.scan import create_packet_capture_scan_helper, delete_all_pcap_files_from_debug_logs_table, \
    get_scan_id, expected_generated_pcap_file_name
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.utility import get_downloaded_files_chrome
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import Nessus, API, SortOrder
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView
from nessus.pageobjects.debug_logs.debug_logs_page import DebugLogsPage, DebugLogsList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.scans.new_scan_form import ScanType, NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import AdvancedSettings
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()

template_constant = Nessus.TemplateNames
unwanted_scan_templates = [template_constant.HOST_DISCOVERY, template_constant.MOBILE_DEVICE,
                           template_constant.MDM_AUDIT, template_constant.PCI_EXTERNAL,
                           template_constant.REMOTE_MONITORING_MANAGE, template_constant.PING_ONLY_DISCOVERY,
                           template_constant.AGENT_RESET, template_constant.CREDENTIAL_VALIDATION]


def click_on_new_scan_button_and_go_to_new_scan_form(template_name: str) -> None:
    """
    Click on 'New Scan' button and go to new scan form after selecting given scan template

    :param str template_name: scan template name
    :return: None
    """
    scan_page = ScansPage()
    scan_page.new_scan_button.click()
    wait(lambda: scan_page.is_element_present('vuln_template_section'),
         waiting_for='Waiting for vulnerabilities section to get populated')

    scan_type = ScanType()
    scan_type.select_scan_type(type_of_scan=API.Permissions.Types.SCANNER)
    scan_type.click_by_scan(scan_text=template_name)
    wait(lambda: NewScanForm().is_element_present('name_field'), waiting_for='new scan form to load properly.')


def click_on_general_link_inside_scan_advanced_setting(template_name: str) -> None:
    """
    Click on 'General' link inside Advanced scan setting sub menu after selecting scan type 'Custom'

    :param str template_name: scan template name
    :return: None
    """
    sleep(WAIT_NORMAL, reason="It takes little bit time to get displayed the scan type drop-down options")
    scan_advanced_setting = AdvancedSettings()
    scan_advanced_setting.get_settings_element(setting_name=Nessus.Scan.SettingsTypes.ADVANCED).click()

    if template_name in [template_constant.BASIC_NETWORK, template_constant.MALWARE, template_constant.WEB_APP,
                         template_constant.AUDIT_PATCH, template_constant.PRINT_NIGHTMARE, template_constant.SCAP_OVAL,
                         template_constant.INTERNAL_PCI, template_constant.COMPLIANCE_AUDIT,
                         template_constant.LOG_4_SHELL, template_constant.LOG4SHELL_REMOTE_CHECKS,
                         template_constant.LOG4SHELL_VULNERABILITY_ECOSYSTEM, template_constant.CISA_ALERTS,
                         template_constant.CONTILEAKS]:
        scan_advanced_setting.scan_type_drop_down.select_by_visible_text(Nessus.Scan.Results.LaunchTypes.CUSTOM)
        scan_advanced_setting.click_link_inside_link(setting_value=Nessus.Scan.SettingsTypes.ADVANCED,
                                                     link_text=Nessus.Scan.SettingsBasicSubMenu.GENERAL)


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures("login", "nessus_api_login")
class TestPacketCaptureSettingsForPro:
    """ Covers Packet capture Settings Related Test Cases for Nessus Pro """

    cat = None
    logs_dir = get_nessus_log_dir()
    scan_file_path = get_file_path('nessus/tests/api/scan/test_data/test_scan_with_packet_capture.json')

    expected_templates = [template for template in template_constant.SCAN_TEMPLATE_LIST if
                          template not in unwanted_scan_templates]

    @staticmethod
    def verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(nessus_api: NessusAPI,
                                                                          scan_name: str) -> None:
        """
        Verifies that given pcap generated file listed in debug logs list

        :param NessusAPI nessus_api: Nessus API instance
        :param str scan_name: scan name to be verified
        :return: None
        """
        logs_dir = __class__.logs_dir
        expected_file_name = expected_generated_pcap_file_name(api=nessus_api, scan_name=scan_name)
        debug_logs_page = DebugLogsPage()

        if not get_driver_no_init().current_url.endswith("/settings/logs"):
            debug_logs_page.open()
        else:
            debug_logs_page.refresh()

        wait(lambda: debug_logs_page.is_element_present("search_logs_field"),
             waiting_for="'Debug Logs' table gets displayed properly")

        assert expected_file_name in DebugLogsList().get_all_pcap_files_name(), \
            "Packet capture file is not getting generated for '{}' scan.".format(scan_name)

        files_under_logs_dir = get_file_list_from_nessus_directory(nessus_dir=logs_dir)

        assert expected_file_name in files_under_logs_dir, "Packet capture file is not getting generated under '{}' " \
                                                           "directory for '{}' scan.".format(logs_dir, scan_name)

    @staticmethod
    def delete_pcap_generated_file_from_debug_logs_table_and_logs_directory(nessus_api: NessusAPI,
                                                                            scan_name: str) -> None:
        """
        Deletes pcap generated file with given name from debug logs table and nessus logs directory

        :param NessusAPI nessus_api: Nessus API instance
        :param str scan_name: scan name to be deleted
        :return: None
        """
        expected_file_name = expected_generated_pcap_file_name(api=nessus_api, scan_name=scan_name)

        if not get_driver_no_init().current_url.endswith("/settings/logs"):
            debug_logs_page = DebugLogsPage()
            debug_logs_page.open()
            wait(lambda: debug_logs_page.is_element_present("search_logs_field"),
                 waiting_for="'Debug Logs' table gets displayed properly")

        DebugLogsList().delete_pcap_file(file_name=expected_file_name)

        delete_file_from_nessus_directory(file_name=expected_file_name, nessus_dir=__class__.logs_dir)

    @pytest.mark.parametrize("scan_template", expected_templates)
    def test_visibility_of_packet_capture_toggle_button_in_all_scan_templates(self, scan_template):
        """
        NES-13475 [Automation]: Verify in Nessus Pro 'Packet Capture' toggle is available on Scan configuration

        Scenario's Tested:
        [x] Verify that 'Packet Capture' toggle button should appear in all available scan templates.
        [x] Verify Packet Capture option for all scan templates except HostDiscovery
        [x] Verify that below options should be visible along with hint message under Packet capture setting
            - Target to capture (Provide one target to capture network scan traffic on next scan launch. Note: can
            not use localhost/127.0.0.1)
            - Ports to capture (Provide ports or port ranges to capture); default value: 1-65535
        """
        click_on_new_scan_button_and_go_to_new_scan_form(template_name=scan_template)

        click_on_general_link_inside_scan_advanced_setting(template_name=scan_template)
        sleep(WAIT_NORMAL, reason="It takes little bit time to load scan's advanced settings")
        scan_advanced_setting = AdvancedSettings()

        if scan_template == template_constant.HOST_DISCOVERY:
            assert not scan_advanced_setting.is_element_present("packet_capture_toggle_button"), \
                "'Packet Capture' toggle button is showing in scan advanced setting in '{}' template which " \
                "should not be.".format(scan_template)
        else:
            assert all([scan_advanced_setting.is_element_present("packet_capture_toggle_button"),
                        scan_advanced_setting.packet_capture_toggle_button.get_attribute("data-value") == "no"]), \
                "'Packet Capture' toggle button is either missing in scan advanced setting in '{}' template or " \
                "showing enabled by default.".format(scan_template)

            scan_advanced_setting.packet_capture_toggle_button.click()

            assert all([scan_advanced_setting.is_element_present("target_to_capture_field"),
                        scan_advanced_setting.target_to_capture_field.value == "",
                        scan_advanced_setting.is_element_present("target_to_capture_required_badge"),
                        scan_advanced_setting.is_element_present("ports_to_capture_field"),
                        scan_advanced_setting.ports_to_capture_field.value == Nessus.Scan.SettingsAdvancedSubMenu.
                       DEFAULT_CAPTURE_PORT_RANGE]), \
                "'Target to capture' or 'Ports to capture' fields are either missing after enabling 'Packet Capture' " \
                "toggle button or it's default values are mismatched in '{}' template.".format(scan_template)

            assert all([scan_advanced_setting.is_element_present("target_to_capture_hint_msg"),
                        scan_advanced_setting.target_to_capture_hint_msg.text == Nessus.Scan.SettingsAdvancedSubMenu.
                       TARGET_TO_CAPTURE_HINT_MSG,
                        scan_advanced_setting.is_element_present("ports_to_capture_hint_msg"),
                        scan_advanced_setting.ports_to_capture_hint_msg.text == Nessus.Scan.SettingsAdvancedSubMenu.
                       PORTS_TO_CAPTURE_HINT_MSG]), \
                "'Target to capture' or 'Ports to capture' hint messages are either missing or mismatched in " \
                "'{}' template.".format(scan_template)

    @pytest.mark.parametrize("invalid_targets", ["", "localhost", "127.0.0.1", "172.26.48.10, 172.26.48.15",
                                                 "172.26.48.0/24"])
    @pytest.mark.parametrize("invalid_ports", ["", 0, 65536, "abed", "6vv3vi"])
    def test_validation_for_packet_capture_required_fields(self, invalid_targets, invalid_ports):
        """
        NES-13476 [Automation]: Verify validation on required field "Target to capture" and "Ports to capture"

        Scenario's Tested:
        [x] Verify validation on required fields "Target to capture" and "Ports to capture"
        [x] Verify validation on entering localhost or 127.0.0.1 as target to capture
        [x] Verify only one target is allowed to add, for multiple target it will not save and show validation message
        [x] Verify port to capture value (out of allowed range)
        """
        scan_templates_list = [template for template in template_constant.SCAN_TEMPLATE_LIST if template not in
                               unwanted_scan_templates]
        scan_template = random.sample(scan_templates_list, k=1)[0]

        click_on_new_scan_button_and_go_to_new_scan_form(template_name=scan_template)

        click_on_general_link_inside_scan_advanced_setting(template_name=scan_template)
        scan_advanced_setting = AdvancedSettings()

        scan_advanced_setting.packet_capture_toggle_button.click()

        # Enters invalid targets into field
        scan_advanced_setting.target_to_capture_field.clear()
        target_to_enter = invalid_targets if invalid_targets else Keys.SPACE
        scan_advanced_setting.target_to_capture_field.value = target_to_enter
        sleep(WAIT_SHORT, reason="It takes little bit time to highlight the field for error")

        assert 'error' in scan_advanced_setting.target_to_capture_field.get_css_classes(), \
            "'Target to capture' field is not highlighting with red border even after entering " \
            "invalid host '{}'.".format(invalid_targets)

        # Enters invalid ports into field
        scan_advanced_setting.ports_to_capture_field.clear()
        port_to_enter = invalid_ports if invalid_ports else Keys.SPACE
        scan_advanced_setting.target_to_capture_field.value = port_to_enter
        sleep(WAIT_SHORT, reason="It takes little bit time to highlight the field for error")

        assert 'error' in scan_advanced_setting.ports_to_capture_field.get_css_classes(), \
            "'Ports to capture' field is not highlighting with red border even after entering " \
            "invalid port '{}'.".format(invalid_ports)

        scan_advanced_setting.save_button.click()
        notification = Notifications()

        assert notification.errors[-1] in [Messages.NotificationMessages.target_to_capture_error,
                                           Messages.NotificationMessages.ports_to_capture_error], \
            "Error notification is missing or mismatched after entering invalid target '{}' and port '{}'.".format(
                invalid_targets, invalid_ports)

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_packet_capture_scan", [{"scan_file_path": scan_file_path,
                                                             "scan_template": "basic"}], indirect=True)
    @pytest.mark.parametrize("perform_scan", [False, True])
    def test_visibility_of_debug_logs_menu_in_side_navigation_panel(self, create_packet_capture_scan, perform_scan):
        """
        NES-13477 [Automation]: Verify a "Debug Logs" option at left side menu of Settings tab of nessus

        Scenario's Tested:
        [x] Verify a "Debug Logs" option at left side menu under Settings tab of Nessus Pro
        [x] Verify if no debug logs available then 'No logs have been created.' message should display.
        [x] Verify below options if any debug logs available
            - Table with columns: Filename | Start Time | End Time | Last Modified | download icon, 'x'(delete) icon
              for each entry
            - Search box for "Search Logs" with count label
        """
        scan_id = int(create_packet_capture_scan[0])

        if perform_scan:
            self.cat.api.scans.launch(scan_id=scan_id)

            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                   timeout=TIME_THIRTY_MINUTES)
        else:
            delete_all_pcap_files_from_debug_logs_table()

        HeaderBasePage().settings_link.click()
        wait(lambda: OverView().is_element_present("nessus_version"), timeout_seconds=TIME_THIRTY_SECONDS * 2,
             waiting_for='about overview page gets load properly.')

        debug_logs_menu = SideNav().get_sidenav_element(element_name=Nessus.SideNavSettings.DEBUG_LOGS)

        assert visibility_of_element_located(locator=debug_logs_menu), \
            "'Debug Logs' menu is not showing in side navigation panel which should be."

        debug_logs_menu.click()
        debug_logs_page = DebugLogsPage()
        wait(lambda: debug_logs_page.is_element_present("search_logs_field") or debug_logs_page.is_element_present(
            "empty_debug_logs"), waiting_for="'Debug Logs' table gets displayed properly")

        if perform_scan:
            column_names = [column_name.text.strip() for column_name in DebugLogsList().columns]

            assert all([column_name in column_names for column_name in Nessus.DebugLogs.DEBUG_LOGS_TABLE_COLUMNS]), \
                "Debug Logs table does not have one or more columns."
        else:
            empty_log_message = Nessus.DebugLogs.EMPTY_LOGS_MESSAGE

            assert all([debug_logs_page.is_element_present("empty_debug_logs"),
                        debug_logs_page.empty_debug_logs.text == empty_log_message]), \
                "'{}' is either not showing in 'Debug Logs' Page or getting mismatched.".format(empty_log_message)

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_packet_capture_scan", [{"scan_file_path": scan_file_path,
                                                             "scan_template": "basic"}], indirect=True)
    def test_pcap_file_gets_generated_after_scan_execution(self, create_packet_capture_scan):
        """
        NES-13499 [Automation]: Verify packet capture for IPv4, IPv6 and DNS targets

        Scenario's Tested:
        [x] Verify that after scan execution, "pcap_SCANNAME_SCANID.tar.gz" file will get generated.
        """
        scan_id, scan_name = int(create_packet_capture_scan[0]), create_packet_capture_scan[1]

        self.cat.api.scans.launch(scan_id=scan_id)

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES)

        self.verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(nessus_api=self.cat.api,
                                                                               scan_name=scan_name)

        expected_pcap_file_name = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)
        pcap_file_path = os.path.join(self.logs_dir, expected_pcap_file_name)
        expected_pcapng_file_name = "_".join(["pcap", "{}.pcapng".format(create_packet_capture_scan[2])])

        with SSH() as ssh:
            pcapng_file = ssh.execute("tar -xvzf {}".format(pcap_file_path))

            assert expected_pcapng_file_name == pcapng_file[0], \
                "'{}' file does not exist in '{}' packet capture file.".format(expected_pcapng_file_name,
                                                                               expected_pcap_file_name)

    @pytest.mark.scanning
    @pytest.mark.parametrize("target_type", ["IPv4", pytest.param("IPv6", marks=pytest.mark.xfail(
        reason="Due to not getting generated the pcap file for IPv6 host, xfail the test for now")), "DNS"])
    def test_packet_capture_scan_with_ipv4_ipv6_and_dns_targets(self, target_type):
        """
        NES-13499 [Automation]: Verify packet capture for IPv4, IPv6 and DNS targets

        Scenario's Tested:
        [x] Verify that packet capture scan get completed successfully for "IPv4, IPv6 and DNS" target and generated
            pcap files under "Debug Logs" too.
        """
        scan_target = Nessus.Scan.Target.AWS_LINUX_TARGET_1
        numbers = list(map(int, scan_target.split('.')))
        ipv6_address = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)

        scan_name = None
        target_type_dict = {'IPv4': scan_target, 'IPv6': ipv6_address, 'DNS': Nessus.Scan.Target.PUB_TARGET_4}

        try:
            scan_id, scan_name = create_packet_capture_scan_helper(
                nessus_api=self.cat.api, scan_file=self.scan_file_path, scan_target=target_type_dict[target_type],
                scan_template='basic')

            self.cat.api.scans.launch(scan_id=scan_id)

            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                   timeout=TIME_THIRTY_MINUTES)

            self.verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(
                nessus_api=self.cat.api, scan_name=scan_name)
        finally:
            self.delete_pcap_generated_file_from_debug_logs_table_and_logs_directory(
                nessus_api=self.cat.api, scan_name=scan_name)

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_packet_capture_scan", [{"scan_file_path": scan_file_path,
                                                             "scan_template": "basic"}], indirect=True)
    @pytest.mark.parametrize("element_type", ["Button", pytest.param("Icon", marks=pytest.mark.xfail(
        reason='Refer Jira ID NES-13525'))])
    def test_user_can_delete_pcap_files_by_clicking_delete_button_or_x_icon(self, create_packet_capture_scan,
                                                                            element_type):
        """
        NES-13500 [Automation]: Verify user should be able to remove file/files by using Delete or 'x'

        Scenario's Tested:
        [x] Verify 'Delete' button is displayed at top right corner on selecting 1/more file entries.
        [x] Verify user should be able to remove file/files by using 'Delete' button or 'x' icon on each files.
        """
        pcap_log_files = []
        scan_id, scan_name = int(create_packet_capture_scan[0]), create_packet_capture_scan[1]

        for _ in range(3):
            self.cat.api.scans.launch(scan_id=scan_id)

            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                   timeout=TIME_THIRTY_MINUTES)

            expected_file_name = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)
            pcap_log_files.append(expected_file_name)

        debug_logs_page = DebugLogsPage()
        debug_logs_page.open()
        wait(lambda: debug_logs_page.is_element_present("search_logs_field"),
             waiting_for="'Debug Logs' table gets displayed properly")

        assert invisibility_of_element_located(debug_logs_page.delete_button), \
            "'Delete' button is getting displayed even though not getting selected any single log from debug logs table"

        debug_log_list = DebugLogsList()

        for selection_type in ['Single', 'Multiple']:
            number_of_file = 1 if selection_type == 'Single' else 2
            file_to_be_select = random.sample(pcap_log_files, k=number_of_file)

            for file in file_to_be_select:
                debug_log_list.select_deselect_pcap_file(file_name=file)
                sleep(WAIT_SHORT, reason="It takes little bit time to get select the checkbox")

            assert debug_logs_page.is_element_present("delete_button"), \
                "'Delete' button is not getting displayed even after selecting single log from debug logs table."

            debug_logs_page.delete_button.click()
            delete_log_modal = ActionCloseModal()
            wait(lambda: delete_log_modal.is_element_present("modal"), waiting_for="'Delete Log' modal gets displayed")

            expected_modal_title = Nessus.DebugLogs.DELETE_LOG if selection_type == 'Single' else \
                Nessus.DebugLogs.DELETE_LOGS
            expected_modal_warning = Nessus.DebugLogs.DELETE_LOG_WARNING if selection_type == 'Single' else \
                Nessus.DebugLogs.DELETE_LOGS_WARNING

            assert all([delete_log_modal.is_element_present("modal"),
                        delete_log_modal.modal_title.text == expected_modal_title,
                        delete_log_modal.modal_content.text == expected_modal_warning,
                        delete_log_modal.is_element_present("action_button"),
                        delete_log_modal.is_element_present("cancel_button")]), \
                "'{}' modal is not getting displayed properly after selecting '{}' log from debug logs table.".format(
                    expected_modal_title, selection_type)

            delete_log_modal.cancel_button.click()
            delete_log_modal.wait_for_modal_closed()

            for file in file_to_be_select:
                debug_log_list.select_deselect_pcap_file(file_name=file, select=False)
                sleep(WAIT_SHORT, reason="It takes little bit time to get deselect the checkbox")

            assert invisibility_of_element_located(debug_logs_page.delete_button), \
                "'Delete' button is getting displayed even after deselecting log from debug logs table."

        if element_type == 'Button':
            for file_name in pcap_log_files:
                debug_log_list.select_deselect_pcap_file(file_name=file_name)
                sleep(WAIT_SHORT, reason="It takes little bit time to get select the checkbox")

            wait(lambda: debug_logs_page.is_element_present("delete_button"),
                 waiting_for="'Delete' button gets displayed after selecting all logs")

            debug_logs_page.delete_button.click()
            delete_log_modal = ActionCloseModal()
            wait(lambda: delete_log_modal.is_element_present("modal"), waiting_for="'Delete Logs' modal gets displayed")

            delete_log_modal.action_button.click()
            delete_log_modal.wait_for_modal_closed()

            notification = Notifications()

            assert notification.successes[-1] == Messages.NotificationMessages.multiple_logs_delete_success, \
                "Successful notification is missing or mismatch after deleting multiple logs in bulk."
        else:
            for file_name in pcap_log_files:
                debug_log_list.delete_pcap_file(file_name=file_name)

                notification = Notifications()

                assert notification.successes[-1] == Messages.NotificationMessages.single_log_delete_success, \
                    "Successful notification is missing or mismatch after deleting single log."

        assert all([pcap_file not in debug_log_list.get_all_pcap_files_name() for pcap_file in pcap_log_files]), \
            "Packet capture log files are not getting deleted properly even after deleting single or multiple logs."

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_packet_capture_scan", [{"scan_file_path": scan_file_path,
                                                             "scan_template": "basic"}], indirect=True)
    def test_user_can_download_pcap_generated_file_by_clicking_download_icon(self, create_packet_capture_scan):
        """
        NES-13501 [Automation]: Verify user is able to download the files successfully

        Scenario's Tested:
        [x] Verify that user can download pcap generated files successfully from debug logs table by clicking on
            'Download' icon
        [x] Verify listed file(s) values under debug logs table
        """
        scan_id, scan_name = int(create_packet_capture_scan[0]), create_packet_capture_scan[1]

        self.cat.api.scans.launch(scan_id=scan_id)

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES)

        self.verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(
            nessus_api=self.cat.api, scan_name=scan_name)

        expected_file_name = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)
        debug_logs_list = DebugLogsList()
        debug_logs_list.last_modified_column.click()
        debug_logs_list.last_modified_column.click()
        for debug_log in debug_logs_list.rows:
            actual_file_name = debug_log.pcap_file_name
            if expected_file_name == actual_file_name:
                assert all([expected_file_name == actual_file_name, debug_log.pcap_start_time == "N/A",
                            debug_log.pcap_end_time == "N/A", debug_log.pcap_last_modified_time.
                           startswith("Today at "), debug_log.download_icon.is_displayed(), debug_log.delete_icon.
                           is_displayed()]), "Something is missing or mismatch in debug logs table list."

        debug_logs_list.download_pcap_file(file_name=expected_file_name)
        sleep(sleep_time=TIME_FIFTEEN_SECONDS, reason="waiting for file gets downloaded")

        downloaded_file = get_downloaded_files_chrome()

        log.debug('Downloaded pcap file is :: {}'.format(downloaded_file))
        file_name = scan_name.split(".")[0]

        assert file_name in downloaded_file, 'Pcap log file does not downloaded successfully.'

    @pytest.mark.scanning
    def test_packet_capture_scan_with_bad_host_capture(self):
        """
        NES-13502 [Automation]: Verify packet should not capture for BadCaptureHost

        Scenario's Tested:
        [x] Verify that packet should not be capture when scan target and 'Target to capture' host are different.
        """
        scan_name = None

        try:
            scan_id, scan_name = create_packet_capture_scan_helper(
                nessus_api=self.cat.api, scan_file=self.scan_file_path, scan_template="basic",
                target_to_capture=Nessus.Scan.Target.LINUX_TARGET, scan_target="172.26.48.{}".format(randint(1, 24)))

            self.cat.api.scans.launch(scan_id=scan_id)

            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                   timeout=TIME_THIRTY_MINUTES)

            expected_file_name = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)
            logs_dir = self.logs_dir

            debug_logs_page = DebugLogsPage()
            debug_logs_page.open()
            wait(lambda: debug_logs_page.is_element_present("empty_debug_logs") or debug_logs_page.is_element_present(
                "search_logs_field"), waiting_for="'Debug Logs' table gets displayed properly")

            all_pcap_files_name = DebugLogsList().get_all_pcap_files_name()

            assert expected_file_name not in all_pcap_files_name, \
                "Packet capture file is getting generated even if we enter bad capture host."

            files_under_logs_dir = get_file_list_from_nessus_directory(nessus_dir=logs_dir)

            assert expected_file_name not in files_under_logs_dir, \
                "Packet capture file is getting generated under '{}' directory too for bad capture host.".format(
                    logs_dir)
        finally:
            self.delete_pcap_generated_file_from_debug_logs_table_and_logs_directory(
                nessus_api=self.cat.api, scan_name=scan_name)

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_packet_capture_scan", [{"scan_file_path": scan_file_path,
                                                             "scan_template": "basic"}], indirect=True)
    @pytest.mark.parametrize("remove_from_ui", [True, False])
    def test_existence_of_scan_archive_after_removing_scan(self, create_packet_capture_scan, remove_from_ui):
        """
        NES-13506 [Automation]: Verify the existence of scan achieves after removing scan from either log
                                directory or from debug logs table

        Scenario's Tested:
        [x] Verify the existence of scan archive in log directory after removing the same file from UI.
        [x] Verify the existence of scan archive on UI after removing the same file from log directory.
        """
        files_under_logs_dir = []
        scan_id, scan_name = int(create_packet_capture_scan[0]), create_packet_capture_scan[1]

        self.cat.api.scans.launch(scan_id=scan_id)

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES)

        self.verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(
            nessus_api=self.cat.api, scan_name=scan_name)

        expected_file_name = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)
        debug_log_list = DebugLogsList()

        if remove_from_ui:
            debug_log_list.delete_pcap_file(file_name=expected_file_name)

            files_under_logs_dir = get_file_list_from_nessus_directory(nessus_dir=self.logs_dir)

            assert expected_file_name not in debug_log_list.get_all_pcap_files_name(), \
                "Failed to delete pcap file from debug logs."
        else:
            delete_file_from_nessus_directory(file_name=expected_file_name, nessus_dir=self.logs_dir)

            debug_log_page = DebugLogsPage()
            debug_log_page.refresh()
            wait(lambda: debug_log_page.is_element_present("search_logs_field") or debug_log_page.is_element_present(
                "empty_debug_logs"), waiting_for="debug logs table gets displayed")

        available_pcap_files = files_under_logs_dir if remove_from_ui else debug_log_list.get_all_pcap_files_name()

        assert expected_file_name not in available_pcap_files, \
            "Packet capture file is getting available even if we delete packet capture file from 'Debug Logs' " \
            "table or '{}' directory.".format(self.logs_dir)

    def test_packet_capture_with_pause_stop_resume_scan(self):
        """
        NES-13507 [Automation]: Verify packet capture with Pause, Stop, resume scan

        Scenario's Tested:
        [x] Verify that packet capture scan should not get generated on running, paused, resuming or stopped scan.
        """
        scan_name = None

        try:
            scan_id, scan_name = create_packet_capture_scan_helper(
                nessus_api=self.cat.api, scan_file=self.scan_file_path, scan_target=Nessus.Scan.Target.PUB_TARGET_4,
                scan_template='basic')

            debug_logs_page = DebugLogsPage()
            debug_logs_page.open()
            wait(lambda: debug_logs_page.is_element_present("search_logs_field") or debug_logs_page.is_element_present(
                "empty_debug_logs"), waiting_for="'Debug Logs' table gets displayed properly")

            scan_action_dict = {"launch": API.Scan.Status.RUNNING, "pause": API.Scan.Status.PAUSED,
                                "resume": API.Scan.Status.RUNNING, "stop": API.Scan.Status.CANCELED}

            for action, status in scan_action_dict.items():
                if action == "launch":
                    self.cat.api.scans.launch(scan_id=scan_id)
                elif action == "pause":
                    self.cat.api.scans.pause(scan_id=scan_id)
                elif action == "resume":
                    self.cat.api.scans.resume(scan_id=scan_id)
                else:
                    self.cat.api.scans.stop(scan_id=scan_id)

                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=status, timeout=TIME_FIVE_MINUTES)
                expected_file_name = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)

                debug_logs_page.refresh()
                wait(lambda: debug_logs_page.is_element_present("search_logs_field") or debug_logs_page.
                     is_element_present("empty_debug_logs"), waiting_for="'Debug Logs' table gets displayed properly")

                available_pcap_files = DebugLogsList().get_all_pcap_files_name()
                is_file_generated_on_ui = expected_file_name in available_pcap_files

                assert is_file_generated_on_ui if action == "stop" else not is_file_generated_on_ui, \
                    "'{}' pcap file is getting generated on '{}' status after '{}' the scan which should " \
                    "not be.".format(expected_file_name, status, action)

                files_under_logs_dir = get_file_list_from_nessus_directory(nessus_dir=self.logs_dir)
                is_file_generated_in_dir = expected_file_name in files_under_logs_dir

                assert is_file_generated_in_dir if action == "stop" else not is_file_generated_in_dir, \
                    "Packet capture file is getting generated under '{}' directory on '{}' status after '{}' the " \
                    "scan which should not be.".format(self.logs_dir, status, action)
        finally:
            self.delete_pcap_generated_file_from_debug_logs_table_and_logs_directory(
                nessus_api=self.cat.api, scan_name=scan_name)

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_packet_capture_scan", [{"scan_file_path": scan_file_path,
                                                             "scan_template": "basic"}], indirect=True)
    def test_packet_capture_with_rerun_the_same_scan(self, create_packet_capture_scan):
        """
        NES-13507 [Automation]: Verify packet capture with Pause, Stop, resume scan

        Scenario's Tested:
        [x] Verify that packet capture scan should generate new file every time while running the same scan
            multiple times.
        """
        scan_id, scan_name = int(create_packet_capture_scan[0]), create_packet_capture_scan[1]

        self.cat.api.scans.launch(scan_id=scan_id)

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES)

        expected_file_1 = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)
        self.verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(
            nessus_api=self.cat.api, scan_name=scan_name)

        self.cat.api.scans.launch(scan_id=scan_id)

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES)

        expected_file_2 = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)
        self.verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(
            nessus_api=self.cat.api, scan_name=scan_name)

        assert expected_file_1 != expected_file_2, "After rerun the same scan, It does not generate new packet " \
                                                   "capture log file."

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_packet_capture_scan", [{"scan_file_path": scan_file_path,
                                                             "scan_template": "basic"}], indirect=True)
    def test_packet_capture_scan_with_setting_toggle_off(self, create_packet_capture_scan):
        """
        NES-13508 [Automation]: Verify 'Packet Capture' toggle off

        Scenario's Tested:
        [x] Verify that packet capture scan should not be generated when 'Packet Capture' setting is disabled.
        """
        scan_id, scan_name = int(create_packet_capture_scan[0]), create_packet_capture_scan[1]

        self.cat.api.scans.launch(scan_id=scan_id)

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES)

        self.verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(
            nessus_api=self.cat.api, scan_name=scan_name)

        header_page = HeaderBasePage()
        header_page.scan_link.click()
        ScanList().click_on_scan(scan_name=scan_name)

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present('vulnerability_tab'), waiting_for='Scan details to load')
        scan_view_page.configure.click()
        scan_new_form = NewScanForm()
        wait(lambda: scan_new_form.is_element_present("name_field"), waiting_for="scan configure page get loaded")

        click_on_general_link_inside_scan_advanced_setting(template_name=template_constant.BASIC_NETWORK)
        scan_advanced_setting = AdvancedSettings()
        scan_advanced_setting.packet_capture_toggle_button.click()

        assert scan_advanced_setting.packet_capture_toggle_button.get_attribute("data-value") == "no", \
            "'Packet Capture' toggle button is showing enabled even after clicking to make it disabled."

        assert not all([scan_advanced_setting.is_element_present("target_to_capture_field"),
                        scan_advanced_setting.is_element_present("ports_to_capture_field")]), \
            "'Target to capture' and 'Ports to capture' fields are still showing even after disabling " \
            "'Packet Capture' setting toggle button."

        scan_new_form.save_button.click()
        wait(lambda: Notifications().successes, waiting_for="Notifications messages to populate")

        header_page.settings_link.click()
        wait(lambda: OverView().is_element_present("nessus_version"), timeout_seconds=TIME_THIRTY_SECONDS * 2,
             waiting_for='about overview page gets load properly.')
        SideNav().get_sidenav_element(element_name=Nessus.SideNavSettings.DEBUG_LOGS).click()

        self.cat.api.scans.launch(scan_id=scan_id)

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                               timeout=TIME_THIRTY_MINUTES)

        expected_file_name = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)
        available_pcap_files = DebugLogsList().get_all_pcap_files_name()

        assert expected_file_name not in available_pcap_files, \
            "'Packet Capture' log file is getting generated even if 'Packet Capture' setting is disabled."

        files_under_logs_dir = get_file_list_from_nessus_directory(nessus_dir=self.logs_dir)

        assert expected_file_name not in files_under_logs_dir, \
            "Packet capture file is getting generated under '{}' directory even if 'Packet Capture' setting is " \
            "disabled.".format(self.logs_dir)

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_packet_capture_scan", [{"scan_file_path": scan_file_path,
                                                             "scan_template": "basic"}], indirect=True)
    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["Filename", "Start Time", "End Time", "Last Modified"])
    def test_verify_sorting_of_columns_under_debug_logs_table(self, create_packet_capture_scan, sort, column_to_sort):
        """
        NES-13529: Verify sorting on debug log page

        Scenario's Tested:
        [x] Verify that column sorting is functioning properly for debug logs table.
        """
        scan_id, scan_name = int(create_packet_capture_scan[0]), create_packet_capture_scan[1]

        debug_logs_page = DebugLogsPage()
        debug_logs_page.open()
        wait(lambda: debug_logs_page.is_element_present("empty_debug_logs") or debug_logs_page.is_element_present(
            "search_logs_field"), waiting_for="'Debug Logs' table gets displayed properly")

        debug_logs_list = DebugLogsList()

        for _ in range(3):
            if len(debug_logs_list.rows) < 3:
                self.cat.api.scans.launch(scan_id=scan_id)

                assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                       timeout=TIME_THIRTY_MINUTES)

                self.verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(
                    nessus_api=self.cat.api, scan_name=scan_name)
            else:
                break

        column_mapping = {"Filename": "pcap_file_name", "Start Time": "pcap_start_time", "End Time": "pcap_end_time",
                          "Last Modified": "pcap_last_modified_time"}
        map_attribute = column_mapping[column_to_sort]

        expected_scans_list = sorted([getattr(debug_log, map_attribute) for debug_log in debug_logs_list.rows],
                                     key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

        rendered_logs_list = sort_on_column_values(page_class_instance=debug_logs_list, sort=sort,
                                                   column_name=column_to_sort)

        assert expected_scans_list == [getattr(debug_log, map_attribute) for debug_log in rendered_logs_list], \
            "'{}' is not getting sorted in '{}' order".format(column_to_sort, sort)

    @pytest.mark.parametrize("scan_template", [
        template_constant.ADVANCED, template_constant.BASIC_NETWORK, template_constant.WEB_APP,
        template_constant.FIND_AI, template_constant.ACTIVE_DIRECTORY_STARTER])
    @pytest.mark.parametrize("valid_port", ["22", "1-22", "8888", "22-8888", "11111", "9001-55555"])
    def test_ports_to_capture_field_allows_single_port_or_port_range_as_value(self, scan_template, valid_port):
        """
        NES-13530: Verify it should allow to add single port or port range for "ports to capture"

        Scenario's Tested:
        [x] Verify that "Ports to Capture" field should allow single port or port range as a value
        """
        scan_name = random_name(prefix="{}-".format(scan_template))
        scan_target = Nessus.Scan.Target.AWS_LINUX_TARGET_1

        try:
            click_on_new_scan_button_and_go_to_new_scan_form(template_name=scan_template)

            new_scan_form = NewScanForm()
            new_scan_form.name_field.value = scan_name
            new_scan_form.targets_textarea.value = scan_target

            click_on_general_link_inside_scan_advanced_setting(template_name=scan_template)

            scan_advanced_setting = AdvancedSettings()
            scan_advanced_setting.packet_capture_toggle_button.click()

            scan_advanced_setting.target_to_capture_field.value = scan_target
            scan_advanced_setting.ports_to_capture_field.clear()
            scan_advanced_setting.ports_to_capture_field.value = valid_port
            sleep(WAIT_SHORT, reason="It takes little bit time to highlight the field for error")

            assert 'error' not in scan_advanced_setting.ports_to_capture_field.get_css_classes(), \
                "'Ports to capture' field is getting highlighting with red border even after entering " \
                "valid port '{}'.".format(valid_port)

            scan_advanced_setting.save_button.click()
            notification = Notifications()

            assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
                "Success notification is missing or mismatched even after entering valid port '{}'.".format(valid_port)
        finally:
            scans_list = [scan['name'] for scan in self.cat.api.scans.get_scans()['scans']]

            if scan_name in scans_list:
                scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)
                self.cat.api.scans.delete(scan_id=scan_id)

    @pytest.mark.scanning
    @pytest.mark.parametrize("create_packet_capture_scan", [{"scan_file_path": scan_file_path,
                                                             "scan_template": "basic"}], indirect=True)
    def test_verify_search_pcap_file_under_debug_logs_table(self, create_packet_capture_scan):
        """
        NES-13532: Verify searching in Debug Logs page

        Scenario's Tested:
        [x] Verify searching in Debug Logs page
        """
        pcap_log_files = []
        scan_id, scan_name = int(create_packet_capture_scan[0]), create_packet_capture_scan[1]

        delete_all_pcap_files_from_debug_logs_table()
        debug_logs_list = DebugLogsList()

        for _ in range(3):
            self.cat.api.scans.launch(scan_id=scan_id)

            assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                   timeout=TIME_THIRTY_MINUTES)

            self.verify_pcap_generated_file_in_debug_logs_table_and_logs_directory(
                nessus_api=self.cat.api, scan_name=scan_name)

            expected_file_name = expected_generated_pcap_file_name(api=self.cat.api, scan_name=scan_name)
            pcap_log_files.append(expected_file_name)

        splitted_file_name = random.sample(pcap_log_files, k=1)[0].split("_")
        random_scan_uuid = random.sample(splitted_file_name[2].split("-"), k=2)
        random_value = random_string()

        string_value_to_be_search = [splitted_file_name[0], splitted_file_name[1], random_value]
        string_value_to_be_search.extend(random_scan_uuid)
        total_count = len(debug_logs_list.rows)

        debug_logs_page = DebugLogsPage()

        assert all([debug_logs_page.is_element_present("search_logs_field"), debug_logs_page.is_element_present(
            "search_icon"), debug_logs_page.is_element_present("total_logs"), debug_logs_page.total_logs.text.
                   strip() == "{} Logs".format(total_count)]), "Total logs count is either missing or mismatched."

        for search_value in string_value_to_be_search:
            debug_logs_page.search_logs_field.clear()
            debug_logs_page.search_logs_field.value = search_value
            sleep(WAIT_SHORT, reason="It takes little bit time to search the logs results")

            if search_value == random_value:
                expected_message = Nessus.DebugLogs.NO_RECORDS_FOUND_MSG

                assert all([debug_logs_page.is_element_present("empty_log_table"),
                            debug_logs_page.empty_log_table.text == expected_message]), \
                    "'{}' message is either missing or mismatch after searching debug logs with " \
                    "random string '{}'.".format(expected_message, search_value)
            else:
                assert debug_logs_list.verify_logs_search_result(search_string=search_value), \
                    "Failed to search with provided search string '{}'.".format(search_value)

            search_log_count = len(debug_logs_list.rows)

            assert all([debug_logs_page.is_element_present("remove_search_icon"), debug_logs_page.is_element_present(
                "search_logs"), debug_logs_page.search_logs.text.strip() == "{} of {} Logs".format(
                search_log_count, total_count)]), "Something is either missing or mismatched after searching debug logs"

            debug_logs_page.remove_search_icon.click()


@pytest.mark.nessus_manager
@pytest.mark.nessus_home
@pytest.mark.usefixtures("login")
class TestPacketCaptureSettingsInManagerAndHome:
    """ Covers Packet capture Settings Related Test Cases for Nessus Manager """

    @staticmethod
    def scan_templates() -> list:
        """
        Returns list of scan templates except the templates with banner

        :return: list of scan templates
        :rtype: list
        """
        scan_type = Nessus.Scan.ScanTemplateTabs.SCANNER_TAB.lower()

        scan_page = ScansPage()
        scan_page.new_scan_button.click()
        wait(lambda: scan_page.is_element_present("back_to_folder"), waiting_for='scan templates gets loaded')

        all_scan_templates = scan_page.get_all_scan_templates(scan_type=scan_type)
        templates_with_banner = scan_page.get_banner_labeled_scan_templates_name(scan_type=scan_type)
        [all_scan_templates.remove(template) for template in templates_with_banner]

        return all_scan_templates

    def test_invisibility_of_packet_capture_and_debug_logs_settings_in_nm_and_home(self):
        """
        NES-13486 [Automation]: "Packet Capture" and "Debug Logs" features are not available for NM, Scanner, Home

        Scenario's Tested:
        [x] Verify that "Packet Capture" and "Debug Logs" features are not available in Nessus Manager and Home.
        """
        available_scan_templates = self.scan_templates()

        if template_constant.MDM_AUDIT in available_scan_templates:
            available_scan_templates.remove(template_constant.MDM_AUDIT)

        header_page = HeaderBasePage()
        header_page.scan_link.click()

        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
            "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")

        for scan_template in available_scan_templates:
            click_on_new_scan_button_and_go_to_new_scan_form(template_name=scan_template)

            click_on_general_link_inside_scan_advanced_setting(template_name=scan_template)
            sleep(WAIT_NORMAL, reason="It takes little bit time to get loaded scan's advanced settings")

            assert not AdvancedSettings().is_element_present("packet_capture_toggle_button"), \
                "'Packet Capture' toggle button is showing in scan advanced setting for Nessus Manager."

            header_page.settings_link.click()
            wait(lambda: OverView().is_element_present("nessus_version"), timeout_seconds=TIME_THIRTY_SECONDS * 2,
                 waiting_for='about overview page gets load properly.')

            debug_logs_menu = SideNav().get_sidenav_element(element_name=Nessus.SideNavSettings.DEBUG_LOGS)

            assert invisibility_of_element_located(locator=debug_logs_menu), \
                "'Debug Logs' menu is showing in side navigation panel which should not be."

            header_page.scan_link.click()
            wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
                "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")
