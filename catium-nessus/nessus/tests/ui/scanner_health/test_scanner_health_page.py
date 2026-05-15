"""
Nessus test cases related to Scanner Health Page

:copyright: Tenable Network Security, 2019
:date: Jan 25, 2019
:last_modified: May 31, 2019
:author: @kpanchal
"""
import ipaddress

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS, WAIT_LONG, TIME_FIFTEEN_SECONDS, WAIT_NORMAL
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.lib.const.constants import Nessus, API
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.scanner_health.scanner_health_page import ScannerHealthPage, ScannerHealthOverviewTab, \
    ScannerHealthNetworkTab, ScannerHealthAlertsTab
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_settings_2
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestScannerHealthPage:
    """ Test case for scanner health page. """

    def test_visibility_of_elements_on_scanner_health_page(self):
        """
        NES-8716: [Testing] Automation testing for scanner health page

        Scenarios Tested:
        [x] Scanner health should be displayed as title.
        [x] Three sub-tabs should be displayed, are overview, network, alerts.
        """
        scanner_health_page = ScannerHealthPage()
        scanner_health_page.open()

        # Verify Scanner Health page url
        assert '/settings/scanner-health' in get_driver_no_init().current_url, 'Scanner Health page is not opened.'

        # Verify Scanner Health page header name
        assert scanner_health_page.page_header == Nessus.ScannerHealth.SCANNER_HEALTH, \
            'Scanner health page header is not displayed.'

        # Verify Overview, Network and Alerts tabs are displayed under Scanner Health Page
        assert scanner_health_page.get_tab_content() == [Nessus.ScannerHealth.OVERVIEW, Nessus.ScannerHealth.NETWORK,
                                                         Nessus.ScannerHealth.ALERTS], \
            "Scanner Health sub-tabs are missing."

    def test_overview_tab_in_scanner_health(self):
        """
        NES-8716: [Testing] Automation testing for scanner health page

        Scenarios Tested:

        - In Overview tab,
        [x] Sub-headers should be displayed like CURRENT HEALTH, SYSTEM MEMORY, NESSUS DATA DISK SPACE, MEMORY USAGE
            HISTORY, CPU USAGE HISTORY and SCANNING HISTORY.
        [x] There should be a dropdown for MEMORY USAGE HISTORY sub-header and it should display all the 7 options and
            default should be 24-hours.
        [x] Current Health header should show Nessus Memory usage(MB), CPULoad(%) and HOSTS BEING SCANNED.
        """
        scanner_health_page = ScannerHealthPage()
        scanner_health_page.open()
        scanner_health_page.overview_tab.click()
        wait(lambda: scanner_health_page.is_element_present('sub_headers'), timeout_seconds=WAIT_LONG,
             waiting_for="sub-headers to load under Overview tab")

        overview_tab = ScannerHealthOverviewTab()

        # Verify 'Overview' tab url under Scanner Health page
        assert '/settings/scanner-health/overview' in get_driver_no_init().current_url, \
            "'Overview' tab is not opened under Scanner Health page."

        # Verify 'Overview' sub-headers like CURRENT HEALTH, SYSTEM MEMORY, NESSUS DATA DISK SPACE, MEMORY USAGE etc
        assert scanner_health_page.get_sub_header_content() == Nessus.ScannerHealth.OVERVIEW_SUBHEADERS_LIST, \
            "Scanner health overview sub-headers are missing."

        # Verify current health sub-headers like Nessus Memory usage(MB), CPULoad(%) and HOSTS BEING SCANNED
        assert overview_tab.get_current_health_count_label() == Nessus.ScannerHealth.CURRENT_HEALTH_COUNT_LABELS, \
            'Count labels are missing under Current Health.'

        # Verify time range dropdown for MEMORY USAGE HISTORY sub-header
        assert overview_tab.time_range_dropdown.is_displayed(), "Time range drop-down is not displayed under " \
                                                                "'Overview' tab in scanner health page."

        # Verify default selected time range option
        assert overview_tab.time_range_dropdown.get_text_selected() == Nessus.ScannerHealth.PAST_24_HOURS, \
            "In time-range drop-down, 'Past 24 hours' option is not selected by-default."

        overview_tab.time_range_dropdown.click()

        # Verify all time range options
        assert all([option.text == Nessus.ScannerHealth.TIME_RANGE_OPTIONS for option in
                    overview_tab.time_range_dropdown.get_options()]), \
            'Few of options are missing under time range drop-down.'

        # Verify MEMORY USAGE HISTORY, CPU USAGE HISTORY and SCANNING HISTORY tiles are displayed under 'Overview' tab
        overview_tab_tiles = {'memory_usage_history_tile': Nessus.ScannerHealth.OverviewTab.MEMORY_USAGE_HISTORY,
                              'cpu_usage_history_tile': Nessus.ScannerHealth.OverviewTab.CPU_USAGE_HISTORY,
                              'scanning_history_tile': Nessus.ScannerHealth.NetworkTab.SCANNING_HISTORY}

        for tile_element, tile_name in overview_tab_tiles.items():
            assert overview_tab.is_element_present(tile_element), \
                "'{}' tile is not displayed under 'Overview' tab.".format(tile_name)

    def test_current_health_and_system_memory_under_overview_tab(self):
        """
        NES-8512: UI - Overview

        Scenarios Tested:

        [x] Check that the boxes in the "Current Health" section have values
        [x] Check that "System Memory" and "Nessus Data Disk Space" have values
        """
        scanner_health_page = ScannerHealthPage()
        scanner_health_page.open()
        scanner_health_page.overview_tab.click()
        wait(lambda: scanner_health_page.is_element_present('sub_headers'), timeout_seconds=WAIT_LONG,
             waiting_for="sub-headers to load under Overview tab")

        overview_tab = ScannerHealthOverviewTab()

        # Verify Nessus Used Memory value is not 0
        assert overview_tab.nessus_used_memory, "'Nessus Used Memory' should not be 0."

        # Verify CPU load value is 0% on initial load
        assert overview_tab.cpu_load.text, "On initial load, 'CPU Load' is not displayed as 0%."

        # Verify Hosts Being Scanned count is 0 on initial load
        assert overview_tab.scanned_host_count == 0, "On initial load, 'Hosts Being Scanned' count is not displayed " \
                                                     "as 0."

        # Verify 'SYSTEM MEMORY' tile is displayed under 'Overview' tab
        assert overview_tab.is_element_present('system_memory_tile'), "'SYSTEM MEMORY' tile is not displayed under " \
                                                                      "'Overview' tab."

        # Verify 'NESSUS DATA DISK SPACE' tile is displayed under 'Overview' tab
        assert overview_tab.is_element_present('data_disk_space_tile'), "'Nessus Data Disk Space' tile is not " \
                                                                        "displayed under 'Overview' tab."

        # Verify 'Other', 'Nessus', 'Used' and 'Free' options are displayed under 'SYSTEM MEMORY' and
        # 'NESSUS DATA DISK SPACE' tile
        overview_tab_tile_detail = {'system_memory': Nessus.ScannerHealth.OverviewTab.OTHER,
                                    'nessus_memory': Nessus.ScannerHealth.OverviewTab.NESSUS,
                                    'used_disk': Nessus.ScannerHealth.OverviewTab.USED,
                                    'free_disk': Nessus.ScannerHealth.OverviewTab.FREE}

        for tile_element, tile_name in overview_tab_tile_detail.items():
            assert all([overview_tab.is_element_present(tile_element),
                        overview_tab.get_text_from_tile(element_name=tile_element) == tile_name]), \
                "'{}' option is not displayed or mismatched.".format(tile_name)

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.BASIC_NETWORK, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format('NQA-1016 Advanced Scan')), "add_configuration": False,
         "target_ip": Nessus.Scan.Target.PUB_TARGET_3}]}], indirect=True)
    def test_current_health_sub_headers_value(self, create_scans):
        """
        NES-8716: [Testing] Automation testing for scanner health page

        Scenario Tested:

        - In Overview tab,
        [x] Verify the host being scanned count should be increased while scan is running.
        [x] Verify the nessus memory used should not be 0MB.
        """
        scan_name = create_scans[0]
        scan_id = ScanList().get_scan_id(scan_name=scan_name)

        nessus_api = NessusAPI()
        nessus_api.login()
        nessus_api.scans.launch(scan_id)

        scan_page = ScansPage()
        scan_page.refresh()

        header_page = HeaderBasePage()
        header_page.settings_link.click()
        SideNav().click_by_link_text(Nessus.SideNavSettings.SCANNER_HEALTH)

        overview_tab = ScannerHealthOverviewTab()
        wait(lambda: (overview_tab.scanned_host_count > 0), waiting_for='Waiting for the hosts to increase.',
             timeout_seconds=TIME_SIXTY_SECONDS)

        assert overview_tab.nessus_used_memory > 0, 'Nessus used memory should be greater than zero MB'

        assert overview_tab.scanned_host_count > 0, 'Host being scanned count should not be 0.'

        header_page.scan_link.click()
        nessus_api.scans.stop(scan_id)
        nessus_api.logout()

    def test_network_tab_in_scanner_health(self):
        """
        NES-8716: [Testing] Automation testing for scanner health page

        Scenario Tested:
        [x] In Network tab, Sub-headers should be displayed are, SCANNING HISTORY, NETWORK CONNECTIONS, NETWORK TRAFFIC,
            NUMBER OF DNS LOOKUPS, DNS LOOKUP TIME.

        NES-8516: UI - Network Tab

        Scenario Tested:
        [x] Check that each graph has labels and values
        """
        scanner_health_page = ScannerHealthPage()
        scanner_health_page.open()
        scanner_health_page.network_tab.click()
        wait(lambda: scanner_health_page.is_element_present('sub_headers'), timeout_seconds=WAIT_LONG,
             waiting_for="sub-headers to load under Network tab")

        # Verify 'Network' tab url under Scanner Health page
        assert '/settings/scanner-health/network' in get_driver_no_init().current_url, \
            "'Network' tab is not opened under Scanner Health page."

        # Verify 'Network' tab sub-headers
        assert scanner_health_page.get_sub_header_content() == Nessus.ScannerHealth.NETWORK_SUBHEADERS_LIST, \
            "Scanner health network sub-headers are missing."

        network_tab = ScannerHealthNetworkTab()

        # Verify SCANNING HISTORY, NETWORK CONNECTIONS, NETWORK TRAFFIC, NUMBER OF DNS LOOKUPS and DNS LOOKUP TIME
        # tiles are displayed under 'Overview' tab
        network_tab_tiles = {'network_scanning_history_tile': Nessus.ScannerHealth.NetworkTab.SCANNING_HISTORY,
                             'network_connections_tile': Nessus.ScannerHealth.NetworkTab.NETWORK_CONNECTIONS,
                             'network_traffic_tile': Nessus.ScannerHealth.NetworkTab.NETWORK_TRAFFIC,
                             'dns_lookups_tile': Nessus.ScannerHealth.NetworkTab.NUMBER_OF_DNS_LOOKUPS,
                             'dns_lookup_time_tile': Nessus.ScannerHealth.NetworkTab.DNS_LOOKUP_TIME}

        for tile_element, tile_name in network_tab_tiles.items():
            assert network_tab.is_element_present(tile_element), \
                "'{}' tile is not displayed under 'Network' tab.".format(tile_name)

    def test_alert_tab_in_scanner_health(self):
        """
        NES-8716: [Testing] Automation testing for scanner health page

        Scenarios Tested:

        - In Alert tab,
        [x] Scanner alerts should be there.
        [x] Same Alerts should be show up on Alert tab as well as on Overview page
        [x] On clicking any alert (from Alerts/Overview tab) it will show a detail pop-up

        NES-8516: UI - Network Tab

        Scenarios Tested:
        - In Alert tab,
        [x] Check that on the alerts tab (/settings/scanner-health/alerts) it says "No scanner alerts"
        [x] Check that alerts appear in the table
                - Red is "High", orange is "Medium"
        [x] Check that each alert can be clicked on for more detail in a popup.
        """
        scanner_health_page = ScannerHealthPage()
        scanner_health_page.open()
        scanner_health_page.alerts_tab.click()

        if not scanner_health_page.is_element_present('health_alerts'):
            # pytest.skip("It's a fresh installation with no alert messages.")
            pytest.xfail(reason="It's a fresh installation with no alert messages.")
        else:
            alert_on_alerts_tab = scanner_health_page.health_alerts.is_displayed()
            alert_message_on_alerts_tab = scanner_health_page.alert_message.text

        assert alert_on_alerts_tab, 'Alerts are not displayed on Alerts tab.'

        alerts_tab = ScannerHealthAlertsTab()

        # Verify 'High' severity alerts are displayed in 'Red' color
        if not len(alerts_tab.high_sev_alert) == 0:
            assert alerts_tab.high_sev_alert[0].value_of_css_property('background-color') == \
                   'rgba(212, 63, 58, 1)', "'High' severity alerts are not displayed in 'Red' color."

        # Verify 'Medium' severity alerts are displayed in 'Orange' color
        if not len(alerts_tab.medium_sev_alert) == 0:
            assert alerts_tab.medium_sev_alert[0].value_of_css_property('background-color') == \
                   'rgba(253, 196, 49, 1)', "'Medium' severity alerts are not displayed in 'Orange' color."

        scanner_health_page.alert_message.click()

        assert ActionCloseModal().modal.is_displayed(), 'In Alerts tab, alert detail pop-up is not displayed ' \
                                                        'after click on alert.'

        alerts_tab.pop_up_remove_icon.click()
        scanner_health_page.overview_tab.click()
        alert_on_overview_tab = scanner_health_page.health_alerts.is_displayed()
        alert_message_on_overview_tab = scanner_health_page.alert_message.text

        assert alert_on_overview_tab, 'Alerts are not displayed on Overview tab.'

        assert alert_on_alerts_tab and alert_on_overview_tab, \
            'Alerts are not displayed on Alerts tab as well as Overview tab.'

        assert alert_message_on_alerts_tab == alert_message_on_overview_tab, \
            'Alert message on overview tab and alert message on alerts tab are different.'

        scanner_health_page.alert_message.click()

        assert ActionCloseModal().modal.is_displayed(), 'In Overview tab, alert detail pop-up is not displayed ' \
                                                        'after click on alert.'

        alerts_tab.pop_up_remove_icon.click()

    @pytest.mark.skip(reason='We cannot scan the lab. We need to adjust this test accordingly')
    @pytest.mark.parametrize('target_host', ['172.26.17.0/26', '172.26.17.0/24'])
    def test_max_host_count_in_overview_tab(self, target_host):
        """
        NES-8512: UI - Overview

        Scenarios Tested:

        - In Overview tab,
        [x] Check that "Hosts Being Scanned" shows less than 100 as a value when we run scan with less than 100 targets.
        [x] Check that "Hosts Being Scanned" shows 100 as a value when we run scan with more than 100 targets.
        """
        created_scan_name = random_name(prefix='{} - '.format(Nessus.TemplateNames.ADVANCED))

        scan_page = ScansPage()
        scan_page.create_new_scan(scan_template=Nessus.TemplateNames.ADVANCED,
                                  scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, scan_name=created_scan_name,
                                  target_ip=target_host)

        scan_list = ScanList()
        scan_list.launch_scan(scan_name=created_scan_name)
        scan_page.refresh()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='scan page to load')

        header_page = HeaderBasePage()
        header_page.settings_link.click()

        SideNav().click_by_link_text(Nessus.SideNavSettings.SCANNER_HEALTH)
        overview_tab = ScannerHealthOverviewTab()

        ip_range = ipaddress.ip_network(target_host)
        lower_limit_addresses = 1
        if ip_range.num_addresses >= 100:
            lower_limit_addresses = 100

        def host_increase():
            sleep(WAIT_NORMAL, reason='page refresh.')
            if overview_tab.scanned_host_count >= lower_limit_addresses:
                return True
            overview_tab.refresh()

        wait(lambda: host_increase(), waiting_for='the hosts to increase.', timeout_seconds=TIME_SIXTY_SECONDS)

        if ip_range.num_addresses < 100:
            # Verify that "Hosts Being Scanned" shows less than 100 when we run scan with less than 100 targets
            assert overview_tab.scanned_host_count < 100, 'Host being scanned count is displayed 100 when we run ' \
                                                          'scan with less than 100 targets.'
        else:
            # Verify that "Hosts Being Scanned" shows 100 when we run scan with more than 100 targets
            assert overview_tab.scanned_host_count == 100, 'Host being scanned count is not displayed 100 when we ' \
                                                           'run scan with more than 100 targets.'

        header_page.scan_link.click()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='scan page to load')

        scan_list.stop_scan(scan_name=created_scan_name)
        stop_status = scan_page.get_scan_status(scan_name=created_scan_name, scan_status=API.Scan.Status.CANCELED)
        wait(lambda: visibility_of_element_located((stop_status.we_by, stop_status.we_value))(get_driver_no_init()),
             waiting_for="scan to be stopped", timeout_seconds=TIME_FIFTEEN_SECONDS)

        scan_list.delete_scan(scan_name=created_scan_name)
        ScansTrashPage().delete_scan_from_trash(scan_name=created_scan_name)
