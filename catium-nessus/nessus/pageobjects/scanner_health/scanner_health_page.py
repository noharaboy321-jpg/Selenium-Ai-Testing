"""
Nessus scanner health related page

:copyright: Tenable Network Security, 2019
:date: Jan 25, 2019
:last_modified: May 31, 2019
:author: @kpanchal
"""
from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.find import Find, Finds
from nessus.pageobjects.basepage import NessusBasePage


@cat_registry.route(r'settings/scanner-health')
class ScannerHealthPage(NessusBasePage):
    """ Scanner Health Page """

    page_title = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    tab_section = Finds(Clickable, by=By.CSS_SELECTOR, value="#tabs a")
    overview_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Overview"]')
    network_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Network"]')
    alerts_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="Alerts"]')
    sub_headers = Finds(by=By.TAG_NAME, value="h3")
    health_alerts = Find(by=By.CSS_SELECTOR, value='.health-alert')
    alert_message = Find(by=By.CSS_SELECTOR, value='.health-alert>td:nth-child(2)')

    def __init__(self):
        super().__init__()

    @property
    def page_header(self):
        """ Return page title from header of your current nessus page. """

        return self.page_title.text

    def get_tab_content(self) -> list:
        """
        Method to get the list of tab name of scanner health page

        :return: List of tab name of scanner health page
        :rtype: list
        """
        return [tab.text for tab in self.tab_section]

    def get_sub_header_content(self) -> list:
        """
        Method to get the list of sub-header name of scanner health page

        :return: List of sub-header name of scanner health page
        :rtype: list
        """
        return [sub_header.text for sub_header in self.sub_headers]


class ScannerHealthOverviewTab(ScannerHealthPage):
    """ Page Object class for Overview tab under Scanner Health Page """

    current_health_count_labels = Finds(by=By.CSS_SELECTOR, value='.bannerCountLabel')
    memory_used = Find(by=By.CSS_SELECTOR, value='.bannerCountValue.memory')
    cpu_load = Find(by=By.CSS_SELECTOR, value='.bannerCountValue.cpu')
    host_count = Find(by=By.CSS_SELECTOR, value='.bannerCountValue.num_hosts')
    system_memory_tile = Find(by=By.ID, value='health-memory-comparison-doughnut')
    system_memory = Find(by=By.CSS_SELECTOR, value='li .system_memory')
    nessus_memory = Find(by=By.CSS_SELECTOR, value='li .nessus_memory')
    data_disk_space_tile = Find(by=By.ID, value='health-disk-comparison-doughnut')
    used_disk = Find(by=By.CLASS_NAME, value='used_disk')
    free_disk = Find(by=By.CLASS_NAME, value='free_disk')
    time_range_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='#hoursAgo')
    memory_usage_history_tile = Find(by=By.ID, value='health-history-timechart-memory')
    cpu_usage_history_tile = Find(by=By.ID, value='health-history-timechart-cpu')
    scanning_history_tile = Find(by=By.ID, value='health-history-timechart-scanning')

    @property
    def nessus_used_memory(self):
        """ Return nessus memory used under current health """
        return int(self.memory_used.text[:-2])

    @property
    def scanned_host_count(self):
        """ Return host count which are being scanned under current health """
        return int(self.host_count.text)

    def get_current_health_count_label(self) -> list:
        """
        Method to get the list of count label of Current Health of scanner health page

        :return: List of banner count label under Current health sub-header
        :rtype: list
        """
        return [count_label.text for count_label in self.current_health_count_labels]

    def get_text_from_tile(self, element_name: str) -> str:
        """
        Method to get the text from element of tile

        :param str element_name: UI element name
        :return: text value of UI element
        :rtype: str
        """
        tile_detail = Find(by=By.XPATH, value='//*[@class="{}"]//parent::li'.format(element_name), context=self)
        return tile_detail.text.strip()


class ScannerHealthNetworkTab(ScannerHealthPage):
    """ Page Object class for Network tab under Scanner Health Page """

    network_scanning_history_tile = Find(by=By.ID, value='health-history-timechart-network-scanning')
    network_connections_tile = Find(by=By.ID, value='health-history-timechart-network-connections')
    network_traffic_tile = Find(by=By.ID, value='health-history-timechart-network-traffic')
    dns_lookups_tile = Find(by=By.ID, value='health-history-timechart-network-dns-lookups')
    dns_lookup_time_tile = Find(by=By.ID, value='health-history-timechart-network-dns-lookup-time')


class ScannerHealthAlertsTab(ScannerHealthPage):
    """ Page Object class for Alerts tab under Scanner Health Page """

    pop_up_remove_icon = Find(Clickable, By.CSS_SELECTOR, value='.glyphicons.remove')
    high_sev_alert = Finds(by=By.CSS_SELECTOR, value='.severity-indicator.sev-high')
    medium_sev_alert = Finds(by=By.CSS_SELECTOR, value='.severity-indicator.sev-medium')
