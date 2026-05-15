"""
Nessus page classes for Scan results Page

:copyright: Tenable Network Security, 2017
:date: July 26, 2017

:last_modified: Dec 16, 2024
:author: @rdutta, @jamreliya, @mameta, @smadan, @ntarwani, @kpanchal, @krpatel, @mdabra
"""
import time
from contextlib import contextmanager
from datetime import datetime
from typing import List

from selenium.common.exceptions import NoSuchElementException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from waiting import TimeoutExpired, wait

from catium.helpers.sleep_lib import sleep
from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_NORMAL
from catium.lib.const.base_constants import WAIT_SHORT, TIME_THREE_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium import Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.date_picker import DatePicker
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable, GenericTableColumn
from catium.lib.webium.controls.text_field import TextField
from nessus.lib.const import API, Nessus
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.generic_modals import SetExportPasswordModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


@cat_registry.route(r'/scans/folders/my-scans')
class ScanViewPage(NessusBasePage):
    """Page Object for the scan view page"""
    header_element = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    back_link = Find(by=By.CSS_SELECTOR, value='.title-box a')

    configure_button = Find(Clickable, by=By.CSS_SELECTOR, value='.button-bar #configure')
    audit_trail_button = Find(Clickable, by=By.CSS_SELECTOR, value='#audit-trail')
    scan_result_button_bar = Find(by=By.CSS_SELECTOR, value='ul.button-bar')
    launch_dropdown = Find(Clickable, by=By.CSS_SELECTOR, value='#launch-dropdown')
    default_launch_option = Find(Clickable, by=By.CSS_SELECTOR, value='#launch-default')
    selected_launch_option = Find(Clickable, by=By.CSS_SELECTOR, value='#launch-selected')
    custom_launch_option = Find(Clickable, by=By.CSS_SELECTOR, value='#launch-custom')
    custom_target_input_box = Find(TextField, by=By.CSS_SELECTOR, value='#custom-launch-targets')
    custom_launch_button = Find(Clickable, by=By.CSS_SELECTOR, value='#custom-targets-launch')
    export_button = Find(Clickable, by=By.CSS_SELECTOR, value='#export')
    export_format = Finds(Clickable, by=By.CSS_SELECTOR, value='#export ul li')
    report_button = Find(Clickable, by=By.ID, value='generate-scan-report')
    locales_on_report_modal = Find(TextField, by=By.CSS_SELECTOR, value='.header-locale-label')
    csv_radio_button = Find(Clickable, by=By.CSS_SELECTOR, value='[aria-label="CSV"]')
    csv_column_options = Finds(by=By.CSS_SELECTOR, value='.csv-columns-group-2 div span')
    select_all_link = Find(Clickable, by=By.CSS_SELECTOR, value='div.selectClear')
    report_format = Finds(Clickable, by=By.CSS_SELECTOR, value='#report ul li')
    modify_button = Find(Clickable, by=By.CSS_SELECTOR, value='#vulnerabilities-modify')
    snooze_button = Find(Clickable, by=By.CSS_SELECTOR, value='#snooze-dropdown')
    wake_button = Find(Clickable, by=By.CSS_SELECTOR, value='#vulnerabilities-wake')
    snooze_dropdown_options = Finds(Clickable, by=By.CSS_SELECTOR, value='#snooze-dropdown ul li')
    snooze_popup_menu_options = Finds(Clickable, by=By.CSS_SELECTOR, value='#snooze-popup-menu li')
    diff_button = Find(Clickable, by=By.CSS_SELECTOR, value='#history-diff')
    delete_host = Find(Clickable, by=By.CSS_SELECTOR, value='#hosts-delete')
    delete_history = Find(Clickable, by=By.CSS_SELECTOR, value='#history-delete')
    tab_section = Finds(Clickable, by=By.CSS_SELECTOR, value="#tabs>a")
    configure = Find(Clickable, by=By.CSS_SELECTOR, value="#configure")
    more_dropdown = Find(Clickable, by=By.CSS_SELECTOR, value='#hosts-more')
    create_scan_option = Find(Clickable, by=By.CSS_SELECTOR, value='#create-scan')
    plugin_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="plugins"]')
    more_dropdown_options = Finds(Clickable, by=By.CSS_SELECTOR, value='#hosts-more ul li')
    filter_key_dropdowns = Finds(by=By.CSS_SELECTOR, value='.select2-results ul li')

    dashboard_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-show-dashboard')
    host_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-show-hosts')
    vulnerability_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-show-vulnerabilities')
    compliance_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-show-compliance')
    threat_level_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-show-prioritization')
    remediation_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-show-remediations')
    notes_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-show-notes')
    history_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#scans-show-history')
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.select-all')
    details_tab = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='scans-show-domain-discovery-details')
    records_tab = host_tab

    right_column_header = Find(by=By.CSS_SELECTOR, value='.right-column-header:nth-of-type(1)')
    license_more_link = Find(Clickable, by=By.CSS_SELECTOR, value='div[data-domselect="license-threshold"] a')
    link_to_enable_dashboard = Find(Clickable, by=By.CSS_SELECTOR, value='div[data-domselect="enable-dashboard"] a')
    percentage_count = Find(by=By.XPATH, value='.//div[@class="chart__count--dynamic" and contains(., "%")]')
    percentile_in_chart = Find(by=By.CSS_SELECTOR, value='.chart__count--dynamic span')
    enable_dashboard_msg = Find(by=By.CSS_SELECTOR, value='div[data-domselect="enable-dashboard"] span.msg')

    # Locators related to Audit Trail section
    audit_trail_section_header = Find(by=By.CSS_SELECTOR, value='.sidebar-wrapper h4')
    audit_plugin_id = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Audit Plugin ID"]')
    audit_host = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Audit Hostname"]')
    search_button = Find(Clickable, by=By.CSS_SELECTOR, value='#audit-trail-submit')
    audit_content = Find(by=By.CSS_SELECTOR, value='#audit-trail-content')
    audit_trail_section_close_icon = Find(Clickable, by=By.CSS_SELECTOR, value='.sidebar-wrapper i.remove')

    # Search related elements
    search_box = Find(TextField, by=By.CSS_SELECTOR, value='#searchbox input')
    search_icon = Find(by=By.CSS_SELECTOR, value='.glyphicons.search')
    output_area = Find(by=By.CSS_SELECTOR, value='[class ="plugin-details-output"]')
    clear_search_icon = Find(Clickable, by=By.CSS_SELECTOR, value='#searchbox .remove')
    total_records = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"]')
    selected_records = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"]')
    filtered_records = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Results"]')
    select_all_records = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"] a[data-domselect="select-all"]')
    clear_selected_item_link = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Checked"] a')

    # filter related locators and variable
    applied_filter_count = 0
    select_date = Find(DatePicker, by=By.CSS_SELECTOR, value='div#ui-datepicker-div')
    current_date = Find(by=By.CSS_SELECTOR, value='.ui-datepicker-today')
    filter_link = Find(Clickable, by=By.CSS_SELECTOR, value='#advanced-search')
    apply_button = Find(Clickable, by=By.CSS_SELECTOR, value='#editor-plugin-filters-apply')
    open_filter = Find(Clickable, by=By.CSS_SELECTOR, value='[title="Asset Inventory"]')
    count_of_filter = Find(by=By.CSS_SELECTOR, value='#advanced-search span')
    match_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.filter-type-select')
    add_filter = Find(Clickable, by=By.XPATH, value='(//div[@class="add-filter"])[last()]')
    remove_filter = Find(Clickable, by=By.CSS_SELECTOR, value='.remove-filter')
    plugin_family_data = Find(by=By.CSS_SELECTOR, value='.plugin-family')
    clear_filter_link = Find(Clickable, by=By.CSS_SELECTOR, value='.clear-advanced-search')
    filter_holder = Find(by=By.CLASS_NAME, value='filter-holder')
    count_of_filter_container = Finds(by=By.CSS_SELECTOR, value='.filter-container')
    close_filter = Find(Clickable, by=By.CSS_SELECTOR, value='.modal-close .remove')

    result_per_page_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.dataTables_length select')
    policy_option = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Policy"]')
    empty_result = Find(by=By.CSS_SELECTOR, value='.empty-results')
    modify_icon = Find(by=By.CSS_SELECTOR, value="#vulnerabilities-modify:nth-child(1)")
    primary_results_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.form-group .select2-hidden-accessible')
    scan_diff_host_count = Find(by=By.CSS_SELECTOR, value='#scans-show-hosts span')
    scan_diff_vulnerabilities_count = Find(by=By.CSS_SELECTOR, value='#scans-show-vulnerabilities span')
    scan_diff_history_count = Find(by=By.CSS_SELECTOR, value='#scans-show-history span')
    no_record_found = Find(by=By.CSS_SELECTOR, value='.dataTables_empty')
    launch_button = Find(Clickable, by=By.CSS_SELECTOR, value='#launch')
    plugin_attachment = Find(by=By.CSS_SELECTOR, value='table.attachments-table tr.attachment')
    plugin_attachment_data = Find(by=By.TAG_NAME, value='body')
    schedule_scan_warning = Find(by=By.CSS_SELECTOR, value=".schedule-note")
    key_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.select-key.new-filter select')
    value_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.select-value select')
    node_dropdown = Find(by=By.CSS_SELECTOR, value='.details-menu')
    agent_details_column_header = Find(by=By.XPATH, value="//*[@class='right-column-header']//following::h5[1]")
    agent_details_section = Find(by=By.XPATH,
                                 value="//*[@class='right-column-header']//following::h5[1]//following-sibling::div[1]")
    search_result_options = Finds(by=By.CSS_SELECTOR, value=".select2-results__options li")
    epss_risk_information = Finds(by=By.XPATH, value="//*[contains(text(),'Exploit Prediction Scoring System (EPSS)')]")
    select2_searchbox = Find(TextField, by=By.CSS_SELECTOR, value='input.select2-search__field')
    key_dropdown_arrow = Find(by=By.CSS_SELECTOR, value=".select-key.new-filter span.select2-selection__arrow")

    # VPR Top Threats tab related locators
    threat_level_description = Finds(by=By.CSS_SELECTOR, value="div.description-copy > p")
    threat_level_host_link = Finds(by=By.CSS_SELECTOR, value="a[data-domselect='prioritization-affected-host-link']")
    threat_level_icon = Find(by=By.CSS_SELECTOR, value="#content .threat-level-icon > path")
    predictive_prioritization_link = Find(Link, by=By.CSS_SELECTOR, value=".content-block.prioritization a")
    assessed_threat_level_value = Find(by=By.CSS_SELECTOR, value="div.description-copy strong")
    empty_results = Find(by=By.CSS_SELECTOR, value='span.empty-results')

    # Severity base related locators
    severity_base_change_icon = Find(by=By.CSS_SELECTOR, value="i.scan-severity-rating-base.edit")
    severity_base_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                                  value="select.severity-base")
    cvss_in_bold = Find(by=By.CSS_SELECTOR, value='.right-column-section span.bold')
    severity_base_value = Find(by=By.XPATH, value='.//*[contains(text(), "Severity Base:")]//following::span[1]')
    cvss_score_column = Find(by=By.CSS_SELECTOR, value='th[aria-label*="CVSS"]')

    # Summary tab related locators
    summary_tab = Find(Clickable, by=By.ID, value='scans-show-cluster-scan-summary')
    node_column = Find(Clickable, by=By.CSS_SELECTOR, value='th[aria-label*="Not Started"]')
    in_progress_column = Find(Clickable, by=By.CSS_SELECTOR, value='th[aria-label*="In Progress"]')
    completed_column = Find(Clickable, by=By.CSS_SELECTOR, value='th[aria-label*="Completed"]')
    aborted_column = Find(Clickable, by=By.CSS_SELECTOR, value='th[aria-label*="Aborted"]')
    failed_column = Find(Clickable, by=By.CSS_SELECTOR, value='th[aria-label*="Failed"]')
    total_column = Find(Clickable, by=By.CSS_SELECTOR, value='th[aria-label*="Total"]')
    switch_node_drop_down = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[aria-label="Switch Node"]')

    # Scan Summary tab related locators
    scan_summary_tab = Find(by=By.CSS_SELECTOR, value='#scans-show-scan-summary')

    def __init__(self, id: str = None):
        super().__init__()
        self.required_elements = ['configure_button']
        if id is not None:
            self.url += 'scans/reports/' + str(id)

    def get_levels_value_of_details_section(self, level_name: str) -> WebElement:
        """
        returns dynamic element of levels value depending on levels name
        :param str level_name: name of the level
        :return: level element
        :rtype: WebElement
        """
        return Find(by=By.XPATH, value='//span[contains(text(),"{}:")]/following-sibling::span[1]'.format(level_name),
                    context=self)

    def get_levels_element_of_chart(self, level_name: str) -> WebElement:
        """
        Get UI element for levels against chart in dashboard
        :param str level_name: level name
        :return: level element of chart
        :rtype: WebElement
        """
        if level_name in Nessus.Scan.Severity.SEVERITY_LEVELS:
            return Find(by=By.CSS_SELECTOR, value='.{}'.format(level_name.upper()), context=self)
        else:
            return Find(by=By.CSS_SELECTOR, value='.{}'.format(level_name), context=self)

    def get_filter_dropdown_element(self, index_value: int, element_type: str) -> WebElement:
        """
        Get UI element for filter condition's dropdown depending on the element type and index of filter
        :param int index_value: index of filter
        :param str element_type: type of element
        :return: dropdown element of filter window
        :rtype: WebElement
        """
        if element_type == Nessus.Filter.OPERATOR:
            element_type = 'op'
        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.filter-container:nth-child({}) div.select-{} select'
                    .format(index_value, element_type), context=self)

    def get_filter_value_text_element(self, index_value: int) -> WebElement:
        """
        Get UI element of filter value textfield
        :param int index_value: index of filter
        :return: text input element of filter window
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='.filter-container:nth-child({}) div.select-value input'
                    .format(index_value), context=self)

    def get_filter_value_datepicker(self, index_value: int) -> WebElement:
        """
        Get UI element of filter value datepicker
        :param int index_value: index of filter
        :return: date input element of filter window
        :rtype: WebElement
        """
        return Find(Clickable, by=By.CSS_SELECTOR, value='.filter-container:nth-child({}) div.select-value .date-picker'
                    .format(index_value), context=self)

    def get_remove_filter_element(self, index_value: int) -> WebElement:
        """
        Get UI element of remove filter icon

        :param int index_value: index of filter
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='.filter-container:nth-child({}) .remove-filter'.format(index_value),
                    context=self)

    def get_element_from_risk_information_section(self, value: str) -> WebElement:
        """
        Get UI element from Risk Information section

        :param str value: value for element
        :return: WebElement
        """
        return Find(by=By.XPATH, value='.//*[contains(text(), "{}")]'.format(value), context=self)

    def get_element_for_vpr_tab_or_description_icon(self, threat_index: str,
                                                    element_for: str = "description") -> WebElement:
        """
        Get UI element from VPR Top Threats tab or description icon

        :param str element_for: tab or description
        :param str threat_index: Severity index like 4 for Critical, 3 for High, etc...
        :return: WebElement
        """
        value = ".tab-icon-svg" if element_for == "tab" else ".content-block.prioritization svg"

        return Find(by=By.CSS_SELECTOR, value='{}.threat-level-icon path.threat-{}'.format(value, threat_index),
                    context=self)

    def get_element_for_vpr_severity_from_table(self, threat_index: str) -> WebElement:
        """
        Get UI element from VPR Severity from table

        :param str threat_index: Severity index like 4 for Critical, 3 for High, etc...
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='.sev-indicator.sev-{}'.format(threat_index), context=self)

    def get_element_for_report_format_radio_button(self, report_format: str, label_element: bool = False) -> WebElement:
        """
        Get UI element for given report format

        :param str report_format: Report format type like PDF, HTML or CSV
        :param bool label_element: True if need report label element else False
        :return: WebElement
        """
        locator_value = 'div[aria-label="{}"]'
        expected_value = locator_value + ' + span' if label_element else locator_value

        return Find(by=By.CSS_SELECTOR, value=expected_value.format(report_format), context=self)

    @property
    def page_header(self):
        """Return scan name from header of corresponding scan details page."""
        return self.header_element.text.split('\n')[0]

    @property
    def total_records_count(self):
        """Return count of records shows in table header."""
        return int(self.total_records.text.split(" ")[0])

    @property
    def filtered_records_count(self):
        """Return count of records filtered with given search string shows in table header."""
        return int(self.filtered_records.text.split(" ")[0])

    @property
    def selected_records_count(self):
        """Return counted string shows in table header of records selected in the list."""
        return int(self.selected_records.text.split(" ")[0][1])

    @property
    def filter_count(self):
        """Return applied filter count."""
        return int(self.count_of_filter.text)

    def launch_scan(self, launch_type: str, scan_targets: str = None) -> None:
        """
        Launch a scan against the targets specified by its type
        :param str launch_type: default/selected/custom
        :param str scan_targets: required for "selected/custom" scan type
        :return: None
        """
        if launch_type == Nessus.Scan.Results.LaunchTypes.SELECTED:
            self.host_tab.click()
            ScansHostList().select_hosts(hosts_list=scan_targets.split(', '))
            LoadingCircle(TIME_THREE_SECONDS)

        self.launch_dropdown.click()
        LoadingCircle(WAIT_SHORT)
        if launch_type == Nessus.Scan.Results.LaunchTypes.CUSTOM:
            self.custom_launch_option.click()
            self.custom_target_input_box.value = scan_targets
            self.custom_launch_button.click()
            LoadingCircle(TIME_THREE_SECONDS)
        elif launch_type == Nessus.Scan.Results.LaunchTypes.DEFAULT:
            self.default_launch_option.click()
        else:
            self.selected_launch_option.click()

    def export_scan_in_format(self, format_type: str, password: str = None, report_flag: bool = False) -> None:
        """
        export a scan in a format specified by format_type
        :param str format_type: type of formats we can export a scan
        :param str password: password for db format, not needed for other format
        :param bool report_flag: False
        :return: None
        """
        action_modal = ActionCloseModal()
        scan_export_page = ScanExportPage()
        password = password if password else Nessus.DummyCredentials.EXPORT_SECURITY_PASSWORD

        if report_flag:
            self.report_button.click()
            wait(lambda: action_modal.is_element_present("modal"), waiting_for='CSV export modal to open')

            self.get_element_for_report_format_radio_button(report_format=format_type).click()
            wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
                "hide_system_template_checkbox"), waiting_for="Selected report options get displayed")

            scan_export_page.generate_report_button.click()
            action_modal.wait_for_modal_closed()
        else:
            self.export_button.click()
            format_list = self.export_format

            for format_name in format_list:
                if format_name.text == API.Scan.UIExportFormats.FORMAT_DB:
                    format_name.click()
                    SetExportPasswordModal().set_password(password=password)
                else:
                    format_name.click()

                action_modal.wait_for_modal_closed()
                break
            else:
                log.error("Wrong export format.")

    def select_export_scan_type_as_custom(self, format_type: str) -> None:
        """
        It will select report type as "Custom" from report type dropdown
        :param str format_type: Format type for Ex. PDF or HTML
        :return: None
        """
        for format_name in self.export_format:
            if format_name.text == format_type:
                if format_name.text in (API.Scan.UIExportFormats.FORMAT_HTML, API.Scan.UIExportFormats.FORMAT_PDF):
                    format_name.click()
                    LoadingCircle(WAIT_SHORT)
                    scan_export_page = ScanExportPage()
                    scan_export_page.report_dropdown_types.select_by_visible_text("Custom")
                    LoadingCircle(WAIT_NORMAL)

    def select_report_scan_type_as_custom(self, format_type: str) -> None:
        """
        It will select report type as "Custom" from report type dropdown
        :param str format_type: Format type for Ex. PDF or HTML
        :return: None
        """
        for format_name in self.report_format:
            if format_name.text == format_type:
                if format_name.text in (API.Scan.UIExportFormats.FORMAT_HTML, API.Scan.UIExportFormats.FORMAT_PDF):
                    format_name.click()
                    scan_export_page = ScanExportPage()
                    scan_export_page.report_dropdown_types.select_by_visible_text("Custom")
                    break

    def get_tab_content(self) -> list:
        """
        Method to get the list of tab name in scan result
        :return: List of tab name in scan result
        :rtype: list
        """
        return [tab.get_attribute("innerText").split()[0] for tab in self.tab_section if
                tab.get_attribute("innerText").split()[0] not in ["Hosts", "History", "Notes"]]

    def apply_search(self, search_string: str) -> None:
        """
        apply a search on list
        :param str search_string: substring for search to apply
        :return: None
        """
        LoadingCircle(WAIT_SHORT)
        self.search_box.value = search_string

    def verify_search_result(self, search_string: str, records_list_object: ObjectList) -> bool:
        """
        verify search string exists in all rows in the list
        :param str search_string: substring of applied filter
        :param ObjectList records_list_object: object of list class
        :return: True if search string found in all rows
        :rtype: bool
        """
        return all(search_string.lower() in row.text.lower() for row in records_list_object.rows)

    def search_results(self, search_list: List[str], records_list_object: ObjectList) -> List:
        rows = [row for row in records_list_object.get_all()]
        results_found = list()
        results_not_found = list()
        for result in search_list:
            result_found = False
            for row in rows:
                values = list(map(lambda x: str(x).lower(), row.values()))
                if str(result).lower() in values:
                    result_found = True
                    break

            if result_found:
                results_found.append(result)
            else:
                results_not_found.append(result)

        return results_found, results_not_found

    def apply_search_on_audit_trail(self, plugin_id: str = None, host: str = None) -> None:
        """
        Apply search on audit trails by provided input
        :param str plugin_id: audit plugin id
        :param str host: host IP
        :return: None
        """
        self.audit_plugin_id.value = plugin_id
        self.audit_host.value = host
        self.search_button.click()

    def get_filter_value(self) -> str:
        """
        Returns filter pre-filled value
        :return: filled value
        :rtype: str
        """
        return self.search_box.get_attribute('value')

    def apply_filter(self, key: str, operator: str, value: str, match_type: str = Nessus.Filter.FilterMatch.ALL,
                     apply: bool = True) -> None:
        """
        Apply particular filter in scan result using advance filter
        :param str key: Key value to apply a filter
        :param str operator: Operator value to apply a filter
        :param str value: Value for the filter.
        :param str match_type: Match type for conditions.
        :param bool apply: Apply filter if True else just set filter values
        :return: None
        """
        if apply:
            self.filter_link.click()

        self.applied_filter_count += 1

        index = self.applied_filter_count
        self.match_dropdown.select_by_visible_text(match_type)
        LoadingCircle(WAIT_SHORT)
        if self.applied_filter_count > 1:
            self.add_filter.click()

        self.get_filter_dropdown_element(index_value=index, element_type=Nessus.Filter.KEY).select_by_visible_text(key)
        self.get_filter_dropdown_element(index_value=index,
                                         element_type=Nessus.Filter.OPERATOR).select_by_visible_text(operator)

        LoadingCircle(WAIT_SHORT)
        if key in Nessus.Filter.FilterKeys.VALUE_DROPDOWN:
            self.get_filter_dropdown_element(index_value=index,
                                             element_type=Nessus.Filter.VALUE).select_by_visible_text(value)
        elif key in Nessus.Filter.FilterKeys.VALUE_DATEPICKER:
            self.get_filter_value_datepicker(index_value=index).click()
            from nessus.helpers.date_selector import select_date_in_datepicker
            select_date_in_datepicker(page_class_instance=self, input_date=value)
        else:
            self.get_filter_value_text_element(index_value=index).clear()
            self.get_filter_value_text_element(index_value=index).send_keys(value)

        if apply:
            filter_modal = ActionCloseModal()
            filter_modal.accept_action()
            filter_modal.wait_for_modal_closed()

    def clear_filter(self) -> None:
        """
        Clear any applied filter in filter window of scans result page.
        :return: None
        """
        self.filter_link.click()
        self.clear_filter_link.click()
        self.applied_filter_count = 0

    def get_export_scan_pop_up(self, format_type: str, report_flag: bool = False) -> None:
        """
        Open export pop-up for scan format

        :param str format_type: export format type
        :param bool report_flag: True if
        :return: None
        """
        format_list = self.report_format if report_flag else self.export_format
        for format_name in format_list:
            if format_name.text == format_type:
                format_name.click()
                LoadingCircle(WAIT_SHORT)

    def remove_specific_filter(self, index_value: int) -> None:
        """
        Remove specific filter from vulnerabilities filter

        :param int index_value: index of filter
        :return: None
        """
        self.get_remove_filter_element(index_value).click()

    def get_filter_value_text(self, index: int) -> list:
        """
        Returns filled values of specific filter

        :param int index: index of filter 
        :return: list of filter values
        :rtype: list
        """
        filter_value = []

        for element_type in [Nessus.Filter.KEY, Nessus.Filter.OPERATOR, Nessus.Filter.VALUE]:
            if element_type in [Nessus.Filter.KEY, Nessus.Filter.OPERATOR]:
                text_value = self.get_filter_dropdown_element(
                    index_value=index, element_type=element_type).get_text_selected()
            else:
                if filter_value[0] in Nessus.Filter.FilterKeys.VALUE_DROPDOWN:
                    text_value = self.get_filter_dropdown_element(
                        index_value=index, element_type=element_type).get_text_selected()
                else:
                    text_value = self.get_filter_value_text_element(index_value=index).text

            filter_value.append(text_value)

        return filter_value

    def get_report_scan_pop_up(self, format_type: str) -> None:
        """
        Open report pop-up for report format

        :param str format_type: report format type
        :return: None
        """
        for format_name in self.report_format:
            if format_name.text == format_type:
                format_name.click()
                LoadingCircle(WAIT_NORMAL)

    def change_severity_base_value_from_popup(self, severity_value) -> str:
        """
        Change the severity base value for particular scan
        :param: CVSS v2.0 or CVSS v3.0 or CVSS v4.0
        :return: New value of severity base or created scan
        :rtype: str
        """
        cvss_pop_up = ActionCloseModal()
        if cvss_pop_up.is_element_present('modal'):
            cvss_pop_up.container_close_icon.click()
            sleep(WAIT_SHORT * 3, reason="It takes little bit time to get UI settled")
        self.severity_base_change_icon.click()
        self.severity_base_dropdown.select_by_visible_text(text=severity_value)
        cvss_pop_up.accept_action()
        cvss_pop_up.wait_for_modal_closed()
        return severity_value


class ScanDashboardPage(ActionCloseModal, ScanViewPage):
    """Defines properties and methods inherited by the Nessus Scans Page."""
    top_vulns_rows = Finds(by=By.CSS_SELECTOR, value='#scanTopVulnerabilities td:nth-child(2)')
    top_hosts_rows = Finds(by=By.CSS_SELECTOR, value='#scanTopHosts td:nth-child(1)')

    def get_top_vulnerabilities(self) -> list:
        """
        Get top vulnerabilities listed in scan dashboard page.
        :return: list of top visible vulnerabilities
        :rtype: list
        """
        return [vulns for vulns in self.top_vulns_rows]

    def get_top_hosts(self) -> list:
        """
        Get top hosts listed in scan dashboard page.
        :return: list of top visible hosts
        :rtype: list
        """
        return [hosts for hosts in self.top_hosts_rows]

    def enabling_dashboard(self) -> None:
        """
        Enables the dashboard for a scan.
        :return: None
        """
        self.link_to_enable_dashboard.click()
        self.action_button.click()
        self.wait_for_modal_closed()

    def is_dashboard_enabled(self) -> bool:
        """
        Check if dashboard of a scan result is enabled or not.
        :return: Returns true if dashboard is enabled otherwise returns false
        :rtype: bool
        """
        try:
            return False if self.link_to_enable_dashboard.is_displayed() else True
        except NoSuchElementException:
            return True

    def click_top_vulnerability(self, vulnerability: str) -> None:
        """
        Click on a particular vulnerability under top vulnerabilities list in scan dashboard.
        :param str vulnerability: vulnerability to be clicked
        :return: None
        """
        for scan_vulnerabilities in self.get_top_vulnerabilities():
            if scan_vulnerabilities.text == vulnerability:
                scan_vulnerabilities.click()
                break
        else:
            log.warning('"%s" not found in top vulnerabilities list in dashboard', vulnerability)

    def click_top_host(self, host: str) -> None:
        """
        Click on a particular host under top hosts list in scan dashboard.
        :param str host: host to be clicked
        :return: None
        """
        for scan_hosts in self.get_top_hosts():
            if scan_hosts.text == host:
                scan_hosts.click()
                break
        else:
            log.warning('"%s" not found in top hosts list in dashboard', host)


class ScanSummaryPage(ScanViewPage):
    """ Page Object class for Scan summary page """

    # Locators related to "Scan Details" section
    scan_details_section = Find(by=By.CSS_SELECTOR, value='.scan-details')

    # Locators related to "Top 5 Operating Systems Detected During Scan" section
    pie_chart_section = Find(by=By.CSS_SELECTOR, value='#scan-summary-pie-chart')
    os_distribution_section_title = Find(by=By.CSS_SELECTOR, value='#scan-summary-pie-chart h3')
    detected_os_list = Finds(by=By.CSS_SELECTOR, value='ul.chart__legend li')

    # Locators related to "Authentication / Credential Info (Hosts)" section
    auth_credential_info_section = Find(by=By.CSS_SELECTOR, value='#scan-summary-auth')
    auth_credential_info_section_label = Find(by=By.CSS_SELECTOR, value='#scan-summary-auth h3')
    succeeded_hosts_with_creds_label = Find(by=By.CSS_SELECTOR,
                                            value='span[class*="hostsWithCreds"] + span.bannerCountLabel')
    succeeded_hosts_with_creds_value = Find(by=By.CSS_SELECTOR, value='span[class*="hostsWithCreds"]')
    failed_hosts_creds_label = Find(by=By.CSS_SELECTOR, value='span[class*="hostsFailedCreds"] + span.bannerCountLabel')
    failed_hosts_creds_value = Find(by=By.CSS_SELECTOR, value='span[class*="hostsFailedCreds"]')

    # Locators related to "Scan Durations" section
    scan_duration_section = Find(by=By.CSS_SELECTOR, value='#scan-summary-timing')
    scan_duration_section_label = Find(by=By.CSS_SELECTOR, value='#scan-summary-timing h3')
    scan_duration_time_label = Find(by=By.CSS_SELECTOR, value='span[class*="scanTime"] + span.bannerCountLabel')
    scan_duration_time_value = Find(by=By.CSS_SELECTOR, value='span[class*="scanTime"]')
    scan_median_time_label = Find(by=By.CSS_SELECTOR, value='span[class*="median"] + span.bannerCountLabel')
    scan_median_time_value = Find(by=By.CSS_SELECTOR, value='span[class*="median"]')
    max_scan_time_label = Find(by=By.CSS_SELECTOR, value='span[class*="max"] + span.bannerCountLabel')
    max_scan_time_value = Find(by=By.CSS_SELECTOR, value='span[class*="max"]')
    scan_duration_export_button = Find(Clickable, by=By.CSS_SELECTOR, value='#scan-summary-timing-button')

    # Locators related to "Scan Notes" section
    scan_notes_section = Find(by=By.CSS_SELECTOR, value='#scan-summary-notes')
    scan_notes_section_label = Find(by=By.CSS_SELECTOR, value='#scan-summary-notes h3')
    search_notes_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-search="search-notes"]')
    total_search_notes = Find(by=By.CSS_SELECTOR,
                              value='div[data-domselect*="Table Searchbox"] > span[data-domselect="Total Records"]')
    search_notes_icon = Find(Clickable, by=By.CSS_SELECTOR,
                             value='div[class*="notes-search"] > i[data-domselect="searchIcon"]')
    remove_search_notes_icon = Find(Clickable, by=By.CSS_SELECTOR,
                                    value='div[class*="notes-search"] > i[data-domselect="removeSearchIcon"]')

    # Locators related to "Plugin Families Enabled/Disabled" section
    plugin_families_section = Find(by=By.CSS_SELECTOR, value='#scan-summary-plugin-families')
    plugin_families_section_label = Find(by=By.CSS_SELECTOR, value='#scan-summary-plugin-families h3')
    search_plugin_families_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-search="search-families"]')
    total_search_plugin_families = Find(by=By.CSS_SELECTOR, value='div[data-domselect*="Table Searchbox"] > '
                                                                  'span[data-domselect="Total Records"]')
    search_plugin_families_icon = Find(Clickable, by=By.CSS_SELECTOR, value='div[class*="families-search"] > i['
                                                                            'data-domselect="searchIcon"]')
    remove_search_plugin_families_icon = Find(Clickable, by=By.CSS_SELECTOR, value='div[class*="families-search"] > i['
                                                                                   'data-domselect="removeSearchIcon"]')
    plugin_families_table = Find(by=By.CSS_SELECTOR, value='.families.dataTable.no-footer')
    results_per_page_label = Find(by=By.CSS_SELECTOR, value='#scan-summary-plugin-families label')
    results_per_page_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='#scan-summary-plugin-families select')
    pagination_first_arrow = Find(Clickable, by=By.CSS_SELECTOR, value='#scan-summary-plugin-families a['
                                                                       'class*="first"]')
    pagination_previous_arrow = Find(Clickable, by=By.CSS_SELECTOR, value='#scan-summary-plugin-families a['
                                                                          'class*="previous"]')
    pagination_next_arrow = Find(Clickable, by=By.CSS_SELECTOR, value='#scan-summary-plugin-families a[class*="next"]')
    pagination_last_arrow = Find(Clickable, by=By.CSS_SELECTOR, value='#scan-summary-plugin-families a[class*="last"]')

    # Locators related to "Plugin Rules Applied" section
    plugin_rules_applied_section = Find(by=By.CSS_SELECTOR, value='#scan-summary-plugins')
    plugin_rules_applied_section_label = Find(by=By.CSS_SELECTOR, value='#scan-summary-plugins h3')
    search_plugin_rules_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-search="search-pluginrules"]')
    total_search_plugin_rules = Find(by=By.CSS_SELECTOR, value='div[data-domselect*="Table Searchbox"] > '
                                                               'span[data-domselect*="Total Records"]')
    search_plugin_rules_icon = Find(Clickable, by=By.CSS_SELECTOR, value='div[class*="pluginrules-search"] > i['
                                                                         'data-domselect="searchIcon"]')
    remove_search_plugin_rules_icon = Find(Clickable, by=By.CSS_SELECTOR, value='div[class*="pluginrules-search"] > i['
                                                                                'data-domselect="removeSearchIcon"]')
    plugin_rules_applied_table = Find(by=By.CSS_SELECTOR, value='.pluginrules.dataTable.no-footer')

    # Locators related to "Policy Details" section
    policies_details_section = Find(by=By.CSS_SELECTOR, value='#scan-summary-policy')
    expand_collapse_arrow = Find(Clickable, by=By.CSS_SELECTOR, value='.scan-summary-policy-title > i')
    export_full_policy_down_arrow = Find(by=By.CSS_SELECTOR, value='#scan-summary-policy-button')
    policy_details_container = Find(by=By.CSS_SELECTOR, value='#policy-details-container')
    policy_details_containers_title = Finds(by=By.CSS_SELECTOR, value='.policy-details h1')

    def get_policy_details_container_titles(self) -> list:
        """
        Returns policy details containers title available under "Policy Details" section

        :return: policy details containers title
        :rtype: list
        """
        return [container_title.text.strip() for container_title in self.policy_details_containers_title]


class PluginFamiliesEnabledDisabledRecords(GenericTableRow):
    """ Defines the key names for 'Plugin Families Enabled/Disabled' section under scan summary page """
    plugin_family_status = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')
    plugin_family_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')

    @property
    def status(self):
        """ Returns plugin family status """
        return self.plugin_family_status.text.strip()

    @property
    def name(self):
        """ Returns name of the plugin family """
        return self.plugin_family_name.text.strip()


class PluginFamiliesEnabledDisabledList(ObjectList):
    """
    Returns a list containing Plugin families displayed under 'Plugin Families Enabled/Disabled' section of scan
    summary page
    """
    configure_button = None
    generics_map = {GenericTableRow: PluginFamiliesEnabledDisabledRecords}

    def __init__(self):
        super().__init__()

    def get_plugin_family_status(self) -> list:
        """
        Returns the list of all plugin status.

        :return: status of plugin family
        :rtype: list
        """
        try:
            return [plugin_family.status for plugin_family in self.rows]
        except NoSuchElementException:
            return []

    def get_plugin_family_name(self) -> list:
        """
        Returns the list of all plugin families.

        :return: name of plugin families
        :rtype: list
        """
        try:
            return [plugin_family.name for plugin_family in self.rows]
        except NoSuchElementException:
            return []


class PluginRulesAppliedRecords(GenericTableRow):
    """ Defines the key names for 'Plugin Rules Applied' section under scan summary page """
    plugin_rules_host = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')
    plugin_rules_id = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    plugin_severity = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')

    @property
    def host(self):
        """ Returns plugin rules host """
        return self.plugin_rules_host.text.strip()

    @property
    def plugin_id(self):
        """ Returns plugin id of plugin rules """
        return self.plugin_rules_id.text.strip()

    @property
    def severity(self):
        """ Returns severity of plugin id """
        return self.plugin_severity.text.strip()


class PluginRulesAppliedList(ObjectList):
    """ Returns a list containing Plugin rules applied under 'Plugin Rules Applied' section of scan summary page """
    configure_button = None
    plugin_rules_data_rows = Finds(PluginRulesAppliedRecords, by=By.CSS_SELECTOR, value='tr[class*="plugin-rules"]')
    plugin_rules_table_columns = Finds(GenericTableColumn, by=By.CSS_SELECTOR,
                                       value='table[class*="pluginrules"] th')

    def __init__(self):
        super().__init__()

    def get_plugin_rules_host(self) -> list:
        """
        Returns the list of all plugin rules host.

        :return: host of plugin rule
        :rtype: list
        """
        try:
            return [plugin_rule.host for plugin_rule in self.plugin_rules_data_rows]
        except NoSuchElementException:
            return []

    def get_plugin_rules_id(self) -> list:
        """
        Returns the list of plugin id of applied plugin rules

        :return: id of plugin rules
        :rtype: list
        """
        try:
            return [plugin_rule.plugin_id for plugin_rule in self.plugin_rules_data_rows]
        except NoSuchElementException:
            return []

    def get_plugin_severity(self) -> list:
        """
        Returns the list of severity of applied plugin rules

        :return: severity of plugins
        :rtype: list
        """
        try:
            return [plugin_rule.severity for plugin_rule in self.plugin_rules_data_rows]
        except NoSuchElementException:
            return []


class ScanNotesRecords(GenericTableRow):
    """ Defines the key names for 'Scan Notes' section under scan summary page """
    scan_notes_title = Find(by=By.CSS_SELECTOR, value='td:nth-child(1) h5')
    scan_notes_description = Find(by=By.CSS_SELECTOR, value='td:nth-child(1) span')

    @property
    def notes_title(self):
        """ Returns scan notes title """
        return self.scan_notes_title.text.strip()

    @property
    def notes_description(self):
        """ Returns scan notes description """
        return self.scan_notes_description.text.split("\n")[1].strip()


class ScanNotesList(ObjectList):
    """ Returns a list containing scan notes displayed under 'Scan Notes' section of scan summary page """
    configure_button = None
    generics_map = {GenericTableRow: ScanNotesRecords}

    def __init__(self):
        super().__init__()

    def get_scan_notes_title(self) -> list:
        """
        Returns the list of all scan notes title.

        :return: title of scan notes
        :rtype: list
        """
        try:
            return [scan_note.notes_title for scan_note in self.rows]
        except NoSuchElementException:
            return []

    def get_scan_notes_description(self) -> list:
        """
        Returns the list of all scan notes description.

        :return: description of scan notes
        :rtype: list
        """
        try:
            return [scan_note.notes_description for scan_note in self.rows]
        except NoSuchElementException:
            return []


class ScanVulnerabilities(ScanViewPage):
    """ Page Object for Scan Vulnerability page """
    critical = Find(by=By.CSS_SELECTOR, value='div[data-severity="4"]')
    high = Find(by=By.CSS_SELECTOR, value='div[data-severity="3"]')
    medium = Find(by=By.CSS_SELECTOR, value='div[data-severity="2"]')
    low = Find(by=By.CSS_SELECTOR, value='div[data-severity="1"]')
    info = Find(by=By.CSS_SELECTOR, value='div[data-severity="0"]')

    def get_data_count(self, element: WebElement) -> int:
        """
        Returns data count for a vulnerability type
        :param WebElement element: element
        :return: vulns count
        :rtype: int
        """
        return int(element.get_attribute('data-countvalue'))

    def get_severity_name(self, element: WebElement) -> str:
        """
        Returns severity name.
        :param WebElement element: element
        :return: severity name
        :rtype: str
        """
        return element.find_element(By.CSS_SELECTOR, '.bannerCountLabel').text

    def get_data_severity(self, element: WebElement) -> str:
        """
        Returns data severity of a element.
        :param WebElement element: element
        :return: severity value
        :rtype: str
        """
        return element.get_attribute('data-severity')


class VulnerabilityRecord(GenericTableRow):
    """Defines the key names for Vulnerability Records returned by VulnerabilityList"""
    checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.checkbox')
    sev_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    cvss_base_score = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    epss_base_score = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    plugin_id = Find(by=By.CSS_SELECTOR, value='td.vulnerability-plugin-id')
    plugin_name = Find(by=By.CSS_SELECTOR, value='td[class*="vulnerability-name"]')
    plugin_family = Find(by=By.CSS_SELECTOR, value='td:nth-child(7)')
    count = Find(Clickable, by=By.CSS_SELECTOR, value='td:nth-child(8)')
    modify_vulnerability = Find(Clickable, by=By.CSS_SELECTOR, value='td #vulnerabilities-modify')
    snooze_icon = Find(Clickable, by=By.CSS_SELECTOR, value='td .snooze')
    wake_icon = Find(Clickable, by=By.CSS_SELECTOR, value='.glyphicons.snoozed.add-tip.pointer')

    @property
    def severity_name(self):
        """Returns severity name of the vulnerability plugin."""
        return self.sev_name.text

    @property
    def cvss_score_tooltip(self):
        """Returns tooltip for cvss score of the plugin"""
        return self.cvss_base_score.get_attribute('original-title')

    @property
    def severity_value(self):
        """Returns severity value of the vulnerability plugin."""
        return self.sev_name.get_attribute('data-order')

    @property
    def vulnerability_plugin_id(self):
        """Returns ID of the plugin."""
        return self.plugin_id.get_attribute('innerHTML')

    @property
    def vulnerability_plugin_name(self):
        """Returns name of the plugin."""
        return self.plugin_name.text

    @property
    def vulnerability_plugin_family(self):
        """Returns plugin family of the vulnerability plugin."""
        return self.plugin_family.text

    @property
    def vulnerabilities_count(self):
        """Returns vulnerabilities count."""
        return int(self.count.text)

    @property
    def cvss_score_value(self):
        """Returns CVSS score value of the vulnerability plugin."""
        return self.cvss_base_score.text

    @property
    def epss_score_value(self):
        """Returns epss score value of the vulnerability plugin."""
        return self.epss_base_score.text


class VulnerabilityList(ObjectList):
    """Returns a list containing scan result vulnerabilities"""
    results = Finds(VulnerabilityRecord, by=By.CSS_SELECTOR, value='tr.vulnerability ')
    vulnerability_setting = Find(Clickable, by=By.CSS_SELECTOR, value='.glyphicons.gear.table-settings.add-tip')
    enable_disable_groups = Find(by=By.CSS_SELECTOR, value='li[data-name="vuln-groups"]')
    disable_popup = Find(by=By.CSS_SELECTOR, value='i[original-title="Settings"]')
    output_header = Find(by=By.CSS_SELECTOR, value=".plugin-details-content>h5")
    configure_button = None
    generics_map = {GenericTableRow: VulnerabilityRecord}
    back_to_vulnerabilities = Find(Link, by=By.CSS_SELECTOR, value='.glyphicons.back')
    vulnerability_columns = Finds(by=By.CSS_SELECTOR, value='tr th[tabindex="0"]')
    vuln_setting_pop_menus = Finds(by=By.CSS_SELECTOR, value='#settings-popup-menu li')

    def __init__(self):
        super().__init__()

    def find_vulnerability_by_id(self, plugin_id: int) -> WebElement:
        """
        Return the row has given plugin id
        :param int plugin_id: Id of the plugin
        :return: plugin row has given id
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value="tr[data-id='{}']".format(str(plugin_id)), context=self)

    def get_total_rows(self) -> int:
        """
        Return total rows summing up for all the pages
        :return: Total count of rows
        :rtype: int
        """
        LoadingCircle(WAIT_NORMAL)
        return len(self.object_table.table_wrapper.get_table_contents())

    def get_plugin_names(self) -> list:
        """
        Returns a list of  existing Plugins Names
        :return: list of names of all listed plugins
        :rtype: list
        """
        return [name.plugin_name.text for name in self.rows]

    def get_plugin_family_names(self) -> list:
        """
        Returns a list of  existing Plugins Names
        :return: list of names of all listed plugins
        :rtype: list
        """
        return [name.plugin_family.text for name in self.rows]

    def check_severity_name(self, severity: str) -> bool:
        """
        Returns true if the severity name for the entire list is same as parameter `severity`
        :param str severity: name of severity
        :return True if severity found same for all rows
        :rtype bool
        """
        return all([result.sev_name.text == severity for result in self.results])

    def check_severity_against_plugin(self, severity: str, plugin_list: list) -> bool:
        """
        Returns true if the severity name against plugin same as parameter `severity`
        :param str severity: name of severity
        :param list plugin_list: list of plugin by names
        :return: True if severity matched against plugin
        :rtype: bool
        """
        return all([True for record in self.results if
                    ((record.plugin_name.text in plugin_list) and (record.sev_name.text == severity))])

    def click_modify_vulnerability_for_plugin(self, plugin_name: str) -> None:
        """
        Applies the filter for the plugin name provide and click on modify button for the returned record
        :param str plugin_name: Plugin name
        :return: None
        """
        for vulnerability in self.results:
            if vulnerability.plugin_name.text == plugin_name:
                vulnerability.modify_vulnerability.click()
                break
        else:
            log.warning('Plugin name "%s" not found in the list', plugin_name)

    def select_vulnerabilities(self, vulnerabilities_list: list) -> None:
        """
        Select vulnerability(s) listed in vulnerabilities_list in the scans_result page
        :param list vulnerabilities_list: vulnerability(s) to be selected.
        :return: None
        """
        for row in self.rows:
            if row.plugin_name.text in vulnerabilities_list:
                row.checkbox.check()

    def get_all_listed_plugins_with_severity(self, list_by_plugin_id: bool = False) -> list:
        """
        Returns the list of all plugins with their severity

        :param bool list_by_plugin_id: if True then list will be generating by plugin_id otherwise by plugin_name
        :return: list of plugin name/id and plugin severity as (key: value) pair
        :rtype: list
        """
        row_attribute = 'vulnerability_plugin_id' if list_by_plugin_id else 'vulnerability_plugin_name'
        return [{getattr(row, row_attribute): row.severity_name} for row in self.rows]

    def get_severity_against_plugin(self, plugin_list: list) -> list:
        """
        Returns a list of severity of vulnerabilities
        :param list plugin_list: list of plugins
        :return: list of names of severity
        :rtype: list
        """
        return [name.severity_name for name in self.rows if name.plugin_name.text in plugin_list]

    def click_snooze_or_wake_icon_for_plugin(self, plugin_name: str, snooze: bool = True) -> None:
        """
        Click on snooze/wake icon for particular plugin/family
        :param str plugin_name: Name of the plugin/family whose snooze/wake icon is to be clicked
        :param bool snooze: if True then click snooze icon else click wake icon
        :return: None
        """
        for vulnerability in self.results:
            if vulnerability.plugin_name.text == plugin_name:
                if snooze:
                    vulnerability.snooze_icon.click()
                else:
                    vulnerability.wake_icon.click()
                break
        else:
            log.warning('Plugin name "%s" not found in the list', plugin_name)

    def get_plugins_under_vulnerability(self, vulnerability: str) -> list:
        """
        Returns list of plugins name under vulnerability.
        :param str vulnerability: vulnerability name.
        :return: list of plugins name
        :rtype: list
        """
        for row in self.rows:
            if not row.get_attribute("title").startswith("Plugin ID") and row.plugin_name.text.split("\n")[1].split(
                    "(")[0].rstrip() == vulnerability:
                row.click()
                return [name.plugin_name.text for name in self.rows]

    def click_on_group_enable_disable(self, enable: bool) -> None:
        """
        Click on Enable Groups or Disable Groups option under vulnerability setting.
        :param bool enable: If True click ‘Enable Groups’ else click ‘Disable Groups’ option under vulnerability setting
        :return: none
        """
        if enable:
            if self.enable_disable_groups.text.startswith('Enable'):
                self.enable_disable_groups.click()
        else:
            if self.enable_disable_groups.text.startswith('Disable'):
                self.enable_disable_groups.click()

    def click_on_vulnerability(self, vulnerability_name: str):
        """
        Click on vulnerability of specified name.

        :param str vulnerability_name: vulnerability name.
        :return: None
        """
        for row in self.rows:
            if row.plugin_name.text == vulnerability_name:
                self.move_to_element(row)
                row.click()
                break

    def get_cvss_score_for_given_vulnerability(self, vulnerability_name: str) -> str:
        """
        Get CVSS score value for given vulnerability.

        :param str vulnerability_name: vulnerability name.
        :return: CVSS score value for given vulnerability
        :rtype: str
        """
        for row in self.rows:
            if row.plugin_name.text == vulnerability_name:
                return row.cvss_score_value

    def get_cvss_score_tooltip_for_vulnerability(self, vulnerability_name: str) -> str:
        """
        Get tooltip of CVSS score value for given vulnerability score.

        :param str vulnerability_name: vulnerability name.
        :return: CVSS score tooltip for given vulnerability
        :rtype: str
        """
        for row in self.rows:
            if row.plugin_name.text == vulnerability_name:
                self.move_to_element(row.cvss_base_score)
                return row.cvss_score_tooltip

    def get_visible_column_names(self) -> list:
        """
        Returns list of column name under vulnerability.

        :return: list of column name
        :rtype: list
        """
        return [column_name.text.split(":")[0] for column_name in self.vulnerability_columns]

    def get_grouped_vulnerabilities_name_and_family(self) -> dict:
        """
        Returns dict of vulnerability name and family which are in group.

        :return: vulnerability name and family which are in group
        :rtype: dict
        """
        vulnerability_name_and_family = {}

        for row in self.rows:
            if row.cvss_score_value == "...":
                vulnerability_name_and_family[row.plugin_name.text.split("\n")[1]] = row.plugin_family.text

        return vulnerability_name_and_family

    def get_grouped_vulnerabilities_score_element(self, plugin_name: str, plugin_family: str) -> Find:
        """
        Return the row has given plugin id

        :param str plugin_name: Vulnerability name
        :param str plugin_family: Vulnerability family name
        :return: element of plugin score
        :rtype: WebElement
        """
        return Find(by=By.XPATH,
                    value='.//tr[@original-title="{}"]//td[contains(text(), "{}")]//preceding::td[4]'.format(
                        plugin_name, plugin_family), context=self)

    def get_cvss_score_of_all_vulnerabilities(self) -> list:
        """
        Returns list of CVSS score of all vulnerabilities.

        :return: CVSS score
        :rtype: list
        """
        return [row.cvss_score_value for row in self.rows]


class VulnerabilityDescription(ScanViewPage):
    """Page Object for Scan Vulnerability Description page"""
    plugin_header = Find(by=By.CSS_SELECTOR, value='.plugin-details-header h4')
    headings = Finds(by=By.CSS_SELECTOR, value='.plugin-details-content section')
    output_blocks = Finds(by=By.CSS_SELECTOR, value='.plugin-details-output li')
    back_to_vulnerabilities = Find(by=By.CSS_SELECTOR, value='.title-box a')
    next_icon = Find(Clickable, by=By.CSS_SELECTOR, value='.plugin-details-pagination.next')
    previous_icon = Find(Clickable, by=By.CSS_SELECTOR, value='.plugin-details-pagination.previous')
    risk_info_details = Finds(by=By.CSS_SELECTOR, value=".right-column-header ~ h5 + div > span")
    plugin_info_details = Finds(by=By.CSS_SELECTOR, value=".right-column-header ~ div span")
    plugin_output_table = Find(by=By.CSS_SELECTOR, value='table[class*="plugin-output-table"]')
    debug_log_hosts_row = Finds(by=By.CSS_SELECTOR, value="tr.attachment")
    plugin_output_header_columns = Finds(by=By.CSS_SELECTOR, value='table[class*="plugin-output-table"] th')

    @property
    def plugin_details_header(self):
        """Return text from header of plugin details page."""
        return self.plugin_header.text

    def get_host_element_from_output_details(self) -> dict:
        """
        Returns host(s) element from a particular output block
        :return: every host with its corresponding output block listed in dictionary
        :rtype: dict
        """
        all_hosts = {}
        for block, row_detail in enumerate(self.output_blocks, start=1):
            hosts_list = row_detail.find_elements(By.CSS_SELECTOR, '.hosts a')
            block_host = {}
            for host_count, host in enumerate(hosts_list, start=1):
                block_host.update({'Host-{}'.format(host_count): host})

            all_hosts.update({'block-{}'.format(block): block_host})
        return all_hosts

    def get_output_details(self) -> dict:
        """
        Returns data within a particular output block
        :return: every output block listed in dictionary
        :rtype: dict
        """
        output_details = {}
        for block, row_detail in enumerate(self.output_blocks, start=1):
            output_details.update({'block{}'.format(block): {
                'heading': row_detail.find_element(By.CSS_SELECTOR, '.content-wrapper').text,
                'port': row_detail.find_element(By.CSS_SELECTOR, '.port').text,
                'hosts': row_detail.find_element(By.CSS_SELECTOR, '.hosts').text}})

        return output_details

    def get_heading_data(self, heading_value: str) -> str:
        """
        Returns data within a particular heading
        :param str heading_value: Value of heading
        :return: header text
        :rtype: str
        """
        for heading in self.headings:
            if heading.find_element(By.CSS_SELECTOR, 'h5').text == heading_value:
                return heading.find_element(By.CSS_SELECTOR, '.plugin-wrap').text
        else:
            log.warning('"See Also" section does not exist')

    def get_heading_section_link(self, heading_value: str) -> list:
        """
        Returns see also section link text if present
        :param str heading_value: Value of Heading
        :return: list of links if visible
        :rtype: list
        """
        for heading in self.headings:
            if heading.find_element(By.CSS_SELECTOR, 'h5').text == heading_value:
                section_link = []
                try:
                    see_also_section = heading.find_element(By.CSS_SELECTOR, '.plugin-wrap')
                    links = see_also_section.find_elements(By.CSS_SELECTOR, 'a')
                    for link in links:
                        section_link.append(link.text)
                    return section_link
                except NoSuchElementException:
                    return False
        else:
            log.warning('"See Also" section does not exist')

    def get_element_of_plugin_debug_log_host(self, host: str) -> WebElement:
        """
        Returns host element from "Plugin debug Log (s)" output table

        :param str host: scan target
        :return: UI element of host
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='a[data-host-id="{}"]'.format(host), context=self)


class ScanASDRecordDescription(VulnerabilityDescription):
    description = Finds(by=By.CSS_SELECTOR, value='.plugin-details-content section .plugin-wrap')
    side_sections = Finds(by=By.CSS_SELECTOR, value='.right-column > .right-column-section')
    port = Find(by=By.CSS_SELECTOR, value='td.port')
    hosts = Find(by=By.CSS_SELECTOR, value='td.hosts')

    def __init__(self):
        super().__init__()
        LoadingCircle(WAIT_SHORT)

    def get_plugin_details_data(self):
        span_data = self.side_sections[0].find_elements(By.CSS_SELECTOR, "span")
        keys = [item.text.strip(" :").lower() for item in span_data if item.text.endswith(":")]
        values = [item.text.strip("") for item in span_data if not item.text.endswith(":")]
        data = dict(zip(keys, values))

        return data

    def get_description(self) -> str:
        """
        :return: returns the 'Description' data
        :rtype: str
        """

        return self.description[0].text

    def get_output_data(self) -> dict:
        data = dict()
        row_detail = self.output_blocks[0]
        split_heading = row_detail.find_element(By.CSS_SELECTOR, '.content-wrapper').text.split("\n")

        data["Description"] = split_heading.pop(0).rstrip(":")
        for item in split_heading:
            key, value = item.strip().split(": ")
            mod_key = key.lower().replace(" ", "_")
            data[mod_key] = value

        return data

    def get_port(self):
        return self.port.text

    def get_hosts(self):
        return self.hosts.text


class ThreatLevelVulnerabilityRecord(GenericTableRow):
    """Defines the key names for Vulnerability Records returned by VulnerabilityList inside Threat Level Tab."""
    sev_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')
    plugin_name = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    plugin_reason = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    vpr_score = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')

    @property
    def severity_name(self):
        """Returns severity name of the vulnerability plugin."""
        return self.sev_name.text

    @property
    def vulnerability_plugin_name(self):
        """Returns name of the plugin."""
        return self.plugin_name.text

    @property
    def vulnerability_plugin_reason(self):
        """Returns plugin family of the vulnerability plugin."""
        return self.plugin_reason.text

    @property
    def vulnerability_vpr_score(self):
        """Returns vulnerabilities count."""
        return self.vpr_score.text


class ThreatLevelVulnerabilityList(ObjectList):
    """Returns a list containing scan result vulnerabilities inside Threat Level Tab"""
    configure_button = None
    results = Finds(ThreatLevelVulnerabilityRecord, by=By.CSS_SELECTOR, value='tr.prioritization ')
    generics_map = {GenericTableRow: ThreatLevelVulnerabilityRecord}
    back_to_vulnerabilities = Find(Link, by=By.CSS_SELECTOR, value='.glyphicons.back')
    vulnerability_details = Finds(by=By.CSS_SELECTOR, value='.plugin-details-content section div')
    plugin_details_content_label = Finds(by=By.CSS_SELECTOR, value='.plugin-details-content section h5')
    plugin_id_from_content = Find(by=By.XPATH, value='.//h5[contains(text(), "Plugin Information")]//following::div[1]')

    def __init__(self):
        super().__init__()

    def get_total_rows(self) -> int:
        """
        Return total rows summing up for all the pages
        :return: Total count of rows
        :rtype: int
        """
        LoadingCircle(WAIT_NORMAL)
        return len(self.object_table.table_wrapper.get_table_contents())

    def get_plugin_names(self) -> list:
        """
        Returns a list of  existing Plugins Names
        :return: list of names of all listed plugins
        :rtype: list
        """
        return [name.vulnerability_plugin_name for name in self.rows]

    def get_plugin_reasons(self) -> list:
        """
        Returns a list of  existing Plugins Reasons
        :return: list of names of all listed plugins Reasons
        :rtype: list
        """
        return [name.vulnerability_plugin_reason for name in self.rows]

    def get_plugin_vpr_score(self) -> list:
        """
        Returns a list of  existing Plugins' vpr score
        :return: list of names of all listed plugins' vpr score
        :rtype: list
        """
        return [name.vulnerability_vpr_score for name in self.rows]

    def click_on_vulnerability(self, vulnerability_name: str) -> None:
        """
        Click on vulnerability of specified name.

        :param str vulnerability_name: vulnerability name.
        :return: None
        """
        for row in self.rows:
            if row.plugin_name.text == vulnerability_name:
                self.move_to_element(row)
                row.click()
                break

    def get_plugin_vpr_severity(self) -> list:
        """
        Returns VPR severity value of given vulnerability name

        :return: list of severity value of all listed plugins
        :rtype: list
        """
        return [row.severity_name for row in self.rows]


class ScanHostRecord(GenericTableRow):
    """Defines the key names for host Records returned by ScansHostList"""
    checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.checkbox')
    host = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    vulnerabilities = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    vul_percentage = Find(by=By.CSS_SELECTOR, value='td:nth-child(7)')
    auth = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    delete_icon = Find(by=By.CSS_SELECTOR, value='td .glyphicons.remove')

    @property
    def host_name(self):
        """Returns name of the host."""
        return self.host.text

    @property
    def auth_check(self):
        """Returns result of the auth."""
        return self.auth.text

    @property
    def host_vulnerabilities(self):
        """Returns vulnerabilities against a host for a specific run of the scan."""
        return self.vulnerabilities.get_attribute('data-order')


class ScansHostList(ObjectList):
    """Returns a list containing scan host displayed"""
    configure_button = None
    generics_map = {GenericTableRow: ScanHostRecord}
    results = Finds(ScanHostRecord, by=By.CSS_SELECTOR, value='tr.host ')

    def __init__(self):
        super().__init__()

    def get_total_rows(self) -> int:
        """
        Return total rows summing up for all the pages
        :return: Total count of listed hosts
        :rtype: int
        """
        return len(self.object_table.table_wrapper.get_table_contents())

    def get_severity_host_list(self) -> dict:
        """
        Returns dictionary with host as key and severity as value
        :return: dictionary of (host: severity) pair
        :rtype: dict
        """
        sev_host_dict = {}
        for row in self.results:
            severity_value = row.element.find_element(By.TAG_NAME, 'li').get_attribute('title')
            sev_host_dict.update({row.host.text: severity_value})
        return sev_host_dict

    def get_host_names(self) -> list:
        """
        Returns a list of  existing Host Names
        :return: list of names of listed hosts
        :rtype: list
        """
        return [host_name.host.text for host_name in self.rows]

    def get_hosts_percentage(self) -> dict:
        """
        Returns dictionary with host as key and percentage update as value
        :return: dictionary of (host: scan_progress_percentage) pair
        :rtype: dict
        """
        host_vul_percentage = {}
        for row in self.rows:
            host_vul_percentage.update({row.host.text: int(row.vul_percentage.get_attribute('data-order'))})
        return host_vul_percentage

    def select_hosts(self, hosts_list: list) -> None:
        """
        Select host(s) listed in scan_host_list under hosts tab in scan_result page
        :param list hosts_list: host(s) to be selected.
        :return: None
        """
        for row in self.rows:
            if row.host_name in hosts_list:
                row.checkbox.check()
                LoadingCircle(WAIT_SHORT)

    def click_on_host(self, host_name: str) -> None:
        """
        Navigated to host details page by clicking on host
        :param str host_name: host name
        :return: None
        """
        for row in self.rows:
            if row.host.text == host_name:
                row.click()
                break
        else:
            log.warning("Host: '%s' not found in the hosts list", host_name)

    def delete_host(self, host_name: str) -> None:
        """
        Delete a host from host_list by clicking on 'x' icon.
        :param str host_name: host name to be deleted
        :return None
        """
        for row in self.rows:
            if row.host.text == host_name:
                row.delete_icon.click()
                ActionCloseModal().accept_action()
                break
        else:
            log.warning("Delete Failed: '%s' not found in the hosts list", host_name)


class ScanASDRecord(GenericTableRow):
    """Defines the key names for host Records returned by ScansHostList"""
    checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.checkbox')
    hosts = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    host_ips = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    ports = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    record_types = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    target_hostnames = Find(by=By.CSS_SELECTOR, value='td:nth-child(6)')
    delete_icon = Find(by=By.CSS_SELECTOR, value='td .glyphicons.remove')

    @property
    def host_name(self):
        """Returns name of the host."""
        return self.hosts.text

    @property
    def host_ip(self):
        """Returns name of the host_ip."""
        return self.host_ips.text

    @property
    def port(self):
        """Returns value for ports"""
        return self.ports.text

    @property
    def record_type(self):
        """Returns value for record_type"""
        return self.record_types.text

    @property
    def target_hostname(self):
        """Returns value for target_hostname"""
        return self.target_hostnames.text


class ScansASDHostsList(ObjectList):
    """Returns a list containing scan ASD host displayed"""
    configure_button = None
    generics_map = {GenericTableRow: ScanASDRecord}
    results = Finds(ScanASDRecord, by=By.CSS_SELECTOR, value='tr.host ')
    filter_link = Find(Clickable, by=By.CSS_SELECTOR, value='#advanced-search')

    def __init__(self):
        super().__init__()
        self.required_elements = ['filter_link']

    def get_all(self):
        self.loaded()
        keys = [item.text for item in self.columns]
        keys = keys[1:-1]
        all_data = list()
        rows = self.rows
        for row in rows:
            named_row = dict()
            data = [cell.text for cell in row.cells]
            data = data[1:-1]

            for num in range(0, len(data)):
                named_row[keys[num]] = data[num]

            all_data.append(named_row)

        return all_data

    def validate_value_in_column(self, item: str, column: str) -> bool:
        """
        Checks if the item is found in the specified column
        :param str item: item to be found in column data
        :param str column: column to search in
        :return: None
        """
        self.loaded()
        if column.lower() == Nessus.Filter.FilterKeys.HOSTNAME.lower():
            columns = self.get_host_names()
        elif column.lower() == Nessus.Filter.FilterKeys.IP_ADDRESS.lower():
            columns = self.get_host_ip()
        elif column.lower() == Nessus.Filter.FilterKeys.PORT.lower():
            columns = self.get_ports()
        elif column.lower() == Nessus.Filter.FilterKeys.RECORD_TYPE.lower():
            columns = self.get_record_type()
        elif column.lower() == Nessus.Filter.FilterKeys.TARGET_HOSTNAME.lower():
            columns = self.get_target_hostname()
        else:
            return False

        item_found = False
        item = item.lower().strip()
        for col in columns:
            if item in str(col).lower().strip():
                item_found = True
                break

        return item_found

    def get_host_names(self) -> list:
        """
        Returns a list of  existing Hostnames
        :return: list of names of listed hosts
        :rtype: list
        """
        return [item.host_name for item in self.rows]

    def get_host_ip(self) -> list:
        """
        Returns a list of existing host_ips
        :return: list of names of listed host_ip
        :rtype: list
        """
        return [item.host_ip for item in self.rows]

    def get_ports(self) -> list:
        """
        Returns a list of existing Ports
        :return: list of names of listed ports
        :rtype: list
        """
        return [item.port for item in self.rows]

    def get_record_type(self) -> list:
        """
        Returns a list of existing record_types
        :return: list of names of listed record_type
        :rtype: list
        """
        return [item.record_type for item in self.rows]

    def get_target_hostname(self) -> list:
        """
        Returns a list of existing target_hostnames
        :return: list of names of listed target_hostname
        :rtype: list
        """
        return [item.target_hostname for item in self.rows]

    def select_hosts(self, hosts_list: list) -> None:
        """
        Select host(s) listed in scan_host_list under hosts tab in scan_result page
        :param list hosts_list: host(s) to be selected.
        :return: None
        """
        for row in self.rows:
            if row.host_name in hosts_list:
                row.checkbox.check()
                LoadingCircle(WAIT_SHORT)

    def click_on_host(self, host_name: str) -> None:
        """
        Navigated to host details page by clicking on host
        :param str host_name: host name
        :return: None
        """
        for row in self.rows:
            if row.host.text == host_name:
                row.click()
                break
        else:
            log.warning("Host: '%s' not found in the hosts list", host_name)

    def delete_host(self, host_name: str) -> None:
        """
        Delete a host from host_list by clicking on 'x' icon.
        :param str host_name: host name to be deleted
        :return None
        """
        for row in self.rows:
            if row.host.text == host_name:
                row.delete_icon.click()
                ActionCloseModal().accept_action()
                break
        else:
            log.warning("Delete Failed: '%s' not found in the hosts list", host_name)


class HDScanHostsRecord(GenericTableRow):
    """Defines the key names for host Records returned by HDScanHostsList"""
    host_ip = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    dns = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    os = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    ports = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')
    delete_icon = Find(by=By.CSS_SELECTOR, value='td .glyphicons.remove')

    @property
    def host_name(self):
        """Returns value for host name"""
        return self.host_ip.text

    @property
    def dns_name(self):
        """Returns value for DNS name"""
        return self.dns.text

    @property
    def os_name(self):
        """Returns value for OS name"""
        return self.os.text

    @property
    def port(self):
        """Returns value for ports"""
        return self.ports.text


class HDScanHostsList(ObjectList):
    """Returns a list containing scan host displayed"""
    configure_button = None
    generics_map = {GenericTableRow: HDScanHostsRecord}
    results = Finds(HDScanHostsRecord, by=By.CSS_SELECTOR, value='tr.host')

    def get_all_hosts(self) -> list:
        """
        Returns list of hosts in Host Discovery Table
        :return: No of hosts
        :rtype: list
        """
        return [row.host_name for row in self.rows]

    def delete_host_from_table(self, host_name: str) -> None:
        """
        Delete a host from host_list by clicking on 'x' icon.
        :param str host_name: host name to be deleted
        :return None
        """
        for row in self.rows:
            if row.host_name == host_name:
                row.delete_icon.click()
                action_modal = ActionCloseModal()
                action_modal.accept_action()
                action_modal.wait_for_modal_closed()
                break
        else:
            log.warning("Delete Failed: '%s' not found in the hosts list", host_name)


class HostDetailsPage(ScanViewPage):
    """age Object for Scan Hosts details page"""
    back_to_hosts = Find(by=By.CSS_SELECTOR, value='.title-box a')
    switch_host = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='div[data-name="Switch Host"] select')
    host_details_file = Find(Clickable, by=By.CSS_SELECTOR, value='#download-kb')
    delete_icon = Find(Clickable, by=By.CSS_SELECTOR, value='#host-details-delete')

    def delete_host(self) -> None:
        """
        Delete a host from its details page.
        :return: None
        """
        self.delete_icon.click()
        ActionCloseModal().accept_action()


class ModifyVulnerability(ActionCloseModal, ScanVulnerabilities):
    """Page Object for modifying Vulnerability"""
    severity = Find(Select2Dropdown, by=By.CSS_SELECTOR, value=".severity")
    host = Find(TextField, by=By.CSS_SELECTOR, value='.plugin-host')
    plugin_rule_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div .plugin-rule-checkbox')
    expiration_date = Find(Clickable, by=By.CSS_SELECTOR, value='.plugin-expiration.hasDatepicker')

    def modify_vulnerability(self, vulnerabilities_list: list, severity: str, host: str = None,
                             select_all: bool = False,
                             apply_on_future_scan: bool = False, expiration_date: datetime.date = None) -> None:
        """
        Modify vulnerability(s) according to the parameter
        :param list vulnerabilities_list: vulnerability(s) to be modified
        :param str severity: severity level to be modify
        :param str host: If specified, then vulnerability(s) will only modified for that host.
        :param bool select_all: If true then select_all checkbox will checked
        :param bool apply_on_future_scan: Checked, if needs to apply the same in future scan.
        :param datetime.date expiration_date: rule expiration date
        :return: None
        """
        if len(vulnerabilities_list) == 1:
            VulnerabilityList().click_modify_vulnerability_for_plugin(plugin_name=vulnerabilities_list[0])
        else:
            if select_all:
                self.select_all_checkbox.check()
                if self.total_records_count > 50:
                    self.select_all_records.click()
                    LoadingCircle(WAIT_SHORT)
            else:
                VulnerabilityList().select_vulnerabilities(vulnerabilities_list=vulnerabilities_list)

            LoadingCircle(WAIT_NORMAL)
            self.modify_button.click()

        self.severity.select_by_visible_text(severity)
        if host:
            self.host.value = host
        if apply_on_future_scan:
            self.plugin_rule_checkbox.check()
            self.expiration_date.click()
            from nessus.helpers.date_selector import select_date_in_datepicker
            select_date_in_datepicker(page_class_instance=self, input_date=expiration_date)

        LoadingCircle(WAIT_SHORT)
        self.accept_action()


class SnoozeVulnerability(ScanVulnerabilities, ActionCloseModal):
    """Page Object for snoozing vulnerability"""
    snooze_until = Find(DatePicker, by=By.CSS_SELECTOR, value='input[class*="Datepicker"]')
    current_date = Find(by=By.CSS_SELECTOR, value='.ui-datepicker-days-cell-over')
    snooze_pop_up = Find(Clickable, by=By.CSS_SELECTOR, value='#snooze-popup-menu')
    settings = Find(Clickable, by=By.CSS_SELECTOR, value='th .table-settings')
    show_hide_snoozed = Find(Clickable, by=By.CSS_SELECTOR, value='ul[id*="settings"] li[data-name="snoozed"]')
    wake_confirmation_pop_up = Find(by=By.CSS_SELECTOR, value='.modal')
    wake_confirmation_title = Find(by=By.CSS_SELECTOR, value='.modal-title')
    wake_confirmation_message = Find(by=By.CSS_SELECTOR, value='.modal-text')

    @contextmanager
    def snooze_vulnerabilities(self, number_of_days: str, plugin_list: list = [], select_all: bool = False,
                               **kwargs) -> None:
        """
        Method to snooze vulnerabilities
        :param str number_of_days: Number of days to set the snoozing period
        :param list plugin_list: List of plugins for which we want to snooze
        :param bool select_all: True or False for selecting all plugins or not
        :return: None
        """
        custom_date = kwargs.get('custom_date')
        vulnerability_list = VulnerabilityList()

        try:
            if len(plugin_list) == 1:
                vulnerability_list.click_snooze_or_wake_icon_for_plugin(plugin_name=plugin_list[0], snooze=True)
                sleep(sleep_time=WAIT_NORMAL, reason="Waiting for vulnerability to get snoozed")

                for day in self.snooze_pop_up.find_elements(By.TAG_NAME, 'li'):
                    if day.text == number_of_days:
                        day.click()
                        break
            else:
                if select_all:
                    self.select_all_checkbox.check()

                    if self.total_records_count > 50:
                        self.select_all_records.click()
                        LoadingCircle(WAIT_NORMAL)
                else:
                    vulnerability_list.select_vulnerabilities(vulnerabilities_list=plugin_list)

                self.snooze_button.click()
                sleep(sleep_time=WAIT_NORMAL, reason="UI element to be visible")

                for day in self.snooze_dropdown_options:
                    if day.text == number_of_days:
                        day.click()

            if number_of_days == 'Custom':
                self.snooze_until.click()
                from nessus.helpers.date_selector import select_date_in_datepicker
                select_date_in_datepicker(page_class_instance=self, input_date=custom_date)

            ActionCloseModal().accept_action()

            yield
        finally:
            try:
                self.move_to_element(self.host_tab)
                self.settings.click()

                if self.show_hide_snoozed.text == "Show Snoozed":
                    sleep(sleep_time=WAIT_NORMAL, reason='Waiting for page to load')
                    self.show_hide_snoozed.click()
                else:
                    self.settings.click()

                if len(plugin_list) == 1:
                    vulnerability_list.click_snooze_or_wake_icon_for_plugin(plugin_name=plugin_list[0], snooze=False)
                else:
                    if select_all:
                        self.select_all_checkbox.check()

                        if self.total_records_count > 50:
                            self.select_all_records.click()
                            LoadingCircle(WAIT_SHORT)
                    else:
                        vulnerability_list.select_vulnerabilities(vulnerabilities_list=plugin_list)

                    self.wake_button.click()

                ActionCloseModal().accept_action()
            except (WebDriverException, NoSuchElementException, TimeoutExpired) as exc:
                log.warning("Unable to wake the plugin. It may be in wake state through the test: %s" % str(exc))


class ScanRemediations(ScanViewPage):
    """Page Object for Scan remediations page."""
    remediation_count = Find(by=By.CSS_SELECTOR, value='#scans-show-remediations span')

    def get_data_count(self) -> int:
        """
        Returns remediations data count for a vulnerability type
        :return: remediation count of vulnerabilities
        :rtype: int
        """
        return int(self.remediation_count.text)


class ScanRemediationsRecord(GenericTableRow):
    """Defines the key names for ScanRemediations Records returned by ScanRemediationsList."""
    actions = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')
    vulnerabilities = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    hosts = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')

    @property
    def vulnerability_remediation(self):
        """Returns vulnerability remediation for a specific run of the scan."""
        return self.vulnerabilities.text

    @property
    def host_remediation(self):
        """Returns host remediation for a specific run of the scan."""
        return self.hosts.text


class ScanRemediationsList(ObjectList):
    """ Returns a list containing scan result remediations."""
    configure_button = None
    object_table = Find(GenericBaseTable, value="content")
    generics_map = {GenericTableRow: ScanRemediationsRecord}

    def __init__(self):
        super().__init__()

    def get_total_rows(self) -> int:
        """
        Return total rows summing up for all the pages
        :return: Total count of remediations listed.
        :rtype: int
        """
        return len(self.object_table.table_wrapper.get_table_contents())

    def get_all_remediations(self) -> list:
        """
        Returns list of remediations
        :return: list of remediations
        :rtype: list
        """
        return [row.text for row in self.rows]


class ScanHistoryRecord(GenericTableRow):
    """ Defines the key names for ScanHistory Records returned by ScanHistoryList."""
    checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.checkbox')
    disabled_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div.null-checkbox')
    start_time = Find(by=By.CSS_SELECTOR, value='td.history-start-time')
    start_time_epoch = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    end_time = Find(by=By.CSS_SELECTOR, value='td.history-end-time')
    end_time_epoch = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    status_icon = Find(by=By.CSS_SELECTOR, value='td.history-status-icon')
    status_text = Find(by=By.CSS_SELECTOR, value='td.history-status-text')
    remove = Find(by=By.CSS_SELECTOR, value='td .remove')

    @property
    def scan_start_time(self):
        """Returns start time for a specific run of the scan."""
        return self.start_time.text

    @property
    def scan_end_time(self):
        """Returns end time for a specific run of the scan."""
        return self.end_time.text

    @property
    def scan_start_epoch_time(self):
        """Returns epoch start time for a specific run of the scan."""
        return self.start_time_epoch.get_attribute('innerHTML')

    @property
    def scan_end_epoch_time(self):
        """Returns epoch end time for a specific run of the scan."""
        return self.end_time_epoch.get_attribute('innerHTML')

    @property
    def scan_status(self):
        """Returns scan status for a specific run of the scan."""
        return self.status_text.text


class ScanHistoryList(ObjectList):
    """ Returns a list containing scan histories."""
    configure_button = None
    generics_map = {GenericTableRow: ScanHistoryRecord}

    def __init__(self):
        super().__init__()

    def get_all_histories(self) -> list:
        """
        Returns a list of existing all histories record
        :return: list of all scan histories
        :rtype: list
        """
        return [(row.scan_start_time, row.scan_end_time) for row in self.rows]

    def delete_history(self, start_time: str, end_time: str) -> None:
        """
        delete a history row from history list
        :param start_time: scan start time
        :param end_time: scan end time
        :return: None
        """
        for row in self.rows:
            if (row.scan_start_time == start_time) and (row.scan_end_time == end_time):
                row.remove.click()
                ActionCloseModal().accept_action()
                break
        else:
            log.warning("Delete Failed: no row found with start-time: '%s' and end-time: '%s'", start_time, end_time)


class ScanExportPage(ObjectList):
    """ Page Object for Export Scan page """

    remediation = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.remediations>div')
    compliance = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.compliance>div')
    vulnerabilities = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vulnerabilities>div')
    vul_group_by_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='#select2-vul-container')
    vulnerabilities_group_by = Find(TextField, by=By.CSS_SELECTOR, value='.form-group.group-by-vulnerabilities>label')
    scan_information = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.scanInfo>div')
    host_information = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.hostInfo>div')
    synopsis = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.Synopsis>div')
    cvss_base_score = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="CVSS Base Score"]>div')
    description = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.Description>div')
    plugin_information = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.Plugin.Information>div')
    see_also = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.See.Also>div')
    plugin_output = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.Plugin.Output>div')
    solution = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.Solution>div')
    references = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.References>div')
    risk_factor = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.Risk.Factor>div')
    vulnerabilities_details = Find(by=By.CSS_SELECTOR, value='.custom-options-details div label')
    report_dropdown = Find(TextField, by=By.CSS_SELECTOR, value='#select2-choose-format-container')
    report_options = Finds(by=By.CSS_SELECTOR, value='#select2-choose-format-results li')
    report_dropdown_types = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select#choose-format')
    export_button = Find(Clickable, by=By.CSS_SELECTOR, value='#export-save')
    generate_report_button = Find(Clickable, by=By.CSS_SELECTOR, value='#report-save')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='.button.link.modal-close')
    stig_severity = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.STIG.Severity>div')
    cvss_temporal_score = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="CVSS Temporal Score"]>div')
    cvss_v3_temporal_score = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                  value='div[data-name="CVSS v3.0 Temporal Score"]>div')
    cvss_v3_base_score = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="CVSS v3.0 Base Score"]>div')
    exploitable_with = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.vuln-group.Exploitable.With>div')
    vulnerability_group_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='#vul')
    group_vuln_by_options = Finds(by=By.CSS_SELECTOR, value=".custom-options-host div.form-groups>div")
    vulnerabilities_details_options = Finds(by=By.CSS_SELECTOR, value=".custom-options-details div.form-groups>div")
    formatting_option_label = Find(by=By.CSS_SELECTOR, value='div[class*="vuln-details-spacing"] label')
    formatting_option_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.form-group.extra-options-group>div')
    formatting_option_text = Find(by=By.CSS_SELECTOR, value='.form-group.extra-options-group>span')
    save_as_default = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.save-as-default div')
    vulnerabilities_details_note_label = Find(by=By.CSS_SELECTOR, value='.vuln-details-note-label.small-note')
    export_csv_options = Finds(by=By.CSS_SELECTOR, value='.csv-columns-details div.form-group.csv-column')
    system_link = Find(Link, by=By.CSS_SELECTOR, value='span.link[data-function="reset"]')
    select_all_link = Find(Link, by=By.CSS_SELECTOR, value='span.link[data-function="select-all"]')
    clear_link = Find(Link, by=By.CSS_SELECTOR, value='span.link[data-function="clear"]')
    vulnerability_details_option_name = Finds(by=By.CSS_SELECTOR, value='.custom-options-details div.form-groups span')
    csv_columns_name = Finds(by=By.CSS_SELECTOR, value='.csv-columns-details div.csv-column span')
    hide_system_template_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                         value='div[data-domselect="hide_system_container"] div.checkbox')
    hide_system_template_label = Find(by=By.CSS_SELECTOR, value='div[data-domselect="hide_system_container"] span')
    system_template = Find(Select2Dropdown, by=By.ID, value="templates")
    report_template_names = Finds(by=By.CSS_SELECTOR, value='#templates .add-tip')
    template_description_div = Find(by=By.CSS_SELECTOR, value='div[class*="selected-template-description-container"]')
    template_description_label = Find(by=By.CSS_SELECTOR, value='div[class*="template-description"] h2')
    custom_template_header = Find(by=By.CSS_SELECTOR, value='#templates option[class*="template-custom-header"]')
    system_template_header = Find(by=By.CSS_SELECTOR, value='#templates option[class="template-list-header"]')
    report_template_description = Find(by=By.CSS_SELECTOR, value='div.selected-template-description')
    filter_applied_div = Find(by=By.CSS_SELECTOR, value='div[class*="report-filters-container"]')
    filter_applied_label = Find(by=By.CSS_SELECTOR, value='div[class*="report-filters-container"] label')
    default_filter_applied_value = Find(by=By.CSS_SELECTOR, value='div.report-filters-list')
    applied_filters_value_list = Finds(by=By.CSS_SELECTOR, value='div[class="report-filters-list"] option')

    def __init__(self):
        super().__init__()

    def get_text_from_custom_option_check_box(self, element: WebElement) -> list:
        """
        Return the list of name of custom option checkbox element

        :param WebElement element: UI element
        :return: list of check box option name
        :rtype: list
        """
        return [result_option.get_attribute("data-key") for result_option in element]

    def get_custom_options(self, option_name: str) -> WebElement:
        """
        Get UI Element for custom option

        :param str option_name: custom report option name
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value=".form-groups div[data-key='{}']".format(option_name), context=self)

    def get_custom_option_checkbox(self, option_name: str) -> WebElement:
        """
        Get UI Element for custom option checkbox

        :param str option_name: custom report option name
        :return: WebElement
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value=".form-groups div[data-key='{}'] div".format(option_name),
                    context=self)

    def get_name_of_export_option(self, element: WebElement, default: bool = False) -> list:
        """
        Return the list of name of export options

        :param WebElement element: UI element
        :param bool default: True for default export option name else False
        :return: list of export option name
        :rtype: list
        """
        if default:
            return [result_option.text for result_option in element if result_option.get_attribute('aria-checked') ==
                    'true']
        else:
            return [result_option.text for result_option in element]

    def get_select_all_and_clear_link_element(self, element_name: str) -> WebElement:
        """
        Get UI Element for Select all and Clear link of vulnerabilities details

        :param str element_name: link name Select All/Clear
        :return: WebElement
        """
        return Find(Link, by=By.CSS_SELECTOR, value="span.link[data-function='{}']".format(element_name), context=self)

    def get_select_all_and_clear_text_element(self, element_name: str) -> WebElement:
        """
        Get UI Element for Select all and Clear text of vulnerabilities details

        :param str element_name: link name Select All/Clear
        :return: WebElement
        """
        return Find(Link, by=By.CSS_SELECTOR, value="span.prefix[data-function='{}']".format(element_name),
                    context=self)

    def select_and_deselect_all_options(self, option_name: list, flag: bool) -> None:
        """
        Select all options if flag is True else deselect all options

        :param list option_name: list of options
        :param bool flag: True to select option as False
        :return: None
        """
        for option in option_name:
            try:
                if self.get_custom_options(option_name=option).is_displayed():
                    if flag:
                        self.get_custom_option_checkbox(option_name=option).check()
                    else:
                        self.get_custom_option_checkbox(option_name=option).uncheck()
            except NoSuchElementException:
                log.error("{} custom results option is not displayed.".format(option))

    def get_tool_tip_message(self, element: WebElement) -> str:
        """
        Return tooltip message from element

        :param WebElement element: UI element
        :return: tooltip message
        :rtype: str
        """
        return element.get_attribute('original-title')

    def get_tool_tip_element(self, option_name: str) -> WebElement:
        """
        Get UI Element for tooltip

        :param str option_name: CSV column option name
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value=".form-groups div[data-key='{}'] span".format(option_name), context=self)

    def get_system_templates_name(self) -> list:
        """
        Returns available system templates name

        return: system templates name
        :rtype: list
        """
        return [template['label'] for template in self.system_template.option_values]

    def select_report_template_from_generate_report_modal(self, template_name: str) -> None:
        """
        Select given template name from available system templates

        :param str template_name: template name that needs to be selected
        :return: None
        """
        for element in self.report_template_names:
            if element.text == template_name:
                element.click()
                break

    def get_applied_filter_value_from_report_launcher(self) -> list:
        """
        Returns list of applied filter value from "Generate Report" modal

        :return: filter result values
        :rtype: list
        """
        return [result_element.get_attribute('innerHTML') for result_element in self.applied_filters_value_list]


class ClusterScanSummaryRecord(GenericTableRow):
    """Defines the key names for host Records returned by ClusterScanSummaryList"""
    node = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')

    @property
    def node_name(self):
        """Returns name of the nodes."""
        return self.node.text

    def get_agent_count_element(self, scan_status: str, is_scan_completed: bool = True) -> Find:
        """
        Returns element to fetch agent count for given scan status.
        :param str scan_status: Status of the scan for which agent count needs to fetch
        :param bool is_scan_completed: True if scan is completed else False
        :return : Webelelment to fetch agent count for given status
        :rtype: Find
        """
        status_dict = {'not_started': 2, 'in_progress': 3, 'completed': 4, 'aborted': 5, 'failed': 6, 'total': 7}
        column_num = status_dict[scan_status] if not is_scan_completed or scan_status == "not_started" else \
            status_dict[scan_status] - 1

        return Find(by=By.CSS_SELECTOR, value='td:nth-child({})'.format(column_num), context=self)


class ClusterScanSummaryList(ObjectList):
    """Returns a list containing nodes along with agent scan status displayed."""
    configure_button = None
    generics_map = {GenericTableRow: ClusterScanSummaryRecord}

    def __init__(self):
        super().__init__()
        self.loaded()

    def get_node_names(self):
        """
        Return node names in Scan summary table.
        """
        return [row.node_name for row in self.rows]

    def get_total_count_element(self, scan_status: str, is_scan_completed: bool = True) -> Find:
        """
        Returns element to fetch total agent count for given scan status.
        :param str scan_status: Status of the scan for which agent count needs to fetch
        :param bool is_scan_completed: True if scan is completed else False
        :return : Webelelment to fetch total agent count for given status
        :rtype: Find
        """
        status_dict = {'not_started': 2, 'in_progress': 3, 'completed': 4, 'aborted': 5, 'failed': 6, 'total': 7}
        column_num = status_dict[scan_status] if not is_scan_completed or scan_status == "not_started" else \
            status_dict[scan_status] - 1

        return Find(by=By.CSS_SELECTOR, value='tfoot th:nth-child({})'.format(column_num), context=self)

    def get_agents_count_for_given_status(self, node_name: str, status: str, is_scan_completed: bool = True) -> int:
        """
        Returns agent count for given scan status and node.
        :param str node_name: Name of the node for which agent count to be fetched.
        :param str status: Status of the scan for which agent count needs to fetch
        :param bool is_scan_completed: True if scan is completed else False
        :return : Agent count for given status
        :rtype: int
        """
        for row in self.rows:
            if row.node_name == node_name:
                return int(row.get_agent_count_element(scan_status=status, is_scan_completed=is_scan_completed).text)
        else:
            log.warning("Unable to find node name in summary table.")

    def get_total_count_for_given_status(self, status: str, is_scan_completed: bool = True) -> int:
        """
        Returns agent count for given scan status.
        :param str status: Status of the scan for which agent count needs to fetch
        :param bool is_scan_completed: True if scan is completed else False
        :return : Total agent count for given status
        :rtype: int
        """
        return int(self.get_total_count_element(scan_status=status, is_scan_completed=is_scan_completed).text)

    def get_column_header_element(self, column_name: str) -> Find:
        """
        Return Web element for given column name header.
        :param str column_name: Name of column name
        :return : Web element for given column name header.
        :rtype: Find
        """
        return Find(by=By.CSS_SELECTOR, value="th[aria-label*='{}']".format(column_name), context=self)
