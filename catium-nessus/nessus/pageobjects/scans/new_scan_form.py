"""
page object model for new scan

:copyright: Tenable Network Security, 2017
:date: Aug 16, 2017
:last_modified: June 10, 2020
:author: @rdutta, @jamreliya, @mameta, @kpanchal
"""

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from waiting import wait

from catium.lib.cat_registry import cat_registry
from catium.lib.const.base_constants import TIME_TEN_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.upload_field import UploadField
from nessus.lib.const import Nessus
from nessus.pageobjects.basepage import NessusBasePage

log = create_logger()


@cat_registry.route('scans/reports/new')
class ScanTemplatePage(NessusBasePage):
    """Page Object for the Scan Template Page in Nessus."""
    scans = Find(by=By.CSS_SELECTOR, value='#content section:nth-child(1)')
    title_in_header = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    template_searchbox = Find(TextField, by=By.CSS_SELECTOR, value='input[aria-label="Search"]')
    scan_categories = Finds(by=By.CSS_SELECTOR, value="div.category-templates[aria-hidden='false']")
    vuln_template_section = Find(by=By.CSS_SELECTOR, value='div[data-category="Vulnerabilities"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['scans']

    def get_scan_templates(self, scan_type: str) -> WebElement:
        """
        Return dynamic element of listed scan templates specific to scan type tab
        :param str scan_type: scan type (scanner/agent/user defined: policies)
        :return: locator of the template of a specific tab
        :rtype: WebElement
        """
        return Finds(by=By.CSS_SELECTOR, value='a.library-item[data-view={}]'.format(scan_type),
                     context=self)

    def get_scans_for_given_category(self, scan_type: str, category_name: str):
        """
        Return dynamic element of listed scan templates for given category
        :param str scan_type: scan type (scanner/agent/user defined: policies)
        :param str category_name: scan template category name (discovery/vulnerabilities/compliance)
        :return: locator of the template for specific scan category
        :rtype: WebElement
        """
        return Finds(by=By.CSS_SELECTOR, value="a.library-item[data-view='{0}'][data-category={1}]".
                     format(scan_type, category_name), context=self)

    def get_all_scan_categories_names(self) -> list:
        """
        Return a list of scan categories on scan page
        :return: list of all scan template categories
        :rtype: list
        """
        try:
            return [template.get_attribute("data-category") for template in self.scan_categories]
        except NoSuchElementException:
            return []

    def get_scan_templates_list_for_given_category(self, category_name: str,
                                                   scan_type: str = Nessus.Scan.ScanTemplateTabs.SCANNER_TAB.
                                                   lower()) -> list:
        """
        Return a list of all scan templates for given template category.
        :param str category_name: scan template category name (discovery/vulnerabilities/compliance)
        :param str scan_type: scan type (scanner/agent/user defined: policies)
        :return: list of scan templates list for given category
        :rtype: list
        """
        try:
            scans_for_given_category = self.get_scans_for_given_category(scan_type=scan_type,
                                                                         category_name=category_name)
            return [template.find_element(By.TAG_NAME, 'h5').text for template in scans_for_given_category if
                    template.get_attribute('aria-hidden') == 'false']

        except NoSuchElementException:
            return []

    @property
    def get_page_heading(self):
        """Return page title from header of your current nessus page."""
        return self.title_in_header.text.split('\n')[0]

    def get_all_scan_templates(self, scan_type: str) -> list:
        """
        Return a list of all scan templates.
        :param str scan_type: scan type (scanner/agent/user defined: policies)
        :return: list of all scan templates
        :rtype: list
        """
        try:
            return [template.find_element(By.TAG_NAME, 'h5').text
                    for template in self.get_scan_templates(scan_type=scan_type) if
                    template.get_attribute('aria-hidden') == 'false']
        except NoSuchElementException:
            return []

    def click_by_scan(self, scan_text: str) -> None:
        """
        Clicks a scan provided on the scan page.
        :param str scan_text: Text for the link to click.
        :return: None
        """
        # if a loading circle is present wait for it to clear
        wait(lambda: len(self.scans.find_elements(By.TAG_NAME, 'a')), timeout_seconds=TIME_TEN_SECONDS,
             waiting_for='Scan templates to load properly')
        scans_title = self.scans.find_elements(By.TAG_NAME, 'a')

        for scan in scans_title:
            if scan.find_element(By.TAG_NAME, 'h5').text == scan_text:
                scan.click()
                break
        else:
            raise NoSuchElementException("Element with the link text " + scan_text + " not found.")

    def get_elements_of_templates_with_banner(self, scan_type: str) -> Finds:
        """
        Return dynamic element of listed scan templates with banner specific to scan type tab

        :param str scan_type: scan type (scanner/agent/user defined: policies)
        :return: locator of the template of a specific tab
        :rtype: WebElement
        """
        return Finds(by=By.CSS_SELECTOR, value='a.library-item[data-view="{}"] span.banner ~ h5.title'.format(
            scan_type), context=self)

    def get_banner_labeled_scan_templates_name(self, scan_type: str) -> list:
        """
        Return a list of all scan templates.

        :param str scan_type: scan type (scanner/agent/user defined: policies)
        :return: list of all scan templates
        :rtype: list
        """
        try:
            return [template.text for template in self.get_elements_of_templates_with_banner(scan_type=scan_type)]
        except NoSuchElementException:
            return []


@cat_registry.route('scans/new')
class NewScanForm(NessusBasePage):
    """
    Page Object for New Scan Creation Page in Nessus.

    .. note:: This Page Object doesn't reroute to a URL since the actual URL
        contains an unique ID, which is unknown upfront. The best way
        to call this object is simply instantiating it after clicking
        the 'New Scan' button.
    """
    title_in_header = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    back_link = Find(Clickable, by=By.CSS_SELECTOR, value='.title-box a')

    settings_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="settings"]')
    plugins_tab = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="plugins"]')
    name_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="name"]')
    description_textarea = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-input-id="description"]')
    domain_textarea = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="domain_discovery_domains"]')
    discovery_option = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Discovery"] span')
    scope_option = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Scope"] span')
    targets_textarea = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-input-id="text_targets"]')
    select_folder = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-type="select"]'
                                                                    '[data-name="Folder"]')
    select_dashboard = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="Show Dashboard"]')
    select_agent_group = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Agent Groups"]')
    select_scan_window = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Scan Window"]')
    upload_targets = Find(by=By.CSS_SELECTOR, value='input[data-name="Upload Targets"]')
    scanner_field = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-input-id="scanner_id"]')
    save_button = Find(by=By.CSS_SELECTOR, value='[data-action="save"]')
    save_action_dropdown = Find(Clickable, by=By.CSS_SELECTOR, value='.button.secondary.fontawesome.down')
    launch_option = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-action="launch"]')
    cancel_button = Find(by=By.CSS_SELECTOR, value='a.editor-cancel')
    name_required_badge = Find(by=By.CSS_SELECTOR, value='.required-badge.entry')
    group_required_badge = Find(by=By.CSS_SELECTOR, value='.required-badge.multi_select.multiple')
    custom_scan_window = Find(by=By.CSS_SELECTOR, value='.glyphicons.edit.add-tip')
    scan_window_textfield = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="scan_time_window"]')
    scan_window_description = Find(by=By.CSS_SELECTOR, value='[data-name="Scan Window Description"]')
    launch_button = Find(by=By.CSS_SELECTOR, value='.glyphicons.launch')
    schedule_confirmation_button = Find(by=By.CSS_SELECTOR, value='.modal .modal-action')
    basic_settings_options = Finds(by=By.CSS_SELECTOR, value='li[data-type="section-menu"] ul li')
    add_file_link = Find(Link, by=By.CSS_SELECTOR, value='a[data-name="Upload Targets"]')
    was_target = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="was_target"]')
    was_file_exclusions_textarea = Find(
        TextField, by=By.CSS_SELECTOR, value='textarea[data-input-id="was[scope]exclude_file_extensions"]'
    )
    was_urls_textarea = Find(
        TextField, by=By.CSS_SELECTOR, value='textarea[data-input-id="was[scope]urls"]'
    )
    was_path_exclusions_textarea = Find(
        TextField, by=By.CSS_SELECTOR, value='textarea[data-input-id="was[scope]exclude_path_patterns"]'
    )

    # UI elements for available tabs
    credentials = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="credentials"]')
    compliance = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="compliance"]')
    scap = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="scap"]')
    dynamic_plugins = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="dynamic-plugins"]')
    plugin = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="plugins"]')
    plugin_eye_icon = Find(by=By.CSS_SELECTOR, value='.glyphicons.enabled.read-only.add-tip')
    plugin_eye_icon_tip_msg = Find(by=By.CSS_SELECTOR, value='.tipsy .tipsy-inner')

    def __init__(self):
        super().__init__()
        self.required_elements = ['name_field', 'cancel_button']

    @property
    def page_heading(self):
        """Return page title from header of your current nessus page."""
        return self.title_in_header.text.split('\n')[0]

    def fill_new_asd_scan_detail(self, scan_name: str = None, domain_name: str = None, description: str = None, folder_name: str = None) -> None:
        """
        Fill up the scan form with provided scan configuration details
        :param str scan_name: scan name
        :param str domain_name: domain name
        :param str description: description field (optional)
        :param str folder_name: scan will listed in this folder
        :return: None
        """

        if scan_name:
            self.name_field.value = scan_name
        if description:
            self.description_textarea.value = description
        if folder_name:
            self.select_folder.select_by_visible_text(folder_name)
        if domain_name:
            self.discovery_option.click()
            self.domain_textarea.value = domain_name

    def fill_new_scan_detail(self, scan_name: str = None, host_ip: str = None, description: str = None,
                             **kwargs) -> None:
        """
        Fill up the scan form with provided scan configuration details
        :param str scan_name: scan name
        :param str host_ip:  host ip
        :param str description: description field (optional)
        :param kwargs:
            str folder: scan will listed in this folder
            str dashboard: dashboard status
            str scanner: select remote scanner from available scanner list
            str agent_group: select agent group for agent scan
            str scan_window: set a window for agent scan
            str target_file: absolute path of target file
        :return: None
        """
        folder_name = kwargs.get('folder')
        dashboard = kwargs.get('dashboard')
        scanner = kwargs.get('scanner')
        agent_group = kwargs.get('agent_group')
        scan_window = kwargs.get('scan_window')
        target_file = kwargs.get('target_file')
        domain_name = kwargs.get('domain_name')

        if domain_name:
            self.domain_textarea.value = domain_name
        if scan_name:
            self.name_field.value = scan_name
        if description:
            self.description_textarea.value = description
        if folder_name:
            self.select_folder.select_by_visible_text(folder_name)
        if dashboard:
            self.select_dashboard.set_checked(dashboard)
        if scanner:
            self.scanner_field.select_by_visible_text(scanner)
        if host_ip:
            self.targets_textarea.value = host_ip
            if target_file:
                UploadField(self.upload_targets).file = target_file
        if agent_group:
            self.select_agent_group.select_by_visible_text(agent_group)
            if scan_window:
                self.select_scan_window.select_by_visible_text(scan_window)

    def fill_new_was_scan_detail(self, scan_name: str = None, description: str = None, folder_name: str = None,
                                 target_url: str = None, **kwargs) -> None:
        """
               Fill up the WAS scan form with provided scan configuration details
               :param str scan_name: scan name
               :param str target_url: target url
               :param str description: description field (optional)
               :param str folder_name: scan will be listed in this folder
               :param kwargs:
                    str file_extension_exclusions: File Extensions to Exclude (optional)
                    str url_list: URLs to be included (optional)
                    str paths_exclusions: URL paths to be excluded (optional)
               :return: None
               """
        url_list = kwargs.get('url_list', "")
        path_exclusions = kwargs.get('path_exclusions', "")
        file_extension_exclusions = kwargs.get('file_extension_exclusions', "")

        if scan_name:
            self.name_field.value = scan_name
        if description:
            self.description_textarea.value = description
        if folder_name:
            self.select_folder.select_by_visible_text(folder_name)
        if target_url:
            self.was_target.value = target_url
        if url_list or path_exclusions or file_extension_exclusions:
            self.scope_option.click()
            self.was_urls_textarea.value = url_list
            self.was_path_exclusions_textarea.value = path_exclusions
            self.was_file_exclusions_textarea.value = file_extension_exclusions

    def get_agent_group_list(self) -> list:
        """
        Returns list of Agent group under dropdown
        :return: Types of Agent group under dropdown
        :rtype: list
        """
        return ['Shared\n' + agent_group['label'] for agent_group in self.select_agent_group.option_values]

    def get_folder_db_dropdown_value(self, drop_down_value) -> list:
        """
        Returns list of value under drop down of Folder and Dashboard
        :return: Folder / Dashboard selected from drop-down
        :rtype: list
        """
        return [element['label'] for element in drop_down_value.option_values]

    def get_custom_scan_tooltip(self) -> str:
        """
        Returns title of custom scan window icon
        :return: Tooltip text of Scan window icon when cursor move on icon
        :rtype: str
        """
        return self.custom_scan_window.get_attribute('original-title')


class ScanType(ScanTemplatePage):
    """Page Object for scan types"""
    scanner = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-view="scanner"]')
    agent = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-view="agent"]')
    was = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-view="was"]')
    user_defined_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-view="policies"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['scanner']

    def select_scan_type(self, type_of_scan: str) -> None:
        """
        select a typed scan tab
        :param str type_of_scan: name of type
        :return: None
        """
        if type_of_scan == Nessus.Scan.ScanTemplateTabs.USER_DEFINED_TAB:
            self.user_defined_tab.click()
        elif type_of_scan == Nessus.Scan.ScanTemplateTabs.AGENT_TAB:
            self.agent.click()
        elif type_of_scan == Nessus.Scan.ScanTemplateTabs.WAS_TAB:
            self.was.click()
        else:
            log.debug("We are already on scanner page.")
