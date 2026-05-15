"""
Nessus page classes for Setting tab in scan configuration
:copyright: Tenable Network Security, 2017
:date: Sept 04, 2017
:last_modified: May 12, 2024
:author: @rdutta, @smadan, @ntarwani, @kpanchal, @krpatel
"""
from datetime import datetime

from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webelement import WebElement

from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_SHORT, TIME_THREE_SECONDS
from catium.lib.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.date_picker import DatePicker
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.toggleswitch import ToggleSwitch
from nessus.helpers.date_selector import select_date_in_datepicker
from nessus.lib.const import API, Nessus
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


class ScanSettings(NewScanForm):
    """Page Object for Basic settings"""

    new_setting_list = Finds(by=By.CSS_SELECTOR, value='li[data-type="section-menu"]')
    exclusive_settings_list = Finds(by=By.CSS_SELECTOR, value='li[class="bold"] li')
    basic = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Basic"]')
    discovery = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Discovery"]')
    assessment = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Assessment"]')
    report = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Report"]')
    advanced = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Advanced"]')
    scan_type_label = Find(by=By.CSS_SELECTOR, value='div[data-parent="advanced"] label')
    scan_type_drop_down = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-input-id="advanced_mode"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['new_setting_list']

    def get_checkbox_element_for_value(self, check_box_value: str) -> WebElement:
        """
        Returns checkbox element for the particular value
        :param str check_box_value: Value for checkbox
        :rtype: WebElement
        """
        checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="{}"]'.format(check_box_value),
                        context=self)
        return checkbox

    def get_settings_element(self, setting_name: str) -> WebElement:
        """
        Returns web element for various settings
        :param str setting_name: setting name to find the element
        :return: Web element for various settings
        :rtype: WebElement
        """
        return Find(Clickable, by=By.CSS_SELECTOR, value='li[data-type="section-menu"][data-title="{}"] span i'.format(
            setting_name.capitalize()), context=self)

    def click_by_link_text(self, setting_value: str) -> None:
        """
        Clicks a link in the settings if the link is there.
        :param str setting_value: Text for the link in the settings to click.
        :return: None
        """
        log.debug('Searching for ' + setting_value + " in settings.")
        for link in self.new_setting_list:
            log.debug("Comparing " + link.get_attribute('data-title') + " to " + setting_value)
            if link.get_attribute('data-title').upper() == setting_value:
                link.find_element(By.CSS_SELECTOR, 'span').click()
                break
        else:
            raise NoSuchElementException("Element with the link text " + setting_value + " not found.")

    def click_link_inside_link(self, setting_value: str, link_text: str) -> None:
        """
        Clicks a link inside the setting if the link is there.

        :param str setting_value: Text for the setting to click.
        :param str link_text: Text for the link inside the settings to click.
        :return: None
        """
        log.debug('Searching for ' + link_text + " in settings.")
        for link in self.new_setting_list:
            log.debug("Comparing " + link.text + " to " + link_text)
            if link.get_attribute('data-title').upper() == setting_value:
                link.find_element(By.CSS_SELECTOR, 'span').click()
                for setting in self.exclusive_settings_list:
                    if setting.get_attribute('data-title') == link_text:
                        setting.click()
                break
        else:
            raise NoSuchElementException("Element with the setting " + setting_value +
                                         " and link text " + link_text + " not found.")


class BasicSetting(ScanSettings):
    """Page object for basic settings"""

    applied_filter_count = 0
    searchbox_in_add_user_group_for_permission = Find(TextField, by=By.CSS_SELECTOR,
                                                      value='.editor-input.share-add-user.autocomplete.'
                                                            'nofocus.ui-autocomplete-input')
    general = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="General"]')
    schedule = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Schedule"]')
    notifications = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Notifications"]')
    permissions = Find(Clickable, by=By.CSS_SELECTOR, value='li[data-title="Permissions"]')

    enable_schedule = Find(ToggleSwitch, by=By.CSS_SELECTOR, value='.toggle-switch')
    email_recipient = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-input-id="emails"]')
    frequency = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Frequency"]')
    select_date = Find(DatePicker, by=By.CSS_SELECTOR, value='#ui-datepicker-div')
    current_date = Find(by=By.CSS_SELECTOR, value='.ui-datepicker-today')
    starts_datepicker_field = Find(Clickable, by=By.CSS_SELECTOR, value='.hasDatepicker')
    start_time_dropdown_field = Find(Select2Dropdown, by=By.XPATH,
                                     value='//label[text()="Starts"]/following-sibling::select')
    time_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Starts Times"]')
    search_input = Find(TextField, by=By.CSS_SELECTOR, value='.select2-search__field')
    timezone = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[ data-name="Timezone"]')
    summary = Find(by=By.CSS_SELECTOR, value='div[data-name="Summary"] span')
    attach_report_toggle = Find(ToggleSwitch, by=By.CSS_SELECTOR, value='div[data-name="Attach Report"]')
    add_filter_link = Find(Link, by=By.ID, value='email-add-filter')
    match_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Result Filters Match"]')
    filter = Find(by=By.CSS_SELECTOR, value='div[data-name="Filter"]')
    report_type = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Report Type"]')
    select_user_permission = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[aria-label="Share Permissions"]')

    def __init__(self):
        super().__init__()

    def set_email_recipient_for_notification(self, recipient_email: str) -> None:
        """
        Pass Email of recipient under SETTINGS -> BASIC -> Notifications
        :param str recipient_email: Email Recipient
        :return: None
        """
        self.click_link_inside_link(setting_value="BASIC", link_text="Notifications")
        LoadingCircle(WAIT_SHORT)
        self.email_recipient.send_keys(recipient_email)

    def get_email_recipient_for_notification(self) -> str:
        """
        Return Email recipient for Notification
        :return: Email recipient from Notifications under BASIC sub menu
        :rtype: str
        """
        self.click_link_inside_link(setting_value="BASIC", link_text="Notifications")
        LoadingCircle(WAIT_SHORT)
        return self.email_recipient.get_attribute('value')

    def get_user_specific_permission_dropdown_for_scans(self, user_name: str) -> WebElement:
        """
        returns dynamic element of permission dropdown according to user
        :param str user_name: user name
        :return: WebElement
        """
        return Find(Select2Dropdown, by=By.CSS_SELECTOR,
                    value='li[data-name="{}"] div select[class="sharing-permissions-select select2-hidden-accessible"]'
                    .format(user_name), context=self)

    def select_user_from_dropdown(self, user_name: str) -> WebElement:
        """
        returns dynamic element of user from available list of user
        :param str user_name: user_name to select
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='.ui-menu-item[data-label="{}"]'.format(user_name), context=self)

    def get_filter_dropdown_element(self, index_value: int, element_type: str) -> WebElement:
        """
        Get UI element for filter condition's dropdown depending on the element type and index of filter
        :param int index_value: index of filter
        :param str element_type: type of element
        :return: dropdown element of filter window
        :rtype: WebElement
        """
        if element_type == Nessus.Filter.OPERATOR:
            element_type = 'Operators'
        elif element_type == Nessus.Filter.VALUE:
            element_type = 'Control Input'

        return Find(Select2Dropdown, by=By.CSS_SELECTOR, value='div[data-index="{}"] select[data-name="Result Filter '
                                                               '{}"]'.format(index_value, element_type.title()),
                    context=self)

    def get_filter_value_text_element(self, index_value: int) -> WebElement:
        """
        Get UI element of filter value textfield
        :param int index_value: index of filter
        :return: text input element of filter window
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='div[data-index="{}"] div[data-name="Result Filter Control"] '
                                                         'input'.format(index_value), context=self)

    def get_filter_value_datepicker(self, index_value: int) -> WebElement:
        """
        Get UI element of filter value datepicker

        :param int index_value: index of filter
        :return: date input element of filter window
        :rtype: WebElement
        """
        return Find(Clickable, by=By.CSS_SELECTOR, value='div[data-index="{}"] div[data-name="Result Filter Control"] '
                                                         '.date-picker'.format(index_value), context=self)

    def set_user_permissions_for_scans(self, permission: str, user_name: str) -> None:
        """
        Set the permission for default/user/group(s)
        :param str permission: permission to set
        :param str user_name: user for whom you want to set up the permission
        :return: None
        """
        LoadingCircle(WAIT_SHORT)
        self.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                    link_text=Nessus.Scan.SettingsBasicSubMenu.PERMISSIONS)
        if user_name != API.User.Users.DEFAULT_USER:
            self.searchbox_in_add_user_group_for_permission.send_keys(user_name)
            self.select_user_from_dropdown(user_name=user_name).click()

        self.get_user_specific_permission_dropdown_for_scans(user_name=user_name).select_by_visible_text(permission)

    def get_all_option_values(self, dropdown_element: WebElement) -> list:
        """
        Returns all option values for the particular dropdown
        :param WebElement dropdown_element: dropdown element
        """
        return [options['label'] for options in dropdown_element.option_values]

    def schedule_scan(self, schedule_date: datetime.date = None, schedule_time: datetime.time = None,
                      schedule_frequency: str = None, schedule_timezone: str = None) -> str:
        """
        Schedule a scan with specified parameters
        :param datetime.date schedule_date: date on which scan to be schedule
        :param datetime.time schedule_time: time on which scan to be schedule
        :param str schedule_frequency: frequency to launch the scheduled scan
        :param str schedule_timezone: timezone for scan
        :return: schedule summary
        :rtype: str
        """
        self.schedule.click()
        if not self.enable_schedule.is_selected():
            self.enable_schedule.toggle()

        if schedule_frequency:
            self.frequency.select_by_visible_text(schedule_frequency)

        if schedule_date:
            if isinstance(schedule_date, str):
                log.warning("date should be datetime.date object, not string.")
                schedule_date = datetime.strptime(schedule_date, "%Y-%m-%d").date()

            # Select date in date_picker
            self.starts_datepicker_field.click()
            select_date_in_datepicker(page_class_instance=self, input_date=schedule_date)

        if schedule_time:
            if isinstance(schedule_time, str):
                log.warning("time should be datetime.time object, not string.")
                schedule_time = datetime.strptime(schedule_time, "%H:%M").time()

            schedule_time = schedule_time.strftime('%H:%M')
            if schedule_date in self.time_dropdown.option_values:
                self.time_dropdown.select_by_visible_text(schedule_time)
            else:
                self.time_dropdown.click()
                self.search_input.send_keys(schedule_time)
                self.search_input.send_keys(Keys.ENTER)

        if schedule_timezone:
            self.timezone.click()
            self.search_input.send_keys(schedule_timezone)
            self.search_input.send_keys(Keys.ENTER)

        sleep(sleep_time=TIME_THREE_SECONDS, reason='waiting for scan schedule summary to be generated')
        return self.summary.text

    def set_filter_value(self, key: str, operator: str, value: str,
                         match_type: str = Nessus.Filter.FilterMatch.ALL) -> None:
        """
        Set particular filter value in notification of scan basic setting

        :param str key: Key value to set a filter
        :param str operator: Operator value to set a filter
        :param str value: Value for the filter.
        :param str match_type: Match type for conditions.
        :return: None
        """
        self.add_filter_link.click()
        self.applied_filter_count += 1
        index = 4 * (self.applied_filter_count - 1)

        self.match_dropdown.select_by_visible_text(match_type)

        if self.applied_filter_count > 1:
            self.add_filter_link.click()

        self.get_filter_dropdown_element(index_value=index, element_type=Nessus.Filter.KEY).select_by_visible_text(key)
        self.get_filter_dropdown_element(index_value=index,
                                         element_type=Nessus.Filter.OPERATOR).select_by_visible_text(operator)

        if key in Nessus.Filter.FilterKeys.VALUE_DROPDOWN:
            self.get_filter_dropdown_element(index_value=index,
                                             element_type=Nessus.Filter.VALUE).select_by_visible_text(value)
        elif key in Nessus.Filter.FilterKeys.VALUE_DATEPICKER:
            self.get_filter_value_datepicker(index_value=index).click()
            select_date_in_datepicker(page_class_instance=self, input_date=value)
        else:
            self.get_filter_value_text_element(index_value=index).clear()
            self.get_filter_value_text_element(index_value=index).send_keys(value)

    def set_report_type(self, report_format: str) -> None:
        """
        Select scan report format from report type drop-down

        :param str report_format: scan report format e.g. HTML / PDF / CSV
        :return: None
        """
        self.report_type.select_by_visible_text(report_format)

    def get_basic_setting_links_in_new_scan_form(self, setting_name: str, link_name: str) -> WebElement:
        """
        Returns dynamic element of Basic settings links under new scan form

        :param str setting_name: setting name like Basic, Discovery, Assessment, Report, etc.
        :param str link_name: link name under setting names
        :return: WebElement
        """
        return Find(Link, by=By.CSS_SELECTOR, value='li[data-title="{}"] > ul > li[data-title="{}"]'.format(
            setting_name, link_name), context=self)


class AdvancedSetting(ScanSettings):
    """Page object for advanced settings"""

    def get_performance_option_element(self, data_name: str) -> WebElement:
        """
        Returns checkbox element for the particular value
        :param str data_name: Value for checkbox

        """
        performance_option = Find(TextField, by=By.CSS_SELECTOR, value='div[data-name="performance"] '
                                                                       'input[data-name="{}"]'
                                  .format(data_name), context=self)

        return performance_option

    def set_performance_option(self, data_name: str, value: str) -> None:
        """
        Set Value for the provided performance option under Advanced Settings

        :param str data_name: data name of the performance option
        :param str value: Value to set for the option
        """

        self.get_performance_option_element(data_name).clear()
        self.get_performance_option_element(data_name).send_keys(value)

    def get_performance_option(self, data_name: str) -> str:
        """Returns Value of the provided performance option"""

        return self.get_performance_option_element(data_name).get_attribute('value')


class AssessmentSetting(ScanSettings):
    """Page object for assessment settings"""

    scan_web_app_switch = Find(by=By.CSS_SELECTOR, value='div[data-input-id="scan_webapps"]')
    malware_switch = Find(ToggleSwitch, by=By.CSS_SELECTOR, value='div[data-input-id="scan_malware"]')
    scan_file_system = Find(by=By.CSS_SELECTOR, value='div[data-name="Scan file system"]')
    anti_grace_period = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-input-id="av_grace_period"]')
    scan_type = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Settings Modes"]')
    override_normal_accuracy_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                             value='div[data-name="Override normal accuracy"]')
    radio_family_for_override_accuracy = Find(by=By.CSS_SELECTOR,
                                              value='div[class*="radio-buttons"]'
                                                    '[data-radio-family="Override normal accuracy"]')
    rid_brute_forcing_toggle = Find(by=By.CSS_SELECTOR,
                                    value='div[data-input-id="rid_brute_forcing"] .toggle')
    enable_generic_webapp_tests = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                       value='div[data-input-id="generic_webapp_tests"]')

    def get_uid_element_under_assessment(self, uid_type: str) -> WebElement:
        """
        Return element for UID under Assessment link
        :param str uid_type: Start UID or End UID
        :return: Element for either Start UID or End UID
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="{}"]'.format(uid_type), context=self)

    def get_scan_web_application_inputs_element(self, data_name) -> WebElement:
        """
        Returns settings element under scan web application

        :param str data_name: data name of the setting
        """
        scan_web_settings = Find(TextField, by=By.CSS_SELECTOR, value='div[ data-parent="Scan web applications"] '
                                                                      'input[data-name="{}"]'.format(data_name),
                                 context=self)
        return scan_web_settings

    def set_scan_web_application_inputs(self, data_name: str, value: str) -> None:
        """
        Set Value for the provided settings under AssessmentSetting

        :param str data_name: data name of the setting
        :param str value: Value to set for the setting
        """
        self.get_scan_web_application_inputs_element(data_name).clear()
        self.get_scan_web_application_inputs_element(data_name).send_keys(value)

    def get_element_of_application_test_settings(self, data_input_id: str) -> WebElement:
        """
        Returns Application Test settings element under scan Web Application Settings

        :param str data_input_id: data input id of web element
        :return: Element for Application Test settings
        :rtype: WebElement
        """
        dom_tag = "input" if data_input_id in ["url_for_rfi", "generic_webapp_tests_max_time"] else "div"

        return Find(by=By.CSS_SELECTOR, value='{}[data-input-id="{}"]'.format(dom_tag, data_input_id), context=self)


class DiscoverySetting(ScanSettings):
    """Page object for discovery settings"""

    # Host discovery related selectors
    ping_remote_switch = Find(ToggleSwitch, by=By.CSS_SELECTOR, value='div[data-input-id="ping_the_remote_host"]')
    max_retries = Find(by=By.CSS_SELECTOR, value='input[data-name="Maximum number of retries"]')
    destination_ports = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Destination ports"]')
    test_local_nessus_host_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                           value='div[data-input-id="test_local_nessus_host"]')

    # Port Scanning related selectors
    port_scan_range = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-name="Port Scan Range"]')


class AdvancedSettings(ScanSettings):
    """ Page Object for Advanced scan settings """

    packet_capture_toggle_button = Find(Clickable, by=By.CSS_SELECTOR, value='div[data-name="Packet Capture"]')
    target_to_capture_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="network_capture_hosts"]')
    target_to_capture_required_badge = Find(by=By.CSS_SELECTOR, value='input[data-input-id="network_capture_hosts"] ~ '
                                                                      'div[class*="required-badge"]')
    target_to_capture_hint_msg = Find(by=By.XPATH, value='.//input[@data-input-id="network_capture_hosts"]//'
                                                         'parent::div//div[@class="editor-inline-hint"]')
    ports_to_capture_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="network_capture_ports"]')
    ports_to_capture_hint_msg = Find(by=By.XPATH, value='.//input[@data-input-id="network_capture_ports"]//'
                                                        'parent::div//div[@class="editor-inline-hint"]')
