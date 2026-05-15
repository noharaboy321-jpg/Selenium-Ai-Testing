"""
Nessus policy related pages

Policy Settings related classes

:copyright: Tenable Network Security, 2017
:date: Sept 04, 2017
:last_modified: June 15, 2018
:author: @smadan, @kpanchal
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.log import create_logger
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.toggleswitch import ToggleSwitch
from nessus.controls.radio_group import RadioGroupNessus
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm

log = create_logger()


class PolicySettings(NewPolicyForm):
    """Page Object for Basic settings"""

    new_setting_list = Finds(by=By.CSS_SELECTOR, value='div[data-name="settings"]>aside>'
                                                       'ul>li[data-type="section-menu"]')
    exclusive_settings_list = Finds(by=By.CSS_SELECTOR, value='li[class="bold"]>ul>li')
    log_scan_details = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-input-id="log_whole_attack"]')
    enable_plugin_debugging = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                   value='div[data-input-id="enable_plugin_debugging"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['new_setting_list']

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


class AssessmentSetting(PolicySettings):
    """Page object for assessment settings"""

    perform_test = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                        value='div[data-type="checkbox"][data-input-id="thorough_tests"]')
    antivirus = Find(Select2Dropdown, by=By.CSS_SELECTOR,
                     value='select[data-name="Antivirus definition grace period (in days):"]')
    report_paranoia = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                           value='div[data-type="checkbox"][data-input-id="report_paranoia"]')
    report_paranoia_radio_options = Find(RadioGroupNessus, by=By.CSS_SELECTOR,
                                         value='[data-name$="accuracy"] '
                                               'div[class*="editor-radio-buttons"] div[class*="radio"]')
    scan_for_malware = Find(ToggleSwitch, by=By.CSS_SELECTOR, value='div[data-name="Scan for malware"]')
    scan_type = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-name="Settings Modes"]')
    request_windows_smb_domain = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                      value='div[data-input-id="request_windows_domain_info"]')
    disable_dns_resolution = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-input-id="disable_dns_resolution"]')

    def __init__(self):
        super().__init__()

    def choose_accuracy_option(self, option_value: str) -> None:
        """
        Choose the option from the radio group and click the checkbox
        
        :param str option_value: data value of radio button to click
        :return: None
        """
        self.report_paranoia.click()
        self.report_paranoia_radio_options.value = option_value
        self.perform_test.click()


class ReportSetting(PolicySettings):
    """Page object for report settings"""

    report_verbosity = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                            value='div[data-type="checkbox"][data-input-id="report_verbosity"]')
    report_verbosity_radio_options = Find(RadioGroupNessus, by=By.CSS_SELECTOR,
                                          value='div[data-name="report_processing"] div[class*="editor-radio-buttons"] '
                                                'div[class*="radio"]')
    report_superseded_patches = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                                     value='div[data-type="checkbox"][data-input-id="report_superseded_patches"]')
    silent_dependencies = Find(CheckboxDiv, by=By.CSS_SELECTOR,
                               value='div[data-type="checkbox"][data-input-id="silent_dependencies"]')
    allow_users_edit_scan = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-input-id="allow_post_scan_editing"]')

    def choose_reports_option(self, option_value: str) -> None:
        """
        Choose the option from the radio group and click the checkbox
        :param str option_value: data value of radio button to click
        :return: None
        """
        self.report_verbosity.click()
        self.report_verbosity_radio_options.value = option_value


class DiscoverySetting(PolicySettings):
    """Page object for discovery settings"""

    tcp_destination_ports = Find(by=By.CSS_SELECTOR, value='input[data-input-id="tcp_ping_dest_ports"]')
    wmi_netstat = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-input-id="wmi_netstat_scanner"]')
    ssh_netstat = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-input-id="ssh_netstat_scanner"]')

    def get_checkbox_element_for_value(self, check_box_value: str) -> WebElement:
        """
        Returns checkbox element for the particular value    
        :param str check_box_value: Value for checkbox
        :return: Returns WebElement of checkbox.
        :rtype: WebElement
        """
        checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="{}"]'.format(check_box_value),
                        context=self)
        return checkbox
