"""
Nessus page object class for Registration page

:copyright: Tenable Network Security, 2019
:date: May 17, 2019
:last_modified: Feb 24, 2023
:author: @yshah, @krpatel
"""
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import WAIT_NORMAL
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.radio_group import RadioGroup
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.find import Find, Finds
from nessus.pageobjects.basepage import NessusBasePage


class RegistrationPage(NessusBasePage):
    """Page objects for registration page"""
    continue_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="continue"]')
    continue_btn = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="btn-continue"]')
    continue_activation = Find(Clickable, by=By.CSS_SELECTOR, value='[data-testid="btn-continue-register"]')
    continue_contact_lookup = Find(Clickable, by=By.CSS_SELECTOR, value='[data-testid="btn-continue-contact-lookup"]')
    back_activation = Find(Clickable, by=By.CSS_SELECTOR, value='[data-testid="btn-back-register"]')
    page_header = Find(by=By.CSS_SELECTOR, value=".register-content h2")
    license_code = Find(by=By.CSS_SELECTOR, value=".register-content label")
    activation_code = Find(by=By.CSS_SELECTOR, value='[for="code"]')
    license_type = Finds(by=By.CSS_SELECTOR, value=".radio-label")
    back_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="back"]')
    btn_back_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="btn-back"]')
    skip_btn = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="btn-skip"]')
    get_started = Find(by=By.CSS_SELECTOR, value='#t-nessus-activation-contact-lookup-container h2')
    email_input = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Email"]')
    first_name = Find(TextField, by=By.CSS_SELECTOR, value='[name="first_name"]')
    last_name = Find(TextField, by=By.CSS_SELECTOR, value='[name="last_name"]')
    phone_text = Find(TextField, by=By.CSS_SELECTOR, value='[name="phone"]')
    job_title = Find(TextField, by=By.CSS_SELECTOR, value='[name="job-title"]')
    company_name = Find(TextField, by=By.CSS_SELECTOR, value='[name="company-name"')
    company_size = Find(TextField, by=By.CSS_SELECTOR, value='[title="Company Size "]')
    link = Find(TextField, by=By.CSS_SELECTOR, value='[href="https://info.tenable.com/SubscriptionManagement.html"]')



    def get_by_license_type(self, license_type: str)-> WebElement:
        """
        Select the license type
        :param str license_type: license type i.e. Nessus Manager
        :return: WebElement
        """
        return Find(RadioGroup, by=By.CSS_SELECTOR, value='[aria-label="{}"]'.format(license_type), context=self)

    def get_tooltip_by_license(self, license_type: str)-> WebElement:
        """
        Get the tooltip of given license
        :param str license_type: license type i.e. Nessus Manager
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='[aria-label="{}"]+div+i'.format(license_type), context=self)


class NessusEssentialsLicensePage(NessusBasePage):
    """Page objects for Nessus Essentials registration page"""
    first_name = Find(TextField, by=By.CSS_SELECTOR, value='[name="first_name"]')
    last_name = Find(TextField, by=By.CSS_SELECTOR, value='[name="last_name"]')
    email_input = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Email"]')
    back_button = Find(Clickable, by=By.CSS_SELECTOR, value='[type="button"][data-name="btn-back"]')
    activation_code_back = Find(Clickable, by=By.CSS_SELECTOR, value='#t-nessus-activation-register-code-container form div.left-side button')
    register_button = Find(Clickable, by=By.CSS_SELECTOR, value='[type="submit"][data-name="btn-continue"]')
    page_header = Find(Clickable, by=By.CSS_SELECTOR, value="#t-nessus-activation-essentials-register-container h2")
    skip_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="skip"]')
    skip_btn = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="btn-skip"]')
    validation_error = Finds(by=By.CSS_SELECTOR, value='div.invalid > div')


class ManagerAndProfessionalLicensePage(NessusBasePage):
    """Page objects for Nessus manager and Nessus Professional registration page"""
    activation_input = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Activation Code"]')
    register_offline_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='[data-field="offline"]')
    setting_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="settings"]')
    back_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="back"]')
    btn_back_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="btn-back"]')
    btn_back_login = Find(Clickable, by=By.CSS_SELECTOR, value='[data-testid="btn-back-login"]')
    continue_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="continue"]')
    page_header = Find(Clickable, by=By.CSS_SELECTOR, value=".register-content h2")
    nessus_license_key_offline = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Nessus License"]')
    skip_btn = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="btn-skip"]')


class ManagedScannerLicensePage(NessusBasePage):
    """Page objects for Managed Scanner registration page"""
    managed_by_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-field="manager.type"]')
    linking_key = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Linking Key"]')
    proxy_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value=".floatleft.checkbox.large-checkbox")
    setting_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="settings"]')
    back_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="back"]')
    continue_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="continue"]')
    host_field = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Manager Host"]')
    port_field = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Manager Port"]')
    page_header = Find(Clickable, by=By.CSS_SELECTOR, value=".register-content h2")


class UserAccountPage(NessusBasePage):
    """Page objects for user accounts page"""
    username = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Username"]')
    password = Find(TextField, by=By.CSS_SELECTOR, value='[aria-label="Password"]')
    back_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="back"]')
    submit_button = Find(Clickable, by=By.CSS_SELECTOR, value='[data-name="submit"]')

    def fill_user_activation_form(self) -> None:
        """
        Fill user activation form
        :return: None
        """
        self.username.value = "admin"
        sleep(sleep_time=WAIT_NORMAL, reason="user field")
        self.password.value = "admin"
        sleep(sleep_time=WAIT_NORMAL, reason="user field")
        self.submit_button.click()
