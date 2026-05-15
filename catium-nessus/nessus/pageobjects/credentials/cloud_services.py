"""
Nessus page classes for Cloud Services

:copyright: Tenable Network Security, 2017
:date: Jan 29, 2018
:last_modified: June 17, 2022
:author: @smadan, @mameta, @ntarwani, @kpanchal, @krpatel
"""
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import WAIT_NORMAL
from catium.lib.webium import Find
from catium.lib.webium import Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.toggleswitch import ToggleSwitch
from nessus.pageobjects.credentials.credentials_page import Credentials
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle


class CloudServices(Credentials):
    """Page class for Cloud Services field under category dropdown in Nessus scan credentials."""
    cloud_service_open_form = Find(by=By.CSS_SELECTOR, value='li[class*=opened]')

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.click_credentials_type(category_name='Cloud Services', credentials_type=kwargs.get('cloud_type'))

    @property
    def opened_form_value(self):
        """Returns the opened form type"""
        return self.cloud_service_open_form.get_attribute('data-name')

    @property
    def username(self) -> WebElement:
        """Returns username element of the form opened under cloud services category"""
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="{}"]'
                                                         ' input[data-input-id="username"]'
                    .format(self.opened_form_value), context=self)

    @property
    def password(self) -> WebElement:
        """Returns password element of the form opened under cloud services category"""
        return Find(TextField, by=By.CSS_SELECTOR, value='li[class*=opened][data-name="{}"]'
                                                         ' input[data-input-id="password"]'
                    .format(self.opened_form_value), context=self)


class AmazonAWS(CloudServices):
    """Page object for Amazon AWS form under Cloud Services"""
    access_key = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="access_key_id"]')
    secret_key = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="secret_key"]')
    regions_to_access = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-input-id="aws_ui_region_type"]')
    https_switch = Find(ToggleSwitch, by=By.CSS_SELECTOR, value='div[data-input-id="aws_use_https"]')
    ssl_certificate = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-input-id="aws_verify_ssl"]')

    def get_checkbox_element_for_regions_to_access(self, check_box_value: str) -> CheckboxDiv:
        """
        Returns checkbox element for the particular value
        :param str check_box_value: Value for checkbox
        :return: Checkbox element for the value given
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="{}"]'.format(check_box_value),
                    context=self)

    def fill_amazon_aws_form(self, access_key: str, secret_key: str, regions_to_access: str, **kwargs) -> None:
        """
        fills Amazon AWS Credentials under Cloud Services.
        :param str access_key: Value of Access key for Amazon AWS Credentials
        :param str secret_key: Value of Secret key for Amazon AWS Credentials
        :param str regions_to_access: Region to access passed for Amazon AWS
        """
        https_switch = kwargs.get('https_switch')
        ssl_certificate = kwargs.get('ssl_certificate')

        check_box_dict = {'us-east-1': kwargs.get('us_east_1', True), 'us-east-2': kwargs.get('us_east_2', True),
                          'us-west-1': kwargs.get('us_west_1', True), 'us-west-2': kwargs.get('us_west_2', True),
                          'ca-central-1': kwargs.get('ca_central_1', True), 'eu-west-1': kwargs.get('eu_west_1', True),
                          'eu-west-2': kwargs.get('eu_west_2', True), 'eu-central-1': kwargs.get('eu_central_1', True),
                          'ap-northeast-1': kwargs.get('ap_northeast_1', True), 'ap-northeast-2':
                              kwargs.get('ap_northeast_2', True), 'ap-southeast-1': kwargs.get('ap_southeast_1', True),
                          'ap-southeast-2': kwargs.get('ap_southeast_2', True), 'ap-south-1':
                              kwargs.get('ap_south_1', True), 'sa-east-1': kwargs.get('sa_east_1', True)}
        check_box_dict_gov = {'us-gov-west-1': kwargs.get('us_gov_west_1', True),
                              'us-gov-east-1': kwargs.get('us_gov_east_1', True)}

        self.access_key.send_keys(access_key)
        self.secret_key.send_keys(secret_key)
        self.regions_to_access.select_by_visible_text(regions_to_access)

        if regions_to_access == "Rest of the World":
            self.js_scroll_into_view(ScansPage().save_button)
            for key, value in check_box_dict.items():
                self.js_scroll_into_view(self.get_checkbox_element_for_regions_to_access(key))
                if not value and self.get_checkbox_element_for_regions_to_access(key).is_selected():
                    self.get_checkbox_element_for_regions_to_access(key).uncheck()
                elif value and not self.get_checkbox_element_for_regions_to_access(key).is_selected():
                    self.get_checkbox_element_for_regions_to_access(key).check()
                LoadingCircle()

        if regions_to_access == "GovCloud":
            self.js_scroll_into_view(ScansPage().save_button)
            for key, value in check_box_dict_gov.items():
                self.js_scroll_into_view(self.get_checkbox_element_for_regions_to_access(key))
                if not value and self.get_checkbox_element_for_regions_to_access(key).is_selected():
                    self.get_checkbox_element_for_regions_to_access(key).uncheck()
                elif value and not self.get_checkbox_element_for_regions_to_access(key).is_selected():
                    self.get_checkbox_element_for_regions_to_access(key).check()
                LoadingCircle()

        if not https_switch and self.https_switch.is_selected():
            self.https_switch.untoggle()
        elif https_switch and not self.https_switch.is_selected():
            self.https_switch.toggle()

        if self.ssl_certificate.is_displayed():
            if ssl_certificate and not self.ssl_certificate.is_selected():
                self.ssl_certificate.check()
            elif not ssl_certificate and self.ssl_certificate.is_selected():
                self.ssl_certificate.uncheck()

    def get_amazon_aws_data(self) -> dict:
        """
        Returns Amazon AWS form data
        :return: dictionary containing amazon aws form data
        :rtype: dict
        """
        check_box_list = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-west-1', 'eu-west-2',
                          'eu-central-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',
                          'ap-south-1', 'sa-east-1']
        check_box_list_gov = ['us-gov-east-1', 'us-gov-west-1']
        amazon_aws_data = {'regions_to_access': self.regions_to_access.get_value_selected(),
                           'https_switch': self.https_switch.is_selected(),
                           'ssl_certificate': self.ssl_certificate.is_selected()}

        if self.regions_to_access.get_value_selected() == "Rest of the World":
            for check_box in check_box_list:
                amazon_aws_data.update({check_box.replace('-', '_'): self.get_checkbox_element_for_regions_to_access(
                    check_box_value=check_box).is_selected()})
        if self.regions_to_access.get_value_selected() == "GovCloud":
            for check_box in check_box_list_gov:
                amazon_aws_data.update({check_box.replace('-', '_'): self.get_checkbox_element_for_regions_to_access(
                    check_box_value=check_box).is_selected()})
        return amazon_aws_data


class MicrosoftAzure(CloudServices):
    """Page object for Microsoft Azure form under Cloud Services"""
    application_id = Finds(by=By.CSS_SELECTOR, value='input[data-input-id="client_id"]')
    subscription_id = Find(by=By.CSS_SELECTOR, value='input[data-input-id="microsoft_azure_subscriptions_ids"]')
    authentication_type = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[data-type="ui-radio"]'
                                                                          '[data-name="Authentication Method"]')
    client_secret = Find(by=By.CSS_SELECTOR, value='input[data-input-id="client_secret"]')
    tenant_id = Find(by=By.CSS_SELECTOR, value='input[data-input-id="tenant_id"]')

    def fill_microsoft_azure_form(self, auth_method: str, subscription_id: str, **kwargs) -> None:
        """
        Method to fill Microsoft Azure form under Cloud Services
        :param str auth_method : Authentication Method
        :param str subscription_id: subscription id value
        :return: None
        """
        sleep(WAIT_NORMAL, reason="Microsoft Azure form takes little bit time to get loaded")
        self.authentication_type.select_by_visible_text(auth_method)

        if auth_method == "Password":
            self.username.send_keys(kwargs.get('username'))
            self.password.send_keys(kwargs.get('password'))
            self.application_id[0].send_keys(kwargs.get('application_id'))
        elif auth_method == "Key":
            self.tenant_id.send_keys(kwargs.get('tenant_id'))
            self.client_secret.send_keys(kwargs.get('client_secret'))
            self.application_id[1].send_keys(kwargs.get('application_id'))

        self.subscription_id.send_keys(subscription_id)

    def get_microsoft_azure_data(self, auth_method: str = "Password") -> dict:
        """
        Returns dictionary containing Microsoft Azure form data
        :return: dictionary containing microsoft azure form data
        :rtype: dict
        """
        if auth_method == "Password":
            return {'username': self.username.get_attribute('value'),
                    'password': self.password.get_attribute('value'),
                    'application_id': self.application_id[0].get_attribute('value'),
                    'subscription_id': self.subscription_id.get_attribute('value')}
        elif auth_method == "Key":
            return {
                'application_id': self.application_id[1].get_attribute('value'),
                'subscription_id': self.subscription_id.get_attribute('value'),
                'client_secret': self.client_secret.get_attribute('value'),
                'tenant_id': self.tenant_id.get_attribute('value')}


class RackSpace(CloudServices):
    """Page object for RackSpace form under Cloud Services"""
    auth_method = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='li[class*="opened"][data-name="Rackspace"]'
                                                                  ' select[data-input-id="auth_method"]')

    def get_checkbox_element_for_global_settings(self, check_box_value: str) -> CheckboxDiv:
        """
        returns checkbox element for the particular value
        :param str check_box_value: Value for checkbox
        :return: Checkbox for given global setting value
        :rtype: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='div[data-name="{}"]'.format(check_box_value),
                    context=self)

    def fill_rackspace_form(self, username: str, password: str, auth_method: str, **kwargs) -> None:
        """
        Fills RackSpace form under Cloud Services under category dropdown in Nessus scan credentials
        :param str username: username value
        :param str password: password or api key value
        :param str auth_method: authentication method option
        """
        global_credentials_dict = {'Dallas-Fort Worth (DFW)': kwargs.get('dallas_fort', True),
                                   'Chicago (ORD)': kwargs.get('chicago_ord', True),
                                   'Northern Virginia (IAD)': kwargs.get('northen_virginia', True),
                                   'London (LON)': kwargs.get('london', True),
                                   'Sydney (SYD)': kwargs.get('sydney', True),
                                   'Hong Kong (HKG)': kwargs.get('hongkong', True)}

        self.username.send_keys(username)
        self.password.send_keys(password)
        self.auth_method.select_by_visible_text(auth_method)
        for key, value in global_credentials_dict.items():
            if not value and self.get_checkbox_element_for_global_settings(key).is_selected():
                self.get_checkbox_element_for_global_settings(key).uncheck()
            elif value and not self.get_checkbox_element_for_global_settings(key).is_selected():
                self.get_checkbox_element_for_global_settings(key).check()
            LoadingCircle()

    def get_rackspace_data(self) -> dict:
        """
        Returns form data for Rackspace under Cloud Services
        :return: dictionary containing Rackspace form data
        :rtype: dict
        """
        return {'auth_method': self.auth_method.get_value_selected(),
                'username': self.username.get_attribute('value'),
                'password': self.password.get_attribute('value'),
                'dallas_fort': self.get_checkbox_element_for_global_settings(
                    check_box_value='Dallas-Fort Worth (DFW)').is_selected(),
                'chicago_ord': self.get_checkbox_element_for_global_settings(
                    check_box_value='Chicago (ORD)').is_selected(),
                'northen_virginia': self.get_checkbox_element_for_global_settings(
                    check_box_value='Northern Virginia (IAD)').is_selected(),
                'london': self.get_checkbox_element_for_global_settings(check_box_value='London (LON)').is_selected(),
                'sydney': self.get_checkbox_element_for_global_settings(check_box_value='Sydney (SYD)').is_selected(),
                'hongkong': self.get_checkbox_element_for_global_settings(
                    check_box_value='Hong Kong (HKG)').is_selected()}


class SalesForce(CloudServices):
    """Page object for Salesforce.com form under Cloud Services"""

    def fill_sales_force_form(self, username: str, password: str) -> None:
        """
        fill salesforce.com form under cloud services credentials under category dropdown in Nessus scan credentials
        :param str username: username
        :param str password: password
        :return: None
        """
        self.username.send_keys(username)
        self.password.send_keys(password)

    def get_sales_force_data(self) -> dict:
        """
        Returns Salesforce.com form data
        :return: dictionary containing salesforce data
        :rtype: dict
        """
        return {'username': self.username.get_attribute('value'),
                'password': self.password.get_attribute('value')}


class Office365(CloudServices):
    """Page object for Office 365 form under Cloud Services"""
    client_id = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="client_id"]')
    client_secret = Find(TextField, by=By.CSS_SELECTOR, value='input[data-input-id="client_secret"]')

    def fill_office_365_form(self, password: str, **kwargs) -> None:
        """
        Fill Office 365 form data under Cloud Services.
        :param str password: password
        :param kwargs: get the value as a dictionary.
        :return: None
        """
        self.username.send_keys(kwargs.get('username'))
        self.password.send_keys(password)
        self.client_id.send_keys(kwargs.get('client_id'))
        self.client_secret.send_keys(kwargs.get('client_secret'))

    def get_office_365_data(self) -> dict:
        """
        Returns filled Office 365 form data as a dictionary.
        :return: dictionary contains office 365 form data
        :rtype: dict
        """
        return {'username': self.username.get_attribute('value'),
                'password': self.password.get_attribute('value'), 'client_id': self.client_id.value,
                'client_secret': self.client_secret.value}
