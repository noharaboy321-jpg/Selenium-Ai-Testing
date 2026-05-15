"""
Nessus page classes credentials tab

:copyright: Tenable Network Security, 2018
:date: January 30, 2018
:last_modified: June 24, 2021
:author: @smadan, @mameta, @ntarwani, @kpanchal
"""

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.const import WAIT_SHORT
from catium.lib.webium import Find
from catium.lib.webium import Finds
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from nessus.lib.message.messages import Messages
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.shared.loading import LoadingCircle


class Credentials(NewScanForm, NewPolicyForm):
    """  Page class for credentials tab in New Scan or Policy Creation Page in Nessus.
    .. note:: This Page Object doesn't reroute to a URL since the actual URL
        contains an unique ID, which is unknown upfront. The best way
        to call this object is simply instantiating it after clicking
        the 'New Policy' or 'New Scan' button.
    """
    open_form = Find(by=By.CSS_SELECTOR, value='li[class*=opened]')
    credentials_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="credentials"]')
    credentials_type = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[id="credentials-category-select"]')
    search_category = Find(TextField, by=By.CSS_SELECTOR, value='#credentials-search>input')
    search_icon = Find(by=By.CSS_SELECTOR, value='i[data-domselect="searchIcon"]')
    remove_icon_searchbox = Find(by=By.CSS_SELECTOR, value='i[data-domselect="clearSearchIcon"]')
    remove_form = Find(by=By.CSS_SELECTOR, value='li[class*="opened"] i[class*="remove"]')
    active_credentials = Finds(by=By.CSS_SELECTOR, value='ul[id="active-credentials"] li[class*="credentials"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['credentials_type']
        # if a loading circle is present wait for it to clear
        LoadingCircle(0)
        self.credentials.click()

    @property
    def opened_form_value(self):
        """Returns the opened form type"""
        return self.open_form.get_attribute('data-name')

    def get_sub_category_list(self, data_credentials: str) -> list:
        """
        returns locator for all the sub category links under a particular category.
        :param str data_credentials: Value of the category option from category dropdown
        :return: list of WebElements
        :rtype: list
        """
        return Finds(by=By.CSS_SELECTOR, value='ul[data-credentials="{}"] li[class*="credentials"]'
                     .format(data_credentials), context=self)

    def get_inclusive_credentials_type(self, data_credentials: str, sub_category: str) -> WebElement:
        """
        returns sub category element from all the sub category links under a particular category.
        :param str data_credentials: Value of the category option from category dropdown
        :param str sub_category: sub category
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='ul[data-credentials="{}"] li[class*="credentials"][data-name="{}"]'
                    .format(data_credentials, sub_category), context=self)

    def get_number_of_forms_element(self, sub_category: str) -> WebElement:
        """
        returns the number of forms left for a sub category
        :param: str sub_category: sub category name
        :return: Web element for number of form
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR,
                    value='li[data-name="{}"] span[class*="instances-badge "]'.format(sub_category), context=self)

    def get_category_type_list(self) -> list:
        """
        returns list of categories under dropdown
        :return: Types of categories under dropdown
        :rtype: list
        """
        return [category['label'] for category in self.credentials_type.option_values]

    def get_credentials_types(self, category_name: str) -> list:
        """
        returns sub category list under a particular category.
        :param str category_name: Value of the category option from category drop down
        :return: list
        """
        return [sub_category.get_attribute('data-name')
                for sub_category in self.get_sub_category_list(category_name)]

    def get_credentials_type_after_filter(self, category_name: str) -> list:
        """
        returns sub category list under a particular category after filter.
        :param str category_name: Value of the category option from category drop down
        :return: Returns sub category list after filter is applied
        :rtype: list
        """
        list1 = []
        for sub_category in self.get_sub_category_list(category_name):
            if "result" in sub_category.get_css_classes():
                list1.append(sub_category.get_attribute('data-name'))
        return list1

    def click_credentials_type(self, category_name: str, credentials_type: str) -> None:
        """
        click on the sub category of a particular category option
        :param str category_name: Value of the category option from category drop down
        :param str credentials_type: Value of subcategory under a particular category
        :return: None
        """
        LoadingCircle(WAIT_SHORT)
        self.credentials_type.select_by_visible_text(category_name)
        self.get_inclusive_credentials_type(category_name, credentials_type).click()

    def open_saved_credentials_component(self, form_name: str) -> None:
        """
        click on the save credentials
        :param str form_name: the saved form to be opened
        :return: None
        """
        for active_credential in self.active_credentials:
            saved_form_name = active_credential.find_element(By.CSS_SELECTOR,
                                                             'ul[id="active-credentials"] span[class="instance-name"]')
            if form_name in saved_form_name.text:
                active_credential.find_element(By.CSS_SELECTOR, ' i[class*="fontawesome right"]').click()
                break

    def remove_attached_file(self, data_name: str) -> WebElement:
        """
        returns locator for remove attached file
        :param str data_name: data file name
        :return: 'Remove' element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"] [class*="remove-attached-file"][data-name="{}"]'
                    .format(data_name), context=self)

    def get_add_file_link(self, data_name: str) -> WebElement:
        """
        returns locator for Add File link
        :param str data_name: data file name
        :return: 'Add File' element
        :rtype: WebElement
        """
        return Find(TextField, by=By.CSS_SELECTOR,
                    value='li[class*="opened"] a[data-name="{}"]'.format(data_name), context=self)

    def check_required_field_validation(self, class_instance: NessusBasePage, element: str, **kwargs) -> bool:
        """
        Return boolean value, True if getting proper validation message on clearing value of required field else False.
        :param NessusBasePage class_instance: class instance
        :param str element: WebElement name as a string
        :return: True or False.
        :rtype: bool
        """
        elmnt = getattr(class_instance, element)

        if callable(elmnt):
            elmnt = elmnt(**kwargs.get('element_args'))

        elmnt.clear()
        self.js_scroll_into_view(self.save_button)
        self.save_button.click()

        error_message = kwargs.get('error_message', element)

        return Notifications().errors[-1] == getattr(Messages.NotificationMessages.Credentials, error_message)
