"""
Nessus page class for compliance tab

:copyright: Tenable Network Security, 2017
:date: May 24, 2018
:last_modified: March 29, 2024
:author: @rdutta, @mameta, @ntarwani, @kpanchal, @krpatel
"""

import os
import time

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT
from catium.lib.const.base_constants import TIME_THREE_SECONDS, WAIT_NORMAL, TIME_FIVE_SECONDS
from catium.lib.webium import Find
from catium.lib.webium import Finds
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select import Select
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.controls.upload_field import UploadField
from catium.lib.webium.wait import wait
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.scans.new_scan_form import NewScanForm
from nessus.pageobjects.shared.loading import LoadingCircle


class Compliance(NewScanForm, NewPolicyForm):
    """  Page class for compliance tab in New Scan or Policy Creation Page in Nessus.
    .. note:: This Page Object doesn't reroute to a URL since the actual URL
        contains an unique ID, which is unknown upfront. The best way
        to call this object is simply instantiating it after clicking
        the 'New Policy' or 'New Scan' button.
    """
    compliance_tab = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-name="compliance"]')
    compliance_type = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[id="compliance-category-select"]')
    amazon_compliance = Find(by=By.CSS_SELECTOR, value='span[title="CIS Amazon Linux 2 v3.0.0 L1"]')
    search_textbox = Find(TextField, by=By.CSS_SELECTOR, value='#compliance-search>input')
    remove_form = Find(by=By.CSS_SELECTOR, value='li[class*="opened"] i[class*="remove"]')
    uploaded_file_title = Find(by=By.CSS_SELECTOR, value='li[data-free = "0"] .instance-name')
    active_compliances = Finds(by=By.CSS_SELECTOR, value='ul[id="active-compliance"] li[class*="compliance"]')
    required_cred_link = Find(by=By.CSS_SELECTOR, value='a[class="required-cred-link"]')
    add_audit_file = Find(Clickable, by=By.CSS_SELECTOR, value='.opened input[data-name="Audit file"]')
    add_config_file = Find(Clickable, by=By.CSS_SELECTOR, value='.opened input[data-name$=" config file(s)"]')
    active_expansion_icon = Find(Clickable, by=By.CSS_SELECTOR, value='span[class="instance-edit action"] i['
                                                                      'class*="fontawesome right"]')
    inactive_expansion_icon = Find(Clickable, by=By.CSS_SELECTOR, value='span[class="instance-close action"] i['
                                                                        'class*="fontawesome down"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['compliance_type']
        LoadingCircle(WAIT_SHORT)
        self.compliance.click()
        LoadingCircle(WAIT_NORMAL)

    def get_remove_element(self, compliance_type: str) -> WebElement:
        """
        returns the remove button locator specific to compliance
        :param str compliance_type: compliance category name
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='li[data-parent="{}"] i[class*="remove"]'
                    .format(compliance_type), context=self)

    def get_sub_category_list(self, data_compliance: str) -> list:
        """
        returns locator for all the sub category links under a particular category.
        :param str data_compliance: Value of the category option from category dropdown
        :return: list of WebElements
        :rtype: list
        """
        return Finds(by=By.CSS_SELECTOR, value='ul[data-compliance="{}"] li[class*="compliance"]'
                     .format(data_compliance), context=self)

    def get_inclusive_compliance_type(self, data_compliance: str, sub_category: str) -> WebElement:
        """
        returns sub category element from all the sub category links under a particular category.
        :param str data_compliance: Value of the category option from category dropdown
        :param str sub_category: sub category
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='ul[data-compliance="{}"] li[class*="compliance"][data-name*="{}"]'
                    .format(data_compliance, sub_category), context=self)

    def get_category_type_list(self) -> list:
        """
        returns list of categories under dropdown
        :return: Types of categories under dropdown
        :rtype: list
        """
        return [category['label'] for category in self.compliance_type.option_values]

    def get_compliance_types(self, category_name: str) -> list:
        """
        returns sub category list under a particular category.
        :param str category_name: Value of the category option from category drop down
        :rtype: list
        """
        return [sub_category.get_attribute('data-name')
                for sub_category in self.get_sub_category_list(category_name)]

    def get_compliance_type_after_filter(self, category_name: str) -> list:
        """
        returns sub category list under a particular category after filter.
        :param str category_name: Value of the category option from category drop down
        :return: Returns sub category list after filter is applied
        :rtype: list
        """
        list1 = []
        for sub_category in self.get_sub_category_list(category_name):
            if sub_category.get_attribute('style') != "display: none;":
                list1.append(sub_category.get_attribute('data-name'))
        return list1

    def click_compliance_type(self, category_name: str, compliance_type: str) -> None:
        """
        click on the sub category of a particular category option
        :param str category_name: Value of the category option from category drop down
        :param str compliance_type: Value of subcategory under a particular category
        :return: None
        """

        self.compliance_type.select_by_visible_text(category_name)
        LoadingCircle(WAIT_NORMAL)
        element_of_compliance = self.get_inclusive_compliance_type(category_name, compliance_type)
        time.sleep(TIME_FIVE_SECONDS)
        element_of_compliance.location_once_scrolled_into_view
        wait(lambda: element_of_compliance.is_displayed(), timeout=TIME_FIVE_SECONDS)
        self.get_inclusive_compliance_type(category_name, compliance_type).click()

    def click_compliance(self, category_name: str, compliance_type: str) -> None:
        """
        click on the sub category of a particular category option
        :param str category_name: Value of the category option from category drop down
        :param str compliance_type: Value of subcategory under a particular category
        :return: None
        """
        LoadingCircle(WAIT_NORMAL)
        self.compliance_type.select_by_visible_text(category_name)
        LoadingCircle(WAIT_NORMAL)
        self.amazon_compliance.click()

    def open_saved_compliance_component(self, form_name: str) -> None:
        """
        click on the saved compliance
        :param str form_name: the saved form to be opened
        :return: None
        """
        for active_compliance in self.active_compliances:
            saved_form_name = active_compliance.find_element(By.CSS_SELECTOR,
                                                             'ul[id="active-compliance"] span[class="instance-name"]')
            if form_name in saved_form_name.text:
                active_compliance.find_element(By.CSS_SELECTOR, ' i[class*="fontawesome right"]').click()
                break

    def fill_compliance_form(self, **kwargs) -> None:
        """
        fill form for compliance according to their specific element type
        :return: None
        """
        for element in kwargs.keys():
            element_type = getattr(self, element)
            if element_type.__class__ == TextField:
                element_type.clear()
                element_type.send_keys(kwargs[element])
            elif element_type.__class__ == CheckboxDiv:
                element_type.set_checked(kwargs[element])
            elif element_type.__class__ in (Select, Select2Dropdown):
                element_type.select_by_visible_text(kwargs[element])
            elif element_type.__class__ == UploadField:
                element_type.send_keys(kwargs[element])

    def get_filled_compliance_form_values(self) -> dict:
        """
        returns filled compliance form values
        :rtype: dict
        """
        _dict = {}
        _element = list(
            filter(lambda x: not x.startswith('__') and x != '_compliance_type', self.__class__.__dict__.keys()))
        for _ele in _element:
            ele = getattr(self, _ele)
            if isinstance(_ele, dict):
                ele = ele(*_ele['args'], **_ele['kwargs'])
            if ele.__class__ == TextField:
                value = ele.get_attribute('value')
            elif ele.__class__ == CheckboxDiv:
                value = ele.is_selected()
            elif ele.__class__ == Select:
                value = ele.get_attribute('value')
            elif ele.__class__ == Select2Dropdown:
                value = ele.text
            elif ele.__class__ == UploadField:
                value = ele.get_attribute('data-value')
                value = value.split('-')[0]
            _dict.__setitem__(_ele, value)
        return _dict

    @staticmethod
    def get_compliance_type(compliance_type: str) -> object:
        """
        Returns object for specific compliance sub category class
        :param str compliance_type: value of compliance type given in string
        :return: object for the particular class
        :rtype: object
        """
        for _cls in Compliance.__subclasses__():
            if hasattr(_cls, '_compliance_type') and _cls._compliance_type == compliance_type:
                return _cls()
        else:
            raise AssertionError("Invalid compliance type {}".format(compliance_type))

    def add_audit_and_config_file(self, audit_file_name: str, audit_file_path: str,
                                  config_file_name: str = None, config_file_path: str = None) -> dict:
        """
        add an audit file and/or config file to opened compliance form
        :param str audit_file_name: Name of audit file to be added
        :param str audit_file_path: audit file path where file resides
        :param str config_file_name: Name of config file to be added
        :param str config_file_path: config file path where file resides
        :return: added file name(s) along with their extensions
        :rtype: dict
        """
        attached_files = {}
        audit_file = os.path.abspath(get_file_path(os.path.join(audit_file_path, audit_file_name)))
        self.add_audit_file.send_keys(audit_file)
        LoadingCircle(WAIT_SHORT)
        attached_files.update({'audit_file': self.add_audit_file.get_attribute('data-value')})

        LoadingCircle(TIME_THREE_SECONDS)
        if config_file_name and config_file_path:
            config_file = os.path.abspath(get_file_path(os.path.join(config_file_path, config_file_name)))
            self.add_config_file.send_keys(config_file)
            LoadingCircle(WAIT_SHORT)
            attached_files.update({'config_file': self.add_config_file.get_attribute('data-value')})

        return attached_files
