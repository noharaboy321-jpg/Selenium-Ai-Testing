"""
Nessus session timeout verification

Generic Object List Class from which object lists should inherit from 

:copyright: Tenable Network Security, 2017
:date: July 25, 2017
:author: @smadan
"""

from abc import abstractmethod

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox import Checkbox
from catium.lib.webium.controls.table import GenericBaseTable
from nessus.pageobjects.basepage import NessusBasePage


class ObjectList(NessusBasePage):
    """Page Object for a List in a List Page in Nessus Manager"""

    # Setup member variable to manage the table containing the list of objects
    object_table = Find(GenericBaseTable, value="content")
    select_all_checkbox = Find(Checkbox, by=By.CSS_SELECTOR, value='.select-all')

    def __init__(self):
        super().__init__()
        self.required_elements = ['object_table']

    @property
    @abstractmethod
    def configure_button(self):
        """ This allows Extending classes to raise an error if new_button isn't overridden"""
        return WebElement(None, None)

    @configure_button.setter
    @abstractmethod
    def configure_button(self, val):
        """ This allows Extending classes to raise an error if new_button isn't overridden"""
        return WebElement(None, None)

    @property
    def rows(self):
        """ Returns rows from table. """
        if len(self.object_table.rows) == 1 and self.object_table.rows[0].text == 'No records found.':
            return []
        return self.object_table.rows

    @property
    def columns(self):
        """ Returns columns from table. """
        if len(self.object_table.columns) == 1 and self.object_table.columns[0].text == 'No records found.':
            return []
        return self.object_table.columns

    def has_by_name(self, name: str='') -> bool:
        """
        Returns true if list has row by name.
        :param name: str
        :return: bool
        """
        return self.object_table.has_by_name(name)

    def has_by_id(self, object_id: str='') -> bool:
        """
        Returns true if list has row by id.
        :param object_id: str
        :return: bool
        """
        return self.object_table.has_by_id(object_id)

    def get_by_name(self, name: str='') -> bool:
        """
        Returns true if list has row by name.
        :param name: str
        :return: bool
        """
        return self.object_table.get_row_item_by_name(name)

    def get_by_id(self, object_id: str='') -> bool:
        """
        Returns true if list has row by id.
        :param object_id: str
        :return: bool
        """
        return self.object_table.get_row_item_by_id(object_id)

    def is_empty(self) -> bool:
        """
        Returns true if list empty.
        :return: bool
        """
        return self.object_table.is_empty()

    def exists(self) -> bool:
        """
        Returns true if list empty.
        :return: bool
        """
        return self.object_table.exists()
