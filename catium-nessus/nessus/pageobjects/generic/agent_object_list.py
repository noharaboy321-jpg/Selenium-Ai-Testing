"""
Generic Object List Class from which object lists should inherit from

:copyright: Tenable Network Security, 2024
:date: Sep 15, 2020
:last_modified: July 23, 2024
:author: @kpanchal, @mdabra
"""
from selenium.webdriver.common.by import By

from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.table import GenericBaseTable, GenericTable
from catium.lib.webium.find import Find
from nessus.pageobjects.basepage import NessusBasePage


class AgentBaseTable(GenericBaseTable):
    """ Implements generic logic to work with Table UI elements. This finds the Agent table and the empty table divs """

    table_wrapper = Find(GenericTable, by=By.CSS_SELECTOR, value="table.agents, table.agent-groups.dataTable.no-footer")

    @property
    def rows(self) -> list:
        """ Accessor for the rows in a Generic Table. If there is no table it returns empty list. """

        if not self.is_empty():
            return self.table_wrapper.table_body.rows
        else:
            return []

    @property
    def columns(self) -> list:
        """ Accessor for the columns in a Generic Table. If there is no table it returns empty list. """

        if not self.is_empty():
            return self.table_wrapper.table_head.columns
        else:
            return []


class AgentObjectList(NessusBasePage):
    """ Page Object for a List in a List Page in Nessus Manager """
    agent_table = Find(AgentBaseTable, value="content")
    select_all_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.select-all')

    @property
    def rows(self):
        """ Returns rows from table. """
        return self.agent_table.rows

    @property
    def columns(self):
        """ Returns columns from table. """
        return self.agent_table.columns
