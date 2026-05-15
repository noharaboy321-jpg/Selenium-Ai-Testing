"""
Nessus helper methods related to sort data on columns

:copyright: Tenable Network Security, 2017
:date: February 23, 2018
:date: March 13, 2018
:author: @rdutta, @mameta
"""
import time

from catium.lib.log import create_logger
from nessus.lib.const import SortOrder
from nessus.pageobjects.basepage import NessusBasePage

log = create_logger()


def sort_on_column_values(page_class_instance: NessusBasePage, column_name: str, sort: str) -> list:
    """
    Method to sort the object list values based on its column
    :param NessusBasePage page_class_instance: class object, where list exists.
    :param str column_name: column name to sort
    :param str sort: asc/ desc
    :return: list: returns a list of sorted data
    """
    # if a loading circle is present wait for it to clear
    table_columns = page_class_instance.object_table.columns

    for column in table_columns:
        if column.text == column_name:
            if sort == SortOrder.DESCENDING:
                time.sleep(3)
                column.sort_descending()
            else:
                time.sleep(3)
                column.sort_ascending()

            return page_class_instance.object_table.rows
    else:
        log.warning("%s column does not exist for sorting.", column_name)
