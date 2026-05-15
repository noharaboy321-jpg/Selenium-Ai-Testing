""""
Nessus page classes for Edit groups in Settings page

:copyright: Tenable Network Security, 2017
:date: December 07, 2017
:last_modified: December 07, 2017
:author: @rdutta
"""

from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.webium import Find, Finds
from catium.lib.webium.controls.checkbox import Checkbox
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.wait import wait
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.object_list import ObjectList


class EditGroupPage(NessusBasePage):
    """Edit Group Object that contains the 2 page objects used in changing settings for groups."""

    def __init__(self, group_id, group_factory=None):
        super().__init__()
        self.group_id = group_id
        self.group_factory = group_factory
        self.settings = EditGroupSettings(group_id)
        self.users = EditGroupUsers(group_id)


@cat_registry.route('settings/groups/{group_id}/settings')
class EditGroupSettings(NessusBasePage):
    """Page Object for Group Settings Page in Tenable Cloud"""

    groupname_field = Find(TextField, by=By.CLASS_NAME, value='edit-group-name')
    save_group_button = Find(value='groups-edit-group')
    error_notification = Find(by=By.CSS_SELECTOR, value='div.error')

    def __init__(self, group_id):
        super().__init__()
        self.required_elements = ['save_group_button']
        self.group_id = group_id


@cat_registry.route('settings/groups/{group_id}')
class EditGroupUsers(NessusBasePage):
    """Page Object for Group User Page in Tenable Cloud"""

    add_user_button = Find(value='settings-groups-user-add')
    remove_user_button = Find(by=By.CSS_SELECTOR, value='#groups-remove-user:not([style*="display: none"])')
    select_all_checkbox = Find(Checkbox, by=By.CLASS_NAME, value='select-all')

    def __init__(self, group_id):
        super().__init__()
        self.required_elements = ['add_user_button']
        self.group_id = group_id


class GroupUserRecord(GenericTableRow):
    """Defines the key names for User Records returned by GroupUserList"""
    select = Find(Checkbox, by=By.CSS_SELECTOR, value='div.checkbox')
    username = Find(by=By.CSS_SELECTOR, value='td.group-user-name')
    last_login = Find(by=By.CSS_SELECTOR, value='td.user-last-login')
    role = Find(by=By.CSS_SELECTOR, value='td.user-type')
    delete = Find(by=By.CSS_SELECTOR, value='td:nth-child(6)')


class GroupUserList(ObjectList):
    """Returns a list containing Users displayed on the Group's User Page"""
    configure_button = None
    object_table = Find(GenericBaseTable, value="content")
    generics_map = {GenericTableRow: GroupUserRecord}

    empty_results = Find(by=By.CSS_SELECTOR, value='span.empty-results')

    def __init__(self):
        super().__init__()


class UserDropdownList(NessusBasePage):
    """Returns a list containing Users displayed in the User Selector Dropdown in the Add User Modal"""

    results = Finds(by=By.CSS_SELECTOR, value='li.select2-results__option')
    result = Find(by=By.CSS_SELECTOR, value='li.select2-results__option')

    def __init__(self):
        super().__init__()
        wait(lambda: len(self.results) > 0, waiting_for='Groups List to populate.')


class DeleteGroupUserConfirmation(NessusBasePage):
    """Page Object for the Delete Group User Confirmation Modal Window"""

    modal = Find(value='modal')
    delete_button = Find(by=By.CLASS_NAME, value='modal-action')
    cancel_button = Find(by=By.CLASS_NAME, value='modal-close')

    def __init__(self):
        super().__init__()
        self.required_elements = ['modal']


class AddGroupUserConfirmation(NessusBasePage):
    """Page Object for the Add User to Group Confirmation Modal Window"""

    modal = Find(value='modal')
    user = Find(by=By.CSS_SELECTOR, value='.form-group > span > span > span > span.select2-selection__rendered')
    user_options = Find(by=By.CLASS_NAME, value='select2-results__options')
    save_button = Find(by=By.CLASS_NAME, value='modal-action')
    cancel_button = Find(by=By.CLASS_NAME, value='modal-close')

    def __init__(self):
        super().__init__()
        self.required_elements = ['modal']
