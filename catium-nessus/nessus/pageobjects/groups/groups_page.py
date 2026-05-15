""""
Nessus page classes for Groups in Settings page

:copyright: Tenable Network Security, 2017
:date: December 07, 2017
:last_modified: April 20, 2020
:author: @rdutta, @kpanchal
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.cat_registry import cat_registry
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.checkbox import Checkbox
from catium.lib.webium.controls.checkbox_div import CheckboxDiv
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.link import Link
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.wait import wait
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.header.notifications import NotificationActions

log = create_logger()


class CreateGroupPage(ActionCloseModal, NessusBasePage):
    """Page Object for creating Group Modal Window"""

    group_name = Find(TextField, by=By.CSS_SELECTOR, value='.validate[data-domselect="Name"]')
    name_required_badge = Find(by=By.CSS_SELECTOR, value='.required-badge')
    add_button = Find(Clickable, by=By.CSS_SELECTOR, value='.modal-action.button')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='.button.link.modal-close')

    def __init__(self):
        super().__init__()
        self.required_elements = ['group_name']


class AddUserWindow(ActionCloseModal, NessusBasePage):
    """Page Object for adding user to Group Modal Window"""

    user_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='select[class="groups-add-user-user-id '
                                                                    'select2-hidden-accessible"]')
    total_user_record = Find(by=By.CSS_SELECTOR,
                             value='div[data-domselect*="Searchbox"] [data-domselect="Total Records"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['user_dropdown']

    def get_all_users_from_dropdown(self) -> list:
        """
        return list of users by their name from user dropdown list.
        :return: list
        """
        return [self.user_dropdown.option_values[user_values]['label'] for user_values in
                range(len(self.user_dropdown.option_values))]

    def get_current_count_of_users(self) -> int:
        """
        return count of current users added into the group
        :return: int
        """
        return int(self.total_user_record.text.split(' ', 1)[0])


@cat_registry.route(r'settings/groups')
class GroupsPage(CreateGroupPage):
    """Page Object for Group Management Page in Nessus."""

    new_group_button = Find(by=By.CSS_SELECTOR, value='#new')
    select_all_checkbox = Find(Checkbox, by=By.CLASS_NAME, value='select-all')
    edit_button = Find(by=By.CSS_SELECTOR, value='#edit')
    delete_button = Find(Clickable, by=By.CSS_SELECTOR, value='#delete')
    create_a_new_group_link = Find(by=By.CSS_SELECTOR, value='.empty-results a')
    search_box = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    total_group_record = Find(by=By.CSS_SELECTOR,
                              value='div[data-domselect*="Searchbox"] [data-domselect="Total Records"]')
    search_group_result = Find(by=By.CSS_SELECTOR,
                               value='div[data-domselect*="Searchbox"] [data-domselect="Results"] b')
    title_in_header = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    clear_selected_items_link = Find(Link, by=By.CSS_SELECTOR, value='a[data-domselect="clear-all"]')
    remove_search_icon = Find(by=By.CSS_SELECTOR, value='#searchbox .remove')
    group_search_icon = Find(by=By.CSS_SELECTOR, value='#searchbox .search')
    add_user = Find(Clickable, by=By.CSS_SELECTOR, value='#group-user-add')

    def __init__(self):
        super().__init__()
        self.required_elements = ['new_group_button']

    def create_new_user_group(self, group_name: str) -> None:
        """
        Create a new group for users
        :param str group_name: name of the group
        :return: None
        """
        self.new_group_button.click()
        self.group_name.value = group_name
        self.add_button.click()


class NewGroupPage(AddUserWindow):
    """Page Object for New Group Page in Nessus Manager"""

    add_user_button = Find(by=By.CSS_SELECTOR, value='#group-user-add')
    back_to_groups = Find(by=By.CSS_SELECTOR, value='.title-box a')
    create_a_new_user_link = Find(by=By.CSS_SELECTOR, value='.empty-results a')
    user_group_page_name = Find(by=By.CSS_SELECTOR, value='.has-back')

    def __init__(self):
        super().__init__()
        self.required_elements = ['add_user_button']

    @property
    def get_group_name_in_header(self):
        """Return group name from header of corresponding group details page."""
        return self.user_group_page_name.text.split('\n')[0]

    def add_user_to_group(self, user_list: list) -> None:
        """
        add user to the group
        :param list user_list: user(s) to add in
        :return: None
        """
        for user in user_list:
            self.add_user_button.click()
            self.user_dropdown.select_by_visible_text(user)
            self.action_button.click()
            self.wait_for_modal_closed()

            NotificationActions().remove_all()
            wait(lambda: self.is_element_present("add_user_button"), waiting_for="'Add User' button to be visible")


class GroupRecord(GenericTableRow):
    """Defines the key names for Group Records returned by GroupList"""
    select = Find(Checkbox, by=By.CSS_SELECTOR, value='td>div.checkbox')
    group_name = Find(by=By.CSS_SELECTOR, value='td.group-name')
    members = Find(by=By.CSS_SELECTOR, value='td.group-current-users')
    edit_icon = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    delete_icon = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')

    @property
    def name(self):
        """ Returns name attribute of a row """
        return self.group_name.text

    @property
    def member(self):
        """ Returns member attribute of a row """
        return self.members.text


class GroupList(ObjectList):
    """ Returns a list containing Groups displayed on the Group Management Page. """
    configure_button = None
    object_table = Find(GenericBaseTable, value="content")
    generics_map = {GenericTableRow: GroupRecord}

    def __init__(self):
        super().__init__()

    def get_specific_group_remove(self, group_name: str) -> WebElement:
        """
        get remove icon for specific group
        :param str group_name: group_name
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR,
                    value='tr[data-name="{}"] i[class*="remove"]'.format(group_name), context=self)

    def get_specific_group_edit_icon(self, group_name: str) -> WebElement:
        """
        get edit icon for specific group
        :param str group_name: group_name
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR,
                    value='tr[data-name="{}"] i[class*="edit"]'.format(group_name), context=self)

    def get_specific_group_checkbox(self, group_name: str) -> CheckboxDiv:
        """
        get checkbox for specific group
        :param str group_name: group_name
        :return: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR,
                    value='tr[data-name="{}"] .checkbox'.format(group_name), context=self)

    def get_specific_member_count(self, group_name: str) -> WebElement:
        """
        get member count of group
        :param str group_name: group name
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR,
                    value='tr[data-name="{}"] .group-current-users.pointer'.format(group_name), context=self)

    def get_all_groups_by_name(self) -> list:
        """
        return list of groups by their name from groups management page.
        :return: list
        """
        try:
            return [group.group_name.text for group in self.rows]
        except NoSuchElementException:
            return []

    def click_on_group(self, group_name: str) -> None:
        """
        Click on a particular group to view new group page
        :param str group_name: group name to click
        :return: None
        """
        for group in self.rows:
            if group.group_name.text == group_name:
                group.click()
                break
        else:
            log.warning('Group: %s not found in the list', group_name)

    def delete_group(self, group_name: str) -> None:
        """
        Delete a particular group from group management page
        :param str group_name: group name to be deleted
        :return: None
        """
        for group in self.rows:
            if group.group_name.text == group_name:
                group.delete_icon.click()
                action_modal = ActionCloseModal()
                action_modal.action_button.click()
                action_modal.wait_for_modal_closed()
                break
        else:
            log.warning('Delete failed: %s not found in the list', group_name)
