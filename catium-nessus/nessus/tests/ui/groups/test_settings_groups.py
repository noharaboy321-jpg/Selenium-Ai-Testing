""""
Nessus test cases related to Settings-> Groups

:copyright: Tenable Network Security, 2017
:date: March 16, 2018
:last_modified: June 24, 2021
:author: @mameta, @kpanchal.ctr
"""
import time

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS, WAIT_NORMAL
from catium.lib.log import create_logger
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.groups import nessus_create_group
from nessus.helpers.sort import sort_on_column_values
from nessus.lib.config import NessusConfig
from nessus.lib.const import Prefixes, API, SortOrder
from nessus.lib.const.constants import Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.groups.groups_page import GroupsPage, GroupList, CreateGroupPage, NewGroupPage
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.pageobjects.users.users_page import NewUserForm, UsersPage
from nessus.pageobjects.users.users_page import UserList

log = create_logger()


@pytest.mark.nessus_settings_1
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestGroups:
    """
    Covers Groups related test cases
    NQA-1060 : Automation tests for Settings-Groups
    """
    current_epoch = str(int(time.time()))
    group_name = Prefixes.GROUP + ' ' + current_epoch
    group_two = Prefixes.GROUP + '_' + current_epoch

    basic_user = current_epoch + '-' + API.User.Users.BASIC_USER
    standard_user = current_epoch + '-' + API.User.Users.STANDARD_USER

    admin_user = random_name(prefix=API.User.Users.ADMIN_USER + ' - ')
    sys_admin_user = random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - ')

    test_data = {"user_details": {
        "Basic": {'user_name': basic_user, 'full_name': 'Basic user', 'email': API.User.Users.TEST_EMAIL,
                  'password': 'admin', 'role': API.User.Role.BASIC},
        "Administrator": {'user_name': admin_user, 'full_name': 'Admin user', 'email': API.User.Users.TEST_EMAIL,
                          'password': 'admin', 'role': API.User.Role.ADMIN},
        "System Administrator": {'user_name': sys_admin_user, 'full_name': 'SysAdmin user', 'password': 'admin',
                                 'email': API.User.Users.TEST_EMAIL, 'role': API.User.Role.SYS_ADMIN},
        "Standard": {'user_name': standard_user, 'full_name': 'Standard user', 'email': API.User.Users.TEST_EMAIL,
                     'password': 'admin', 'role': API.User.Role.STANDARD}}, "check_login": False}

    def test_group_page(self):
        """
        Navigate to groups page under settings, and verify that a 'New Group' button is present at the top right
        corner as well as “Create a new group” link on the same page when no groups are already present.
        Verify that the same pop-up opens on clicking the Create a new group page link and New Group button
        """
        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        assert group_page.new_group_button.is_displayed(), \
            "new group button in not present on ui at the top right corner"

        group_list = GroupList()

        if len(group_list.get_all_groups_by_name()) == 0:
            assert group_list.object_table.empty_results.text.rsplit(' ', 4)[0] == Messages.NotificationMessages. \
                Groups.empty_group_list, "Empty message is missing or mismatched."

            assert group_page.create_a_new_group_link.is_displayed(), "‘create a new group’ link is invisible."
        else:
            # pytest.skip("Group list is not empty, this can be tested only with empty group list.")
            pytest.xfail("Group list is not empty, this can be tested only with empty group list.")

        group_page.new_group_button.click()
        action_close_modal = ActionCloseModal()
        new_group_button_pop_up_text = action_close_modal.modal.text
        action_close_modal.cancel_button.click()
        action_close_modal.wait_for_modal_closed()

        group_page.create_a_new_group_link.click()
        create_a_new_group_pop_up = action_close_modal.modal.text
        action_close_modal.cancel_button.click()

        assert new_group_button_pop_up_text == create_a_new_group_pop_up, \
            "different pop-up opens on clicking the Create a new group link and New Group button"

    def test_new_group_pop_up(self):
        """
        Verify that the new group pop –up which opens on clicking New Group button has a name field with required badge.
        Verify that on clicking on Add button with empty name, error shows up.
        Verify that new group pop-up has a cancel button, and clicking on Cancel button,
        closes the pop-up and the group will not be created.
        """
        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        assert group_page.new_group_button.is_displayed(), \
            "new group button in not present on ui at the top right corner"

        group_page.new_group_button.click()
        create_group = CreateGroupPage()

        assert create_group.group_name.is_displayed(), "name field is not visible for new group"

        assert create_group.name_required_badge.is_displayed(), "name field doesn't have required badge"

        create_group.add_button.click()
        notifications = Notifications()

        assert notifications.errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "did not get error message"

        assert create_group.cancel_button.is_displayed(), "cancel button is not visible for create group pop up"

        create_group.cancel_button.click()

    def test_add_new_group(self):
        """
        Enter a valid name in the new group pop-up, and click on Add button, group must be created successfully
        and opens a new page having "Add User" button.
        """
        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        group_name = random_name(prefix='UserGroup-')
        group_page.create_new_user_group(group_name=group_name)

        new_group_page = NewGroupPage()
        wait(lambda: new_group_page.is_element_present("add_user_button"), waiting_for="Add User button to be visible")

        assert new_group_page.add_user_button.is_displayed(), \
            "add user button is not present on current page"

        new_group_page.back_to_groups.click()

        assert group_name in GroupList().get_all_groups_by_name(), \
            "created group is not available in group list"

    def test_delete_group(self):
        """
        Click on the X icon of the group created, a confirmation pop-up will appear.
        Click on Cancel button; dialog should disappear and group should not be deleted.
        Click on the X icon again, and verify confirmation pop-up is displayed. Click on Delete button and
        verify that group is deleted successfully with the notification and the group list is updated not to include
        the group and to have the new current group count.
        """
        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        group_name = random_name(prefix='UserGroup-')
        group_page.create_new_user_group(group_name=group_name)

        new_group_page = NewGroupPage()
        wait(lambda: new_group_page.is_element_present("add_user_button"), waiting_for="Add User button to be visible")

        new_group_page.back_to_groups.click()
        group_list = GroupList()
        group_list.get_specific_group_remove(group_name=group_name).click()
        action_modal = ActionCloseModal()

        assert all([action_modal.is_element_present(element_name='modal'),
                    action_modal.is_element_present(element_name='action_button'),
                    action_modal.is_element_present(element_name='cancel_button'),
                    action_modal.is_element_present(element_name='close_button')]), \
            '"Delete Group" pop-up is not visible after selecting single group.'

        assert action_modal.modal_title.text == Nessus.SideNavAccounts.Groups.DELETE_SINGLE_GROUP, \
            '"Delete Group" modal title is missing or mismatch.'

        assert action_modal.modal_content.text == Nessus.SideNavAccounts.Groups.DELETE_SINGLE_GROUP_WARNING, \
            '"Delete Groups" modal content is missing or mismatch.'

        action_modal.cancel_button.click()

        assert group_name in group_list.get_all_groups_by_name(), "group is not present in group list"

        group_list.get_specific_group_remove(group_name=group_name).click()
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()

        assert group_name not in group_list.get_all_groups_by_name(), \
            "group is still present in group list"

    @pytest.mark.parametrize("create_groups", [{
        'group_details': [{"group_name": group_name}, {"group_name": group_two}, {"group_name": random_name(
            prefix=Prefixes.GROUP)}, {"group_name": random_name(prefix=Prefixes.GROUP)}]}], indirect=True)
    def test_search_group(self, create_groups):
        """
        Verify Search box exists at the top of the list with number of groups count written next to the box.
        Verify that the list count is equal to the number displayed next to the search box.
        Verify that searching is based on name basis: enter any substring which exists in the list and
        check that the list is updated with search value.
        """
        group_page = GroupsPage()

        assert group_page.search_box.is_displayed(), "searchbox for groups is not available at the top of the list"

        assert group_page.total_group_record.is_displayed(), \
            "total number of groups count is not written next to the box."

        group_page.search_box.value = self.current_epoch
        group_list = GroupList().get_all_groups_by_name()

        assert len(group_list) == int(group_page.search_group_result.text), \
            "Count did not get updated after searching substring"

        assert [self.group_name, self.group_two] == group_list, \
            "searched groups are not in group list"

        group_page.remove_search_icon.click()
        wait(lambda: visibility_of_element_located(group_page.group_search_icon), waiting_for='Group search icon')

    @pytest.mark.parametrize("create_groups", [{
        'group_details': [{"group_name": random_name(prefix=Prefixes.GROUP), "unique_group": True},
                          {"group_name": random_name(prefix=Prefixes.GROUP), "unique_group": True}]}], indirect=True)
    def test_edit_group(self, create_groups):
        """
        Verify that edit (pencil) icon exists next to X-icon and on clicking the edit icon, edit pop-up will appear.
        Verify that edit pop-up has a name field already filled with group name. Clear the field and enter any other
            valid group name and click on save button. Group should be updated successfully.
        Attempt to edit a group to set name to an already existing name; verify an error is displayed
        and the name is not changed.
        """
        group_one, group_two = create_groups
        edit_username = self.current_epoch + "-user group"
        group_list = GroupList()
        group_list.loaded()

        assert group_list.get_specific_group_edit_icon(group_name=group_one).is_displayed(), \
            "edit (pencil) icon does not exists next to X-icon"

        group_page = GroupsPage()
        group_list.get_specific_group_edit_icon(group_name=group_one).click()

        assert group_page.modal.is_displayed(), "modal is not displayed after clicking on edit icon"

        assert group_page.group_name.get_attribute('value') == group_one, \
            "edit pop-up doest not have a name field already filled with group name"

        group_page.group_name.clear()
        group_page.group_name.value = group_two
        group_page.add_button.click()

        notifications = Notifications()

        assert notifications.errors[-1] == Messages.NotificationMessages.Groups.duplicate_group_name, \
            "did not get error message for duplicate group name"

        group_page.group_name.clear()
        group_page.group_name.value = edit_username
        group_page.add_button.click()

        assert notifications.successes[-1] == Messages.NotificationMessages.Groups.edit_group_name, \
            "did not get error message for edit group name"

        group_list.delete_group(edit_username)

    @pytest.mark.parametrize("create_groups", [{
        'group_details': [{"group_name": random_name(prefix=Prefixes.GROUP)},
                          {"group_name": random_name(prefix=Prefixes.GROUP)},
                          {"group_name": random_name(prefix=Prefixes.GROUP)}]}], indirect=True)
    def test_select_group(self, create_groups):
        """
        Verify that on selecting a row, Edit and Delete buttons appear next to the New Group button
        Verify that on selecting more than one row, the Delete button appears, but not the Edit button
        Verify that  on selecting the select-all checkbox, the Delete button appears next to New Group button,
                                                                                    but not the Edit button.
        Verify that on de-selecting all but one entry, both the Delete and Edit buttons appear.
        Verify that on de-selecting all entries, the Delete and Edit buttons disappear from beside the 'New Group' page.
        """
        group_one = create_groups[0]
        group_two = create_groups[1]
        group_page = GroupsPage()

        group_list = GroupList()
        group_list.get_specific_group_checkbox(group_one).check()

        assert group_page.edit_button.is_displayed(), "edit button is not visible for selected group"
        assert group_page.delete_button.is_displayed(), "delete button is not visible for selected group"

        group_list.get_specific_group_checkbox(group_two).check()
        assert group_page.delete_button.is_displayed(), "delete button is not visible for selected group"

        assert not group_page.is_element_present('edit_button'), "edit button is visible for selected group"

        group_page.select_all_checkbox.check()
        group_page.select_all_checkbox.check()

        assert group_page.delete_button.is_displayed(), "delete button is not visible for groups"

        assert not group_page.is_element_present('edit_button'), "edit button is visible for selected group"

        group_page.select_all_checkbox.check()
        group_list.get_specific_group_checkbox(group_one).check()

        assert group_page.edit_button.is_displayed(), "edit button is not visible for selected group"

        assert group_page.delete_button.is_displayed(), "delete button is not visible for selected group"

        group_list.get_specific_group_checkbox(group_one).uncheck()

        assert not group_page.is_element_present('edit_button'), "edit button is still visible after deselect the group"

        assert not group_page.is_element_present('delete_button'), \
            "delete button is still visible after deselect the group."

    @pytest.mark.parametrize("create_groups", [{
        'group_details': [{"group_name": random_name(prefix=Prefixes.GROUP)},
                          {"group_name": random_name(prefix=Prefixes.GROUP)},
                          {"group_name": random_name(prefix=Prefixes.GROUP)}]}], indirect=True)
    def test_delete_confirmation_popup(self, create_groups):
        """
        Verify that on selecting the select-all checkbox, a Delete button appears next to New Group button.
        Click on Delete and verify a confirmation pop-up appears. Accept the pop-up, and verify that all groups
        are deleted and list is not present any more
        """
        group_page = GroupsPage()
        group_page.select_all_checkbox.check()

        assert group_page.delete_button.is_displayed(), "delete button is not visible for group"

        group_page.delete_button.click()

        assert group_page.modal.is_displayed(), "confirmation popup does not appears for delete all group"

        group_page.action_button.click()

        assert len(GroupList().get_all_groups_by_name()) == 0, \
            "groups are not deleted after clicking on delete button"

    @pytest.mark.parametrize("create_user", [
        {'username': random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - '), 'password': 'password',
         'role': API.User.Role.SYS_ADMIN, 'do_login': False}], indirect=True)
    def test_member_count(self, create_user):
        """
        Verify that the number of members in the Member column is the same as number of users in group.
        """
        username = create_user[0]

        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        group_name = random_name(prefix='UserGroup-')
        group_page.create_new_user_group(group_name=group_name)

        new_group_page = NewGroupPage()
        wait(lambda: new_group_page.is_element_present("add_user_button"), waiting_for="Add User button to be visible")
        new_group_page.add_user_to_group(user_list=[username])

        new_group_page.back_to_groups.click()
        group_list = GroupList()
        group_list.loaded()

        group_member_count = int(group_list.get_specific_member_count(group_name).text)
        group_list.click_on_group(group_name)

        user_list = UserList()
        user_list.loaded()

        assert group_member_count == len(user_list.get_all_users()), \
            "member count is not equal to users available in the group."

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["Name", "Members"])
    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    @pytest.mark.parametrize("create_groups", [{
        'group_details': [{"group_name": random_name(prefix=Prefixes.GROUP),
                           "add_users": True, "user_list": [standard_user, sys_admin_user]},
                          {"group_name": random_name(prefix=Prefixes.GROUP),
                           "add_users": True, "user_list": [sys_admin_user]},
                          {"group_name": random_name(prefix=Prefixes.GROUP)}]}], indirect=True)
    def test_group_sort(self, create_users, create_groups, sort, column_to_sort):
        """
        Verify that sorting works as expected on the Name and Members columns
        """
        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        column_mapping = {"Name": "name", "Members": "member"}
        map_attribute = column_mapping[column_to_sort]

        group_list = GroupList()
        group_list.loaded()
        expected_group_list = sorted([getattr(group, map_attribute) for group in group_list.rows],
                                     key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

        rendered_group_list = sort_on_column_values(page_class_instance=group_list, column_name=column_to_sort,
                                                    sort=sort)

        assert expected_group_list == [getattr(group, map_attribute) for group in rendered_group_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

    @pytest.mark.parametrize("create_groups", [
        {'group_details': [{"group_name": group_name, "add_users": False}]}], indirect=True)
    def test_add_user_page(self, create_groups):
        """
        Click on the group created. Verify Add user page is opened, having Add User button on top right corner and
        a ‘Add a user’ link in the middle
        Verify that on clicking the Add User button or the 'Add a user' link , a pop-up appears having drop-down
        field containing all the users
        """
        group_list = GroupList()
        group_list.loaded()

        group_list.click_on_group(group_name=self.group_name)
        new_group_page = NewGroupPage()

        assert new_group_page.add_user_button.is_displayed(), \
            "new user button in not present on ui at the top right corner"

        user_list = UserList()
        user_list.loaded()

        if len(user_list.get_all_users()) == 0:
            assert user_list.object_table.empty_results.text.rsplit(' ', 3)[0] == Messages.NotificationMessages. \
                Users.empty_user_list, "Empty message is missing or mismatched."

            assert new_group_page.create_a_new_user_link.is_displayed(), "‘create a new user’ link is invisible."
        else:
            pytest.xfail("User list is not empty, this can be tested only with empty user list.")

        # verifying drop-down field containing all the users
        new_group_page.add_user_button.click()
        users_list_dd_by_button = new_group_page.get_all_users_from_dropdown()
        action_modal = ActionCloseModal()
        action_modal.close_button.click()

        new_group_page.create_a_new_user_link.click()
        users_list_dd_by_link = new_group_page.get_all_users_from_dropdown()
        action_modal.close_button.click()

        new_user_form = NewUserForm()
        new_user_form.open()
        new_user_form.cancel_button.click()
        users = user_list.get_all_users()

        assert len(users) == len(users_list_dd_by_button), "Drop down field doesn't contain all the users"

        assert len(users) == len(users_list_dd_by_link), "Drop down field doesn't contain all the users"

    @pytest.mark.parametrize("create_groups", [
        {'group_details': [{"group_name": group_name, "add_users": False}]}], indirect=True)
    def test_back_to_group_link_in_user_page(self, create_groups):
        """
        Verify that Add User page has group name written as ‘Groups/ [GroupName]’ at the top-left corner of the page
        and below it'll have a 'Back to Groups' page link. Verify 'Back to Groups' link returns to the group list page
        """
        group_list = GroupList()
        group_list.loaded()

        group_list.click_on_group(group_name=self.group_name)
        new_group_page = NewGroupPage()

        assert new_group_page.add_user_button.is_displayed(), "Add user button is not visible on ui"

        assert new_group_page.get_group_name_in_header == (
                Messages.NotificationMessages.Users.user_group_page_name + self.group_name), \
            "Name of user group page is different"

        assert new_group_page.is_element_present('back_to_groups'), "'Back to Groups' link is not displaying"

        new_group_page.back_to_groups.click()

        assert GroupsPage().is_element_present('new_group_button'), "User is unable to navigate to Groups page"

    @pytest.mark.parametrize("create_user", [
        {'username': sys_admin_user, 'password': 'password', 'role': API.User.Role.SYS_ADMIN, 'do_login': False}],
                             indirect=True)
    @pytest.mark.parametrize("create_groups", [
        {'group_details': [{"group_name": group_name, "add_users": False}]}], indirect=True)
    def test_adding_new_user(self, create_user, create_groups):
        """
        From Add User page, click on Add User button, select any one user from the dropdown and click on Save button.
        Verify user is added successfully and the list is updated with one row.
        """
        group_list = GroupList()
        group_list.loaded()

        group_list.click_on_group(group_name=self.group_name)
        group_user_page = NewGroupPage()
        group_user_page.add_user_to_group([self.sys_admin_user])
        all_users = UserList().get_all_users()

        assert self.sys_admin_user in all_users, "user did not added in group"

        assert len(all_users) == 1, "user list have more than one users"

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    @pytest.mark.parametrize("create_groups", [
        {'group_details': [{"group_name": group_name, "add_users": True, "user_list": [
            basic_user, standard_user, admin_user, sys_admin_user]}]}], indirect=True)
    def test_search_users_in_groups(self, create_users, create_groups):
        """
        Verify that searching is based on name basis, enter any substring which exists in the list and check that list
        is updated with members matching string.
        Verify that on searching, the count next to search box is updated with correct 'X of Y Users' string
        """
        group_page = GroupsPage()
        group_page.open()

        GroupList().click_on_group(group_name=self.group_name)

        group_page.search_box.value = self.current_epoch
        user_list = UserList().get_all_users()

        assert len(user_list) == int(group_page.search_group_result.text), \
            "Count did not get updated after searching substring"

        assert [self.basic_user, self.standard_user] == user_list, \
            "searched groups are not in group list"

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    @pytest.mark.parametrize("create_groups", [
        {'group_details': [{"group_name": group_name, "add_users": False}]}], indirect=True)
    def test_user_count(self, create_users, create_groups):
        """
        Verify that the dropdown does not contain any users which have already been added to the group.
        Verify that the user count written next to search box gets updated on adding another user.
        Verify that on clicking the X-icon of user row will give a confirmation pop-up, and clicking on Delete button
        deletes the user with notification that user was deleted successfully as well as the member count on
        the group page is reduced by 1.
        """
        UsersPage().open()

        user_list = UserList()
        total_users = user_list.get_all_users()
        new_group_page = NewGroupPage()

        # adding user and checking error message.
        GroupsPage().open()
        GroupList().click_on_group(group_name=self.group_name)
        new_group_page.add_user_to_group([self.basic_user])
        new_group_page.add_user_button.click()

        assert self.basic_user not in new_group_page.get_all_users_from_dropdown(), \
            "dropdown contains user which have already been added to the group"

        action_modal = ActionCloseModal()
        action_modal.close_button.click()
        user_count = new_group_page.get_current_count_of_users()

        new_group_page.add_user_to_group([total_users[1]])
        assert new_group_page.get_current_count_of_users() == (user_count + 1), \
            "user count written next to search box doesn't get updated on adding another user"

        # deleting user
        user_list.get_specific_user_remove(username=self.basic_user).click()
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()

        assert self.basic_user not in user_list.get_all_users(), "user is still present in group list"

        assert new_group_page.get_current_count_of_users() == user_count, \
            "No. of users is not reduced by 1"

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    @pytest.mark.parametrize("create_groups", [
        {'group_details': [{"group_name": group_name, "add_users": False}]}], indirect=True)
    def test_error_message_while_adding_user(self, create_users, create_groups):
        """
        Verify that on adding all the users available and then clicking on add user button will throw error that
        no user is available.
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page gets loaded")

        total_user = UserList().get_all_users()

        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        GroupList().click_on_group(group_name=self.group_name)
        new_group_page = NewGroupPage()
        wait(lambda: new_group_page.is_element_present("add_user_button"), waiting_for="Add User button to be visible")
        new_group_page.add_user_to_group(total_user)

        NotificationActions().remove_all()
        sleep(WAIT_NORMAL, reason="It takes little bit time to remove notifications and be visible 'Add User' button")
        new_group_page.add_user_button.click()

        notifications = Notifications()

        assert notifications.errors[-1] == Messages.NotificationMessages.Users.error_message, \
            "did not get error message for empty user list"

    @pytest.mark.parametrize("create_user", [
        {'username': sys_admin_user, 'password': 'password', 'role': API.User.Role.SYS_ADMIN, 'do_login': False}],
                             indirect=True)
    @pytest.mark.parametrize("create_groups", [
        {'group_details': [{"group_name": group_name, "add_users": False}]}], indirect=True)
    def test_select_group_user(self, create_user, create_groups):
        """
        Verify that on selecting the checkbox to the left of a row, the Delete button shows up next to
        the Add User button.
        Verify that de-selecting the checkbox causes the Delete button to disappear.
        Verify that on clicking the select-all checkbox, the Delete button is present next to Add User button.
        Verify clicking on Delete opens the confirmation pop-up, and upon confirming, all users are deleted
        from the group, the table is not present any more, and the ‘Add a user’ link appears on the page
        """
        user_page = UsersPage()
        user_page.open()

        user_list = UserList()
        total_user = user_list.get_all_users()

        group_page = GroupsPage()
        group_page.open()

        GroupList().click_on_group(group_name=self.group_name)

        # selecting the checkbox
        new_group_page = NewGroupPage()
        new_group_page.add_user_to_group(total_user)

        user_list.get_specific_user_checkbox(create_user[0]).check()
        assert user_page.remove_button.is_displayed(), "delete button is not visible for selected user"

        # de-selecting the checkbox
        user_list.get_specific_user_checkbox(create_user[0]).uncheck()

        # verify remove button is not available
        assert not user_page.is_element_present('remove_button'), \
            'remove button is still visible after deselect the user.'

        # clicking the select-all checkbox
        user_page.select_all_checkbox.check()
        assert user_page.remove_button.is_displayed(), "delete button is not visible for all selected user"

        user_page.remove_button.click()
        assert new_group_page.modal.is_displayed(), "confirmation pop up is not displayed"

        action_modal = ActionCloseModal()
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()

        assert new_group_page.create_a_new_user_link.is_displayed(), "add user link is not displaying"

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["Name", "Role", "Last Login"])
    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    @pytest.mark.parametrize("create_groups", [{
        'group_details': [{"group_name": group_name, "add_users": True, "user_list": [
            basic_user, standard_user, admin_user, sys_admin_user], "unique_group": True}]}], indirect=True)
    def test_sort_group_user_list(self, create_users, create_groups, sort, column_to_sort):
        """
        Test to sort list column values
        Verify that names under list are present in ascending order and on clicking the name column,
        list will get change to descending order.
        Verify that roles under list are present in ascending order and on clicking the Role column,
        list will get change to descending order.
        """
        column_mapping = {"Name": "name", "Last Login": "users_last_login", "Role": "user_role"}
        map_attribute = column_mapping[column_to_sort]

        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        group_name = create_groups[0]
        GroupList().click_on_group(group_name)
        users_list = UserList()
        users_list.loaded()

        expected_users_list = sorted([getattr(user, map_attribute) for user in users_list.rows],
                                     key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

        rendered_users_list = sort_on_column_values(page_class_instance=users_list, column_name=column_to_sort,
                                                    sort=sort)

        assert expected_users_list == [getattr(user, map_attribute) for user in rendered_users_list], \
            "{} is not sorted in {} order".format(column_to_sort, sort)

    @pytest.mark.parametrize("create_user", [
        {'username': sys_admin_user, 'password': 'password', 'role': API.User.Role.SYS_ADMIN, 'do_login': False}],
                             indirect=True)
    @pytest.mark.parametrize("create_groups", [{'group_details': [
        {"group_name": group_name, "add_users": False, "unique_group": True}]}], indirect=True)
    def test_user_member_navigation(self, create_user, create_groups):
        """
        Verify that clicking on a member row redirects to the User page, with a 'Back to Group' link at the top.
        (Note: Clicking on the current admin user redirects to the My Account page instead.)
        """
        user_page = UsersPage()
        user_page.open()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User list gets loaded")

        user_list = UserList()
        user_list.loaded()
        total_user = user_list.get_all_users()

        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box"), waiting_for="User group page gets loaded")

        GroupList().click_on_group(group_name=create_groups[0])
        new_group_page = NewGroupPage()
        wait(lambda: new_group_page.is_element_present("add_user_button"), waiting_for="Add User button to be visible")
        new_group_page.add_user_to_group(total_user)

        user_list.loaded()
        user_list.click_on_user(create_user[0])

        assert "Users /" in new_group_page.user_group_page_name.text, "did not navigate to users page"

        assert new_group_page.back_to_groups.is_displayed(), "'Back to Groups' link is not displaying"

        new_group_page.back_to_groups.click()
        wait(lambda: group_page.is_element_present("search_box"), waiting_for="User group page gets loaded")
        user_list.click_on_user(NessusConfig.CAT_NESSUS_USERNAME)

        assert '#/settings/my-account' in get_driver_no_init().current_url, \
            'Current url is incorrect for update the current user info'

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    @pytest.mark.parametrize("create_groups", [{
        'group_details': [{"add_users": True, "user_list": [admin_user, sys_admin_user], "unique_group": True},
                          {"add_users": True, "user_list": [basic_user, standard_user], "unique_group": True},
                          {"add_users": True, "user_list": [standard_user], "unique_group": True},
                          {"add_users": False, "unique_group": True}]}], indirect=True)
    def test_visibility_of_clear_selected_item_link(self, create_users, create_groups):
        """
        NES-11020: Add test coverage for User Groups page on Nessus UI

        Scenario tested:
        [x] Verify that "Clear selected Item" link is visible after selecting groups.
        """
        group_page = GroupsPage()
        group_list = GroupList()
        list_of_all_groups = create_groups[::2]

        for group in list_of_all_groups:
            group_list.get_specific_group_checkbox(group_name=group).check()

        wait(lambda: visibility_of_element_located(group_page.clear_selected_items_link),
             waiting_for="'Clear Selected Item' link to be visible.")

        assert group_page.is_element_present(element_name='clear_selected_items_link'), \
            "'Clear Selected Item' link is not visible after selecting the groups."

        group_page.clear_selected_items_link.click()

        for group in list_of_all_groups:
            assert not group_list.get_specific_group_checkbox(group_name=group).is_selected(), \
                'Group "{}" is still selected after clicking on "Clear Selected Item" link.'

    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    @pytest.mark.parametrize("create_groups", [{
        'group_details': [{"add_users": True, "user_list": [admin_user, sys_admin_user], "unique_group": True},
                          {"add_users": True, "user_list": [basic_user, standard_user], "unique_group": True},
                          {"add_users": False, "unique_group": True}]}], indirect=True)
    def test_bulk_user_group_delete(self, create_users, create_groups):
        """
        NES-11020: Add test coverage for User Groups page on Nessus UI

        Scenario tested:
        [x] Delete user groups in bulk using "Delete" button on user groups page.
        """
        created_groups = create_groups
        group_list = GroupList()

        for group in created_groups:
            group_list.get_specific_group_checkbox(group_name=group).check()

        group_page = GroupsPage()
        wait(lambda: visibility_of_element_located(group_page.clear_selected_items_link),
             waiting_for="'Clear Selected Item' link to be visible.")

        assert group_page.is_element_present(element_name='clear_selected_items_link'), \
            "'Clear Selected Item' link is not visible after selecting all groups."

        assert group_page.is_element_present(element_name='delete_button'), \
            '"Delete" button is not visible on top right corner after selecting the groups.'

        group_page.delete_button.click()
        action_modal = ActionCloseModal()

        assert all([action_modal.is_element_present(element_name='modal'),
                    action_modal.is_element_present(element_name='action_button'),
                    action_modal.is_element_present(element_name='cancel_button'),
                    action_modal.is_element_present(element_name='close_button')]), \
            '"Delete Groups" pop-up is not visible after selecting multiple or all groups.'

        assert action_modal.modal_title.text == Nessus.SideNavAccounts.Groups.DELETE_MULTIPLE_GROUP, \
            '"Delete Groups" modal title is missing or mismatch.'

        assert action_modal.modal_content.text == Nessus.SideNavAccounts.Groups.DELETE_MULTIPLE_GROUP_WARNING, \
            '"Delete Groups" modal content is missing or mismatch.'

        action_modal.accept_action()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Groups.delete_bulk_groups, \
            "Success notification message for deleted group is missing or mismatch."

        assert all([group_name not in group_list.get_all_groups_by_name() for group_name in create_groups]), \
            'Groups are not deleted successfully in bulk by using "Delete" button.'

    @pytest.mark.parametrize("group_count", ["single", "multiple"])
    def test_visibility_of_edit_and_delete_buttons_for_single_and_multiple_group(self, group_count):
        """
        NES-13152 [Automation]: Verify that "Edit" and "Delete" buttons are displayed for each group

        Scenario Tested:
        [x] Verify that "Edit" and "Delete" buttons should be display after selecting single group.
        [x] Verify the "Edit Group" and "Delete Group" popups after selecting single group.
        [x] Verify that only "Delete" button should be display after selecting multiple groups.
        [x] Verify the "Delete Groups" popup after selecting multiple groups.
        """
        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        created_group_details = []
        group_list = GroupList()

        try:
            for _ in range(3):
                nessus_api = NessusAPI()
                nessus_api.login()

                group_detail = nessus_create_group(api=nessus_api)
                created_group_details.append(group_detail['name'])

                if group_count == "single":
                    break

            group_list.refresh()
            group_list.loaded()
            edit_or_delete_group_modal = ActionCloseModal()

            if group_count == "single":
                single_group_name = created_group_details[0]
                group_list.get_specific_group_checkbox(group_name=single_group_name).check()
                wait(lambda: group_list.get_specific_group_checkbox(group_name=single_group_name).is_selected(),
                     waiting_for="User group to be selected")

                assert group_page.is_element_present("edit_button"), \
                    "'Edit' button is missing on top right corner after selecting single user group."

                group_page.edit_button.click()
                wait(lambda: edit_or_delete_group_modal.is_element_present("modal"), waiting_for="'Edit Group' popup")

                assert all([edit_or_delete_group_modal.modal_title.text == "Edit Group",
                            group_page.is_element_present("group_name"),
                            group_page.group_name.get_attribute('value') == single_group_name,
                            edit_or_delete_group_modal.is_element_present("action_button"),
                            edit_or_delete_group_modal.is_element_present("cancel_button")]), \
                    "'Edit Group' pop up is either not opened or displayed properly after clicking on 'Edit' button."

                edit_or_delete_group_modal.cancel_button.click()
                edit_or_delete_group_modal.wait_for_modal_closed()
            else:
                [group_list.get_specific_group_checkbox(group_name=group_name).check() for group_name in
                 created_group_details]

                assert all(
                    [group_list.get_specific_group_checkbox(group_name=group_name).is_selected() for group_name in
                     created_group_details]), "Group are not getting selected after clicking on checkbox."

                assert not group_page.is_element_present("edit_button"), \
                    "'Edit' button is still visible on top right corner even after selecting multiple user groups."

            assert group_page.is_element_present("delete_button"), \
                "'Delete' button is missing on top right corner after selecting single/multiple user group."

            group_page.delete_button.click()
            wait(lambda: edit_or_delete_group_modal.is_element_present("modal"), waiting_for="'Delete Group' popup")

            expected_modal_title = Nessus.SideNavAccounts.Groups.DELETE_SINGLE_GROUP if group_count == "single" else \
                Nessus.SideNavAccounts.Groups.DELETE_MULTIPLE_GROUP

            expected_modal_warning = Nessus.SideNavAccounts.Groups.DELETE_SINGLE_GROUP_WARNING if \
                group_count == "single" else Nessus.SideNavAccounts.Groups.DELETE_MULTIPLE_GROUP_WARNING

            assert all([edit_or_delete_group_modal.modal_title.text == expected_modal_title,
                        edit_or_delete_group_modal.modal_content.text == expected_modal_warning,
                        edit_or_delete_group_modal.is_element_present("action_button"),
                        edit_or_delete_group_modal.is_element_present("cancel_button")]), \
                "'Delete Group' pop up is either not opened or displayed properly after clicking on 'Delete' button."

            edit_or_delete_group_modal.cancel_button.click()
            edit_or_delete_group_modal.wait_for_modal_closed()
        finally:
            [group_list.delete_group(group_name=group_name) for group_name in created_group_details]
            NotificationActions().remove_all()

    @pytest.mark.xray(test_key='NES-15342')
    @pytest.mark.xfail(reason='Refer Jira ID NES-13155')
    @pytest.mark.parametrize("create_users", [test_data], indirect=True)
    @pytest.mark.parametrize("create_groups", [
        {'group_details': [{"add_users": True, "user_list": [basic_user, standard_user, admin_user, sys_admin_user],
                            "unique_group": True}]}], indirect=True)
    def test_visibility_of_remove_button_after_removing_users_from_group(self, create_users, create_groups):
        """
        NES-13153 [Automation]: Verify that "Remove" button is not displayed on UI after deleting users one by one by
        clicking 'x' sign.
        NES-15342 : Verify that from user group, on deleting users one-by-one by first selecting
        them and clicking 'x' sign then Remove buttons should not be displayed on UI

        Scenario Tested:
        [x] Verify that "Remove" button is not displayed on UI after deleting users from group one by one by
            clicking 'x' sign.
        """
        created_group_name = create_groups[0]

        group_list = GroupList()
        group_list.loaded()
        group_list.click_on_group(group_name=created_group_name)

        user_page = UsersPage()
        wait(lambda: user_page.is_element_present("search_box"), waiting_for="User group page gets loaded")

        GroupsPage().select_all_checkbox.check()
        user_list = UserList()
        remove_user_modal = ActionCloseModal()

        for user_role in [API.User.Role.STANDARD, API.User.Role.SYS_ADMIN, API.User.Role.ADMIN, API.User.Role.BASIC]:
            user_list.get_specific_user_remove(username=create_users[user_role]['user_name']).click()
            wait(lambda: remove_user_modal.is_element_present("modal"), waiting_for="'Remove User' modal")

            assert all([remove_user_modal.modal_title.text == Nessus.SideNavAccounts.Groups.REMOVE_USER,
                        remove_user_modal.modal_content.text == Nessus.SideNavAccounts.Groups.REMOVE_USER_WARNING,
                        remove_user_modal.is_element_present("action_button"),
                        remove_user_modal.is_element_present("cancel_button")]), \
                "'Remove User' pop up is either not opened or displayed properly after clicking on 'x' sign."

            remove_user_modal.action_button.click()
            remove_user_modal.wait_for_modal_closed()

            notifications = Notifications()

            assert notifications.successes[-1] == Messages.NotificationMessages.Groups.remove_user, \
                'Success notifications for saving scan is mismatched or missing.'

        assert user_page.is_element_present("remove_button"), \
            "'Remove' button is visible yet after removing all users from group."

    def test_duplicate_group(self):
        """
        Enter an already existing group name in the New Group pop-up and click on Add button,
        it will throw an error “Error: A group with that name already exists”
        """
        group_page = GroupsPage()
        group_page.open()
        wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
            "create_a_new_group_link"), waiting_for="User group page gets loaded")

        group_name = random_name(prefix='UserGroup-')
        group_page.create_new_user_group(group_name=group_name)

        new_group_page = NewGroupPage()
        wait(lambda: new_group_page.is_element_present("add_user_button"), waiting_for="Add User button to be visible")
        new_group_page.back_to_groups.click()

        group_page.create_new_user_group(group_name=group_name)
        notifications = Notifications()

        assert notifications.errors[-1] == Messages.NotificationMessages.Groups.duplicate_group_name, \
            "did not get error message"

        group_page.cancel_button.click()


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.usefixtures('login')
class TestGroupsOnNessusProAndLegacy:
    """
    test Groups tab on Nessus Professional 7 or Nessus Legacy
    """

    def test_groups_tab(self):
        """
        Verify that on navigating to the settings page, the Groups tab is not displayed,
        and group creation is not allowed.
        """
        if not invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()):
            log.info('welcome to Nessus Pro Pop up is visible')
            action_close_modal = ActionCloseModal()
            action_close_modal.close_button.click()
            action_close_modal.wait_for_modal_closed()

        HeaderBasePage().settings_link.click()
        wait(lambda: OverView().is_element_present("nessus_version"), timeout_seconds=TIME_THIRTY_SECONDS * 2,
             waiting_for='about overview page gets load properly.')

        assert 'Groups' not in SideNav().get_all_sidenav_links(), \
            "Groups tab is available in side navigation for this Nessus Version"
