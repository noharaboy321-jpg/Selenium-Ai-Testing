""""
Nessus page classes for users in Settings page

:copyright: Tenable Network Security, 2017
:date: December 07, 2017
:last_modified: June 22, 2021
:author: @rdutta, @mameta, @kpanchal
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
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.wait import wait
from nessus.lib.const import API
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList
from nessus.pageobjects.my_account.my_account_page import AccountSettings, APIKeys

log = create_logger()


@cat_registry.route('settings/users/new')
class NewUserForm(NessusBasePage):
    """Page Object for New User Creation Page in Nessus."""

    username_field = Find(TextField, by=By.CSS_SELECTOR, value='.new-user-username')
    full_name_field = Find(TextField, by=By.CSS_SELECTOR, value='.new-user-fullname')
    email_field = Find(TextField, by=By.CSS_SELECTOR, value='.new-user-email')
    password_field = Find(TextField, by=By.CSS_SELECTOR, value='.new-user-password')
    password_confirm_field = Find(TextField, by=By.CSS_SELECTOR, value='.new-user-confirm-password')
    role_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.new-user-permissions-select')
    save_button = Find(value='users-save-user')
    ldap_username_field = Find(TextField, by=By.CSS_SELECTOR, value='.new-user-ldap')
    account_type_dropdown = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.new-user-type-select')
    cancel_button = Find(by=By.CSS_SELECTOR, value='.button.link.floatleft')
    required_badge = Find(by=By.CSS_SELECTOR, value='.required-badge')
    password_toggle_eye = Find(by=By.CSS_SELECTOR, value='.password-toggle.glyphicons.add-tip')

    def __init__(self):
        super().__init__()
        self.required_elements = ['username_field', 'save_button']

    def fill_user_form(self, **kwargs) -> None:
        """
        Fills the user form with mandatory field.
        :param kwargs: fill the provided value accordingly 
                    str user_name: user name
                    str full_name: full name of user
                    str email: email of user
                    str password: password
                    str role: user role
        :return: None
        """
        user_name = kwargs.get("user_name")
        full_name = kwargs.get("full_name")
        email = kwargs.get("email")
        password = kwargs.get("password")
        role = kwargs.get("role")

        if user_name:
            self.username_field.value = user_name
        if full_name:
            self.full_name_field.value = full_name
        if email:
            self.email_field.value = email
        if password:
            self.password_field.value = password
        if role:
            self.role_dropdown.select_by_visible_text(role)

        self.save_button.click()

    def fill_ldap_user_form(self, **kwargs) -> None:
        """
        Fills the ldap user form with mandatory field.
        :param kwargs: fill the provided value accordingly
                    str user_name: user name
                    str account_type: account type
                    str role: user role
        :return: None
        """
        acc_type = kwargs.get('account_type')
        ldap_user_name = kwargs.get("user_name")
        role = kwargs.get("role")

        self.account_type_dropdown.select_by_visible_text(acc_type)
        if ldap_user_name:
            self.ldap_username_field.value = ldap_user_name
        if role:
            self.role_dropdown.select_by_visible_text(role)

        self.save_button.click()

    def get_user_role_options(self) -> list:
        """
        get all the options under role drop down
        :return: list of user roles
        :rtype: list
        """
        return [self.role_dropdown.option_values[role_values]['label'] for role_values in
                range(len(self.role_dropdown.option_values))]


@cat_registry.route('settings/users')
class UsersPage(NessusBasePage):
    """Defines properties and methods inherited by the Nessus Users Page."""

    new_user_button = Find(Clickable, by=By.ID, value='settings-new-user')
    back_to_users = Find(Clickable, by=By.CSS_SELECTOR, value='.title-box a')
    select_all_checkbox = Find(CheckboxDiv, by=By.CLASS_NAME, value='select-all')
    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='#user-edit-account-save')
    remove_button = Find(by=By.CSS_SELECTOR, value='#groups-remove-user')
    delete_button = Find(Clickable, by=By.CSS_SELECTOR, value='#users-delete')
    search_box = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')
    total_user_record = Find(by=By.CSS_SELECTOR,
                             value='div[data-domselect*="Searchbox"] [data-domselect="Total Records"]')
    search_user_result = Find(by=By.CSS_SELECTOR, value='div[data-domselect*="Searchbox"] [data-domselect="Results"] b')
    no_record_found = Find(by=By.CSS_SELECTOR, value='.dataTables_empty')
    transfer_data_button = Find(Clickable, by=By.ID, value='users-transfer')
    transfer_ownership_checkbox = Find(CheckboxDiv, by=By.CSS_SELECTOR, value='.modal-checkbox')

    def __init__(self):
        super().__init__()
        self.required_elements = ['new_user_button', 'select_all_checkbox']

    def add_new_user(self, **kwargs) -> None:
        """
        Create a user by adding all user details coming in kwargs 
        :param kwargs: 
        """
        wait(lambda: self.is_element_present("new_user_button"), waiting_for="User page gets loaded")
        self.new_user_button.click()
        NewUserForm().fill_user_form(**kwargs)

    def add_ldap_user(self, **kwargs) -> None:
        """
        add ldap user by providing details coming from kwargs
        :return: None
        """
        self.new_user_button.click()
        NewUserForm().fill_ldap_user_form(**kwargs)

    def edit_user_account_settings(self, user_name: str, **kwargs) -> None:
        """
        Edit user's account settings according to the values in kwargs of the user
        :param str user_name: user whose details to edit
        :param kwargs: values to edit
        """
        UserList().click_on_user(user_name=user_name)
        account_page = AccountSettings()
        full_name = kwargs.get("full_name")
        email = kwargs.get("email")
        password = kwargs.get("password")
        role = kwargs.get("role")

        if full_name:
            account_page.full_name.clear()
            account_page.full_name.value = full_name
        if email:
            account_page.email.clear()
            account_page.email.value = email
        if password:
            account_page.new_password.clear()
            account_page.new_password.value = password
        if role:
            account_page.role.select_by_visible_text(role)

        self.save_button.click()
        if (role == API.User.Role.DISABLED) or (user_name.startswith(API.User.Role.DISABLED)):
            ActionCloseModal().action_button.click()

    @staticmethod
    def regenerate_user_api_keys(user_name: str) -> None:
        """
        Regenerate api keys value of the user
        :param str user_name: user whose details to edit
        """
        UserList().click_on_user(user_name=user_name)
        account_page = APIKeys()
        account_page.api_keys_tab.click()
        account_page.generate_api_keys()


class UserRecord(GenericTableRow):
    """Defines the key names for User Records returned by UserList."""

    select = Find(Checkbox, by=By.CSS_SELECTOR, value='div.checkbox')
    username = Find(by=By.CSS_SELECTOR, value='td.user-name')
    last_login = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    role = Find(by=By.CSS_SELECTOR, value='td:nth-child(4)')
    remove = Find(by=By.CSS_SELECTOR, value='td:nth-child(5)')

    @property
    def name(self):
        """ Returns name attribute of a row """
        return self.username.text

    @property
    def user_role(self):
        """ Returns user role attribute of a row """
        return self.role.text

    @property
    def users_last_login(self):
        """ Returns last login attribute of a row """
        return self.last_login.text


class UserList(ObjectList):
    """Returns a list containing Users displayed on the User Management Page."""
    configure_button = None
    object_table = Find(GenericBaseTable, value="content")
    generics_map = {GenericTableRow: UserRecord}

    def __init__(self):
        super().__init__()

    def get_specific_user_remove(self, username: str) -> Find:
        """
        get remove icon for specific user

        :param str username: username
        :return: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='tr[data-username="{}"] i[class*="remove"]'.format(username),
                    context=self)

    def get_specific_user_checkbox(self, user_name: str) -> Find:
        """
        get checkbox for specific user

        :param str user_name: user name
        :return: CheckboxDiv
        """
        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='tr[data-username="{}"] .checkbox'.format(user_name),
                    context=self)

    def delete_user(self, user_name: str) -> None:
        """
        Delete an user specified by user_name

        :param str user_name: name of the user to delete
        """
        for user in self.rows:
            if user.username.text == user_name:
                user.remove.click()
                ActionCloseModal().action_button.click()
                break
        else:
            log.warning('User name "%s" not found in the list', user_name)

    def get_all_users(self) -> list:
        """
        Returns the list of available users

        :return: list of all users
        :rtype: list
        """
        try:
            return [user.username.text for user in self.rows]
        except NoSuchElementException:
            return []

    def get_user_role(self, user_name: str) -> str:
        """
        Get user role

        :param str user_name: username
        :return: str
        """
        for user in self.rows:
            if user.username.text == user_name:
                return user.role.text
        else:
            log.warning('User name "%s" not found in the list', user_name)

    def click_on_user(self, user_name: str) -> None:
        """
        view user detail by clicking on it

        :param str user_name: user name
        :return: None
        """
        for user in self.rows:
            if user.username.text == user_name:
                user.click()
                break
        else:
            log.warning("User: '%s' not found in the user list", user_name)

    def get_all_roles_of_all_users(self) -> list:
        """
        list of roles for all available user's

        :return: list of user role
        :rtype: list
        """
        try:
            return [user.role.text for user in self.rows]
        except NoSuchElementException:
            return []

    def get_admin_sys_admin_checkbox_element(self, permission: str) -> Find:
        """
        Get checkbox for admin and system admin

        :param str permission: user role
        :return: Checkbox element of admin and system admin
        :rtype: WebElement
        """
        if permission == API.User.Role.SYS_ADMIN:
            permission = "128"
        elif permission == API.User.Role.ADMIN:
            permission = "64"

        return Find(CheckboxDiv, by=By.CSS_SELECTOR, value='tr[data-permissions="{}"] .null-checkbox'.format(
            permission), context=self)

    def get_last_login_time_of_users(self, user_name: str = None) -> list:
        """
        Returns the list of last login time of all available users

        :param str user_name: created user's name
        :return: list of last login time of all users
        :rtype: list
        """
        try:
            if user_name:
                return [user.users_last_login for user in self.rows if user.username.text == user_name]
            else:
                return [user.users_last_login for user in self.rows]
        except NoSuchElementException:
            return []
