""""
Nessus page classes for My Account page

:copyright: Tenable Network Security, 2017
:date: January 08, 2018
:last_modified: Aug 23, 2019
:author: @rdutta, @smadan, @kpanchal
"""

from selenium.webdriver.common.by import By

from catium.lib.cat_registry import cat_registry
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.select2dropdown import Select2Dropdown
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.wait import wait
from nessus.lib.message.messages import Messages
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.notifications import Notifications

log = create_logger()


@cat_registry.route('settings/my-account')
class MyAccount(NessusBasePage):
    """Page Object class for My Account page in Nessus."""

    account_settings_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Account Settings"]')
    api_keys_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="API Keys"]')


class AccountSettings(MyAccount):
    """Page Object Class for account settings in My Account page in Nessus."""

    my_account_title = Find(by=By.CSS_SELECTOR, value='.title-box h1')
    full_name = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Full Name"]')
    email = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Email"]')
    current_password = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="Current Password"]')
    new_password = Find(TextField, by=By.CSS_SELECTOR, value='input[data-domselect="New Password"]')
    show_password_eye = Find(Clickable, by=By.CSS_SELECTOR, value='i[data-domselect="Show Password"]')
    role = Find(Select2Dropdown, by=By.CSS_SELECTOR, value='.form-group select[data-domselect="Role"]')
    password_title = Find(by=By.CSS_SELECTOR, value='div:nth-child(7) > label')
    password_description = Find(by=By.CSS_SELECTOR, value='.group-description')

    save_button = Find(Clickable, by=By.CSS_SELECTOR, value='#save')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='#cancel')
    user_edit_save_button = Find(Clickable, by=By.CSS_SELECTOR, value='#user-edit-account-save')
    user_edit_cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='.button.link.floatleft')
    back_to_users_link = Find(by=By.CSS_SELECTOR, value='.title-box a')

    def show_password_enabled(self) -> bool:
        """
        Returns true if show password eye icon is enabled
        :return bool: True if 'enabled' is found from 'class' attributes
        """
        return 'enabled' in self.show_password_eye.get_attribute('class')

    def save_email(self, email_value: str) -> None:
        """
        Save email address
        :param str email_value: Email value to save
        """
        self.email.clear()
        self.email.send_keys(email_value)
        self.save_button.click()

    def change_password(self, current_password: str, new_password: str) -> None:
        """
        Changes the current password
        :param str current_password: current password value
        :param str new_password: new password value
        """
        self.current_password.clear()
        self.current_password.send_keys(current_password)
        self.new_password.clear()
        self.new_password.send_keys(new_password)
        self.save_button.click()

    def change_full_name(self, name: str) -> None:
        """
        Changes full name of user

        :param str name: Full name of User
        :return: None
        """
        self.full_name.clear()
        self.full_name.send_keys(name)
        self.save_button.click()


@cat_registry.route(r'api-keys')
class APIKeys(MyAccount):
    """Page Object Class for api keys in My Account page in Nessus."""

    generate_button = Find(Clickable, by=By.CSS_SELECTOR, value='.generate-keys.button.secondary.floatleft')
    api_documentation_link = Find(Clickable, by=By.CSS_SELECTOR, value='.description-copy.noselect.pt5 a')
    access_key_field = Find(by=By.CSS_SELECTOR, value='.no-edit.access-key')
    secret_key_field = Find(by=By.CSS_SELECTOR, value='.no-edit.secret-key')

    @property
    def access_key(self) -> str:
        """
        Return access key displayed in the page.
        :return: access key as text
        """
        return self.access_key_field.text

    @property
    def secret_key(self) -> str:
        """
        Return secret key displayed in the page.
        :return: secret key as text
        """
        return self.secret_key_field.text

    def generate_api_keys(self) -> None:
        """Generate the api keys."""
        self.generate_button.click()
        actionclosemodal = ActionCloseModal()
        actionclosemodal.accept_action()
        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.api_keys_generation, \
            "did not get message for api keys generation"
        actionclosemodal.wait_for_modal_closed()


class GenerateAPIKeysModal(ActionCloseModal):
    """Modal shown when generating new API keys to inform user that previous API keys will be deactivated."""

    modal_title = Find(by=By.CSS_SELECTOR, value='.modal-title')

    def __init__(self):
        super().__init__()

    @property
    def get_modal_title(self) -> str:
        """
        Will return the title displayed on modal popup.
        :return: modal title as text
        """
        return self.modal_title.text
