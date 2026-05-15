""""
Nessus test cases related to Master password tab in about page under Settings

:copyright: Tenable Network Security, 2017
:date: Feb 13, 2018
:last_modified: May 26, 2021
:author: @rdutta, @smadan, @kpanchal
"""

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located

from catium.lib.const.base_constants import TIME_THIRTY_SECONDS
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.lib.config import NessusConfig
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import MasterPassword, OverView
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications


@pytest.mark.nessus_settings_1
@pytest.mark.serial
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestMasterPassword:
    """
    Covers "Master Password" tab related test cases in about page under Settings.
    # NQA-1056 : automation test for Settings - About-Master_password.
    """

    def test_master_password_cancel_button(self):
        """
        Test cancel link on Master Password Tab under About Page.
        1. Navigate to Master Password tab.
        2. Get master password if already set.
        3. Enter new password and click on cancel button.
        4. Verify it should take you to overview tab.
        5. Again navigate to Master Password tab and verify password remains same.
        """
        about_master_page = MasterPassword()
        about_master_page.open()

        about_master_page.new_password_field.value = 'master'
        about_master_page.cancel_button.click()

        assert get_driver_no_init().current_url == '{}/#/settings/about'.format(NessusConfig.CAT_NESSUS_URL), \
            "Cancel button does not work"

        about_master_page.encryption_password_tab.click()

        if about_master_page.is_element_present('existing_password_field'):
            about_master_page.set_master_password(existing_password='master')

    def test_eyeball_icon(self):
        """
        Test eyeball icon on Master Password Tab under About Page.
        1. Verify presence of eyeball icon next to password field.
        2. Verify icon changes on click.
        3. Verify password is shown/hidden.
        """
        about_master_page = MasterPassword()
        about_master_page.open()

        assert about_master_page.eyeball_icon.is_displayed(), "Eyeball icon is not present"

        about_master_page.new_password_field.value = 'master'
        previous_input_type = about_master_page.get_new_password_input_type()

        assert about_master_page.is_eye_icon_enabled(), 'Hide password is not enabled'

        about_master_page.eyeball_icon.click()

        assert not about_master_page.is_eye_icon_enabled(), 'Show password is not enabled'

        assert previous_input_type != about_master_page.get_new_password_input_type(), \
            "Password shown/hidden does not change on clicking eyeball icon"

    def test_set_master_password(self):
        """
        Test to set a new master password.
        1. Enter new password and click on save button.
        2. Password should be saved with success notification.
        3. Again navigate to Master password tab and verify there are two password fields now (existing password’
           field and ‘new password’).
        """
        about_master_page = MasterPassword()
        about_master_page.open()

        if about_master_page.is_element_present('existing_password_field'):
            pytest.xfail('Master Password is already set.')

        try:
            about_master_page.set_master_password(new_password='master')

            assert Notifications().successes[-1] == Messages.NotificationMessages.About. \
                master_password_saved_successfully, "Master password is not saved"

            assert about_master_page.new_password_field.is_displayed(), "New password field is not visible"

            assert about_master_page.existing_password_field.is_displayed(), "Existing password field is not visible"
        finally:
            about_master_page.set_master_password(existing_password='master')

    def test_correct_existing_master_password(self):
        """
        1. Enter password in ‘existing password’ field and leave ‘new password’ blank.
        2. Clicking on save button should save password and there is only one password field
        3. Verify notification displays successful update
        """
        about_master_page = MasterPassword()
        about_master_page.open()

        try:
            about_master_page.set_master_password(new_password='master')

            wait(lambda: visibility_of_element_located(about_master_page.existing_password_field),
                 waiting_for='Existing password field to be visible.')
            about_master_page.set_master_password(existing_password='master')

            assert Notifications().successes[-1] == Messages.NotificationMessages. \
                About.master_password_saved_successfully, "Master password is not saved"

            wait(lambda: invisibility_of_element_located((By.CSS_SELECTOR, 'input[data-name="Old Password"]'))(
                get_driver_no_init()), waiting_for='Existing Password textfield to be invisible.')
            assert about_master_page.new_password_field.is_displayed(), "New password field is not visible"

            assert not about_master_page.is_element_present('existing_password_field'), \
                'Existing password field is still present'
        finally:
            about_master_page.set_master_password(existing_password='master')

    def test_incorrect_existing_master_password(self):
        """
        Test incorrect master password gives you error notification.
        1. Enter incorrect password into ‘existing password’ and leave ‘new password’ field blank.
        2. Click on save and verify two password field remains.
        3. Verify notification display incorrect password entered.
        """
        about_master_page = MasterPassword()
        about_master_page.open()
        about_master_page.loaded()

        if not about_master_page.is_element_present('existing_password_field'):
            about_master_page.set_master_password(new_password='master')

        wait(lambda: visibility_of_element_located(about_master_page.existing_password_field),
             waiting_for='Existing password field to be visible.')

        about_master_page.set_master_password(existing_password='incorrect')
        notification = Notifications()

        assert notification.errors[-1] == Messages.NotificationMessages.Users.invalid_master_password, \
            "Expected %s" % Messages.NotificationMessages.Users.invalid_master_password

        assert about_master_page.new_password_field.is_displayed(), "New password field is not visible"

        assert about_master_page.existing_password_field.is_displayed(), "Existing password field is not visible"

    @pytest.mark.parametrize('change_master_password', [{'existing_password': "master", 'new_password': "master1"}],
                             indirect=True)
    def test_change_master_password(self, change_master_password):
        """
        1. Enter correct password into ‘existing password’ and new password in ‘new password’ field.
        2. Click on save. Verify two password field remains
        3. Verify notification displays successful update
        """
        about_master_page = MasterPassword()
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages. \
            About.master_password_saved_successfully, "Master password is not saved"

        assert about_master_page.new_password_field.is_displayed(), "New password field is not visible"

        assert about_master_page.existing_password_field.is_displayed(), "Existing password field is not visible"

        about_master_page.existing_password_field.value = change_master_password['new_password']
        about_master_page.save_button.click()
        wait(lambda: invisibility_of_element_located((By.CSS_SELECTOR, 'input[data-name="Old Password"]'))(
            get_driver_no_init()), waiting_for='Existing Password textfield to be invisible.')

        assert not about_master_page.is_element_present('existing_password_field'), \
            'Existing password field is still present'

    def test_encryption_password_in_description(self):
        """
        NES-13052 [Automation]: Verify inclusive language changes for Encryption Password

        Scenario Tested:
        [x] Verify that Encryption Password should display instead of Master password in description.
        """
        about_master_page = MasterPassword()
        about_master_page.open()
        wait(lambda: about_master_page.is_element_present("encryption_pwd_description"),
             waiting_for="Encryption password page get loaded")

        assert about_master_page.is_element_present("encryption_pwd_desc_icon"), \
            "Encryption password description icon is missing."

        description_content = about_master_page.encryption_pwd_description.text

        assert all([about_master_page.is_element_present("encryption_pwd_description"),
                    len(description_content) > 0]), "Encryption password description block is missing or empty."

        assert all([bool(filter(lambda x: 'encryption' in x, description_content)),
                    bool(filter(lambda x: 'master' not in x, description_content))]), \
            "'Master Password' has not been replaced with 'Encryption password' in description content."

    def test_encryption_password_in_url(self):
        """
        NES-13052 [Automation]: Verify inclusive language changes for Encryption Password

        Scenario Tested:
        [x] Verify the "Encryption Password" in the URL when you access the Encryption Password in the settings tab
            of the About section.
        """
        HeaderBasePage().settings_link.click()

        about_overview = OverView()
        wait(lambda: about_overview.is_element_present("nessus_version"), timeout_seconds=TIME_THIRTY_SECONDS * 2,
             waiting_for='about overview page gets load properly.')

        about_overview.encryption_password_tab.click()

        about_master_page = MasterPassword()
        wait(lambda: about_master_page.is_element_present("encryption_pwd_description"),
             waiting_for="Encryption password page get loaded")

        assert "encryption-password" in about_master_page.current_url, \
            "'Master password' did not replaced with 'Encryption password' in the page URL."
