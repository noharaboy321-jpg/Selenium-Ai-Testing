"""
Nessus test cases related to Upgrade Assistant Page

:copyright: Tenable Network Security, 2019
:date: Aug 20, 2019
:last_modified: Oct 10, 2019
:author: @kpanchal
"""

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.lib.util.util import generate_request_uuid
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.lib.const.constants import Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.upgrade_assistant.upgrade_assistant_page import UpgradeAssistantPage


@pytest.mark.nessus_settings_2
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestUpgradeAssistantPage:
    """Test class covers Upgrade Assistant page related Test Cases"""

    def test_upgrade_process_page(self):
        """
        NES-9707: UI Automation: Verify Upgrade to Tenable.io upgrade process page
        NES-9697: UI Automation: Verify Upgrade Assistant page

        Steps:
        3. Click 'Upgrade Now' button under 'I have a Tenable.io account' option
        4. Verify upgrade process page opens with 4 field options -
            i. Access Key
            ii. Secret Key
            iii. Tenable.io Domain
            iv. Nessus Identifier
        5. Verify tooltip popups when hover mouse over '?' icon with each field text-box

        Scenario Tested:
        [x] Verify that upgrade page opens on clicking 'Upgrade Now' button
        [x] Verify that tooltip should popup with info message when hover mouse over '?' icon with each field
        """
        upgrade_assistant_page = UpgradeAssistantPage()
        upgrade_assistant_page.open()
        wait(lambda: visibility_of_element_located(upgrade_assistant_page.upgrade_now_button),
             waiting_for='Upgrade Assistant page to load')

        assert upgrade_assistant_page.is_element_present('upgrade_now_button'), '\'Upgrade Now\' button is not ' \
                                                                                'displayed in Upgrade Assistant Page.'

        upgrade_assistant_page.upgrade_now_button.click()

        upgrade_process_fields = {
            Nessus.UpgradeAssistant.ACCESS_KEY: ['access_key', Nessus.UpgradeAssistant.ACCESS_KEY_TOOLTIP],
            Nessus.UpgradeAssistant.SECRET_KEY: ['secret_key', Nessus.UpgradeAssistant.SECRET_KEY_TOOLTIP],
            Nessus.UpgradeAssistant.TENABLE_IO_DOMAIN: ['tenable_io_domain',
                                                        Nessus.UpgradeAssistant.TENABLE_IO_DOMAIN_TOOLTIP],
            Nessus.UpgradeAssistant.NESSUS_IDENTIFIER: ['nessus_identifier',
                                                        Nessus.UpgradeAssistant.NESSUS_IDENTIFIER_TOOLTIP]}

        for field_name, field_element in upgrade_process_fields.items():
            assert upgrade_assistant_page.is_element_present(field_element[0]), 'Upgrade process field \'{}\' is not ' \
                                                                                'displayed.'.format(field_name)

            tooltip_element = upgrade_assistant_page.get_tool_tip_element(element_name=field_name)
            upgrade_assistant_page.move_to_element(element=tooltip_element)

            assert tooltip_element.get_attribute(name='original-title') == field_element[1], \
                'Getting incorrect tooltip message for \'{}\''.format(field_name)

        assert all([upgrade_assistant_page.is_element_present('upgrade_button'),
                    upgrade_assistant_page.is_element_present('cancel_button')]), \
            '\'Upgrade\' or \'Cancel\' button is not displayed in Upgrade Assistant Page.'

    def test_sign_up_first_button(self):
        """
        NES-9707: UI Automation: Verify Upgrade to Tenable.io upgrade process page
        NES-9697: UI Automation: Verify Upgrade Assistant page

        Steps:
        1. Navigate to Scans > Upgrade Assistant page
        2. Click 'Sign Up First' button - it should open https://www.tenable.com/products/tenable-io/evaluate in new tab

        Scenario Tested:
        [x] Verify that https://www.tenable.com/products/tenable-io/evaluate page url should open in separate tab when
            'Sign Up First' button is clicked
        [x] Verify new Tenable.io account can be created from 'Sign Up First' button
        """
        upgrade_assistant_page = UpgradeAssistantPage()
        upgrade_assistant_page.open()
        wait(lambda: visibility_of_element_located(upgrade_assistant_page.sign_up_first_button),
             waiting_for='Upgrade Assistant page to load')

        assert upgrade_assistant_page.is_element_present('sign_up_first_button'), '\'Sign Up First\' button is not ' \
                                                                                  'displayed in Upgrade Assistant Page.'

        upgrade_assistant_page.sign_up_first_button.click()

        assert upgrade_assistant_page.switch_window_and_get_url() == Nessus.UpgradeAssistant.SIGN_UP_URL, \
            'Getting incorrect Sign Up URL. Expected URL is \'{}\''.format(Nessus.UpgradeAssistant.SIGN_UP_URL)

    @pytest.mark.parametrize('required_upgrade_field', ['access_key', 'secret_key', 'tenable_io_domain'])
    def test_mandatory_field_validation(self, required_upgrade_field):
        """
        NES-9707: UI Automation: Verify Upgrade to Tenable.io upgrade process page

        Scenarios Tested:
        [x] Verify validation message displayed for mandatory fields "Access Key", "Secret Key" and "Tenable.io Domain".
        """
        upgrade_assistant_page = UpgradeAssistantPage()
        upgrade_assistant_page.open()

        wait(lambda: visibility_of_element_located(upgrade_assistant_page.upgrade_now_button),
             waiting_for='Upgrade Assistant page to load')
        upgrade_assistant_page.upgrade_now_button.click()

        # Update required upgrade field value to blank
        upgrade_details = {'access_key': generate_request_uuid() * 2, 'secret_key': generate_request_uuid() * 2,
                           'tenable_io_domain': 'us-2b.svc.nessus.org', 'nessus_instance': '127.0.0.1'}
        upgrade_details.update({required_upgrade_field: ''})

        # Fill upgrade details and click on 'Upgrade' button
        upgrade_assistant_page.fill_upgrade_details(**upgrade_details)

        upgrade_field_elements = {
            'access_key': [upgrade_assistant_page.access_key,
                           Messages.NotificationMessages.UpgradeAssistant.invalid_access_key],
            'secret_key': [upgrade_assistant_page.secret_key,
                           Messages.NotificationMessages.UpgradeAssistant.invalid_secret_key],
            'tenable_io_domain': [upgrade_assistant_page.tenable_io_domain,
                                  Messages.NotificationMessages.UpgradeAssistant.invalid_domain]}

        upgrade_field_details = upgrade_field_elements.get(required_upgrade_field)
        upgrade_assistant_page.upgrade_button.click()

        # Verify error notification message on keeping blank required upgrade field value
        assert Notifications().errors[-1] == upgrade_field_details[1], \
            'Getting incorrect error notification, Expected is \'{}.\''.format(upgrade_field_details[1])

        # Verify required upgrade field is highlighted with 'Red' color border when user leaves it blank.
        assert 'error' in upgrade_field_details[0].get_css_classes(), \
            '{} required upgrade field is not highlighted with \'Red\' color border.'.format(required_upgrade_field)

    def test_upgrade_confirm_pop_up_modal(self):
        """
        NES-9707: UI Automation: Verify Upgrade to Tenable.io upgrade process page

        Steps:
        7. Fill all mandatory detail and click 'Upgrade' button - should display warning popup
        8. Clicking 'Cancel' button should discard the warning popup

        Scenarios Tested:
        [x] Verify that 'Confirm Upgrade' popup should open with warning message on clicking 'Upgrade' button.
        """
        upgrade_assistant_page = UpgradeAssistantPage()
        upgrade_assistant_page.open()

        # Click on 'Upgrade Now' button
        wait(lambda: visibility_of_element_located(upgrade_assistant_page.upgrade_now_button),
             waiting_for='Upgrade Assistant page to load')
        upgrade_assistant_page.upgrade_now_button.click()

        upgrade_details = {'access_key': generate_request_uuid() * 2, 'secret_key': generate_request_uuid() * 2,
                           'tenable_io_domain': 'us-2b.svc.nessus.org', 'nessus_instance': '127.0.0.1'}

        # Fill upgrade details and click on 'Upgrade' button
        upgrade_assistant_page.fill_upgrade_details(**upgrade_details)
        upgrade_assistant_page.upgrade_button.click()
        confirm_upgrade_modal = ActionCloseModal()

        # Verify 'Continue' and 'Cancel' buttons are displayed in 'Confirm Upgrade' modal
        assert all([confirm_upgrade_modal.is_element_present('modal'),
                    confirm_upgrade_modal.is_element_present('action_button'),
                    confirm_upgrade_modal.is_element_present('cancel_button')]), \
            '\'Confirm Upgrade\' modal is not displayed properly.'

        # Verify 'Confirm Upgrade' modal title
        assert confirm_upgrade_modal.modal_title.text == Nessus.UpgradeAssistant.CONFIRM_UPGRADE, \
            'Getting incorrect modal title. Expected title is \'{}\''.format(Nessus.UpgradeAssistant.CONFIRM_UPGRADE)

        # Verify 'Confirm Upgrade' modal content
        assert confirm_upgrade_modal.modal_content.text == Nessus.UpgradeAssistant.CONFIRM_UPGRADE_MODAL_CONTENT, \
            'Getting incorrect modal content. Expected content is \'{}\''.format(Nessus.UpgradeAssistant.
                                                                                 CONFIRM_UPGRADE_MODAL_CONTENT)

        # Verify 'Confirm Upgrade' modal warning
        assert confirm_upgrade_modal.modal_warning.text == Nessus.UpgradeAssistant.CONFIRM_UPGRADE_WARNING, \
            'Getting incorrect modal warning. Expected warning is \'{}\''.format(Nessus.UpgradeAssistant.
                                                                                 CONFIRM_UPGRADE_WARNING)

        confirm_upgrade_modal.cancel_button.click()

        # Verify 'Confirm Upgrade' modal is displayed after clicking on 'Cancel' button
        assert not confirm_upgrade_modal.is_element_present('modal'), \
            '\'Confirm Upgrade\' modal is still displayed after clicking on \'Cancel\' button.'

    def test_upgrade_assistant_page_content(self):
        """
        NES-9697: UI Automation: Verify Upgrade Assistant page

        Steps:
        1. Go to Upgrade Assistant page from Settings
        2. Verify description text visible on Upgrade to Tenable.io table
        3. Verify 2 options:
            - I have a Tenable.io account with 'Upgrade Now' button and
            - I need a Tenable.io account with 'Sign Up First' button

        Scenario Tested:
        [x] Verify content on Upgrade Assistant page
        """
        upgrade_assistant_page = UpgradeAssistantPage()
        upgrade_assistant_page.open()
        wait(lambda: visibility_of_element_located(upgrade_assistant_page.upgrade_now_button),
             waiting_for='Upgrade Assistant page to load')

        # Verify that Upgrade Assistant page description is displayed
        assert upgrade_assistant_page.is_element_present('upgrade_assistant_description'), \
            '\'Upgrade Assistant\' page description is not present.'

        # Verify the Upgrade Assistant page description message
        assert upgrade_assistant_page.upgrade_assistant_description.text == Nessus.UpgradeAssistant. \
            UPGRADE_ASSISTANT_DESCRIPTION, 'Getting incorrect description.'

        buttons_description = upgrade_assistant_page.upgrade_buttons_description

        # Verify that description is displayed above the 'Upgrade Now' button
        assert visibility_of_element_located((buttons_description[0].we_by, buttons_description[0].we_value))(
            get_driver_no_init()), 'Description is not present above \'Upgrade Now\' button.'

        # Verify the 'Upgrade Now' description message
        assert buttons_description[0].text == Nessus.UpgradeAssistant.UPGRADDDE_NOW_DESCRIPTION, \
            'Getting incorrect description for \'Upgrade Now\' button.'

        # Verify that 'Upgrade Now' button is displayed
        assert upgrade_assistant_page.is_element_present('upgrade_now_button'), \
            '\'Upgrade Now\' button is not displayed in Upgrade Assistant Page.'

        # Verify that description is displayed above the 'Sign Up First' button
        assert visibility_of_element_located((buttons_description[1].we_by, buttons_description[1].we_value))(
            get_driver_no_init()), 'Description is not present above \'Sign Up First\' button.'

        # Verify the 'Sign Up First' description message
        assert buttons_description[1].text == Nessus.UpgradeAssistant.SIGN_UP_FIRST_DESCRIPTION, \
            'Getting incorrect description for \'Sign Up First\' button.'

        # Verify that 'Sign Up First' button is displayed
        assert upgrade_assistant_page.is_element_present('sign_up_first_button'), \
            '\'Sign Up First\' button is not displayed in Upgrade Assistant Page.'
