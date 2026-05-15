"""
Remote Link related test case

:copyright: Tenable Network Security, 2019
:date: Oct 10, 2019
:last_modified: Oct 15, 2019
:author: @kpanchal
"""

import pytest

from catium.lib.util.util import generate_request_uuid, random_name
from catium.lib.webium.wait import wait
from nessus.lib.const.constants import Nessus, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.remote_link.remote_link_page import RemoteLinkPage


@pytest.mark.nessus_settings_2
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestRemoteLinkPage:
    """ Test class covers Remote Link page related Test Cases """

    def test_visibility_of_default_elements(self):
        """
        NES-9743: UI Automation: Remote link | Verify validation of remote link options

        Steps:
        1. Navigate to Settings > Remote link
        2. Turn ON remote link toggle > user should be able to see file options which are used for linking process
           (Link to, Scanner Name, Linking key, Use Proxy checkbox)
        3. Verify that 'Link to' has two options 'Tenable.io'(Default) and 'Nessus Manager'
        """
        remote_link_page = RemoteLinkPage()
        remote_link_page.open()
        wait(lambda: remote_link_page.is_element_present('toggle_switch'), waiting_for='Remote link page to load')

        # Verify that Remote Link description is displayed
        assert remote_link_page.is_element_present('remote_link_description'), 'Description is not present on ' \
                                                                               '\'Remote Link\' page.'

        # Verify that toggle switch is displayed
        assert remote_link_page.is_element_present('toggle_switch'), 'Toggle switch is not displayed.'

        remote_link_page.toggle_switch.toggle()

        remote_link_fields = {
            Nessus.RemoteLink.LINK_TO: 'link_to_dropdown', Nessus.RemoteLink.SCANNER_NAME: 'scanner_name',
            Nessus.RemoteLink.LINKING_KEY: 'linking_key', Nessus.RemoteLink.USE_PROXY: 'use_proxy_checkbox'}

        # Verify that 'Link to', 'Scanner Name', 'Linking key' and 'Use Proxy' checkbox is displayed
        for field_name, field_element in remote_link_fields.items():
            assert remote_link_page.is_element_present(field_element), '\'{}\' field option is not displayed.'.format(
                field_name)

        # Verify that default selected option is 'Tenable.io'
        assert remote_link_page.link_to_dropdown.get_text_selected() == Nessus.RemoteLink.TENABLE_IO, \
            'In Link to drop-down, \'Tenable.io\' option is not selected by-default.'

        remote_link_page.link_to_dropdown.click()

        # Verify that 'Tenable.io' and 'Nessus Manager' options are displayed in 'Link to' dropdown
        assert all([option.text == Nessus.RemoteLink.LINK_TO_OPTIONS for option in remote_link_page.link_to_dropdown.
                   get_options()]), '\'Tenable.io\' and \'Nessus Manager\' options are not displayed in \'Link to\' ' \
                                    'drop-down.'

    def test_visibility_of_elements_for_nm_linking(self):
        """
        NES-9743: UI Automation: Remote link | Verify validation of remote link options
        """
        remote_link_page = RemoteLinkPage()
        remote_link_page.open()
        wait(lambda: remote_link_page.is_element_present('toggle_switch'), waiting_for='Remote link page to load')

        remote_link_page.toggle_switch.toggle()
        remote_link_page.link_to_dropdown.select_by_visible_text(Nessus.RemoteLink.NESSUS_MANAGER)

        nm_linking_fields = {
            Nessus.RemoteLink.LINK_TO: 'link_to_dropdown', Nessus.RemoteLink.SCANNER_NAME: 'scanner_name',
            Nessus.RemoteLink.MANAGER_HOST: 'manager_host', Nessus.RemoteLink.MANAGER_PORT: 'manager_port',
            Nessus.RemoteLink.LINKING_KEY: 'linking_key', Nessus.RemoteLink.USE_PROXY: 'use_proxy_checkbox'}

        # Verify that 'Link to', 'Scanner Name', 'Manager Host', 'Manager Port', 'Linking key' and 'Use Proxy' checkbox
        # is displayed for Nessus Manager linking
        for field_name, field_element in nm_linking_fields.items():
            assert remote_link_page.is_element_present(field_element), \
                '\'{}\' field option is not displayed for Nessus Manager linking.'.format(field_name)

    @pytest.mark.parametrize('required_linking_field', ['scanner_name', 'linking_key'])
    def test_mandatory_field_for_tenable_io_linking(self, required_linking_field):
        """
        NES-9743: UI Automation: Remote link | Verify validation of remote link options

        Steps:
        4. For linking to T.io, "Linking Key" and "Scanner Name" are mandatory and on missing any of them it should
           give a validation message

        Scenario Tested:
        [x] Verify that on linking to T.io, 'Linking Key' and 'Scanner Name' are mandatory and on missing any of them
            it should give a validation message.
        """
        remote_link_page = RemoteLinkPage()
        remote_link_page.open()
        wait(lambda: remote_link_page.is_element_present('toggle_switch'), waiting_for='Remote link page to load')

        required_linking_details = {'link_to': Nessus.RemoteLink.TENABLE_IO, 'linking_key': generate_request_uuid() * 2,
                                    'scanner_name': random_name(prefix="Test_Remote_scanner-")}

        # Update required setting field value to blank
        required_linking_details.update({required_linking_field: ''})

        # Turn on toggle switch and fill required linking field details
        remote_link_page.toggle_switch.toggle()
        remote_link_page.add_linking_settings(**required_linking_details)
        remote_link_page.save_button.click()

        notification = Notifications()


        # Verify error notification message on keeping blank required linking field value
        assert notification.errors[-1] == Messages.NotificationMessages.continue_button_code, \
            'Getting incorrect error notification, Expected is \'{}.\''.format(
                Messages.NotificationMessages.continue_button_code)

    @pytest.mark.parametrize('required_linking_field', ['scanner_name', 'manager_host', 'manager_port', 'linking_key'])
    def test_mandatory_field_for_nessus_manager_linking(self, required_linking_field):
        """
        NES-9743: UI Automation: Remote link | Verify validation of remote link options

        Steps:
        5. For linking to NM, Manager Host, Manager Port, Linking Key and Scanner Name are mandatory and on missing any
           of them it should give a validation message

        Scenario Tested:
        [x] Verify that on linking to NM, 'Manager Host', 'Manager Port', 'Linking Key' and 'Scanner Name' are mandatory
            and on missing any of them it should give a validation message.
        """
        remote_link_page = RemoteLinkPage()
        remote_link_page.open()
        wait(lambda: remote_link_page.is_element_present('toggle_switch'), waiting_for='Remote link page to load')

        required_linking_details = {
            'link_to': Nessus.RemoteLink.NESSUS_MANAGER, 'linking_key': generate_request_uuid() * 2,
            'manager_host': API.Settings.ProxyServer.PROXY_HOST, 'manager_port': API.Settings.ProxyServer.PROXY_PORT,
            'scanner_name': random_name(prefix="Test_Remote_scanner-")}

        # Update required setting field value to blank
        required_linking_details.update({required_linking_field: ''})

        # Turn on toggle switch and fill required linking field details
        remote_link_page.toggle_switch.toggle()
        remote_link_page.add_linking_settings(**required_linking_details)
        remote_link_page.save_button.click()

        notification = Notifications()


        # Verify error notification message on keeping blank required linking field value
        assert notification.errors[-1] == Messages.NotificationMessages.continue_button_code, \
            'Getting incorrect error notification, Expected is \'{}.\''.format(
                Messages.NotificationMessages.continue_button_code)

    def test_error_message_on_invalid_linking_key_for_tenable_io(self):
        """
        NES-9743: UI Automation: Remote link | Verify validation of remote link options

        Steps:
        6. If a linking from T.io account is invalid / expired then validation message should be pop up on saving it.

        Scenario Tested:
        [x] Verify the validation message for invalid linking key while linking to 'Tenable.io'.
        """
        remote_link_page = RemoteLinkPage()
        remote_link_page.open()
        wait(lambda: remote_link_page.is_element_present('toggle_switch'), waiting_for='Remote link page to load')

        required_linking_details = {'link_to': Nessus.RemoteLink.TENABLE_IO, 'linking_key': generate_request_uuid() * 2,
                                    'scanner_name': random_name(prefix="Test_Remote_scanner-")}

        # Turn on toggle switch and fill required linking field details
        remote_link_page.toggle_switch.toggle()
        remote_link_page.add_linking_settings(**required_linking_details)
        remote_link_page.save_button.click()

        notification = Notifications()


        # Verify error notification message for invalid linking key while linking to 'Tenable.io' or 'Nessus Manager'
        assert notification.errors[-1] == Messages.NotificationMessages.tenable_io_linking_error, \
            'Getting incorrect error notification, Expected is \'{}.\''.format(Messages.NotificationMessages.
                                                                               tenable_io_linking_error)
