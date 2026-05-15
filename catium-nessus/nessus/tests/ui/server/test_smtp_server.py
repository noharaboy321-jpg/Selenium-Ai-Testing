"""
Nessus SMTP Server related test cases

:copyright: Tenable Network Security, 2017
:date: Jan 23, 2018
:last_modified: Jan 31, 2022
:author: @jamreliya, @kpanchal
"""

import re

import pytest
import requests
from selenium.webdriver.common.keys import Keys

from catium.helpers.sleep_lib import sleep
from catium.lib.const import WAIT_SHORT
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_TEN_MINUTES, TIME_THIRTY_SECONDS
from catium.lib.const.mailcatcher_constants import Mailcatcher
from catium.lib.log.log import create_logger
from catium.lib.mailcatcher.retrieve_mail import MailRetriever
from catium.lib.util.util import random_name, load_testdata
from catium.lib.webium.wait import wait
from nessus.helpers.advanced_settings import get_color_code_of_ui_element
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import get_scan_id
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const.constants import API, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import SetEmailModal, ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.server.smtpserver.smtp_server_page import SmtpServerPage
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.fixture()
def set_default_smtp_settings(nessus_api_handler):
    """ Set SMTP server settings to default settings """
    settings_dict = load_testdata(filename='nessus/tests/api/nessus_qa/test_data/test_nessus_communication.json')[
        "default_smtp_settings"]

    nessus_api_handler.settings.set_smtp_settings(settings=settings_dict)


@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'set_default_smtp_settings', 'login')
class TestSmtpServer:
    """ LDAP Test Cases NQA - 1058 Automation tests for Settings - SMTP """

    cat = None

    @pytest.mark.xray(test_key='NES-14134')
    def test_verify_default_value_of_encryption_and_auth_method(self):
        """
        NES-13671 [Automation]: Verify SMTP server settings by entering invalid port details
        NES-14134 : Verify default dropdown values for encryption and auth method

        Scenario's Tested:
        [x] Verify that "NONE" should be default value of auth method drop-down.
        [x] Verify that "No Encryption" should be default value of Encryption drop-down.
        """
        smtp_server_page = SmtpServerPage()
        smtp_server_page.open()

        actual_selected_encryption = smtp_server_page.encryption.get_text_selected()
        expected_encryption = API.Settings.Smtp.SMTP_NO_ENCRYPT

        assert actual_selected_encryption == expected_encryption, \
            "Got incorrect default auth method '{}'. Expected auth method is :: '{}'".format(
                actual_selected_encryption, expected_encryption)

        actual_selected_auth_method = smtp_server_page.auth_dropdown.get_text_selected()
        expected_auth_method = API.Settings.Smtp.SMTP_NONE

        assert actual_selected_auth_method == expected_auth_method, \
            "Got incorrect default auth method '{}'. Expected auth method is :: '{}'".format(
                actual_selected_auth_method, expected_auth_method)

    @pytest.mark.xray(test_key='NES-14564')
    @pytest.mark.parametrize("invalid_port", ["", 0, 65536, "abed", "6vv3vi"])
    def test_validation_for_smtp_server_port_field(self, invalid_port):
        """
        NES-13671 [Automation]: Verify SMTP server settings by entering invalid port details
        NES-14564 : Verify by entering invalid port details

        Scenario's Tested:
        [x] Verify that port field should highlight with red color border for invalid port value.
        """
        smtp_server_page = SmtpServerPage()
        smtp_server_page.open()

        smtp_server_page.port_field.clear()
        port_to_enter = invalid_port if invalid_port else Keys.SPACE
        smtp_server_page.port_field.value = port_to_enter
        sleep(WAIT_SHORT, reason="It takes little bit time to highlight the field for error")

        assert 'error' in smtp_server_page.port_field.get_css_classes(), \
            "'Ports to capture' field is not highlighting with red border even after entering " \
            "invalid port '{}'.".format(invalid_port)

        assert get_color_code_of_ui_element(element=smtp_server_page.port_field,
                                            css_property='border-color') in ['#DD4B50', '#FF5959'], \
            "Port input field is not getting highlighted with red color border for '{}' value.".format(invalid_port)

    @pytest.mark.xray(test_key='NES-14319')
    @pytest.mark.parametrize("save_setting", [False, True])
    def test_save_smtp_server_setting(self, save_setting):
        """
        NQA - 1058 Automation tests for Settings - SMTP
        NES-13671 [Automation]: Verify SMTP server settings by entering invalid port details

        Scenario's Tested:
        [x] Verify that settings should not be saved if user clicks on 'Cancel' button even after entering correct
            setting values.
        [x] Verify that giving correct information and Click on save, settings should be saved successfully.
        """
        smtp_server_page = SmtpServerPage()
        smtp_server_page.open()

        smtp_server_settings = {
            'host': API.Settings.Smtp.SMTP_HOST, 'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL,
            'port': API.Settings.Smtp.SMTP_PORT, 'host_name': API.Settings.Smtp.SMTP_HOST_NAME}

        smtp_server_page.add_smtp_settings(**smtp_server_settings)

        if save_setting:
            smtp_server_page.save_settings.click()

            assert Notifications().successes[-1] == Messages.NotificationMessages.saved_smtp_settings, \
                'Success Notification is missing.'

            side_nav = SideNav()
            side_nav.click_by_link_text(link_text='Proxy Server')
            side_nav.click_by_link_text(link_text='SMTP Server')

            assert smtp_server_page.get_smtp_server_settings() == SmtpServerPage.sanitize_smtp_server_settings(
                smtp_data=smtp_server_settings), 'SMTP server settings not saved'
        else:
            smtp_server_page.cancel_button.click()
            sleep(WAIT_NORMAL, reason="Settings takes little bit time to get reset")

            actual_smtp_server_setting = smtp_server_page.get_smtp_server_settings()

            expected_setting_values = {'host': '', 'port': '', 'auth_method': 'NONE', 'sender_email': '',
                                       'encryption': 'No Encryption', 'host_name': ''}

            assert actual_smtp_server_setting == expected_setting_values, \
                "SMTP server setting value got saved even though clicking on 'Cancel' button which should not be."

    @pytest.mark.parametrize('sender_email_value', [
        pytest.param('', marks=pytest.mark.xfail(reason='Refer Jira ID NES-7924')), 'test@tenable', 'abc', '12345',
        'tenable.com'])
    def test_save_invalid_email_smtp_server_setting(self, sender_email_value):
        """
        NQA - 1058 Automation tests for Settings - SMTP

        NES-9751: UI Automation: Server | Check that all mandatory fields should highlighted in Red border on saving
                  the settings (eg. From (sender email))

        Steps:
        1. Navigate to Settings -> SMTP Server
        2. Enter valid “Host”(For eg. smtp.lab.tenablesecurity.com) and “Port”(For eg. 25) details and leave
           “From (sender email)” field blank
        3. Click on “Save” button

        Scenario Tested:
        [x] Verify that it should display proper required field validation message if user keeps “From (sender email)”
            field blank
        [x] Verify that on entering invalid email, input box turned to red color border
        """
        # Go to SMTP server page
        smtp_server_page = SmtpServerPage()
        smtp_server_page.open()

        # Add required SMTP server settings
        smtp_server_page.add_smtp_settings(host=API.Settings.Smtp.SMTP_HOST, port=API.Settings.Smtp.SMTP_PORT,
                                           sender_email=sender_email_value, host_name=API.Settings.Smtp.SMTP_HOST_NAME)

        # Verify 'From (sender email)' field is highlighted with 'Red' color border when user enters invalid mail format
        if sender_email_value:
            assert 'error' in smtp_server_page.sender_email.get_css_classes(), \
                "'From (sender email)' field is not highlighted with 'Red' color border."

        # Click on save button and wait for error message to populate
        smtp_server_page.save_settings.click()

        # Verify error notification message after entering invalid or blank email value
        assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
            'SMTP server settings not saved due to invalid email format.'

        # Verify 'From (sender email)' field is highlighted with 'Red' color border after saving the settings with
        # blank 'From (sender email)' field.
        if not sender_email_value:
            assert 'error' in smtp_server_page.sender_email.get_css_classes(), \
                '\'From (sender email)\' field is not highlighted with \'Red\' color border.'

    @pytest.mark.ie
    def test_email_format_smtp_server_setting(self):
        """
        Verify email address follow rfc5322 standard
        NQA - 1058 Automation tests for Settings - SMTP
        """
        smtp_server_page = SmtpServerPage()
        smtp_server_page.open()

        smtp_server_page.add_smtp_settings(host=API.Settings.Smtp.SMTP_HOST, port=API.Settings.Smtp.SMTP_PORT,
                                           sender_email=API.Settings.Smtp.SMTP_SENDER_EMAIL,
                                           host_name=API.Settings.Smtp.SMTP_HOST_NAME)

        rfc5322_std_format = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

        assert rfc5322_std_format.match(smtp_server_page.sender_email.value), \
            'Sender Email address is not valid'

    @pytest.mark.ie
    @pytest.mark.parametrize("add_smtp_server_settings", [
        {'encryption': API.Settings.Smtp.SMTP_FORCE_SSL}, {'encryption': API.Settings.Smtp.SMTP_USE_TLS},
        {'encryption': API.Settings.Smtp.SMTP_FORCE_TLS}, {'encryption': API.Settings.Smtp.SMTP_NO_ENCRYPT}],
                             indirect=True)
    def test_save_encryption_choice_smtp_settings(self, add_smtp_server_settings):
        """
        Verify encryption options: No encryption, Force SSL, Use TLS are available and
        encryption choice saves successfully.
        NQA - 1058 Automation tests for Settings - SMTP
        """
        smtp_server_page = SmtpServerPage()
        encryption_list = [element['label'] for element in smtp_server_page.encryption.option_values]

        assert encryption_list == API.Settings.Smtp.SMTP_ENCRYPTION_TYPE, \
            'There is some change in Encryption option. check available Encryption options'

        assert smtp_server_page.get_smtp_server_settings()['encryption'] == add_smtp_server_settings['encryption'], \
            'Selected Encryption value is not saved'

    @pytest.mark.xray(test_key='NES-14520')
    @pytest.mark.ie
    def test_check_auth_method_smtp_settings(self):
        """
        Verify different auth method : None, Plain, Login, NTLM, CRAM-MD5 are available.
        NQA - 1058 Automation tests for Settings - SMTP
        """
        smtp_server_page = SmtpServerPage()
        smtp_server_page.open()

        auth_list = [element['label'] for element in smtp_server_page.auth_dropdown.option_values]

        assert auth_list == API.Settings.Smtp.SMTP_AUTH_TYPE, \
            'here is some change in auth method. check available auth methods'

    @pytest.mark.parametrize("add_smtp_server_settings", [
        {'host': API.Settings.Smtp.SMTP_HOST, 'port': API.Settings.Smtp.SMTP_PORT,
         'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL, 'auth_method': API.Settings.Smtp.SMTP_LOGIN,
         'encryption': API.Settings.Smtp.SMTP_NO_ENCRYPT, 'smtp_user': 'admin', 'smtp_password': 'password',
         'host_name': API.Settings.Smtp.SMTP_HOST_NAME}], indirect=True)
    def test_save_auth_method_smtp_server_setting(self, add_smtp_server_settings):
        """
        Verify that username/password credentials supplied for Auth methods (other than None) are saved successfully.
        NQA - 1058 Automation tests for Settings - SMTP
        """
        assert Notifications().successes[-1] == Messages.NotificationMessages.saved_smtp_settings, \
            'Success Notification is missing.'

        side_nav = SideNav()
        side_nav.click_by_link_text(link_text='Proxy Server')
        side_nav.click_by_link_text(link_text='SMTP Server')

        assert SmtpServerPage().get_smtp_server_settings() == SmtpServerPage.sanitize_smtp_server_settings(
            smtp_data=add_smtp_server_settings), 'SMTP server settings with login auth method not saved'

    @pytest.mark.xray(test_key='NES-14177')
    @pytest.mark.parametrize("add_smtp_server_settings", [
        {'host': API.Settings.Smtp.SMTP_HOST, 'port': API.Settings.Smtp.SMTP_PORT,
         'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL, 'host_name': API.Settings.Smtp.SMTP_HOST_NAME}],
                             indirect=True)
    @pytest.mark.parametrize("send_email", [False, True])
    def test_check_send_email_setting(self, add_smtp_server_settings, send_email):
        """
        Test SMTP server settings: NQA - 1058 Automation tests for Settings - SMTP
        NES-13671 [Automation]: Verify SMTP server settings by entering invalid port details

        Scenario's Tested:
        [x] Verify that 'Send Test Email' popup should discard and stop the process after clicking on 'Cancel' button.
        """
        notification = Notifications()

        assert notification.successes[-1] == Messages.NotificationMessages.saved_smtp_settings, \
            'Success Notification is missing.'

        HeaderBasePage().clear_notification_history()
        sleep(WAIT_NORMAL, reason="It takes little bit time to get clear notification history.")
        SmtpServerPage().send_test_email.click()
        set_email_modal = SetEmailModal()

        assert set_email_modal.unsaved_changes_title.text == 'Send Test Email', \
            'Send Test Mail pop up did not appear'

        if send_email:
            recipient_mail = 'xyz@tenable.com'
            set_email_modal.set_email(email=recipient_mail)

            assert notification.successes[-1] == Messages.NotificationMessages.smtp_email_sent + recipient_mail, \
                'Success Notification is either missing or mismatched.'
        else:
            set_email_modal.cancel_button.click()

            assert not ActionCloseModal().is_element_present("modal"), \
                "'Send Test Email' modal is still getting visible even after clicking on cancel button."

    @pytest.mark.parametrize("add_smtp_server_settings", [
        {'host': API.Settings.Smtp.SMTP_HOST, 'port': API.Settings.Smtp.SMTP_PORT,
         'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL, 'host_name': API.Settings.Smtp.SMTP_HOST_NAME}],
                             indirect=True)
    def test_remove_smtp_server_setting(self, add_smtp_server_settings):
        """
        Remove all SMTP server settings, and save. Navigate to any other page,
        come back to SMTP Server page and verify settings have all been removed.
        NQA - 1058 Automation tests for Settings - SMTP
        """
        assert Notifications().successes[-1] == Messages.NotificationMessages.saved_smtp_settings, \
            'Success Notification is missing.'

        smtp_server_page = SmtpServerPage()
        smtp_server_page.add_smtp_settings(host_name='', port='', sender_email='', host='')
        smtp_server_page.save_settings.click()

        side_nav = SideNav()
        side_nav.click_by_link_text(link_text='Proxy Server')
        side_nav.click_by_link_text(link_text='SMTP Server')
        empty_smtp_data = {'host': '', 'port': '', 'sender_email': '', 'encryption': 'No Encryption',
                           'host_name': '', 'auth_method': 'NONE'}

        assert SmtpServerPage().get_smtp_server_settings() == empty_smtp_data, 'SMTP server settings not removed'

    @pytest.mark.xray(test_key='NES-14193')
    def test_cancel_smtp_server_setting(self):
        """
        NES-14193 :Verify cancel button of SMTP works
        """

        smtp_server_page = SmtpServerPage()

        smtp_server_page.open()
        smtp_server_page.add_smtp_settings(host_name='', port='', sender_email='', host='')
        smtp_server_page.save_settings.click()

        smtp_server_settings = {
            'host': API.Settings.Smtp.SMTP_HOST, 'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL,
            'port': API.Settings.Smtp.SMTP_PORT, 'host_name': API.Settings.Smtp.SMTP_HOST_NAME}

        smtp_server_page.add_smtp_settings(**smtp_server_settings)

        smtp_server_page.cancel_button.click()

        empty_smtp_data = {'host': '', 'port': '', 'sender_email': '', 'encryption': 'No Encryption',
                           'host_name': '', 'auth_method': 'NONE'}
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for fields to get cleared')
        assert SmtpServerPage().get_smtp_server_settings() == empty_smtp_data, 'SMTP server settings not removed'

    @pytest.mark.xray(test_key='NES-14176')
    @pytest.mark.parametrize("add_smtp_server_settings", [
        {'host': API.Settings.Smtp.SMTP_HOST, 'port': API.Settings.Smtp.SMTP_PORT,
         'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL, 'host_name': API.Settings.Smtp.SMTP_HOST_NAME}],
                             indirect=True)
    def test_cancel_on_send_test_email(self, add_smtp_server_settings):
        """
        NES-14176 : Verify cancel button of send test mail works
        """
        smtp_server_page = SmtpServerPage()
        smtp_server_page.add_smtp_settings()
        smtp_server_page.send_test_email.click()

        action_modal = ActionCloseModal()
        sleep(WAIT_SHORT, reason="let modal open")
        assert action_modal.is_element_present('modal'), 'Test mail modal is not visible'

        action_modal.close_button.click()
        sleep(WAIT_SHORT, reason="let modal close")
        assert not action_modal.is_element_present('modal'), "Test mail modal is still visible"

    @pytest.mark.parametrize('required_setting_field', [
        'host', 'port', pytest.param('sender_email', marks=pytest.mark.xfail(reason='Refer Jira ID NES-7924'))])
    def test_required_smtp_server_setting_fields(self, required_setting_field):
        """
        NES-9751: UI Automation: Server | Check that all mandatory fields should highlighted in Red border on saving
                  the settings (eg. From (sender email))

        Scenario Tested:
        [x] Verify that all mandatory fields should highlighted in Red border on saving the settings and also display
            proper required field validation message.
        """
        # Go to SMTP server page
        smtp_server_page = SmtpServerPage()
        smtp_server_page.open()

        required_setting_details = {'host': API.Settings.Smtp.SMTP_HOST, 'port': API.Settings.Smtp.SMTP_PORT,
                                    'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL}

        # Update required setting field value to blank
        required_setting_details.update({required_setting_field: ''})

        # Add required SMTP server settings and click on save button
        smtp_server_page.add_smtp_settings(**required_setting_details)
        smtp_server_page.save_settings.click()
        expected_error_message = Messages.NotificationMessages.continue_button_code

        # Verify error notification message on keeping blank required setting field value
        assert Notifications().errors[-1] == expected_error_message, \
            "Getting incorrect error notification, Expected is '{}'.".format(expected_error_message)

        setting_field_elements = {'host': smtp_server_page.host_field, 'port': smtp_server_page.port_field,
                                  'sender_email': smtp_server_page.sender_email}

        # Verify required setting field is highlighted with 'Red' color border when user leaves it blank.
        assert 'error' in setting_field_elements.get(required_setting_field).get_css_classes(), \
            '{} required setting field is not highlighted with \'Red\' color border.'.format(required_setting_field)

    # @pytest.mark.xfail(reason='Refer Jira ID NES-7897')
    @pytest.mark.parametrize('invalid_value', ['test@tenable', '', 'abc', '12345', 'tenable.com'])
    def test_send_test_email_recipient_field_with_invalid_value(self, invalid_value):
        """
        NES-9749: UI Automation: Server | Validate Recipient field available under Send Test email (Blank value,
                  Invalid format/value)

        Steps:
        1. Go to Settings -> SMTP Server
        2. Click on 'Send Test Email' button
        3. Leave blank 'Recipient' filed on pop up
        4. Click on Send

        Scenario Tested:
        [x] Validate 'Recipient' field available under 'Send Test email' with blank and invalid format value.
        """
        # Go to SMTP server page
        smtp_server_page = SmtpServerPage()
        smtp_server_page.open()
        smtp_server_page.host_field.send_keys('1.1.1.1')
        smtp_server_page.port_field.send_keys('8025')

        # Click on 'Send Test Email' button
        smtp_server_page.send_test_email.click()

        # Enter value in recipient field from pop-up
        set_email_modal = SetEmailModal()
        set_email_modal.recipient_field.value = invalid_value
        ActionCloseModal().action_button.click()
        expected_error_message = Messages.NotificationMessages.continue_button_code
        notifications = Notifications()

        # Verify 'Recipient' field is highlighted with 'Red' color border when user enters invalid mail format.
        if invalid_value == "":
            assert 'error' in set_email_modal.recipient_field.get_css_classes(), \
                "'Recipient' field is not highlighted with 'Red' color border"
            assert Notifications().errors[-1] == expected_error_message, \
                "Getting incorrect error notification, Expected is '{}'.".format(expected_error_message)
        elif invalid_value != "":
            assert notifications.errors[-1] == Messages.NotificationMessages.SMTPServer.recepient_error, \
                "Email sent with invalid email"

    @pytest.mark.xray(test_key='NES-14095')
    @pytest.mark.parametrize("add_smtp_server_settings", [
        {'host': Mailcatcher.Server.MAILCATCHER_SERVER_HOSTNAME, 'port': Mailcatcher.Server.MAILCATCHER_PORT,
         'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL, 'host_name': API.Settings.Smtp.SMTP_HOST_NAME}],
                             indirect=True)
    def test_sample_email_verification(self, add_smtp_server_settings):
        """
        NES-9739: UI Automation: Server | Verify that the user is able to get sample mail on given email address

        Steps:
        1. Navigate to Settings-> SMTP Server page
        2. Enter valid value of Host, Port, From, Hostname, Encryption (No Encryption), Auth Method(None)
        3. Click on 'Send Test Email' button
        4. Add Recipient email address
        5. Click 'Send' button

        Scenario Tested:
        [x] Verify that the user is able to get sample mail on given email address.
        """
        recipient_mail = '{}{}'.format(random_name(prefix='to-'), Mailcatcher.Server.EMAIL_DOMAIN)
        notification = Notifications()

        # Verify success notification message after adding SMTP server settings
        assert notification.successes[-1] == Messages.NotificationMessages.saved_smtp_settings, \
            'Success Notification is missing or mismatched.'

        smtp_server_page = SmtpServerPage()
        if Notifications().is_element_present(element_name='results'):
            NotificationActions().remove_all()
            smtp_server_page.refresh()
            wait(lambda: smtp_server_page.is_element_present('save_settings'),
                 waiting_for="Server page to get reloaded")

        smtp_server_page.send_test_email.click()
        set_email_modal = SetEmailModal()

        # Verify 'Send Test Email' modal title
        assert set_email_modal.unsaved_changes_title.text == 'Send Test Email', \
            '\'Send Test Email\' pop up did not appear after clicking on \'Send Test Email\' button.'

        set_email_modal.set_email(email=recipient_mail)
        set_email_modal.wait_for_modal_closed()

        # Verify success notification message after sending mail to recipient
        assert notification.successes[-1] == Messages.NotificationMessages.smtp_email_sent + recipient_mail, \
            'Success Notification is missing or mismatched.'

        sleep(TIME_THIRTY_SECONDS, reason="waiting for Mailcatcher service to load mails")
        found_mail = MailRetriever().search_email(API.Settings.Smtp.SMTP_SENDER_EMAIL, [recipient_mail])
        log.info('Received sample test email :: :: {}'.format(found_mail))

        # Verify that User actually receives sample test email successfully
        assert found_mail, 'The mail search did not find the correct email.'

        # Verify sender email id from received sample test email
        assert re.sub('[(){}<>]', '', found_mail[0][Mailcatcher.EmailArrtibutes.SENDER]) == API.Settings.Smtp. \
            SMTP_SENDER_EMAIL, 'Getting incorrect email sender for sample test email.'

        # Verify subject name from received sample test email
        assert found_mail[0][Mailcatcher.EmailArrtibutes.SUBJECT] == API.Settings.Smtp.SMTP_TEST_EMAIL_SUBJECT, \
            'Getting incorrect email subject for sample test email.'

    @pytest.mark.xray(test_key='NES-14288')
    @pytest.mark.parametrize("add_smtp_server_settings", [
        {'host': Mailcatcher.Server.MAILCATCHER_SERVER_HOSTNAME, 'port': Mailcatcher.Server.MAILCATCHER_PORT,
         'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL, 'host_name': API.Settings.Smtp.SMTP_HOST_NAME}],
                             indirect=True)
    @pytest.mark.parametrize('add_filter', [True, False])
    def test_scan_result_email_verification(self, add_smtp_server_settings, add_filter):
        """
        NES-9746: UI Automation : Scan | Verify that csv report received in email notification will have only system
                  default columns
        NES-9691: UI-Automation : Scan | Verify that user is able to send the scan result with filtered criteria

        Steps:
        1. Log in NM/NP with the valid credential.
        2. Click on any scan template and fill general information like name, target host etc..
        3. Go to notification and configure report filter and give email Id
        4. Launch scan.
        5. After a completed scan, verify given Email Id

        Scenario Tested:
        [x] Verify that user should be able to receive the report in an email, and received report should be system
            defined (default) report type.
        [x] Verify that user should be able to receive the report in an email as per applied filter.
        """
        recipient_mail = '{}{}'.format(random_name(prefix='to-'), Mailcatcher.Server.EMAIL_DOMAIN)

        notification = Notifications()

        # Verify success notification message after adding SMTP server settings
        assert notification.successes[-1] == Messages.NotificationMessages.saved_smtp_settings, \
            'Success Notification is missing or mismatched.'

        HeaderBasePage().scan_link.click()
        scan_page = ScansPage()

        # Create 'Advanced scan'
        scan_name = random_name(prefix='Advanced_Scan-')
        scan_page.create_new_scan(scan_name=scan_name, scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                  scan_template=Nessus.TemplateNames.ADVANCED, target_ip=Nessus.Scan.Target.LOCALHOST,
                                  add_configuration=True)

        basic_setting = BasicSetting()
        basic_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                             link_text=Nessus.Scan.SettingsBasicSubMenu.NOTIFICATIONS)

        # Add recipient email id in 'Email Recipient(s)' field
        basic_setting.set_email_recipient_for_notification(recipient_email=recipient_mail)

        if add_filter:
            # Set filter key, operator and value
            basic_setting.set_filter_value(key=Nessus.Filter.FilterKeys.SEVERITY, value=Nessus.Scan.Severity.MEDIUM,
                                           operator=Nessus.Filter.FilterOperators.EQUAL_TO)

        scan_page.save_button.click()

        # Verify success notification message after creating new scan
        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification is missing after saving the scan'

        scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)

        self.cat.api.scans.launch(scan_id=scan_id)

        # Launch created scan and wait for scan to be completed
        with polling_ui():
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_TEN_MINUTES * 2)

        SmtpServerPage().open()

        # Search sent mail from received mails
        sleep(TIME_THIRTY_SECONDS,reason="waiting for Mailcatcher service to load mails")
        found_mail = MailRetriever().search_email(API.Settings.Smtp.SMTP_SENDER_EMAIL, [recipient_mail])
        log.info('Received scan result email :: :: {}'.format(found_mail))

        if found_mail is True:
            # Verify that User actually receives scan result email successfully
            assert found_mail, 'The mail search did not find the correct email.'

            # Verify sender email id from received scan result email
            assert re.sub('[(){}<>]', '', found_mail[0][Mailcatcher.EmailArrtibutes.SENDER]) == API.Settings.Smtp. \
                SMTP_SENDER_EMAIL, 'Getting incorrect email sender for scan result email.'

            scan_result_email_subject = API.Settings.Smtp.SCAN_RESULT_EMAIL_SUBJECT + scan_name

            # Verify subject name from received scan result email
            assert found_mail[0][Mailcatcher.EmailArrtibutes.SUBJECT] == scan_result_email_subject, \
                'Getting incorrect email subject for scan result email.'


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login', 'set_default_smtp_settings', 'login')
class TestScanReportFormatEmail:
    """ Test class to cover test cases related to verify email with attached scan report """

    cat = None

    @staticmethod
    def get_email_attachments(email_id: int) -> list:
        """
        Returns list of email attachments contents from given email id

        :param int email_id: id of email from which you want to get the attachments
        :return: list of contents of the file attachments
        :rtype: list
        """
        response = requests.get(Mailcatcher.Server.MESSAGES_URL + '/{}{}'.format(email_id, '.json')).json()
        return response['attachments']

    @pytest.mark.parametrize("add_smtp_server_settings", [
        {'host': Mailcatcher.Server.MAILCATCHER_SERVER_HOSTNAME, 'port': Mailcatcher.Server.MAILCATCHER_PORT,
         'sender_email': API.Settings.Smtp.SMTP_SENDER_EMAIL, 'host_name': API.Settings.Smtp.SMTP_HOST_NAME}],
                             indirect=True)
    @pytest.mark.parametrize('report_format', [API.Scan.UIExportFormats.FORMAT_PDF, API.Scan.UIExportFormats.FORMAT_CSV,
                                               API.Scan.UIExportFormats.FORMAT_NESSUS])
    @pytest.mark.parametrize('add_filter', [True, False])
    def test_email_with_attached_scan_report_format(self, add_smtp_server_settings, report_format, add_filter):
        """
        NES-9692: UI Automation: Scan | Verify that user is able to choose attachment (PDF, HTML, Nessus)

        Steps:
        1. Log in NM/NP with the valid credential.
        2. Click on any scan template and fill general information like name, target host etc..
        3. In scan template go to Settings -> Basic -> Notifications and give respective email Id in Email Recipient(s)
           text box
        4. Enable "Attach Report" option and select option "Nessus, CSV,or PDF"
        5. Launch scan.

        Scenario Tested:
        [x] Verify that In email, user should be getting a scan result as per selected attach report file format.
        """
        recipient_mail = '{}{}'.format(random_name(prefix='to-'), Mailcatcher.Server.EMAIL_DOMAIN)

        # Verify success notification message after adding SMTP server settings
        assert Notifications().successes[-1] == Messages.NotificationMessages.saved_smtp_settings, \
            'Success Notification is missing or mismatched.'

        HeaderBasePage().scan_link.click()
        scan_page = ScansPage()

        # Create 'Advanced scan'
        scan_name = random_name(prefix='Advanced_Scan-')
        scan_page.create_new_scan(scan_name=scan_name, scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                  scan_template=Nessus.TemplateNames.ADVANCED, target_ip=Nessus.Scan.Target.LOCALHOST,
                                  add_configuration=True)

        # Click on 'Notification' under 'Basic' setting of scan
        basic_setting = BasicSetting()
        basic_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                             link_text=Nessus.Scan.SettingsBasicSubMenu.NOTIFICATIONS)

        # Add recipient email id in 'Email Recipient(s)' field
        basic_setting.set_email_recipient_for_notification(recipient_email=recipient_mail)

        # Toggle 'Attach Report' and select report format type from 'Report Type' drop-down
        basic_setting.attach_report_toggle.toggle()
        basic_setting.set_report_type(report_format=report_format)

        if add_filter:
            # Set filter key, operator and value
            basic_setting.set_filter_value(key=Nessus.Filter.FilterKeys.SEVERITY, value=Nessus.Scan.Severity.MEDIUM,
                                           operator=Nessus.Filter.FilterOperators.EQUAL_TO)

        scan_page.save_button.click()

        # Verify success notification message after creating new scan
        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Notification is missing after saving the scan'

        scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)

        self.cat.api.scans.launch(scan_id=scan_id)

        # Launch created scan and wait for scan to be completed
        with polling_ui():
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_TEN_MINUTES * 2)

        SmtpServerPage().open()

        # Search sent mail from received mails
        sleep(TIME_THIRTY_SECONDS, reason="waiting for Mailcatcher service to load mails")
        mail_retriever = MailRetriever()
        found_mail = mail_retriever.search_email(API.Settings.Smtp.SMTP_SENDER_EMAIL, [recipient_mail])
        log.info('Received scan result email :: :: {}'.format(found_mail))

        if found_mail is True:
            # Verify that User actually receives scan result email successfully
            assert found_mail, 'The mail search did not find the correct email.'

            # Verify sender email id from received scan result email
            assert re.sub('[(){}<>]', '', found_mail[0][Mailcatcher.EmailArrtibutes.SENDER]) == API.Settings.Smtp. \
                SMTP_SENDER_EMAIL, 'Getting incorrect email sender for scan result email.'

            scan_result_email_subject = API.Settings.Smtp.SCAN_RESULT_EMAIL_SUBJECT + scan_name

            # Verify subject name from received scan result email
            assert found_mail[0][Mailcatcher.EmailArrtibutes.SUBJECT] == scan_result_email_subject, \
                'Getting incorrect email subject for scan result email.'

            # Get attached report from email id
            mail_attachment = self.get_email_attachments(email_id=int(found_mail[0][Mailcatcher.EmailArrtibutes.ID]))
            log.info('Received email\'s attachments :: :: {}'.format(mail_attachment))

            file_name_and_extension = mail_attachment[0]['filename'].split('.')

            # Verify that attached report name is start with created scan name
            assert file_name_and_extension[0].startswith(scan_name), \
                'Attached report name is not start with created scan name.'

            # Verify attached report format (report file extension)
            assert file_name_and_extension[1] == report_format.lower(), \
                'Getting incorrect report file extension. Expected file extension is \'{}\''.format(report_format.lower())

            report_type_details = {API.Scan.UIExportFormats.FORMAT_CSV: 'text/csv',
                                   API.Scan.UIExportFormats.FORMAT_PDF: 'application/pdf',
                                   API.Scan.UIExportFormats.FORMAT_NESSUS: 'application/xml'}

            # Verify attached report type
            assert mail_attachment[0]['type'] == report_type_details.get(report_format), \
                'Getting incorrect attachment type. Expected type is \'{}\''.format(report_type_details.get(report_format))
