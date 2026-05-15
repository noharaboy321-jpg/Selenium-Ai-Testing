"""
Nessus automatic Software Update related test cases

:copyright: Tenable Network Security, 2020
:date: Oct 15, 2020
:last_modified: May 07, 2021
:author: @kpanchal
"""
import datetime

import pytest
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting.exceptions import TimeoutExpired

from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator, ActivationCodes
from catium.lib.const.base_constants import TIME_TEN_SECONDS, TIME_FIVE_MINUTES, TIME_THIRTY_SECONDS, WAIT_NORMAL
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.license import close_welcome_nessus_10_modal_for_pro, close_welcome_nessus_10_modal_for_expert
from nessus.helpers.nessuscli import users, fix, fetch
from nessus.helpers.nessuscli.helper import get_nessus_cli, get_system_datetime
from nessus.helpers.nessuscli.logchecker import is_log_entries
from nessus.helpers.scan import start_stop_nessus_wait_for_ready
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.system import is_pro, is_expert
from nessus.lib.config.environment_variables import NESSUS_LOGS_DIR
from nessus.lib.const import Nessus
from nessus.lib.const.constants import API, NessusFilePath, NessusCli
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import SoftwareUpdate
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import ModalNotifications
from nessus.pageobjects.login.login_page import LoginPage

log = create_logger()


@pytest.fixture()
def remove_plugins_dir_and_feed_info_file():
    """ Removes plugins directory and feed info file """
    commands = [NessusFilePath.Linux.NESSUS_PLUGIN_MD5_DIR, NessusFilePath.Linux.NESSUS_PLUGIN_FEED_INFO_DIR,
                NessusFilePath.Linux.NESSUS_METADATA_JSON]

    with SSH() as ssh:
        [ssh.execute(command="rm -rf {}".format(cmnd)) for cmnd in commands]

    start_stop_nessus_wait_for_ready(nessus_api=NessusAPI(), status=API.Status.READY)


def register_nessus_with_no_update(license_type: str = None, auto_update_value: str = 'no') -> None:
    """ This function will register the Nessus with given auto_update value """
    api_object = NessusAPI()

    if license_type:
        log.info('Adding user into Nessus')
        add_user_output = users.adduser(username='admin', password='admin', passconfirm='admin', sysadmin=True)
        log.debug('Added user output :: {}'.format(add_user_output))

        fix.set(key='auto_update', value=auto_update_value)
        fix.set(key='custom_host', value=Nessus.Scan.Target.PRODUCTION_FEED_SERVER_HOST, secure=True)

        activation_code = ActivationCodeGenerator()

        if license_type == 'Nessus Expert':
            code = activation_code.generate_nessus_expert_code(expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)
            log.info("<<<<<The activation code is " + code + " >>>>>>>>>>>")
        elif license_type == 'Nessus Manager':
            code = activation_code.generate_nessus_manager_code(expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS,
                                                                scanner_mode=ActivationCodes.Nessus.Mode.Full)
        else:
            code = activation_code.generate_nessus_professional(expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)

        fetch.register_only(serial=code)

    wait_for_scanner_to_be_ready(api=api_object)

    login_page = LoginPage()
    login_page.refresh()
    login_page.login_with_defaults() if login_page.is_element_present(
        'username_field', timeout=TIME_THIRTY_SECONDS) else log.warning('User has been logged in already..!!')
    wait(lambda: visibility_of_element_located(HeaderBasePage().scan_link), waiting_for='Scan page to load')

    if is_pro():
        close_welcome_nessus_10_modal_for_pro()
    elif is_expert():
        close_welcome_nessus_10_modal_for_expert()

    # Dismiss welcome banner if present
    welcome_banner_modal = ActionCloseModal()
    welcome_banner_modal.close_button.click() if welcome_banner_modal.is_element_present(
        'close_button', timeout=TIME_TEN_SECONDS) else log.warning('Welcome banner is not displayed.')
    welcome_banner_modal.wait_for_modal_closed()


def update_nessus_plugins_and_wait_for_ready():
    """ Updates Nessus plugins and wait for to be ready """
    with SSH() as ssh:
        ssh.execute("{} update --plugins-only".format(get_nessus_cli()), timeout=TIME_FIVE_MINUTES)

    wait_for_scanner_to_be_ready(api=NessusAPI())

    login_page = LoginPage()
    login_page.refresh()

    login_page.login_with_defaults() if login_page.is_element_present(
        'username_field', timeout=TIME_TEN_SECONDS) else log.warning('User has been logged in already..!!')


@pytest.mark.license_change
class TestAutomaticSoftwareUpdate:
    """ Covers tests for Automatic Software core/plugins updates """

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.usefixtures('remove_plugins_dir_and_feed_info_file', 'login')
    def test_only_plugin_update(self):
        """
        NES-11629: Automation: test plugins only update

        Steps:
        1. Reset registration and complete registration process with no update
        2. Verify last update date and plugin set value should be available as N/A
        3. Verify by default Disabled should be checked in automatic software update feature
        4. Select only plugins update -> save and verify the value in backend.log file
        5. Restart the scanner -> login and verify last updated date and plugin set in visible
        """
        start_timestamp = get_system_datetime()
        end_timestamp = start_timestamp + datetime.timedelta(minutes=30)

        # Go to software update tab under About page
        about_software_update = SoftwareUpdate()
        about_software_update.open()
        wait(lambda: about_software_update.is_element_present('update_server'),
             waiting_for='Software update page to get loads properly')

        about_software_update.update_plugins.click()

        if about_software_update.is_element_present('modal_acknowledge'):
            about_software_update.modal_acknowledge.click()

        about_software_update.save_button.click()
        if about_software_update.is_element_present('modal_acknowledge'):
            about_software_update.modal_acknowledge.click()

        # Verify "Nessus Plugins Update: Started" is present in the logs
        try:
            wait(lambda: any([is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                             log_entry=Messages.NessusCli.PLUGIN_UPDATE_STARTED,
                                             start_timestamp=start_timestamp, end_timestamp=end_timestamp,
                                             max_lines_per_file=100, log_line=True)]),
                 timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=WAIT_NORMAL)
        except TimeoutExpired:
            assert False, '{} is not present in log file'.format(Messages.NessusCli.PLUGIN_UPDATE_STARTED)

        # Verify "Nessus Core Components Update: Started" is not present in the logs
        assert not is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG, log_entry=Messages.
                                  NessusCli.NESSUS_CORE_UPDATE_STARTED, start_timestamp=start_timestamp,
                                  end_timestamp=end_timestamp, max_lines_per_file=100, log_line=True)

    @pytest.mark.parametrize("test_details", [
        pytest.param({'license_type': 'Nessus Professional'}, marks=pytest.mark.nessus_pro),
        pytest.param({'license_type': 'Nessus Manager'}, marks=pytest.mark.nessus_manager)])
    @pytest.mark.usefixtures('remove_plugins_dir_and_feed_info_file', 'reset_license', 'wizard_open')
    @pytest.mark.parametrize('update_frequency', ['default', 'custom'])
    def test_update_all_components(self, test_details, update_frequency):
        """
        NES-11630: Automation: test updating all components

        Steps:
        1. Reset registration and complete registration process with no update
        2. Verify last update date and plugin set value should be available as N/A
        3. Verify by default Disabled should be checked in automatic software update feature
        4. Select only All components -> save and verify the value in backend.log file
        5. Restart the scanner -> login and verify last updated date and plugin set in visible
        """
        try:
            register_nessus_with_no_update(license_type=test_details['license_type'])

            start_timestamp = get_system_datetime()
            end_timestamp = start_timestamp + datetime.timedelta(minutes=30)

            # Go to software update tab under About page
            about_software_update = SoftwareUpdate()
            about_software_update.open()
            wait(lambda: about_software_update.is_element_present('update_all_components'),
                 waiting_for='software update page get loads properly')
            about_software_update.update_all_components.click()

            if about_software_update.is_element_present('modal_acknowledge'):
                about_software_update.modal_acknowledge.click()

            if update_frequency == 'custom':
                if about_software_update.is_element_present('update_frequency_custom_tip'):
                    about_software_update.update_frequency_custom_tip.click()

                    # Verify input field for custom update frequency hours is displayed
                assert about_software_update.is_element_present('update_frequency_in_hours'), \
                    'Input field for Custom update frequency is not displayed.'

                # Verify 'hours' label next to 'Update Frequency' input field
                assert about_software_update.is_element_present('hours_label'), \
                    "'hours' label is not displayed next to 'Update Frequency' input box."

                # Verify 'x' icon next to 'hours' label
                assert about_software_update.is_element_present('update_frequency_remove_icon'), \
                    "'Update Frequency' remove icon is not displayed."

                # Enter value in custom update frequency input field
                about_software_update.update_frequency_in_hours.value = "1"

            about_software_update.save_button.click()
            if about_software_update.is_element_present('modal_acknowledge'):
                about_software_update.modal_acknowledge.click()

            # Verify "Nessus Plugins Update: Started" is present in the logs
            try:
                wait(lambda: any([is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                                 log_entry=Messages.NessusCli.PLUGIN_UPDATE_STARTED,
                                                 start_timestamp=start_timestamp, end_timestamp=end_timestamp,
                                                 max_lines_per_file=100, log_line=True)]),
                     timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=WAIT_NORMAL)
            except TimeoutExpired:
                assert False, '{} is not present in log file'.format(Messages.NessusCli.PLUGIN_UPDATE_STARTED)

            # Verify "Nessus Core Components Update: Started" is present in the logs
            try:
                wait(lambda: any([is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                                 log_entry=Messages.NessusCli.NESSUS_CORE_UPDATE_STARTED,
                                                 start_timestamp=start_timestamp, end_timestamp=end_timestamp,
                                                 max_lines_per_file=100, log_line=True)]),
                     timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=WAIT_NORMAL)
            except TimeoutExpired:
                assert False, '{} is not present in log file'.format(Messages.NessusCli.PLUGIN_UPDATE_STARTED)
        finally:
            update_nessus_plugins_and_wait_for_ready()
