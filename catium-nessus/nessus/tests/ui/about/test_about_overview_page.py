""""
Nessus test cases related to About page

:copyright: Tenable Network Security, 2017
:date: February 01, 2018
:last_modified: Apr 27, 2023
:author: @rdutta, @jamreliya, @jchavda, @kpanchal, @krpatel.ctr, @mdabra, @sacharya.ctr, @msekar

Note:
These Environment variables need to be added during the run for CLI Integration.
--> NESSUS_CLI_LOCAL=False
--> CAT_SSH_USERNAME=<machine_username>
--> CAT_SSH_PASSWORD=<machine_password>
"""

import datetime
import os
import re
import tarfile
import time
from http import HTTPStatus

import pytest
from selenium.webdriver import ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.util import get_browser_download_file_path
from catium.lib import const
from catium.lib.config import Config
from catium.lib.const import WAIT_NORMAL, TIME_SIXTY_SECONDS, TIME_FIFTEEN_MINUTES, TIME_NINETY_SECONDS, \
    TIME_FIVE_MINUTES, TIME_THREE_SECONDS, WAIT_LONG, TIME_FIVE_SECONDS
from catium.lib.const.base_constants import GRID_BROWSER_DOWNLOAD_PATH, TIME_THIRTY_MINUTES, TIME_TEN_SECONDS, \
    TIME_THIRTY_SECONDS, WAIT_TINY, TIME_TEN_MINUTES
from catium.lib.log import create_logger
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers import license
from nessus.helpers.nessus_ui.settings import handle_connection_popup, manage_server_restart_task
from nessus.helpers.nessuscli.helper import get_system_datetime, get_os_name
from nessus.helpers.nessuscli.logchecker import is_log_entries
from nessus.helpers.utility import get_downloaded_files_chrome
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.config import NessusConfig
from nessus.lib.config.environment_variables import NESSUS_LOGS_DIR
from nessus.lib.const import Nessus, NessusCli
from nessus.lib.const.constants import API, OperatingSystems
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView, About
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AddAdvancedSettingModal, \
    AdvancedSettingsList
from nessus.pageobjects.generic.generic_modals import UnsavedChangesModal, ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()

timestamped_path = 'Download_logs_file_' + str(int(time.time()))  # use timestamp to differentiate test


@pytest.fixture()
def chrome_options():
    """ Set download path for Chrome. """
    log.debug('fixture init: Override Chrome Options to support downloads')

    options = ChromeOptions()
    if Config.CAT_USE_GRID:
        log.info("Using grid")
        directory = os.path.join(GRID_BROWSER_DOWNLOAD_PATH, timestamped_path)
    else:
        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path)
    prefs = {'download.default_directory': directory}
    options.add_experimental_option('prefs', prefs)
    return options


def close_wizard():
    try:
        wait(lambda: ActionCloseModal().is_element_present('modal'), waiting_for='Get welcome banner after login')

        if not invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()):
            log.info('Welcome banner is visible after fresh installation.')
            action_close_modal = ActionCloseModal()
            action_close_modal.close_button.click()
            action_close_modal.wait_for_modal_closed()
    except:
        log.info('Attempted to close welcome banner.')
        pass


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestAboutOverview:
    """
    Covers Overview tab related test cases in About page.
    # NQA-1054 : Automation tests for Settings - About.
    """

    cat = None

    @pytest.mark.xray(test_key='NES-14201')
    @pytest.mark.nessus_home
    @pytest.mark.nessus_smoke
    def test_visibility_of_overview_tab(self):
        """
        NES-14201: Verify about page
        Test "Overview tab is present/visible in about page
        1. Navigate to About page under Settings.
        2. Verify visibility of "Overview" tab.
        """
        about_page = About()
        about_page.open()
        wait(lambda: OverView().is_element_present('update_activation_code_tip'), waiting_for='about page to get load')

        about_page.encryption_password_tab.click()

        assert visibility_of_element_located((about_page.overview_tab.we_by,
                                              about_page.overview_tab.we_value))(get_driver_no_init()), \
            "Overview tab is invisible."

    def test_feed_status(self):
        """
        NES-8929: Fix about, custom CA and login page related skipped test cases

        In the Nessus 7.0.2 release, this page has been updated to have a Feed Status section that displays
        while waiting for a feed update to complete, or when there is an error.
        1. Navigate to Overview tab in About page under Settings.
        2. Check if a feed status available, if yes then verify needful according to feed status.
        """
        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')

        if Nessus.About.FEED_STATUS not in overview_page.get_about_page_labels(element=overview_page.product_labels):
            overview_page.update_plugins_tip.click()
            wait(lambda: overview_page.clear_feed_status_link.is_displayed(), waiting_for='clear feed status link')

        assert overview_page.is_element_present('clear_feed_status_link'), "'Clear feed status' link is invisible."

        overview_page.clear_feed_status_link.click()

        wait(lambda: not overview_page.is_element_present('clear_feed_status_link'),
             timeout_seconds=WAIT_LONG, waiting_for='clear feed status link to become invisible.')

    @pytest.mark.xray(test_key='NES-14685')
    def test_cancel_button_to_close_activation_code_popup(self):
        """
        NES-14685 - Verify the cancel button and 'x' icon of activation code popup
        Test the activation code pop up close with cancel and x button
        1. Navigate to About page under Settings.
        2. Click on pencil icon and Update activation code pops up.
        3. Click on cancel/close button and observe the popup is closed.
        """

        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')
        NotificationActions().remove_all()

        assert overview_page.update_activation_code_tip.is_displayed(), \
            'Update Activation code icon is invisible or not present.'

        # Cancel button in Activation popup
        activated_code = overview_page.activation_code.text
        overview_page.update_activation_code_tip.click()
        update_activation_code_modal = ActionCloseModal()

        assert (update_activation_code_modal.is_element_present('modal') and
                update_activation_code_modal.action_button.text == 'Activate' and
                update_activation_code_modal.cancel_button.is_displayed()), \
            'In Overview tab of About page, update activation code pop-up is not opened after click on ' \
            'activation code tip.'

        update_activation_code_modal.cancel_button.click()
        update_activation_code_modal.wait_for_modal_closed(timeout_seconds=WAIT_TINY)
        assert not update_activation_code_modal.is_element_present('modal'), 'Activation pop up is not closed'

        # Close button in Activation popup
        overview_page.update_activation_code_tip.click()
        update_activation_code_modal = ActionCloseModal()

        assert (update_activation_code_modal.is_element_present('modal') and
                update_activation_code_modal.action_button.text == 'Activate' and
                update_activation_code_modal.close_button.is_displayed()), \
            'In Overview tab of About page, update activation code pop-up is not opened after click on ' \
            'activation code pencil icon.'

        update_activation_code_modal.close_button.click()
        update_activation_code_modal.wait_for_modal_closed(timeout_seconds=WAIT_TINY)
        assert not update_activation_code_modal.is_element_present('modal'), 'Activation pop up is not closed'

    @pytest.mark.xray(test_key='NES-14201')
    def test_plugin_update(self):
        """
        NES-14201: Verify about page
        Test to update plugins.
        1. Navigate to Overview tab in About page under Settings.
        2. Verify tooltip on plugin update icon
        3. Clicking on update plugin icon, plugin update should start and a “Software update scheduled successfully”
           notification should display.
        4. Once plugin is updated successfully plugin set Id should be updated
        5. Verify plugin update starts/completes by looking at nessusd.messages
        """
        # start and end time in which log will be read
        start_timestamp = get_system_datetime()
        end_timestamp = start_timestamp + datetime.timedelta(minutes=20)

        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')

        assert overview_page.update_plugins_tip.is_displayed(), 'Update Plugin tool tip is invisible or not present.'

        last_updated = overview_page.last_updated.text
        plugin_set_id = overview_page.plugin_set.text
        overview_page.update_plugins_tip.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.About.update_plugins, \
            "Success notification is missing or incorrect."

        try:
            wait(lambda: any([is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                             log_entry=Messages.NessusCli.PLUGIN_UPDATE_STARTED,
                                             start_timestamp=start_timestamp, end_timestamp=end_timestamp,
                                             max_lines_per_file=30)]),
                 timeout_seconds=TIME_SIXTY_SECONDS, sleep_seconds=WAIT_NORMAL)
        except TimeoutExpired:
            assert False, '{} is not present in log file'.format(Messages.NessusCli.PLUGIN_UPDATE_STARTED)

        try:
            wait(lambda: any([is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                             log_entry=Messages.NessusCli.PLUGIN_NOUPDATE,
                                             start_timestamp=start_timestamp, end_timestamp=end_timestamp,
                                             max_lines_per_file=30),
                              is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                             log_entry=Messages.NessusCli.UI_UPTODATE,
                                             start_timestamp=start_timestamp, end_timestamp=end_timestamp,
                                             max_lines_per_file=30)]),
                 timeout_seconds=TIME_FIFTEEN_MINUTES, sleep_seconds=WAIT_NORMAL)
        except TimeoutExpired:
            assert False, 'plugin update is not finished within specified timeout.'

        is_no_update = is_log_entries(log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG,
                                      log_entry=Messages.NessusCli.PLUGIN_NOUPDATE, start_timestamp=start_timestamp,
                                      end_timestamp=end_timestamp, max_lines_per_file=50)

        if is_no_update:
            # there is no update
            assert last_updated == overview_page.last_updated.text, "updated date for plugins mismatched"

            assert plugin_set_id == overview_page.plugin_set.text, "updated plugins set mismatched"
        else:
            # plugins are updated
            wait(lambda: overview_page.check_for_plugin_date_update(last_updated=last_updated,
                                                                    plugin_set_id=plugin_set_id),
                 timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=TIME_NINETY_SECONDS)
            assert last_updated != overview_page.last_updated.text, "Plugins update failed."

            assert plugin_set_id != overview_page.plugin_set.text, "Plugins set has not updated after plugins update."

    @pytest.mark.license_change
    @pytest.mark.disable_logout
    @pytest.mark.usefixtures('nessus_api_login')
    def test_offline_registration_option(self):
        """
        NES-8724: UI Automated Tests: Verify "Offline" option is available in UI

        Scenarios Tested:
        [x] Verify that the admin user is able to see the Offline option
        [x] Verify that the offline method can be used to generate a license.

        NQA-395: Short Cycle - Controller - Stage 6 - Reactivation and un-installation.
        Test to reactivate controller by updating licence activation key depending upon product type.

        1. Navigate to Overview tab in About page under Settings.
        2. Verify presence of pencil icon next to 'activation code'.
        3. Click the pencil icon and enter new activation code and click ‘Activate’ button
        4. Confirm activation succeeds, by verifying backend.log log file
        5. Verify new code is displayed
        6. Verify expiration date is updated
        """
        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')
        NotificationActions().remove_all()

        assert overview_page.update_activation_code_tip.is_displayed(), \
            'Update Activation code icon is invisible or not present.'

        activated_code = overview_page.activation_code.text
        overview_page.update_activation_code_tip.click()
        update_activation_code_modal = ActionCloseModal()

        assert (update_activation_code_modal.is_element_present('modal') and
                update_activation_code_modal.action_button.text == 'Activate' and
                update_activation_code_modal.cancel_button.is_displayed()), \
            'In Overview tab of About page, update activation code pop-up is not opened after click on ' \
            'activation code tip.'

        overview_page.registration_dropdown.click()

        for option in overview_page.registration_dropdown.option_values:
            assert option['label'] in Nessus.About.REGISTRATION_OPTIONS, \
                "'{}' options is missing in registration options".format(option['label'])

        overview_page.registration_dropdown.click()
        overview_page.registration_dropdown.select_by_visible_text(Nessus.About.OFFLINE)

        assert overview_page.nessus_license_field.is_displayed(), \
            "'Nessus License' field is not displayed after selecting 'Offline' option from registration drop-down."

        properties = self.cat.api.server.properties()
        activation_code = license.get_activation_code(properties=properties)
        nessus_license = license.get_offline_license(code=activation_code, challenge=overview_page.challenge_code.text)

        overview_page.nessus_license_field.value = "\n" + nessus_license
        LoadingCircle(WAIT_LONG)
        update_activation_code_modal.accept_action()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Users.success_sign_out, \
            'Success sign-out notification after offline activation did not appear.'

        handle_connection_popup(timeout_to_appear=TIME_FIFTEEN_MINUTES, timeout_to_disappear=TIME_THIRTY_MINUTES)

        # Wait till server is ready
        wait_for_scanner_status(api=self.__class__.cat.api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES,
                                msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)

        get_driver_no_init().refresh()
        wait(lambda: visibility_of_element_located(LoginPage().username_field))
        LoginPage().login_with_defaults()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')

        assert activated_code != activation_code, "Activation code is not updated successfully."

    @pytest.mark.xray(test_key='NES-14328')
    @pytest.mark.xray(test_key='NES-14254')
    @pytest.mark.nessus_home
    def test_activation_code_popup(self):
        """
        NES-14328 : Verify UI of the Activation Code popup
        NES-14254 : Verify the options of registration dropdown of activation code popup
        """
        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')

        overview_page.update_activation_code_tip.click()
        update_activation_code_modal = ActionCloseModal()

        assert (update_activation_code_modal.is_element_present('modal') and
                update_activation_code_modal.action_button.text == 'Activate' and
                update_activation_code_modal.cancel_button.is_displayed()), \
            'In Overview tab of About page, update activation code pop-up is not opened after click on ' \
            'activation code tip.'

        assert update_activation_code_modal.modal_title.text == "Update Activation Code", "Activation modal title is missing/changed"
        assert overview_page.is_element_present(
            'update_activation_code_area'), "Update Activation code field is missing"
        assert overview_page.is_element_present('registration_dropdown'), "Registration dropdown is missing"
        for option in overview_page.registration_dropdown.option_values:
            assert option['label'] in Nessus.About.REGISTRATION_OPTIONS, \
                "'{}' options is missing in registration options".format(option['label'])


@pytest.mark.nessus_settings_1
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestNessusManagerAboutOverview:
    """
    Covers Overview tab related test cases in About page for Nessus Manager.
    # NQA-1054 : Automation tests for Settings - About.
    """

    @pytest.mark.xray(test_key='NES-14201')
    @pytest.mark.ie
    def test_nm_overview_page_data(self):
        """
        NES-14201: Verify about page
        Test Overview page data.
        1. Navigate to Overview tab in About page under Settings.
        2. Verify information displayed is correct:
            Plugin section: Plugins, Last Updated, Plugin, Activation Code
            Nessus Manager:
                Nessus manager : Version, Licensed Hosts, Licensed Scanners, Licensed Agents
        3. Verify that the template version is not N/A
        """
        overview_page = OverView()
        overview_page.open()

        wait(lambda: overview_page.is_element_present('plugins_labels'), timeout_seconds=TIME_TEN_SECONDS)
        plugins_labels = overview_page.get_about_page_labels(element=overview_page.plugins_labels)

        assert Nessus.About.PLUGINS_LABELS == plugins_labels, "Plugins labels are missing or incorrect."

        assert overview_page.policy_template_version.text != 'N/A'

        product_labels = overview_page.get_about_page_labels(element=overview_page.product_labels)

        Nessus.About.NESSUS_MANAGER_LABELS.append(Nessus.About.FEED_STATUS) \
            if Nessus.About.FEED_STATUS in product_labels else Nessus.About.NESSUS_MANAGER_LABELS

        assert sorted(product_labels) == sorted(Nessus.About.NESSUS_MANAGER_LABELS), \
            "Product labels are missing or incorrect."


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestNessusPro7AboutOverview:
    """
    Covers Overview tab related test cases in About page for Nessus Pro7.
    # NQA-1054 : Automation tests for Settings - About.
    """

    def test_npro7_overview_page_data(self):
        """
        Test Overview page data.
        1. Navigate to Overview tab in About page under Settings.
        2. Verify information displayed is correct:
            Plugin section: Plugins, Last Updated, Plugin, Activation Code
            Nessus Professional 7:
                Nessus Professional Version 7: Version, Licensed Hosts
        """
        overview_page = OverView()
        overview_page.open()

        wait(lambda: overview_page.is_element_present('plugins_labels'), timeout_seconds=TIME_TEN_SECONDS)
        plugins_labels = overview_page.get_about_page_labels(element=overview_page.plugins_labels)

        assert Nessus.About.PLUGINS_LABELS == plugins_labels, "Plugins labels are missing or incorrect."

        assert overview_page.policy_template_version.text != 'N/A'

        product_labels = overview_page.get_about_page_labels(element=overview_page.product_labels)

        Nessus.About.NESSUS_PROFESSIONAL_10_LABELS.append(Nessus.About.FEED_STATUS) \
            if Nessus.About.FEED_STATUS in product_labels else Nessus.About.NESSUS_PROFESSIONAL_10_LABELS

        assert sorted(product_labels) == sorted(Nessus.About.NESSUS_PROFESSIONAL_10_LABELS), \
            "Product labels are missing or incorrect."


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_expert
@pytest.mark.usefixtures('login')
class TestNessusExpertAboutOverview:
    """
    Covers Overview tab related test cases in About page for Nessus Pro7.
    #NES-16312 : Verify about page of Expert license
    """

    @pytest.mark.xray(test_key='NES-16312')
    @pytest.mark.xray(test_key='NES-14201')
    def test_expert_about_overview_page_data(self):
        """
        Test Overview page data under About Tab.
        NES-16312 : Verify about page of Expert license
            1. Login into Expert and navigate to Settings > About
            2. Verify correct license type is displayed

        NES-14201: Verify about page
        """
        overview_page = OverView()
        overview_page.open()

        wait(lambda: overview_page.is_element_present('product_labels'), timeout_seconds=TIME_TEN_SECONDS)
        product_labels = overview_page.get_about_page_labels(element=overview_page.product_labels)

        Nessus.About.NESSUS_EXPERT_10_LABELS.append(Nessus.About.FEED_STATUS) \
            if Nessus.About.FEED_STATUS in product_labels else Nessus.About.NESSUS_EXPERT_10_LABELS

        assert sorted(product_labels) == sorted(Nessus.About.NESSUS_EXPERT_10_LABELS), \
            "Product labels are missing or incorrect."


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_legacy
@pytest.mark.usefixtures('login')
class TestNessusProAboutOverview:
    """
    Covers Overview tab related test cases in About page for Nessus Pro.
    # NQA-1054 : Automation tests for Settings - About.
    """

    @pytest.mark.xray(test_key='NES-14201')
    def test_npro_overview_page_data(self):
        """
        Test Overview page data.
        1. Navigate to Overview tab in About page under Settings.
        2. Verify information displayed is correct:
            Plugin section: Plugins, Last Updated, Plugin, Activation Code
            Nessus Professional:
                Nessus Professional (original): Version, Licensed Hosts
        NES-14201: Verify about page
        """
        overview_page = OverView()
        overview_page.open()

        wait(lambda: overview_page.is_element_present('plugins_labels'), timeout_seconds=TIME_TEN_SECONDS)
        plugins_labels = overview_page.get_about_page_labels(element=overview_page.plugins_labels)

        assert Nessus.About.PLUGINS_LABELS == plugins_labels, "Plugins labels are missing or incorrect."

        assert overview_page.policy_template_version.text != 'N/A'

        product_labels = overview_page.get_about_page_labels(element=overview_page.product_labels)

        Nessus.About.NESSUS_PROFESSIONAL_LABELS.append(Nessus.About.FEED_STATUS) \
            if Nessus.About.FEED_STATUS in product_labels else Nessus.About.NESSUS_PROFESSIONAL_LABELS

        assert sorted(product_labels) == sorted(Nessus.About.NESSUS_PROFESSIONAL_LABELS), \
            "Product labels are missing or incorrect."


@pytest.mark.nessus_settings_1
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestAboutDownloadLogs:
    """
    Covers Download logs related test cases under About page.
    STA-52 : Automation tests for 'Download Logs' from UI.
    """
    cat = None

    @staticmethod
    def get_log_line_number(file_path, search_text: str) -> int:
        """
        Returns specific line number of given search text from log file

        :param file_path: log file path
        :param str search_text: text which needs to be search in log file
        :return: line number
        :rtype: int
        """
        with open(file_path, 'r') as log_file:
            line_number = 0
            number = 0

            for line in log_file.readlines():
                number += 1

                if search_text in line:
                    line_number = number

        return line_number

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("debug_log_type", ["Basic logs", "Extended"])
    @pytest.mark.parametrize("sanitize_checkbox", [False, True])
    def test_download_logs_from_about_page(self, debug_log_type, sanitize_checkbox):
        """
        1. Verify that user is able to download log files with ‘Debug Log Type’ = Basic.
            1. Click on ‘Download Logs’ button under 'About' panel
            2. Select 'Basic' Debug Log Type
            3. Click on Download button
        2. Verify that user is able to download log files with ‘Debug Log Type’ =  Extended.
            1. Click on ‘Download Logs’ button under ‘About’ panel
            2. Select 'Extended' Debug Log Type
            3. Click on Download button.
        3. Verify that the user is able to download log files with ‘Debug Log Type’ =Basic and
        ‘Debug Options’= Sanitize IPs.
            1. Click on ‘Download Logs’ button under ‘About’ panel.
            2. Select ‘Basic’ Debug Log Type.
            3. Check mark on ‘Sanitize IPs’ option under ‘Debug Options’
            4. Click on Download button
        4.Verify that the user is able to download log files with ‘Debug Log Type’ =Extended and
        ‘Debug Options’= Sanitize IPs.
            1. Click on ‘Download Logs’ button under ‘About’ panel.
            2. Select ‘Extended’ Debug Log Type.
            3. Check mark on ‘Sanitize IPs’ option
            4. Click on Download button
        Expected Result: It should download log files in ZIP/TXT format.
        NOTE:
            1.Linux: Log files will be downloaded in ZIP format which contains multiple logs
            2. Windows: Only one text file will be downloaded.
        """
        response = self.cat.api.server.properties()
        about_page = About()
        about_page.open()
        wait(lambda: OverView().is_element_present('update_activation_code_tip'), waiting_for='about page to get load')

        before_file_download_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        about_page.download_logs(debug_log_type=debug_log_type, sanitize_ips=sanitize_checkbox)

        assert about_page.download_button.text == 'Generating...', 'Downloading not started'
        ActionCloseModal().wait_for_modal_closed()

        sleep(sleep_time=TIME_FIVE_SECONDS, reason='Log file to be downloaded entirely')
        downloaded_file = get_downloaded_files_chrome()

        log.debug('Downloaded pcap file is :: {}'.format(downloaded_file))
        file_name = 'nessus-bug-report'

        file_date = re.sub('[A-Za-z-./:_]', '', downloaded_file)
        download_file_time = datetime.datetime.strptime(file_date, '%Y%m%d%H%M%S').strftime('%Y-%m-%d %H:%M:%S')

        assert download_file_time >= before_file_download_time, 'File is not downloaded'

        if response['platform'] == 'WINDOWS':
            assert downloaded_file.split(".")[-1] == 'txt', 'Log files not downloaded in TXT format'
        else:
            assert downloaded_file.split(".")[-1] == 'zip', 'Log files not downloaded in ZIP format'

    def test_cancel_downloading_of_logs(self):
        """
        Verify that user is able to Cancel downloading of logs
        1. Click on ‘Download Logs’ button under ‘About’ panel.
        2. Click on Cancel button
        Expected Result: Opened ‘Download Logs’ page should be closed and navigate back to the About page.
        """
        about_page = About()
        about_page.open()
        wait(lambda: OverView().is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')

        about_page.download_log.click()
        before_file_download_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        modal_window = UnsavedChangesModal()

        assert all([modal_window.is_element_present('modal'),
                    modal_window.unsaved_changes_title.text == 'Download Logs']), \
            'Download Logs pop-up window is invisible'

        # Click on Cancel button
        about_page.download_cancel_button.click()

        assert not modal_window.is_element_present('modal'), 'Download Logs pop-up window is visible'

        assert '/#/settings/about' in get_driver_no_init().current_url, 'User is not on About page.'

    def test_cancel_logs_when_downloading_is_ongoing(self):
        """
        Verify that the user is able to Cancel logs downloading when a log files downloading is ongoing.
        1. Click on ‘Download Logs’ button under ‘About’ panel.
        2. Click on the download button
        3. Click on Cancel button when downloading is ongoing.
        Expected Result: Downloading log file should be stopped and navigate back to About page.
        """
        about_page = About()
        about_page.open()
        wait(lambda: OverView().is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')

        before_file_download_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        about_page.download_logs()
        about_page.download_cancel_button.click()

        assert not UnsavedChangesModal().is_element_present('modal'), 'Download Logs pop-up window is visible'

        assert '/#/settings/about' in get_driver_no_init().current_url, 'User is not on About page.'

    @pytest.mark.browser_file_download
    @pytest.mark.parametrize("nessus_log_level", Nessus.AdvancedSettings.BACKEND_LOG_LEVELS)
    def test_nessus_backend_log_level(self, nessus_log_level):
        """
        NES-9690: UI Automation: Adv Settings | Verify all 3 log levels- verbose, normal, debug in log files downloaded
                  through ssh and/or from UI (downloading logs)

        Scenario Tested:
        [x] Verify that as per set log levels- verbose, normal, debug, logs should be displayed in log files.

        - backend_log_level = normal -> It should display logs in normal verbal format.
        - backend_log_level = debug -> In backend.logs, debug logs will be displayed having '[debug] ' label.
        - backend_log_level = verbose -> in nessusd.messages file, messages'[verbose]' level will be displayed.
        """
        log_level_list = []

        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()
        advanced_setting.get_settings_tab_element(setting_tab=Nessus.AdvancedSettings.LOGGING_TAB).click()

        setting_value = AdvancedSettingsList().get_specific_setting_value(setting_name=Nessus.AdvancedSettings.
                                                                          NESSUS_LOG_LEVEL).text

        if not setting_value == nessus_log_level:
            # Change the value of 'Nessus Log Level' setting from 'Logging' tab
            AddAdvancedSettingModal().select_value_from_setting_dropdown(
                setting_tab=Nessus.AdvancedSettings.LOGGING_TAB, setting_value=nessus_log_level,
                setting_name=Nessus.AdvancedSettings.NESSUS_LOG_LEVEL)

            wait(lambda: advanced_setting.is_element_present('service_restart_link'),
                 waiting_for='Service restart link to visible')

            # Verify that 'Restart now' link is displayed after updating the setting value
            assert advanced_setting.is_element_present("service_restart_link"), \
                '\'Restart Server\' link is not displayed after updating advanced setting value.'

            # Click on 'Restart now' link and wait for server to be ready
            advanced_setting.service_restart_link.click()
            manage_server_restart_task()

        # Go to 'About' page and click on 'Download logs' button from top right corner
        about_page = About()
        about_page.open()
        wait(lambda: OverView().is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')
        about_page.download_logs(debug_log_type='Basic logs')

        # Verify that downloading is started after clicking on 'Generate' button from 'Download Logs' modal
        assert about_page.download_button.text == 'Generating...', 'Downloading is not started.'

        ActionCloseModal().wait_for_modal_closed()
        sleep(sleep_time=TIME_THREE_SECONDS, reason='Log file to be downloaded entirely')

        downloaded_file = get_downloaded_files_chrome()

        log.debug('Downloaded pcap file is :: {}'.format(downloaded_file))
        file_name = 'nessus-bug-report'

        assert file_name in downloaded_file[0], 'Scan results did not export successfully.'

        directory = os.path.join(Config.CAT_LOCAL_BROWSER_DOWNLOAD_PATH, timestamped_path, file_name)
        downloaded_file_path = get_browser_download_file_path(directory)

        if get_os_name() == OperatingSystems.LINUX:
            archive = tarfile.open(downloaded_file_path, "r")

            # Extract downloaded tar.gz file and read the logs from 'backend.log' file
            for mem in archive.getmembers():
                if 'backend.log' in mem.name:
                    log_file = archive.extractfile(mem)

                    for log_line in log_file.readlines():
                        # Append log_line if it is in standard format (i.e. starts with timestamp followed by log_level)
                        if len(log_line.decode('utf-8').split('] ')) > 1:
                            log_level = log_line.decode('utf-8').split('] ')[1].lstrip('[')
                            log_level_list.append(log_level)

                    log.info('Log level from downloaded logs :: :: {}'.format(log_level_list))
                    break
        else:
            start_log_line = self.get_log_line_number(file_path=downloaded_file_path,
                                                      search_text="bug_report\\backend.log")
            end_log_line = self.get_log_line_number(file_path=downloaded_file_path,
                                                    search_text="bug_report\\www_server.log")

            log_file = open(downloaded_file_path, "r")

            for line in log_file.readlines()[start_log_line + 1:end_log_line - 2]:
                if len(line.split('] ')) > 1:
                    log_level = line.split('] ')[1].lstrip('[')
                    log_level_list.append(log_level)

        required_log_levels = {
            Nessus.AdvancedSettings.NORMAL: [Nessus.AdvancedSettings.INFO],
            Nessus.AdvancedSettings.DEBUG: [Nessus.AdvancedSettings.INFO, Nessus.AdvancedSettings.DEBUG],
            Nessus.AdvancedSettings.VERBOSE: [Nessus.AdvancedSettings.INFO, Nessus.AdvancedSettings.DEBUG,
                                              Nessus.AdvancedSettings.VERBOSE]}

        # Verify the nessus log level from 'backend.log' file
        assert all([level in log_level_list for level in required_log_levels.get(nessus_log_level)]), \
            'Nessus backend log level is not same as expected. Expected log level should be \'{}\''.format(
                nessus_log_level)


@pytest.mark.nessus_settings_1
@pytest.mark.linux_only
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.serial
@pytest.mark.disable_logout
@pytest.mark.usefixtures('login')
@pytest.mark.usefixtures('nessus_api_login', "change_expiration_date")
class TestUpdateToPro:
    def test_visibility_and_text_of_buy_now_link(self):
        """
        NES-9310 - NES-9231 Create updated Purchase option in Trialware(Pro Eval)

        Scenarios:
            [x] "Click here to buy now" must be present on overview page

        Steps:
        1. Click on setting link once logged in.
        2. Verify the link text "Click Here to Buy Now".
        """
        # Below step is added to close the host discovery scan wizard which appears for Nessus Pro Trialware.
        close_wizard()
        HeaderBasePage().settings_link.click()

        about_overview = OverView()
        wait(lambda: about_overview.is_element_present("buy_now_on_overview_page"),
             waiting_for="'Buy Nessus Professional now' link to display on about overview page")

        # Verify the link text "Click Here to Buy Now".
        assert about_overview.buy_now_on_overview_page.text == Nessus.About.TenableStore.BUY_NOW_MESSAGE, \
            "Link text is different"

    @pytest.mark.parametrize("click_location", ["Overview page", "Notifications"])
    def test_click_buy_now_link_from_overview_and_notifications(self, click_location):
        """
        NES-9310 - NES-9231 Create updated Purchase option in Trialware(Pro Eval)

        Scenarios:
            [x] Click on "Click here to buy now" link on overview page should redirect the user to
            https://store.tenable.com/...
            [x] Click on  "Click here to buy now" link in the notification should redirect the user to
            https://store.tenable.com/...

        Steps:
        1. Click on setting link once logged in.
        2. Click on "Click here to buy now"(It will take user to new tab).
        3. Verify it is redirecting to correct url.
        4. Switch to previous tab and verify the visibility of purchase completed pop-up.
        """
        # Remove email address of 'admin' user to avoid errors for buy now link.
        nessus_api = NessusAPI()
        nessus_api.login()
        nessus_api.session.edit(name=NessusConfig.CAT_USERNAME, email="")

        # Below step is added to close the host discovery scan wizard which appears for Nessus Pro Trialware.
        close_wizard()

        header_page = HeaderBasePage()
        header_page.settings_link.click()

        about_overview = OverView()
        wait(lambda: about_overview.is_element_present("nessus_version"), timeout_seconds=TIME_THIRTY_SECONDS * 2,
             waiting_for='about overview page gets load properly.')

        wait(lambda: about_overview.is_element_present("buy_now_on_overview_page"),
             waiting_for="'Buy Nessus Professional now' link to display on about overview page")

        windows_handler = WindowsHandler()
        if click_location == "Overview page":
            about_overview.buy_now_on_overview_page.click()
        else:
            header_page.notification_icon.click()
            about_overview.buy_now_in_notification.click()

        sleep(sleep_time=TIME_THREE_SECONDS, reason='Wait for new tab to open')
        windows_handler.switch_to_window(windows_handler.handles[-1])
        try:
            wait(lambda: about_overview.is_element_present('pro_store_page_content', timeout=TIME_THIRTY_SECONDS))
        except TimeoutExpired:
            log.info("Failed while validating page. Current url is : {}".format(get_driver_no_init().current_url))
            raise Exception("Error while validating the page.")

        log.info("Current url is : {}".format(get_driver_no_init().current_url))

        # Verify click on link is redirecting to correct URL
        assert any(get_driver_no_init().current_url.split('/')[2] in tenable_store_url for tenable_store_url in
                   Nessus.About.TenableStore.TENABLE_STORE_LINKS), "It is redirecting to different URL"

        # Verify shopping cart element is present on about page
        assert about_overview.is_element_present("pro_store_page_content"), "Shopping cart does not exist"

        windows_handler.switch_to_window(windows_handler.handles[0])
        sleep(sleep_time=TIME_THREE_SECONDS, reason='Waiting for parent tab to open')

        action_modal = ActionCloseModal()
        wait(lambda: action_modal.is_element_present("close_button", timeout=TIME_THIRTY_SECONDS))

        # Verify the visibility of complete purchase pop-up modal.
        assert action_modal.is_element_present("modal"), "Purchase NP pop-up modal is not visible"

        action_modal.close_button.click()

    def test_content_of_purchase_np_popup(self):
        """
        NES-9310 - NES-9231 Create updated Purchase option in Trialware(Pro Eval)

        Scenarios:
            [x] Verify the content on pop-up display when user comes back to previous tab after purchasing the pro.

        Steps:
        1. Click on setting link once logged in.
        2. Click on "Click here to buy now"(It will take user to new tab).
        3. Switch to previous tab and verify the content of purchase completed pop-up.
        """
        # Below step is added to close the host discovery scan wizard which appears for Nessus Pro Trialware.
        close_wizard()

        HeaderBasePage().settings_link.click()
        about_overview = OverView()
        wait(lambda: about_overview.is_element_present("buy_now_on_overview_page"),
             waiting_for="'Buy Nessus Professional now' link to display on about overview page")

        windows_handler = WindowsHandler(driver=get_driver_no_init())
        about_overview.buy_now_on_overview_page.click()
        windows_handler.switch_to_window(windows_handler.handles[0])
        action_modal = ActionCloseModal()

        # Verify the content on pop-up modal
        assert all(action_modal.is_element_present(element) for element in ('modal', 'action_button',
                                                                            'cancel_button', 'close_button'))

        assert action_modal.modal_title.text == Nessus.About.TenableStore.PURCHASE_NP, \
            "Purchase NP Pop-up title is different"

        assert action_modal.modal_content.text == Messages.NotificationMessages.About.purchase_np_message, \
            "Purchase NP Pop-up message is different"

        action_modal.close_button.click()


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_home
@pytest.mark.usefixtures('login')
class TestUsedHostsForEssential:
    """Test cases related to newly designed value for used_hosts on Overview tab"""

    def test_used_hosts_info_on_overview_tab(self):
        """
        NES-9914 : License consumption visibility (NES-9865)

        Scenarios:
            [x] Verify that used hosts information is available with proper format on Overview tab of About page.

        Steps:
        1. Login to Nessus.
        2. Go to Overview tab on About page.
        3. Verify that "used hosts" information is available with proper format.
        4. Verify that used hosts is less than or equal to max hosts.
        5. Logout from Nessus.
        """

        about_page = OverView()
        about_page.open()
        wait(lambda: about_page.is_element_present('used_hosts'), timeout_seconds=const.TIME_THIRTY_SECONDS,
             waiting_for='OverView tab to be displayed.')

        host_usage_info = about_page.used_hosts.text

        # Verify that "used hosts" information is available with proper format.
        assert re.match(r'(\d{1,2}(?!\d)) of (\d{1,2}(?!\d)) used', host_usage_info), \
            "Used hosts information is not in proper format"

        scanned_host_no = int(host_usage_info.split(' of')[0])
        max_host_scanned = int(host_usage_info.split(' of ')[1].split(' used')[0])

        # Verify that used hosts is less than or equal to max hosts.
        assert scanned_host_no <= max_host_scanned, "used hosts is not less than or equal to max hosts"

    @pytest.mark.xray(test_key='NES-13913')
    def test_upgrade_to_pro_link(self):
        """
        NES-13913 :For Nessus Essential, verify that "Upgrade to Nessus Professional" option is present.

        Scenarios Tested:
        [x] Verify Upgrade to Pro link is available
        [x] Verify modal appears when link is clicked
        [x] Verify title of the modal
        [x] Verify modal is closed when clicking X icon
        """

        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.loaded(), timeout_seconds=WAIT_NORMAL,
             waiting_for="waiting for all plugin data to get loaded")
        sleep(WAIT_NORMAL, reason="It takes little bit time to get settings loaded")
        plugin_values = overview_page.get_about_page_labels(element=overview_page.plugin_values)
        assert Nessus.Essentials.UPGRADE_TO_PROFESSIONAL in plugin_values[
            2], ' Upgrade to Nessus Professional link is not found'
        action_modal = ActionCloseModal()
        overview_page.upgrade_to_pro_link.click()
        assert action_modal.is_element_present('modal'), 'Upgrade modal is not available'
        assert action_modal.modal_title.text == Nessus.Essentials.UPGRADE_TO_PROFESSIONAL, 'Modal title does not match'
        action_modal.close_button.click()
        action_modal.wait_for_modal_closed(timeout_seconds=WAIT_TINY)
        assert not action_modal.is_element_present('modal'), 'modal is still visible'


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestWhileCompiling:
    """
    Covers testing while nessus is compiling.
    """

    cat = None

    @pytest.mark.xray(test_key='NES-16411')
    @pytest.mark.usefixtures('login')
    def test_login_while_nessus_compiling(self):
        """
        NES-16411 : Validate ability to Login while compiling plugins.

        Scenario Tested:
            [x] Verify able to login when nessus is compiling the plugins.
        """
        UserMenu().logout()
        self.cat.api.server.restart()
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
            HTTPStatus.OK, self.cat.api.http_status_code)

        # Wait till server status switch to loading
        wait_for_scanner_status(api=self.cat.api, status=API.Status.LOADING,
                                timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                                sleep_interval=TIME_FIVE_SECONDS)
        response = self.cat.api.server.status()
        if response['initLevel'] != '4':
            self.cat.api.login()
            assert response['status'] == API.Status.LOADING, "Status showing ready while plugin compilation is not done"
