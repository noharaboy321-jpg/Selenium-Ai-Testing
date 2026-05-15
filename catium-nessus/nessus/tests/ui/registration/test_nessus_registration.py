""""
Nessus test cases related to Registration for all type of license.

:copyright: Tenable Network Security, 2019
:date: May 17, 2019
:last_modified: Feb 24, 2023
:author: @yshah, @pdave, @kpanchal, @krpatel
"""

import ipaddress
import re
import socket

import pytest
import requests
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib import const
from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.config import CommonConfig
from catium.lib.const import STRING_NO
from catium.lib.const.base_constants import TIME_TEN_SECONDS, WAIT_NORMAL, TIME_THIRTY_SECONDS, \
    TIME_FIVE_MINUTES, TIME_SIXTY_SECONDS, TIME_FIVE_SECONDS, TIME_THIRTY_MINUTES, WAIT_LONG, TIME_FIFTEEN_MINUTES, \
    HOST_PLUGIN_FEED_STAGING
from catium.lib.errors import CatiumActivationCodeGeneratorError
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.license import remove_nessus_registration
from nessus.helpers.nessus_ui.settings import login_helper_after_server_restart
from nessus.helpers.nessuscli import fix
from nessus.helpers.nessuscli import users
from nessus.helpers.nessuscli.helper import register_nessus_license_type, get_nessus_cli, stop_nessus, start_nessus
from nessus.helpers.nessuscli.update import activation_code_generator
from nessus.helpers.scan import start_stop_nessus_wait_for_ready
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.settings import handle_connection_popup
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.config import NessusConfig
from nessus.lib.const.constants import Nessus, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView, About
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import NotificationActions
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.registration.registration_page import ManagedScannerLicensePage, \
    RegistrationPage, NessusEssentialsLicensePage, ManagerAndProfessionalLicensePage, UserAccountPage
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.setup.setup_page import ProductRegistrationPage, AdvancedSettingsModal
from nessus.pageobjects.setup.setup_page import SetupCommonPoints
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


def login_after_setup_nessus_pro() -> None:
    """ Setup nessus pro and login to nessus """
    register_nessus_license_type(license_type="professional")
    sleep(sleep_time=TIME_SIXTY_SECONDS, reason="waiting for reload to start")

    get_driver_no_init().refresh()
    login_page = LoginPage()

    if login_page.is_element_present('username_field', timeout=TIME_SIXTY_SECONDS):
        login_page.login_with_defaults()


def get_activation_code(properties: dict) -> str:
    """
    This helper function generates activation code according to license type given into server properties

    :param dict properties: server properties
    :return: activation code
    :rtype: str
    """
    serial = None
    if 'professional' in properties['license']['type'] and properties['npv7'] == 0:
        serial = ActivationCodeGenerator.generate_nessus_professional_legacy()
    elif 'manager' in properties['license']['type']:
        serial = ActivationCodeGenerator.generate_nessus_manager_code()
    elif 'users' not in properties['features'] or not properties['features']['users'] or (
            'npv7' in properties and properties['npv7']):
        serial = ActivationCodeGenerator.generate_nessus_professional()
    return serial


def get_offline_license(code: str = '', challenge: str = ''):
    data = {'activation_code': code, 'challenge': challenge}
    base_url = 'https://%s/v2/' % NessusConfig.CAT_PLUGIN_FEED_HOST
    url = base_url + 'offline.php'
    response = requests.post(url, data=data, timeout=const.TIME_SIXTY_SECONDS)

    if response.status_code != 200:
        raise CatiumActivationCodeGeneratorError('Error. HTTP {0} status code returned.'.format(response.status_code))
    match = re.search('<a class="btn" href="(mkconfig.php\?ac=[^"]+)"', response.text)
    url = base_url + match.group(1)

    response = requests.get(url, timeout=const.TIME_SIXTY_SECONDS)
    return response.text


@pytest.mark.license_change
@pytest.mark.serial
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestExpiredLicense:
    """
   This Class covers all the test cases related to nessus behaviour when license expires.
   """

    def test_verify_download_plugin_failed_with_negative_exp_days_over_1_day(self):
        """
        NES-9416 NES-9211 Expiration Lockout settings update

        Scenarios tested:
        [x] Verify Plugin update should not be successful when user uses activation code with negative expiration days.

        Steps:
        1. Go to about page and click on edit activation key icon.
        2. Fill the activation code generated with negative expiration days i.e. -1.
        3. Click on Continue and wait for plugins file to download
        4. Verify it should give error download plugin popup.
        """
        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')
        NotificationActions().remove_all()

        # Verify update activation code tip is visible on UI
        assert overview_page.is_element_present("update_activation_code_tip", timeout=TIME_TEN_SECONDS), \
            'Update Activation code icon is invisible'

        UserMenu().logout()
        login_page = LoginPage()
        wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)

        stop_nessus()
        activation_code = ActivationCodeGenerator().generate_nessus_professional(expiration_days=-1)

        with SSH() as ssh:
            ssh.execute(command='{} fetch --register-only {}'.format(get_nessus_cli(), activation_code))

        try:
            start_nessus()
            wait_for_scanner_to_be_ready(api=NessusAPI())
            wait(lambda: login_page.is_element_present("username_field"), timeout=TIME_FIVE_MINUTES,
                 waiting_for="login page gets loaded")

            login_helper_after_server_restart()
            error_notification = Notifications().errors[-1]

            # Verify the notification error message when user login with expired nessus
            assert all(['Your license expired' in error_notification, '1 day ago' in error_notification]), \
                "Error notification is missing or mismatched for license expiration."

        finally:
            login_after_setup_nessus_pro()

    @pytest.mark.parametrize("license_details", [
        {'product_type': 'pro-eval', 'license_type': 'Nessus Pro Eval (WEBEVAL)'},
        {'product_type': 'professional', 'license_type': 'Nessus Professional'}])
    def test_verify_install_expired_with_negative_exp_days_over_30_days(self, license_details):
        """
        NES-9416 NES-9211 Expiration Lockout settings update

        Scenarios tested:
        [x] Verify Plugin update should not be successful when user uses activation code with negative expiration days.

        Steps:
        1. Go to about page and click on edit activation key icon.
        2. Fill the activation code generated with negative expiration days i.e. -31.
        3. Click on Continue and wait for plugins file to download
        4. Verify it should give error download plugin popup.
        5. Restart the nessus service.
        6. Verify it should show license expired popup.
        7. Verify tenable customer support and tenable renewal links are visible on UI.
        8. Repeat the steps for nessus professional
        """
        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')
        NotificationActions().remove_all()

        assert overview_page.update_activation_code_tip.is_displayed(), \
            'Update Activation code icon is invisible or not present.'

        UserMenu().logout()
        activation_code = ActivationCodeGenerator().generate_nessus_professional(expiration_days=-31) \
            if license_details['product_type'] == 'professional' \
            else activation_code_generator(expire_days=-1, product_type='pro-eval', flag=True)

        with SSH() as ssh:
            ssh.execute(command='{} fetch --register-only {}'.format(get_nessus_cli(), activation_code))

        try:
            wait_for_scanner_status(api=NessusAPI(), timeout=TIME_FIFTEEN_MINUTES, status=API.Status.FEED_EXPIRED,
                                    msg='server to finish loading.', sleep_interval=WAIT_NORMAL)

            setup_points = SetupCommonPoints()
            setup_points.refresh()
            wait(lambda: setup_points.install_expired.text == Nessus.PluginDownloadFailedPage.INSTALLATION_EXPIRED,
                 timeout_seconds=TIME_FIVE_MINUTES)

            # Verify it should show installation expired pop-up, tenable customer support link and tenable renewal link.
            assert setup_points.install_expired.text == Nessus.PluginDownloadFailedPage.INSTALLATION_EXPIRED, \
                "Page title is different, actual title is {}".format(setup_points.install_expired.text)

            assert setup_points.is_element_present("tenable_customer_support"), \
                "Tenable customer support link is not visible"

            assert setup_points.is_element_present('tenable_renewals'), "Tenable renewals link is not visible"
        finally:
            login_after_setup_nessus_pro()

    @pytest.mark.xfail(reason='Refer JIRA ID NES-11286')
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'description': 'Created a {} scan for NES-9416.'.format(Nessus.TemplateNames.ADVANCED.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST},
        {'scan_template': Nessus.TemplateNames.BASIC_NETWORK, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.BASIC_NETWORK)),
         'description': 'Created a {} scan for NES-9416.'.format(Nessus.TemplateNames.BASIC_NETWORK.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    def test_scans_behaviour_with_expired_license(self, create_scans):
        """
         NES-9416 NES-9211 Expiration Lockout settings update
         Scenarios tested:
         [x] Verify scan should not be launched when user uses activation code with negative expiration days.
         [x] Verify scheduled scan should be disabled when user uses activation code with negative expiration days.
         Steps:
         1. Go to about page and click on edit activation key icon.
         2. Fill the activation code generated with negative expiration days i.e. -1.
         3. Click on Continue and wait for plugins file to download
         4. Verify it should give error download plugin popup.
         5. Restart the nessus service using SSH.
         6. Login to nessus and verify that the scan should not be launched and it should give error.
         7. Verify scheduled scan should be disabled.
         """
        scan_page = ScansPage()
        wait(lambda: scan_page.is_element_present("scan_searchbox", timeout=TIME_FIVE_SECONDS))

        overview_page = OverView()
        overview_page.open()
        NotificationActions().remove_all()

        # Verify update activation code tip is visible on UI
        assert overview_page.update_activation_code_tip.is_displayed(), \
            'Update Activation code icon is invisible or not present.'

        UserMenu().logout()
        activation_code = ActivationCodeGenerator().generate_nessus_professional(expiration_days=-1)

        with SSH() as ssh:
            ssh.execute(command='{} fetch --register-only {}'.format(get_nessus_cli(), activation_code))

        try:
            wait_for_scanner_to_be_ready(api=NessusAPI())
            wait(lambda: LoginPage().is_element_present("username_field"), timeout_seconds=TIME_FIVE_MINUTES)

            login_helper_after_server_restart()
            notifications = Notifications()

            # Verify the notification error message when user login with expired nessus
            assert 'Your license expired' in notifications.errors[0], \
                "Error notification is missing or mismatched for license expiration."

            assert '1 day ago' in notifications.errors[0], \
                "Error notification is missing or mismatched for license expiration."

            wait(lambda: scan_page.is_element_present('scan_searchbox', timeout=TIME_FIVE_SECONDS))
            notification_actions = NotificationActions()
            notification_actions.remove_all()

            scan_list = ScanList()
            scan_list.launch_scan(scan_name=create_scans[0])

            notifications = Notifications()

            # Verify the error notification message
            assert notifications.errors[-1] == Messages.ExpiredLicense.scan_launch_disabled, \
                "Error message doesn't displayed"

            notification_actions.remove_all()
            scan_list.click_on_scan(scan_name=create_scans[1])
            scan_result_page = ScanViewPage()
            wait(lambda: scan_result_page.is_element_present("configure_button", timeout=TIME_THIRTY_SECONDS))

            scan_result_page.configure.click()
            basic_setting = BasicSetting()
            basic_setting.schedule.click()
            basic_setting.enable_schedule.toggle()

            # Verify it should show warning text in schedule scan
            assert scan_result_page.schedule_scan_warning.text == Messages.ExpiredLicense.schedule_scan_warning, \
                "No warning schedule scan related message found"

            HeaderBasePage().scan_link.click()
            wait(lambda: scan_page.is_element_present("scan_searchbox", timeout=TIME_FIVE_SECONDS))
            scan_list.launch_scan(scan_name=create_scans[1])

            notifications = Notifications()

            # Verify the error notification message
            assert notifications.errors[-1] == Messages.ExpiredLicense.scan_launch_disabled, \
                "Error message doesn't displayed"
        finally:
            login_after_setup_nessus_pro()


@pytest.mark.license_change
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.serial
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.usefixtures('wizard_open', 'disable_auto_update')
class TestNessusRegistrationValidations:
    """
    This Class covers all the test cases related to validation messages, UI content and tooltip for each license type
    """

    @staticmethod
    def generate_activation_code(product_type: str, expiration_days: float) -> str:
        """
        This function will generate and return activation code

        :param str product_type: type of product
        :param Float expiration_days: Number of days
        :return: activation code for apparent product-type
        :rtype: str
        """
        activation_code = ActivationCodeGenerator()
        if product_type == ActivationCodeGenerator.NESSUS_MANAGER:
            code = activation_code.generate_nessus_manager_code(expiration_days=expiration_days)
        elif product_type == ActivationCodeGenerator.NESSUS_EXPERT:
            code = activation_code.generate_nessus_expert_code(expiration_days=expiration_days)
        else:
            code = activation_code.generate_code(code_type=product_type, expiration_days=expiration_days)

        return code

    def test_verify_content_of_nessus_registration_page(self):
        """
        NES-9317 NES-9131 Single-site Essentials Activation

        Scenarios tested:
        [x] Verify the content of Nessus registration page.

        Steps:
        1. Go to registration page and verify all type of licenses are available on UI
        2. Verify all the type of scanners are visible on UI
        3. Verify continue button is visible.
        """
        remove_nessus_registration()
        register_page = RegistrationPage()

        # Refreshing the web page after removing Nessus registration.
        register_page.refresh()
        wait(lambda: register_page.is_element_present("page_header"), timeout_seconds=TIME_SIXTY_SECONDS,
             waiting_for="Nessus registration page to get loaded")
        register_page.continue_button.click()
        wait(lambda: register_page.is_element_present('page_header'), timeout_seconds=TIME_SIXTY_SECONDS)
        nessus_type = [element.text for element in register_page.license_type]

        # Verify all the type of scanners are visible on UI
        assert nessus_type == Nessus.RegistrationPage.NESSUS_TYPE, "{} license type is not visible on UI" \
            .format(set(Nessus.RegistrationPage.NESSUS_TYPE) - set(nessus_type))
        # Verify continue button is visible.
        assert all(register_page.is_element_present(element) for element in ("continue_btn", "page_header")), \
            "Element is not visible on registration page"

    def test_verify_content_of_nessus_essential_registration_page(self):
        # TODO test-try2
        """
        NES-9317 NES-9131 Single-site Essentials Activation

        Scenarios tested:
        [x] Verify the content of Nessus essentials registration page.

        Steps:
        1. Go to registration page and click on 'Nessus essentials'
        2. Verify all fields are visible on UI
        """
        registration = RegistrationPage()
        registration.continue_button.click()
        wait(lambda: registration.is_element_present('page_header'), timeout_seconds=TIME_SIXTY_SECONDS)
        registration.get_by_license_type(license_type='Register for Nessus Essentials').click()
        registration.continue_btn.click()

        # Verify all fields are visible on UI
        assert all(NessusEssentialsLicensePage().is_element_present(element)
                   for element in ("first_name", "last_name", "email_input", "skip_btn", "back_button",
                                   "register_button")), "All the element are not visible on registration page"

    def test_verification_of_buttons_working_and_validations_for_essentials(self):
        """
        NES-9317 NES-9131 Single-site Essentials Activation

        Scenarios tested:
        [x] Verify the validation messages, tooltip and working of buttons on essential registration page

        Steps:
        1. Go to registration page and verify the tooltip displayed on UI for nessus essentials.
        2. Click on Continue.
        3. Click on skip button and verify the activation code input field is visible.
        4. Click on back button and verify the page header of registration page.
        """
        registration = RegistrationPage()

        # Refreshing the web page after removing Nessus registration.
        registration.refresh()
        license_type = "Register for Nessus Essentials"

        log.debug("Waiting for 'Registration' page")
        wait(lambda: registration.is_element_present("page_header"), timeout_seconds=TIME_SIXTY_SECONDS,
             waiting_for="Nessus registration page to get loaded")

        registration.continue_button.click()
        log.info("Select {} type and click on 'Continue' button".format(license_type))

        # Verify the tooltip displayed on UI
        assert registration.get_tooltip_by_license(license_type=license_type).get_attribute(
            'original-title') == Messages.ToolTip.nessus_essentials, "Tooltip is different"
        registration.get_by_license_type(license_type=license_type).click()
        registration.continue_btn.click()
        nessus_essential = NessusEssentialsLicensePage()

        LoadingCircle(WAIT_NORMAL)
        nessus_essential.skip_btn.click()
        nessus_license = ManagerAndProfessionalLicensePage()

        # Verify the activation input field is visible on UI
        assert nessus_license.is_element_present("activation_input"), "Activation code field is not present"
        nessus_essential.activation_code_back.click()

        # Verify the page header is correct
        assert nessus_essential.page_header.text == Nessus.RegistrationPage.ACTIVATION_CODE_HEADER, \
            "Welcome header message does not match"

    @pytest.mark.parametrize("license_type", ['Start a trial of Nessus Professional', 'Start a trial of Nessus Expert'])
    def test_verify_content_of_nessus_pro_and_nessus_expert(self, license_type):
        """
        NES-9317 NES-9131 Single-site Essentials Activation

        Scenarios tested:
        [x] Verify the content of Start a trial of Nessus professional registration page.
        [x] Verify the content of Start a trial of Nessus Expert registration page.

        Steps:
        1. Go to registration page and verify all fields are visible on UI
        2. Verify the tooltip.
        3. Repeat step #1 and #2 for Nessus Manager.
        """
        remove_nessus_registration()
        registration = RegistrationPage()
        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
             waiting_for="page header to appear")

        registration.continue_button.click()
        registration.get_by_license_type(license_type=license_type).click()

        # Verify the tooltip displayed on UI
        if license_type == "Start a trial of Nessus Expert":
            assert registration.get_tooltip_by_license(license_type=license_type).get_attribute(
                'original-title') == Messages.ToolTip.expert_title, "Tooltip is different for expert license trial"
        else:
            assert registration.get_tooltip_by_license(license_type=license_type).get_attribute(
                'original-title') == Messages.ToolTip.professional_title, "Tooltip is different for pro license trial"

        registration.continue_btn.click()
        wait(lambda: registration.is_element_present('get_started'), timeout_seconds=TIME_TEN_SECONDS)
        assert registration.get_started.text == Nessus.RegistrationPage.GET_STARTED, "Title not matched."
        random_char = random_name(prefix='nessus')
        registration.email_input.value = (random_char + "@tenable.com")
        registration.continue_contact_lookup.click()

        # Verify all fields are visible on UI
        assert all(RegistrationPage().is_element_present(element)
                   for element in ("first_name", "last_name", "phone_text",
                                   "job_title", "company_name", "company_size", "link")), \
            "Elements are not visible on registration page"

    @pytest.mark.parametrize("license_type", ['Set up a purchased instance of Nessus'])
    @pytest.mark.parametrize("products_type", ['manager', 'professional', 'expert'])
    # TODO: add case for another license type. ("license_type", ['Start a trial of Nessus Professional'])
    def test_verification_of_buttons_working_and_validations_for_nessus(self, license_type, products_type):
        """
        NES-9317 NES-9131 Single-site Essentials Activation

        Scenarios tested:
        [x] Verify the tooltip and working of buttons and navigation on nessus product registration page
        [ ] Verify the tooltip and working of buttons on nessus professional registration page

        Steps:
        1. Go to registration page and Click on Continue
        2. Verify the tooltip displayed.
        3. Click on back buttons 2 times and check settings button is available
        4. Click on settings button and verify modal is opened
        5. Close the setting modal and go back to license registration page
        6. Click on back button and verify the page header of registration page.
        7. Click on skip and again go back to check the navigation
        8. Go to activation and add the code
        9. Verify the code on license information screen.
        """
        registration = RegistrationPage()
        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
             waiting_for="page header to appear")

        registration.continue_button.click()
        log.info("Select {} type and click on 'Continue' button".format(license_type))
        registration.get_by_license_type(license_type=license_type).click()

        assert registration.get_tooltip_by_license(license_type=license_type).get_attribute(
            'original-title') == Messages.ToolTip.top_radiobutton_tip, "Tooltip is different"
        registration.continue_btn.click()

        nm_and_np_license = ManagerAndProfessionalLicensePage()
        wait(lambda: nm_and_np_license.is_element_present("btn_back_login"))
        nm_and_np_license.btn_back_login.click()
        wait(lambda: registration.is_element_present("btn_back_button"))
        nm_and_np_license.btn_back_button.click()

        wait(lambda: nm_and_np_license.is_element_present("setting_button"))
        nm_and_np_license.setting_button.click()

        advanced_settings_modal = AdvancedSettingsModal()
        advanced_settings_modal.new_cancel_button.click()

        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_SECONDS,
             waiting_for="page header to appear")
        registration.continue_button.click()
        log.info("Select {} type and click on 'Continue' button".format(license_type))
        registration.get_by_license_type(license_type=license_type).click()
        registration.continue_btn.click()

        wait(lambda: registration.is_element_present("skip_btn"))
        registration.skip_btn.click()
        wait(lambda: registration.is_element_present("back_activation"))
        registration.back_activation.click()
        wait(lambda: registration.is_element_present("skip_btn"))
        registration.skip_btn.click()
        log.debug("Skipped email-verification")

        wait(lambda: registration.is_element_present("activation_code"))
        assert registration.activation_code.text == Nessus.RegistrationPage.ACTIVATION_CODE, \
            "Activation code header message does not match"

        code = self.generate_activation_code(product_type=products_type,
                                             expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)
        ManagerAndProfessionalLicensePage().activation_input.value = code
        registration.continue_activation.click()
        wait(lambda: registration.is_element_present("continue_button"), timeout=TIME_TEN_SECONDS,
             waiting_for="next page header to appear")

        assert registration.page_header.text == Nessus.RegistrationPage.LICENSE_INFORMATION, \
            "License Information header not matched"
        activation_code_text = registration.license_code.text
        assert code in activation_code_text, "Activation code not matched at license information screen."

    @pytest.mark.parametrize("select_by_text", ['Tenable Vulnerability Management', 'Tenable Security Center',
                                                'Nessus Manager (Scanner)', 'Nessus Manager (Cluster Node)'])
    def test_verification_of_buttons_working_and_validations_for_managed_scanner(self, select_by_text):
        """
         NES-9317 NES-9131 Single-site Essentials Activation

         Scenarios tested:
         [x] Verify the validation messages, tooltip and working of buttons on Nessus managed scanner page.

         Steps:
         1. Go to registration page and click on "Managed scanner"
         2. Click on Tenable.io and click on continue
         3. Click on continue button and verify the error message
         4. Click on back button and verify the page header.
         5. Click on setting and verify the setting modal appears
         6. Verify managed by dropdown is visible on UI.
         7. Repeat the steps for "Nessus Manager" and "Tenable.sc"
         """
        license_type = "Link Nessus to another Tenable product"

        log.debug("Waiting for 'Registration' page")
        registration = RegistrationPage()
        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
             waiting_for="page header to appear")

        registration.continue_button.click()
        log.info("Select {} type and click on 'Continue' button".format(license_type))

        registration.get_by_license_type(license_type=license_type).click()
        registration.continue_btn.click()

        managed_scanner = ManagedScannerLicensePage()
        wait(lambda: managed_scanner.is_element_present("managed_by_dropdown"))
        managed_scanner.managed_by_dropdown.select_by_visible_text(select_by_text)

        if select_by_text == "Tenable.io":
            managed_scanner.continue_button.click()

            # Verify the error message displayed when click on continue without filling linking key
            assert Notifications().errors[-1] == Messages.NotificationMessages.missing_linking_key, \
                "Error message doesn't displayed"
        elif select_by_text == "Nessus Manager (Scanner)":
            managed_scanner.continue_button.click()

            # Verify the error message displayed when click on continue without filling linking key and host
            assert Notifications().errors[-1] == Messages.NotificationMessages.missing_host_and_key, \
                "Error message doesn't displayed"

            # wait for previous error notification to remove
            managed_scanner.port_field.clear()
            managed_scanner.continue_button.click()

            # Verify the error message displayed when click on continue without filling linking key, host and port
            assert Notifications().errors[-1] == Messages.NotificationMessages.missing_host_port_and_key, \
                "Error message doesn't displayed"

        managed_scanner.back_button.click()
        wait(lambda: managed_scanner.is_element_present("page_header"))

        # Verify the page header
        assert managed_scanner.page_header.text == Nessus.RegistrationPage.WELCOME_HEADER, \
            "Welcome header message does not match"

        registration.get_by_license_type(license_type=license_type).click()
        registration.continue_btn.click()
        wait(lambda: managed_scanner.is_element_present("back_button"))
        registration.back_button.click()
        wait(lambda: registration.is_element_present("btn_back_button"))
        registration.btn_back_button.click()
        wait(lambda: managed_scanner.is_element_present("setting_button"))
        managed_scanner.setting_button.click()

        advanced_settings_modal = AdvancedSettingsModal()
        wait(lambda: advanced_settings_modal.is_element_present("new_cancel_button"), timeout=TIME_FIVE_SECONDS,
             waiting_for="button to appear")
        advanced_settings_modal.new_cancel_button.click()

        log.debug("Waiting for 'Registration' page")
        registration = RegistrationPage()
        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
             waiting_for="page header to appear")

        registration.continue_button.click()
        log.info("Select {} type and click on 'Continue' button".format(license_type))

        registration.get_by_license_type(license_type=license_type).click()
        registration.continue_btn.click()

        # Verify the managed by dropdown is visible on managed scanner page
        assert managed_scanner.is_element_present("managed_by_dropdown"), "Managed by dropdown is not visible"

    def test_verification_of_buttons_working_and_validations_for_user_account_page(self):
        """
        NES-9317 NES-9131 Single-site Essentials Activation

        Scenarios tested:
        [x] Verify the validation messages, tooltip and working of buttons on Nessus user account page.

        Steps:
         1. Go to registration page and click on "Nessus Professional"
         2. Click on continue button and enter activation code value as "0ABF"
         3. Click on continue button.
         4. Click on submit button and verify the error notification.
         5. Enter username, click submit and verify the error notification.
         6. Enter password, click submit and verify the error notification
        """
        registration = RegistrationPage()
        registration.continue_button.click()

        wait(lambda: registration.is_element_present("continue_btn"))
        registration.get_by_license_type(license_type="Set up a purchased instance of Nessus").click()
        registration.continue_btn.click()

        wait(lambda: registration.is_element_present("skip_btn"))
        registration.skip_btn.click()
        professional = ManagerAndProfessionalLicensePage()
        professional.activation_input.value = "0ABF"

        wait(lambda: registration.is_element_present("continue_activation"))
        registration.continue_activation.click()

        wait(lambda: registration.is_element_present("continue_button"))
        registration.continue_button.click()

        user_account = UserAccountPage()
        user_account.submit_button.click()
        notifications = Notifications()

        # Verify the error message displayed when click on submit button without filling username and password
        assert notifications.errors[-1] == Messages.NotificationMessages.missing_username_password, \
            "Error message doesn't displayed"

        # wait for previous error notification to disappear
        LoadingCircle(WAIT_NORMAL)
        user_account.username.value = "admin"
        user_account.submit_button.click()
        notifications = Notifications()

        # Verify the error message displayed when click on submit button without filling password
        assert notifications.errors[-1] == Messages.NotificationMessages.missing_password, \
            "Error message doesn't displayed"
        # wait for previous error notification to disappear
        LoadingCircle(WAIT_NORMAL)
        user_account.username.clear()
        user_account.password.value = "admin"
        user_account.submit_button.click()
        notifications = Notifications()

        # Verify the error message displayed when click on submit button without filling username
        assert notifications.errors[-1] == Messages.NotificationMessages.missing_username, \
            "Error message doesn't displayed"

    @pytest.mark.parametrize("select_text, values", [
        ("Tenable Vulnerability Management", ["managed_by_dropdown", "linking_key", "continue_button",
                                              "back_button"]),
        ("Nessus Manager (Scanner)", ["managed_by_dropdown", "linking_key",
                                      "continue_button", "back_button", "host_field", "port_field"]),
        ("Tenable Security Center", ["managed_by_dropdown", "continue_button", "back_button"]),
        ("Nessus Manager (Cluster Node)", ["managed_by_dropdown", "continue_button", "back_button"])])
    def test_verify_content_of_managed_scanner(self, select_text, values):
        """
        NES-9317 NES-9131 Single-site Essentials Activation

        Scenarios tested:
        [x] Verify the content of Nessus managed scanner page.

        Steps:
        1. Go to registration page and click on "Managed scanner"
        2. Select tenable.io form dropdown
        3. Verify all fields are visible on UI on Managed scanner registration page for tenable.io value
        4. Repeat the steps for "Nessus Manager" and "Tenable.sc" value
        """
        log.debug("Waiting for 'Registration' page")
        registration = RegistrationPage()
        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
             waiting_for="page header to appear")

        registration.continue_button.click()
        license_type = "Link Nessus to another Tenable product"
        registration = RegistrationPage()
        registration.get_by_license_type(license_type=license_type).click()

        # Verify the tooltip visible on UI
        assert registration.get_tooltip_by_license(license_type=license_type).get_attribute(
            'original-title') == Messages.ToolTip.managed_scanner, "Tooltip is different"
        registration.continue_btn.click()
        managed_scanner = ManagedScannerLicensePage()
        managed_scanner.managed_by_dropdown.select_by_visible_text(select_text)
        assert all(managed_scanner.is_element_present(element) for element in values), \
            "All the element are not visible on registration page"

    @pytest.mark.parametrize("license_type", ['Nessus Professional', 'Nessus Manager', 'Nessus Expert'])
    def test_verification_of_buttons_working_and_validations_for_offline_page(self, license_type):
        """
        NES-9317 NES-9131 Single-site Essentials Activation

        Scenarios tested:
        [x] Verify the content of Nessus offline scanner page.

        Steps:
        1. Go to registration page and click on "Nessus Professional"
        2. Verify the checkbox is unchecked and offline input box is not visible by default.
        3. Click on checkbox and click on continue button without filling activation code.
        4. Verify the error message.
        5. Fill the fake offline key and click on continue.
        6. Verify it should take the user to user registration page.
        7. Click on back button and click on setting button.
        8. Verify the setting modal should appear and close the modal.
        9. Click on back and verify it should be on Registration page.
        """
        response = NessusAPI().server.status()

        if response.get('status') != API.Status.REGISTER:
            remove_nessus_registration()
        log.debug("Waiting for 'Registration' page")
        registration = RegistrationPage()
        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
             waiting_for="page header to appear")
        nm_and_np_license = ManagerAndProfessionalLicensePage()

        # Verify the checkbox is unchecked and offline input box is not visible by default.
        assert nm_and_np_license.register_offline_checkbox.get_attribute("class").split()[-1] != "checked", \
            "Checkbox is not checked by default"

        nm_and_np_license.register_offline_checkbox.click()
        nm_and_np_license.continue_button.click()

        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_SECONDS,
             waiting_for="page header to appear")
        assert registration.page_header.text == Nessus.RegistrationPage.WELCOME_HEADER, \
            "Welcome header message does not match"

        registration.get_by_license_type(license_type=license_type).click()
        registration.continue_button.click()
        # Verify the input box is not visible by default.
        assert nm_and_np_license.is_element_present("nessus_license_key_offline"), \
            "Nessus offline license key is visible on UI"
        nm_and_np_license.nessus_license_key_offline.value = "OABF"
        nm_and_np_license.continue_button.click()

        # Verify Click on continue should take the user to user registration page
        user_account_page = UserAccountPage()
        assert user_account_page.is_element_present("username"), "User name field is not visible"
        user_account_page.back_button.click()
        wait(lambda: user_account_page.is_element_present('back_button'), timeout_seconds=TIME_THIRTY_SECONDS)
        user_account_page.back_button.click()
        wait(lambda: user_account_page.is_element_present('back_button'), timeout_seconds=TIME_THIRTY_SECONDS)
        user_account_page.back_button.click()
        wait(lambda: nm_and_np_license.is_element_present('setting_button'), timeout_seconds=TIME_THIRTY_SECONDS)
        nm_and_np_license.setting_button.click()
        action_close_modal = ActionCloseModal()

        # Verify the setting modal should appear
        assert action_close_modal.is_element_present('modal'), "Setting modal does not open"
        action_close_modal.close_button.click()

        # Verify the page header
        wait(lambda: registration.is_element_present('page_header'), timeout_seconds=TIME_THIRTY_SECONDS)
        assert registration.page_header.text == Nessus.RegistrationPage.WELCOME_HEADER, \
            "Welcome header message does not match"
        nm_and_np_license.register_offline_checkbox.click()

    @pytest.mark.parametrize("proxy_host_type", ["IPv4", "IPv6", "Host name", "FQDN"])
    @pytest.mark.parametrize("plugin_feed_host_type", ["IPv4", "IPv6", "Host name", "FQDN"])
    @pytest.mark.parametrize("proxy_port", [API.Settings.ProxyServer.PROXY_PORT, 0, -1])
    def test_proxy_and_plugin_feed_settings_accepts_only_valid_host_and_port_while_registration(
            self, proxy_host_type, plugin_feed_host_type, proxy_port):
        """
        NES-12920: Automation for proxy IP vs hostname

        Scenarios Tested:
        [x] Proxy host accepts IPs (ipv4/ipv6) and hostnames (includes FQDN)
        [x] Proxy port accepts ports only
        [x] Plugin feed custom host allows for the same entry as proxy host
        [x] All other inputs allow expected values
        """
        response = NessusAPI().server.status()

        if response.get('status') != API.Status.REGISTER:
            remove_nessus_registration()

        ProductRegistrationPage().setting_button.click()
        action_close_modal = ActionCloseModal()

        assert action_close_modal.is_element_present('modal'), \
            "Advanced Settings modal does not open after clicking on 'Settings' link while register Nessus."

        proxy_host_ip_v4 = Nessus.Scan.Target.AWS_LINUX_TARGET_2
        proxy_host_ip_v6 = ipaddress.IPv6Address('2002::' + proxy_host_ip_v4).compressed

        proxy_host_details_by_type = {"IPv4": proxy_host_ip_v4, "IPv6": proxy_host_ip_v6,
                                      "Host name": socket.gethostbyaddr(proxy_host_ip_v4)[0],
                                      "FQDN": socket.getfqdn(proxy_host_ip_v4)}

        proxy_settings = {'username': API.Settings.ProxyServer.PROXY_USERNAME,
                          'password': API.Settings.ProxyServer.PROXY_PASSWORD}

        advanced_setting = AdvancedSettingsModal()
        advanced_setting.fill_proxy_settings_form(host=proxy_host_details_by_type[proxy_host_type], port=proxy_port,
                                                  **proxy_settings)

        plugin_feed_host_ip_v4 = Nessus.Scan.Target.OLD_STAGING_FEED_SERVER_HOST
        plugin_feed_host_ip_v6 = ipaddress.IPv6Address('2002::' + plugin_feed_host_ip_v4).compressed

        plugin_feed_host_details_by_type = {"IPv4": plugin_feed_host_ip_v4, "IPv6": plugin_feed_host_ip_v6,
                                            "Host name": socket.gethostbyaddr(plugin_feed_host_ip_v4)[0],
                                            "FQDN": socket.getfqdn(plugin_feed_host_ip_v4)}

        advanced_setting.plugin_feed.click()
        advanced_setting.custom_host_field.value = plugin_feed_host_details_by_type[plugin_feed_host_type]
        advanced_setting.save_button.click()

        if proxy_port == API.Settings.ProxyServer.PROXY_PORT:
            action_close_modal.wait_for_modal_closed()

            assert not action_close_modal.is_element_present('modal'), \
                "Getting error while saving advanced settings with '{}' host or port type while register " \
                "Nessus.".format(proxy_host_type)
        else:
            notification = Notifications()

            assert notification.errors[-1] == Messages.NotificationMessages.continue_button_code, \
                'Getting incorrect error notification, Expected is \'{}.\''.format(
                    Messages.NotificationMessages.continue_button_code)

            advanced_setting.cancel_button.click()

    @pytest.mark.license_change
    @pytest.mark.disable_logout
    @pytest.mark.parametrize("license_type", ['Nessus Professional'])
    def test_software_update_button_for_offline_registration(self, license_type):
        """
        Scenarios Tested: CS-58827 : Manual software update button is not disabled when trying offline nessus config
        [x] . Button is enabled and able to click when there is no plugin set available

        1. Login to Nessus
        2. remove the registration on nessus
        3. Reload the nessus and go to configuration page
        4. select offline button
        5. Generate the activation code nad license file
        6. Provide to configuration
        7. Login to Nessus once UI is up
        8. Go to the software settings page
        9. Check and click on manual software update button
        """
        nessus_api = NessusAPI()
        response = nessus_api.server.status()

        if response.get('status') != API.Status.REGISTER:
            remove_nessus_registration()
        log.debug("Waiting for 'Registration' page")
        registration = RegistrationPage()
        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
             waiting_for="page header to appear")
        nm_and_np_license = ManagerAndProfessionalLicensePage()

        # Verify the checkbox is unchecked and offline input box is not visible by default.
        assert nm_and_np_license.register_offline_checkbox.get_attribute("class").split()[-1] != "checked", \
            "Checkbox is not checked by default"

        nm_and_np_license.register_offline_checkbox.click()
        nm_and_np_license.continue_button.click()

        wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_SECONDS,
             waiting_for="page header to appear")
        assert registration.page_header.text == Nessus.RegistrationPage.WELCOME_HEADER, \
            "Welcome header message does not match"

        registration.get_by_license_type(license_type=license_type).click()
        registration.continue_button.click()

        # Verify the input box is not visible by default.
        assert nm_and_np_license.is_element_present("nessus_license_key_offline"), \
            "Nessus offline license key is visible on UI"

        overview_page = OverView()
        properties = nessus_api.server.properties()
        activation_code = get_activation_code(properties=properties)
        nessus_license = get_offline_license(code=activation_code, challenge=overview_page.challenge_code_text.text)

        nm_and_np_license.nessus_license_key_offline.value = "\n" + nessus_license
        LoadingCircle(WAIT_LONG)
        registration.continue_button.click()

        user_account = UserAccountPage()
        wait(lambda: user_account.is_element_present("username"), timeout=TIME_FIVE_SECONDS,
             waiting_for="username field to appear")
        user_account.username.value = "admin"
        wait(lambda: user_account.is_element_present("password"), timeout=TIME_FIVE_SECONDS,
             waiting_for="username field to appear")
        user_account.password.value = "admin"
        user_account.submit_button.click()

        handle_connection_popup(timeout_to_appear=TIME_FIFTEEN_MINUTES, timeout_to_disappear=TIME_THIRTY_MINUTES)

        # Wait till server is ready
        wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES,
                                msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)

        get_driver_no_init().refresh()
        wait(lambda: visibility_of_element_located(LoginPage().username_field))
        LoginPage().login_with_defaults()
        overview_page.open()
        wait(lambda: overview_page.is_element_present('update_activation_code_tip'),
             waiting_for='about page to get load')

        if not get_driver_no_init().current_url.endswith('/settings/about/software-update'):
            HeaderBasePage().settings_link.click()

            about_page = About()
            wait(lambda: about_page.is_element_present("software_update_tab"))
            about_page.software_update_tab.click()

            wait(lambda: overview_page.is_element_present('manual_software_update_button'),
                 waiting_for='manual software button to visible')

            assert overview_page.is_element_present(
                'manual_software_update_button'), "Software update button is not available."

            # Verify that button is not disabled and able to click.
            overview_page.manual_software_update_button.click()
            wait(lambda: overview_page.is_element_present('continue_on_button'),
                 waiting_for='manual software button to visible')
            assert overview_page.is_element_present('continue_on_button'), "Modal popup is not opened."


@pytest.mark.license_change
@pytest.mark.usefixtures('reset_license', 'wizard_open', 'disable_auto_update')
class TestNessusRegistrationProcess:
    """
    This Class covers all the test cases related to registration process for each license type
    """

    @staticmethod
    def generate_activation_code(product_type: str, expiration_days: float) -> str:
        """
        This function will generate and return activation code

        :param str product_type: type of product
        :param Float expiration_days: Number of days
        :return: activation code for apparent product-type
        :rtype: str
        """
        activation_code = ActivationCodeGenerator()

        code = activation_code.generate_nessus_manager_code(expiration_days=expiration_days) \
            if product_type == ActivationCodeGenerator.NESSUS_MANAGER else activation_code.generate_code(
            code_type=product_type, expiration_days=expiration_days)

        return code

    @staticmethod
    def set_and_validate_settings_via_cli(setting_name: str, setting_value: str) -> None:
        """
        This function will set settings via CLI and validate those settings

        :param str setting_name: setting name
        :param str setting_value: setting value
        :return: None
        """
        secure = True if setting_name == 'custom_host' else False
        output = fix.set(key=setting_name, value=setting_value, secure=secure)

        assert "Successfully set '{}' to '{}'".format(setting_name, setting_value) in output['stdout'] and not \
            output['stderr'], "Updating {} setting to {} wasn't successful".format(setting_name, setting_value)

    def add_user_and_register_nessus(self, expiration_day: float, nessus_type: str):
        """  """
        log.debug('Adding user into Nessus')
        add_user_output = users.adduser(username='admin', password='admin', passconfirm='admin', sysadmin=True)

        # Verifies user is added successfully in Nessus
        assert 'User added' in add_user_output['stdout'], 'Failed to add user in Nessus...'

        log.debug("Setting {} value to {}".format('custom_host', HOST_PLUGIN_FEED_STAGING))
        self.set_and_validate_settings_via_cli(setting_name='custom_host', setting_value=HOST_PLUGIN_FEED_STAGING)

        log.debug("Generate 'Activation code' for {}".format(nessus_type))
        code = self.generate_activation_code(product_type=nessus_type, expiration_days=expiration_day)

        with SSH() as ssh:
            log.debug("Register Nessus {}".format(nessus_type))
            ssh.execute("{} fetch --register {}".format(get_nessus_cli(), code))

    def register_nessus_via_cli(self, nessus_api: NessusAPI, nessus_type: str):
        """"""
        self.set_and_validate_settings_via_cli(setting_name='custom_host',
                                               setting_value=CommonConfig.CAT_PLUGIN_FEED_HOST)

        start_stop_nessus_wait_for_ready(nessus_api=nessus_api, status=API.Status.REGISTER)

        self.add_user_and_register_nessus(expiration_day=Nessus.DEFAULT_EXPIRATION_DAYS, nessus_type=nessus_type)

    @pytest.mark.parametrize("test_details", [
        pytest.param({'product_type': 'home', 'license_type': 'Set up a purchased instance of Nessus'},
                     marks=pytest.mark.nessus_home),
        pytest.param({'product_type': 'manager', 'license_type': 'Set up a purchased instance of Nessus'},
                     marks=pytest.mark.nessus_manager),
        pytest.param({'product_type': 'expert', 'license_type': 'Set up a purchased instance of Nessus'},
                     marks=pytest.mark.nessus_expert)])
    def test_register_nessus_licenses(self, test_details):
        """
        NES-9317 NES-9131 Single-site Essentials Activation

        Scenarios tested:
        [x] Verify the nessus essentials license can be registered from UI.
        [ ] Verify the nessus manager license can be registered from UI.
        [x] Verify the nessus professional license can be registered from UI.
        [x] Verify the nessus expert license can be registered from UI.

        Steps:
        1. Go to registration page and click on "Nessus essentials"
        2. Fill the required steps and activation code related to particular license type
        3. Click on Continue and wait for plugins file to download
        4. Repeat the steps #1-#3 for manager and professional license.
        """
        nessus_api = NessusAPI()
        settings_details = {'auto_update': STRING_NO, 'custom_host': Nessus.Scan.Target.PRODUCTION_FEED_SERVER_HOST}

        for setting_name, setting_value in settings_details.items():
            log.info("Setting {} value to {}".format(setting_name, setting_value))
            self.set_and_validate_settings_via_cli(setting_name=setting_name, setting_value=setting_value)

        try:
            log.info("Stop and Start Nessus and wait to be in 'Register' status")
            start_stop_nessus_wait_for_ready(nessus_api=nessus_api, status=API.Status.REGISTER)

            registration = RegistrationPage()
            wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
                 waiting_for="page header to appear")

            registration.continue_button.click()
            log.info("Select {} type and click on 'Continue' button".format(test_details['license_type']))
            registration.get_by_license_type(license_type=test_details['license_type']).click()
            registration.continue_btn.click()

            NessusEssentialsLicensePage().skip_btn.click()
            log.debug("Skipped email-verification")

            code = self.generate_activation_code(product_type=test_details['product_type'],
                                                 expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)
            ManagerAndProfessionalLicensePage().activation_input.value = code
            registration.continue_activation.click()
            wait(lambda: registration.is_element_present("continue_button"), timeout=TIME_TEN_SECONDS,
                 waiting_for="next page header to appear")
            registration.continue_button.click()

            UserAccountPage().fill_user_activation_form()

            wait_for_scanner_to_be_ready(api=nessus_api)
            get_driver_no_init().refresh()

            login_page = LoginPage()

            if login_page.is_element_present('username_field', timeout=TIME_TEN_SECONDS):
                login_page.login_with_defaults()
                wait(lambda: (not login_page.find_elements(By.CSS_SELECTOR, 'body.nosession-wrapper')),
                     timeout_seconds=2 * WAIT_LONG, sleep_seconds=0.5, waiting_for='Dashboard/Scans page to appear')

            action_close_modal = ActionCloseModal()

            if action_close_modal.is_element_present('modal', timeout=TIME_SIXTY_SECONDS) and \
                    action_close_modal.is_element_present('close_button', timeout=TIME_SIXTY_SECONDS):
                action_close_modal.close_button.click()

            # Verifies if user login successfully or not
            assert UserMenu().is_element_present("user_menu_dropdown"), "User menu dropdown is not visible"
        finally:
            if nessus_api.server.status()['status'] == API.Status.REGISTER:
                log.debug("Register Nessus if it's not registered")
                self.register_nessus_via_cli(nessus_api=nessus_api, nessus_type=test_details['product_type'])

                wait_for_scanner_to_be_ready(api=nessus_api)

    @pytest.mark.parametrize("test_details", [
        pytest.param({'product_type': 'home', 'license_type': 'Set up a purchased instance of Nessus'},
                     marks=pytest.mark.nessus_home),
        pytest.param({'product_type': 'professional', 'license_type': 'Set up a purchased instance of Nessus'},
                     marks=[pytest.mark.nessus_pro, pytest.mark.xfail]),
        pytest.param({'product_type': 'manager', 'license_type': 'Set up a purchased instance of Nessus'},
                     marks=pytest.mark.nessus_manager)])
    @pytest.mark.parametrize('niap_mode_value', ['enforcing'])
    @pytest.mark.parametrize('strict_certificate_validation_value', ['no', 'yes'])
    def test_register_using_niap_mode_and_strict_certificate_validation(self, test_details, niap_mode_value,
                                                                        strict_certificate_validation_value):
        """
        SCE-2177 : Verify Nessus can link to plugin feed server with combinations of niap_mode and
                   strict_certificate_validation

        Scenarios tested:
        [x] Verify the nessus essentials license can be registered from UI with combinations of settings i.e.
            strict_certificate_validation and niap_mode.
        [ ] Verify the nessus manager license can be registered from UI with combinations of settings i.e.
            strict_certificate_validation and niap_mode.
        [x] Verify the nessus professional license can be registered from UI with combinations of settings i.e.
            strict_certificate_validation and niap_mode.

        Steps:
        1. Enable/disable combinations of settings i.e. strict_certificate_validation, niap_mode
        2. Change auto_update to no, as to prevent downgrading for safe side.
        3. Verify the settings are successfully changed.
        4. Go to registration page and click on "Nessus essentials"
        5. Fill the required steps and activation code related to particular license type, add plugin-feed url to
           IP of feed server.
        6. If both the settings are disabled then skip to step-8.
        7. If any of the settings is enabled then verify registration fails.
        8. Change plugin-feed url to domain name of feed server and register nessus again.
        9. Click on Continue and wait for plugins file to download.
        10. if product is Manager then skip to step-12.
        11. Verify Welcome modal contains product name and then close it.
        12. Verify the admin button appears in top-right corner.
        13. Repeat the steps #1-#8 for manager and professional license.
        """
        nessus_api = NessusAPI()

        if niap_mode_value == "non-enforcing" and strict_certificate_validation_value == "no":
            settings_details = {'auto_update': STRING_NO, 'niap_mode': niap_mode_value,
                                'custom_host': Nessus.Scan.Target.PRODUCTION_FEED_SERVER_HOST,
                                'strict_certificate_validation': strict_certificate_validation_value}
        else:
            settings_details = {'auto_update': STRING_NO, 'niap_mode': niap_mode_value,
                                'custom_host': Nessus.Scan.Target.OLD_PRODUCTION_FEED_SERVER_HOST,
                                'strict_certificate_validation': strict_certificate_validation_value}

        for setting_name, setting_value in settings_details.items():
            log.info("Setting {} value to {}".format(setting_name, setting_value))
            self.set_and_validate_settings_via_cli(setting_name=setting_name, setting_value=setting_value)

        try:
            log.info("Stop and Start Nessus and wait to be in 'Register' status")
            start_stop_nessus_wait_for_ready(nessus_api=nessus_api, status=API.Status.REGISTER)

            log.debug("Waiting for 'Registration' page")
            registration = RegistrationPage()
            wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
                 waiting_for="page header to appear")

            registration.continue_button.click()
            log.info("Select {} type and click on 'Continue' button".format(test_details['license_type']))
            registration.get_by_license_type(license_type=test_details['license_type']).click()
            registration.continue_btn.click()

            NessusEssentialsLicensePage().skip_btn.click()
            log.debug("Skipped email-verification")

            log.debug("Enter 'Activation code' for {} and click on 'Continue' button".format(
                test_details['product_type']))
            code = self.generate_activation_code(product_type=test_details['product_type'],
                                                 expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)
            ManagerAndProfessionalLicensePage().activation_input.value = code
            registration.continue_activation.click()
            wait(lambda: registration.is_element_present("continue_button"), timeout=TIME_TEN_SECONDS,
                 waiting_for="next page header to appear")
            registration.continue_button.click()

            UserAccountPage().fill_user_activation_form()

            if niap_mode_value == 'enforcing' or strict_certificate_validation_value == 'yes':
                # Verifies activation failed error message when 'niap_mode': 'enforcing' or
                # 'strict_certificate_validation': 'yes'
                assert Notifications().errors[-1] == "Error: Activation failed", \
                    "Error notification for registration failed is mismatched or missing."

                self.add_user_and_register_nessus(expiration_day=Nessus.DEFAULT_EXPIRATION_DAYS,
                                                  nessus_type=test_details['product_type'])

            log.debug("Waiting for Nessus to be ready")
            wait_for_scanner_status(api=nessus_api, timeout=TIME_THIRTY_MINUTES, status=API.Status.READY,
                                    msg='Waiting for server to be in ready state.',
                                    sleep_interval=TIME_THIRTY_SECONDS)

            get_driver_no_init().refresh()
            wait_for_scanner_to_be_ready(api=nessus_api)

            log.debug("Login with default credentials if login page appears")
            login_page = LoginPage()

            if login_page.is_element_present('username_field', timeout=TIME_TEN_SECONDS):
                login_page.login_with_defaults()
                wait(lambda: (not login_page.find_elements(By.CSS_SELECTOR, 'body.nosession-wrapper')),
                     timeout_seconds=2 * WAIT_LONG, sleep_seconds=0.5, waiting_for='Dashboard/Scans page to appear')

            log.debug("Dismiss welcome banner if present")
            action_close_modal = ActionCloseModal()

            if action_close_modal.is_element_present('modal', timeout=TIME_SIXTY_SECONDS) and \
                    action_close_modal.is_element_present('close_button', timeout=TIME_SIXTY_SECONDS):
                action_close_modal.close_button.click()
                action_close_modal.wait_for_modal_closed()
                log.debug("Closed the welcome modal")

            # Verifies if user login successfully or not
            assert UserMenu().is_element_present("user_menu_dropdown"), "User menu dropdown is not visible"
        finally:
            server_status = nessus_api.server.status()['status']

            if server_status == API.Status.REGISTER:
                log.info("Register Nessus if it's not registered")
                self.add_user_and_register_nessus(expiration_day=Nessus.DEFAULT_EXPIRATION_DAYS,
                                                  nessus_type=test_details['product_type'])

                log.debug("Waiting for Nessus to be ready")
                wait_for_scanner_status(api=nessus_api, timeout=TIME_THIRTY_MINUTES, status=API.Status.READY,
                                        msg='Waiting for server to be in ready state.',
                                        sleep_interval=TIME_THIRTY_SECONDS)

            log.info("Revert all settings which set at starting of the test")
            settings_details = {'auto_update': STRING_NO, 'niap_mode': 'non-enforcing',
                                'custom_host': Nessus.Scan.Target.STAGING_FEED_SERVER_HOST,
                                'strict_certificate_validation': STRING_NO}

            for setting_name, setting_value in settings_details.items():
                log.debug("Setting {} value to {}".format(setting_name, setting_value))
                self.set_and_validate_settings_via_cli(setting_name=setting_name, setting_value=setting_value)

            log.debug("Stop and Start Nessus and wait to be in 'Ready' status")
            start_stop_nessus_wait_for_ready(nessus_api=nessus_api, status=API.Status.READY)

    @pytest.mark.xfail
    @pytest.mark.parametrize("test_details", [
        pytest.param({'product_type': 'home', 'license_type': 'Set up a purchased instance of Nessus'},
                     marks=pytest.mark.nessus_home),
        pytest.param({'product_type': 'professional', 'license_type': 'Set up a purchased instance of Nessus'},
                     marks=[pytest.mark.nessus_pro, pytest.mark.xfail]),
        pytest.param({'product_type': 'manager', 'license_type': 'Set up a purchased instance of Nessus'},
                     marks=pytest.mark.nessus_manager)])
    @pytest.mark.parametrize('niap_mode_value', ['non-enforcing'])
    @pytest.mark.parametrize('strict_certificate_validation_value', ['no', 'yes'])
    def test_register_using_non_niap_mode_and_strict_certificate_validation(self, test_details, niap_mode_value,
                                                                            strict_certificate_validation_value):
        """
        SCE-2177 : Verify Nessus can link to plugin feed server with combinations of niap_mode and
                   strict_certificate_validation

        Scenarios tested:
        [x] Verify the nessus essentials license can be registered from UI with combinations of settings i.e.
            strict_certificate_validation and niap_mode.
        [ ] Verify the nessus manager license can be registered from UI with combinations of settings i.e.
            strict_certificate_validation and niap_mode.
        [x] Verify the nessus professional license can be registered from UI with combinations of settings i.e.
            strict_certificate_validation and niap_mode.

        Steps:
        1. Enable/disable combinations of settings i.e. strict_certificate_validation, niap_mode
        2. Change auto_update to no, as to prevent downgrading for safe side.
        3. Verify the settings are successfully changed.
        4. Go to registration page and click on "Nessus essentials"
        5. Fill the required steps and activation code related to particular license type, add plugin-feed url to
           IP of feed server.
        6. If both the settings are disabled then skip to step-8.
        7. If any of the settings is enabled then verify registration fails.
        8. Change plugin-feed url to domain name of feed server and register nessus again.
        9. Click on Continue and wait for plugins file to download.
        10. if product is Manager then skip to step-12.
        11. Verify Welcome modal contains product name and then close it.
        12. Verify the admin button appears in top-right corner.
        13. Repeat the steps #1-#8 for manager and professional license.
        """
        nessus_api = NessusAPI()

        if niap_mode_value == "non-enforcing" and strict_certificate_validation_value == "no":
            settings_details = {'auto_update': STRING_NO, 'niap_mode': niap_mode_value,
                                'custom_host': Nessus.Scan.Target.PRODUCTION_FEED_SERVER_HOST,
                                'strict_certificate_validation': strict_certificate_validation_value}
        else:
            settings_details = {'auto_update': STRING_NO, 'niap_mode': niap_mode_value,
                                'custom_host': Nessus.Scan.Target.OLD_PRODUCTION_FEED_SERVER_HOST,
                                'strict_certificate_validation': strict_certificate_validation_value}

        for setting_name, setting_value in settings_details.items():
            log.info("Setting {} value to {}".format(setting_name, setting_value))
            self.set_and_validate_settings_via_cli(setting_name=setting_name, setting_value=setting_value)

        try:
            log.info("Stop and Start Nessus and wait to be in 'Register' status")
            start_stop_nessus_wait_for_ready(nessus_api=nessus_api, status=API.Status.REGISTER)

            log.debug("Waiting for 'Registration' page")
            registration = RegistrationPage()
            wait(lambda: registration.is_element_present("page_header"), timeout=TIME_FIVE_MINUTES,
                 waiting_for="page header to appear")

            registration.continue_button.click()
            log.info("Select {} type and click on 'Continue' button".format(test_details['license_type']))
            registration.get_by_license_type(license_type=test_details['license_type']).click()
            registration.continue_btn.click()

            NessusEssentialsLicensePage().skip_btn.click()
            log.debug("Skipped email-verification")

            log.debug("Enter 'Activation code' for {} and click on 'Continue' button".format(
                test_details['product_type']))
            code = self.generate_activation_code(product_type=test_details['product_type'],
                                                 expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)
            ManagerAndProfessionalLicensePage().activation_input.value = code
            registration.continue_activation.click()
            wait(lambda: registration.is_element_present("continue_button"), timeout=TIME_TEN_SECONDS,
                 waiting_for="next page header to appear")
            registration.continue_button.click()

            UserAccountPage().fill_user_activation_form()

            if niap_mode_value == 'enforcing' or strict_certificate_validation_value == 'yes':
                # Verifies activation failed error message when 'niap_mode': 'enforcing' or
                # 'strict_certificate_validation': 'yes'
                assert Notifications().errors[-1] == "Error: Activation failed", \
                    "Error notification for registration failed is mismatched or missing."

                self.add_user_and_register_nessus(expiration_day=Nessus.DEFAULT_EXPIRATION_DAYS,
                                                  nessus_type=test_details['product_type'])

            log.debug("Waiting for Nessus to be ready")
            wait_for_scanner_status(api=nessus_api, timeout=TIME_THIRTY_MINUTES, status=API.Status.READY,
                                    msg='Waiting for server to be in ready state.',
                                    sleep_interval=TIME_THIRTY_SECONDS)

            get_driver_no_init().refresh()
            wait_for_scanner_to_be_ready(api=nessus_api)

            log.debug("Login with default credentials if login page appears")
            login_page = LoginPage()

            if login_page.is_element_present('username_field', timeout=TIME_TEN_SECONDS):
                login_page.login_with_defaults()
                wait(lambda: (not login_page.find_elements(By.CSS_SELECTOR, 'body.nosession-wrapper')),
                     timeout_seconds=2 * WAIT_LONG, sleep_seconds=0.5, waiting_for='Dashboard/Scans page to appear')

            log.debug("Dismiss welcome banner if present")
            action_close_modal = ActionCloseModal()

            if action_close_modal.is_element_present('modal', timeout=TIME_SIXTY_SECONDS) and \
                    action_close_modal.is_element_present('close_button', timeout=TIME_SIXTY_SECONDS):
                action_close_modal.close_button.click()
                action_close_modal.wait_for_modal_closed()
                log.debug("Closed the welcome modal")

            # Verifies if user login successfully or not
            assert UserMenu().is_element_present("user_menu_dropdown"), "User menu dropdown is not visible"
        finally:
            server_status = nessus_api.server.status()['status']

            if server_status == API.Status.REGISTER:
                log.info("Register Nessus if it's not registered")
                self.add_user_and_register_nessus(expiration_day=Nessus.DEFAULT_EXPIRATION_DAYS,
                                                  nessus_type=test_details['product_type'])

                log.debug("Waiting for Nessus to be ready")
                wait_for_scanner_status(api=nessus_api, timeout=TIME_THIRTY_MINUTES, status=API.Status.READY,
                                        msg='Waiting for server to be in ready state.',
                                        sleep_interval=TIME_THIRTY_SECONDS)

            log.info("Revert all settings which set at starting of the test")
            settings_details = {'auto_update': STRING_NO, 'niap_mode': 'non-enforcing',
                                'custom_host': Nessus.Scan.Target.STAGING_FEED_SERVER_HOST,
                                'strict_certificate_validation': STRING_NO}

            for setting_name, setting_value in settings_details.items():
                log.debug("Setting {} value to {}".format(setting_name, setting_value))
                self.set_and_validate_settings_via_cli(setting_name=setting_name, setting_value=setting_value)

            log.debug("Stop and Start Nessus and wait to be in 'Ready' status")
            start_stop_nessus_wait_for_ready(nessus_api=nessus_api, status=API.Status.READY)
