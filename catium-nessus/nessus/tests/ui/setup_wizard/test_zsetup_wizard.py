"""
Nessus setup wizard verification and validation

Test cases to verify setup wizard elements and setup links to nessus manager,
securityCenter and offline

:copyright: Tenable Network Security, 2017
:date: September 13, 2017
:last_modified: April 18, 2023
:author: @mameta, @krpatel
"""
import time

import pytest
from requests import HTTPError

from catium.helpers.sleep_lib import sleep
from catium.lib.activation_code_generator import ActivationCodeGenerator
from catium.lib.config import CommonConfig
from catium.lib.const.base_constants import WAIT_NORMAL, WAIT_LONG, TIME_FIVE_SECONDS, TIME_THIRTY_SECONDS, \
    HOST_PLUGIN_FEED_STAGING
from catium.lib.const.base_constants import WAIT_SHORT, STRING_NO
from catium.lib.const.deployment import DOCKER_IMAGES
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from catium.lib.webium.driver import get_driver, get_driver_no_init
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.license import remove_nessus_registration
from nessus.helpers.nessuscli import fix
from nessus.helpers.nessuscli import users
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.helpers.scan import start_stop_nessus_wait_for_ready
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.lib.const.constants import Nessus, API
from nessus.lib.const.setup_wizard_constants import SetupWizardConst
from nessus.lib.message.messages import Messages
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scanners.linked_scanners import ScannerPage
from nessus.pageobjects.setup.setup_page import SetupPage, AccountSetupPage, SetupCommonPoints, \
    ProductRegistrationPage, AdvancedSettingsModal, LoginSetupPage
from nessus.pageobjects.shared.loading import LoadingCircle
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI


@pytest.mark.nessus_settings_2
@pytest.mark.standalone
@pytest.mark.usefixtures('wizard_open')
class TestSetupWizard(object):
    """
    Test cases to cover
    Nessus Setup Wizard
    1. Verify Account Setup Page -      NQA-906 - Verify Account Setup Page: DONE
    2. Verify Registration Page -       NQA-907 - Verify Registration Page: DONE
    3. Verify Advance Setting option -  NQA-912 Verify All the options under Advanced Setting: DONE
    4. Verify Link to Security Center - NQA-910 Verify all the the option while linking to Security Center: DONE
    5. Verify Setup Wizard: Offline -   NQA-911 verify setup wizard with offline rtegistration: DONE
    6. Verify Link to Nessus Manager -  NQA-909 verify linking to nessus manager: DONE
    7. Verify Link to tenable.io   -    NQA-908 verify linking to tenable.io : DONE
    8. Setup Wizard - Setup Complete -  NQA-913 verify setup complete   : DONE

    """

    setup = SetupCommonPoints()
    setup_page = SetupPage()
    account_page = AccountSetupPage()
    login_page = LoginSetupPage()

    @pytest.mark.usefixtures("kube_deploy_nessus_manager", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config",
                             [{"link": STRING_NO, "freshInstall": True,
                               "image": DOCKER_IMAGES['nessus']['es7']['release']}])
    def test_account_setup(self, kube_deploy_nessus_config):
        """Verify Account Setup Page: NQA-906"""

        assert TestSetupWizard.setup.setup_element_present(TestSetupWizard.setup.nessus_icon), \
            "Nessus logo is not displayed"

        assert TestSetupWizard.setup.setup_element_present(TestSetupWizard.setup.body_area_text), \
            "Body text not displayed"

        assert TestSetupWizard.setup.copyright_text == SetupWizardConst.COPYRIGHT_INFO_MESSAGE, \
            "copyright information is not available in the footer."

        account_setup_page = AccountSetupPage()

        LoadingCircle(WAIT_NORMAL)
        assert TestSetupWizard.setup.setup_element_present(account_setup_page.username_field), \
            "Username input box is not usable."

        account_setup_page.username_field.value = SetupWizardConst.NESSUS_SESSION_USERNAME

        username_text = account_setup_page.username_field.get_attribute('value')
        assert username_text == "admin", " Username input box is not usable."

        assert TestSetupWizard.setup.setup_element_present(account_setup_page.password_field), \
            "Password input box is not usable."

        account_setup_page.password_field.value = SetupWizardConst.NESSUS_SESSION_PASSWORD

        password_text = account_setup_page.password_field.get_attribute('value')
        assert password_text == "admin", " Password input box is not usable."

        account_setup_page.show_password.click()
        LoadingCircle(WAIT_SHORT)
        assert TestSetupWizard.setup.setup_element_present(account_setup_page.password_field), \
            " Password input box is not usable."

        account_setup_page.continue_button.click()

        LoadingCircle(WAIT_SHORT)
        registration_title = TestSetupWizard.setup.welcome_text
        assert registration_title == SetupWizardConst.REGISTRATION_PAGE_TITLE, \
            "Registration Page is not present"

        LoadingCircle(WAIT_SHORT)

        account_setup_page.back_button.click()
        registration_title = TestSetupWizard.setup.welcome_text
        assert registration_title == SetupWizardConst.ACCOUNT_SETUP_PAGE_TITLE, \
            "Account setup Page is not present"

    @pytest.mark.usefixtures("kube_deploy_nessus_manager", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config",
                             [{"link": STRING_NO, "freshInstall": True,
                               "image": DOCKER_IMAGES['nessus']['es7']['release']}])
    def test_registration_page_setup(self, kube_deploy_nessus_config):
        """Verify Registration Page: NQA-907"""

        registration_page = ProductRegistrationPage()
        LoadingCircle(WAIT_SHORT)

        TestSetupWizard.account_page.setup_account(SetupWizardConst.NESSUS_SESSION_USERNAME,
                                                   SetupWizardConst.NESSUS_SESSION_PASSWORD)

        assert TestSetupWizard.setup.setup_element_present(TestSetupWizard.setup.nessus_icon), \
            "Nessus logo is not displayed"

        assert TestSetupWizard.setup.setup_element_present(TestSetupWizard.setup.body_area_text), \
            "Body text not displayed"

        assert TestSetupWizard.setup.copyright_text == SetupWizardConst.COPYRIGHT_INFO_MESSAGE, \
            "copyright information is not available in the footer."

        LoadingCircle(WAIT_SHORT)
        assert TestSetupWizard.setup.setup_element_present(registration_page.registration_select), \
            "Registration drop down box is not visible"

        assert TestSetupWizard.setup.setup_element_present(registration_page.activation_code_field), \
            "activation code text filed is not available"
        LoadingCircle(WAIT_SHORT)

        assert TestSetupWizard.setup.setup_element_present(registration_page.advanced_settings_button), \
            "advanced setting button is not visible"

        registration_page.continue_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "error notification is not displaying"

        registration_page.advanced_settings_button.click()

        advanced_option = AdvancedSettingsModal()

        assert TestSetupWizard.setup.setup_element_present(advanced_option.modal), "host text field is not displayed"

        advanced_option.cancel_button.click()

        registration_page.back_button.click()

        assert get_driver().title, "page did not navigate to account setup page"

    @pytest.mark.usefixtures("kube_deploy_nessus_manager", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config",
                             [{"link": STRING_NO, "freshInstall": True,
                               "image": DOCKER_IMAGES['nessus']['es7']['release']}])
    def test_advanced_settings(self, kube_deploy_nessus_config):
        """Verify Advance Stting Option: NQA-912"""

        TestSetupWizard.account_page.setup_account(SetupWizardConst.NESSUS_SESSION_USERNAME,
                                                   SetupWizardConst.NESSUS_SESSION_PASSWORD)

        advance_setting_button = ProductRegistrationPage()
        advance_setting_button.advanced_settings_button.click()

        advanced_option = AdvancedSettingsModal()

        assert TestSetupWizard.setup.setup_element_present(advanced_option.host_field), \
            "manager host field is not displayed"

        assert TestSetupWizard.setup.setup_element_present(advanced_option.port_field), \
            "manager port field is not displayed"

        assert TestSetupWizard.setup.setup_element_present(advanced_option.username_field), \
            " Username input box is not usable."

        assert TestSetupWizard.setup.setup_element_present(advanced_option.password_field), \
            " Password input box is not usable. "

        assert TestSetupWizard.setup.setup_element_present(advanced_option.auth_method_dropdown), \
            "auth method dropdown is not available"

        assert TestSetupWizard.setup.setup_element_present(advanced_option.user_agent_field), \
            "user agent text field is not present"

        advanced_option.plugin_feed.click()
        assert TestSetupWizard.setup.setup_element_present(advanced_option.custom_host_field), \
            "custom host field is not present"

        advanced_option.master_feed.click()
        assert TestSetupWizard.setup.setup_element_present(advanced_option.master_field_password), \
            "master plugin password field is not present"

        save_button_value = advanced_option.save_button.is_enabled()
        assert save_button_value, "save button is disabled"

        cancel_button_value = advanced_option.cancel_button.is_enabled()
        assert cancel_button_value, "cancel button is disabled"

        advanced_option.cancel_button.click()
        assert get_driver().title, "page did not navigate to registration setup page"

    @pytest.mark.usefixtures("kube_deploy_nessus_manager", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config",
                             [{"link": STRING_NO, "freshInstall": True,
                               "image": DOCKER_IMAGES['nessus']['es7']['release']}])
    def test_link_to_security_center(self, kube_deploy_nessus_config):
        """Verify Link to Security Center: NQA-910"""

        TestSetupWizard.account_page.setup_account(SetupWizardConst.NESSUS_SESSION_USERNAME,
                                                   SetupWizardConst.NESSUS_SESSION_PASSWORD)

        registration_page = ProductRegistrationPage()
        registration_page.registration_select.select_by_visible_text(SetupWizardConst.
                                                                     REGISTRATION_DROPDOWN_SECURITY_CENTER_VALUE)

        assert TestSetupWizard.setup.setup_element_present(registration_page.advanced_settings_button), \
            "advanced setting button is not visible"

        registration_page.advanced_settings_button.click()

        advanced_option = AdvancedSettingsModal()

        assert TestSetupWizard.setup.setup_element_present(advanced_option.modal), \
            "advanced settings modal is not displayed"

        advanced_option.cancel_button.click()

        registration_page.back_button.click()
        page_title = get_driver().title
        assert page_title, "page did not navigate to account setup page"

        registration_page.continue_button.click()
        LoadingCircle(WAIT_SHORT)

        registration_page.continue_button.click()
        sc_setup_complete = registration_page.dynamic_element("Setup Complete").text
        LoadingCircle(WAIT_SHORT)

        assert sc_setup_complete, "link to SecurityCenter is not done"

    @pytest.mark.usefixtures("kube_deploy_nessus_manager", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config",
                             [{"link": STRING_NO, "freshInstall": True,
                               "image": DOCKER_IMAGES['nessus']['es7']['release']}])
    def test_offline_setup_wizard(self, kube_deploy_nessus_config):
        """Verify Setup Wizard: Offline - NQA-911"""
        TestSetupWizard.account_page.setup_account(SetupWizardConst.NESSUS_SESSION_USERNAME,
                                                   SetupWizardConst.NESSUS_SESSION_PASSWORD)

        registration_page = ProductRegistrationPage()
        registration_page.registration_select.select_by_visible_text(SetupWizardConst.
                                                                     REGISTRATION_DROPDOWN_OFFLINE_VALUE)
        window_ids = [WindowsHandler().handles[0]]
        try:
            registration_page.click_here_button.click()
            click_here_page_id = WindowsHandler().handles[1]
            window_ids.append(click_here_page_id)
            WindowsHandler().switch_to_window(click_here_page_id)
            LoadingCircle(WAIT_SHORT)
            link_page_title = get_driver().title
            current_page_url = get_driver().current_url

            assert link_page_title, "window switching failed"
            assert current_page_url == SetupWizardConst.CLICK_HERE_URL, "url not found"

        finally:
            LoadingCircle(WAIT_SHORT)
            get_driver().close()
            WindowsHandler().switch_to_window(window_ids[0])
            setup_page_title = get_driver().title
            assert setup_page_title, "window switching failed"

        LoadingCircle(WAIT_SHORT)
        assert TestSetupWizard.setup.setup_element_present(registration_page.advanced_settings_button), \
            "advanced setting button is not visible"

        registration_page.advanced_settings_button.click()

        advanced_option = AdvancedSettingsModal()
        assert TestSetupWizard.setup.setup_element_present(advanced_option.modal), \
            "advanced settings modal is not displayed"

        advanced_option.cancel_button.click()

        assert TestSetupWizard.setup.setup_element_present(registration_page.nessus_license_textbox), \
            "license textbox is not visible"

        registration_page.continue_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "error notification is not displaying"

        registration_page.back_button.click()
        page_title = get_driver().title
        assert page_title, "page did not navigate to account setup page"

        registration_page.continue_button.click()
        page_title = get_driver().title
        assert page_title, "page did not navigate to registration setup page"

        challenge_code_id = registration_page.challenge_code.text

        activation_code = ActivationCodeGenerator()
        activate_code = activation_code.generate_nessus_manager_code()

        WindowsHandler().create_window()
        new_win = WindowsHandler().handles[1]
        window_ids.append(new_win)
        LoadingCircle(WAIT_SHORT)
        WindowsHandler().switch_to_window(new_win)

        get_driver().get(Nessus.ENDPOINT_FOR_OFFLINE_LINKING)

        registration_page.challenge_code_textbox.send_keys(challenge_code_id)
        registration_page.activation_code_textbox.send_keys(activate_code)

        registration_page.submit.click()
        LoadingCircle(WAIT_SHORT)
        license_text_value = registration_page.dynamic_element("BEGIN TENABLE").text

        get_driver().close()

        WindowsHandler().switch_to_window(window_ids[0])
        registration_page.nessus_license_textbox.send_keys(license_text_value)
        registration_page.continue_button.click()
        LoadingCircle(WAIT_NORMAL)

        offline_setup_complete = registration_page.initializing_setup.text
        assert offline_setup_complete, "offline setup is not done"

    @pytest.mark.usefixtures("kube_deploy_nessus_manager", "kube_standalone_deploy")
    @pytest.mark.parametrize("kube_deploy_nessus_config",
                             [{"link": STRING_NO, "freshInstall": True,
                               "image": DOCKER_IMAGES['nessus']['es7']['release']}])
    @pytest.mark.parametrize('param',
                             [{'version': 'Nessus_Manager', 'url': SetupWizardConst.NESSUS_SESSION_URL, 'user_name':
                                 SetupWizardConst.NESSUS_SESSION_USERNAME,
                               'password': SetupWizardConst.NESSUS_SESSION_PASSWORD, 'host_ip':
                                   SetupWizardConst.NESSUS_MANAGER_HOST, 'port': SetupWizardConst.NESSUS_MANAGER_PORT},
                              {'version': 'Tenable_IO', 'url': SetupWizardConst.TENABLE_URL,
                               'user_name': SetupWizardConst.TENABLE_USERNAME, 'password':
                                   SetupWizardConst.TENABLE_PASSWORD,
                               'host_ip': SetupWizardConst.TENABLE_URL, 'port': SetupWizardConst.TENABLE_PORT}])
    def test_link_to_nessus_manager(self, param, kube_deploy_nessus_config):
        """Verify Link to Nessus Manager :
                linking with Nessus Manager and Tenable.io :  NQA-909, NQA-908
        """
        TestSetupWizard.account_page.setup_account(SetupWizardConst.NESSUS_SESSION_USERNAME,
                                                   SetupWizardConst.NESSUS_SESSION_PASSWORD)

        registration_page = ProductRegistrationPage()
        registration_page.registration_select.select_by_visible_text(SetupWizardConst.
                                                                     REGISTRATION_DROPDOWN_NESSUS_VALUE)

        assert TestSetupWizard.setup.setup_element_present(registration_page.manager_host_field), \
            "manager host field is not displayed"

        assert TestSetupWizard.setup.setup_element_present(registration_page.manager_port_field), \
            "manager port field is not displayed"

        assert TestSetupWizard.setup.setup_element_present(registration_page.linking_key), \
            "linking key text field is not present"

        LoadingCircle(WAIT_SHORT)
        registration_page.use_proxy_checkbox.click()
        checkbox_value = registration_page.use_proxy_checkbox.get_attribute('class')
        assert checkbox_value == SetupWizardConst.CHECKED_CHECKBOX_VALUE, \
            "checkbox is not checked"

        registration_page.move_to_element(registration_page.help_tool_tip)
        tool_tip_text = registration_page.help_tool_tip.get_attribute('original-title')
        assert tool_tip_text == SetupWizardConst.TOOL_TIP_TEXT, \
            "tool tip text is not present"

        assert TestSetupWizard.setup.setup_element_present(registration_page.advanced_settings_button), \
            "advanced setting button is not visible"

        registration_page.advanced_settings_button.click()

        advanced_option = AdvancedSettingsModal()
        assert TestSetupWizard.setup.setup_element_present(advanced_option.modal), \
            "advanced settings modal is not displayed"

        advanced_option.cancel_button.click()

        registration_page.continue_button.click()
        LoadingCircle(WAIT_SHORT)

        assert Notifications().errors[-1] == Messages.NotificationMessages.continue_button_code, \
            "error notification is not displaying"

        registration_page.back_button.click()
        page_title = get_driver().title
        assert page_title, "page did not navigate to account setup page"
        LoadingCircle(WAIT_SHORT)
        registration_page.continue_button.click()

        if param['version'] == 'Nessus_Manager':
            ness = NessusAPI()
        else:
            ness = TenableCloudAPI()
            pytest.xfail(reason='As discussed in meeting, skipping this test as linking to tenableio is not required')

        ness.session_url = param['url']
        ness.login(username=param['user_name'], password=param['password'])

        LoadingCircle(WAIT_SHORT)
        link_key_fetch = ness.scanners.get_linking_key()
        LoadingCircle(WAIT_SHORT)
        registration_page.manager_host_field.send_keys(param['host_ip'])
        registration_page.manager_port_field.clear()
        registration_page.manager_port_field.send_keys(param['port'])
        registration_page.linking_key.send_keys(link_key_fetch['key'])

        registration_page.continue_button.click()

        setup_complete = registration_page.dynamic_element("Setup Complete").text
        LoadingCircle(WAIT_SHORT)

        assert setup_complete, "setup not completed"


log = create_logger()


@pytest.mark.nessus_settings_2
@pytest.mark.usefixtures("reset_license")
@pytest.mark.nessus_manager
class TestSetupScanner(object):

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

    @pytest.mark.xray(test_key='NES-13733')
    @pytest.mark.parametrize('param',
                             [{'version': 'Nessus_Manager', 'url': SetupWizardConst.NM_HOST, 'user_name':
                                 SetupWizardConst.NESSUS_SESSION_USERNAME,
                               'password': SetupWizardConst.NESSUS_SESSION_PASSWORD, 'host_ip':
                                   SetupWizardConst.NM_HOST, 'name': SetupWizardConst.NAME,
                               'port': SetupWizardConst.NESSUS_MANAGER_PORT}])
    def test_zmanaged_scanner_linked_to_nessus_manager(self, param):
        """
          NES-13733: Verify scanner can be linked to NM from nessuscli.

          Scenarios Tested:
          [x] Verify that scanner is linked to NM and appear in list.
        """

        global ness1
        try:
            ness1 = NessusAPI()
            link_key_fetch = '93d9fefa8e31f4ad95a6ebfe588762ac7f462b8cb2d027959c0bf62021d6aea9'

            with SSH() as ssh:
                command = '{} managed link --key={} --host={} --port={} --name={}'.format(
                    get_nessus_cli(), link_key_fetch, SetupWizardConst.NM_HOST,
                    SetupWizardConst.NESSUS_MANAGER_PORT, SetupWizardConst.NAME)
                ssh.execute(command=command, sudo=True)

            sleep(WAIT_LONG, reason="It takes time to link with NM")

            if param['version'] == 'Nessus_Manager':
                ness = NessusAPI()
            else:
                ness = TenableCloudAPI()
                pytest.xfail(
                    reason='As discussed in meeting, skipping this test as linking to tenableio is not required')

            ness.session_url = param['url']
            ness.login(username=param['user_name'], password=param['password'])

            time.sleep(5)
            link_key_fetch1 = ness.scanners.get_scanner_linking_key()
            log.info("Linking key for scanner link to manager is {}".format(link_key_fetch1['key']))

            assert link_key_fetch == link_key_fetch1[
                'key'], "Linking key has been changed for Nessus manager please update it."

            list_scanners = ness.scanners.get_list()
            for scanner in list_scanners['scanners']:
                if scanner['name'] == SetupWizardConst.NAME:
                    assert scanner[
                               'name'] == SetupWizardConst.NAME, 'Scanner name not found in list of available linked scanner'

            try:
                for scanner in list_scanners['scanners']:
                    if scanner['name'] == SetupWizardConst.NAME:
                        ness.scanners.delete(scanner_id=scanner['id'])
            except HTTPError as exc:
                log.warning("Unable to delete scan in clean up. Scan "
                            "may have been deleted by test or may be running. Error: %s", exc)

            ness.logout()

        finally:
            if ness1.server.status()['status'] == API.Status.REGISTER:
                remove_nessus_registration()
                log.debug("Registering Nessus as it's not registered")
                self.register_nessus_via_cli(nessus_api=ness1, nessus_type='manager')
                wait_for_scanner_to_be_ready(api=ness1)

    @pytest.mark.xray(test_key='NES-15534')
    @pytest.mark.usefixtures("login")
    @pytest.mark.parametrize('param',
                             [{'version': 'Nessus_Manager', 'url': SetupWizardConst.NM_HOST, 'user_name':
                                 SetupWizardConst.NESSUS_SESSION_USERNAME,
                               'password': SetupWizardConst.NESSUS_SESSION_PASSWORD, 'host_ip':
                                   SetupWizardConst.NM_HOST, 'name': SetupWizardConst.NAME,
                               'port': SetupWizardConst.NESSUS_MANAGER_PORT}])
    def test_notification_when_requested_log_for_linked_scanner_to_nessus_manager(self, param):
        """
                NES-15534: Verify 'Log Requested' notification is displayed on clicking 'Request Logs' button

                Scenarios Tested:
                [x] Verify that notification is appears.
        """

        if param['version'] == 'Nessus_Manager':
            ness = NessusAPI()
        else:
            ness = TenableCloudAPI()
            pytest.xfail(
                reason='As discussed in meeting, skipping this test as linking to tenableio is not required')

        ness.session_url = param['url']
        driver = get_driver()
        driver.get(ness.session_url)
        sleep(sleep_time=TIME_FIVE_SECONDS, reason="waiting for page to load")
        get_driver_no_init().refresh()
        login_page = LoginPage()
        login_page.refresh()
        login_page.login_with_credentials(username='admin', password='admin', open_page=False)
        ness.login(username=param['user_name'], password=param['password'])

        list_scanners = ness.scanners.get_list()
        for scanner in list_scanners['scanners']:
            if scanner['name'] == 'qa-india-ubuntu6':
                assert scanner['name'] == 'qa-india-ubuntu6', 'Same name scanner not found.'

        header_page = HeaderBasePage()
        wait(lambda: header_page.is_element_present('sensors_tab'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Sensors tab to appear on Nessus main page headers.')
        header_page.sensors_tab.click()
        wait(lambda: header_page.is_element_present('linked_scanner'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Linked scanner option to appear on sensors tab.')
        header_page.linked_scanner.click()
        wait(lambda: header_page.is_element_present('linking_key_text'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Linking key text to be appear on linked scanner page.')

        ScannerPage().open_scanner_details(scanner_name='qa-india-ubuntu6')
        wait(lambda: header_page.is_element_present('logs_tab_of_scanner'), timeout_seconds=TIME_THIRTY_SECONDS,
             waiting_for='Linking key text to be appear on linked scanner page.')
        header_page.logs_tab_of_scanner.click()

        if wait(lambda: header_page.is_element_present('request_logs'), timeout_seconds=TIME_THIRTY_SECONDS,
                waiting_for='request logs to be appear on page.') is True:
            header_page.request_logs.click()
            assert Notifications().successes[-1] == Messages.NotificationMessages. \
                About.logs_requested, "Notifications not showing for requesting logs."
