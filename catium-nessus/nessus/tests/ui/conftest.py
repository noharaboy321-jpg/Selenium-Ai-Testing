"""
:Copyright: Tenable Network Security, 2019
:Creation Date: July 03, 2017
:last_modified: Sept 04, 2020
:author: @smadan, @jamreliya, @rdutta, @mameta, @ntarwani, @vsoni, @yshah, @kpanchal, @sacharya
"""

import os
import random
import time
from datetime import datetime, timedelta
from random import randint
from typing import TYPE_CHECKING

import pytest
from requests import HTTPError, RequestException
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.config import Config
from catium.lib.const import TIME_SIXTY_SECONDS, TIME_THREE_SECONDS, WAIT_NORMAL, HTTPStatus
from catium.lib.const import TIME_TEN_MINUTES, TIME_ONE_HOUR
from catium.lib.const import WAIT_SHORT
from catium.lib.const.base_constants import WAIT_LONG, TIME_THIRTY_SECONDS, TIME_FIVE_MINUTES, TIME_FIVE_SECONDS, \
    TIME_FIFTEEN_MINUTES, TIME_TWENTY_SECONDS, TIME_THIRTY_MINUTES, TIME_TWO_MINUTES
from catium.lib.errors import CatiumInvalidPasswordError, CatiumInvalidUsernameError, CatiumLoginError, \
    CatiumPageLoadError
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util import random_name
from catium.lib.util.util import load_testdata
from catium.lib.webium.driver import close_driver, get_driver, get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.license import remove_nessus_registration, start_nessus_and_wait_till_it_becomes_ready, \
    close_welcome_nessus_10_modal_for_pro
from nessus.helpers.metadata.agent import get_agent_id
from nessus.helpers.nessus_ui.settings import add_advanced_setting as add_advanced_setting_helper, \
    delete_advanced_setting as delete_advanced_setting_helper, login_helper_after_server_restart
from nessus.helpers.nessuscli import fix
from nessus.helpers.nessuscli.helper import get_os_name, delete_file_from_nessus_directory, \
    get_nessus_log_dir, stop_nessus, start_nessus
from nessus.helpers.nessuscli.logchecker import read_from_file
from nessus.helpers.nessuscli.update import activation_code_generator
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import create_packet_capture_scan_helper, create_scan_helper, \
    expected_generated_pcap_file_name, empty_trash_folder
from nessus.helpers.software_update import get_nessus_version_details, update_software_and_wait_for_nessus_to_be_ready
from nessus.helpers.system import get_nessus_type_using_api, is_home, is_pro, is_expert
from nessus.helpers.waiters import wait_for_scanner_status, wait_for_plugins
from nessus.lib.const.constants import API, Nessus, OperatingSystems
from nessus.models.scan import ScanModel
from nessus.pageobjects.about.about_page import MasterPassword, OverView
from nessus.pageobjects.about.about_page import SoftwareUpdate
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AddAdvancedSettingModal, \
    AdvancedSettingsList, NoticeAdvancedSettings
from nessus.pageobjects.agents.agent_blackout_windows_page import AgentBlackoutWindowsPage, AgentBlackoutWindowList, \
    AgentBlackoutWindowSettingsPage
from nessus.pageobjects.agents.agent_group_page import AgentGroupsList, CreateGroupWindowPage, AgentGroupsPage
from nessus.pageobjects.agents.agent_settings_page import AgentSettingsPage
from nessus.pageobjects.agents.agents_page import AgentsPage, AgentsList
from nessus.pageobjects.agents.create_agent_blackout_window_page import CreateBlackoutWindowPage
from nessus.pageobjects.cluster.cluster_group_page import ClusterGroupPage, ClusterGroupDetails, ClusterGroupList
from nessus.pageobjects.custom_ca.custom_ca_page import CustomCAPage
from nessus.pageobjects.debug_logs.debug_logs_page import DebugLogsList, DebugLogsPage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal, UnsavedChangesModal
from nessus.pageobjects.groups.groups_page import GroupsPage, NewGroupPage, GroupList
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import NotificationActions, disable_initial_scan_wizard_nessus_home, \
    close_welcome_banner_for_nessus_pro, close_pendo_guide_container_banner_for_nessus_pro, \
    close_pendo_guide_container_banner_for_nessus_expert, close_welcome_banner_for_nessus_expert
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage, Wizard
from nessus.pageobjects.plugin_rules.plugin_rules_page import PluginRulesPage, PluginRulesList
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm, PolicyType
from nessus.pageobjects.policies.policies_page import PoliciesPage, PolicyList
from nessus.pageobjects.scans.new_scan_form import ScanType, ScanTemplatePage, NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.server.ldapserver.ldap_server_page import LdapServerPage
from nessus.pageobjects.server.proxyserver.proxy_server_page import ProxyServer
from nessus.pageobjects.server.smtpserver.smtp_server_page import SmtpServerPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav
from nessus.pageobjects.users.users_page import NewUserForm, UsersPage, UserList

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def wizard_open(driver_instance):
    """ helper method to open wizard"""
    try:
        Wizard.do_wizard()
    except Exception as exc:
        log.exception('wizard opening fixture failed to complete. Error: %s', exc)
        raise
    else:
        yield
    finally:
        close_driver()


@pytest.fixture()
def login(request: 'SubRequest', driver_instance):  # pylint: disable=unused-argument
    """Automatically logs into Nessus with configured username and password before each test"""
    if request.node.get_closest_marker('disable_logout'):
        perform_logout = False
    else:
        perform_logout = True
    api = NessusAPI()
    try:
        plugin_status = api.server.status()['pluginSet']
        log.debug("Nessus plugin-set status is : {}".format(plugin_status))
    except (RequestException, KeyError):
        start_nessus()
        log.info("Got error while fetching plugin status.")
    try:
        # Skipping pluginSet property check for <10 Nessus as it was not available
        if is_pro():
            ver = get_nessus_version_details()['nessus_ui_version']
            nes_ver = ver.split(".")

            if int(nes_ver[0]) < 10:
                log.info("Skipping pluginSet check for 8x Nessus version")
                pass
            else:
                wait_for_plugins(api=api, timeout=TIME_THIRTY_MINUTES)
        else:
            wait_for_plugins(api=api, timeout=TIME_THIRTY_MINUTES)
    except TimeoutExpired:
        log.info("Nessus plugins are not loaded after waiting for Thirty minutes")
        try:
            log.info("Server plugin-set is : {}".format(api.server.status()['pluginSet']))
        except:
            pass
    try:
        start_nessus_and_wait_till_it_becomes_ready()
        login_page = LoginPage()
        login_page.refresh()
        login_page.do_login()

        if is_home():
            keep_wizard_enabled = request.param['keep_wizard_enabled'] if hasattr(
                request, 'param') and 'keep_wizard_enabled' in request.param else False

            if not keep_wizard_enabled:
                disable_initial_scan_wizard_nessus_home()

            NotificationActions().dismiss_offer_notifications_nessus_home()
        elif is_pro():
            close_pendo_guide_container_banner_for_nessus_pro()
            close_welcome_banner_for_nessus_pro()
        elif is_expert():
            close_pendo_guide_container_banner_for_nessus_expert()
            close_welcome_banner_for_nessus_expert()

    except (CatiumInvalidPasswordError, CatiumInvalidUsernameError, CatiumLoginError, CatiumPageLoadError,
            TimeoutExpired):
        log.exception('Login fixture failed to complete login.')
        raise
    else:
        yield
    finally:
        if perform_logout:
            LoadingCircle(0)
            NotificationActions().remove_all()
            user_menu = UserMenu()
            if user_menu.is_element_present('user_menu_dropdown'):
                try:
                    user_menu.logout()
                except (NoSuchElementException, StaleElementReferenceException):
                    log.warning("Error while performing logout")
            else:
                log.warning("Unable to logout from UI in fixture teardown")


@pytest.fixture()
def add_smtp_server_settings(request: 'SubRequest', driver_instance) -> dict:
    """
    Automatically add passed smtp server settings
         @pytest.mark.parametrize("add_smtp_server_settings", [{'host': API.Settings.Smtp.SMTP_HOST,
                                                                'port': API.Settings.Smtp.SMTP_HOST,
                                                                'sender_email': 'test@tenable.com',
                                                                'host_name': API.Settings.Smtp.SMTP_HOST_NAME}],
                                                                 indirect=True)
    The Above code will add smtp server settings.
    """
    smtp_server_page = SmtpServerPage()

    try:
        smtp_server_page.open()
        smtp_server_page.add_smtp_settings(**request.param)
        smtp_server_page.save_settings.click()
    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to save smtp server settings .')
        raise
    else:
        yield request.param
    finally:
        try:
            smtp_server_page.add_smtp_settings(host='', port='', sender_email='', host_name='')
            smtp_server_page.save_settings.click()
            sleep(WAIT_NORMAL, reason="It takes little bit time to get setting saved.")
        except (AttributeError, NoSuchElementException) as exc:
            log.warning("Unable to delete smtp server settings in clean up. Error: %s", exc)


@pytest.fixture()
def create_blackout_window(request: 'SubRequest', driver_instance):
    """
    Automatically create a blackout window with a random name and provided frequency
      @pytest.mark.parametrize("create_blackout_window", ["Once"],
                             indirect = True)
    The Above code will create a new blackout window with once as frequency
    """

    new_blackout_window_name = random_name(prefix="FreezeWindow-")
    try:
        agent_blackout_windows_page = AgentBlackoutWindowsPage()
        agent_blackout_windows_page.open()
        agent_blackout_windows_page.new_button.click()
        CreateBlackoutWindowPage().new_blackout_window(new_blackout_window_name, request.param.title())
        LoadingCircle(WAIT_NORMAL)

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create a new blackout window')
        raise
    else:
        yield new_blackout_window_name
    finally:
        try:
            agent_list_page = AgentBlackoutWindowList()
            if new_blackout_window_name in agent_list_page.blackout_window_all_names:
                agent_list_page.delete_blackout_windows(new_blackout_window_name)

        except (AttributeError, NoSuchElementException) as exc:
            log.warning("Unable to delete agent blackout window in clean up. window "
                        "may have been deleted by test or may be running. Error: %s", exc)


@pytest.fixture()
def create_blackout_window_list(request: 'SubRequest', driver_instance):
    """
    Automatically creates a list of blackout windows
        @pytest.mark.parametrize("create_blackout_window_list", [{'freq': (["Once",
                                                                           "Daily"
                                                                       ]),
                                                              'shouldwait': False}], indirect=True)
    The above code will create four blackout windows with two kind of frequencies
    """

    agent_blackout_windows_page = AgentBlackoutWindowsPage()
    agent_blackout_windows_page.open()

    blackout_wnd_name_list = []
    try:
        frequency = request.param['freq']
        for freq_value in frequency:
            blackout_window_name = random_name(prefix="FreezeWindow-")
            blackout_wnd_name_list.append(blackout_window_name)
            agent_blackout_windows_page.new_button.click()
            CreateBlackoutWindowPage().new_blackout_window(blackout_window_name, freq_value.title())
            LoadingCircle(WAIT_NORMAL)

            if request.param['shouldwait']:
                LoadingCircle(TIME_SIXTY_SECONDS)

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create a new blackout window')
        raise
    else:
        yield
    finally:
        try:
            agent_list_page = AgentBlackoutWindowList()
            for created_blackout_window in blackout_wnd_name_list:
                agent_list_page.delete_blackout_windows(created_blackout_window)

        except (AttributeError, NoSuchElementException, StaleElementReferenceException) as exc:
            log.warning("Unable to delete agent blackout window in clean up. window "
                        "may have been deleted by test or may be running. Error: %s", exc)


@pytest.fixture()
def create_policy(request: 'SubRequest', driver_instance):
    """
    Automatically create a policy by adding credentials with a random name and description depending upon type
          @pytest.mark.parametrize("create_policy", [("Advanced Scan", "scanner"),
                             indirect = True)
    The Above code will create a new Advanced Scan policy under scanner type
    """

    new_policy_name = random_name(prefix=request.param[0] + "-")
    policy_description = "Creating a new policy for " + request.param[0] + "."
    cred_type = None
    policy_page = PoliciesPage()

    try:
        policy_page.open()
        policy_page.js_scroll_into_view(element=policy_page.new_policy_button)
        policy_page.new_policy_button.click()
        wait(lambda: ScanTemplatePage().is_element_present('vuln_template_section'),
             waiting_for='scan templates to load properly.')

        policy_type = PolicyType()
        if request.param[1] == Nessus.Scan.ScanTemplateTabs.AGENT_TAB:
            policy_type.agent.click()

        policy_type.click_by_policy(request.param[0])
        NewPolicyForm().add_policy(policy_name=new_policy_name, policy_description=policy_description)

        try:
            if request.param[1] in (API.Credentials.Host.Types.WINDOWS,
                                    API.Credentials.Host.Types.SSH,
                                    API.Credentials.PlaintextAuthentication.HTTP):

                cred_type = request.param[1]
            else:
                cred_type = None
        except IndexError:
            log.warning("No extra settings required")

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create a new policy')
        raise
    else:
        if cred_type:
            yield new_policy_name, cred_type
        else:
            yield new_policy_name
    finally:
        try:
            SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.POLICIES).click()
            wait(lambda: policy_page.is_element_present('scan_templates_link'), waiting_for='policies page get loads')

            if not policy_page.is_element_present('create_a_new_policy_link'):
                policy_list = PolicyList()
                policy_list.loaded()
                policy_list.delete_policy(policy_name=new_policy_name)

        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete policy in clean up, it may have been deleted by test or may be running."
                        "Error: %s", exc)


@pytest.fixture()
def create_scan(request: 'SubRequest', driver_instance):
    """
    Automatically create a scan by adding provided name or host or random data depending upon type
              @pytest.mark.parametrize("create_scan",  [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    The Above code will create a new Advanced Scan policy under scanner type
    """
    scan_name = request.param.get('scan_name', random_name(prefix=request.param.get('template_name') + "-"))
    host_ip = request.param.get('host_ip', Nessus.Scan.Target.LOCALHOST)
    scan_page = ScansPage()

    try:
        if get_driver().current_url != Config.CAT_URL + "/#/scans/folders/my-scans":
            SideNav().click_by_link_text("My Scans (S)")
            wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
                "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")

        scan_page.new_scan_button.click()

        if is_home():
            ActionCloseModal().close_upgrade_np_offer_modal_nessus_home()
        elif is_pro():
            close_pendo_guide_container_banner_for_nessus_pro()

        scan_type = ScanType()
        scan_type.select_scan_type(type_of_scan=request.param.get('scan_type'))
        wait(lambda: ScanTemplatePage().is_element_present('vuln_template_section'),
             waiting_for='scan templates to load properly.')

        scan_type.click_by_scan(scan_text=request.param.get('template_name'))
        wait(lambda: NewScanForm().is_element_present('name_field'), waiting_for='new scan form to load properly.')

        scan_page.fill_new_scan_detail(scan_name=scan_name, host_ip=host_ip)

        yield scan_name
    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create a new scan')
        raise
    finally:
        try:
            if not get_driver().current_url.endswith('/scans/folders/my-scans'):
                SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
                wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scan list get loaded")

            ScanList().delete_scan(scan_name=scan_name)
            ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)
        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete scan at clean up, it may have been deleted"
                        " by test or may be running. Error: %s", exc)


@pytest.fixture()
def create_scan_bit_discovery(request: 'SubRequest', driver_instance):
    """
    Automatically create a scan by adding provided name or host or random data depending upon type
              @pytest.mark.parametrize("create_scan_bit_discovery",  [{'template_name': 'Attack Surface Discovery',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    The Above code will create a new BD Scan policy under scanner type
    """
    scan_name = request.param.get('scan_name', random_name(prefix=request.param.get('template_name') + "-"))
    domain_name = request.param.get('domain_name', "tenablesecurity.com")

    scan_page = ScansPage()

    try:
        if get_driver().current_url != Config.CAT_URL + "/#/scans/folders/my-scans":
            SideNav().click_by_link_text("My Scans (S)")
            wait(lambda: scan_page.is_element_present("scan_searchbox") or scan_page.is_element_present(
                "create_a_new_scan_link"), waiting_for="Scan page gets loaded properly")

        scan_page.new_scan_button.click()
        scan_type = ScanType()
        scan_type.select_scan_type(type_of_scan=request.param.get('scan_type'))
        wait(lambda: ScanTemplatePage().is_element_present('vuln_template_section'),
             waiting_for='scan templates to load properly.')

        scan_type.click_by_scan(scan_text=request.param.get('template_name'))
        wait(lambda: NewScanForm().is_element_present('name_field'), waiting_for='new scan form to load properly.')

        scan_page.fill_new_scan_detail(scan_name=scan_name)
        scan_page.discovery_option.click()
        scan_page.fill_new_scan_detail(domain_name=domain_name)

        yield scan_name
    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create a new scan')
        raise
    finally:
        try:
            if not get_driver().current_url.endswith('/scans/folders/my-scans'):
                SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
                wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scan list get loaded")

            ScanList().delete_scan(scan_name=scan_name)
            ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)
        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete scan at clean up, it may have been deleted"
                        " by test or may be running. Error: %s", exc)


@pytest.fixture()
def create_agents(request: 'SubRequest', driver_instance) -> list:
    """
    Automatically creates a list of agents
        @pytest.mark.parametrize("create_agent", [{'no_of_agents': 4}], indirect=True)
        this will create four agents.
    :return: agents_list
    """
    agents_list = []
    try:
        # create some fake agents
        for agents in range(request.param['no_of_agents']):
            if agents % 2 == 0:
                agent_name = random_name("LinkedAgents - e")
            else:
                agent_name = random_name("LinkedAgents - o")
            created_agents = request.cls.cat.api.agents.add_fake_agent(agent_name=agent_name)
            agents_list.append(created_agents.get('name'))
    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create agents')
        raise
    else:
        yield agents_list
    finally:
        # delete above created linked agents from agent management page
        try:
            AgentsPage().open()
            agent_list = AgentsList()
            while True:
                for agents in AgentsList().rows:
                    if agents.agent_name.text in agents_list:
                        agent_id = get_agent_id(request.cls.cat.api.agents.get_agents(1),
                                                agents.agent_name.text)
                        request.cls.cat.api.agents.delete(1, agent_id)

                if agent_list.agent_table.table_wrapper.is_button_enabled('next_page_button'):
                    agent_list.agent_table.table_wrapper.next_page_button.click()
                else:
                    break
        except (AttributeError, NoSuchElementException, StaleElementReferenceException) as exc:
            log.warning("Unable to delete agents in clean up. Agent may have been deleted by test "
                        "or may be running. Error: %s", exc)


@pytest.fixture()
def create_new_folder(request: 'SubRequest', nessus_api_login):
    """
    Automatic API Folder Creation.  Creates a randomly named folder and then deletes the folder when finished.
    """
    log.debug('fixture init: create_folder: Creates a folder')
    folder_id = None

    try:
        folder = request.param['folder_name']
    except (AttributeError, KeyError):
        folder = random_name(prefix='Ui-Auto-')

    try:
        folder_id = request.instance.cat.api.folders.create(name=folder)['id']

        yield folder_id, folder
    finally:
        try:
            request.instance.cat.api.folders.delete(folder_id=folder_id)
        except HTTPError:
            log.warning("Failed to delete created folder", exc_info=True)


@pytest.fixture()
def create_user(request: 'SubRequest'):
    """
    Automatic User Creation.  Creates a user with a particular role and then deletes the user when finished.
         @pytest.mark.parametrize("create_user", [{'username': API.User.Users.STANDARD_USER, 'password': 'password',
                                              'role': API.User.Role.STANDARD, 'do_login': True}]
    The Above code will create a new user with standard role and log in from that user.
    """
    username = request.param['username']
    password = request.param['password']
    is_ldap_user = request.param.get('is_ldap_user', False)
    unique_username = request.param.get('unique_username', False)
    user_menu = UserMenu()
    user_list = UserList()

    if unique_username:
        username = random_name(prefix=username + '-')

    try:
        new_user_form = NewUserForm()
        new_user_form.open()

        if is_ldap_user:
            new_user_form.fill_ldap_user_form(account_type=request.param['account_type'], user_name=username)
        else:
            new_user_form.fill_user_form(user_name=username, password=password, role=request.param['role'])

        sleep(WAIT_NORMAL, reason="It takes little bit time to move back to user page")
        user_list.loaded()

        if request.param['do_login']:
            user_menu.logout()
            login_page = LoginPage()
            wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)

            login_page.login_with_credentials(username=username, password=password)
            wait(lambda: ScansPage().is_element_present('title_in_header'),
                 waiting_for="My Scans page to load properly", timeout_seconds=TIME_SIXTY_SECONDS)

        yield username, password

    finally:
        try:
            user_menu.logout()
            LoginPage().login_with_defaults()
            wait(lambda: ScansPage().is_element_present('title_in_header'),
                 waiting_for="My Scans page to load properly", timeout_seconds=TIME_SIXTY_SECONDS)

            user_page = UsersPage()
            user_page.open()
            wait(lambda: user_page.is_element_present("search_box"), waiting_for="User list gets loaded")
            user_list.loaded()

            if is_ldap_user:
                user_list.delete_user(user_name='LDAP\n{}'.format(username))
            else:
                user_list.delete_user(user_name=username)

        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete user at clean up, it may have been deleted"
                        " by test or may be running. Error: %s", exc)


@pytest.fixture()
def create_users(request: 'SubRequest'):
    """
    Automatic User Creation.  Creates all available type  of user with a particular role and then deletes all the user
    when finished.
    @pytest.mark.parametrize("create_users", [{"user_details":
    {"Basic": {'user_name': random_name(prefix=API.User.Users.BASIC_USER + ' - '),'full_name': 'Basic user',
               'email': API.User.Users.TEST_EMAIL, 'password': 'Basic_P@ssw0rd', 'role': API.User.Role.BASIC},
     "Standard": {'user_name': random_name(prefix=API.User.Users.STANDARD_USER + ' - '), 'full_name': 'Standard user',
                  'email': API.User.Users.TEST_EMAIL,'password': 'Standard_P@ssw0rd','role': API.User.Role.STANDARD},
     "Administrator":{'user_name': random_name(prefix=API.User.Users.ADMIN_USER + ' - '), 'full_name': 'Admin user',
                      'email': API.User.Users.TEST_EMAIL, 'password': 'Admin_P@ssw0rd', 'role': API.User.Role.ADMIN},
     "System Administrator":{'user_name': random_name(prefix=API.User.Users.SYS_ADMIN_USER + ' - '),
                             'full_name': 'SysAdmin user', 'email': API.User.Users.TEST_EMAIL,
                             'password': 'SysAdmin_P@ssw0rd', 'role': API.User.Role.SYS_ADMIN}
    }, "check_login": True}], indirect=True)
    The Above code will create 4 new user with different role.
    """
    user_details = request.param.get('user_details', 'No user details found.')
    user_credentials = {}

    user_page = UsersPage()
    user_page.open(timeout=WAIT_LONG)

    user_list = UserList()
    unique_username = request.param.get('unique_username', False)

    try:
        for user in user_details.keys():
            if unique_username:
                user_details.get(user)['user_name'] = random_name(
                    prefix=user_details.get(user).get('user_name').split()[0] + ' - ')

            user_page.add_new_user(user_name=user_details.get(user).get('user_name'),
                                   full_name=user_details.get(user).get('full_name'),
                                   email=user_details.get(user).get('email'),
                                   password=user_details.get(user).get('password'),
                                   role=user_details.get(user).get('role'))

            wait(lambda: user_page.is_element_present("search_box"), waiting_for="User page gets loaded")
            user_list.loaded()
            user_credentials.update({user: user_details.get(user)})

            if request.param.get('check_login'):
                user_menu = UserMenu()
                user_menu.logout()

                login_page = LoginPage()
                wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)
                login_page.login_with_credentials(username=user_details.get(user).get('user_name'),
                                                  password=user_details.get(user).get('password'))

                user_menu.loaded(timeout=WAIT_LONG)
                NotificationActions().remove_all()
                user_menu.logout()
                wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)

                login_page.login_with_defaults()
                user_menu.loaded(timeout=WAIT_LONG)

                user_page.open()
                wait(lambda: user_page.is_element_present("search_box"), waiting_for="User list gets loaded")

        log.debug("Created user's details: %s", user_credentials)
        yield user_credentials

    finally:
        try:
            user_menu = UserMenu()
            user_menu.logout()

            LoginPage().login_with_defaults()
            user_menu.loaded()

            user_page.open(timeout=WAIT_LONG)
            wait(lambda: user_page.is_element_present("search_box"), waiting_for="User list gets loaded")

            for user in user_details.keys():
                user_list.delete_user(user_name=user_details.get(user).get('user_name'))
                ActionCloseModal().wait_for_modal_closed()

        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete user at clean up, it may have been deleted by test or may be running. "
                        "Error: %s", exc)


@pytest.fixture()
def add_ldap_setting(request: 'SubRequest'):
    """
    fixture to add ldap server settings
    """
    host = request.param['host']
    port = request.param['port']
    username = request.param['username']
    password = request.param['password']
    base_dn = request.param['base_dn']
    attributes = request.param.get('attributes', {})
    test_connection = request.param.get('test_connection', True)

    ldap_server_page = LdapServerPage()

    try:
        ldap_server_page.open()
        ldap_server_page.add_ldap_settings(host=host, port=port, username=username, password=password, base_dn=base_dn,
                                           **attributes)

        if test_connection:
            ldap_server_page.test_ldap_server_btn.click()
            action_close_modal = ActionCloseModal()
            wait(lambda: action_close_modal.is_element_present("modal"), waiting_for="modal gets opened")

            assert action_close_modal.modal.is_displayed(), 'LDAP Server is not configured properly'

            action_close_modal.cancel_button.click()
            action_close_modal.wait_for_modal_closed()

        ldap_server_page.save_button.click()
        sleep(WAIT_NORMAL, reason="waiting for LDAP server settings gets saved")
        yield

    finally:
        # clearing LDAP Server settings and removing LDAP user
        ldap_server_page.open()
        ldap_server_page.add_ldap_settings(host="", port="", username="", password="", base_dn="",
                                           **API.Settings.Ldap.Attributes.WITHOUT_ATTRIBUTES)
        ldap_server_page.save_button.click()
        sleep(WAIT_NORMAL, reason="waiting for LDAP server settings gets saved")


@pytest.fixture()
def create_plugin_rule(request: 'SubRequest', driver_instance) -> dict:
    """
    Fixture for filling plugin rule form and clearing the data after test case is done.

    @pytest.mark.parametrize("create_plugin_rule", [{'plugin_id': 22964,
                                                     'severity': Nessus.Scan.Severity.CRITICAL}], indirect=True)
    """

    plugin_rule = PluginRulesPage()
    try:
        plugin_rule.open()
        plugin_rule.add_new_plugin_rule(**request.param)

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to save plugin rule settings.')
        raise
    else:
        yield request.param
    finally:
        try:
            plugin_rule.open()
            plugin_list = PluginRulesList()
            plugin_list.delete_plugin_rule(request.param['plugin_id'])
            LoadingCircle(WAIT_SHORT)
        except(AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete plugin rule in clean up, it may have been deleted"
                        " by test or may be running. Error: %s", exc)


@pytest.fixture()
def add_custom_ca(request: 'SubRequest'):
    """
    fixture to add custom_ca certificate
    @pytest.mark.parametrize("add_custom_ca", [{'file_path':get_file_path('nessus/tests/ui/ca-cert/test_data/rdp.cer')}]
    , indirect=True)
    above code will save custom_ca certificate
    """
    custom_ca_page = CustomCAPage()

    try:
        file_path = os.path.abspath(request.param['file_path'])
        file_data = read_from_file(filename=file_path)

        custom_ca_page.open()
        custom_ca_page.add_custom_ca(ca_value=file_data)

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to save custom_ca certificate.')
        raise
    else:
        yield
    finally:
        try:
            # removes custom_ca certificate
            custom_ca_page.remove_custom_ca()
        except (AttributeError, NoSuchElementException) as exc:
            log.warning("Unable to delete custom_ca in clean up. Error: %s", exc)


@pytest.fixture()
def proxy_server_settings(request: 'SubRequest', driver_instance) -> dict:
    """
    Fixture for filling Proxy Server Form and clearing the data after test case is done.

   @pytest.mark.parametrize(("proxy_server_settings", [{'host': API.Settings.ProxyServer.PROXY_HOST,
                                                        'port': API.Settings.ProxyServer.PROXY_PORT,
                                                        'username': API.Settings.ProxyServer.PROXY_USERNAME,
                                                        'password': API.Settings.ProxyServer.PROXY_PASSWORD,
                                                        'agent': API.Settings.ProxyServer.PROXY_USER_AGENT}],
                                                       indirect=True)
    """
    proxy_server = ProxyServer()

    try:
        proxy_server.open()
        proxy_server.fill_proxy_server_form(**request.param)
    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to save proxy server settings .')
        raise
    else:
        yield request.param
    finally:
        try:
            proxy_server.fill_proxy_server_form(host='', port='')
            proxy_server.save_button.click()
        except (AttributeError, NoSuchElementException) as exc:
            log.warning("Unable to delete proxy server settings in clean up. Error: %s", exc)


@pytest.fixture()
def change_master_password(request: 'SubRequest', driver_instance) -> dict:
    """
    Fixture for changing master password. After test is completed, revert password back to original
        @pytest.mark.parametrize('change_master_password', [{'existing_password': "master", 'new_password': "master1"}],
        indirect=True)
    The Above code will change the master password.
    """
    about_master_page = MasterPassword()
    about_master_page.open()
    about_master_page.loaded()

    try:
        about_master_page.set_master_password(**request.param)

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to save master password .')
        raise
    else:
        yield request.param

    finally:
        # revert password back to original
        try:
            about_master_page.set_master_password(existing_password=request.param['new_password'])
        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to revert back master password. Exception :: {}".format(exc), exc_info=True)


@pytest.fixture()
def add_advanced_setting(request: 'SubRequest'):
    """
    Fixture for creating advanced setting and delete after test case is finished.
    @pytest.mark.parametrize('add_advanced_setting', [{"name": "login_banner", "value":"my login banner"}],
        indirect=True)
    """
    get_driver_no_init().refresh()
    setting_name = request.param.get("name")
    setting_value = request.param.get("value")

    advanced_setting = AdvancedSettingsPage()
    advanced_setting_list = AdvancedSettingsList()

    try:
        if not invisibility_of_element_located((By.CSS_SELECTOR, '.modal'))(get_driver_no_init()):
            if UnsavedChangesModal().unsaved_changes_title.text == "Banner":
                log.info('Login banner is visible')
                ActionCloseModal().accept_action()

        advanced_setting.open()
        advanced_setting.loaded()
        get_driver_no_init().refresh()
        sleep(TIME_TWENTY_SECONDS, reason="setting page reload takes bit time to get loaded.")

        nessus_api = NessusAPI()
        nessus_api.login()

        settings = nessus_api.settings.get_list()
        is_setting_exist = any([True if setting['name'] == setting_name else False for setting in
                                settings['preferences']])

        if not is_setting_exist:
            add_advanced_setting_helper(setting_name=setting_name, setting_value=setting_value)

            try:
                NotificationActions().remove_all()
            except:
                pass
        else:
            log.warning("Setting '{}' is already exist there...".format(setting_name))
    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to add new setting .')
        raise
    else:
        yield setting_name, setting_value

    finally:
        try:
            if not get_driver_no_init().current_url.endswith("/settings/advanced"):
                advanced_setting.open()
                wait(
                    lambda: advanced_setting_list.is_element_present("user_interface_tab", timeout=TIME_THIRTY_SECONDS),
                    waiting_for="User Interface tab to visible")

            if advanced_setting_list.is_element_present("custom_tab") and setting_name in \
                    advanced_setting_list.get_setting_identifiers_by_tab(setting_tab="Custom"):
                delete_advanced_setting_helper(setting_name=setting_name)
        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete the setting.", exc_info=True)


@pytest.fixture()
def edit_xmlrpc_listen_port(request: 'SubRequest'):
    """
    Fixture for editing Listen Port and changing it back to default after case is complete
    @pytest.mark.parametrize('edit_xmlrpc_listen_port', [{"port": "8835"}],
        indirect=True)
    """
    notice_settings = NoticeAdvancedSettings()

    advanced_setting = AdvancedSettingsPage()
    advanced_setting.open()
    try:
        advanced_setting = AdvancedSettingsPage()
        advanced_setting.open()

        changed_port = request.param.get('port')

        advanced_setting_list = AdvancedSettingsList()
        advanced_setting_list.edit_or_add_setting(setting_name=Nessus.AdvancedSettings.XMLRPC_LISTEN_PORT,
                                                  setting_value=changed_port)
        LoadingCircle(WAIT_SHORT)

        notice_settings.notice_restart.click()
        notice_settings.is_element_present('connection_popup', timeout=TIME_TEN_MINUTES)
    except (CatiumPageLoadError, TimeoutExpired):
        raise
    else:
        yield changed_port
    finally:
        HeaderBasePage().settings_link.click()
        LoadingCircle(WAIT_SHORT)
        SideNav().click_by_link_text(Nessus.SideNavSettings.ADVANCED)
        LoadingCircle(WAIT_SHORT)

        advanced_setting.get_dynamic_element_for_setting_name(Nessus.AdvancedSettings.XMLRPC_LISTEN_PORT).click()
        LoadingCircle(WAIT_SHORT)
        add_advanced_modal = AddAdvancedSettingModal()
        add_advanced_modal.change_setting(setting_value=Nessus.DEFAULT_PORT)
        LoadingCircle(WAIT_NORMAL)

        notice_settings.notice_restart.click()
        notice_settings.is_element_present('connection_popup', timeout=TIME_TEN_MINUTES)

        get_driver_no_init().get(Config.CAT_URL)
        get_driver_no_init().refresh()
        LoadingCircle(WAIT_LONG)

        login_page = LoginPage()
        if get_driver_no_init().current_url == Config.CAT_URL + '/#/':
            login_page.is_element_present('username_field', timeout=TIME_SIXTY_SECONDS)
            login_page.refresh()
            login_page.login_with_defaults()
            LoadingCircle(WAIT_NORMAL)


@pytest.fixture()
def create_policies(request: 'SubRequest'):
    """
    Fixture to create multiple policies.
    e.g. : @pytest.mark.parametrize("create_policies", [{'policies_details': [
                {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER},
                {"template_name": Nessus.TemplateNames.ADVANCED_AGENT, "type": API.Permissions.Types.AGENT,
                 "policy_name": "test1111", "description": "test description"}]}], indirect=True)
    The Above code will create 3 policies with provided details.
    """
    policies_details = request.param.get('policies_details')
    if not policies_details:
        log.error("Can't create any policy, No details found.")
        return

    created_policies_list = []
    policy_page = PoliciesPage()
    policy_page.open()

    try:
        for policy in policies_details:
            created_policy = policy_page.create_new_policy(**policy)
            created_policies_list.append(created_policy)

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create a new policy')
        raise
    else:
        yield created_policies_list
    finally:
        try:
            SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.POLICIES).click()
            wait(lambda: policy_page.is_element_present('scan_templates_link'), waiting_for='policies page get loads')

            if not policy_page.is_element_present('create_a_new_policy_link'):
                policy_list = PolicyList()
                policy_list.loaded()

                for policy in created_policies_list:
                    policy_list.delete_policy(policy_name=policy)

        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete policy in clean up, it may have been deleted"
                        " by test or may be running. Error: %s", exc)


@pytest.fixture()
def import_scan_file(request: 'SubRequest'):
    """
    fixture to import a scan file
    e.g. : @pytest.mark.parametrize("import_scan_file", [{"filename": 'System_Health_Discovery_-_100MB.db',
                                                   "scan_file_path": 'nessus/tests/ui/scans/test_data/',
                                                   "password": 'Tenable123'},
                                                  {"filename": 'Advanced_all_plugIns_with_compliance.nessus',
                                                   "scan_file_path": 'nessus/tests/ui/scans/test_data/'}
                                                  ], indirect=True)
    :param request:
        :str filename : file to import
        :str scan_file_path : path from where to import
        :str password : (optional) Needed only when you import '.db' file
        :str folder_name: (optional) folder where scan will import.
    :return: str : imported scan file name
    """
    scan_file_name = request.param.get('filename')
    file_path = request.param.get('scan_file_path')
    password = request.param.get('password')
    folder_name = request.param.get('folder_name')
    imported_file = None

    if not (scan_file_name and file_path):
        log.error("Import not possible as filename and/or file path is missing.")
        return

    if folder_name:
        side_nav = SideNav()
        side_nav.refresh()
        side_nav.get_sidenav_element(element_name=folder_name).click()

    scan_file_extension = os.path.splitext(scan_file_name)[1][1:]
    try:
        scan_page = ScansPage()
        if scan_file_extension == API.Scan.ExportFormats.FORMAT_DB:
            imported_file = scan_page.import_scan_file(file_name=scan_file_name, scan_file_path=file_path,
                                                       password=password)
        else:
            imported_file = scan_page.import_scan_file(file_name=scan_file_name, scan_file_path=file_path)

        yield imported_file

    finally:
        try:
            if imported_file:
                scan_list = ScanList()
                scan_list.delete_scan(scan_name=imported_file)
                LoadingCircle(WAIT_SHORT)

                ScansTrashPage().delete_scan_from_trash(scan_name=imported_file)
                LoadingCircle(WAIT_SHORT)
        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete imported scan at clean up, it may have been deleted by test "
                        "or may be running or might not imported successfully. Error: %s", exc)


@pytest.fixture()
def import_scan_via_api(request: 'SubRequest'):
    """
    fixture to import a scan file via API
    e.g.: @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Agent_Scan.db',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'password': 'password', "encrypted": True}], indirect=True)
    :param request:
        :str file_name : file to import
        :str file_path : path from where to import
        :str password : (optional) Needed only when you import '.db' file
        :str folder_name : (optional) Needed only when you want to import in specified folder
    :return: str : imported scan file name
    """
    scan_file_name = request.param.get('file_name')
    scan_file_path = request.param.get('file_path')
    folder_name = request.param.get('folder_name')
    create_folder = request.param.get('create_folder', False)
    folder_id = None
    response = None

    if not (scan_file_name and scan_file_path):
        log.error("Import not possible as filename and/or file path is missing.")
        return

    if folder_name:
        folder_list = request.instance.cat.api.folders.get_folders()['folders']
        if folder_list:
            for folder in folder_list[::-1]:
                if folder_name == folder['name']:
                    folder_id = folder['id']
                    break
        else:
            log.debug("%s : folder not found.")
    else:
        if create_folder:
            folder_name = random_name(prefix='UI-Auto-')
            created_folder_response = request.instance.cat.api.folders.create(name=folder_name)
            folder_id = created_folder_response['id']

    try:
        scan_file = get_file_path(scan_file_path + scan_file_name)
        file_uploaded = request.instance.cat.api.file.upload(file=scan_file,
                                                             encrypted=request.param.get('encrypted', None))
        response = request.instance.cat.api.scans.import_scan(file_uploaded, folder_id=folder_id,
                                                              password=request.param.get('password', None))
        assert request.instance.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % request.instance.cat.api.http_status_code

        yield (response['scan']['name'], folder_name, folder_id) if create_folder else (response['scan']['name'],response['scan']['id'])

    finally:
        if response:
            try:
                request.cls.cat.api.scans.delete(response['scan']['id'])
            except HTTPError:
                log.warning("Unable to delete scan in fixture teardown.")

        if create_folder:
            try:
                request.instance.cat.api.folders.delete(folder_id=folder_id)
            except HTTPError:
                log.warning("Unable to delete folder in fixture teardown.")


@pytest.fixture()
def import_policy(request: 'SubRequest'):
    """
    fixture to import a policy file
    e.g. : @pytest.mark.parametrize("import_policy", [{"file_name": 'Advanced_all_plugIns_with_compliance.nessus',
                                                "file_path": 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    :param request:
        :file_name: file to import
        :file_path: path from where to import
    :return: str : imported policy file name
    """
    policy_file_name = request.param.get('file_name')
    file_path = request.param.get('file_path')

    if not (policy_file_name and file_path):
        log.error("Import not possible as filename and/or file path is missing.")
        return

    policies_page = PoliciesPage()

    try:
        policies_page.open()
        imported_policy_file = policies_page.import_policy_file(file_name=policy_file_name, file_path=file_path)

        yield imported_policy_file

    finally:
        try:
            policies_page.open()
            policies_list = PolicyList()
            policies_list.delete_policy(policy_name=imported_policy_file)

        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete imported policy at clean up, it may have been deleted by test "
                        "or may be running or might not imported successfully. Error: %s", exc)


@pytest.fixture()
def create_groups(request: 'SubRequest'):
    """
    Fixture to create multiple groups.
    e.g. : @pytest.mark.parametrize("create_groups", [{
                            'group_details': [{"group_name": random_name(prefix=Prefixes.GROUP)},
                                              {"group_name": random_name(prefix=Prefixes.GROUP)}]}], indirect=True)
    The Above code will create 2 groups with provided details.
    """
    group_details = request.param.get('group_details')

    if not group_details:
        log.error("Can't create any group, No details found.")
        return

    group_page = GroupsPage()
    group_page.open()
    wait(lambda: group_page.is_element_present("search_box") or group_page.is_element_present(
        "create_a_new_group_link"), waiting_for="User group page gets loaded")

    created_group_list = []
    new_group_page = NewGroupPage()

    try:
        for group in group_details:
            if group.get("unique_group", False):
                group.update({"group_name": "group-{}".format(random.randint(10000, 99999))})

            group_page.create_new_user_group(group.get("group_name"))
            wait(lambda: new_group_page.is_element_present("add_user_button"),
                 waiting_for="'Add User' button to be visible")
            created_group_list.append(group.get("group_name"))

            if group.get("add_users"):
                new_group_page.add_user_to_group(group.get('user_list'))

            wait(lambda: visibility_of_element_located(new_group_page.back_to_groups),
                 waiting_for='Page getting load properly.')
            new_group_page.back_to_groups.click()
            wait(lambda: group_page.is_element_present("search_box"), waiting_for="Group page gets loaded")

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create a new group')
        raise
    else:
        yield created_group_list
    finally:
        try:
            group_page.open(timeout=WAIT_LONG)
            wait(lambda: group_page.is_element_present("search_box"), waiting_for="Group list gets loaded")

            group_list = GroupList()
            group_list.loaded()

            for group in created_group_list:
                group_list.delete_group(group)
        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete group in clean up, it may have been deleted by test or may be running. "
                        "Error: %s", exc)


@pytest.fixture()
def create_agent_groups(request: 'SubRequest'):
    """
    Fixture to create multiple agent groups.
    e.g. : @pytest.mark.parametrize("create_agent_groups", [{'agent_group_details': [
            {'agent_group_name': random_name(prefix=Prefixes.AGENT_GROUP), 'add_agents': True,
             'agents_details': ['LinkedAgents - ea76ad8eb6a8e', 'LinkedAgents - ebd41e765b1e5']},
            {'agent_group_name': random_name(prefix=Prefixes.AGENT_GROUP)}]}], indirect=True)
    The Above code will create 2 agent groups with provided details.
    """
    agent_group_details = request.param.get('agent_group_details')
    if not agent_group_details:
        log.error("Can't create any agent group, No details found.")
        return

    created_agent_group_list = []
    agent_group_page = CreateGroupWindowPage()
    agent_group_page.open()
    LoadingCircle(WAIT_NORMAL)
    try:
        for agent_group in agent_group_details:
            LoadingCircle(WAIT_SHORT)
            agent_group_name = random_name(prefix=agent_group.get("agent_group_name"))
            agent_group_page.create_group(group_name=agent_group_name, add_agents=agent_group.get("add_agents"))
            if agent_group.get("add_agents") and agent_group.get('agents_details'):
                agent_group_page.add_agent_member_to_agent_group(agent_group.get('agents_details'))
                LoadingCircle(TIME_THREE_SECONDS)
                created_agent_group_list.append({agent_group_name: agent_group.get('agents_details')})
            else:
                created_agent_group_list.append(agent_group_name)

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create a new agent_group.')
        raise
    else:
        yield created_agent_group_list
    finally:
        try:
            agent_group_page.open()
            LoadingCircle(WAIT_LONG)

            if not AgentGroupsPage().is_element_present('new_group_link'):
                agent_group_list = AgentGroupsList()
                for agent_group in created_agent_group_list:
                    agent_group_list.delete_group(group_name=agent_group)
                    LoadingCircle(WAIT_NORMAL)

        except (AttributeError, NoSuchElementException, TimeoutExpired) as exc:
            log.warning("Unable to delete agent group in clean up, it may have been deleted"
                        " by test or may be running. Error: %s", exc)


@pytest.fixture()
def create_new_blackout_window_and_wait_till_activation(request: 'SubRequest', driver_instance):
    """
    Automatically create a blackout window with a random name and provided frequency.
    Blackout window time period will start after two minutes of the time when fixture is called.
    This fixture will wait till the blackout window gets activated.

    @pytest.mark.parametrize("create_new_blackout_window_and_wait_till_activation", ["Once"],indirect = True)
    The Above code will create a new blackout window with once as frequency
    """
    is_time_set = request.param['is_time_set'] if hasattr(request, 'param') and 'is_time_set' in request.param \
        else True
    bw_duration = request.param['bw_duration'] if hasattr(request, 'param') and 'bw_duration' in request.param \
        else True
    frequency_value = request.param['frequency'] if hasattr(request, 'param') and 'frequency' in request.param \
        else API.Schedule.Frequencies.FREQ_ONCE.title()

    new_blackout_window_name = random_name(prefix="FreezeWindow-")
    agent_blackout_windows_page = AgentBlackoutWindowsPage()

    try:
        agent_blackout_windows_page.open()
        agent_blackout_windows_page.new_button.click()
        create_blackout_window_page = CreateBlackoutWindowPage()
        create_blackout_window_page.new_blackout_window(new_blackout_window_name, frequency_value, is_time_set,
                                                        bw_duration)
        LoadingCircle(WAIT_NORMAL)

    except (CatiumPageLoadError, TimeoutExpired):
        log.exception('Fixture failed to create a new blackout window')
        raise
    else:
        yield new_blackout_window_name
    finally:
        try:
            agent_blackout_windows_page.open()
            wait(lambda: agent_blackout_windows_page.is_element_present('new_button'),
                 sleep_seconds=TIME_THREE_SECONDS, timeout_seconds=TIME_SIXTY_SECONDS,
                 waiting_for="wait till blackout window page loaded successfully.")
            agent_list_page = AgentBlackoutWindowList()
            if new_blackout_window_name in agent_list_page.blackout_window_all_names:
                agent_list_page.delete_blackout_windows(new_blackout_window_name)

        except (AttributeError, NoSuchElementException) as exc:
            log.warning("Unable to delete agent blackout window in clean up. window "
                        "may have been deleted by test or may be running. Error: %s", exc)


@pytest.fixture()
def create_permanent_blackout_window(request: 'SubRequest', driver_instance):
    """ This fixture will create permanent blackout window for agents """
    agent_bw_setting_page = AgentBlackoutWindowSettingsPage()
    agent_bw_setting_page.open()
    LoadingCircle(WAIT_NORMAL)
    is_permanent_blackout_selected = agent_bw_setting_page.get_checkbox_element_for_blackout_window(
        data_name='permanent blackout').is_selected()

    if not is_permanent_blackout_selected:
        agent_bw_setting_page.get_permanent_blackout_window_checkbox().click()
        agent_bw_setting_page.save_button.click()
        LoadingCircle(WAIT_NORMAL)
    yield

    # Moving the agent setting's permanent blackout window option back to the original state.
    if not is_permanent_blackout_selected:
        agent_bw_setting_page.get_permanent_blackout_window_checkbox().click()
        agent_bw_setting_page.save_button.click()
        LoadingCircle(WAIT_NORMAL)


@pytest.fixture()
def prevent_software_update(request: 'SubRequest', driver_instance):
    """ This fixture will enable "prevent software update" option in Agent's setting page"""
    agent_bw_setting_page = AgentBlackoutWindowSettingsPage()
    agent_bw_setting_page.open()
    LoadingCircle(WAIT_NORMAL)
    is_prevent_software_update_selected = agent_bw_setting_page.get_checkbox_element_for_blackout_window(
        data_name='Prevent core updates').is_selected()

    if not is_prevent_software_update_selected:
        agent_bw_setting_page.get_prevent_core_update_checkbox().click()
        agent_bw_setting_page.save_button.click()
        LoadingCircle(WAIT_NORMAL)

    yield
    # Moving the agent setting's "prevent software update" option back to the original state.
    if not is_prevent_software_update_selected:
        agent_bw_setting_page.get_prevent_core_update_checkbox().click()
        agent_bw_setting_page.save_button.click()
        LoadingCircle(WAIT_NORMAL)


@pytest.fixture()
def track_unlinked_agent(request: 'SubRequest', driver_instance) -> None:
    """
    Fixture to set track unlinked agent setting under agent settings page

    @pytest.mark.parametrize('track_unlinked_agent', [{'enable_tracking':False}], indirect=True)
    The above code will set the 'Track Unlinked Agent' setting under agent settings page to 'Disable'
    """
    enable_tracking = request.param.get('enable_tracking', True) if hasattr(request, 'param') else True
    agent_setting = AgentSettingsPage()
    agent_setting.open()
    cb_status = agent_setting.track_unlinked_agent_checkbox.is_selected()
    agent_setting.track_unlinked_agent(enable_tracking=enable_tracking)
    yield
    agent_setting.open()
    agent_setting.track_unlinked_agent(enable_tracking=cb_status)


@pytest.fixture()
def create_scans(request: 'SubRequest'):
    """
    Fixture to create multiple scans.
    e.g. : @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": API.Permissions.Types.SCANNER,
         "scan_name": random_name(prefix=Nessus.TemplateNames.ADVANCED), "description": "test description",
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, "folder": "test", "dashboard": "Enabled",
         "target_file": get_file_path('nessus/tests/ui/scans/test_data/Basic_Agent_Scan.nessus')},
        {"scan_template": Nessus.TemplateNames.ADVANCED_AGENT, "scan_type": API.Permissions.Types.AGENT,
         "scan_name": random_name(prefix=Nessus.TemplateNames.ADVANCED), "description": "test ad description",
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, "folder": "test", "dashboard": "Enabled",
         "agent_group": 'test', "scan_window": '3 hours'}]}], ret_details=False, indirect=True)
    The Above code will create 3 scans with provided details.
    """
    scans_details = request.param.get('scans_details')
    ret_details = request.param.get('ret_details')

    if not scans_details:
        raise AssertionError("Can't create any scans, No details found.")

    created_scans_list = []

    try:
        for scan in scans_details:
            scan.get("schedule_scan", False)
            if not scan.get('folder'):
                if not get_driver().current_url.endswith('/scans/folders/my-scans'):
                    HeaderBasePage().scan_link.click()
                    scan_page = ScansPage()
                    wait(lambda: scan_page.is_element_present('create_a_new_scan_link') or scan_page.is_element_present(
                        'scan_searchbox'), waiting_for='Scan page to load properly')

                SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()

            if not scan.get('keep_original_scan_name'):
                scan.update({'scan_name': random_name(prefix="{} - ".format(scan.get('scan_template')))})

            if scan.get('schedule_scan'):
                ScansPage().create_new_scan(**scan)
                schedule_info = {'schedule_date': datetime.today().date() + timedelta(days=2),
                                 'schedule_timezone': time.tzname[0],
                                 'schedule_time': (datetime.today() + timedelta(hours=1)).time(),
                                 'schedule_frequency': API.Schedule.Frequencies.FREQ_ONCE.title()}
                BasicSetting().schedule_scan(**schedule_info)
                if ret_details:
                    created_scans_list.append(scan)
                else:
                    created_scans_list.append(scan.get('scan_name'))
            else:
                if all([scan.get('scan_template'), scan.get('scan_type'), scan.get('scan_name')]):
                    scans_page = ScansPage()
                    if not scans_page.is_element_present('new_scan_button'):
                        HeaderBasePage().scan_link.click()
                        wait(lambda: scans_page.is_element_present('new_scan_button'),
                             waiting_for="Scans page to get loaded.")
                    scans_page.create_new_scan(**scan)
                    if ret_details:
                        created_scans_list.append(scan)
                    else:
                        created_scans_list.append(scan.get('scan_name'))
                else:
                    raise AssertionError("Can't create a scan, mandatory field details not found.")

    except (CatiumPageLoadError, TimeoutExpired) as e:
        log.exception('Fixture failed to create a new scan')
        raise AssertionError(e)

    else:
        yield created_scans_list

    finally:
        try:
            scan_list = ScanList()
            wait(lambda: visibility_of_element_located(ScansPage().scan_searchbox), waiting_for='scan list to load')

            for scan in created_scans_list[::-1]:
                if ret_details and not isinstance(scan, str):
                    scan_name = scan.get('scan_name')
                else:
                    scan_name = scan

                scan_list.delete_scan(scan_name=scan_name)
                LoadingCircle(WAIT_SHORT)

                # remove tooltip 'Trash'
                get_driver_no_init().execute_script("$('.tipsy.tipsy-s').remove()")

            trash_page = ScansTrashPage()
            for scan in created_scans_list:
                trash_page.delete_scan_from_trash(scan_name=scan)

            api = NessusAPI()
            api.login()

            # Also delete any remaining scans from previous runs that didn't get deleted
            try:
                if api.scans.get_scans(folder_id=1)['scans']:
                    SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
                    scan_list = ScanList()
                    scan_list.loaded()

                    for scan in scan_list.get_all_scans():
                        scan_list.delete_scan(scan_name=scan)
                        LoadingCircle(WAIT_SHORT)
            except:
                pass

        except Exception as exc:
            log.warning("Unable to delete scans in clean up, it may have been deleted"
                        " by test or may be running. Error: %s", exc)


@pytest.fixture(scope="class")
def change_expiration_date():
    """
    Fixture to change the product type with given expiration days as setup and update the activation code again to
    change the product type to previous one as teardown process
    """
    try:
        nessus_api = NessusAPI()
        nessus_api.login()
        nessus_api.settings.edit_software_updates_setting(
            payload={"custom_host": Nessus.Scan.Target.STAGING_FEED_SERVER_HOST})

        activation_code_generator(expire_days=2, product_type='pro-eval')
        yield
    finally:
        activation_code_generator(expire_days=365, product_type='professional')


@pytest.fixture()
def reset_license():
    """ This fixture will reset the the product and take user to product registration page"""
    try:
        remove_nessus_registration()
    except:
        log.error(msg="Unable to reset the existing license")


@pytest.fixture()
def change_update_frequency(request: 'SubRequest'):
    """
    fixture to change the value of update frequency in about page and revert back in tear-down

    :return: update frequency to be set
    :rtype: str

    e.g.: @pytest.mark.parametrize('change_update_frequency', [{'frequency': '3'}], indirect=True)
    """
    about_software_update = SoftwareUpdate()
    about_software_update.open()
    wait(lambda: visibility_of_element_located(about_software_update.update_frequency_custom_tip),
         waiting_for='software update page to open')

    update_frequency = ""
    new_frequency = request.param.get('frequency') if hasattr(request, 'param') else '1'

    try:
        if about_software_update.is_element_present('update_frequency'):
            update_frequency = about_software_update.update_frequency.get_text_selected()
            about_software_update.update_frequency_custom_tip.click()
        else:
            update_frequency = about_software_update.update_frequency_in_hours.value

        about_software_update.update_frequency_in_hours.value = new_frequency
        about_software_update.save_button.click()

    except Exception as err:
        log.warning("fixture failed to update the value of frequency. Exception :: {}".format(err))

    yield new_frequency

    try:
        if update_frequency in [dct["label"] for dct in about_software_update.update_frequency.option_values]:
            about_software_update.update_frequency_default_tip.click()
            about_software_update.change_software_update_settings(frequency_option=update_frequency)
        else:
            about_software_update.update_frequency_in_hours.value = update_frequency
            about_software_update.save_button.click()

    except Exception as err:
        log.warning("unable to revert back the value of frequency. Exception :: {}".format(err))


@pytest.fixture()
def setup_nessus_with_expiration_days(request: 'SubRequest'):
    """This fixture will setup the nessus license with given expiration days in setup and revert the license back
     with expiration days as 365"""

    nessus_type = get_nessus_type_using_api().split()[1].lower()
    expiration_day = request.param['expiration_days']
    activation_generator = ActivationCodeGenerator()
    log.info("Updating license expiration to %d days from now" % expiration_day)
    try:
        if nessus_type == 'manager':
            activation_code = activation_generator.generate_nessus_manager_code(expiration_days=expiration_day)
        else:
            activation_code = activation_generator.generate_code(code_type=nessus_type,
                                                                 expiration_days=expiration_day)
        overview_page = OverView()
        overview_page.open()
        NotificationActions().remove_all()

        overview_page.update_activation_code_tip.click()
        overview_page.update_activation_code_area.value = activation_code

        try:
            action_modal = ActionCloseModal()
            action_modal.accept_action()
            action_modal.wait_for_modal_closed()

            wait_for_scanner_status(api=NessusAPI(), timeout=TIME_ONE_HOUR, status=API.Status.READY,
                                    msg='Waiting for server to be in ready state.', sleep_interval=TIME_THIRTY_SECONDS)
        except:
            log.info(msg="Unable to update the activation code")
        yield expiration_day
    finally:
        log.info("Restoring license expiration to 365 days from now")
        if nessus_type == 'manager':
            activation_code = activation_generator.generate_nessus_manager_code(
                expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)
        else:
            activation_code = activation_generator.generate_code(
                code_type=nessus_type, expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)

        overview_page = OverView()
        overview_page.open()
        overview_page.update_activation_code_tip.click()
        overview_page.update_activation_code_area.value = activation_code

        action_modal = ActionCloseModal()
        action_modal.accept_action()
        action_modal.wait_for_modal_closed()

        wait_for_scanner_status(api=NessusAPI(), timeout=TIME_ONE_HOUR, status=API.Status.READY,
                                msg='Waiting for server to be in ready state.', sleep_interval=TIME_THIRTY_SECONDS)
        wait(lambda: LoginPage().is_element_present("username_field"), timeout_seconds=TIME_SIXTY_SECONDS)
        login_helper_after_server_restart()

        if is_pro():
            close_welcome_nessus_10_modal_for_pro()

        wait(lambda: UserMenu().is_element_present('user_menu_dropdown'))


@pytest.fixture()
def create_data_for_different_users(create_users) -> dict:
    """
    Creates different data like scan, policy and plugin for different users

    :return: user data created by different users
    :rtype: dict
    """
    user_data = {}

    user_menu = UserMenu()
    user_menu.logout()

    login_page = LoginPage()
    wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)
    scan_page = ScansPage()

    try:
        for user in create_users.keys():
            user_role = create_users.get(user).get('role')
            user_name = create_users.get(user).get('user_name')

            user_data[user_name] = {}
            login_page.login_with_credentials(username=user_name, password=create_users.get(user).get('password'))

            if user_role != API.User.Role.BASIC:
                scan_name = random_name(prefix="Advanced_Scan" + "-")
                scan_page.create_new_scan(scan_name=scan_name, scan_template=Nessus.TemplateNames.ADVANCED,
                                          scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                                          target_ip=Nessus.Scan.Target.LOCALHOST)

                LoadingCircle(WAIT_NORMAL)
                user_data[user_name].update({'scan': scan_name})

                if user_role == API.User.Role.ADMIN:
                    policy_page = PoliciesPage()
                    policy_page.open()

                    policy_name = random_name(prefix="Policy" + "-")
                    policy_page.create_new_policy(policy_name=policy_name, template_name=Nessus.TemplateNames.ADVANCED)

                    user_data[user_name].update({'policy': policy_name})

                elif user_role == API.User.Role.STANDARD:
                    plugin_rule = PluginRulesPage()
                    plugin_rule.open()

                    plugin_id = random.randint(10000, 20000)
                    plugin_rule.add_new_plugin_rule(plugin_id=plugin_id, severity=Nessus.Scan.Severity.CRITICAL)

                    user_data[user_name].update({'plugin': plugin_id})
            else:
                imported_scan = scan_page.import_scan_file(file_name='Basic_Network_Scan_Result.db', password='nessus',
                                                           scan_file_path='nessus/tests/ui/scans/test_data/')
                user_data[user_name].update({'scan': imported_scan})

            user_menu.logout()
            wait(lambda: login_page.is_element_present('username_field'), timeout_seconds=TIME_THIRTY_SECONDS)

        yield user_data

    finally:
        side_nav = SideNav()
        scan_list = ScanList()
        policy_list = PolicyList()
        plugin_rule_list = PluginRulesList()

        for user in create_users.keys():
            side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
            scan_list.loaded()

            user_name = create_users.get(user).get('user_name')
            scan_name = user_data.get(user_name).get('scan')

            scan_list.delete_scan(scan_name=scan_name)
            ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

            if user[:5] == API.User.Role.ADMIN:
                side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.POLICIES).click()
                policy_list.loaded()
                policy_list.delete_policy(policy_name=user_data.get(user_name).get('policy'))

            elif user == API.User.Role.STANDARD:
                side_nav.get_sidenav_element(element_name=Nessus.SideNavResources.PLUGIN_RULES).click()
                plugin_rule_list.loaded()
                plugin_rule_list.delete_plugin_rule(plugin_id=str(user_data.get(user_name).get('plugin')))


@pytest.fixture()
def delete_all_scans_in_nessus():
    """This fixture will delete all scans in Nessus using API before the testcase starts"""
    nessus_api = NessusAPI()
    nessus_api.login()
    scans = nessus_api.scans.get_scans()

    if 'scans' in scans and scans['scans'] is not None:
        wait_required = False

        for scan in scans['scans']:
            if scan['status'] in [API.Scan.Status.RUNNING, API.Scan.Status.PAUSED]:
                log.info(msg='Stopping scan %d' % scan['id'])
                nessus_api.scans.stop(scan['id'])
                wait_required = True

        if wait_required:
            sleep(sleep_time=TIME_THIRTY_SECONDS * 2, reason='for scans to stop.')

        for scan in scans['scans']:
            log.info(msg='Deleting scan %d' % scan['id'])
            try:
                nessus_api.scans.delete(scan['id'])
            except HTTPError:
                log.warning("Unable to delete the scan having ID : {} ".format(scan['id']))

    nessus_api.logout()


@pytest.fixture()
def create_cluster_group(request: 'SubRequest'):
    """This fixture will create a cluster group in sensor manager."""
    cluster_group_name = request.param['cluster_group_name'] if \
        hasattr(request, 'param') and 'cluster_group_name' in request.param else random_name(prefix='cluster-group-')

    cluster_group = ClusterGroupPage()
    cluster_group.open()

    cluster_group.new_group_button.click()
    cluster_group.group_name_field.value = cluster_group_name
    cluster_group.add_button.click()
    wait(lambda: ClusterGroupDetails().is_element_present('add_node_button'))

    yield cluster_group_name

    try:
        cluster_group.open()
        cluster_group_list = ClusterGroupList()
        cluster_group_list.loaded()

        if cluster_group_name in cluster_group_list.get_all_group_names():
            cluster_group_list.delete_cluster_group(group_name=cluster_group_name)
            delete_cluster_group_modal = ActionCloseModal()
            delete_cluster_group_modal.accept_action()
            delete_cluster_group_modal.wait_for_modal_closed()
        else:
            log.warning("Cluster Group - {} not found on list".format(cluster_group_name))
    except(AttributeError, NoSuchElementException, StaleElementReferenceException, TimeoutExpired):
        log.warning("Unable to delete cluster group in cleanup")


@pytest.fixture()
def update_software(request: 'SubRequest'):
    """This fixture will select update choice and and wait till nessus gets ready."""
    update_choice = request.param.get('update_choice')
    scanner_type = request.param.get('scanner_type')
    api = NessusAPI()

    with polling_ui():
        try:
            wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                    msg="waiting for Nessus to get 'loading' status")
        except TimeoutExpired:
            log.warning("Nessus did not get 'loading' status after starting the service")

        wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_TEN_MINUTES * 3,
                                msg='registration to complete.')

    update_software_and_wait_for_nessus_to_be_ready(update_choice=update_choice, scanner_type=scanner_type)
    version_details = get_nessus_version_details()

    yield {'update_choice': update_choice, 'original_nessus_version': version_details['nessus_ui_version'],
           'original_nessus_build': version_details['nessus_ui_build']}


@pytest.fixture(scope='class')
def disable_signature_verification():
    """Disable signature verification by setting secure fix parameter feed_no_sig as 'yes'."""
    fix.set(key="feed_no_sig", value="yes", secure=True)

    stop_nessus()
    start_nessus()

    api = NessusAPI()
    wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Wait for loading')
    wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_TEN_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')


@pytest.fixture(scope='class')
def enable_auto_update():
    """Enable software update by setting fix parameter auto_update to 'yes'."""
    fix.set(key="auto_update", value="yes")

    with SSH() as ssh:
        if get_os_name() == OperatingSystems.LINUX:
            stop_nessus()
            start_nessus()
        else:
            ssh.execute(command='sc stop "Tenable Nessus"')
            ssh.execute(command='sc start "Tenable Nessus"')

    api = NessusAPI()
    wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Wait for loading')
    wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')


@pytest.fixture()
def configure_agent_settings_options(request: 'SubRequest'):
    """ This fixture will enable given agent settings option in Agent's setting page"""
    setting_options_list = request.param['setting_options_list']

    agent_bw_setting_page = AgentBlackoutWindowSettingsPage()
    agent_bw_setting_page.enable_or_disable_agent_settings(option_list=setting_options_list)

    yield

    for setting in setting_options_list:
        setting['setting_action'] = "disable"

    agent_bw_setting_page.enable_or_disable_agent_settings(option_list=setting_options_list)


@pytest.fixture()
def create_packet_capture_scan(request: 'SubRequest', nessus_api_handler: NessusAPI) -> str:
    """
    Fixture to create a scan with "Packet Capture" setting enabled

    e.g.: @pytest.mark.parametrize('create_packet_capture_scan', [
                {"scan_file_path": get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
                "scan_template": 'advanced'}])

    :param request:
        :str scan_file_path : scan file path
        :str scan_template : scan template name

    :param nessus_api_handler: NessusAPI object
    :return: created scan name
    :rtype: str
    """
    try:
        scan_file_path = request.param.get('scan_file_path')
        scan_template = request.param.get('scan_template')
        scan_target = request.param.get('scan_target', "172.26.48.{}".format(randint(1, 24)))

        scan_id, scan_name = create_packet_capture_scan_helper(nessus_api=nessus_api_handler, scan_file=scan_file_path,
                                                               scan_template=scan_template, scan_target=scan_target)

        yield scan_id, scan_name, scan_target
    finally:
        try:
            nessus_api_handler.scans.delete(scan_id=scan_id)

            if not get_driver_no_init().current_url.endswith("/settings/logs"):
                debug_logs_page = DebugLogsPage()
                debug_logs_page.open()
                wait(lambda: debug_logs_page.is_element_present("search_logs_field"),
                     waiting_for="'Debug Logs' table gets displayed properly")

            expected_file_name = expected_generated_pcap_file_name(api=NessusAPI(), scan_name=scan_name)
            DebugLogsList().delete_pcap_file(file_name=expected_file_name)

            delete_file_from_nessus_directory(file_name=expected_file_name, nessus_dir=get_nessus_log_dir())
        except HTTPError:
            log.warning("Unable to delete packet capture scan in fixture teardown.")


@pytest.fixture()
def import_policy_via_api(request: 'SubRequest'):
    """
    fixture to import a scan file via API
    e.g.: @pytest.mark.parametrize("import_policy_via_api", [
        {"file_name": 'Advanced_all_plugIns_with_compliance.nessus', "file_path": 'nessus/tests/ui/scans/test_data/'}],
                             indirect=True)
    :param request:
        :str file_name : policy file to import
        :str file_path : file path from where to import
    """
    response = None
    policy_file_name = request.param.get('file_name')
    policy_file_path = request.param.get('file_path')

    if not (policy_file_name and policy_file_path):
        log.error("Import not possible as policy filename and/or file path is missing.")
        return

    try:
        file_path = get_file_path(policy_file_path + policy_file_name)

        file_uploaded = request.instance.cat.api.file.upload(file=file_path)
        response = request.instance.cat.api.policies.import_policy(file=file_uploaded)

        assert request.instance.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % request.instance.cat.api.http_status_code

        yield response['name']
    finally:
        if response:
            try:
                request.cls.cat.api.policies.delete(response['id'])
            except HTTPError:
                log.warning("Unable to delete policy in fixture teardown.")


@pytest.fixture()
def create_scan_with_enable_plugin_debugging(request: 'SubRequest', nessus_api_handler: NessusAPI) -> tuple:
    """
    Fixture to create a scan with "Enable plugin debugging" setting

    e.g.: @pytest.mark.parametrize('create_scan_with_enable_plugin_debugging', [
                {"scan_file_path": get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
                "scan_template": 'advanced', "scan_target": "172.26.48.10"}])

    :param request:
        :str scan_file_path : scan file path
        :str scan_template : scan template name

    :param nessus_api_handler: NessusAPI object
    :return: created scan name and id
    :rtype: tuple
    """
    try:
        scan_target = request.param.get('scan_target', Nessus.Scan.Target.PUB_TARGET_4)
        payload = load_testdata(request.param.get('scan_file_path'))

        scan_details_dict = {"enable_plugin_debugging": "yes", "text_targets": scan_target,
                             "name": random_name(prefix='Automated-Scan-')}

        payload.get('settings').update(scan_details_dict)
        scan_details = create_scan_helper(nessus_api_handler, file_name="", payload=payload,
                                          template_title=request.param.get('scan_template'))

        scan_id = scan_details[0]['scan']['id']

        yield scan_id, scan_details[0]['scan']['name'], scan_target
    finally:
        try:
            nessus_api_handler.scans.delete(scan_id=scan_id)
        except HTTPError:
            log.warning("Unable to delete packet capture scan in fixture teardown.")


@pytest.fixture()
def delete_all_custom_folders() -> None:
    """ This fixture will delete all custom folders in Nessus using API before the testcase starts """
    nessus_api = NessusAPI()
    nessus_api.login()
    custom_folders = nessus_api.folders.get_folders()

    if 'folders' in custom_folders and custom_folders['folders'] is not None:
        for folder in custom_folders['folders']:
            try:
                nessus_api.folders.delete(folder_id=folder['id'])
            except HTTPError:
                log.warning("Unable to delete custom folder having ID : {} ".format(folder['id']))

    nessus_api.logout()


@pytest.fixture()
def empty_trash_and_create_or_import_bulk_scan(request: 'SubRequest', create_new_folder):
    """
    Empty trash folder and create or import bulk scans (by default import scan will be done)
    """
    # Deletes all scans from trash folder and imports bulk scans
    empty_trash_folder()

    scan_count = request.param['scan_count']
    import_scan = request.param['import_scan'] if hasattr(request, 'param') and 'import_scan' in request.param else True
    response = None
    responses = []

    nessus_api = NessusAPI()
    nessus_api.login()

    try:
        folder_detail = create_new_folder
        log.info('Folder created successfully.')

        scans_details = {'name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
                         'text_targets': 'localhost', 'folder_id': folder_detail[0]}
        scan_name = scans_details['name']

        if import_scan:
            scan_file = get_file_path('nessus/tests/ui/scans/test_data/' + 'Test_Advanced_Scan_NES-8592.nessus')
            file_uploaded = nessus_api.file.upload(file=scan_file)

        for count in range(scan_count):
            if import_scan:
                response = nessus_api.scans.import_scan(file_uploaded, folder_id=folder_detail[0])
            else:
                scans_details['name'] += " - " + str(count)
                scan_model = ScanModel(**scans_details)
                responses.append(nessus_api.scans.create(model=scan_model))
                scans_details['name'] = scan_name

        log.info('Scans created successfully.')
        scan_page = ScansPage()
        scan_page.refresh()

        SideNav().get_sidenav_element(element_name=folder_detail[1]).click()
        ScanList().loaded()

        if import_scan:
            yield response['scan']['name'], folder_detail
        else:
            yield [response['scan']['name'] for response in responses], scan_count, folder_detail

    finally:
        scan_ids = [scan['id'] for scan in nessus_api.scans.get_scans()['scans']]
        [nessus_api.scans.stop(scan_id=scan_id) for scan_id in scan_ids if nessus_api.scans.get_status(
            scan_id=scan_id) == API.Scan.Status.RUNNING]
        sleep(TIME_TWO_MINUTES, reason="waiting for scans to get stopped")

        if scan_ids:
            nessus_api.scans.delete_bulk_scans(id_list=scan_ids)
        else:
            log.debug("Did not get any Scans. May be, It was deleted from test side.")

        nessus_api.logout()
        empty_trash_folder()


@pytest.fixture()
def import_bulk_scan(request: 'SubRequest', create_new_folder):
    """
    Empty trash folder and create or import bulk scans (by default import scan will be done)
    """
    # Deletes all scans from trash folder and imports bulk scans

    scan_count = request.param['scan_count']
    import_scan = request.param['import_scan'] if hasattr(request, 'param') and 'import_scan' in request.param else True
    response = None
    responses = []

    nessus_api = NessusAPI()
    nessus_api.login()

    try:
        folder_detail = create_new_folder
        log.info('Folder created successfully.')

        scans_details = {'name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
                         'text_targets': 'localhost', 'folder_id': folder_detail[0]}
        scan_name = scans_details['name']

        if import_scan:
            scan_file = get_file_path('nessus/tests/ui/scans/test_data/' + 'Test_Advanced_Scan_NES-8592.nessus')
            file_uploaded = nessus_api.file.upload(file=scan_file)

        for count in range(scan_count):
            if import_scan:
                response = nessus_api.scans.import_scan(file_uploaded, folder_id=folder_detail[0])
            else:
                scans_details['name'] += " - " + str(count)
                scan_model = ScanModel(**scans_details)
                responses.append(nessus_api.scans.create(model=scan_model))
                scans_details['name'] = scan_name

        log.info('Scans created successfully.')
        scan_page = ScansPage()
        scan_page.refresh()

        SideNav().get_sidenav_element(element_name=folder_detail[1]).click()
        ScanList().loaded()

        if import_scan:
            yield response['scan']['name'], folder_detail
        else:
            yield [response['scan']['name'] for response in responses], scan_count, folder_detail

    finally:
        scan_ids = [scan['id'] for scan in nessus_api.scans.get_scans()['scans']]
        [nessus_api.scans.stop(scan_id=scan_id) for scan_id in scan_ids if nessus_api.scans.get_status(
            scan_id=scan_id) == API.Scan.Status.RUNNING]
        sleep(TIME_TWO_MINUTES, reason="waiting for scans to get stopped")

        if scan_ids:
            nessus_api.scans.delete_bulk_scans(id_list=scan_ids)
        else:
            log.debug("Did not get any Scans. May be, It was deleted from test side.")

        nessus_api.logout()
        empty_trash_folder()
