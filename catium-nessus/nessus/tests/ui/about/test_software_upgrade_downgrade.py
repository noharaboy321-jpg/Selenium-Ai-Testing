"""
Nessus software upgrade/downgrade related test cases

:copyright: Tenable Network Security, 2017
:creation date: Jan 21, 2020
:last_modified: Feb 21, 2022
:author: @vsoni.ctr, @kpanchal.ctr
"""
import datetime
from uuid import uuid4

import pytest
from packaging.version import parse
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located
from waiting import wait as waiting_wait, TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.activation_code_generator.activation_code_generator import ActivationCodeGenerator
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS, TIME_FIVE_MINUTES, TIME_FIFTEEN_MINUTES, \
    TIME_FIVE_SECONDS, TIME_TEN_MINUTES, HOST_PLUGIN_FEED_STAGING, TIME_TEN_SECONDS, TIME_THIRTY_MINUTES, \
    TIME_NINETY_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.license import remove_nessus_registration
from nessus.helpers.nessus_link_to_tio import add_tenable_io_container
from nessus.helpers.nessus_ui.settings import modify_existing_advanced_setting, handle_connection_popup, \
    login_helper_after_server_restart
from nessus.helpers.nessuscli import users
from nessus.helpers.nessuscli.helper import get_nessus_cli, get_system_datetime, stop_nessus, start_nessus, \
    register_nessus_license_type
from nessus.helpers.nessuscli.logchecker import verify_log_entry_in_specific_time_range
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.software_update import navigate_to_software_update_tab, \
    update_software_and_wait_for_nessus_to_be_ready, get_nessus_version_details_from_ui, \
    fetch_nessus_version_and_build_for_given_channel, \
    wait_for_nessus_to_be_ready_after_software_update, replace_feed_files, is_downgrade_build, \
    verify_nessus_build_details_after_upgrade_downgrade
from nessus.helpers.system import is_pro, is_home
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.config import NessusConfig
from nessus.lib.config.environment_variables import NESSUS_LOGS_DIR
from nessus.lib.const import Nessus, API, NessusCli
from nessus.lib.const.constants import NessusFilePath
from nessus.pageobjects.about.about_page import SoftwareUpdate, About, OverView
from nessus.pageobjects.advanced_settings.advanced_settings_page import AdvancedSettingsPage, AdvancedSettingsList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, close_pendo_guide_container_banner_for_nessus_pro
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList, PoliciesPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanHistoryList
from nessus.pageobjects.scans.scans_page import ScanList
from nessus.pageobjects.sidenav.sidenav import SideNav
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI

log = create_logger()


@pytest.fixture(scope='class')
def set_custom_feed():
    """This fixture will set up plugins-internal-staging.cloud.aws.tenablesecurity.com as custom host in Nessus Pro"""
    with SSH() as ssh:
        ssh.execute('{} fix --secure --set custom_host="{}"'.format(
            get_nessus_cli(), Nessus.Scan.Target.STAGING_FEED_SERVER_HOST))

    stop_nessus()
    start_nessus()

    api = NessusAPI()
    wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Wait for loading')
    wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES,
                            sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')


def verify_user_data_preserved_after_updating_nessus(setting_name: str, setting_value: str, created_scan: str,
                                                     created_policy: str, history_count: int) -> None:
    """
    Verifies user data like advanced setting, created scan and created policy after updating Nessus.

    :param str setting_name: advanced setting name
    :param str setting_value: advanced setting value
    :param str created_scan: created scan name
    :param str created_policy: created policy name
    :param int history_count: scan history raw count
    :return: None
    """
    advanced_setting = AdvancedSettingsPage()
    advanced_setting.open()
    advanced_setting_list = AdvancedSettingsList()
    wait(lambda: advanced_setting_list.is_element_present("user_interface_tab"),
         waiting_for="User Interface tab to be visible")

    advanced_setting.get_settings_tab_element(setting_tab=Nessus.AdvancedSettings.CUSTOM_TAB).click()
    all_advanced_settings = advanced_setting_list.get_all_settings_name()
    log.info('Added advanced setting after updating nessus :: {}'.format(setting_name))

    # Verifies advanced setting gets preserved after updating the Nessus.
    assert setting_name in all_advanced_settings and setting_value == advanced_setting_list. \
        get_specific_setting_value(setting_name=setting_name).text, \
        'Advanced setting is missing or not get preserved after updating the Nessus.'

    HeaderBasePage().scan_link.click()
    scan_list = ScanList()
    scan_list.loaded()
    all_scans_list = scan_list.get_all_scans()
    log.info('List of all preserved scans after updating nessus :: {}'.format(all_scans_list))

    # Verifies created scan gets preserved after updating the Nessus.
    assert created_scan in all_scans_list, 'Created scan is missing or not get preserved after updating the Nessus.'

    scan_list.click_on_scan(scan_name=created_scan)
    scan_result_page = ScanViewPage()
    wait(lambda: visibility_of_element_located(scan_result_page.history_tab), waiting_for='Scan results page to load')
    scan_result_page.history_tab.click()

    # Verifies created scan result history gets preserved after updating the Nessus.
    assert scan_result_page.total_records_count == len(ScanHistoryList().rows) == history_count, \
        "Created scan result history is missing or not get preserved after updating the Nessus."

    SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
    policies_list = PolicyList()
    all_policy_list = policies_list.get_all_policies()
    log.info('List of all preserved policies after updating nessus :: {}'.format(all_policy_list))

    # Verifies created policy gets preserved after updating the Nessus.
    assert created_policy in policies_list.get_all_policies(), \
        'Created policy is missing or not get preserved after updating the Nessus.'


def launch_scan_and_navigate_to_software_update_tab(scan_name: str, scanner_type: str, nessus_version: str) -> tuple:
    """
    Launch created scan and navigation to software update tab to get selected choice option

    :param str scan_name: created scan name
    :param str scanner_type: scanner type like managed or licensed
    :param str nessus_version: Nessus version
    :return: scan result history count and selected choice option
    :rtype: tuple
    """
    wait(lambda: SideNav().is_element_present('scan_tab_on_header'), waiting_for="My scans page to get loaded.")
    SideNav().scan_tab_on_header.click()
    wait(lambda: SideNav().is_element_present('search_textbox'), waiting_for="My scans page to get loaded.")
    SideNav().my_scan_tab.click()
    wait(lambda: SideNav().is_element_present('search_textbox'), waiting_for="My scans page to get loaded.")
    scan_list = ScanList()
    scan_list.loaded()
    log.info('Launch scan and wait for to be ready...')
    scan_list.launch_scan_and_wait_for_status(scan_name=scan_name)

    scan_list.click_on_scan(scan_name=scan_name)
    scan_result_page = ScanViewPage()
    scan_result_page.history_tab.click()

    before_history_count = scan_result_page.total_records_count

    navigate_to_software_update_tab()
    locator_value = "Nessus Version Update" if parse(nessus_version) > parse(
        "10.2.0") else "Version Update"
    selected_option = SoftwareUpdate().get_selected_software_update_choice(locator_value=locator_value)

    return before_history_count, selected_option


def verify_nessus_build_details_and_preserved_scans_after_updating(
        original_nessus_version: str, original_nessus_build: str, updated_nessus_version: str,
        updated_nessus_build: str, expected_nessus_version: str, expected_nessus_build: str, choice_option: str,
        nessus_details: dict, created_scans_list: list) -> None:
    """
    Verify nessus version, build number and preserved scan data after updating Nessus

    :param original_nessus_version: Nessus version before updating
    :param original_nessus_build: Nessus build number before updating
    :param updated_nessus_version: Nessus version after updating
    :param updated_nessus_build: Nessus build number after updating
    :param expected_nessus_version: Expected nessus version after updating
    :param expected_nessus_build: Expected nessus build number after updating
    :param choice_option: Update choice option e.g. EA/GA/Stable
    :param nessus_details: Nessus version details
    :param created_scans_list: Created scans list before updating nessus
    :return: None
    """
    verify_nessus_build_details_after_upgrade_downgrade(
        original_nessus_version=original_nessus_version, original_nessus_build=original_nessus_build,
        updated_nessus_version=updated_nessus_version, updated_nessus_build=updated_nessus_build,
        expected_nessus_version=expected_nessus_version, expected_nessus_build=expected_nessus_build,
        choice_option=choice_option, nessus_details=nessus_details)

    all_scans_list = ScanList().get_all_scans()
    log.info('List of all preserved scans after updating nessus :: {}'.format(all_scans_list))

    assert all([scan in all_scans_list for scan in created_scans_list]), \
        'Nessus does not preserved created scan data after updating via software update channel.'


@pytest.mark.managed_channel_update
@pytest.mark.usefixtures('link_scanner', 'login')
class TestSoftwareUpgradeDowngradeOptionsForManagedScanner:
    cat = None

    def test_visibility_of_software_update_tab_contents_for_managed_scanner(self):
        """
        NES-10776 - Nessus Update Channel UI Automation

        Scenario Tested:
            [x] Verify Software Update tab contents for managed scanner

        Steps:
        1. Link Nessus to tenable.io
        2. Verify that "Software Update" tab appears on About page.
        3. Verify that "Manual Software Update" tab does not appear on "Software Update" tab.
        4. Verify that three update options appear on "Software Update" tab.
        """
        about_page = About()
        about_page.open()
        wait(lambda: about_page.is_element_present("software_update_tab"))

        # Verify that "Software Update" tab appears for managed scanner.
        assert about_page.is_element_present("software_update_tab"), "Software update tab is not visible on About page."

        about_page.software_update_tab.click()
        about_software_update = SoftwareUpdate()
        wait(lambda: about_software_update.is_element_present("update_option_labels"))

        # Wait and verify that update options gets loaded on "Software Update" tab.
        assert about_software_update.is_element_present("update_option_labels"), \
            "Update options are not present on Software Update tab."

        # Verify that "Manual Software Update" tab does not appear
        assert not about_software_update.is_element_present("manual_software_update"), \
            "Manual Software update tab is present for managed scanner."

        update_options = about_software_update.get_software_update_options_for_managed_scanner()

        # Verify the software update options' labels.
        assert update_options == [Nessus.About.SoftwareUpdateChannel.UPDATE_GA_LABEL,
                                  Nessus.About.SoftwareUpdateChannel.UPDATE_EA_LABEL,
                                  Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_LABEL], \
            "Software Update option labels are not as expected."

    def test_verify_default_option_for_software_update_choice(self):
        """
        NES-10776 - Nessus Update Channel UI Automation

        Steps:
        1. Link Nessus to tenable.io
        2. Verify the default update option on "Software Update" tab

        Scenario Tested:
            [x] Verify default update option on "Software Update" tab
        """
        navigate_to_software_update_tab()
        default_update_option = SoftwareUpdate().get_software_update_options_for_managed_scanner()[0]

        # Verify the default selected software update option
        assert "Default" in default_update_option, "Default tag is not present in first software update option."

        assert Nessus.About.SoftwareUpdateChannel.UPDATE_GA_LABEL == default_update_option, \
            "Default option label is not as expected."

    def test_verify_version_update_warning_while_saving_software_update_option(self):
        """
        NES-10776 - Nessus Update Channel UI Automation

        Steps:
        1. Link Nessus to tenable.io
        2. Click on non-default option for software update and see if version update warning pop-up appears.
        3. Verify the version update pop-up title and warning message.
        4. Verify that software update setting not saved when declining version update warning pop-up.

        Scenario Tested:
            [x] Verify version update warning pop-up on "Software Update" tab
        """
        navigate_to_software_update_tab(update_option_to_default=True)
        about_software_update = SoftwareUpdate()
        about_software_update.click_and_save_software_update_option(option=Nessus.About.SoftwareUpdateChannel.
                                                                    UPDATE_EA_OPTION, accept_warning=False)
        version_update_modal = ActionCloseModal()

        # Verify Version update warning pop-up title
        assert version_update_modal.modal_title.text == Nessus.About.SoftwareUpdateChannel. \
            VERSION_UPDATE_WARNING_TITLE, "Version Update Warning title is incorrect."

        # Verify Version update warning pop-up text
        assert version_update_modal.modal_content.text == Nessus.About.SoftwareUpdateChannel. \
            VERSION_UPDATE_WARNING_MESSAGE, "Version Update pop-ip message is incorrect."

        version_update_modal.cancel_button.click()
        version_update_modal.wait_for_modal_closed()
        about_software_update.refresh()
        wait(lambda: about_software_update.is_element_present("update_option_labels"))

        # Verify that software update setting not saved when declining version update warning pop-up.
        assert about_software_update.get_selected_update_option() != Nessus.About.SoftwareUpdateChannel. \
            UPDATE_EA_LABEL, "Software update setting saved even after declining the version update warning pop-up."

    def test_verify_software_update_option_changes_after_saving(self):
        """
        NES-10776 - Nessus Update Channel UI Automation

        Steps:
        1. Link Nessus to tenable.io
        2. Click on different software-update option and save them
        3. Verify that update option gets saved successfully.

        Scenario Tested:
            [x] Verify software-update options saved successfully in "Software Update" tab.
        """
        navigate_to_software_update_tab(update_option_to_default=True)
        about_software_update = SoftwareUpdate()

        try:
            for update_choice in Nessus.About.SoftwareUpdateChannel.UPDATE_CHOICE_DICT.keys():
                about_software_update.click_and_save_software_update_option(option=update_choice)

                # Verify the success notification for saving the setting.
                assert Notifications().successes[-1] == Nessus.About.SoftwareUpdateChannel. \
                    SOFTWARE_UPDATE_SETTING_SAVED_NOTIFICATION, \
                    "Software update setting saved notification is incorrect."

                # Verify that selected option text is same as expected.
                assert about_software_update.get_selected_update_option() == \
                       Nessus.About.SoftwareUpdateChannel.UPDATE_CHOICE_DICT[
                           update_choice], "Software update choice has not been saved."
        finally:
            about_software_update.click_and_save_software_update_option(option=Nessus.About.SoftwareUpdateChannel.
                                                                        UPDATE_GA_OPTION)

    @pytest.mark.parametrize("update_software", [
        {'update_choice': Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION, 'scanner_type': 'managed'},
        {'update_choice': Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION, 'scanner_type': 'managed'},
        {'update_choice': Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION, 'scanner_type': 'managed'}],
                             indirect=True)
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'description': 'Created a {} scan by Automation script.'.format(Nessus.TemplateNames.ADVANCED.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST},
        {'scan_template': Nessus.TemplateNames.WEB_APP, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.WEB_APP)),
         'description': 'Created a {} scan by Automation script.'.format(Nessus.TemplateNames.WEB_APP.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.parametrize("choice_option", [Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION])
    def test_software_upgrade_choice_for_managed_scanner(self, update_software, create_scans, choice_option):
        """
        NES-10900 - Nessus Update Channel UI Automation

        Steps:
        1. Link Nessus to tenable.io
        2. Click on different software-update option and save them
        3. Verify that nessus is getting upgraded/downgraded successfully by verifying the version/build.

        Scenario Tested:
            [x] Verify nessus version/build after upgrade/downgrade by saving given choice option in
                "Software Update" tab.
        """
        nessus_details = update_software

        # Get nessus version and build before updating it
        original_nessus_version = nessus_details['original_nessus_version']
        original_nessus_build = nessus_details['original_nessus_build']
        selected_option = nessus_details['update_choice']

        created_scans_list = create_scans
        log.info('Created scans list before updating Nessus :: {}'.format(created_scans_list))
        log.info('Nessus version before updating :: {}'.format(original_nessus_version))
        log.info('Nessus build before updating :: {}'.format(original_nessus_build))

        start_timestamp = get_system_datetime()
        end_timestamp = start_timestamp + datetime.timedelta(minutes=30)

        # Update nessus with given choice option
        update_software_and_wait_for_nessus_to_be_ready(update_choice=choice_option, scanner_type="managed")

        updated_nessus_version, updated_nessus_build = get_nessus_version_details_from_ui()
        log.info('Nessus version after updating :: {}'.format(updated_nessus_version))
        log.info('Nessus build after updating :: {}'.format(updated_nessus_build))

        if (parse(original_nessus_version) != parse(updated_nessus_version)) and \
                (int(original_nessus_build) != int(updated_nessus_build)):
            expected_log_message = "backend: {}-{}".format(updated_nessus_version, updated_nessus_build)

            assert verify_log_entry_in_specific_time_range(
                log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG, log_entry=expected_log_message,
                end_timestamp=end_timestamp, start_timestamp=start_timestamp), \
                "'{}' log message is either missing or mismatch in 'backend.log' file after upgrading/downgrading " \
                "Nessus.".format(expected_log_message)

        sigsegv_error_message = "SIGSEGV occurred -- trying to dump the current environment"

        with SSH() as ssh:
            assert any([sigsegv_error_message not in log_line for log_line in ssh.execute("cat {}".format(
                NessusFilePath.Linux.NESSUS_BACKEND_LOGS))]), \
                "Scanner crashed while switching Nessus upgrade/downgrade channels and throws SIGSEGV error in " \
                "'backend.log' file."

        update_option_index = {'ea': 2, 'ga': 1, 'stable': 0}

        if choice_option == "stable" and update_option_index[selected_option] > update_option_index[choice_option]:
            expected_downgrade_message = "Success! Downgraded from {} to {}".format(original_nessus_version,
                                                                                    updated_nessus_version)

            try:
                assert verify_log_entry_in_specific_time_range(
                    log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.NESSUSCLI_LOG, log_entry=expected_downgrade_message,
                    end_timestamp=end_timestamp, start_timestamp=start_timestamp), \
                    "'{}' log message is either missing or mismatch in 'nessuscli.log' file after downgrading " \
                    "Nessus.".format(expected_downgrade_message)
            except AssertionError:
                pytest.xfail("It shows version 8.15.2 instead of 8.15.3 due to referring the version from database.")

        # Expected nessus version and build details after updating it
        expected_nessus_version, expected_nessus_build = fetch_nessus_version_and_build_for_given_channel(
            update_channel=choice_option, scanner_type="managed")

        # As downgrading build is not supported, modifying expected build details as original build details.
        if is_downgrade_build(current_version=original_nessus_version, current_build=original_nessus_build,
                              expected_version=expected_nessus_version, expected_build=expected_nessus_build):
            expected_nessus_version = original_nessus_version
            expected_nessus_build = original_nessus_build

        verify_nessus_build_details_and_preserved_scans_after_updating(
            original_nessus_version=original_nessus_version, original_nessus_build=original_nessus_build,
            updated_nessus_version=updated_nessus_version, updated_nessus_build=updated_nessus_build,
            expected_nessus_version=expected_nessus_version, expected_nessus_build=expected_nessus_build,
            choice_option=choice_option, nessus_details=nessus_details, created_scans_list=created_scans_list)

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.WEB_APP, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.WEB_APP)),
         'description': 'Created a {} scan by Automation script.'.format(Nessus.TemplateNames.WEB_APP.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.parametrize('add_advanced_setting', [{"name": random_name(prefix="{} - ".format("xmlrpc_")),
                                                       "value": "test"}], indirect=True)
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    @pytest.mark.parametrize("choice_option", [Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION])
    def test_user_data_preserved_after_software_upgrade_downgrade_for_managed_scanner(
            self, create_scans, add_advanced_setting, create_policy, choice_option):
        """
        NES-11007: Automate software upgrade/downgrade tests to verify the user data like policy, custom advanced
                   setting and scan history is preserved after Nessus update.

        Steps:
        1. Link Nessus to tenable.io
        2. Click on different software-update option and save them
        3. Verify that user's data should be preserved after getting upgraded/downgraded the Nessus.

        Scenario Tested:
            [x] Verify user's data like advanced setting, created scan and created policy after upgrading/downgrading
                the nessus by saving given choice option in "Software Update" tab.
        """
        # Get nessus version and build before updating it
        setting_name, setting_value = add_advanced_setting
        log.info('Added advanced setting before updating nessus :: {}'.format(setting_name))

        created_scan = create_scans[0]
        log.info('Created scan before updating Nessus :: {}'.format(created_scan))

        created_policy = create_policy
        NewPolicyForm().save_button.click()
        wait(lambda: PoliciesPage().is_element_present("policies_searchbox"))
        log.info('Created new policy before updating nessus :: {}'.format(created_policy))

        # Launch created scan to get history and navigate to software update tab to get choice option
        original_nessus_version, original_nessus_build = get_nessus_version_details_from_ui()
        before_history_count, selected_option = launch_scan_and_navigate_to_software_update_tab(
            scan_name=created_scan, scanner_type="managed", nessus_version=original_nessus_version)

        # Get Nessus version and build number before updating
        log.info('Nessus version before updating :: {}'.format(original_nessus_version))
        log.info('Nessus build before updating :: {}'.format(original_nessus_build))

        # Update nessus with given choice option
        log.info('Update Nessus from "{}" to "{}"'.format(selected_option, choice_option))
        update_software_and_wait_for_nessus_to_be_ready(update_choice=choice_option, scanner_type="managed")

        # Get Nessus version and build number after updating
        updated_nessus_version, updated_nessus_build = get_nessus_version_details_from_ui()
        log.info('Nessus version after updating :: {}'.format(updated_nessus_version))
        log.info('Nessus build after updating :: {}'.format(updated_nessus_build))

        verify_user_data_preserved_after_updating_nessus(setting_name=setting_name, setting_value=setting_value,
                                                         created_scan=created_scan, created_policy=created_policy,
                                                         history_count=before_history_count)

    @pytest.mark.parametrize('advanced_setting_details', [
        {'setting_tab': Nessus.AdvancedSettings.LOGGING_TAB, 'setting_name': Nessus.AdvancedSettings.NESSUS_LOG_LEVEL,
         'setting_value': Nessus.AdvancedSettings.NORMAL},
        {'setting_tab': Nessus.AdvancedSettings.LOGGING_TAB, 'setting_name': Nessus.AdvancedSettings.NESSUS_LOG_LEVEL,
         'setting_value': Nessus.AdvancedSettings.DEBUG},
        {'setting_tab': Nessus.AdvancedSettings.LOGGING_TAB, 'setting_name': Nessus.AdvancedSettings.NESSUS_LOG_LEVEL,
         'setting_value': Nessus.AdvancedSettings.VERBOSE}])
    def test_backend_log_level_after_upgrade_downgrade_for_managed_scanner(self, advanced_setting_details):
        """
        NES-11634: Automation: verify backend log after channel change

        Scenario Tested:
            [x] Verify that correct logs are displayed in backend.log(debug level) when Nessus is updated to each
                channel (GA, EA, Stable)
        """
        scanner_type = "managed"
        log_level_list = []

        log.info("Setting backend.log level to :: '{}'".format(advanced_setting_details['setting_value']))
        modify_existing_advanced_setting(setting_tab=advanced_setting_details['setting_tab'],
                                         setting_name=advanced_setting_details['setting_name'],
                                         setting_value=advanced_setting_details['setting_value'])

        upgrade_downgrade_channel_options = [Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                             Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                             Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION]

        for choice_option in upgrade_downgrade_channel_options:
            original_nessus_version, original_nessus_build = get_nessus_version_details_from_ui()

            # Get nessus version and build before updating it
            navigate_to_software_update_tab()
            locator_value = "Nessus Version Update" if parse(original_nessus_version) > parse(
                "10.2.0") or scanner_type == "licensed" else "Version Update"
            selected_option = SoftwareUpdate().get_selected_software_update_choice(locator_value=locator_value)

            if choice_option != selected_option:

                log.info('Nessus version before updating :: {}'.format(original_nessus_version))
                log.info('Nessus build before updating :: {}'.format(original_nessus_build))

                # Update nessus with given choice option
                log.info('Update Nessus from "{}" to "{}"'.format(selected_option, choice_option))
                update_software_and_wait_for_nessus_to_be_ready(update_choice=choice_option, scanner_type="managed")
                handle_connection_popup(timeout_to_appear=TIME_FIVE_MINUTES, timeout_to_disappear=TIME_TEN_MINUTES)

                updated_nessus_version, updated_nessus_build = get_nessus_version_details_from_ui()
                log.info('Nessus version after updating :: {}'.format(updated_nessus_version))
                log.info('Nessus build after updating :: {}'.format(updated_nessus_build))

                backend_log = SSH().execute("cat {}".format(NessusFilePath.Linux.NESSUS_BACKEND_LOGS))

                # Printing backend.log file for debug purpose
                log.debug("Printing backend.log file")
                for output in backend_log:
                    log.debug(output)

                for log_line in backend_log:
                    # Append log_line if it is in standard format (i.e. starts with timestamp followed by log_level)
                    if len(log_line.split('] ')) > 1:
                        log_level = log_line.split('] ')[1].lstrip('[')
                        log_level_list.append(log_level)

                log.info('Log levels from "backend.log" file after setting "{}" log level:: {}'.format(
                    advanced_setting_details['setting_value'], log_level_list))

                required_log_levels = {Nessus.AdvancedSettings.NORMAL: [Nessus.AdvancedSettings.INFO],
                                       Nessus.AdvancedSettings.DEBUG: [Nessus.AdvancedSettings.INFO,
                                                                       Nessus.AdvancedSettings.DEBUG],
                                       Nessus.AdvancedSettings.VERBOSE: [Nessus.AdvancedSettings.INFO,
                                                                         Nessus.AdvancedSettings.DEBUG,
                                                                         Nessus.AdvancedSettings.VERBOSE]}

                # Verify the nessus log level from 'backend.log' file
                assert all([level in log_level_list for level in required_log_levels.get(
                    advanced_setting_details['setting_value'])]), \
                    'Nessus backend log level is not same as expected. Expected log level should be \'{}\''.format(
                        advanced_setting_details['setting_value'])

                wait_for_scanner_status(api=NessusAPI(), status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES,
                                        sleep_interval=TIME_FIVE_SECONDS, msg='waiting for Nessus to be ready...')


@pytest.mark.nessus_settings_1
@pytest.mark.nessus_pro
@pytest.mark.feed_channel_update
@pytest.mark.usefixtures('disable_signature_verification', 'set_custom_feed', 'enable_auto_update', 'login')
class TestSoftwareUpgradeDowngradeOptionsForNessusPro:
    """Testcases for Software Update choice for Nessus Pro"""

    @pytest.mark.skip(reason="as per new upgrade flow, build always updates to Nessus 10.5.0 build 1161. so skipping for now ")
    @pytest.mark.parametrize("update_software", [
        {'update_choice': Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION, 'scanner_type': 'licensed'},
        {'update_choice': Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION, 'scanner_type': 'licensed'},
        {'update_choice': Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION, 'scanner_type': 'licensed'}],
                             indirect=True)
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.ADVANCED, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'description': 'Created a {} scan by Automation script.'.format(Nessus.TemplateNames.ADVANCED.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST},
        {'scan_template': Nessus.TemplateNames.WEB_APP, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix='{} - '.format(Nessus.TemplateNames.WEB_APP)),
         'description': 'Created a {} scan by Automation script.'.format(Nessus.TemplateNames.WEB_APP.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.parametrize("choice_option", [Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION])
    def test_software_upgrade_choice_for_nessus_pro(self, update_software, create_scans, choice_option):
        """
        NES-10957 - Nessus Update Channel UI Automation

        Steps:
        1. Click on different software-update option and save them
        2. Verify that nessus is getting upgraded/downgraded successfully by verifying the version/build.

        Scenario Tested:
            [x] Verify nessus version/build after upgrade/downgrade by saving given choice option in
                "Software Update" tab.
        """
        initial_keyword_to_search = ""
        nessus_details = update_software

        # Get nessus version and build before updating it
        original_nessus_version = nessus_details['original_nessus_version']
        original_nessus_build = nessus_details['original_nessus_build']
        selected_option = nessus_details['update_choice']

        created_scans_list = create_scans
        log.info('Created scans list before updating Nessus :: {}'.format(created_scans_list))
        log.info('Nessus version before updating :: {}'.format(original_nessus_version))
        log.info('Nessus build before updating :: {}'.format(original_nessus_build))

        start_timestamp = get_system_datetime()
        end_timestamp = start_timestamp + datetime.timedelta(minutes=30)

        # Update nessus with given choice option
        update_software_and_wait_for_nessus_to_be_ready(update_choice=choice_option, scanner_type="licensed")

        updated_nessus_version, updated_nessus_build = get_nessus_version_details_from_ui()
        log.info('Nessus version after updating :: {}'.format(updated_nessus_version))
        log.info('Nessus build after updating :: {}'.format(updated_nessus_build))

        if (parse(original_nessus_version) != parse(updated_nessus_version)) and \
                (int(original_nessus_build) != int(updated_nessus_build)):
            update_option_index = {'ea': 2, 'ga': 1, 'stable': 0}

            initial_keyword_to_search = "downgrade" if update_option_index[selected_option] > update_option_index[
                choice_option] else "upgrade"
            expected_keyword = "upgrade" if selected_option == 'stable' else initial_keyword_to_search

            expected_log_message = "Considering {} from Nessus {} build {} to Nessus {} build {}".format(
                expected_keyword, original_nessus_version, original_nessus_build, updated_nessus_version,
                updated_nessus_build)

            assert verify_log_entry_in_specific_time_range(
                log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.BACKEND_LOG, log_entry=expected_log_message,
                end_timestamp=end_timestamp, start_timestamp=start_timestamp), \
                "'{}' log message is either missing or mismatch in 'backend.log' file after upgrading/downgrading " \
                "Nessus.".format(expected_log_message)

        sigsegv_error_message = "SIGSEGV occurred -- trying to dump the current environment"

        with SSH() as ssh:
            assert any([sigsegv_error_message not in log_line for log_line in ssh.execute("cat {}".format(
                NessusFilePath.Linux.NESSUS_BACKEND_LOGS))]), \
                "Scanner crashed while switching Nessus upgrade/downgrade channels and throws SIGSEGV error in " \
                "'backend.log' file."

        if initial_keyword_to_search == "downgrade":
            expected_downgrade_message = "Success! Downgraded from {} to {}".format(original_nessus_version,
                                                                                    updated_nessus_version)

            try:
                assert verify_log_entry_in_specific_time_range(
                    log_dir=NESSUS_LOGS_DIR, file_name=NessusCli.NESSUSCLI_LOG, log_entry=expected_downgrade_message,
                    end_timestamp=end_timestamp, start_timestamp=start_timestamp), \
                    "'{}' log message is either missing or mismatch in 'nessuscli.log' file after downgrading " \
                    "Nessus.".format(expected_downgrade_message)
            except AssertionError:
                pytest.xfail("It shows version 8.15.2 instead of 8.15.3 due to referring the version from database.")

        # Expected nessus version and build details after updating it
        expected_nessus_version, expected_nessus_build = fetch_nessus_version_and_build_for_given_channel(
            update_channel=choice_option, scanner_type="licensed")

        # As downgrading build is not supported, modifying expected build details as original build details.
        # If user switches to same channel then nessus version should not get updated.
        if (is_downgrade_build(current_version=original_nessus_version, current_build=original_nessus_build,
                               expected_version=expected_nessus_version, expected_build=expected_nessus_build) or
                nessus_details['update_choice'] == choice_option):
            expected_nessus_version = original_nessus_version
            expected_nessus_build = original_nessus_build

        verify_nessus_build_details_and_preserved_scans_after_updating(
            original_nessus_version=original_nessus_version, original_nessus_build=original_nessus_build,
            updated_nessus_version=updated_nessus_version, updated_nessus_build=updated_nessus_build,
            expected_nessus_version=expected_nessus_version, expected_nessus_build=expected_nessus_build,
            choice_option=choice_option, nessus_details=nessus_details, created_scans_list=created_scans_list)

    @pytest.mark.parametrize("choice_option", [Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION])
    @pytest.mark.parametrize("auto_update_option", ["disable_auto_update", "plugins_only"])
    def test_verify_nessus_update_plan_with_different_auto_update_options(self, choice_option, auto_update_option):
        """
        NES-10988 :Automate testcases to verify no updates using Nessus update plan when automatic updates are disabled.
        NES-11006 :Automate software upgrade/downgrade by clicking on "Manual Software Update" button when
                auto updates are disabled.
        NES-11017 :Verify Nessus Update plan when "plugins-only" option is selected

        Steps:
        1. Select auto update option : ("Disable auto update"/"Plugins only")
        2. Change software update channel and verify that Nessus build and version does not get changed.
        3. Click on "Manual Software Update" button and verify that nessus gets updated as per channel selected.

        Scenario Tested:
            [x] Verify that Nessus build and version does not change when automatic updates are disabled.
            [x] Verify that Nessus build and version does not change when "plugins-only" option is selected
            [x] Verify that Nessus build/version changes by clicking on "Manual Software Update" tab
                even though auto_updates are disabled.
        """
        scanner_type = "licensed"
        software_update = SoftwareUpdate()
        navigate_to_software_update_tab()

        version_details_ui = get_nessus_version_details_from_ui()
        locator_value = "Nessus Version Update" if parse(version_details_ui[0]) > parse(
            "10.2.0") else "Version Update"
        selected_option = software_update.get_selected_software_update_choice(locator_value=locator_value)

        if auto_update_option == "disable_auto_update":
            software_update.disabled.click()
        elif auto_update_option == "plugins_only":
            software_update.update_plugins.click()

        software_update.save_button.click()
        original_nessus_version, original_nessus_build = get_nessus_version_details_from_ui()

        log.info('Nessus version before updating :: {}'.format(original_nessus_version))
        log.info('Nessus build before updating :: {}'.format(original_nessus_build))

        navigate_to_software_update_tab()
        software_update.click_and_save_software_update_option(option=choice_option)

        sleep(TIME_SIXTY_SECONDS, reason="Waiting for Nessus to be ready after software channel option got changed.")
        current_nessus_version, current_nessus_build = get_nessus_version_details_from_ui()

        # Verify that Nessus version and build does not change when automatic updates are disabled.
        assert original_nessus_build == current_nessus_build, \
            "Nessus build updated even though automatic updates are disabled."

        assert original_nessus_version == current_nessus_version, \
            "Nessus version updated even though automatic updates are disabled,"

        if auto_update_option == "disable_auto_update":
            software_update.manual_software_update.click()
            manual_update_modal = ActionCloseModal()
            manual_update_modal.accept_action()
            manual_update_modal.wait_for_modal_closed()

            check_loading = \
                fetch_nessus_version_and_build_for_given_channel(update_channel=selected_option,
                                                                 scanner_type="licensed") != \
                fetch_nessus_version_and_build_for_given_channel(update_channel=choice_option, scanner_type="licensed")

            wait_for_nessus_to_be_ready_after_software_update(check_loading)

            # Expected nessus version and build details after updating it
            expected_nessus_version, expected_nessus_build = fetch_nessus_version_and_build_for_given_channel(
                update_channel=choice_option, scanner_type="licensed")

            # As downgrading build is not supported, modifying expected build details as original build details.
            if is_downgrade_build(current_version=original_nessus_version, current_build=original_nessus_build,
                                  expected_version=expected_nessus_version, expected_build=expected_nessus_build):
                expected_nessus_version = original_nessus_version
                expected_nessus_build = original_nessus_build

            updated_nessus_version, updated_nessus_build = get_nessus_version_details_from_ui()
            log.info('Nessus version after updating :: {}'.format(updated_nessus_version))
            log.info('Nessus build after updating :: {}'.format(updated_nessus_build))

            # Verify that Nessus version and build changes when user clicks on "Manual Software Update" tab.
            assert expected_nessus_build == updated_nessus_build, \
                "Nessus build updated even though automatic updates are disabled."

            assert expected_nessus_version == updated_nessus_version, \
                "Nessus version updated even though automatic updates are disabled,"

    @pytest.mark.skip(reason="Fetching feed files from plugins-internal-staging.cloud.aws.tenablesecurity.com so skipping the testcase for now")
    @pytest.mark.parametrize("feed_details",
                             [{"original_channel": "ea", "new_feed_files_folder": "nightly-release"},
                              {"original_channel": "ga", "new_feed_files_folder": "nightly-release"},
                              {"original_channel": "ga", "new_feed_files_folder": "nightly-release-next"},
                              {"original_channel": "stable", "new_feed_files_folder": "nightly-release"},
                              {"original_channel": "stable", "new_feed_files_folder": "nightly-release-next"}])
    def test_verify_nessus_version_and_build_after_updating_feed_files(self, feed_details):
        """
        NES-10932 - Automate Nessus upgrade/downgrade testcases when feed files updated in particular channel

        Steps:
        1. Select software update channel (GA/EA/Stable).
        2. Change the feed files for the selected channel.
        3. Verify that Nessus version and build updated as per the feed files updated.
        Scenario Tested:

            [x] Verify Nessus Version/Build when feed files get updated for particular channel.
        """
        navigate_to_software_update_tab()

        # Updating Nessus to the original feed for particular channel.
        update_software_and_wait_for_nessus_to_be_ready(update_choice=feed_details['original_channel'],
                                                        scanner_type="licensed", manual_update=True)
        navigate_to_software_update_tab()
        log.info("Original build details are : {}".format(get_nessus_version_details_from_ui()))

        expected_nessus_version, expected_nessus_build = \
            fetch_nessus_version_and_build_for_given_channel(update_channel=feed_details['new_feed_files_folder'],
                                                             scanner_type="licensed")

        check_loading = \
            fetch_nessus_version_and_build_for_given_channel(update_channel=feed_details['original_channel'],
                                                             scanner_type="licensed") != \
            fetch_nessus_version_and_build_for_given_channel(update_channel=feed_details['new_feed_files_folder'],
                                                             scanner_type="licensed")

        with replace_feed_files(update_choice=feed_details['original_channel'],
                                new_feed_files_folder=feed_details['new_feed_files_folder']):
            SoftwareUpdate().manual_software_update.click()

            manual_update_modal = ActionCloseModal()
            manual_update_modal.accept_action()
            manual_update_modal.wait_for_modal_closed()
            wait_for_nessus_to_be_ready_after_software_update(check_loading)

            updated_nessus_version, updated_nessus_build = get_nessus_version_details_from_ui()
            log.info("Updated build details are : {} - {}".format(updated_nessus_version, updated_nessus_build))

            # Verify Nessus version and build after feed files updated for particular channel.
            assert updated_nessus_version == expected_nessus_version, \
                "Nessus version is not as expected after feed files updated."

            assert updated_nessus_build == expected_nessus_build, \
                "Nessus build is not as expected after feed files updated."

    @pytest.mark.skip(reason="Fetching feed files from plugins-internal-staging.cloud.aws.tenablesecurity.com so skipping the testcase for now")
    @pytest.mark.parametrize("feed_details",
                             [{"select_channel": "ea", "other_channel": "stable",
                               "new_feed_files_folder": "nightly-release"},
                              {"select_channel": "ga", "other_channel": "ea",
                               "new_feed_files_folder": "nightly-release"},
                              {"select_channel": "stable", "other_channel": "ga",
                               "new_feed_files_folder": "nightly-release-next"}])
    def test_verify_no_nessus_update_when_feed_files_modified_at_other_channel(self, feed_details):
        """
        NES-11055 - Automate no Nessus update when feed files updated at channel which is not selected
        Steps:
        1. Select software update channel (GA/EA/Stable).
        2. Change the feed files for other channel than selected channel.
        3. Verify that Nessus version and build does not get updated.
        Scenario Tested:
            [x] Verify no Nessus update when feed files get updated for channel which is not selected.
        """
        navigate_to_software_update_tab()

        # Updating Nessus to the original feed for particular channel.
        update_software_and_wait_for_nessus_to_be_ready(update_choice=feed_details['select_channel'],
                                                        scanner_type="licensed", manual_update=True)

        navigate_to_software_update_tab()
        original_nessus_version, original_nessus_build = get_nessus_version_details_from_ui()
        log.info("Original build details are : {} - {}".format(original_nessus_version, original_nessus_build))

        with replace_feed_files(update_choice=feed_details['other_channel'],
                                new_feed_files_folder=feed_details['new_feed_files_folder']):
            SoftwareUpdate().manual_software_update.click()
            manual_update_modal = ActionCloseModal()
            manual_update_modal.accept_action()
            manual_update_modal.wait_for_modal_closed()

            # There can be plugin update for which Nessus may go in "loading" state.
            sleep(TIME_SIXTY_SECONDS,
                  reason="Waiting for Nessus to be ready after manual software update.")
            # If Nessus went to "loading" state then wait for Nessus to be in "ready" state.
            wait_for_nessus_to_be_ready_after_software_update(check_loading=False)

            updated_nessus_version, updated_nessus_build = get_nessus_version_details_from_ui()
            log.info("Updated build details are : {} - {}".format(updated_nessus_version, updated_nessus_build))

            # Verify Nessus version and build after feed files updated for particular channel.
            assert updated_nessus_version == original_nessus_version, \
                "Nessus version is not as expected after feed files updated."

            assert updated_nessus_build == original_nessus_build, \
                "Nessus build is not as expected after feed files updated."

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {'scan_template': Nessus.TemplateNames.WEB_APP, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'scan_name': random_name(prefix="{} - ".format(Nessus.TemplateNames.WEB_APP)),
         'description': 'Created a {} scan by Automation script.'.format(Nessus.TemplateNames.WEB_APP.lower()),
         'target_ip': Nessus.Scan.Target.LOCALHOST}]}], indirect=True)
    @pytest.mark.parametrize('add_advanced_setting', [{"name": random_name(prefix="{} - ".format("xmlrpc_")),
                                                       "value": "test"}], indirect=True)
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    @pytest.mark.parametrize("choice_option", [Nessus.About.SoftwareUpdateChannel.UPDATE_EA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION,
                                               Nessus.About.SoftwareUpdateChannel.STABLE_VERSION_OPTION])
    def test_user_data_preserved_after_software_upgrade_downgrade_for_nessus_pro(
            self, create_scans, add_advanced_setting, create_policy, choice_option):
        """
        NES-11007: Automate software upgrade/downgrade tests to verify the user data like policy, custom advanced
                   setting and scan history is preserved after Nessus update.

        Steps:
        1. Link Nessus to tenable.io
        2. Click on different software-update option and save them
        3. Verify that user's data should be preserved after getting upgraded/downgraded the Nessus.

        Scenario Tested:
            [x] Verify user's data like advanced setting, created scan and created policy after upgrading/downgrading
                the nessus by saving given choice option in "Software Update" tab.
        """
        # Get nessus version and build before updating it
        setting_name, setting_value = add_advanced_setting
        log.info('Added advanced setting before updating nessus :: {}'.format(setting_name))

        created_scan = create_scans[0]
        log.info('Created scan before updating Nessus :: {}'.format(created_scan))

        created_policy = create_policy
        NewPolicyForm().save_button.click()
        wait(lambda: PoliciesPage().is_element_present("policies_searchbox"))
        log.info('Created new policy before updating nessus :: {}'.format(created_policy))

        # Launch created scan to get history and navigate to software update tab to get choice option
        original_nessus_version, original_nessus_build = get_nessus_version_details_from_ui()
        before_history_count, selected_option = launch_scan_and_navigate_to_software_update_tab(
            scan_name=created_scan, scanner_type="licensed", nessus_version=original_nessus_version)

        # Get Nessus version and build number before updating
        log.info('Nessus version before updating :: {}'.format(original_nessus_version))
        log.info('Nessus build before updating :: {}'.format(original_nessus_build))

        # Update nessus with given choice option
        log.info('Update Nessus from "{}" to "{}"'.format(selected_option, choice_option))
        update_software_and_wait_for_nessus_to_be_ready(update_choice=choice_option, scanner_type="licensed",
                                                        manual_update=True)

        # Get Nessus version and build number after updating
        updated_nessus_version, updated_nessus_build = get_nessus_version_details_from_ui()
        log.info('Nessus version after updating :: {}'.format(updated_nessus_version))
        log.info('Nessus build after updating :: {}'.format(updated_nessus_build))

        verify_user_data_preserved_after_updating_nessus(setting_name=setting_name, setting_value=setting_value,
                                                         created_scan=created_scan, created_policy=created_policy,
                                                         history_count=before_history_count)


@pytest.mark.nessus_settings_1
@pytest.mark.usefixtures('login')
@pytest.mark.nessus_home
@pytest.mark.nessus_manager
@pytest.mark.feed_channel_update
class TestSoftwareUpgradeDowngradeOptionsForManagerAndHome:
    """Testcases for software update choice invisibility for Nessus Manager and Home."""

    @pytest.mark.xfail(reason="Refer Jira ID NES-15803")
    def test_invisibility_of_software_update_tab_contents_for_manager_or_home(self):
        """
        NES-10901 - Automate upgrade/downgrade feature related testcases for Licensed scanner
        Steps:
        1. Verify that "Software Update" tab appears on About page.
        2. Verify that three update channel options does not appear under "Software Update" tab.
        Scenario Tested:
            [x] Verify update channel options does not appear for Nessus Manager/Home.
        """
        about_page = About()
        about_page.open()
        wait(lambda: OverView().is_element_present('update_activation_code_tip'), waiting_for='about page to get load')

        # Verify that "Software Update" tab appears for Nessus Manager/Home
        assert about_page.is_element_present("software_update_tab"), \
            "Software update tab is not visible on About page."

        about_page.software_update_tab.click()

        # Wait and verify that update channel options does not get loaded on "Software Update" tab.
        assert not SoftwareUpdate().is_element_present("update_option_labels"), \
            "Update channel options are present on Software Update tab."


@pytest.mark.nessus_settings_1
@pytest.mark.license_change
@pytest.mark.xfail(reason="this class fails further tests because it downgrade the instance.")
@pytest.mark.nessus_pro
@pytest.mark.usefixtures("reset_license", "wizard_open")
class TestNessusAutoDowngradeAfterFreshInstall:
    """ Testcase for Nessus auto downgrade """

    @staticmethod
    def login_after_register_nessus(code_generator_url: str) -> None:
        """
        Register Nessus professional and login with admin

        :param str code_generator_url: URL to generate activation code
        :return: None
        """
        users.adduser(username=Nessus.USERNAME, password=Nessus.PASSWORD, passconfirm=Nessus.PASSWORD, sysadmin=True)

        register_nessus_license_type(license_type=ActivationCodeGenerator.NESSUS_PROFESSIONAL,
                                     code_generator_url=code_generator_url)

        wait(lambda: LoginPage().is_element_present("username_field"), timeout_seconds=TIME_FIVE_MINUTES)
        login_helper_after_server_restart()
        wait_for_scanner_to_be_ready(api=NessusAPI())

    def test_nessus_downgrades_automatically_after_fresh_install_with_managed_scanner(self):
        """
        NES-15730 [UI-Automation]: Verify that Nessus downgrades automatically after fresh install.

        Scenario Tested:
        [x] Verify that Nessus downgrades automatically after fresh installation.
        """
        code_generator_url = 'https://{}/keygen/json.generate.php'.format(HOST_PLUGIN_FEED_STAGING)

        try:
            users.adduser(username=Nessus.USERNAME, password=Nessus.PASSWORD, passconfirm=Nessus.PASSWORD,
                          sysadmin=True)

            container_details = add_tenable_io_container()
            scanner_name = "test_nessus_scanner_%s" % uuid4().hex[:6]

            tio_api = TenableCloudAPI()
            tio_api.login(username=container_details['container'].model.contact,
                          password=container_details['container'].model.password)

            with SSH() as ssh:
                cmnd_output = ssh.execute(command="{} managed link --name={} --host={} --port=443 --key={}".format(
                    get_nessus_cli(), scanner_name, NessusConfig.CAT_TIO_URL, container_details['linking_key']))
                log.debug("Nessus - T.io linking output :: {}".format(cmnd_output))

            waiting_wait(lambda: [scanner for scanner in tio_api.scanners.get_list()['scanners'] if scanner_name ==
                                  scanner['name']], sleep_seconds=TIME_TEN_SECONDS, timeout_seconds=TIME_SIXTY_SECONDS,
                         waiting_for="Scanner to appear in scanners list")

            nessus_api = NessusAPI()
            get_driver_no_init().refresh()

            wait_for_scanner_status(api=nessus_api, status=API.Status.LOADING, timeout=TIME_TEN_MINUTES,
                                    sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')

            wait_for_scanner_status(api=nessus_api, status=API.Status.READY, timeout=TIME_THIRTY_MINUTES,
                                    msg='Availability of Nessus scanner API after linking to t.io.',
                                    sleep_interval=TIME_FIVE_SECONDS)

            login_helper_after_server_restart()
            wait_for_scanner_to_be_ready(api=nessus_api)
            login_page = LoginPage()
            user_menu = UserMenu()

            if login_page.is_element_present('username_field', timeout=TIME_SIXTY_SECONDS):
                login_page.login_with_defaults()
                user_menu.loaded()

            About().open()
            overview_page = OverView()
            wait(lambda: overview_page.is_element_present(element_name='nessus_version'))

            nessus_version_detail = overview_page.nessus_version.text.split()
            log.debug("Version details from Nessus UI :: {}".format(nessus_version_detail))

            version_details_from_manifest = fetch_nessus_version_and_build_for_given_channel(
                update_channel=Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION, scanner_type="managed")
            log.debug("Version details from feed server info :: {}".format(version_details_from_manifest))

            assert all([nessus_version_detail[0] == version_details_from_manifest[0],
                        nessus_version_detail[1].lstrip('(#').rstrip(')') == version_details_from_manifest[1]]), \
                "Nessus is not getting downgraded automatically after fresh installation."

            user_menu.logout()
            wait(lambda: login_page.is_element_present("username_field"))
        finally:
            remove_nessus_registration()
            self.login_after_register_nessus(code_generator_url=code_generator_url)

    @pytest.mark.skip(reason="Refer: ESQO-1061")
    def test_nessus_downgrades_automatically_after_fresh_install_with_licensed_scanner(self):
        """
        NES-15730 [UI-Automation]: Verify that Nessus downgrades automatically after fresh install.

        Scenario Tested:
        [x] Verify that Nessus downgrades automatically after fresh installation.
        """
        code_generator_url = 'https://{}/keygen/json.generate.php'.format(HOST_PLUGIN_FEED_STAGING)

        try:
            self.login_after_register_nessus(code_generator_url=code_generator_url)
            wait_for_scanner_to_be_ready(api=NessusAPI())

            try:
                welcome_modal = ActionCloseModal()

                if is_pro():
                    wait(lambda: welcome_modal.is_element_present("pendo_guide_container", timeout=TIME_NINETY_SECONDS))
                    close_pendo_guide_container_banner_for_nessus_pro()
                elif is_home():
                    wait(lambda: welcome_modal.is_element_present("modal", timeout=TIME_NINETY_SECONDS))
                    welcome_modal.close_button.click()
                    welcome_modal.wait_for_modal_closed()
            except (TimeoutException, TimeoutExpired):
                log.warning("May be 'Welcome to Nessus 10' guide modal has already been closed.")

            About().open()
            overview_page = OverView()
            wait(lambda: overview_page.is_element_present(element_name='nessus_version'))
            nessus_version_detail = overview_page.nessus_version.text.split()
            log.debug("Version details from Nessus UI :: {}".format(nessus_version_detail))

            version_details_from_manifest = fetch_nessus_version_and_build_for_given_channel(
                update_channel=Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION, scanner_type="licensed")
            log.debug("Version details from feed server info :: {}".format(version_details_from_manifest))

            assert all([nessus_version_detail[0] == version_details_from_manifest[0],
                        nessus_version_detail[1].lstrip('(#').rstrip(')') == version_details_from_manifest[1]]), \
                "Nessus is not getting downgraded automatically after fresh installation."

            UserMenu().logout()
            wait(lambda: LoginPage().is_element_present("username_field"))
        finally:
            remove_nessus_registration()
            self.login_after_register_nessus(code_generator_url=code_generator_url)
