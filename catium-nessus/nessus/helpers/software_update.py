"""
Nessus software update helpers

:copyright: Tenable Network Security, 2020
:date: Feb 18, 2020
:last_modified: Nov 26, 2020
:author: @kpanchal.ctr, @vsoni.ctr
"""

import json
import os
import subprocess
from contextlib import contextmanager
from http import HTTPStatus

from packaging.version import parse
from requests.exceptions import RequestException
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_FIVE_SECONDS, TIME_FIFTEEN_MINUTES, TIME_FIVE_MINUTES, \
    TIME_THIRTY_MINUTES, WAIT_LONG, TIME_THIRTY_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_cli, get_nessus_backend_log, get_nessusd_dump, \
    get_nessusd_messages, get_command
from nessus.helpers.polling_ui import polling_ui
from nessus.helpers.scan import create_scan_helper
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.system import is_pro
from nessus.helpers.waiters import wait_for_scanner_status, wait_scan_state
from nessus.lib.config import NessusConfig
from nessus.lib.const.constants import API, Nessus
from nessus.pageobjects.about.about_page import SoftwareUpdate, OverView, About
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import close_pendo_guide_container_banner_for_nessus_pro, \
    close_welcome_banner_for_nessus_pro, is_welcome_banner_handled
from nessus.pageobjects.header.user_menu import UserMenu
from nessus.pageobjects.login.login_page import LoginPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList

log = create_logger()


def navigate_to_software_update_tab(update_option_to_default: bool = False) -> None:
    """
    This method will navigate to software update tab and click on default software update option(if required)

    :param bool update_option_to_default: True if "Default" option must be selected.
    :return: None
    """
    if not get_driver_no_init().current_url.endswith('/settings/about/software-update'):
        HeaderBasePage().settings_link.click()

        about_page = About()
        wait(lambda: about_page.is_element_present("software_update_tab"))
        about_page.software_update_tab.click()

        about_software_update = SoftwareUpdate()
        wait(lambda: about_software_update.is_element_present("update_option_labels"))

        if update_option_to_default and "Default" not in about_software_update.get_selected_update_option():
            about_software_update.click_and_save_software_update_option(
                option=Nessus.About.SoftwareUpdateChannel.UPDATE_GA_OPTION)


def update_software_and_wait_for_nessus_to_be_ready(update_choice: str, scanner_type: str,
                                                    manual_update: bool = False) -> None:
    """
    This function will save given update choice option and wait until the nessus to be in ready state after
    upgrading/downgrading.
    :param update_choice: software update choice option
    :param scanner_type: scanner type like Managed/Licensed
    :param manual_update: True if manual update is needed else False
    :return: None
    """
    version_details_ui = get_nessus_version_details_from_ui()
    version_details_from_manifest = fetch_nessus_version_and_build_for_given_channel(
        update_channel=update_choice, scanner_type=scanner_type)

    navigate_to_software_update_tab()

    software_update = SoftwareUpdate()
    locator_value = "Nessus Version Update" if parse(version_details_ui[0]) > parse(
        "10.2.0") else "Version Update"
    selected_option = software_update.get_selected_software_update_choice(locator_value=locator_value)

    if scanner_type == "managed":
        check_loading = not (selected_option == update_choice)

    if update_choice:
        software_update.click_and_save_software_update_option(option=update_choice)

    # For "licensed" scanner, if build and versions are same for channels then no need to wait for loading status.
    if scanner_type == "licensed":
        check_loading = version_details_ui != version_details_from_manifest

        # Setting check loading to false as downgrade to build is not possible.
        if check_loading and version_details_ui[0] == version_details_from_manifest[0] and int(
                version_details_ui[1]) > int(version_details_from_manifest[1]):
            check_loading = False

        if manual_update:
            try:
                software_update.manual_software_update.click()
                manual_update_modal = ActionCloseModal()
                manual_update_modal.accept_action()
                manual_update_modal.wait_for_modal_closed()
            except Exception as e:
                log.warning("Unable to click on 'Manual Software Update' button. Getting exception : {}".format(e))
        elif selected_option == update_choice:
            check_loading = False

    wait_for_nessus_to_be_ready_after_software_update(check_loading=check_loading)


def wait_for_nessus_to_be_ready_after_software_update(check_loading: bool = False, do_login: bool = True):
    """
    This method will wait till nessus becomes ready after software updates through Nessus update plan.

    :param bool check_loading: True is 'loading' status needs to be verified else False
    :param bool do_login: True if login is required else False
    :return:
    """
    api = NessusAPI()

    with polling_ui():
        if check_loading:
            try:
                # Wait till server status switch to loading
                wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES * 2,
                                        sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')
            except TimeoutExpired:
                log.warning("Nessus did not get 'loading' state!!!")

        # Wait till server is ready
        wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES * 2,
                                sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')

    # Navigate to software update tab after nessus successfully updated.
    wait_for_scanner_to_be_ready(api=api)

    if do_login:
        login_page = LoginPage()
        login_page.refresh()

        try:
            if login_page.is_element_present('username_field', timeout=TIME_THIRTY_SECONDS):
                login_page.login_with_defaults()
                sleep(TIME_THIRTY_SECONDS, reason="It sometimes take little bit time to get login")
                welcome_banner = ActionCloseModal()

                if is_pro() and welcome_banner.is_element_present("modal", timeout=TIME_THIRTY_SECONDS):
                    close_pendo_guide_container_banner_for_nessus_pro()
                    is_welcome_banner_visible = welcome_banner.is_element_present("welcome_banner_title",
                                                                                  timeout=WAIT_LONG)

                    log.debug("Banner handled :: {} and Banner visible :: {}".format(is_welcome_banner_handled,
                                                                                     is_welcome_banner_visible))
                    if not is_welcome_banner_handled or is_welcome_banner_visible:
                        close_welcome_banner_for_nessus_pro()
                else:
                    UserMenu().loaded()
        except TimeoutExpired:
            log.warning("Username field was not found after refreshing")
        finally:
            navigate_to_software_update_tab()


def create_scan_and_verify_completion_after_nessus_update() -> bool:
    """
    This function will create and launch scan after nessus upgraded/downgraded

    :return: True if scan gets completed else False
    :rtype: bool
    """
    HeaderBasePage().scan_link.click()
    scans_page = ScansPage()
    wait(lambda: scans_page.is_element_present('new_scan_button'))

    scan_name = random_name(prefix="{} - ".format(Nessus.TemplateNames.BASIC_NETWORK))
    scans_page.create_new_scan(scan_template=Nessus.TemplateNames.BASIC_NETWORK,
                               scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
                               scan_name=scan_name, target_ip=Nessus.Scan.Target.LOCALHOST)

    wait(lambda: scans_page.is_element_present('new_scan_button'))
    scan_list = ScanList()

    try:
        return scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, launch_scan=True,
                                                         status=API.Scan.Status.COMPLETED)
    finally:
        scan_list.delete_scan(scan_name=scan_name)
        log.info("'{}' scan deleted successfully.".format(scan_name))


def get_nessus_version_details() -> dict:
    """
    Returns the nessus version details through API

    :return: nessus version details
    :rtype: dict
    """
    nessus_api = NessusAPI()
    nessus_api.login()

    version_details = nessus_api.server.properties()
    nessus_api.logout()

    return version_details


def get_nessus_version_details_from_ui() -> tuple:
    """
    Returns nessus version details under overview tab from UI

    :return: nessus version and build number
    :rtype: tuple
    """
    if is_pro():
        close_pendo_guide_container_banner_for_nessus_pro()
        is_welcome_banner_visible = ActionCloseModal().is_element_present("welcome_banner_title", timeout=WAIT_LONG)

        if not is_welcome_banner_handled or is_welcome_banner_visible:
            close_welcome_banner_for_nessus_pro()

    if not get_driver_no_init().current_url.endswith('/settings/about'):
        HeaderBasePage().settings_link.click()
        wait(lambda: About().is_element_present("software_update_tab"))
        About().open()

    overview_page = OverView()
    wait(lambda: overview_page.is_element_present(element_name='nessus_version'))
    nessus_version_detail = overview_page.nessus_version.text.split()

    overview_page.software_update_tab.click()
    software_update_page = SoftwareUpdate()
    wait(lambda: (software_update_page.is_element_present("update_option_labels") or
                  software_update_page.is_element_present("update_all_components")))

    return nessus_version_detail[0], nessus_version_detail[1].lstrip('(#').rstrip(')')


def fetch_nessus_version_and_build_for_given_channel(update_channel: str, scanner_type: str = "licensed") -> tuple:
    """
    This function will read manifest file from goat-feed-server and extract Nessus version and build.

    :param str update_channel: Software Update Channel (EA/GA/Stable)
    :param str scanner_type: Nessus scanner type ("licensed"/"managed")
    :return: Nessus version and build from manifest file
    :rtype: tuple
    """
    nessus_version = ""
    nessus_build = ""

    with SSH() as ssh:
        if scanner_type == "managed":
            output = ssh.execute(command="{} fix --secure --get ms_token | grep 'current value'".format(
                get_nessus_cli()))
            token_value = output[0].split('is')[1].split("'")[1]

            update_output = ssh.execute(
                'curl -s -H "MS-Scanner: token={}" "https://{}/remote/scanner/updates?type=managed&platform=LINUX&'
                'distro=es7-x86-64&channel={}" | python -m json.tool;'.format(
                    token_value, NessusConfig.CAT_TIO_URL, update_channel))

            update_dict = json.loads("".join(update_output))
            nessus_version = update_dict['ui_version']
            nessus_build = update_dict['ui_build']
        elif scanner_type == "licensed":
            update_json = json.loads("".join(ssh.execute(
                command='curl -sk https://{}/info | python -m json.tool'.format(
                    Nessus.Scan.Target.STAGING_FEED_SERVER_HOST))))['nessus_build_channels']

            nessus_version = update_json[update_channel]['version']
            nessus_build = update_json[update_channel]['build']

    return str(nessus_version), str(nessus_build)


@contextmanager
def replace_feed_files(update_choice: str, new_feed_files_folder: list) -> None:
    """
    This function will replace feed files at goat-feed-server for given software update channel.
    :param update_choice: Software Update channel choice
    :param new_feed_files_folder: Folder name where the new feed files will be present.
    :return: None
    """
    plugin_server = os.getenv('PLUGIN_SERVER_DOCKER_CONTAINER')
    if not plugin_server:
        plugin_server = os.getenv('PLUGIN_SERVER')
    assert plugin_server, "PLUGIN_SERVER not set in environment, unable to replace files to feed without a hostname"
    subprocess.call(['docker', 'exec', plugin_server, 'mkdir', "/app/files/{}_backup".format(update_choice)])

    for file in Nessus.About.SoftwareUpdateChannel.BUILD_UPDATE_FILES_LIST:
        subprocess.call(['docker', 'exec', plugin_server, 'mv', '/app/files/%s/%s' % (update_choice, file),
                         '/app/files/%s_backup' % update_choice])
        code = subprocess.call(['docker', 'cp', "/tmp/%s/%s" % (new_feed_files_folder, file),
                                '%s:/app/files/%s' % (plugin_server, update_choice)])
        assert code == 0, 'Error copying file %s into feed' % file
    yield
    for file in Nessus.About.SoftwareUpdateChannel.BUILD_UPDATE_FILES_LIST:
        subprocess.call(['docker', 'exec', plugin_server, 'rm', '-rf', "/app/files/%s/%s" % (update_choice, file)])
        subprocess.call(['docker', 'exec', plugin_server, 'mv', '/app/files/%s_backup/%s' % (update_choice, file),
                         '/app/files/%s' % update_choice])
    subprocess.call(['docker', 'exec', plugin_server, 'rm', '-rf', "/app/files/%s_backup" % update_choice])


def is_downgrade_build(current_version: str, current_build: str, expected_version: str, expected_build: str) -> bool:
    """
    This helper will identify if the Nessus engine detects build downgrading in backend.
    :param str current_version: Current Nessus Version
    :param str current_build: Current Nessus Build
    :param str expected_version: Expected Nessus Version
    :param str expected_build: Expected Nessus Build
    :return: True if build downgrades else False
    :rtype: bool
    """
    return current_version == expected_version and int(current_build) > int(expected_build)


def get_nessus_version_and_build_using_api() -> tuple:
    """
    Returns the nessus version details through API

    :return: nessus version details
    :rtype: tuple
    """
    version_details = get_nessus_version_details()

    return version_details['nessus_ui_version'], version_details['nessus_ui_build']


def set_software_update_channel(api: NessusAPI, update_channel: str,
                                custom_host: str = Nessus.Scan.Target.STAGING_FEED_SERVER_HOST) -> None:
    """
    This method sets the software update channel
    :param NessusAPI api:Instance of Nessus API
    :param str update_channel: update_channel which needs to be set
    :param custom_host: specific custom_host/feed_host (if needs to be given)
    :return: None
    """
    api.settings.edit_software_updates_setting(payload={"update": "all", "update_channel": update_channel,
                                                        "custom_host": custom_host})


def verify_no_errors_while_software_update() -> bool:
    """
    This helper method verifies that there is no errors present in backend.log, nessusd.messages and nessusd.dump
    """
    ssh = SSH()
    backend_log = get_nessus_backend_log()
    nessusd_dump = get_nessusd_dump()
    nessusd_messages = get_nessusd_messages()
    success_flag = True
    for file in [backend_log, nessusd_messages, nessusd_dump]:
        try:
            assert all([False if 'error' in entry.lower() else True for entry in ssh.execute(
                '{} {}'.format(get_command('display_content'), file))]), \
                "There is error level log entry in '{}' file.".format(file)
        except AssertionError:
            success_flag = False
            log.info("Error tag present in file : {}".format(file))
            for log_entry in ssh.execute('{} {}'.format(get_command('display_content'), file)):
                log.info(log_entry)
    return success_flag


def clean_up_log_files_before_software_update() -> None:
    """
    This helper method clear existing log files so only new and fresh logs can be verified after the update operation.
    """
    with SSH() as ssh:
        for file in [get_nessus_backend_log(), get_nessusd_dump(), get_nessusd_messages()]:
            ssh.execute("echo > {}".format(file))


def verify_scan_gets_executed_properly_after_software_update(api: NessusAPI) -> bool:
    """
    This helper method verifies if scan gets created, launched and completed successfully after software update
    :param NessusAPI api: Instance of Nessus API
    :return: True if scan works properly else False
    :rtype: bool
    """
    scan_details = create_scan_helper(api, file_name='nessus/tests/api/scan/test_data/test_basic_network_scan.json',
                                      template_title='basic')
    scan_id = scan_details[0]['scan']['id']
    try:
        api.scans.launch(scan_id)

        assert api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % api.http_status_code

        scan_completed = wait_scan_state(api=api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                         timeout=TIME_THIRTY_MINUTES)
        # Get scan details after completion and verify the same.
        scan_details = api.scans.details(scan_id)
        assert len(scan_details['vulnerabilities']) >= 1, "Scan failed to get vulnerabilities"
    finally:
        api.scans.delete(scan_id=scan_id)
    return scan_completed


def is_nessus_updated(update_operation: str, original_version: str) -> bool:
    """
    This helper verifies if nessus updated as required or not
    :param str update_operation: upgrade or downgrade
    :param str original_version: Original version against which the new nessus version is to be verified
    :return: True if nessus updated else False
    """
    try:
        updated_nessus_version = get_nessus_version_and_build_using_api()[0]
        return parse(updated_nessus_version) < parse(original_version) if update_operation == "downgrade" else \
            parse(updated_nessus_version) > parse(original_version)
    except RequestException as exception:
        log.debug("Error while fetching nessus version : {}".format(exception))
        return False


def upgrade_nessus_package(nessus_installer_path: str, force: bool = False) -> None:
    """
    Upgrades/Downgrades Nessus with given installer package path

    :param str nessus_installer_path: installer package path
    :param bool force: True if upgrade nessus package forcefully else False
    :return: None
    """
    list_args = [nessus_installer_path]

    if force:
        list_args.append('--force')

    execute(command='rpm -Uvh', args=list_args)


def download_nessus_installer_from_nexus(channel: str) -> str:
    """
    Downloads Nessus installer of given software upgrade/downgrade channel from Nexus

    :param str channel: software upgrade/downgrade channel (e.g: EA/GA/Stable)
    :return: Nessus installer path
    :rtype: str
    """
    ssh = SSH()

    if channel == 'ga':
        installer_path = 'https://nexus.cloud.aws.tenablesecurity.com/repository/product-release/nessus/{}/' \
                         'Nessus-{}-es7.x86_64.rpm --output Nessus-{}-es7.x86_64.rpm'. \
            format(channel.upper(), channel.upper(), channel)

        log.info("Download Nessus {} installer from Nexus...".format(channel.upper()))
        ssh.execute(command='curl {}'.format(installer_path))

    dir_path_to_search = '/' if channel == 'ga' else '/install'
    log.debug("Dir path to search installer for {} :: {}".format(channel, dir_path_to_search))

    log.debug("Search downloaded nessus installer")
    find_nessus_installer = ssh.execute(command='find {} -name "Nessus-*-es7.x86_64.rpm"'.format(
        dir_path_to_search))

    return find_nessus_installer[0]


def verify_nessus_build_details_after_upgrade_downgrade(
        original_nessus_version: str, original_nessus_build: str, updated_nessus_version: str,
        updated_nessus_build: str, expected_nessus_version: str, expected_nessus_build: str, choice_option: str,
        nessus_details: dict) -> None:
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
    :return: None
    """
    # Verifies the nessus version and build after updating with given update choice
    if choice_option == nessus_details['update_choice']:
        assert original_nessus_version == updated_nessus_version == expected_nessus_version, \
            'Nessus version is getting upgraded/downgraded when updating the channel with same option' \
            ' - {}.'.format(choice_option)

        assert original_nessus_build == updated_nessus_build == expected_nessus_build, \
            'Nessus build is getting upgraded/downgraded when updating the channel with same option' \
            ' - {}.'.format(choice_option)
    else:
        assert updated_nessus_version == expected_nessus_version, \
            'Nessus version is not getting upgraded/downgraded after updating with different channel option.'

        assert updated_nessus_build == expected_nessus_build, \
            'Nessus build is not getting upgraded/downgraded after updating with different channel option.'

    assert create_scan_and_verify_completion_after_nessus_update(), \
        'Scan is not getting completed after upgrading/downgrading the nessus with channel option.'
