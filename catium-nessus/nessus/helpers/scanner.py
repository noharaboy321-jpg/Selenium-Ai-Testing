"""
Nessus Scanner Helpers

:Copyright: Tenable Network Security, 2017
:Creation Date: Mar 16, 2017
:last_modified: January 03, 2019
:author: @jyerge, @rdutta, @kpanchal
"""

from contextlib import contextmanager
from http import HTTPStatus

from waiting.exceptions import TimeoutExpired

from catium.lib.const import TIME_FIFTEEN_MINUTES, TIME_FIVE_SECONDS, TIME_TEN_MINUTES, TIME_THREE_MINUTES, STRING_ON
from catium.lib.const.base_constants import TIME_FIVE_MINUTES
from catium.lib.log import create_logger
from catium.lib.url import Url
from catium.lib.util import random_agent_uuid, random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.waiters import wait_for_scanner_status, wait_for_scanner_login
from nessus.lib.config import NessusConfig
from nessus.lib.const import API

log = create_logger()


def link_scanner_to_cloud(scanner: dict, linking_key: str, is_managed_scanner=True, is_use_proxy=False) -> None:
    """
    Method to link the specified `scanner` to a CloudIron instance by specified `linking key`.

    :param dict scanner: Dictionary with information about scanner to be linked
    :param str linking_key: Link token of the CloudIron instance
    :param bool is_managed_scanner: scanner being linked is managed one or not
    :param bool is_use_proxy: scanner being linked is through proxy or not
    :return: None
    :rtype: None
    """
    parsed_url = Url(NessusConfig.CAT_NESSUS_URL)
    cloud_iron_hostname = parsed_url.hostname
    nessus_api = NessusAPI()
    nessus_api.session_url = 'https://%s:%s/' % (scanner['host'], scanner['port'])
    wait_for_scanner_login(nessus_api, username=scanner['username'], password=scanner['password'],
                           timeout=TIME_THREE_MINUTES, msg='Waiting for scanner login to succeed')
    wait_for_scanner_status(api=nessus_api, status=API.Status.READY,
                            timeout=TIME_THREE_MINUTES, msg='Availability of Nessus scanner',
                            sleep_interval=TIME_FIVE_SECONDS)
    log.info("Login successful to Nessus Scanner")
    nessus_api.scanners.link_to_cloud(manager_host=cloud_iron_hostname, linking_key=linking_key,
                                      scanner_name=scanner['name'], manager_port=scanner['port'],
                                      register=is_managed_scanner, use_proxy=is_use_proxy)
    log.debug('Scanner "%s" linked to "%s" CloudIron instance', scanner['name'], cloud_iron_hostname)


def unlink_scanner_to_cloud(scanner: dict, from_scanner=False) -> None:
    """
    Method to unlink the specified `scanner` to a CloudIron instance.

    :param dict scanner: Dictionary with information about scanner to be linked
    :param bool from_scanner: True for unlink from scanner
    :return: None
    """
    parsed_url = Url(NessusConfig.CAT_NESSUS_URL)
    cloud_iron_hostname = parsed_url.hostname
    nessus_api = NessusAPI()
    nessus_api.session_url = 'https://%s:%s/' % (scanner['host'], scanner['port'])
    nessus_api.login(scanner['username'], scanner['password'])
    nessus_api.scanners.unlink_to_cloud(from_scanner)
    log.debug('Scanner "%s" unlinked to "%s" CloudIron instance', scanner['name'], cloud_iron_hostname)


def create_scanner(scanner_details: dict = None, is_multi_scanner=False, api: NessusAPI = None, **kwargs):
    """Helper function to create and link a scanner

    :param dict scanner_details: a dictionary of scanner details used as json payload
           for creating and linking scanner
    :param TenableCloudAPI api: existing TenableCloud API session
    :param is_multi_scanner: Check if Multi scanner needs to be added
    :returns: dict
    """

    scanner_name = kwargs.get('scanner_name', random_name(prefix='scanner-'))
    if not scanner_details:
        scanner_details = {'name': scanner_name,
                           'key': api.scanners.get_scanner_linking_key()['key'],
                           'suuid': random_agent_uuid(),
                           'distro': 'es6-x86-64', 'platform': 'LINUX'}
    else:
        if 'name' not in scanner_details:
            scanner_details['name'] = scanner_name
        if 'key' not in scanner_details:
            scanner_details['key'] = api.scanners.get_scanner_linking_key()['key']
        if 'suuid' not in scanner_details:
            scanner_details['suuid'] = random_agent_uuid()
        if 'distro' not in scanner_details:
            scanner_details['distro'] = 'es6-x86-64'
        if 'platform' not in scanner_details:
            scanner_details['platform'] = 'LINUX'

    if is_multi_scanner:
        scanner_details['engine_version'] = '8.1.1'
        scanner_details['ui_version'] = '8.1.1'
        response = api.multi_scanner.register(scanner_details)
    else:
        response = api.scanners.add_remote_scanner(scanner_details)
        scanner_details['scanner_token'] = response['token']
    scanner_details['scanner_response'] = response
    scanner_id = ''
    list_scanners = api.scanners.get_list()
    for scanner in list_scanners['scanners']:
        if scanner['name'] == scanner_details['name']:
            scanner_id = scanner['id']
            break
    scanner_details['id'] = scanner_id

    return scanner_details


def restart_scanner(api, scanner_id=1) -> None:
    """
    Reboot Nessus service
    :param api: existing Nessus API session
    :param scanner_id: scanner id
    :return: None
    """
    api.server.restart()

    assert api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
        HTTPStatus.OK, api.http_status_code)

    # Wait till server status switch to loading
    wait_for_scanner_status(api=api, status=API.Status.LOADING,
                            timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                            sleep_interval=TIME_FIVE_SECONDS)

    # Wait till server is ready
    wait_for_scanner_status(api=api, status=API.Status.READY,
                            timeout=TIME_FIFTEEN_MINUTES, msg='Availability of Nessus scanner',
                            sleep_interval=TIME_FIVE_SECONDS)

    response = api.server.status()
    api.login()

    # Verifies reboot is done successfully
    assert response['status'] == API.Status.READY, 'Reboot is unsuccessful or taking long'


def get_remote_scanner(api: NessusAPI) -> list:
    """
    Returns name of remote scanner(s)
    :param api: Nessus API session object
    :return: list of remote scanner if one/more remote scanner listed in scanner_list
    :rtype: list
    """
    scanner_list = api.scanners.get_list()['scanners']
    if scanner_list:
        return [scanner['name'] for scanner in scanner_list if (scanner['id'] != 1 and scanner['status'] == STRING_ON)]
    else:
        log.warning("Not able to fetch any remote scanner from scanners_list.")
        return []


def check_remote_scanner(remote_scanner: str, api: NessusAPI) -> bool:
    """
    Returns true if the remote scanner exist
    :param str remote_scanner: Name of remote scanner
    :param api: existing Nessus API session
    :return: True if remote scanner found
    :rtype: bool
    """
    scanner_list = api.scanners.get_list()['scanners']
    if scanner_list:
        for scanner_name in scanner_list:
            if remote_scanner == scanner_name['name']:
                return True
        return False
    else:
        return False


@contextmanager
def scanner_token(api: NessusAPI, token: str) -> None:
    """
    Sets scanner token for scanner authentication

    :param NessusAPI api: NessusAPI object
    :param str token: token for remote scanner
    :return: None
    """
    api.remove_header('MS-Scanner')
    api.add_header({'MS-Scanner': 'token={}'.format(token)})
    yield
    api.remove_header('MS-Scanner')


def wait_for_scanner_to_be_ready(api: NessusAPI, is_login_required: bool = True) -> None:
    """ This helper waits for Nessus to become ready """
    try:
        wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                msg="waiting for Nessus to get 'loading' status")
    except TimeoutExpired:
        log.warning("Nessus did not get 'loading' status after starting the service")

    wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_TEN_MINUTES * 3,
                            msg='registration to complete.')

    if is_login_required:
        api.login()
