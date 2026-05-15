"""
Nessus License/Registration Helpers
:copyright: Tenable Network Security, 2017
:date: September 12, 2017
:author: @pellsworth
"""

import re

import requests
from requests import RequestException
from waiting import TimeoutExpired

from catium.lib import const
from catium.lib.activation_code_generator import ActivationCodeGenerator
from catium.lib.const import TIME_FIVE_MINUTES, TIME_FIVE_SECONDS
from catium.lib.const.base_constants import TIME_TEN_MINUTES, TIME_TWO_MINUTES
from catium.lib.errors import CatiumActivationCodeGeneratorError
from catium.lib.log.log import create_logger
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli import update, users
from nessus.helpers.nessuscli.helper import stop_nessus, start_nessus
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.config import NessusConfig
from nessus.lib.const import API
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.notifications import close_pendo_guide_container_banner_for_nessus_pro, \
    close_pendo_guide_container_banner_for_nessus_expert

log = create_logger()


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


def remove_nessus_registration() -> None:
    """ This helper function removes nessus registration using CLI commands """
    stop_nessus()
    reset_nessus_output = update.reset_nessus_license()
    log.debug("Output of nessus reset command :: {}".format(reset_nessus_output))

    log.debug("User existed in nessus :: {}".format(NessusConfig.CAT_NESSUS_USERNAME))
    rm_user_output = users.rmuser(username='{}'.format(NessusConfig.CAT_NESSUS_USERNAME))
    log.debug("Output of user removal command :: {}".format(rm_user_output))

    start_nessus()
    api = NessusAPI()

    log.debug("waiting for nessus in ready state after getting service started")
    wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_TWO_MINUTES,
                            msg='plugins loading to start.')
    wait_for_scanner_status(api=api, status=API.Status.REGISTER, timeout=TIME_TEN_MINUTES,
                            msg='Waiting for nessus to get ready for register')


def close_welcome_nessus_10_modal_for_pro():
    """ This helper function dismisses "Welcome to Nessus 10" modal for Nessus Pro license """
    try:
        wait(lambda: ActionCloseModal().is_element_present("pendo_guide_container"),
             waiting_for='"Welcome to Nessus 10" guide modal gets displayed')
        close_pendo_guide_container_banner_for_nessus_pro()
    except TimeoutExpired:
        log.warning('"Welcome to Nessus 10" guide modal is either not getting visible or already closed.')


def close_welcome_nessus_10_modal_for_expert():
    """ This helper function dismisses "Welcome to Nessus 10" modal for Nessus Expert license """
    try:
        wait(lambda: ActionCloseModal().is_element_present("pendo_guide_container"),
             waiting_for='"Welcome to Nessus 10" guide modal gets displayed')
        close_pendo_guide_container_banner_for_nessus_expert()
    except TimeoutExpired:
        log.warning('"Welcome to Nessus 10" guide modal is either not getting visible or already closed.')


def start_nessus_and_wait_till_it_becomes_ready():
    """This helper make sure Nessus is up and running before performing login to Nessus in UI."""

    api = NessusAPI()
    try:
        server_status = api.server.status()['status']
        log.debug("Nessus server status is : {}".format(server_status))
    except (RequestException, KeyError):
        start_nessus()
        log.info("Got error while fetching server status.")
    try:
        wait_for_scanner_status(api=api, timeout=TIME_FIVE_MINUTES * 2, status=API.Status.READY,
                                msg='Waiting for server to be in ready state.', sleep_interval=TIME_FIVE_SECONDS)
    except TimeoutExpired:
        log.info("Nessus is not in ready state after waiting for five minutes")
        try:
            log.info("Server status is : {}".format(api.server.status()['status']))
        except:
            pass
