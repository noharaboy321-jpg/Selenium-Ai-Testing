"""
 :copyright: Tenable Network Security, 2018
 :date: July 10, 2018
 :author: @agaskov
"""
import pytest
from _pytest.fixtures import SubRequest
from requests.exceptions import RequestException
from waiting.exceptions import TimeoutExpired

from catium.lib.const import TIME_FIVE_SECONDS, TIME_TEN_MINUTES
from catium.lib.const.base_constants import TIME_FIVE_MINUTES
from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import start_nessus
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import API

log = create_logger()
nessus_api_instance = None


@pytest.fixture()
def store_nessus_api_instance(request: 'SubRequest') -> bool:
    """
    If nessus_api_login fixture is used in product integration testing when more than one product involved
    i.e. SC and Nessus and no need to preserve Nessus API session as request.instance.cat.api object
    than nessus_api_login fixture should be used with store_nessus_api_instance parameter set to 'False'
    """
    return getattr(request, 'param', True)


@pytest.fixture()
def nessus_api_login(request: 'SubRequest', store_nessus_api_instance: bool) -> NessusAPI:
    """
    Automatic API login for Nessus
    If used in product integration testing when more than one product involved i.e. SC and Nessus
    and no need to preserve Nessus API session as request.instance.cat.api object than nessus_api_login fixture
    should be used with store_nessus_api_instance parameter set to 'False'

    .. note:: Uses the environment variables CAT_URL, CAT_NESSUS_USERNAME and CAT_NESSUS_PASSWORD
    """
    log.debug('fixture init: nessus_api_login: Automatic login for Nessus')

    if request.node.get_closest_marker('disable_logout'):
        perform_logout = False
    else:
        perform_logout = True

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
    api.login()
    if store_nessus_api_instance:
        request.instance.cat.api = api

        global nessus_api_instance
        nessus_api_instance = api
    yield api
    wait_for_scanner_status(api=api, status=API.Status.READY,
                            timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                            sleep_interval=TIME_FIVE_SECONDS)
    if perform_logout:
        try:
            api.logout()
            nessus_api_instance = None
        except Exception as e:
            log.warning("Unable to perform api logout. Exception is : {}".format(e))


def get_stored_nessus_api_instance():
    """ Returns nessus api instance which is stored while login via API """
    return nessus_api_instance
