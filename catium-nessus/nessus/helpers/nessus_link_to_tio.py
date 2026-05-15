"""
Helpers for Nessus linking to tenable-io
:copyright: Tenable Network Security, 2020
:date: May 27, 2020
:last_modified: May 27, 2020
:author: @vsoni
"""

from waiting import wait
from waiting.exceptions import TimeoutExpired

from catium.helpers.site_configuration_fetcher import product_and_site
from catium.lib.const.base_constants import TIME_TEN_SECONDS, TIME_TEN_MINUTES
from catium.lib.log.log import create_logger
from nessus.lib.config import NessusConfig
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI
from tenableio.helpers.container import create_container

log = create_logger()


def add_tenable_io_container(product: str = 'tenableio', site: str = NessusConfig.CAT_TIO_URL.split('.')[0]) -> dict:
    """
    Create a container in tenable-io
    :param str product: Name of product
    :param str site: Name of tenable-io site
    :return: Container details
    :rtype: dict
    """
    outcome = {'product': product, 'site': site}

    with product_and_site(product='tenableio', site=site):
        container = create_container()
        log.info('Created container: %s' % container.details['name'])
        outcome['container'] = container
        api = TenableCloudAPI()
        api.login(username=container.model.contact, password=container.model.password)
        linking_key = api.scanners.get_linking_key()['key']
        outcome['linking_key'] = linking_key
        api.logout()

    return outcome


def wait_for_scanner_to_become_online_in_tio(scanner_name: str, api: TenableCloudAPI) -> bool:
    """
    Wait till given Nessus scanner become online in Tenable-io
    :param str scanner_name: Name of scanner
    :param TenableCloudAPI api: instance of TenableCloudAPI
    :return: True if scanner become online withing 10 minutes of time else False
    :rtype: bool
    """

    def is_scanner_online():
        return [scanner for scanner in api.scanners.get_list()['scanners']
                if scanner_name == scanner['name']][0]['status'] == "on"

    try:
        wait(lambda: is_scanner_online(), sleep_seconds=TIME_TEN_SECONDS, timeout_seconds=TIME_TEN_MINUTES,
             waiting_for="Scanner to become online in tenable-io")
        return True
    except TimeoutExpired:
        return False
