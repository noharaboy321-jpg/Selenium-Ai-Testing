"""
    Fixtures for Plugin locales

    :copyright: Tenable Network Security, 2024
    :date: Aug 30, 2024
    :author: @krpatel
"""
from typing import TYPE_CHECKING

import pytest
from requests.exceptions import HTTPError

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def enable_plugin_locales(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Enables plugin locales"""
    log.debug('fixture init: enable_disable_locales: Enables plugin locales')

    try:
        payload = {"enabled":True}
        enabled = nessus_api_handler.locales.enable_disable_locales(payload)

    except HTTPError:
        log.warning("Unable to disable the plugin locales")


@pytest.fixture()
def disable_plugin_locales(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Disables plugin locales"""
    log.debug('fixture init: enable_disable_locales: Disable plugin locales')

    try:
        payload = {"enabled":False}
        disabled = nessus_api_handler.locales.enable_disable_locales(payload)

    except HTTPError:
        log.warning("Unable to disable the plugin locales")


@pytest.fixture()
def get_locale_detail(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """get details of plugin locales"""
    log.debug('fixture init: get_locale_detail: getting locales details')

    details = nessus_api_handler.locales.get_locales_details()
    yield details


@pytest.fixture()
def set_locale_detail(request: 'SubRequest', nessus_api_handler: NessusAPI, data):
    """set details of plugin locales"""
    log.debug('fixture init: set_locale_detail: setting locales details')
    try:

        details = nessus_api_handler.locales.set_default_locales(data)

    except HTTPError:
        log.warning("Unable to set the plugin locales")


@pytest.fixture()
def wait_for_downloading_locales(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """

    :param request:
    :param nessus_api_handler:
    :return:
    """
    log.debug('fixture init: Waiting for logs to downloading the locales')
    # TODO:
