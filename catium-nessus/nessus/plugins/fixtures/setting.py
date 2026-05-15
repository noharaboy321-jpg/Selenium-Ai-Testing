"""
Create password complexity on the Nessus

:copyright: Tenable Network Security, 2018
:date: Aug 14, 2018
:last_modified: December 20, 2018
:author: @jchavda, @lambaliya
"""
from http import HTTPStatus
from typing import TYPE_CHECKING

import pytest
from requests.exceptions import HTTPError

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def password_complexity_settings(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Set Password Complexity on Nessus"""
    pwd_settings = nessus_api_handler.settings.get_setting_complexity()

    try:
        payload = request.param['payload']
        nessus_api_handler.settings.set_password_complexity(payload)

        yield payload

        nessus_api_handler.settings.set_password_complexity(pwd_settings)
    except HTTPError:
        log.warning("Unable to retrieved Password Management Detail")


@pytest.fixture()
def proxy_server_settings(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Set Proxy Setting Nessus"""

    proxy_settings = nessus_api_handler.settings.get_proxy_setting()
    try:
        payload = request.param['payload']
        nessus_api_handler.settings.set_proxy(payload)
        yield payload
        nessus_api_handler.settings.set_proxy(proxy_settings)
    except HTTPError:
        log.warning("Unable to retrieved Proxy Server")


@pytest.fixture()
def add_advance_setting(request: 'SubRequest', nessus_api_handler: NessusAPI) -> tuple:
    """Add Advance setting"""
    payload = request.param.get("payload")
    remove_added_setting = request.param.get("remove_added_setting")

    nessus_api_handler.settings.update(payload)
    setting_added_successfully = nessus_api_handler.http_status_code == HTTPStatus.OK

    settings = nessus_api_handler.settings.get_list()
    for setting in settings['preferences']:
        if setting['name'] == payload['setting.0.name']:
            created_setting = setting
            break
    yield created_setting
    if remove_added_setting and setting_added_successfully:
        if created_setting:
            req_payload = {
                "setting.0.id": created_setting["id"],
                "setting.0.action": "remove",
                "setting.0.name": created_setting["name"]}
            nessus_api_handler.settings.update(req_payload)
