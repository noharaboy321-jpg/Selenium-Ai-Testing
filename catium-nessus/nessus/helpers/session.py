"""
:copyright: Tenable Network Security, 2017
:date: June 1, 2017
:author: @cdombrowski
"""
from contextlib import contextmanager
from http import HTTPStatus

import pytest
from requests import HTTPError

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.lib.config import NessusConfig

log = create_logger()


def create_session_api_keys(api: NessusAPI = None) -> dict:
    """
    Method to create Nessus API secret key and access key for the current user's session.
    :param NessusAPI api:      Nessus API instance
    :return dict:              Returns dict of the access_key and secret_key
    """
    try:
        resp = api.session.generate_keys()
    except HTTPError as exception:
        log.debug('Request Error: %s', exception)
        if api.http_status_code == HTTPStatus.NOT_FOUND:
            return api.http_status_code
        elif api.http_status_code != HTTPStatus.OK:
            pytest.fail('The specified user_id was not found when attempting to create an api key')

    if 'accessKey' and 'secretKey' in resp:
        return {'access_key': resp['accessKey'], 'secret_key': resp['secretKey']}
    else:
        pytest.fail('Unable to retrieve Nessus API access key and/or secret key.')


@contextmanager
def nessus_api_session(api_username: str=None, api_password: str=None, api_session: NessusAPI=None) -> NessusAPI:
    """
    Method to setup the Nessus API session (if not specified) and close it after any operations.

    .. note:: If api_session is set api_username and api_password are ignored
    .. note:: Logout only occurs if an API session is created using the supplied credentials

    :param str api_username: Username to login to Nessus API
    :param str api_password: Password to login to Nessus API
    :param NessusAPI api_session: Optional existing Nessus API session
    """
    # Configure dynamic values outside of function defaults so it's always set at runtime.
    api_username = NessusConfig.CAT_NESSUS_USERNAME if api_username is None else api_username
    api_password = NessusConfig.CAT_NESSUS_PASSWORD if api_password is None else api_password

    logout = False
    if not api_session:
        api_session = NessusAPI()
        api_session.login(api_username, api_password)
        logout = True
    yield api_session
    if logout:
        api_session.logout()
