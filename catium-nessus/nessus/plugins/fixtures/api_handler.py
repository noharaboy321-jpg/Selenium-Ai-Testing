"""
 :copyright: Tenable Network Security, 2018
 :date: Feb 27, 2018
 :author: @wsmith
"""
from typing import TYPE_CHECKING

import pytest

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def nessus_api_handler(request: 'SubRequest') -> NessusAPI:
    """
        Wrapper fixture for API; if api is present in request.cls.cat use that API otherwise create api instance
        and login using the environment variables CAT_URL, CAT_NESSUS_USERNAME and CAT_NESSUS_PASSWORD
    """
    log.debug('fixture init: nessus_api_handler: Check if API exists, create it if not')
    created = False
    try:
        api = request.cls.cat.api
        if api is None:
            raise AttributeError('Cat has uninitialized api member')
    except AttributeError:
        api = NessusAPI()
        api.login()
        created = True

    yield api
    log.debug('fixture teardown: nessus_api_handler: Logout if API was created. Created: %s', created)
    # Only if API instance was created within this fixture log it out
    if created:
        api.logout()
