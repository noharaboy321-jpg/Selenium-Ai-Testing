"""
Nessus Commandline Tools - Wait for Scanner

Waits for a Nessus scanners plugin set to be populated
in order to determine when the Scanner is ready for use.

:copyright: Tenable, 2018
:date: Mar 4, 2018
:author: @jyerge, @krpatel.ctr
"""
import os
import sys

from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.waiters import wait_for_plugins, wait_for_scanner_login
from nessus.lib.config import NessusConfig

WAIT_MULTIPLIER = float(os.getenv('CAT_WAIT_MULTIPLIER', 1))
TIME_SIXTY_SECONDS = 60 * WAIT_MULTIPLIER


def _logout(api: NessusAPI) -> None:
    try:
        api.logout()
    except Exception:
        pass


if __name__ == '__main__':
    nessus_api = NessusAPI()
    for _ in range(0, 60):
        try:
            wait_for_scanner_login(api=nessus_api,
                                   username=NessusConfig.CAT_NESSUS_USERNAME,
                                   password=NessusConfig.CAT_NESSUS_PASSWORD,
                                   timeout=int(TIME_SIXTY_SECONDS),
                                   msg='Waiting for scanner login to succeed')
            wait_for_plugins(api=nessus_api, timeout=int(TIME_SIXTY_SECONDS))
            _logout(api=nessus_api)
            sys.exit(0)
        except Exception:
            _logout(api=nessus_api)

    sys.exit(1)