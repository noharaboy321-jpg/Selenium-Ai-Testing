"""
Nessus fixtures for Scan Endpoints

:copyright: Tenable Network Security, 2019
:date: Mar 4, 2019
:last_modified: Mar 4, 2019
:author: @pellsworth
"""

import pytest

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_command, path_join, stop_nessus, start_nessus
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.lib.config.environment_variables import NESSUS_DATA_DIR
from nessus.models.scan import ScanModel

log = create_logger()


# Reload... then wait for Nessus to become not-available, and then available.
def _reload_and_wait(api: NessusAPI):
    stop_nessus()
    start_nessus()
    wait_for_scanner_to_be_ready(api=api)


@pytest.fixture(scope="function")
def break_credentials_json():
    """
    Copy credentials.json to a backup location, and break the original so it
    fails the tampering check.

    On teardown it restores the original.
    """
    api = NessusAPI()
    log.debug('Moving original credentials.json to credentials.json.bak')

    # TODO: This is *nix specific.
    move_file = get_command(operation='move_file')

    execute(move_file, [path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates', 'credentials.json']),
                        path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates', 'credentials.json.bak'])])
    try:
        _reload_and_wait(api)
        log.debug('Done breaking credentials.json')

        yield
    finally:
        log.debug('Restoring credentials.json.bak')
        execute(move_file, [path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates', 'credentials.json.bak']),
                            path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates', 'credentials.json'])])
        _reload_and_wait(api)
        log.debug('Done restoring credentials.json')


@pytest.fixture(scope="function")
def create_two_scheduled_scans():
    api = NessusAPI()
    api.login()

    config = {
        'enabled': True,
        'starttime': '20300101T120000',
        'timezone': 'US/Samoa',
        'launch': 'ONETIME',
        'rrules': 'FREQ=ONETIME',
        'description': 'Created by Automation',
        'text_targets': '127.0.0.1',
    }

    scan1_id = api.scans.create(ScanModel(name='scan1', **config))['scan']['id']
    scan2_id = api.scans.create(ScanModel(name='scan2', **config))['scan']['id']

    yield scan1_id, scan2_id

    api.scans.delete(scan1_id)
    api.scans.delete(scan2_id)


@pytest.fixture(scope="function")
def create_two_unscheduled_scans():
    api = NessusAPI()
    api.login()

    config = {
        'enabled': False,
        'starttime': '20300101T120000',
        'timezone': 'US/Samoa',
        'launch': 'ONETIME',
        'rrules': 'FREQ=ONETIME',
        'description': 'Created by Automation',
        'text_targets': '127.0.0.1',
    }

    scan1_id = api.scans.create(ScanModel(name='scan1', **config))['scan']['id']
    scan2_id = api.scans.create(ScanModel(name='scan2', **config))['scan']['id']

    yield scan1_id, scan2_id

    api.scans.delete(scan1_id)
    api.scans.delete(scan2_id)
