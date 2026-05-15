"""
Nessus fixtures for Server Endpoints

:copyright: Tenable Network Security, 2019
:date: Feb 21, 2019
:last_modified: April 05, 2019
:author: @mdriscoll, @kpanchal
"""

import json
import os
import tempfile
import time

import pytest

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_FIFTEEN_MINUTES, TIME_FIVE_SECONDS
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import execute, upload
from nessus.helpers.nessuscli.helper import get_nessus_cli, get_nessus_var_dir, stop_nessus, start_nessus
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const.constants import API

log = create_logger()


@pytest.fixture(scope="function")
def appliance_telemetry_valid(request: 'SubRequest'):
    """
        Writes valid JSON to /var/spool/tenablecore/telemetry/telemetry.json
    """
    execute('mkdir', ['-p', '/var/spool/tenablecore/telemetry'])
    execute('cp', ['/var/spool/tenablecore/telemetry/telemetry.json', '/tmp/telemetry.json'])
    with tempfile.NamedTemporaryFile() as f:
        f.write(b'{"data":"value"}\n')
        f.flush()
        upload(f.name, '/var/spool/tenablecore/telemetry/telemetry.json')
    yield
    execute('rm', ['/var/spool/tenablecore/telemetry/telemetry.json'])
    execute('cp', ['/tmp/telemetry.json', '/var/spool/tenablecore/telemetry/telemetry.json'])


@pytest.fixture(scope="function")
def appliance_telemetry_broken(request: 'SubRequest'):
    """
        Writes invalid JSON to /var/spool/tenablecore/telemetry/telemetry.json
    """
    execute('cp', ['/var/spool/tenablecore/telemetry/telemetry.json', '/tmp/telemetry.json'])
    execute('sh', ['-c', 'echo 12345totesinvalid > /var/spool/tenablecore/telemetry/telemetry.json'])
    yield
    execute('rm', ['/var/spool/tenablecore/telemetry/telemetry.json'])
    execute('cp', ['/tmp/telemetry.json', '/var/spool/tenablecore/telemetry/telemetry.json'])


@pytest.fixture(scope="function")
def imitate_tenable_core(request: 'SubRequest'):
    """
        Puts a string into /etc/os-release to imitate Tenable Core
    """
    execute('cp', ['/etc/os-release', '/tmp/os-release'])
    execute('sh', ['-c', 'echo tenablecore >> /etc/os-release'])
    yield
    execute('rm', ['/etc/os-release'])
    execute('cp', ['/tmp/os-release', '/etc/os-release'])


@pytest.fixture(scope="function")
def imitate_tenable_appliance(request: 'SubRequest'):
    """
        Puts a string into /etc/os-release to imitate Tenable Appliance
    """
    execute('cp', ['/etc/os-release', '/tmp/os-release'])
    execute('sh', ['-c', 'echo tenableappliance >> /etc/os-release'])
    yield
    execute('rm', ['/etc/os-release'])
    execute('cp', ['/tmp/os-release', '/etc/os-release'])


@pytest.fixture(scope="class")
def load_sample_notifications(request: 'SubRequest'):
    """
    Copies test_data/sample_notifications.json to the nessus installation
    and triggers them to be loaded.

    On teardown it removes the notifications.
    """
    file_name = request.param['file_name'] if hasattr(request, 'param') and 'file_name' in request.param else \
        'sample_notifications.json'

    api = NessusAPI()
    tmp_file = _create_notifications_file(file_name)

    with open(tmp_file, 'r') as f:
        notes_json = json.load(f)

    log.debug('Inserting sample notifications')
    upload(tmp_file, os.path.join(get_nessus_var_dir(), 'notifications.json'))
    os.unlink(tmp_file)
    _reload_nessus(api)
    log.debug('Done inserting sample notifications')

    yield notes_json

    log.debug('Removing sample notifications')
    notifications_file = 'nessus/tests/api/server/test_data/default_notifications.json'
    upload(notifications_file, os.path.join(get_nessus_var_dir(), 'notifications.json'))
    _reload_nessus(api)
    log.debug('Done removing sample notifications')


def _reload_nessus(api: NessusAPI):
    execute(get_nessus_cli(), ['reload'])
    wait_for_scanner_status(api=api, timeout=TIME_FIFTEEN_MINUTES, status=API.Status.LOADING,
                            msg='server to start loading.', sleep_interval=1)
    wait_for_scanner_status(api=api, timeout=TIME_FIFTEEN_MINUTES, status=API.Status.READY,
                            msg='server to finish loading.', sleep_interval=1)
    sleep(sleep_time=TIME_FIVE_SECONDS, reason='for reload to take effect.')


def _create_notifications_file(file: str) -> str:
    # we need unique ids or nessusd will re-use flags
    sample_file = 'nessus/tests/api/server/test_data/{}'.format(file)

    with open(sample_file) as f:
        notes_json = json.load(f)

    next_id = int(time.time())
    for note in notes_json['notifications']:
        note['id'] = next_id
        next_id += 1

    fd, tmp_file = tempfile.mkstemp()
    with os.fdopen(fd, 'w') as f:
        json.dump(notes_json, f, indent=2)
        f.write("\n")
    return tmp_file


@pytest.fixture()
def prepare_tenable_links_file(request: 'SubRequest'):
    # copy the sample json file to the nessus folder and reload nessus

    with SSH() as ssh:
        log.info(
            "The file tenable_links.json is {}".format(ssh.path_is_file(os.path.join(get_nessus_var_dir(),
                                                                                     'tenable_links.json'))))
    dest_file = os.path.join(get_nessus_var_dir(), 'tenable_links.json')
    dest_file_bak = os.path.join(get_nessus_var_dir(), 'tenable_links.json.bak')

    execute('mv', [dest_file, dest_file_bak])

    filename = request.param
    if filename:
        upload(filename, dest_file)

    stop_nessus()
    start_nessus()
    api = NessusAPI()
    wait_for_scanner_to_be_ready(api=api, is_login_required=False)

    yield filename

    execute('mv', [dest_file_bak, dest_file])
