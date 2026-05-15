"""
    Fixtures for WAS

    :copyright: Tenable Network Security, 2017
    :date: Aug 08 2017
    :author: @ivargas jyerge
"""
from typing import TYPE_CHECKING

import pytest
import time
from requests.exceptions import HTTPError

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_command
from catium.lib.ssh import SSH

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def enable_was(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Enables WAS"""
    log.debug('fixture init: enable_was: Enables WAS')
    payload = {"was": True}
    enabled = nessus_api_handler.was.toggle_was(payload)
    downloading = nessus_api_handler.was.download_was()

    container_exists = get_command(operation='docker_image_exists').format('was-scanner')
    # 10 mins from now
    timeout = time.time() + 60*5

    while True:
        with SSH() as ssh:
            result = ssh.execute(f"""{container_exists}""")
            if result and 'tenable/was-scanner' in result[0]:
                break
            if time.time() > timeout:
                break
    
    assert 'tenable/was-scanner' in result[0],\
        'Expected tenable/was-scanner to be present in response "{}"'.format(result[0])


@pytest.fixture()
def disable_was(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Disables WAS"""
    log.debug('fixture init: disable_was: Disables WAS')
    payload = {"was": False}
    disabled = nessus_api_handler.was.toggle_was(payload)

    container_exists = get_command(operation='docker_container_exists').format('was-scanner')
    timeout = time.time() + 60*5 # 5 mins from now

    while True:
        with SSH() as ssh:
            result = ssh.execute(f"""{container_exists}""")
            if not result:
                break
            if time.time() > timeout:
                break
    
    assert not result,\
        'Expected tenable/was-scanner to be present in response "{}"'.format(result[0])


@pytest.fixture()
def stop_docker(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Stops docker"""
    log.debug('fixture init: stop_docker: stops docker')
    stop_docker = get_command(operation='stop_docker')
    with SSH() as ssh:
        ssh.execute(f"""{stop_docker}""")


@pytest.fixture()
def start_docker(request: 'SubRequest', nessus_api_handler: NessusAPI):
    """Starts docker"""
    log.debug('fixture init: start_docker: starts docker')
    start_docker = get_command(operation='start_docker')
    with SSH() as ssh:
        ssh.execute(f"""{start_docker}""")
