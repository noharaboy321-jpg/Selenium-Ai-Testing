"""
Fixtures for upgrade tests
"""
import subprocess

import os
import pytest
from _pytest.fixtures import SubRequest

from catium.lib.const.base_constants import TIME_THIRTY_MINUTES
from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const.constants import API

log = create_logger()


@pytest.fixture(scope='class')
def feed_files_upload(request: 'SubRequest'):
    """
    This fixture is created to upload feed files on plugin-server to test Nessus upgrade using tarball package
    :param request:  parameter values
    """
    log.debug('fixture init: Copy files into the goat feed proxy server')
    plugin_server = os.getenv('PLUGIN_SERVER_DOCKER_CONTAINER')

    if not plugin_server:
        plugin_server = os.getenv('PLUGIN_SERVER')

    assert plugin_server, "PLUGIN_SERVER not set in environment, unable to upload files to feed without a hostname"

    wait_for_scanner_status(api=NessusAPI(), status=API.Status.READY, timeout=TIME_THIRTY_MINUTES,
                            msg="Wait for Nessus to get ready")

    subprocess.call(['docker', 'exec', plugin_server, 'mkdir', "/app/files/"])
    file_list = request.param

    for file in file_list:
        if os.path.exists(file):
            log.info("File name :: {}".format(file))
            channel = file.split('/')[2] if "tests" not in file else file.split('/')[5]
            code = subprocess.call(['docker', 'cp', file, '%s:/app/files/%s' % (plugin_server, channel)])
            assert code == 0, 'Error copying file %s into feed' % file
        else:
            print('file %s does not exist' % file)

    yield file_list
