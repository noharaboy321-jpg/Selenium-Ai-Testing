"""
Fixtures for upgrade tests
"""
import subprocess

import os
import pytest

from catium.lib.log import create_logger

log = create_logger()


@pytest.fixture(scope='session')
def feed_files_upload(request: 'SubRequest'):
    """
    This fixture is created to upload feed files on goat-feed server to test Nessus Update channel plan
    :param request:  parameter values
    """
    log.debug('fixture init: Copy files into the goat feed proxy server')

    plugin_server = os.getenv('PLUGIN_SERVER_DOCKER_CONTAINER')
    if not plugin_server:
        plugin_server = os.getenv('PLUGIN_SERVER')
    assert plugin_server, "PLUGIN_SERVER not set in environment, unable to upload files to feed without a hostname"
    subprocess.call(['docker', 'exec', plugin_server, 'mkdir', "/app/files/nightly-release"])
    subprocess.call(['docker', 'exec', plugin_server, 'mkdir', "/app/files/nightly-release-next"])
    file_list = request.param
    for file in file_list:
        if os.path.exists(file):
            channel = file.split('/')[2] if "tests" not in file else file.split('/')[5]
            code = subprocess.call(['docker', 'cp', file, '%s:/app/files/%s' % (plugin_server, channel)])
            assert code == 0, 'Error copying file %s into feed' % file
        else:
            print('file %s does not exist' % file)

    yield file_list
