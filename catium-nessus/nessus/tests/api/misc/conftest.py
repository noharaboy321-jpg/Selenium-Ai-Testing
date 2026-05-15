"""
Fixtures for upgrade tests
"""
import os
import pytest

from catium.lib.log import create_logger
from catium.helpers.testdata import get_file_path
from nessus.helpers.cli_command import upload
from nessus.helpers.nessuscli.helper import get_nessus_plugin_dir

log = create_logger()


@pytest.fixture(scope="class")
def copy_plugin_files(request: 'SubRequest'):
    """
    :param request:  parameter values
    """
    log.debug('fixture init: Copy files to the plugins directory')

    file_list = request.param
    for file in file_list:
        local_file = get_file_path('nessus/tests/api/misc/test_data/' + file)
        plugin_file = os.path.join(get_nessus_plugin_dir(), file)
        upload(local_file, plugin_file)

