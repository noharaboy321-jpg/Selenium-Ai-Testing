"""
    Fixtures for Nessus Plugins

    :copyright: Tenable Network Security, 2017
    :date: Aug 08 2017
    :author: @ivargas jyerge
"""
import os
from typing import TYPE_CHECKING

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.log import create_logger
from catium.lib.ssh import SSH

from nessus.helpers.scanner import restart_scanner

from nessus.helpers.nessuscli.helper import get_nessus_plugin_dir, path_join, get_command

if TYPE_CHECKING:
    from catium.lib.typechecking import SubRequest

log = create_logger()


@pytest.fixture()
def get_plugin_families(request: 'SubRequest'):
    """Gets the list of plugin families"""
    plugin_families = request.cls.cat.api.plugins.families()
    return plugin_families['families']


@pytest.fixture()
def get_plugins(request: 'SubRequest', get_plugin_families):
    """Gets the list of plugin families"""
    plugins = []
    for plugin_family in get_plugin_families:
        plugin_family_plugins = request.cls.cat.api.plugins.family_details(plugin_family['id'])['plugins']
        for plugin in plugin_family_plugins:
            plugins.append(plugin)
    return plugins


@pytest.fixture()
def install_custom_plugin(request: 'SubRequest'):
    """
    Adds and installs custom plugin file(s) from local repository test files.

    Supports single-file (legacy) and multi-file modes:

    Single file (existing callers)::

        @pytest.mark.parametrize('install_custom_plugin', [
            {'plugin_filename': 'my_plugin.nasl', 'cleanup_file': True}
        ], indirect=True)

    Multiple files with options::

        @pytest.mark.parametrize('install_custom_plugin', [{
            'filenames': ['main.nasl', 'lib1.inc', 'lib2.inc'],
            'test_data_dir': 'nessus/tests/nessuscli/test_data',
            'cleanup_file': True,
            'restart': False,
        }], indirect=True)
    """
    remote_plugin_dir = get_nessus_plugin_dir()
    default_test_data_dir = os.path.join('nessus/tests', 'plugins/test_data', 'pluginsets_custom')

    # Normalize single-file vs multi-file params
    if 'filenames' in request.param:
        filenames = request.param['filenames']
    else:
        filenames = [request.param['plugin_filename']]

    test_data_dir = request.param.get('test_data_dir', default_test_data_dir)
    cleanup = request.param.get('cleanup_file', True)
    restart = request.param.get('restart', True)

    remote_paths = []
    with SSH() as ssh:
        for filename in filenames:
            local_path = get_file_path(os.path.join(test_data_dir, filename))
            if not os.path.exists(local_path):
                raise FileNotFoundError(
                    f"Plugin file not found: {local_path}. "
                    f"Ensure the file exists in the repository under {test_data_dir}/"
                )
            remote_path = path_join(path_dir_list=[remote_plugin_dir, filename])
            ssh.send_file(local_path, remote_file_path=remote_path)
            remote_paths.append(remote_path)
            log.info(f"Copied {filename} to {remote_path}")

    if restart:
        remove_file = get_command(operation='remove_file')
        with SSH() as ssh:
            ssh.execute(f"""{remove_file} {path_join(path_dir_list=[remote_plugin_dir, "plugin_feed_info.inc"])}""")
        restart_scanner(request.cls.cat.api)

    yield remote_paths

    if cleanup:
        remove_file = get_command(operation='remove_file')
        with SSH() as ssh:
            for remote_path in remote_paths:
                ssh.execute(f"{remove_file} {remote_path}")
