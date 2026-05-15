"""
Upgrade test for nessuscli
"""
from http import HTTPStatus

import os
import pytest
from _pytest.fixtures import SubRequest

from catium.helpers.testdata import get_file_path
from catium.lib.const.base_constants import TIME_FIFTEEN_MINUTES
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_cli, get_os_name, get_nessus_plugin_dir
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import API, OperatingSystems
from nessus.lib.const.constants import NessusFilePath

log = create_logger()


def get_nessus_tools_dir():
    """This function will return tools directory path for Nessus according to operating system."""

    return NessusFilePath.Windows.NESSUS_TOOLS_DIR if get_os_name() == OperatingSystems.WINDOWS else \
        NessusFilePath.Linux.NESSUS_TOOLS_DIR


def check_nessus_version_using_cli() -> dict:
    """
    Returns Nessus version details after fetching via CLI

    :return: Nessus version details
    :rtype: dict
    """
    return execute(get_nessus_cli(), ['-v'])


def update_nessus_using_cli(windows_os: bool, command: str) -> dict:
    """
    Updates Nessus using CLI command args

    :param bool windows_os: True if windows OS else False
    :param str command: CLI command args
    :return: Update nessus CLI command output
    :rtype: dict
    """
    # how to set NESSUS_QA_MODE
    if windows_os:
        result = execute(get_nessus_cli(), ['update', command])
    else:
        result = execute('/bin/sh', ['-c', 'export NESSUS_QA_MODE=1 && {} update {}'.format(
            get_nessus_cli(), command)])

    return result


def start_stop_nessus_and_wait_for_ready(api: None, windows_os: bool, action: str) -> None:
    """
    Starts or Stops Nessus service and wait for nessus to be in ready state

    :param NessusAPI api: Nessus API object
    :param bool windows_os: True if windows OS else False
    :param str action: action like start or stop Nessus
    :return: None
    """
    if not api:
        api = NessusAPI()
    if windows_os:
        result = execute('net', ['{}'.format(action), 'Tenable Nessus'])
    else:
        result = execute('supervisorctl', ['{}'.format(action), 'nessusd'])

    log.debug("Nessus service {} command output :: {}".format(action, result))

    if action == 'start':
        # This may involve a plugin compilation, so we'll wait for up to 30min.
        wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES * 3,
                                msg="waiting for Nessus scanner to be ready")


@pytest.fixture()
def nessuscli_update_all(request: 'SubRequest'):
    """
    Upgrade Nessus via "nessuscli update --all"
    """
    tar_file_path = []
    downgrader_filename = 'downgrader.500.0.0.ntool'
    downgrader_file_path = os.path.join(get_nessus_tools_dir(), downgrader_filename)
    is_update_all = getattr(request, 'param')
    is_windows = get_os_name() == OperatingSystems.WINDOWS

    if not is_update_all and is_windows:
        pytest.xfail(reason='Nessus upgrade via tarball test skipped for Windows for now.')

    ssh = SSH()
    api = NessusAPI()

    nessus_details_before_update = check_nessus_version_using_cli()
    log.info("Nessus version before update :: {}".format(nessus_details_before_update))

    if is_windows:
        plugin_server = os.getenv("PLUGIN_SERVER")
        result = execute(get_nessus_cli(), ['fix', '--set', '--secure', 'custom_host=' + plugin_server])
        log.debug("plugin_server = " + plugin_server + " result = %s" % result)

    commands = ['auto_update=yes', 'feed_no_sig=yes']

    for cmnd in commands:
        result = execute(get_nessus_cli(), ['fix', '--set', cmnd])
        log.debug("CLI command output for {} :: {}".format(cmnd, result))

    start_stop_nessus_and_wait_for_ready(api=api, windows_os=is_windows, action='stop')

    try:
        if not is_update_all:
            tar_file = 'win' if is_windows else 'es7'
            tar_file_path = ssh.execute(command='find /tmp/tarball/ -name "nessus-{}-*.tar.gz"'.format(tar_file))
            log.debug('Output of tar_file_path :: {}'.format(tar_file_path))

        command_args = '--all' if is_update_all else tar_file_path[0]
        log.debug('Output of command_args = {}'.format(command_args))

        result = update_nessus_using_cli(windows_os=is_windows, command=command_args)
        log.debug("'nessuscli update' CLI command output :: {}".format(result))

        if is_update_all:
            assert 'Nessus Core Components are now up-to-date' in result['stdout'], \
                "Success message not present in: %s" % result['stdout']

            # Check that it applies immediately
            result = check_nessus_version_using_cli()
            log.info("Nessus version after upgrading it to 500.0.0 build :: {}".format(result))

            assert '500.0.0' in result['stdout'], "Nessus was not version 500.0.0: %s" % result['stdout']

            for file in ['plugin_feed_info.inc', 'plugin_list.nasl', 'pluginrules.nbin']:
                filename = os.path.join(get_nessus_plugin_dir(), file)

                assert ssh.path_exist(filename), "The plugin tarball was not properly extracted to %s" % filename

                ssh.remove_file(filename)
        else:
            assert all(['* Update successful.' in result['stdout'], '* Failed to update from {}.  Invalid manifest.'.
                       format(tar_file_path[0].split('/')[3]) not in result['stdout']]), \
                'Failed to update Nessus via tarball.'

            # Check that it applies immediately
            result = check_nessus_version_using_cli()
            log.info("Nessus version after upgrading it to 500.0.0 build :: {}".format(result))

            files_under_remote_dir = ssh.execute(command='ls -al /opt/nessus/var/nessus/remote/')

            for file in files_under_remote_dir:
                log.debug(file)

        start_stop_nessus_and_wait_for_ready(api=api, windows_os=is_windows, action='start')

        list_dir = ssh.list_directory(remote_directory=get_nessus_tools_dir())
        log.debug("Files under nessus tools dir :: {}".format(list_dir))

        assert ssh.path_exist(downgrader_file_path), "The downgrader file %s is not exist under nessus tools " \
                                                     "directory after upgrading Nessus." % downgrader_filename

        # Check that it remains applied (e.g., plugins-core.tar.gz or something wasn't accidentally left behind)
        result = check_nessus_version_using_cli()
        log.debug("Nessus version CLI command output after Nessus gets ready :: {}".format(result))

        assert '500.0.0' in result['stdout'], "Nessus was not version 500.0.0: %s" % result['stdout']

        yield
    finally:
        log.info("In finally block...")
        if not is_windows:
            if api.server.status()['status'] == API.Status.READY:
                start_stop_nessus_and_wait_for_ready(api=api, windows_os=is_windows, action='stop')

            tar_file = 'win' if is_windows else 'es7'
            tar_file_path = ssh.execute(command='find /tmp/tarball/ -name "nessus-latest-{}*.tar.gz"'.format(tar_file))

            result = update_nessus_using_cli(windows_os=is_windows, command=tar_file_path[0])
            log.debug("'nessuscli update' CLI command output :: {}".format(result))

            result = check_nessus_version_using_cli()
            log.info("Nessus version CLI command output after downgrading :: {}".format(result))

            start_stop_nessus_and_wait_for_ready(api=api, windows_os=is_windows, action='start')

            ssh.remove_file(remote_path=downgrader_file_path)
        log.info("Finished finally block...")


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('feed_files_upload', 'nessuscli_update_all', 'nessus_api_login')
@pytest.mark.parametrize('feed_files_upload', [[
    '/tmp/ga/nessus-es7-x86-64.tar.gz',
    '/tmp/ga/nessus-win-x86-64.tar.gz',
    '/tmp/ga/nessus.manifest',
    'nessus/tests/ui/about/test_data/ga/all-2.0.tar.gz',
    'nessus/tests/ui/about/test_data/ga/nessus.manifest.sig',
]], indirect=True)
@pytest.mark.parametrize('nessuscli_update_all', [True, False], indirect=True)
class TestNessuscliUpdate:
    """ Covers test to create scan after upgrading Nessus """

    cat = None

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_wannacry_scan.json'),
         'scan_type': 'wannacry'}], indirect=True)
    def test_create_scan(self, create_scan):
        """
        Creates a new scan on the upgraded scanner.
        """

        scan_id = create_scan['scan']['id']
        scans = self.cat.api.scans.get_scans()['scans']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert scan_id in [scan['id'] for scan in scans], 'Failed to create scan'
