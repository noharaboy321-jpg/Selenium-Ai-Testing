"""
Tests to verify logfiles and options
:copyright: Tenable Network Security, 2023
:created: May 25, 2023
:author: @stellex
"""

import pytest
import re
from catium.lib.log import create_logger
from catium.lib.ssh import SSH

from nessus.helpers.nessuscli.helper import get_command, get_nessus_log_dir, path_join, get_os_name
from nessus.lib.const import OperatingSystems

log = create_logger()


@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestLogfiles:
    """
    Tests for different logfile settings and behaviors
    """

    # Setup test variables
    cat = None

    log_dir = get_nessus_log_dir() if get_os_name() != OperatingSystems.WINDOWS else get_nessus_log_dir() + "\\"

    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': [log_dir + 'nessusd.messages', log_dir + 'nessusd.dump', log_dir + 'backend.log'],
                                               'restart_nessus': False}], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'settings': {'logfile_msec': None}, 'expected_time_format': r'\d{2}:\d{2}:\d{2}', 'restart': True, 'cleanup_settings': True},
        {'settings': {'logfile_msec': 'yes'}, 'expected_time_format': r'\d{2}:\d{2}:\d{2}\.\d{3}', 'restart': True, 'cleanup_settings': True},
        {'settings': {'logfile_msec': 'no'}, 'expected_time_format': r'\d{2}:\d{2}:\d{2}', 'restart': True, 'cleanup_settings': True}
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3574')
    def test_logfile_timestamp(self, test_data_file, nessus_api_login, delete_files,
                               configure_advanced_settings_and_env_variables):
        """
        Test deletes logfiles and sets logfile_msec to various values, then makes sure setting is applied the same way
        to timestamps within each file.
        """

        os_windows = True if get_os_name() == OperatingSystems.WINDOWS else False
        os_freebsd = True if get_os_name() == OperatingSystems.FREEBSD else False

        time_format = test_data_file['expected_time_format']

        file_list = ['nessusd.dump', 'nessusd.messages', 'backend.log']
        nessusd_dump_format = r"\[[A-z]{3} [A-z]* \d{2} " + time_format + r" \d{4} [+,-]\d{4}\]"
        backend_log_format = r"\[\d{2}/[A-z]*/\d{4}:" + time_format + r" [+,-]\d{4}\]"

        display_content = get_command(operation='display_content')
        log_dir = get_nessus_log_dir()

        failed_file = []

        for file_name in file_list:

            file = path_join([log_dir, file_name]) if not os_windows else path_join([log_dir, file_name]).replace("\\", "\\\\")
            sudo = False if get_os_name() in [OperatingSystems.WINDOWS, OperatingSystems.FREEBSD] else True

            with SSH() as ssh:
                timestamp = None
                file_content = ssh.execute(f"{display_content} {file}", sudo=sudo)
                for line in file_content:
                    if file_name == "backend.log":
                        timestamp_format = backend_log_format
                    else:
                        timestamp_format = nessusd_dump_format
                    timestamp = re.search(timestamp_format, line)
                    if timestamp:
                        break

            if not timestamp:
                log.info(f"{file} content: {file_content}")
                failed_file.append(file)

        assert not failed_file, f"Matching timestamp line not found in {failed_file} file(s)"
