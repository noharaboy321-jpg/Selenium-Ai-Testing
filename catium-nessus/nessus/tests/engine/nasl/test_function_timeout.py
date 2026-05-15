"""
NASL test for function timeouts
Test cases for timeout of NASL functions such as egrep
:copyright: Tenable Network Security, 2022
:last_modified: August 30, 2022
:author: @stellex
"""

import pytest
import re
from catium.helpers.testdata import get_file_path
from catium.lib.ssh import SSH
from nessus.helpers.nessuscli.helper import get_nessus_plugin_dir, get_nessus_log_dir, get_command, path_join


@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestFunctionTimeouts:
    """
    Test for NASL function timeouts. May be modified in the future to cover other NASL function testing.
    """

    # Setup test variables
    cat = None
    plugin_directory = get_nessus_plugin_dir()
    log_dir = get_nessus_log_dir()

    egrep_plugin = {'plugin_filename': 'cs-45156.nasl', 'cleanup_file': True}
    egrep_plugin_test_data = {'scan_json_path':
                              (get_file_path('nessus/tests/engine/nasl/test_data/test_egrep_function_timeout.json')),
                              'scan_type': 'advanced', 'plugin_data': egrep_plugin}

    @pytest.mark.parametrize('install_custom_plugin', [egrep_plugin_test_data['plugin_data']], indirect=True)
    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': log_dir + 'nessusd*'}], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': egrep_plugin_test_data['scan_json_path'], 'scan_type': egrep_plugin_test_data['scan_type'],
         'settings': {"scanner.metrics": 127, "nasl_no_signature_check": "yes"}}
    ], indirect=True)
    def test_egrep_timeout(self, delete_files, test_data_file, nessus_api_login, install_custom_plugin,
                           configure_advanced_settings_and_env_variables, create_scan_class):
        """
        Installs custom NASL plugin and generates a large text file at runtime. Plugin executes large egrep regex
        function against the text file which should trigger a timeout. The test then verifies the nessusd.dump file
        for the correct entries that indicate the timeout correctly occurs.
        """
        # Generate big.txt at runtime (~165MB) to trigger egrep timeout
        big_txt_path = path_join([self.plugin_directory, "big.txt"])
        with SSH() as ssh:
            # Generate a ~165MB file using yes and head (fast and efficient)
            ssh.execute(f"yes 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | head -c 165000000 > /tmp/big.txt", sudo=True)
            ssh.execute(f"mv /tmp/big.txt {big_txt_path}", sudo=True)
            ssh.execute(f"chmod 644 {big_txt_path}", sudo=True)

        try:
            # Get Scan related information for newly created scan and verify its 200 response
            logfile_scan = create_scan_class
            scan_exists = logfile_scan.scan_state()
            dumpfile_path = path_join([get_nessus_log_dir(), "nessusd.dump"])

            assert scan_exists, 'Failed to create scan'

            logfile_scan.launch_scan()

            # Verify scan is pass or fail to complete
            assert logfile_scan.scan_result, "Scan failed to complete."

            display_content = get_command(operation='display_content')
            with SSH() as ssh:
                dumpfile_content = ssh.execute(f"{display_content} {dumpfile_path}")

            too_slow = None
            regexec = None
            for line in dumpfile_content:
                # Check for timeout message. Older nessusd.dump entries used a message like
                # "too slow - after Xs, stopping it". Timeout logging was updated to include a
                # millisecond-precision "[duration=XXXX]" field, and the message was simplified to
                # "too slow - stopping it". This test only validates the newer format, since the
                # legacy "after Xs" format is no longer emitted by supported Nessus versions.
                if "too slow - stopping it" in line:
                    too_slow = line
                    # Extract duration from [duration=XXXX] in the line (duration is in milliseconds)
                    duration_match = re.search(r'\[duration=(\d+)\]', line)
                    if duration_match:
                        duration_ms = int(duration_match.group(1))
                        time_sec = duration_ms / 1000.0
                        assert 4.5 < time_sec < 6.0, f"Timeout duration {time_sec}s not in expected range 4.5-6.0s"
                # Check for regexec error - format is "[error=1]...regexec failed" not "regexec...failed [1]"
                elif "regexec failed" in line:
                    # Verify error=1 is present in the line
                    if "[error=1]" in line:
                        regexec = line

            assert too_slow is not None, "Too slow dumpfile message was not found"
            assert regexec is not None, "regexec dumpfile message was not found"
        finally:
            # Cleanup: Remove the generated big.txt file
            with SSH() as ssh:
                ssh.execute(f"rm -f {big_txt_path}", sudo=True)
