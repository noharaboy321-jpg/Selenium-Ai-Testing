"""
Nessus Service update test
Test cases for verifying Nessus Service update upon Nessusd shutdown
:copyright: Tenable Network Security, 2019
:date: August 10, 2022
:last_modified: August 16, 2022
:author: @stellex
"""
import pytest
from catium.helpers.sleep_lib import sleep
from catium.lib.ssh import SSH

from nessus.helpers.nessuscli.helper import stop_nessusd, get_command, get_nessus_sbin_dir, path_join


@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestNessusServiceUpdate:
    """ Test to verify nessus-service checks for and runs an update of itself upon Nessusd shutdown """

    sbin_directory = get_nessus_sbin_dir()

    @pytest.mark.parametrize('test_data_file', [{'output_file': '/yes-the-fake-nessus-service-ran'}], indirect=True)
    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': sbin_directory + 'yes-the-fake-nessus-service-ran'}], indirect=True)
    @pytest.mark.parametrize('rename_file', [{'file_path': sbin_directory, 'old_file_name': 'nessus-service',
                                              'new_file_name': 'old_nessus_service', 'cleanup_file': True}], indirect=True)
    @pytest.mark.parametrize('add_test_file', [{'file_path': sbin_directory, 'file_name': 'nessus-service',
                                                      'cleanup_file': True}], indirect=True)
    @pytest.mark.xray(test_key='SCE-3264')
    def test_nessus_service_update(self, test_data_file, delete_files, rename_file, add_test_file):
        """
        With nessus-service running, stores existing nessus-service file, adds dummy nessus-service file with only a
        command to touch a file, then stops nessusd. Expected functionality is that the running nessus-service detects
        a change to the binary and updates, visible by the new file being created. Cleanup - swaps the existing
        nessus-service file back in and restarts.
        """

        file = test_data_file['output_file']

        stop_nessusd()
        sleep(sleep_time=30, reason="Waiting for nessus-service to upgrade")
        display_content = get_command(operation='display_content')
        with SSH() as ssh:
            active_file = ssh.execute(f"{display_content} {file}")

            assert len(active_file) == 0, f"{file} not found"
