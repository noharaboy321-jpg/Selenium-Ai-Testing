"""
Nessus Log Rotation Options
Test cases for verifying log rotation option functionality
:copyright: Tenable Network Security, 2022
:last_modified: August 15, 2022
:author: @stellex
"""
from datetime import datetime, timedelta

import pytest
from catium.helpers.testdata import get_file_path
from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_FIVE_SECONDS, TIME_THIRTY_SECONDS
from catium.lib.ssh import SSH

from nessus.helpers.nessuscli.helper import get_command, get_nessus_log_dir, path_join

@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestLogRotationOptions:
    """
    Tests for log rotation options, rotation to new log files as older files exceed size or time limits.
    """

    # Setup test variables
    cat = None
    unique_filename = 'nessusd' + datetime.now().strftime('%y%m%d%H%M%S')
    log_dir = get_nessus_log_dir()
    log_rotation_scan_data = {
        'scan_json_path': (get_file_path('nessus/tests/engine/logs/test_data/test_log_rotation.json')), 'scan_type': 'advanced'
    }

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'logfile': path_join(path_dir_list=[log_dir, unique_filename + '.messages'])}},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'logfile': path_join(path_dir_list=[log_dir, 'extra_logs/nessusd.messages'])}},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': path_join(path_dir_list=[log_dir, unique_filename + '.dump'])}},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': path_join(path_dir_list=[log_dir, 'extra_logs/nessusd.dump'])}}
    ], indirect=True)
    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': log_dir + 'nessusd*'}], indirect=True)
    def test_logfile_path_option(self, delete_files, test_data_file, configure_advanced_settings_and_env_variables,
                                 nessus_api_login, create_scan_class):
        """
        Sets logfile or dumpfile path to a different value than the default, creates and runs a scan, then verifies
        the logfile or dumpfile is in the correct location.
        """
        file = None

        # Unpack test_data_file
        if 'logfile' in test_data_file['settings'].keys():
            file = test_data_file['settings']['logfile']
        elif 'dumpfile' in test_data_file['settings'].keys():
            file = test_data_file['settings']['dumpfile']
        else:
            pytest.fail("Logfile or dumpfile not found in test_data_file['settings']")

        # Get Scan related information for newly created scan and verify its 200 response
        logfile_scan = create_scan_class
        scan_exists = logfile_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        logfile_scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert logfile_scan.scan_result, "Scan failed to complete."

        display_content = get_command(operation='display_content')
        with SSH() as ssh:
            active_file = ssh.execute(f"{display_content} {file}")

            assert "No such file or directory" not in active_file[0], f"{file} not found"

    # Test-level variables for test_logfile_size_option
    default_scale_factor = {'NESSUS_LOG_SCALE_FACTOR': '1024'}
    dumpfile_path = path_join(path_dir_list=[log_dir, unique_filename + '.dump'])
    logfile_path = path_join(path_dir_list=[log_dir, unique_filename + '.messages'])

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': dumpfile_path, 'dumpfile_rot': 'size', 'dumpfile_max_size': '225',
                      'dumpfile_rotation_time': '365'},
         'environment_variables': {'NESSUS_LOG_SCALE_FACTOR': '1'}, 'rotate_logs': True},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': dumpfile_path, 'dumpfile_rot': 'size', 'dumpfile_max_size': '100',
                      'dumpfile_rotation_time': '1'},
         'environment_variables': default_scale_factor, 'rotate_logs': False},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'logfile': logfile_path, 'logfile_rot': 'size', 'logfile_max_size': '3',
                      'logfile_rotation_time': '365'},
         'environment_variables': default_scale_factor, 'rotate_logs': True},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'logfile': logfile_path, 'logfile_rot': 'size', 'logfile_max_size': '100',
                      'logfile_rotation_time': '1'},
         'environment_variables': default_scale_factor, 'rotate_logs': False}
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3195')
    @pytest.mark.xray(test_key='SCE-3199')
    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': log_dir + 'nessusd*'}], indirect=True)
    @pytest.mark.disable_logout
    def test_logfile_size_option(self, delete_files, nessus_api_login, configure_advanced_settings_and_env_variables,
                                 test_data_file, create_scan_class):
        """
        Sets the logfile or dumpfile rotation to size and a given size value, then creates and launches a scan,
        verifying that if the size limit is exceeded for a logfile or dumpfile log rotation creates a new file.
        """
        max_size = None
        file = None

        # Unpack variables from the test_data_file
        rotation_scale_factor = int(test_data_file['environment_variables']['NESSUS_LOG_SCALE_FACTOR'])
        if 'logfile' in test_data_file['settings'].keys():
            file = test_data_file['settings']['logfile']
            max_size = test_data_file['settings']['logfile_max_size']
        elif 'dumpfile' in test_data_file['settings'].keys():
            file = test_data_file['settings']['dumpfile']
            max_size = test_data_file['settings']['dumpfile_max_size']
        else:
            pytest.fail("Logfile or dumpfile not found in test_data_file['settings']")
        rotate_logs = test_data_file['rotate_logs']

        logfile_scan = create_scan_class
        scan_exists = logfile_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        i = 0
        while True:
            logfile_scan.launch_scan()

            # Verify scan is pass or fail to complete
            assert logfile_scan.scan_result, "Scan failed to complete."

            get_file_size = get_command(operation='get_file_size')
            with SSH() as ssh:
                active_file_size = ssh.execute(f"{get_file_size.format(file)}")
                old_file_sizes = ssh.execute(f"{get_file_size.format(file + '.*')}")

                if not rotate_logs:
                    break
                elif 'No such file or directory' not in old_file_sizes[0]:
                    break
                else:
                    i += 1

                if i > 5:
                    pytest.fail(f"Too many attempts to create log rotation with {file}, failing test.")

        file_max_size = rotation_scale_factor * int(max_size)
        if rotate_logs:
            for file_size in old_file_sizes:
                assert int(file_size) < file_max_size, f"Old file size {file_size} exceeds max file size {file_max_size}"

        else:
            assert 'No such file or directory' in old_file_sizes[0], "Rotated files found and were not expected."

        if 'No such file or directory' in active_file_size[0]:
            pytest.fail("{} not found!".format(file))

        assert int(active_file_size[0]) < file_max_size, \
            f"Active file size {active_file_size[0]} exceeds max file size {file_max_size}"

    # Test-level variables for test_logfile_time_option
    default_scale_factor = {'NESSUS_LOG_SCALE_FACTOR': '1'}
    dumpfile_path = path_join(path_dir_list=[log_dir, unique_filename + '.dump'])
    logfile_path = path_join(path_dir_list=[log_dir, unique_filename + '.messages'])

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': dumpfile_path, 'dumpfile_rot': 'time', 'dumpfile_rotation_time': '5',
                      'dumpfile_max_size': '2048'},
         'environment_variables': default_scale_factor, 'rotate_logs': True},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': dumpfile_path, 'dumpfile_rot': 'time', 'dumpfile_rotation_time': '365',
                      'dumpfile_max_size': '200'},
         'environment_variables': default_scale_factor, 'rotate_logs': False},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'logfile': logfile_path, 'logfile_rot': 'time', 'logfile_rotation_time': '30',
                      'logfile_max_size': '2048'},
         'environment_variables': default_scale_factor, 'rotate_logs': True},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'logfile': logfile_path, 'logfile_rot': 'time', 'logfile_rotation_time': '365',
                      'logfile_max_size': '1000'},
         'environment_variables': default_scale_factor, 'rotate_logs': False}
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3197')
    @pytest.mark.xray(test_key='SCE-3201')
    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': log_dir + 'nessusd*'}], indirect=True)
    @pytest.mark.disable_logout
    def test_logfile_time_option(self, test_data_file, delete_files, nessus_api_login,
                                 configure_advanced_settings_and_env_variables, create_scan_class):
        """
        Sets the logfile or dumpfile rotation to time and a given size value, then creates and launches a scan,
        verifying that if the time limit is exceeded for a logfile or dumpfile log rotation creates a new file.
        """
        rotation_time = None
        file = None

        # Unpack variables from the test_data_file
        rotation_scale_factor = int(test_data_file['environment_variables']['NESSUS_LOG_SCALE_FACTOR'])
        if 'logfile' in test_data_file['settings'].keys():
            file = test_data_file['settings']['logfile']
            rotation_time = int(test_data_file['settings']['logfile_rotation_time'])
        elif 'dumpfile' in test_data_file['settings'].keys():
            file = test_data_file['settings']['dumpfile']
            rotation_time = int(test_data_file['settings']['dumpfile_rotation_time'])
        else:
            pytest.fail("Logfile or dumpfile not found in test_data_file['settings']")
        rotate_logs = test_data_file['rotate_logs']

        logfile_scan = create_scan_class
        scan_exists = logfile_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        if rotate_logs:
            sleep(sleep_time=rotation_time + TIME_FIVE_SECONDS, reason="Waiting for log rotation",
                  interval=TIME_FIVE_SECONDS)
        else:
            sleep(sleep_time=TIME_THIRTY_SECONDS, reason="Waiting to ensure log rotation doesn't happen.",
                  interval=TIME_FIVE_SECONDS)

        logfile_scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert logfile_scan.scan_result, "Scan failed to complete."

        last_modified = get_command(operation='last_modified')
        with SSH() as ssh:
            active_file_last_mod_date = ssh.execute(f"{last_modified.format(file)}")[0][:-16]
            old_file_last_mod_dates = ssh.execute(f"{last_modified.format(file + '.*')}")

        if 'No such file or directory' in active_file_last_mod_date[0]:
            pytest.fail("{} not found!".format(file))

        if rotate_logs:

            if "No such file or directory" in old_file_last_mod_dates:
                pytest.fail("Rotated logs were not found")

            active_file_last_mod_date = datetime.strptime(active_file_last_mod_date, "%Y-%m-%d %H:%M:%S")
            active_difference = active_file_last_mod_date - datetime.strptime(old_file_last_mod_dates[-1][:-16],
                                                                              "%Y-%m-%d %H:%M:%S")

            rotation_time_delta = timedelta(seconds=int(rotation_time) * rotation_scale_factor)

            assert active_difference >= rotation_time_delta, \
                f"File mod date difference of {active_difference} does not exceed rotation time {rotation_time_delta}"

            last_date = None
            for mod_date in old_file_last_mod_dates:
                mod_date = datetime.strptime(mod_date[:-16], "%Y-%m-%d %H:%M:%S")
                if last_date is not None:
                    old_mod_date_difference = mod_date - last_date
                    assert old_mod_date_difference >= rotation_time_delta, \
                        f"Old rotated logs do not have a mod date difference exceeding {rotation_time_delta}"
                last_date = mod_date

        else:
            assert 'No such file or directory' in old_file_last_mod_dates[0], \
                "Rotated files found and were not expected."

    # Test-level variables for test_logfile_max_files_option
    default_scale_factor = {'NESSUS_LOG_SCALE_FACTOR': '1'}
    dumpfile_path = path_join(path_dir_list=[log_dir, unique_filename + '.dump'])
    logfile_path = path_join(path_dir_list=[log_dir, unique_filename + '.messages'])

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': dumpfile_path, 'dumpfile_rot': 'time', 'dumpfile_rotation_time': '1',
                      'dumpfile_max_files': '1000'},
         'environment_variables': default_scale_factor, 'reach_max_files': False},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': dumpfile_path, 'dumpfile_rot': 'size', 'dumpfile_max_size': '1',
                      'dumpfile_max_files': '1000'},
         'environment_variables': default_scale_factor, 'reach_max_files': False},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': dumpfile_path, 'dumpfile_rot': 'time', 'dumpfile_rotation_time': '1',
                      'dumpfile_max_files': '3'},
         'environment_variables': default_scale_factor, 'reach_max_files': True},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': dumpfile_path, 'dumpfile_rot': 'size', 'dumpfile_max_size': '1',
                      'dumpfile_max_files': '3'},
         'environment_variables': default_scale_factor, 'reach_max_files': True},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'dumpfile': dumpfile_path, 'dumpfile_rot': 'time', 'dumpfile_rotation_time': '1',
                      'dumpfile_max_files': '1000'},
         'environment_variables': default_scale_factor, 'reach_max_files': False},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'logfile': logfile_path, 'logfile_rot': 'size', 'logfile_max_size': '2048',
                      'logfile_max_files': '1000'},
         'environment_variables': default_scale_factor, 'reach_max_files': False},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'logfile': logfile_path, 'logfile_rot': 'time', 'logfile_rotation_time': '1',
                      'logfile_max_files': '3'},
         'environment_variables': default_scale_factor, 'reach_max_files': True},
        {'scan_json_path': log_rotation_scan_data['scan_json_path'], 'scan_type': log_rotation_scan_data['scan_type'],
         'settings': {'logfile': logfile_path, 'logfile_rot': 'size', 'logfile_max_size': '1',
                      'logfile_max_files': '3'},
         'environment_variables': default_scale_factor, 'reach_max_files': True},
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3196')
    @pytest.mark.xray(test_key='SCE-3200')
    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': log_dir + 'nessusd*'}], indirect=True)
    @pytest.mark.disable_logout
    def test_logfile_max_files_option(self, test_data_file, delete_files, nessus_api_login,
                                      configure_advanced_settings_and_env_variables, create_scan_class):
        """
        Sets the logfile or dumpfile rotation to time and a given size value, then creates and launches a scan,
        verifying that if the time limit is exceeded for a logfile or dumpfile log rotation creates a new file.
        """
        file = None
        max_files = None

        # Unpack variables from the test_data_file
        if 'logfile' in test_data_file['settings'].keys():
            file = test_data_file['settings']['logfile']
            max_files = int(test_data_file['settings']['logfile_max_files'])
        elif 'dumpfile' in test_data_file['settings'].keys():
            file = test_data_file['settings']['dumpfile']
            max_files = int(test_data_file['settings']['dumpfile_max_files'])
        else:
            pytest.fail("Logfile or dumpfile not found in test_data_file['settings']")
        reach_max_files = test_data_file['reach_max_files']

        logfile_scan = create_scan_class
        scan_exists = logfile_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        logfile_scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert logfile_scan.scan_result, "Scan failed to complete."

        get_file_size = get_command(operation='get_file_size')
        with SSH() as ssh:
            active_file_size = ssh.execute(f"{get_file_size.format(file)}")
            old_file_sizes = ssh.execute(f"{get_file_size.format(file + '.*')}")

        if 'No such file or directory' in active_file_size[0]:
            pytest.fail("{} not found!".format(file))

        if reach_max_files:
            assert len(active_file_size) + len(old_file_sizes) == max_files, \
                f"Expected a maximum of {max_files} rotated files, but {len(old_file_sizes)} were found"
        else:
            assert len(active_file_size) + len(old_file_sizes) < max_files, \
                f"Expected rotated files to be fewer than {max_files}, but {len(old_file_sizes)} were found"

    @pytest.mark.parametrize('test_data_file', [
        {'settings': {'dumpfile_rot': 'cookies'}, 'error_type': 'invalid'},
        {'settings': {'dumpfile_rot': '1234'}, 'error_type': 'invalid'},
        {'settings': {'dumpfile_max_size': '0'}, 'error_type': 'minimum'},
        {'settings': {'dumpfile_max_size': '2049'}, 'error_type': 'maximum', 'max_size': '2048'},
        {'settings': {'dumpfile_max_size': 'cookies'}, 'error_type': 'minimum'},
        {'settings': {'dumpfile_rotation_time': '0'}, 'error_type': 'minimum'},
        {'settings': {'dumpfile_rotation_time': '366'}, 'error_type': 'maximum', 'max_size': '365'},
        {'settings': {'dumpfile_rotation_time': 'cookies'}, 'error_type': 'minimum'},
        {'settings': {'dumpfile_max_files': '0'}, 'error_type': 'minimum'},
        {'settings': {'dumpfile_max_files': '1001'}, 'error_type': 'maximum', 'max_size': '1000'},
        {'settings': {'dumpfile_max_files': 'cookies'}, 'error_type': 'minimum'},
        {'settings': {'logfile_rot': 'cookies'}, 'error_type': 'invalid'},
        {'settings': {'logfile_rot': '1234'}, 'error_type': 'invalid'},
        {'settings': {'logfile_max_size': '0'}, 'error_type': 'minimum'},
        {'settings': {'logfile_max_size': '2049'}, 'error_type': 'maximum', 'max_size': '2048'},
        {'settings': {'logfile_max_size': 'cookies'}, 'error_type': 'minimum'},
        {'settings': {'logfile_rotation_time': '0'}, 'error_type': 'minimum'},
        {'settings': {'logfile_rotation_time': '366'}, 'error_type': 'maximum', 'max_size': '365'},
        {'settings': {'logfile_rotation_time': 'cookies'}, 'error_type': 'minimum'},
        {'settings': {'logfile_max_files': '0'}, 'error_type': 'minimum'},
        {'settings': {'logfile_max_files': '1001'}, 'error_type': 'maximum', 'max_size': '1000'},
        {'settings': {'logfile_max_files': 'cookies'}, 'error_type': 'minimum'}
    ], indirect=True)
    @pytest.mark.parametrize('configure_advanced_settings_and_env_variables', [{'restart': False}], indirect=True)
    @pytest.mark.disable_logout
    def test_logfile_option_boundaries(self, test_data_file, configure_advanced_settings_and_env_variables):
        """
        Sets the logfile or dumpfile rotation to size and a given size value, then creates and launches a scan,
        verifying that if the size limit is exceeded for a logfile or dumpfile log rotation creates a new file.
        """

        file_type = None
        expected_error = None
        setting = None
        setting_type = None

        settings_output, env_vars_output = configure_advanced_settings_and_env_variables
        max_size = test_data_file['max_size'] if 'max_size' in test_data_file.keys() else None

        for key in test_data_file['settings'].keys():
            setting = key

        # Building expected error variables
        if 'dumpfile' in setting:
            file_type = 'Dump File'
        elif 'logfile' in setting:
            file_type = 'Scanner Log'
        else:
            pytest.fail("Unexpected setting, no expected error setup!")

        if 'max_size' in setting:
            setting_type = 'Max Size'
        elif 'rotation_time' in setting:
            setting_type = 'Rotation Time'
        elif 'max_files' in setting:
            setting_type = 'Max Files'

        # Building expected error message
        if test_data_file['error_type'] == 'invalid':
            expected_error = f"Can not set '{setting}': Allowable values for Nessus {file_type} " \
                             f"Rotation Type are: size, time"
        elif test_data_file['error_type'] == 'minimum':
            expected_error = f"Can not set '{setting}': Minimum value for Nessus {file_type} {setting_type} is 1"
        elif test_data_file['error_type'] == 'maximum':
            expected_error = f"Can not set '{setting}': Maximum value for Nessus {file_type} {setting_type} is " \
                             f"{max_size}"
        else:
            pytest.fail("Unexpected error type, no expected error setup!")

        assert expected_error in settings_output[0]['stdout'], f"Received output: {settings_output[0]}, " \
                                                               f"{expected_error} was expected."
