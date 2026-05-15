"""
Tests to verify FIPS settings
:copyright: Tenable Network Security, 2022
:created: September 22, 2022
:last_modified: September 22, 2022
:author: @stellex
"""
import pytest
import requests
from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_FIVE_MINUTES, TIME_FIVE_SECONDS
from catium.lib.ssh import SSH

from nessus.helpers.waiters import wait_for_scanner_status

from nessus.helpers.nessuscli.fix import set
from nessus.helpers.nessuscli.helper import get_nessus_conf_dir, stop_nessus, start_nessus, get_command, \
    get_nessus_log_dir, path_join, get_os_name
from nessus.lib.const import API, OperatingSystems


@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestFipsSettings:
    """
    Tests for FIPS mode being on/off
    """

    # Setup test variables
    cat = None
    conf_directory = get_nessus_conf_dir()
    fips_scan_data = {
        'scan_json_path': (get_file_path('nessus/tests/engine/advanced_settings/test_data/test_fips_setting.json')),
        'scan_type': 'basic'
    }

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': fips_scan_data['scan_json_path'], 'scan_type': fips_scan_data['scan_type'],
         'settings': {'niap_mode': 'enforcing'}, 'cleanup_settings': True},
        {'scan_json_path': fips_scan_data['scan_json_path'], 'scan_type': fips_scan_data['scan_type'],
         'settings': {'niap_mode': 'non-enforcing'}, 'cleanup_settings': True},
        {'scan_json_path': fips_scan_data['scan_json_path'], 'scan_type': fips_scan_data['scan_type'],
         'settings': {'fips_mode': 'enforcing'}, 'cleanup_settings': True},
        {'scan_json_path': fips_scan_data['scan_json_path'], 'scan_type': fips_scan_data['scan_type'],
         'settings': {'fips_mode': 'non-enforcing'}, 'cleanup_settings': True},
        {'scan_json_path': fips_scan_data['scan_json_path'], 'scan_type': fips_scan_data['scan_type'],
         'settings': {'niap_mode': 'enforcing', 'fips_mode': 'enforcing'}, 'cleanup_settings': True},
        {'scan_json_path': fips_scan_data['scan_json_path'], 'scan_type': fips_scan_data['scan_type'],
         'settings': {'niap_mode': 'enforcing', 'fips_mode': 'non-enforcing'}, 'cleanup_settings': True},
        {'scan_json_path': fips_scan_data['scan_json_path'], 'scan_type': fips_scan_data['scan_type'],
         'settings': {'niap_mode': 'non-enforcing', 'fips_mode': 'enforcing'}, 'cleanup_settings': True},
        {'scan_json_path': fips_scan_data['scan_json_path'], 'scan_type': fips_scan_data['scan_type'],
         'settings': {'niap_mode': 'non-enforcing', 'fips_mode': 'non-enforcing'}, 'cleanup_settings': True}
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3312')
    def test_fips_setting(self, test_data_file, configure_advanced_settings_and_env_variables, nessus_api_login,
                          create_scan_class):
        """
        Sets a combination of NIAP and FIPS settings and executes a basic scan, ensuring neither will prevent scans from
        running.
        """

        # Get Scan related information for newly created scan and verify its 200 response
        logfile_scan = create_scan_class
        scan_exists = logfile_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        logfile_scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert logfile_scan.scan_result, "Scan failed to complete."

    log_dir = get_nessus_log_dir() if get_os_name() != OperatingSystems.WINDOWS else get_nessus_log_dir() + "\\"

    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': [log_dir + 'nessusd.messages', log_dir + 'nessusd.dump'],
                                               'restart_nessus': True}], indirect=True)
    @pytest.mark.parametrize('rename_file', [{'file_path': conf_directory, 'old_file_name': 'fipsmodule.cnf',
                                              'new_file_name': 'renamedfips.cnf', 'cleanup_file': True, 'restart': True}
                                             ], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'settings': {'niap_mode': 'enforcing'}, 'login_result': 'failure', 'restart': False, 'cleanup_settings': True},
        {'settings': {'niap_mode': 'non-enforcing' }, 'login_result': 'success', 'restart': False, 'cleanup_settings': True},
        {'settings': {'fips_mode': 'enforcing'}, 'login_result': 'failure', 'restart': False, 'cleanup_settings': True},
        {'settings': {'fips_mode': 'non-enforcing'}, 'login_result': 'success', 'restart': False, 'cleanup_settings': True},
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3313')
    def test_fips_enforcement(self, test_data_file, nessus_api_login, delete_files, rename_file,
                              configure_advanced_settings_and_env_variables):
        """
        Test deletes the fips_module.conf file which will trigger a failure if in FIPS mode. Then FIPS mode is either
        activated or not, and the ttest verifies whether Nessus can be accessed or not.
        """

        os_windows = True if get_os_name() == OperatingSystems.WINDOWS else False
        os_freebsd = True if get_os_name() == OperatingSystems.FREEBSD else False

        login_result = test_data_file['login_result']

        stop_nessus()
        start_nessus()

        if login_result == 'success':
            wait_for_scanner_status(api=nessus_api_login, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                    msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)
            wait_for_scanner_status(api=nessus_api_login, status=API.Status.READY, timeout=TIME_FIVE_MINUTES,
                                    msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)

        try:
            nessus_api_login.login()
        except Exception as e:
            if type(e) == requests.exceptions.ConnectionError:
                if login_result == 'success':
                    raise e
                else:
                    display_content = get_command(operation='display_content')
                    log_dir = get_nessus_log_dir()
                    file = path_join([log_dir, 'nessusd.dump']) if not os_windows else path_join([log_dir, 'nessusd.dump']).replace("\\", "\\\\")
                    fips_line_found = False
                    sudo = False if get_os_name() in [OperatingSystems.WINDOWS, OperatingSystems.FREEBSD] else True
                    with SSH() as ssh:
                        dump_file = ssh.execute(f"{display_content} {file}", sudo=sudo)
                    for line in dump_file:
                        if 'Can not set encryption key for database: FIPS is required, but the FIPS module did not load.' in line:
                            fips_line_found = True
                            break
                    if not fips_line_found:
                        pytest.fail('FIPS text not found in nessusd.dump file')
            else:
                raise e

    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': [log_dir + 'nessusd.messages', log_dir + 'nessusd.dump'],
                                               'restart_nessus': True}], indirect=True)
    @pytest.mark.parametrize('rename_file', [{'file_path': conf_directory, 'old_file_name': 'fipsmodule.cnf',
                                              'new_file_name': 'renamedfips.cnf', 'cleanup_file': True, 'restart': True}
                                             ], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'settings': {'niap_mode': 'enforcing'}, 'test_setting': {'last_connect': 2}, 'setting_result': 'failure', 'restart': False, 'cleanup_settings': True},
        {'settings': {'niap_mode': 'non-enforcing'}, 'test_setting': {'last_connect': 2}, 'setting_result': 'success', 'restart': False, 'cleanup_settings': True},
        {'settings': {'fips_mode': 'enforcing'}, 'test_setting': {'last_connect': 2}, 'setting_result': 'failure', 'restart': False, 'cleanup_settings': True},
        {'settings': {'fips_mode': 'non-enforcing'}, 'test_setting': {'last_connect': 2}, 'setting_result': 'success', 'restart': False, 'cleanup_settings': True},
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3322')
    def test_fips_enforcement_cli(self, test_data_file, nessus_api_login, delete_files, rename_file,
                                  configure_advanced_settings_and_env_variables):
        """
        Test deletes the fips_module.conf file which will trigger a failure if in FIPS mode. Then FIPS mode is either
        activated or not, and the ttest verifies whether Nessus can be accessed or not.
        """

        os_windows = True if get_os_name() == OperatingSystems.WINDOWS else False
        os_freebsd = True if get_os_name() == OperatingSystems.FREEBSD else False

        settings = test_data_file['test_setting'].keys()
        for setting in settings:
            setting_name = setting
            setting_value = test_data_file['test_setting'][setting]
        setting_result = test_data_file['setting_result']

        stop_nessus()
        start_nessus()

        if setting_result == 'success':
            wait_for_scanner_status(api=nessus_api_login, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                    msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)
            wait_for_scanner_status(api=nessus_api_login, status=API.Status.READY, timeout=TIME_FIVE_MINUTES,
                                    msg='Availability of Nessus scanner', sleep_interval=TIME_FIVE_SECONDS)

        settings_output = []
        sudo = False if os_windows or os_freebsd else True
        output = set(setting_name, setting_value, sudo=sudo, secure=True)
        settings_output.append(output)

        if setting_result == "success":
            assert f"Successfully set '{setting_name}' to '{setting_value}'.\nThe Nessus web server will be restarted." \
                   in settings_output[0]["stdout"], "Setting was not set successfully."
            assert "Can not set encryption key for database: FIPS is required, but the FIPS module did not load." not \
                   in settings_output[0]["stderr"], "Setting did not produce expected failure message."
        else:
            assert f"Successfully set '{setting_name}' to '{setting_value}'.\nThe Nessus web server will be restarted." \
                   not in settings_output[0]["stdout"], "Setting was not set successfully."
            assert "Can not set encryption key for database: FIPS is required, but the FIPS module did not load." in \
                   settings_output[0]["stderr"], "Setting did not produce expected failure message."
