"""
Test to verify various scan notes
:copyright: Tenable Network Security, 2023
:created: May 15, 2023
:author: @stellex
"""
import os
from os.path import exists

import pytest
import datetime
import platform
import re

from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_FIVE_MINUTES, TIME_FIVE_SECONDS, TIME_FIFTEEN_MINUTES
from catium.lib.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli import fix
from nessus.helpers.plugins import Plugin
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.config import NessusConfig
from nessus.helpers.nessus_db import ScanDB
from nessus.helpers.nessuscli.helper import path_join, get_nessus_var_dir, set_nessus_env_variables, get_command, \
    stop_nessus, start_nessus, get_nessus_plugin_dir
from nessus.lib.const import API


@pytest.mark.nessus_engine
class TestScanDB:
    """
    Tests for Scan DB and realted files created after a scan executes.
    """

    # Setup test variables
    cat = None

    password_sanitization_test_data = {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_scan_db_password_sanitization.json')),
                                       'scan_type': 'advanced'}

    db_decrypt = {"file_path": get_nessus_var_dir(), "file_name": f"nessusdbDecrypt_{NessusConfig.CAT_NESSUS_PLATFORM}_amd64",
                  "cleanup_file": True}

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [{'scan_json_path': password_sanitization_test_data['scan_json_path'],
                                                 'scan_type': password_sanitization_test_data['scan_type']}], indirect=True)
    @pytest.mark.xray(test_key='SCE-3557')
    @pytest.mark.parametrize('add_test_file', [db_decrypt], indirect=True)
    def test_password_sanitization(self, nessus_api_login, test_data_file, add_test_file, create_scan_class):
        """
        Creates a scan that contains password data, executes the scan, then ensures the password data is sanitized in
        the resulting Scan DB
        """

        # Get Scan related information for newly created scan and verify its 200 response
        password_sanitization_scan = create_scan_class
        scan_exists = password_sanitization_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        password_sanitization_scan.launch_scan()

        # Verify scan is pass or fail to complete
        assert password_sanitization_scan.scan_result, "Scan failed to complete."

        password_sanitization_scan.get_scan_details()

        scan_uuid = password_sanitization_scan.scan_details['info']['uuid']
        scan_user_id = NessusConfig.CAT_USERNAME
        var_directory = get_nessus_var_dir()

        scan_db_path = path_join([var_directory, "users", scan_user_id, "reports", scan_uuid])

        scan_db = ScanDB(db_path=scan_db_path, decrypt=False, connect=False)
        decrypted_db_name = scan_db_path + "_decrypted.db"
        scan_db.decrypt_db(output_file_path=decrypted_db_name, decrypt_file_path=add_test_file, key="",
                           master_key=True, execute_locally=False)

        with SSH() as ssh:
            query_output = ssh.execute(command=f"""sqlite3 {decrypted_db_name} \"select * from SETTINGS where SETTINGS.key like '%[password]%' AND SETTINGS.value != ''\"""")

        assert "Login configurations[password]:FTP password (sent in clear) :|********" in query_output[0]
        assert "Login configurations[password]:SMB password :|********" in query_output[1]

    scan_coverage_cache_common_data = {'scan_json_path': get_file_path('nessus/tests/engine/scan/test_data/test_scan_coverage_cache.json'),
                                       'scan_type': 'advanced'}

    scan_coverage_cache_test_cases = [
        {'environment_variable_1': None, 'environment_variable_2': 'NESSUS_QA_BASELINE_SCAN'} | scan_coverage_cache_common_data,
        {'environment_variable_1': None, 'environment_variable_2': 'NESSUS_QA_DIFFERENTIAL_SCAN'} | scan_coverage_cache_common_data,
        {'environment_variable_1': 'NESSUS_QA_BASELINE_SCAN', 'environment_variable_2': 'NESSUS_QA_BASELINE_SCAN'} | scan_coverage_cache_common_data,
        {'environment_variable_1': 'NESSUS_QA_BASELINE_SCAN', 'environment_variable_2': 'NESSUS_QA_DIFFERENTIAL_SCAN'} | scan_coverage_cache_common_data,
        {'environment_variable_1': 'NESSUS_QA_DIFFERENTIAL_SCAN', 'environment_variable_2': 'NESSUS_QA_BASELINE_SCAN'} | scan_coverage_cache_common_data,
        {'environment_variable_1': 'NESSUS_QA_DIFFERENTIAL_SCAN', 'environment_variable_2': 'NESSUS_QA_DIFFERENTIAL_SCAN'} | scan_coverage_cache_common_data,
        {'environment_variable_1': 'NESSUS_QA_BASELINE_SCAN', 'environment_variable_2': None} | scan_coverage_cache_common_data,
        {'environment_variable_1': 'NESSUS_QA_DIFFERENTIAL_SCAN', 'environment_variable_2': None} | scan_coverage_cache_common_data
    ]

    cov_state_file_path = path_join([get_nessus_var_dir(), "cov_state.bin"])

    @pytest.mark.xray(test_key='SCE-3635')
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': cov_state_file_path}], indirect=True)
    @pytest.mark.parametrize('test_data_file', scan_coverage_cache_test_cases, indirect=True)
    def test_scan_coverage_cache(self, enable_qa_mode_in_nessus, delete_files, nessus_api_login, test_data_file,
                                 create_scan_class):
        env_var_1 = test_data_file['environment_variable_1']
        env_var_2 = test_data_file['environment_variable_2']

        stop_nessus()
        set_nessus_env_variables(environment_variables={"NESSUS_QA_BASELINE_SCAN": "True"}, restart=False, set_variable=False)
        set_nessus_env_variables(environment_variables={"NESSUS_QA_DIFFERENTIAL_SCAN": "True"}, restart=False, set_variable=False)
        if env_var_1 is not None:
            set_nessus_env_variables(environment_variables={env_var_1: "True"}, restart=True)
        start_nessus()

        scan_coverage_cache_scan = create_scan_class
        scan_coverage_cache_scan.wait_for_scanner(login=True)

        try:
            scan_exists = scan_coverage_cache_scan.scan_state()

            assert scan_exists, 'Failed to create scan'

            scan_start = datetime.datetime.now()
            scan_coverage_cache_scan.launch_scan()

            # Verify scan is pass or fail to complete
            assert scan_coverage_cache_scan.scan_result, "Scan failed to complete."

            var_dir = get_nessus_var_dir()
            cov_state_path = path_join([var_dir, "cov_state.bin"])
            file_info_command = get_command(operation="file_created_date").format(cov_state_path)

            with SSH() as ssh:
                created_date_output = ssh.execute(command=file_info_command)

            # Validating created date or that file does not exist
            if env_var_1 is not None:
                created_date = datetime.datetime.strptime(re.sub(r"\..*", "", created_date_output[0]), "%Y-%m-%d %H:%M:%S")
                assert created_date > scan_start
            else:
                assert "No such file or directory" in created_date_output[0]

            stop_nessus()
            if env_var_1 is not None:
                set_nessus_env_variables(environment_variables={env_var_1: "True"}, restart=False, set_variable=False)
            if env_var_2 is not None:
                set_nessus_env_variables(environment_variables={env_var_2: "True"}, restart=False, set_variable=True)
            start_nessus()

            scan_coverage_cache_scan.wait_for_scanner(login=True)
            scan_start = datetime.datetime.now()
            scan_coverage_cache_scan.launch_scan()

            # Verify scan is pass or fail to complete
            assert scan_coverage_cache_scan.scan_result, "Scan failed to complete."

            with SSH() as ssh:
                created_date_output = ssh.execute(command=file_info_command)

            # Validating created date or that file does not exist
            created_date = datetime.datetime.strptime(re.sub(r"\..*", "", created_date_output[0]), "%Y-%m-%d %H:%M:%S")
            if env_var_2 is not None:
                assert created_date > scan_start
            else:
                assert created_date < scan_start

        finally:
            stop_nessus()
            set_nessus_env_variables(environment_variables={"NESSUS_QA_BASELINE_SCAN": "True"}, restart=False, set_variable=False)
            set_nessus_env_variables(environment_variables={"NESSUS_QA_DIFFERENTIAL_SCAN": "True"}, restart=False, set_variable=False)
            start_nessus()
            scan_coverage_cache_scan.wait_for_scanner()

    scan_coverage_db_common_data = {'scan_json_path': get_file_path('nessus/tests/engine/scan/test_data/test_scan_coverage_db.json'),
                                    'scan_type': 'advanced', 'create_scan': False, 'settings': {'nasl_no_signature_check': 'yes'}}

    db_decrypt = {"file_path": './scripts/db/', "file_name": f"nessusdbDecrypt_{platform.system().lower()}_amd64",
                  "cleanup_file": True, "execute_locally": True}

    scan_coverage_db_test_cases = [
        {'environment_variables': {'NESSUS_QA_BASELINE_SCAN': 1}, "scan_2_expected_plugins": [945001, 945002, 945003, 945004, 945007, 945008]} | scan_coverage_db_common_data,
        {'environment_variables': None, "scan_2_expected_plugins": [945001, 945002, 945003, 945004, 945007, 945008]} | scan_coverage_db_common_data,
        {'environment_variables': {'NESSUS_QA_DIFFERENTIAL_SCAN': 1}, "scan_2_expected_plugins": [945001, 945002, 945004, 945007, 945008]} | scan_coverage_db_common_data
    ]

    @pytest.mark.xray(test_key='SCE-3643')
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('delete_files', [{'file_pattern_to_delete': cov_state_file_path}], indirect=True)
    @pytest.mark.parametrize('test_data_file', scan_coverage_db_test_cases, indirect=True)
    @pytest.mark.parametrize('add_test_file', [db_decrypt], indirect=True)
    def test_scan_coverage_db(self, enable_qa_mode_in_nessus, configure_advanced_settings_and_env_variables,
                              add_test_file, delete_files, nessus_api_login, test_data_file, create_scan_class):
        # Map test_data_file to variables
        scan_2_expected_plugins = test_data_file["scan_2_expected_plugins"]
        if test_data_file['environment_variables'] is not None:
            differential_scan_type = 'baseline' if 'BASELINE' in list(test_data_file['environment_variables'].keys())[0] else 'differential'
        else:
            differential_scan_type = None

        # Create and compile custom plugins for test
        info_text = 'security_note'
        low_text = 'security_low'
        medium_text = 'security_warning'
        high_text = 'security_hole'
        critical_text = 'security_critical'
        plugin_line_1 = 'if (!file_exists(\\"{}\\"))'
        plugin_line_2 = '    {}(port:0, extra:\\"This is vulnerable\\");'
        plugin_list = []

        try:
            i = 1
            # Creating 8 info-level plugins to cover all vulnerable/not vulnerable/not in scan combinations desired
            while i < 9:
                working_plugin = Plugin(filename=f"test_plugin_{i}.nasl", name=f"Fake Plugin {i}",
                                        plugin_family=f"Fake Plugins {i}", script_id=945000 + i,
                                        description="Reports back a vulnerability if a certain file exists in the "
                                                    "plugin directory")
                working_plugin.add_lines_to_plugin_file(lines=[plugin_line_1.format(f"test_file_{i}.txt"), plugin_line_2.format(info_text)])
                plugin_list.append(working_plugin)
                i += 1
            # Creating two scans at each severity level above info - one to be vulnerable and one to be not vulnerable
            severity_list = [low_text, medium_text, high_text, critical_text]
            for severity in severity_list:
                j = 0
                while j < 2:
                    working_plugin = Plugin(filename=f"test_plugin_{i}.nasl", name=f"Fake Plugin {i}",
                                            plugin_family=f"Fake Plugins {i}", script_id=945000 + i,
                                            description="Reports back a vulnerability if a certain file exists in the "
                                                        "plugin directory")
                    working_plugin.add_lines_to_plugin_file(lines=[plugin_line_1.format(f"test_file_{i}.txt"), plugin_line_2.format(severity)])
                    plugin_list.append(working_plugin)
                    i += 1
                    j += 1

            plugin_list[0].compile_plugin()

            # Create test files to trigger each plugin to be in the correct starting vulnerable/not vulnerable state
            test_file_list = ["test_file_2.txt", "test_file_4.txt", "test_file_6.txt", "test_file_10.txt",
                              "test_file_12.txt", "test_file_14.txt", "test_file_16.txt"]
            with SSH() as ssh:
                create_file_command = get_command("create_file")
                for file in test_file_list:
                    ssh.execute(command=create_file_command.format(path_join([get_nessus_plugin_dir(), file])))

            # Creating and launching scan
            scan_coverage_db_scan = create_scan_class
            scan_coverage_db_scan.wait_for_scanner(login=True)
            scan_coverage_db_scan.create_scan()
            scan_coverage_db_scan.launch_scan()

            # export the scan (this validates the export completed)
            export_details = scan_coverage_db_scan.export_scan(export_format=API.Scan.ExportFormats.FORMAT_DB, password='sapphire')
            assert re.findall('^[0-9a-f]{64}$', export_details['uuid']), 'Scan export failed'

            # pull down the exported file
            scan_coverage_db_scan.download_scan(filename=export_details['uuid'], output_directory='./output')
            # db_path=f"/tmp/{export_details['uuid']}.db"
            assert exists(scan_coverage_db_scan.export_file_name), "Unable to locate downloaded exported scan file"

            scan_coverage_db = ScanDB(db_path=f"./output/{export_details['uuid']}.db", decrypt=True, connect=True)

            pragma_query = "PRAGMA table_info(ScanCoverage)"
            scan_coverage_db.load_custom_query(pragma_query)
            scan_coverage_db.execute_query()

            # Validate ScanCoverage table has the correct columns

            assert len(scan_coverage_db.result) == 7, "Incorrect number of columns exist in the ScanCoverage table"
            assert scan_coverage_db.result[0][1] == "host_id", f"Column 1 does not equal host_id, instead it is {scan_coverage_db.result[0][1]}"
            assert scan_coverage_db.result[1][1] == "plugin", f"Column 1 does not equal plugin, instead it is {scan_coverage_db.result[1][1]}"
            assert scan_coverage_db.result[2][1] == "exit_code", f"Column 1 does not equal exit_code, instead it is {scan_coverage_db.result[2][1]}"
            assert scan_coverage_db.result[3][1] == "audit_code", f"Column 1 does not equal audit_code, instead it is {scan_coverage_db.result[3][1]}"
            assert scan_coverage_db.result[4][1] == "completion_status", f"Column 1 does not equal completion_status, instead it is {scan_coverage_db.result[4][1]}"
            assert scan_coverage_db.result[5][1] == "time_begin", f"Column 1 does not equal time_begin, instead it is {scan_coverage_db.result[5][1]}"
            assert scan_coverage_db.result[6][1] == "time_end", f"Column 1 does not equal time_end, instead it is {scan_coverage_db.result[6][1]}"

            # Query for ScanCoverage table data for test plugins
            scan_coverage_query = "SELECT * FROM ScanCoverage WHERE plugin >= 945000 AND plugin <=945016"
            scan_coverage_db.load_custom_query(scan_coverage_query)
            scan_coverage_db.execute_query()

            """Validate ScanCoverage query result is correct. Since this is a baseline scan for differential too, all
            are expected here unless this is neither baseline nor differential"""
            scan_1_expected_plugins = [945001, 945002, 945003, 945004, 945005, 945006, 945009, 945010, 945011, 945012,
                                       945013, 945014, 945015, 945016]

            # Check if this is a baseline/differential scan or not, if it is assert data is in the query result
            if test_data_file['environment_variables'] is not None:
                assert len(scan_coverage_db.result) == len(scan_1_expected_plugins), f"Expected " \
                    f"{len(scan_1_expected_plugins)} plugins in ScanCoverage table result, found {len(scan_coverage_db.result)} instead."

                i = 0
                for expected_plugin in scan_1_expected_plugins:
                    row = scan_coverage_db.result[i]

                    assert row[0] == 2, "host_id does not have the correct value in the ScanCoverage table"
                    assert row[1] == expected_plugin, "plugin does not have the correct value in the ScanCoverage table"
                    assert row[2] == 0, "exit_code does not have the correct value in the ScanCoverage table"
                    assert row[3] == -1, "audit_code does not have the correct value in the ScanCoverage table"
                    assert row[4] == 0, "completion_status does not have the correct value in the ScanCoverage table"
                    assert len(str(row[5])) == 10, "time_begin does not have the correct value in the ScanCoverage table, based on the value's length"
                    assert len(str(row[6])) == 10, "time_end does not have the correct value in the ScanCoverage table, based on the value's length"

                    i += 1
            else:
                # If this is not a baseline or differential scan, ScanCoverage should be empty
                assert scan_coverage_db.result == [], "ScanCoverage table was expected to be empty but was not"

            scan_hostags_query = "SELECT tag_name, tag_value FROM HostTags JOIN TagNames ON tag_name_id = TagNames.id JOIN TagValues ON tag_value_id = TagValues.id WHERE tag_name = 'differential_scan'"
            scan_coverage_db.load_custom_query(scan_hostags_query)
            scan_coverage_db.execute_query()

            # Asserting differential_scan HostTag is correct
            if differential_scan_type is not None:
                assert len(scan_coverage_db.result) == 1, "More than one differential_scan tag was found"
                assert scan_coverage_db.result[0][0] == "differential_scan", "differential_scan tag has an incorrect name"
                assert scan_coverage_db.result[0][1] == "baseline", f"differential_scan tag does not have a value of '{differential_scan_type}'"
            else:
                assert len(scan_coverage_db.result) == 0, "A differential_scan tag was found and should not have been"

            # Enabling/disabling certain test plugins for second scan
            scan_coverage_db_scan.update_scan_plugins({"Fake Plugins 5": "disabled", "Fake Plugins 6": "disabled",
                                                       "Fake Plugins 7": "enabled", "Fake Plugins 8": "enabled"})

            # Create/remove test files to trigger plugins to be in the correct ending vulnerable/not vulnerable state
            create_file_list = ["test_file_1.txt", "test_file_4.txt", "test_file_8.txt"]
            remove_file_list = ["test_file_2.txt", "test_file_3.txt", "test_file_7.txt"]
            with SSH() as ssh:
                remove_file_command = get_command("remove_file")
                for file in remove_file_list:
                    ssh.execute(command=remove_file_command + " " + path_join([get_nessus_plugin_dir(), file]), sudo=True)
                for file in create_file_list:
                    ssh.execute(command=create_file_command.format(path_join([get_nessus_plugin_dir(), file])))

            scan_coverage_db_scan.launch_scan()

            # Verify scan is pass or fail to complete
            assert scan_coverage_db_scan.scan_result, "Scan failed to complete."

            # export the scan (this validates the export completed)
            export_details = scan_coverage_db_scan.export_scan(export_format=API.Scan.ExportFormats.FORMAT_DB, password='sapphire')
            assert re.findall('^[0-9a-f]{64}$', export_details['uuid']), 'Scan export failed'

            # pull down the exported file
            scan_coverage_db_scan.download_scan(filename=export_details['uuid'], output_directory='./output')
            # db_path=f"/tmp/{export_details['uuid']}.db"
            assert exists(scan_coverage_db_scan.export_file_name), "Unable to locate downloaded exported scan file"

            # Query for ScanCoverage table data for test plugins
            scan_coverage_db = ScanDB(db_path=f"./output/{export_details['uuid']}.db", decrypt=True, connect=True)
            scan_coverage_db.load_custom_query(scan_coverage_query)
            scan_coverage_db.execute_query()

            """Pulling variable expected plugins from test_data_file and adding non-info level plugins which should be
            the same across test cases"""
            scan_2_expected_plugins.extend([945009, 945010, 945011, 945012, 945013, 945014, 945015, 945016])

            # Check if this is a baseline/differential scan or not, if it is assert data is in the query result
            if test_data_file['environment_variables'] is not None:
                assert len(scan_coverage_db.result) == len(scan_2_expected_plugins), f"Expected " \
                    f"{len(scan_2_expected_plugins)} plugins in ScanCoverage table result, found " \
                    f"{len(scan_coverage_db.result)} instead."

                i = 0
                for expected_plugin in scan_2_expected_plugins:
                    row = scan_coverage_db.result[i]
                    assert row[0] == 2, "host_id does not have the correct value in the ScanCoverage table"
                    assert row[1] == expected_plugin, "plugin does not have the correct value in the ScanCoverage table"
                    assert row[2] == 0, "exit_code does not have the correct value in the ScanCoverage table"
                    assert row[3] == -1, "audit_code does not have the correct value in the ScanCoverage table"
                    assert row[4] == 0, "completion_status does not have the correct value in the ScanCoverage table"
                    assert len(str(row[5])) == 10, "time_begin does not have the correct value in the ScanCoverage table, based on the value's length"
                    assert len(str(row[6])) == 10, "time_end does not have the correct value in the ScanCoverage table, based on the value's length"
                    i += 1
            else:
                # If this is not a baseline or differential scan, ScanCoverage should be empty
                assert scan_coverage_db.result == [], "ScanCoverage table was expected to be empty but was not"

            scan_hostags_query = "SELECT tag_name, tag_value FROM HostTags JOIN TagNames ON tag_name_id = TagNames.id JOIN TagValues ON tag_value_id = TagValues.id WHERE tag_name = 'differential_scan'"
            scan_coverage_db.load_custom_query(scan_hostags_query)
            scan_coverage_db.execute_query()

            # Asserting differential_scan HostTag is correct
            if differential_scan_type is not None:
                assert len(scan_coverage_db.result) == 1, "More than one differential_scan tag was found"
                assert scan_coverage_db.result[0][0] == "differential_scan", "differential_scan tag has an incorrect name"
                assert scan_coverage_db.result[0][1] == differential_scan_type, f"differential_scan tag does not have a value of '{differential_scan_type}'"
            else:
                assert len(scan_coverage_db.result) == 0, "A differential_scan tag was found and should not have been"

        finally:
            # Removing baseline/differential environment variables
            set_nessus_env_variables(environment_variables={"NESSUS_QA_BASELINE_SCAN": "True"}, restart=False, set_variable=False)
            set_nessus_env_variables(environment_variables={"NESSUS_QA_DIFFERENTIAL_SCAN": "True"}, restart=False, set_variable=False)

            # Removing test NASL and .txt files
            remove_file_command = get_command("remove_file")
            with SSH() as ssh:
                i = 1
                for plugin in plugin_list:
                    ssh.execute(command=remove_file_command + " " + path_join([plugin.plugin_directory, plugin.filename]), sudo=True)
                    ssh.execute(command=remove_file_command + " " + path_join([plugin.plugin_directory, f"test_file_{i}.txt"]), sudo=True)
                    i += 1

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('plugin_metadata_setting', ['yes', 'no'])
    @pytest.mark.parametrize('add_test_file', [db_decrypt], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': (get_file_path('nessus/tests/engine/scan/test_data/test_disable_plugin_metadata.json')),
         'scan_type': 'advanced'}
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3631')
    def test_disable_plugin_metadata(self, test_data_file, add_test_file, nessus_api_login, create_scan_class, plugin_metadata_setting):
        """
        Creates a scan designed to generate a particular scan note text then verifies text is correct.
        """

        # Get Scan related information for newly created scan and verify its 200 response

        scan = create_scan_class
        scan_exists = scan.scan_state()
        assert scan_exists, 'Failed to create scan'

        # Stopping Nessus, setting preference, then restarting Nessus to ensure it takes effect
        stop_nessus()
        fix.set(key="report.prune_plugin_attributes", value=plugin_metadata_setting, sudo=NessusConfig.CAT_SSH_USE_SUDO)
        start_nessus()
        api = NessusAPI()
        wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                sleep_interval=TIME_FIVE_SECONDS, msg='Wait for loading')
        wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES,
                                sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')
        scan.api = api
        scan.api.login()

        export_details = None
        try:
            # Launching the scan
            scan.launch_scan()

            # Verify scan is pass or fail to complete
            assert scan.scan_result, "Scan failed to complete."

            # export the scan (this validates the export completed)
            export_details = scan.export_scan(export_format=API.Scan.ExportFormats.FORMAT_DB, password='sapphire')
            assert re.findall('^[0-9a-f]{64}$', export_details['uuid']), 'Scan export failed'

            # pull down the exported file
            scan.download_scan(filename=export_details['uuid'], output_directory='./output')
            # db_path=f"/tmp/{export_details['uuid']}.db"
            assert exists(scan.export_file_name), "Unable to locate downloaded exported scan file"

            scan_db = ScanDB(db_path=f"./output/{export_details['uuid']}.db", decrypt=True, connect=True)

            # Execute query to determine if there is data in the PluginAttributes table
            plugin_attributes_query = "SELECT * FROM PluginAttributes"
            scan_db.load_custom_query(plugin_attributes_query)
            scan_db.execute_query()

            # Validate if there is/isn't data in PluginAttributes depending on what we expect
            if plugin_metadata_setting == 'yes':
                assert len(scan_db.result) <= 0, "No records found in PluginAttributes table when report.prune_plugin_attributes was set to no"
            else:
                assert len(scan_db.result) > 0, "Records found in PluginAttributes table when report.prune_plugin_attributes was set to yes"
        finally:
            # Cleaning up, removing the preference, and removing DB files
            stop_nessus()
            fix.delete(key="report.prune_plugin_attributes", sudo=NessusConfig.CAT_SSH_USE_SUDO)
            start_nessus()
            api = NessusAPI()
            wait_for_scanner_status(api=api, status=API.Status.LOADING, timeout=TIME_FIVE_MINUTES,
                                    sleep_interval=TIME_FIVE_SECONDS, msg='Wait for loading')
            wait_for_scanner_status(api=api, status=API.Status.READY, timeout=TIME_FIFTEEN_MINUTES,
                                    sleep_interval=TIME_FIVE_SECONDS, msg='Availability of Nessus scanner')
            if export_details is not None:
                os.remove(path=f"./output/{export_details['uuid']}.db")
                os.remove(path=f"./output/{export_details['uuid']}.plain.db")
