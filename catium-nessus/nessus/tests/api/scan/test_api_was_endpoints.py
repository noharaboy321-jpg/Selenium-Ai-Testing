"""
Nessus WAS Endpoints verification

:copyright: Tenable Network Security, 2023
:date: June 7, 2023
:last_modified: June 12, 2023
:author: @tkeyser, @tdavis, @xxia, @dcoppock
"""
from os.path import exists
from nessus.helpers.nessus_db import ScanDB
import platform
import re
from http import HTTPStatus
import json
import pytest
from catium.helpers.testdata import get_file_path
from catium.lib.log.log import create_logger
from nessus.lib.const import API
from nessus.helpers.nessuscli.helper import get_command, get_nessus_var_dir, get_command
import time
from nessus.lib.config import NessusConfig
from catium.lib.ssh import SSH

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.skip_nessustc
class TestWASEndpoints:

    cat = None

    scan_data = {
        'scan_json_path': (get_file_path('nessus/tests/api/scan/test_data/test_was_scan.json')),
        'scan_type': 'was_scan'
    }

    # API_Tested# POST /tools/was
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': scan_data['scan_json_path'], 'scan_type': scan_data['scan_type']}], indirect=True)
    def test_run_was_scan(self, nessus_api_login, enable_was, test_data_file, create_scan_class):

        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code
        # Get Scan related information for newly created scan and verify its 200 response
        was_scan = create_scan_class
        scan_exists = was_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        was_scan.launch_scan()
        was_scan.wait_for_scan_complete()

        # Verify scan is pass or fail to complete
        assert was_scan.scan_result, "Scan failed to complete."

    def test_disable_was(self, nessus_api_login, disable_was):
    
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': scan_data['scan_json_path'], 'scan_type': scan_data['scan_type']}], indirect=True)
    def test_restart_was_scan(self, nessus_api_login, enable_was, test_data_file, create_scan_class):

        was_scan = create_scan_class
        scan_exists = was_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        was_scan.start_scan()
        assert was_scan.scan_result, 'Failed to start scan'

        was_scan.scan_state()

        was_scan.pause_scan()
        assert was_scan.scan_result, 'Failed to pause scan'

        was_scan.resume_scan()
        assert was_scan.scan_result, 'Failed to start scan'

        # Verify scan is pass or fail to complete
        was_scan.wait_for_scan_complete()
        assert was_scan.scan_result, "Scan failed to complete."

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': scan_data['scan_json_path'], 'scan_type': scan_data['scan_type']}], indirect=True)
    def test_get_log_from_completed_scan(self, nessus_api_login, enable_was, test_data_file, create_scan_class):
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code
        was_scan = create_scan_class
        scan_exists = was_scan.scan_state()

        assert scan_exists, "Failed to create scan."

        was_scan.launch_scan()

        was_scan.get_web_scanner_plugin_attachments()
        was_scan.output = was_scan.scan_result.decode("utf-8")
        was_scan.output = json.loads(was_scan.output)
        for item in was_scan.output["outputs"][0]["ports"].keys():
            for attachment in was_scan.output["outputs"][0]["ports"][item][0]["attachments"]:
                if attachment["name"] == 'scan_logs.log':
                    assert attachment["size"] > 0, "Attachment exists but the size is 0"

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': scan_data['scan_json_path'], 'scan_type': scan_data['scan_type']}], indirect=True)
    def test_second_scan_gets_denied(self, nessus_api_login, enable_was, test_data_file, create_scan_class):

        # scan #1
        was_scan1 = create_scan_class
        scan_exists = was_scan1.scan_state()
        assert scan_exists, 'Failed to create first scan'

        was_scan1.start_scan()
        assert was_scan1.scan_result, 'Failed to start first scan'

        # scan #2
        was_scan2 = create_scan_class
        scan_exists = was_scan2.scan_state()
        assert scan_exists, 'Failed to create second scan'

        try:
            was_scan2.start_scan()
            # no exception is actually a failure for this test
            assert False, 'Second scan started; should not have happened with a scan already running'
        except Exception as e:
            # an exception is expected for this test
            print(f"Expected exception: {e}")
            assert True, 'This will never be uttered'

        # no longer need either scan
        if was_scan1:
            try:
                was_scan1.kill_scan()
            except Exception as e:
                log.error(e)
        if was_scan2:
            try:
                was_scan2.kill_scan()
            except Exception as e:
                log.error(e)


@pytest.mark.nessus_expert
@pytest.mark.skip_arm
@pytest.mark.skip(reason="Test is not ready and never passed, needs improvement as per NES-18804")
class TestWASExportDB:

    cat = None

    db_decrypt = {"file_path": './scripts/db/', "file_name": f"nessusdbDecrypt_{platform.system().lower()}_amd64",
                  "cleanup_file": True, "execute_locally": True}

    scan_data = {
        'scan_json_path': (get_file_path('nessus/tests/api/scan/test_data/test_was_scan.json')),
        'scan_type': 'was_scan'
    }

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': scan_data['scan_json_path'], 'scan_type': scan_data['scan_type']}], indirect=True)
    @pytest.mark.parametrize('add_test_file', [db_decrypt], indirect=True)
    def test_export_db(self, nessus_api_login, enable_was, test_data_file, add_test_file, create_scan_class):

        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code
        # create scan
        was_scan = create_scan_class
        scan_exists = was_scan.scan_state()
        assert scan_exists, 'Failed to create scan'

        # run the scan
        was_scan.launch_scan()
        assert was_scan.scan_result, "Scan failed to complete."

        # export the scan (this validates the export completed)
        export_details = was_scan.export_scan(export_format=API.Scan.ExportFormats.FORMAT_DB, password='sapphire')
        assert re.findall('^[0-9a-f]{64}$', export_details['uuid']), 'Scan export failed'

        # pull down the exported file
        was_scan.download_scan(filename=export_details['uuid'], output_directory='./output')
        # db_path=f"/tmp/{export_details['uuid']}.db"
        assert exists(was_scan.export_file_name), "Unable to locate downloaded exported scan file"

        time.sleep(600)

        # get the decrypted db into an object for querying
        exported_db = ScanDB(db_path=was_scan.export_file_name, decrypt=True, connect=True)
        # decrypted_db_name = db_path + "_decrypted.db"
        # exported_db.decrypt_db(output_file_path=decrypted_db_name, decrypt_file_path=add_test_file, key="",
        #                    master_key=True, execute_locally=False)

        # check for expected tables
        exported_db.load_custom_query(query="SELECT name FROM sqlite_schema WHERE type ='table' AND name NOT LIKE 'sqlite_%'")
        exported_db.execute_query()
        rows = exported_db.result
        export_tables = []
        if type(rows) == list and len(rows) > 0:
            for tup in rows:
                export_tables.append(tup[0])
        # assert that a few obvious ones exist
        for table in ["Host", "Plugins", "ScanResults"]:
            assert table in export_tables, f"Unable to detect expected table ({table}) in exported scan results"

        exported_db.load_custom_query(query="SELECT count(*) AS count FROM ScanResults")
        exported_db.execute_query()
        rows = exported_db.result
        if type(rows) == list and len(rows) == 1:
            assert rows[0][0] > 0, "No detections found in exported scan results"

