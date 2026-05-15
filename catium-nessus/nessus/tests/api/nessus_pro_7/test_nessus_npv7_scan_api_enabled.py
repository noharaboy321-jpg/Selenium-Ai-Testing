"""
:copyright: Tenable Network Security, 2018
:date: July 16, 2018
:last_modified: Mar 10, 2022
:author: @xxia, @kpanchal.ctr
"""
from http import HTTPStatus

import pytest

from catium.helpers.testdata import load_testdata, get_file_path
from catium.lib.const import TIME_THIRTY_MINUTES, TIME_FIVE_MINUTES
from catium.lib.util import random_name
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API


# copy from scan/test_nessus_scans_endpoint.py, will only run when the "scan-api-enabled" flag is 1 in license


@pytest.mark.scanning
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login', 'no_automation_api_key')
@pytest.mark.skip_pro_scan_api_disabled()
class TestNessusScanEndpointPro7WithScanApiEnabled:
    """
    Tests to make sure that Nessus Pro 7 users can use the API to work with scans when scan-api-enabled flag is 1

    Here we are just making sure the scan API is working, for detail scan API tests, please refer 
    to scan/test_nessus_scans_endpoint.py
    """

    cat = None

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_wannacry_scan.json'),
         'scan_type': 'wannacry'}], indirect=True)
    def test_create_scan(self, create_scan):
        """Creates an scan."""

        # Get Scan related information for newly created scan and verify its 200 response
        scan_id = create_scan['scan']['id']
        scans = self.cat.api.scans.get_scans()['scans']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify scan exists in list.
        assert scan_id in [scan['id'] for scan in scans], 'Failed to create scan'

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_wannacry_scan.json'),
         'scan_type': 'wannacry'}], indirect=True)
    def test_launch_scan(self, create_scan):
        """Launches a scan."""

        # Get newly created scan information
        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id,
                                 end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

        # Get scan details
        self.cat.api.scans.details(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.parametrize('scan', [{"filename": 'advance_scan_c7kspv.nessus'}, ])  # NQA-700
    def test_import_scan(self, scan):
        """Verifies scans can be imported"""
        # Import a scan and verify 200 status

        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])

        fileuploaded = self.cat.api.file.upload(file=file, encrypted=scan.get('encrypted', None))
        import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None,
                                                     password=scan.get('password', None))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get scans and verify scan was imported
        response = self.cat.api.scans.get_scans()
        new_scan = next((scan for scan in response['scans']
                         if scan['name'] == import_scan['scan']['name']),
                        None)
        assert new_scan, "Scan was not properly imported."

        # Delete the imported scan
        self.cat.api.scans.delete(import_scan['scan']['id'])

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_wannacry_scan.json'),
         'scan_type': 'wannacry'}], indirect=True)
    def test_configure_scan(self, create_scan, test_data_file):
        """Verifies the scan can be configured"""
        scan_new_name = random_name(prefix='update-scan-')

        # load payload from the json file and edit name
        payload = load_testdata(test_data_file['scan_json_path'])
        payload['settings']['name'] = scan_new_name
        payload["settings"]["folder_id"] = "3"

        self.cat.api.scans.configure(create_scan['scan']['id'], payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_org_name = self.cat.api.scans.details(create_scan['scan']['id'])['info']['name']
        assert scan_org_name == scan_new_name, \
            'Expected %s, got %s instead.' % (scan_new_name, scan_org_name)

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_wannacry_scan.json'),
         'scan_type': 'wannacry'}], indirect=True)
    def test_delete_scan(self, create_scan):

        """Verifies scan can be deleted"""

        # Get Scan ID for newly created scan
        scan_id = create_scan['scan']['id']

        # Delete scan and verify 200 response
        self.cat.api.scans.delete(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get list of scans in container
        scans = self.cat.api.scans.get_scans()['scans']

        # Verify scan no longer exists.
        if scans:
            assert scan_id not in [scan['id'] for scan in scans], 'Failed to delete scan with id %s.' % scan_id

    @pytest.mark.parametrize('scan', [{"filename": 'internal_pci_network_scan_i5jc01.nessus'},  # NQA-771
                                      {"filename": 'advance_scan_c7kspv.nessus'}])  # NQA-770
    def test_delete_history(self, scan):
        """Verifies the scan history can be deleted."""

        # Import a scan and verify 200 status
        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])
        filename = self.cat.api.file.upload(file=file)
        scan = self.cat.api.scans.import_scan(filename)['scan']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get scan details
        details = self.cat.api.scans.details(scan['id'])
        # Get history id
        history_id = details['history'][0]['history_id']

        # Delete scan history
        self.cat.api.scans.delete_history(scan['id'], history_id)

        # assert the scan history is deleted
        history = self.cat.api.scans.details(scan['id'])['history']
        assert not history, 'History was not deleted.'

        # Delete the imported scan
        self.cat.api.scans.delete(scan['id'])

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/create_scheduled_scan_daily.json'), 'scan_type': 'basic'},  # NQA-843
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/create_scheduled_scan_weekly.json'), 'scan_type': 'basic'},  # NQA-844
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/create_scheduled_scan_monthly.json'), 'scan_type': 'basic'},  # NQA-845
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/create_scheduled_scan_yearly.json'), 'scan_type': 'basic'},  # NQA-846
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/create_scheduled_scan_once.json'), 'scan_type': 'basic'}],  # NQA-842
                             indirect=True)
    def test_schedule(self, create_scan):
        """Verifies the schedule for a scan can be enabled and disabled."""

        # Get scan ID
        scan_id = create_scan['scan']['id']

        # Set schedule enabled to false and assert 200 response
        self.cat.api.scans.schedule(scan_id, enabled=True)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get scans and verify enabled is true
        scans = self.cat.api.scans.get_scans()
        scan = scans['scans']
        enabled = False
        for scanner in scan:
            if scanner['id'] == scan_id:
                enabled = scanner['enabled']

        assert enabled is True, "Expected True, got False."

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_copy_scan(self, create_scan):
        """Verifies scan can be copied"""

        # Get information from newly created ScanModel
        scan = create_scan['scan']
        scan_id = scan['id']

        # Copy scan with new name and verify 200 response
        name = random_name(prefix='copy_') + scan['name']
        response = self.cat.api.scans.copy(scan_id, name=name)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get list of scans and verify copied scan exists
        scans = self.cat.api.scans.get_scans()['scans']
        assert name in [scan['name'] for scan in scans], 'Failed to copy scan.'

        self.cat.api.scans.delete(response['id'])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_move_advanced_scan(self, create_scan):
        """Verifies Advanced scan moved to trash folder/MyScans folder."""

        scan_id = create_scan['scan']['id']
        self.cat.api.scans.launch(scan_id)

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id,
                                 end_state=API.Scan.Status.COMPLETED,
                                 timeout=(TIME_FIVE_MINUTES * 4))

        # Verify scan has been completed
        assert result, "Scan failed to launch or taking more than 10 minutes"

        # Move completed Advanced scan into trash folder
        self.cat.api.scans.move(scan_id, "2")

        # Get scan details after moving scan to trash folder
        details = self.cat.api.scans.details(scan_id)
        assert details['info']["folder_id"] == 2, "Scan does not move into Trash folder"

        # Move Advanced scan from Trash folder into MyScans folder
        self.cat.api.scans.move(scan_id, "3")

        # Get scan details after moving to MyScans folder
        details = self.cat.api.scans.details(scan_id)
        assert details['info']["folder_id"] == 3, "Scan does not move from Trash into MyScans folder"

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_attachments(self, create_scan):
        """Verifies the scan attachments can be retrieved."""
        # Create and run a scan that will generate an attachment
        scan_id = create_scan['scan']['id']

        self.cat.api.scans.launch(scan_id)

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=(TIME_FIVE_MINUTES * 4))

        # Verify scan has been completed
        assert result, "Scan failed to launch or taking more than 15 minutes"

        # Get scan details
        details = self.cat.api.scans.details(scan_id)

        # Get host id
        host_id = details['hosts'][0]['host_id']

        # Get output for plugin id 84239
        output = self.cat.api.scans.plugin_output(scan_id, host_id, plugin_id=84239)

        # Get attachment ID and key
        attach_id = output['outputs'][0]['ports']['0 / tcp / '][0]['attachments'][0]['id']

        # Get attachment and verify 200 response
        attachment = self.cat.api.scans.attachments(scan_id, attach_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify that attachment is not null
        assert attachment["attachment_token"], "Attachment was not returned."
