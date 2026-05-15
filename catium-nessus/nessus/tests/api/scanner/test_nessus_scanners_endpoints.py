"""
Nessus Scanners Endpoints Unit Test

:copyright: Tenable Network Security, 2017
:date: June, 2017
:last_modified: July 15, 2020
:author: @smadan, @dkothari, @kpanchal
"""
from http import HTTPStatus

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.activation_code_generator import ActivationCodeGenerator
from catium.lib.const import TIME_FIVE_MINUTES, TIME_TEN_MINUTES, TIME_FIVE_SECONDS, TIME_FIFTEEN_MINUTES
from catium.lib.log.log import create_logger
from nessus.helpers.scanner import create_scanner, wait_for_scanner_to_be_ready
from nessus.helpers.server import expect_http_error
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.extended_smoke
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusScannerEndpoint:
    """Tests for Nessus scanner Endpoint"""

    cat = None

    # API_Tested# GET /scanners
    @pytest.mark.nessus_mat
    def test_get_scanners_list(self):
        """
            Verifies scanners list retrieved.
            .. note:: #NQA- 903(Get scanners list)

            Scenarios:
              [x] Successfully retrieve scanner list
        """
        output = self.cat.api.scanners.get_list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify list returned is not empty
        assert (len(output['scanners'])) >= 1, "No scanners list returned"

    @pytest.mark.scanning
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    # API_Tested# GET /scanners/{scanner_id}/scans
    def test_get_running_scans(self, create_scan):
        """
            Verifies running scans of a particular scanner
            .. note:: #NQA- 902(Get scans list)

            Scenarios:
              [x] Successfully retrieve created and launched scan for specific scanner
              [ ] Check that the retrieved scan is in a running state
        """
        # create scan and get its id
        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # get list of running scans and verify 200 response
        output = self.cat.api.scanners.get_scans(1)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify that scan name exists in scans
        new_scan = next((scan for scan in output['scans'] if scan['name'] == scan['name']), None)
        assert new_scan is not None, "Scan with name %s was not found." % scan['name']

        # Stop scan and verify 200 response
        self.cat.api.scans.stop(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Wait for  scan  to get canceled
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                        timeout=TIME_FIVE_MINUTES)

    # API_Tested# GET /scanners/{scanner_id}/key
    def test_get_scanner_key(self):
        """
            Verifies the scanner key can be retrieved.
            .. note:: #NQA- 901(Get scanner key)

            Scenarios:
              [x] Successfully retrieve the key for a specific scanner
              [ ] Unsuccessfully retrieve the key for non-existent scanner
        """
        # Get key and verify 200 response
        scanner_key = self.cat.api.scanners.get_scanner_key(1)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify that scanner key retrieved
        assert scanner_key, "Scanner Key empty."

    # API_Tested# PUT /scanners/{scanner_id}
    def test_force_plugin_update(self):
        """
            Verifies to force a plugin update
            .. note:: #NQA- 895(Settings - Force plugin update)

            Scenarios:
              [x] Successfully force a plugin update
        """
        self.cat.api.scanners.edit(scanner_id=1, force_plugin_update=True)
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
            HTTPStatus.OK, self.cat.api.http_status_code)

    # API_Tested# GET /server/status
    # API_Tested# PUT /scanners/{scanner_id}
    def test_force_scanner_reboot(self):
        """
            Verifies to force a scanner reboot
            .. note:: #NQA- 897(Settings - Force scanner reboot)

            Scenarios:
              [x] Successfully reboot scanner
              [x] Successfully fetch the server status
              [ ] Unsuccessfully reboot non-existent scanner
        """
        self.cat.api.server.restart()
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
            HTTPStatus.OK, self.cat.api.http_status_code)

        # Wait till server status switch to loading
        wait_for_scanner_status(api=self.cat.api, status=API.Status.LOADING,
                                timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                                sleep_interval=TIME_FIVE_SECONDS)

        # Wait till server is ready
        wait_for_scanner_status(api=self.cat.api, status=API.Status.READY,
                                timeout=TIME_FIFTEEN_MINUTES, msg='Availability of Nessus scanner',
                                sleep_interval=TIME_FIVE_SECONDS)

        response = self.cat.api.server.status()
        self.cat.api.login()
        # Verifies reboot is done sucessfully
        assert response['status'] == "ready", 'Reboot is unsucessfull or taking long'

    # API_Tested# PUT /scanners/{scanner_id}
    @pytest.mark.skip(reason='This test causes a UI update, which is unwanted and breaks coverage reporting')
    def test_force_ui_update(self):
        """
            Verifies to force a ui update
            .. note:: #NQA-896(Settings - Force ui update)

            Scenarios:
              [x] Successfully force a UI update
        """
        self.cat.api.scanners.edit(scanner_id=1, force_ui_update=True)
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
            HTTPStatus.OK, self.cat.api.http_status_code)

    @pytest.mark.scanning
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    # API_Tested# POST /scanners/{scanner_id}/scans/{scan_uuid}/control
    def test_control_scanner_scans(self, create_scan):
        """
            Verifies the Advanced scan for a scanner can be controlled.
            .. note:: #NQA- 892(Control Scans - Control a scan using scanners route)

            Scenarios:
              [x] Pause a running scan
              [x] Resume a paused scan
              [x] Stop a running scan
              [ ] Pause a stopped scan
              [ ] Stop a paused scan
              [ ] Resume a stopped scan
              [ ] Control scan with non-existent scanner
        """
        # create scan and get its id
        scan_created = create_scan['scan']
        scan_id = scan_created['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify scan status is running
        response = self.cat.api.scanners.get_scans(1)
        new_scan = next((scan for scan in response['scans'] if scan['scan_id'] == scan_id), None)
        assert new_scan['status'] == 'running', "Scan status incorrect. Expected running, got %s" % new_scan['status']

        # Pause scan and verify 200 response
        self.cat.api.scanners.control(1, new_scan['id'], 'pause')
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
            HTTPStatus.OK, self.cat.api.http_status_code)

        # Verify scan status is pausing/paused
        response = self.cat.api.scanners.get_scans(1)
        new_scan = next((scan for scan in response['scans'] if scan['scan_id'] == scan_id), None)
        assert new_scan['status'] == API.Scan.Status.PAUSING or new_scan['status'] == API.Scan.Status.PAUSED, \
            "Scan status incorrect. Expected pausing or paused, got %s" % new_scan['status']

        # Resume scan and verify 200 response
        self.cat.api.scanners.control(1, new_scan['id'], 'resume')
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
            HTTPStatus.OK, self.cat.api.http_status_code)

        # Verify scan status is resuming
        response = self.cat.api.scanners.get_scans(1)
        new_scan = next((scan for scan in response['scans'] if scan['scan_id'] == scan_id), None)
        assert new_scan['status'] == 'resuming', "Scan status incorrect. Expected resuming, got %s" % new_scan['status']

        # Stop scan and verify 200 response
        self.cat.api.scanners.control(1, new_scan['id'], 'stop')
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
            HTTPStatus.OK, self.cat.api.http_status_code)

        # Wait 5 minutes for scan to abort
        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                                 timeout=TIME_FIVE_MINUTES)

        # Verify scan status is "aborted"
        assert result, "Scan failed to stop."

    @pytest.mark.skip(reason="skipping test for now")
    # API_Tested# PUT /scanners/{scanner_id}
    def test_aws_update_interval(self):
        """
            Verifies to update aws interval
            .. note:: #NQA-899(Settings - Set AWS update interval)
            .. As a pre requisite scanner should be linked to NM

            Scenarios:
              [x] Successfully edit a scanner's aws update interval
        """
        scanner_list = self.cat.api.scanners.get_list()
        for scanner in scanner_list['scanners']:
            if scanner['id'] != 1:  # 1 is local scanner id
                self.cat.api.scanners.edit(scanner_id=scanner['id'], aws_update_interval=TIME_FIFTEEN_MINUTES)
                details = self.cat.api.scanners.details(scanner['id'])
                assert details['aws_update_interval'] == TIME_FIFTEEN_MINUTES, 'unable to set aws update interval'
                break
        else:
            raise AssertionError('There is no linked scanner')

    # NES-8900
    # API_Tested# GET /scanners/local/load
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_get_local_load(self, create_scan):
        """
        NES-8900: Create tests for scanners GET /scanners/local/load

        Scenarios tested:
            [x] Successfully get the local load
        """
        scan_id = create_scan['scan']['id']
        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        local_load = self.cat.api.scanners.local_load()
        assert local_load != "nessus_scanner_load 0", "Local load not return successfully."
        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_FIFTEEN_MINUTES)

        # Verify scan has been completed
        assert result, "Scan failed to complete"

    # NES-8900
    # API_Tested# GET /scanners/local/scans
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    def test_get_local_scans(self, create_scan):
        """
        NES-8900: Create tests for scanners GET /scanners/local/scans

        Scenarios tested:
            [x] Successfully get the local scans
        """
        scan_id = create_scan['scan']['id']
        self.cat.api.scans.launch(scan_id)

        scans = self.cat.api.scanners.local_scans()['scans']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        local_scan = next((scan for scan in scans if scan['scan_id'] == scan_id), None)

        assert local_scan['scan_id'] == scan_id, "Fail to get local scan"
        self.cat.api.scans.stop(scan_id=scan_id)
        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                                 timeout=TIME_FIVE_MINUTES)

        # Verify scan has been canceled
        assert result, "Scan failed to complete"


@pytest.mark.nessus_manager
@pytest.mark.extended_smoke
@pytest.mark.usefixtures('nessus_api_login', 'remove_all_linked_scanners')
class TestNessusScannerEndpointForNessusManager:
    """Tests for Nessus scanner Endpoint"""

    cat = None

    # API_Tested# GET /scanners/{scanner_id}
    @pytest.mark.nessus_manager_mat
    def test_get_scanner_details(self, add_scanner_locally):
        """
            Verifies scanner details can be retrieved.
            .. note:: #NQA- 894(Details - Get the details of a scanner)

            Scenarios:
              [x] Successfully retrieve the NM scanner details
        """
        # Add scanner
        scanner_info = add_scanner_locally
        # Get scanner details and verify 200 response
        response = self.cat.api.scanners.details(scanner_info['id'])
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
            HTTPStatus.OK, self.cat.api.http_status_code)

        # Verify scanner details match expected
        assert response['name'] == scanner_info['name'], "Name mismatch. Expected %s, got %s." % (scanner_info['name'],
                                                                                                  response['name'])
        assert response['uuid'] == scanner_info['suuid'], "Name mismatch. Expected %s, got %s." % (
            scanner_info['suuid'], response['uuid'])

    @pytest.mark.parametrize('add_scanners', [3])
    @pytest.mark.flaky_test
    def test_verify_scanner_link_once_license_limit_exceeds(self, add_scanners):
        """
        NES-12202 : [API] [Negative] Verify user is not able to link more sensors once license limit exceeded

        Scenarios Tested:
            [x] Verify that user is not able to link scanners once license limit exceeded.
        """
        original_scanners_limit = self.cat.api.server.properties()['license']['scanners']
        linked_scanners = self.cat.api.scanners.get_list()['scanners']
        scanner_ids = []

        new_scanners_limit = (len(linked_scanners) - 1) + add_scanners
        activation_code = ActivationCodeGenerator.generate_nessus_manager_code(scanners=new_scanners_limit)
        self.cat.api.server.server_register(data={"code": activation_code})
        try:
            wait_for_scanner_to_be_ready(api=self.cat.api)
            for _ in range(add_scanners):
                scanner = create_scanner(api=self.cat.api)
                scanner_ids.append(scanner['id'])

            # Verify that scanner linking gives error due to license limit reached.
            with expect_http_error(code=HTTPStatus.FORBIDDEN,
                                   look_for="License scanner limit exceeded: {} of {} linked".format(
                                       new_scanners_limit, new_scanners_limit)):
                create_scanner(api=self.cat.api)
        finally:
            register_code = ActivationCodeGenerator.generate_nessus_manager_code(scanners=original_scanners_limit)
            self.cat.api.server.server_register(data={"code": register_code})
            wait_for_scanner_to_be_ready(api=self.cat.api)
            for id in scanner_ids:
                self.cat.api.scanners.delete(scanner_id=id)

    # API_Tested# PUT /scanners/{scanner_id}/link
    @pytest.mark.parametrize("local_scanner", [True, False])
    def test_toggle_link_state(self, add_scanner_locally, local_scanner):
        """
        NQA-904 : API - Scanners - Settings - Link state
        NES-12166 : [API] Toggle link state for local scanner on NM

        Scenarios:
          [x] Successfully toggle link state from False to True knowing initial state for remote scanner
          [x] Successfully toggle link state from False to True knowing initial state for local scanner
        """
        # Add scanner
        scanner_info = [scanner for scanner in self.cat.api.scanners.get_list()['scanners'] if scanner[
            'name'] == 'Local Scanner'][0] if local_scanner else add_scanner_locally
        try:
            # Toggle link state to false and verify 200 response
            self.cat.api.scanners.link(scanner_info['id'])
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            # Get scanner details and check link state changed to 0
            response = self.cat.api.scanners.details(scanner_info['id'])
            assert response['linked'] == 0, "Incorrect linking state present. Linking state did not toggle."
        finally:
            # Toggle link state to true and verify 200 response
            self.cat.api.scanners.link(scanner_info['id'], link=True)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            # Get scanner details and check link state changed to 1
            response = self.cat.api.scanners.details(scanner_info['id'])
            assert response['linked'] == 1, "Incorrect linking state present. Linking state did not toggle."

    # API_Tested# DELETE /scanners/{scanner_id}
    def test_delete_scanner(self, add_scanner_locally):
        """
            Verifies scanner can be deleted.
            .. note:: #NQA- 893(Delete - Delete a scanner)

            Scenarios:
              [x] Successfully delete newly created scanner
              [ ] Delete scanner with running scan
              [ ] Delete scanner with paused scan
              [ ] Unsuccessfully delete non-existent scanner
        """
        # Add scanner
        scanner_info = add_scanner_locally
        # Delete scanner and verify 200 response
        self.cat.api.scanners.delete(scanner_info['id'])
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % (
            HTTPStatus.OK, self.cat.api.http_status_code)

        # Verify scanner no longer present
        response = self.cat.api.scanners.get_list()
        new_scanner = next((scanner for scanner in response['scanners'] if scanner['name'] == scanner_info['name']),
                           None)
        assert new_scanner is None, "Scanner %s is still present after delete." % new_scanner['name']

    # API_Tested# PUT /scanners/{scanner_id}
    def test_set_registration_key(self, add_scanner_locally):
        """
            Verifies registration code can be set
            .. note:: #NQA- 898(Settings - Set registration code)

            Scenarios:
              [x] Successfully edit scanner's NP registration key
              [ ] Unsuccessfully edit scanner's with invalid NP registration key
              [ ] Successfully edit scanner's NM registration key
              [ ] Unsuccessfully edit scanner's with invalid NM registration key
        """
        # Add scanner
        scanner_info = add_scanner_locally

        # Get registration code
        registration_key = ActivationCodeGenerator.generate_code(ActivationCodeGenerator.NESSUS_PROFESSIONAL, 250)

        # Set registration Key
        self.cat.api.scanners.edit(scanner_id=scanner_info['id'], registration_code=registration_key)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get details of created scanner
        details = self.cat.api.scanners.details(scanner_info['id'])
        code = details['registration_code']

        # Verifies if code has been set
        assert code == registration_key, 'Registration key "%s" has not been updated for scanner "%s" ' \
                                         % registration_key % scanner_info['id']

    # NES-8900
    # API_Tested# DELETE /scanners
    def test_delete_all_scanners(self, add_scanner_locally):
        """
        NES-8900: Create tests for scanners DELETE /scanners

        Scenarios tested:
            [x] Successfully delete all scanners
        """

        scanner_info = add_scanner_locally
        another_scanner_info = create_scanner(api=self.cat.api)
        scanner_ids = [scanner_info['id'], another_scanner_info['id']]
        self.cat.api.scanners.delete_all_scanners(scanner_ids)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        scanner_list = self.cat.api.scanners.get_list()['scanners']
        all_scanner_ids = [scanner_id['id'] for scanner_id in scanner_list]
        assert all(scanner_id not in all_scanner_ids for scanner_id in scanner_ids), \
            'Scanners are not deleted successfully'
