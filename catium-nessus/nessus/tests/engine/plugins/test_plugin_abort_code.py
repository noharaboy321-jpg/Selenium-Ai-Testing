"""
Nessus NASL Plugin Abort Code
Test cases for verifying abort code
:copyright: Tenable Network Security, 2019
:date: May 25, 2022
:last_modified: June 27, 2022
:author: @stellex
"""
from http import HTTPStatus

import pytest
from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_THIRTY_MINUTES

from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API


@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login')
class TestPluginAbortCode:
    """
    Tests for abort code when a plugin is aborted by the NASL VM
    """

    cat = None
    abort_plugin = {'plugin_path': 'nessus/tests/plugins/test_data/', 'plugin_filename': 'sce-3132.nbin',
                    'cleanup_file': True, 'plugin_id': 903132, 'exit_code': 1006,
                    'expected_message': 'virtual machine abnormally aborted plugin'}
    abort_plugin_test_data = {'scan_json_path': (get_file_path('nessus/tests/plugins/test_data/test_plugin_abort_code.json')),
                              'scan_type': 'advanced', 'plugin_data': abort_plugin}

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': abort_plugin_test_data['scan_json_path'],
         'scan_type': abort_plugin_test_data['scan_type'],
         'plugin_data': abort_plugin_test_data['plugin_data']}], indirect=True)
    @pytest.mark.xray(test_key='SCE-3229')
    @pytest.mark.parametrize('install_custom_plugin', [abort_plugin_test_data['plugin_data']], indirect=True)
    def test_plugin_abort_code(self, install_custom_plugin, nessus_api_login, create_scan_with_plugin_data,
                               test_data_file):
        """
        Creates an advanced scan for a custom plugin that will trigger an abort code
        """

        # Get Scan related information for newly created scan and verify its 200 response
        custom_scan = create_scan_with_plugin_data['scan']
        scan_id = custom_scan['id']
        scans = self.cat.api.scans.get_scans()['scans']
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify scan exists in list.
        assert scan_id in [scan['id'] for scan in scans], 'Failed to create scan'

        self.cat.api.scans.launch(scan_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

        plugin_data = test_data_file['plugin_data']
        plugin_id = plugin_data['plugin_id']
        exit_code = plugin_data['exit_code']
        expected_message = plugin_data['expected_message']
        audit_trail = self.cat.api.scans.get_audit_trail(scan_id, plugin_id)

        assert str(plugin_id) + '/' + str(exit_code) in [key for key in audit_trail['trails'][0]['ports'].keys()], \
            'Expected exit_code %d/%s, exit_code was not found in audit trail.' % (scan_id, exit_code)
        assert expected_message == audit_trail['trails'][0]['output'], \
            'Expected output message \'%s\', output message was %s instead.' \
            % (expected_message, audit_trail['trails'][0]['output'])
