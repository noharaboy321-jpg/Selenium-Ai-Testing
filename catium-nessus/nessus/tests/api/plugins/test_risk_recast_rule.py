"""
Nessus plugin recast verification test

:copyright: Tenable Network Security, 2017
:date: Nov 20, 2017
:author: @jamreliya
"""

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import TIME_THIRTY_MINUTES
from nessus.helpers.recast import plugin_rule_to_recast_mapper
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API


@pytest.mark.scanning
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestPluginRecast:
    """Tests for Nessus plugin severity recast"""

    cat = None

    # API_Tested# PUT /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    @pytest.mark.skip_rhel8
    @pytest.mark.parametrize('enable_dashboard', [True, False])
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
         'scan_type': 'advanced'}],
                             indirect=True)  # NQA - 97
    def test_recast_rule(self, create_scan, enable_dashboard):
        """
        NQA-97 : Scans - Plugin Rules - Risk Recast rules
        NES-12243 : [API] Verify modifying / recasting plugin when dashboard is enabled

        Scenario Tested:
            Verify below scenario when dashboard is enabled/disabled on Nessus.
            [x] Verify recast plugin reflected on scan result and if saved for future then it works with newer scan.
        """
        plugin_id = 19506  # Nessus Scan Information
        # create scan
        scan_id = create_scan['scan']['id']

        # Launch scan and wait for complete
        self.cat.api.scans.launch(scan_id)
        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        assert result, "Scan failed to complete."

        # Enabling/disabling scan dashboard
        self.cat.api.scans.enable_dashboard(scan_id, enable_dashboard)

        # Get scan details
        scan_details = self.cat.api.scans.details(scan_id)
        host_id, host_name = scan_details['hosts'][0]['host_id'], scan_details['hosts'][0]['hostname']

        # modify plugin severity to critical
        payload = {'type': API.Severity.CRITICAL, 'host': host_name}
        self.cat.api.scans.modify_plugin_severity(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id,
                                                  payload=payload)
        plugin_output = self.cat.api.scans.plugin_output(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id)

        assert plugin_output['info']['plugindescription']['severity'] == plugin_rule_to_recast_mapper(
            'recast_critical'), 'unable to change severity'

        # re-launch scan and check plugin severity
        self.cat.api.scans.launch(scan_id)
        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

        # Get scan details
        plugin_output = self.cat.api.scans.plugin_output(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id)

        assert plugin_output['info']['plugindescription']['severity'] == plugin_rule_to_recast_mapper('recast_info'), \
            'severity is different from the actual one'

        try:
            payload = {'type': API.Severity.CRITICAL, 'host': host_name, 'save_rule': 'yes'}
            self.cat.api.scans.modify_plugin_severity(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id,
                                                      payload=payload)
            self.cat.api.scans.launch(scan_id)
            result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                     timeout=TIME_THIRTY_MINUTES)

            # Verify scan is pass or fail to complete
            assert result, "Scan failed to complete."

            # Get scan details
            plugin_output = self.cat.api.scans.plugin_output(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id)

            assert plugin_output['info']['plugindescription']['severity'] == \
                   plugin_rule_to_recast_mapper('recast_critical'), 'unable to change severity'

        finally:
            # revert severity to actual one
            payload = {'type': API.Severity.INFO, 'host': host_name, 'save_rule': 'yes'}
            self.cat.api.scans.modify_plugin_severity(scan_id=scan_id, host_id=host_id, plugin_id=plugin_id,
                                                      payload=payload)
