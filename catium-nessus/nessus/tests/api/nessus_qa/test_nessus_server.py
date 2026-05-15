"""
:copyright: Tenable Network Security, 2017
:date: June 5, 2017
:last_modified: Mar 16, 2022
:author: @cdombrowski, @kpanchal
"""
import pytest

from catium.lib.log import create_logger
from nessus.helpers.server import is_pro_7

log = create_logger()


@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login', 'revert_nessus_pro_7_setting')
class TestNessusServer:
    """
    Class will handle testing the Nessus Server API calls.  This includes both server.properties and server.status.
    """

    cat = None

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    # API_Tested# GET /server/properties
    def test_nessus_server_properties(self):
        """
        Test that we are able to retrieve the server properties from Nessus via the API.
        """
        properties = self.cat.api.server.properties()

        assert properties and 'nessus_type' in properties, 'Unable to retrieve the server properties.'

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    # API_Tested# GET /server/status
    def test_nessus_server_status(self):
        """
        Test that we are able to retrieve the server status from Nessus via the API.

        Scenarios tested:
          [x] Successfully get server status
          [ ] Lock the server, verify the status returns code 503 with "locked" string.
        we return a lot of status, not sure if we want to verify every of them?
        """
        status = self.cat.api.server.status()

        assert status and 'code' in status, 'Unable to retrieve the server status.'

    @pytest.mark.skip('As discussed, not in scope for Musikaar team to fix this, hence skipping.')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    # API_Tested# GET /server/upgrade-to-pro-7
    def test_nessus_pro_7_upgrades(self):
        """
        This one is skipped
        Scenarios tested:
            We might not need this one in auto testing?
        """
        # Test the upgrade TO pro 7 first.
        properties = self.cat.api.server.properties()

        # TODO: This should skip, not fail!
        assert "Professional" in properties['nessus_type']

        # if it already is pro7, then downgrade first.
        if is_pro_7(properties):
            self.cat.api.server.downgrade_pro_7()

        self.cat.api.server.upgrade_pro_7()

        # Test to make sure that various features are now disabled.
        properties = self.cat.api.server.properties()

        assert not properties['license']['features']['api']
        assert not properties['license']['features']['users']
        assert properties['license']['features']['custom_reports']
        assert properties['license']['features']['email_reports']

        # TODO: Check various API routes that should be allowed, and check at least one route that should not be
        #       allowed anymore.

        # allowable routes:
        # POST /session
        # DELETE /session
        # GET /tokens/:token/download and GET /tokens/:token/status
        # GET /scans
        # GET /scans/exports/{token}/download
        # POST /scans/{scan_id}/export
        # GET /scans/{scan_id}/export/formats
        # DELETE /scans/{scan_id}/export/{export_id}
        # GET /scans/{scan_id}/export/{export_id}/status
        # GET /scans/{scan_id}/export/{export_id}/download

    @pytest.mark.skip('As discussed, not in scope for Musikaar team to fix this, hence skipping.')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    # API_Tested# GET /server/downgrade-from-pro-7
    def test_nessus_pro_7_downgrade(self):
        # Test the upgrade TO pro 7 first.
        properties = self.cat.api.server.properties()

        # TODO: This should skip, not fail!
        assert "Professional" in properties['nessus_type']

        # if it is not already pro7, then upgrade first.
        if not is_pro_7(properties):
            self.cat.api.server.upgrade_pro_7()

        self.cat.api.server.downgrade_pro_7()

        # Test to make sure that various features are now disabled.
        properties = self.cat.api.server.properties()

        assert properties['license']['features']['api']
        assert properties['license']['features']['users']
        assert not properties['license']['features']['custom_reports']
        assert not properties['license']['features']['email_reports']
