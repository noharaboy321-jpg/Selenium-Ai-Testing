"""
:copyright: Tenable Network Security, 2017
:date: October 6, 2017
:author: @pellsworth
"""
import pytest
from nessus.helpers.server import expect_http_error


@pytest.mark.skip('As discussed, not in scope for Musikaar team to fix this, hence skipping.')
@pytest.mark.scanning
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login', 'no_automation_api_key')
@pytest.mark.skip_pro_scan_api_enabled()
class TestNessusScanEndpointPro7:
    """
    Tests to make sure that Nessus Pro 7 users cannot use the API to work with scans.
    """

    cat = None

    # API_Tested# POST /scans
    def test_create_scan(self):
        """Test scan creation"""
        # Get Scan related information for newly created scan and verify its 200 response
        with expect_http_error(code=412):
            self.cat.api.scans.create_raw(payload={})

    # API_Tested# POST /scans/{scan_id}/launch
    def test_launch_scan(self):
        """Tests scan launch"""
        with expect_http_error(code=412):
            self.cat.api.scans.launch(scan_id='1')

    # API_Tested# POST /scans/import
    def test_import_scan(self):
        """Tests scan import"""
        with expect_http_error(code=412):
            self.cat.api.scans.import_scan(file='bogus.scan',
                                           folder_id=None,
                                           password='12345')

    # API_Tested# PUT /scans/{scan_id}
    def test_configure_scan(self):
        """Tests scan configuration"""
        with expect_http_error(code=412):
            self.cat.api.scans.configure(scan_id='1', payload={})

    # API_Tested# DELETE /scans/{scan_id}
    def test_delete_scan(self):
        """Tests deleting a scan"""
        with expect_http_error(code=412):
            self.cat.api.scans.delete(scan_id='1')

    # API_Tested# DELETE /scans/{scan_id}/history/{history_id}
    def test_delete_history(self):
        """Tests deleting scan history"""
        with expect_http_error(code=412):
            self.cat.api.scans.delete_history(scan_id='1', history_id='1')

    # API_Tested# PUT /scans/{scan_id}/schedule
    def test_schedule(self):
        """Tests scan schedule"""
        with expect_http_error(code=412):
            self.cat.api.scans.schedule(scan_id='1', enabled=True)

    # API_Tested# POST /scans/{scan_id}/copy
    def test_copy_scan(self):
        """Tests copying a scan"""
        with expect_http_error(code=412):
            self.cat.api.scans.copy(scan_id='1', name='bogus')

    # API_Tested# PUT /scans/{scan_id}/folder
    def test_move_advanced_scan(self):
        """Tests moving a scan"""
        with expect_http_error(code=412):
            self.cat.api.scans.move(scan_id='1', folder_id='2')

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_attachments(self):
        """Tests scan attachments"""
        with expect_http_error(code=412):
            self.cat.api.scans.plugin_output(scan_id='1', host_id='1', plugin_id=84239)
