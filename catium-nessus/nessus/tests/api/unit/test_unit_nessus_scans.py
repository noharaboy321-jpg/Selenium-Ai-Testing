"""
Unit Test
"""
import pytest
from waiting import wait, TimeoutExpired

from nessus.helpers.credentials.credential import CredentialHelper
from nessus.models.scan import ScanModel
from catium.lib.const import WAIT_SHORT, TIME_FIVE_MINUTES
from catium.lib.util import poll
from nessus.lib.const import API


# TODO Create scan fixture


@pytest.mark.unittest
@pytest.mark.usefixtures('nessus_class_api_login')
class TestNessusScans:
    """Unit tests for nessus scans"""

    cat = None

    # API_Tested# POST /scans
    def test_create_scan_from_model(self):
        """Verifies a Scan can be created using a ScanModel object"""
        scan_model = ScanModel.create_model()
        scan = self.cat.api.scans.create(scan_model)
        self._validate_scan_response(scan)
        self.cat.api.scans.delete(scan['scan']['id'])

    # API_Tested# POST /scans
    def test_create_scan_from_model_with_custom_plugins(self):
        """Verifies a Scan can be created using a ScanModel object with custom plugins"""
        scan_model = ScanModel.create_model()
        scan_model.plugins = [12122, 73189, 87732]
        scan = self.cat.api.scans.create(scan_model)
        self._validate_scan_response(scan)
        self.cat.api.scans.delete(scan['scan']['id'])

    # API_Tested# POST /scans
    def test_new_scan_with_oracle_database_credential(self):
        """Verifies a scan can be added with Oracle Database Login Credentials"""
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(
            CredentialHelper.Database.create_oracle_credential(username='admin', service='tenable', password='admin'))
        scan = self.cat.api.scans.create(scan_model)
        self._validate_scan_response(scan)
        self.cat.api.scans.delete(scan['scan']['id'])

    # API_Tested# POST /scans
    def test_new_scan_with_multiple_credentials(self):
        """Verifies a scan can be added with multiple Credentials"""
        scan_model = ScanModel.create_model()

        # Add an Oracle Credential
        scan_model.add_database_credential(
            CredentialHelper.Database.create_oracle_credential(username='admin', service='tenable', password='admin'))

        # Add a SSH Password Credential
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_password_credential(username='mrrobot', password='tenable')
        )

        # Add a MongoDB Credential
        scan_model.add_mongodb_credential(
            CredentialHelper.Database.create_mongodb_credential(username='tester', password='tester', database='stats')
        )

        scan = self.cat.api.scans.create(scan_model)
        self._validate_scan_response(scan)
        self.cat.api.scans.delete(scan['scan']['id'])

    # API_Tested# POST /scans
    def test_new_scan_with_mysql_credential(self):
        """Verifies a scan can be added with MySQL Database Login Credentials"""
        scan_model = ScanModel.create_model()
        scan_model.add_database_credential(
            CredentialHelper.Database.create_mysql_credential(username='root', password='sapphire', port=3309))
        scan = self.cat.api.scans.create(scan_model)
        self._validate_scan_response(scan)
        self.cat.api.scans.delete(scan['scan']['id'])

    # API_Tested# POST /scans/{scan_id}/launch
    @pytest.mark.scanning
    def test_new_scan_launch(self):
        """Verifies that a newly create Scan can be launched"""
        scan_model = ScanModel.create_model()
        scan = self.cat.api.scans.create(scan_model)
        self.cat.api.scans.launch(scan['scan']['id'], alt_targets=['127.0.0.1'])
        poll(lambda: self.cat.api.server.status())

        try:
            wait(lambda: self.cat.api.scans.details(scan['scan']['id'])['info']['status'] != API.Scan.Status.RUNNING,
                 timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=WAIT_SHORT, waiting_for='Scan to complete.')
        except TimeoutExpired:
            pass

        assert self.cat.api.scans.details(scan['scan']['id'])['info']['status'] != API.Scan.Status.RUNNING,\
            'Scan is still running.'
        self.cat.api.scans.delete(scan['scan']['id'])

    def _validate_scan_response(self, scan):
        assert 'scan' in scan, 'Bad API response: missing "scan" field'
        assert 'id' in scan['scan'], 'Bad API response: missing "id" field'
        assert str(scan['scan']['id']).isdigit() is True, 'Bad API response: expected ID, got "%s"' % scan['scan']['id']
