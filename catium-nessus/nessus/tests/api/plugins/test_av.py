"""
Nessus plugin AV checks

:copyright: Tenable Network Security, 2017
:date: June 27, 2017
:author: tkeyser
"""
import pytest

from nessus.helpers.credentials.credential import CredentialHelper
from nessus.models.scan import ScanModel
from nessus.helpers.scan import launch_scan


@pytest.mark.scanning
@pytest.mark.plugins
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.usefixtures('load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/plugins/test_data/test_av.json'])
class TestAV:
    """Test class for SSH authentication"""

    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_sep_report(self, load_test_data):
        """Verify Symantec Endpoint Protection report"""
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_win_password_credential(username=load_test_data['SEP_report']['username'],
                                                                 password=load_test_data['SEP_report']['password'],
                                                                 domain=load_test_data['SEP_report']['domain']))
        target = load_test_data['SEP_report']['target']
        plugin_ids = load_test_data['SEP_report']['plugins_to_enable']
        plugin_id_report = load_test_data['SEP_report']['plugin_id_report']
        scan_model.plugins = plugin_ids
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report)
        outputs = json_out['outputs']
        assert 'The remote host has antivirus software from Symantec installed.' \
            in outputs[0]['plugin_output'], 'Symantec software not detected'
        assert 'Symantec Endpoint Protection' in outputs[0]['plugin_output'], 'Symantec software not detected'

    # API_Tested# GET /scans/{scan_id}/trails
    def test_sep_audit(self, load_test_data):
        """Verify Symantec Endpoint Protection no issues audit"""
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_win_password_credential(username=load_test_data['SEP_audit']['username'],
                                                                 password=load_test_data['SEP_audit']['password'],
                                                                 domain=load_test_data['SEP_audit']['domain']))
        target = load_test_data['SEP_audit']['target']
        plugin_ids = load_test_data['SEP_audit']['plugins_to_enable']
        plugin_id_report = load_test_data['SEP_audit']['plugin_id_report']
        scan_model.plugins = plugin_ids
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id_report, check_audit=True)
        outputs = json_out['outputs']
        assert 'Detected Symantec Endpoint Protection with no known issues to report.' \
            in audit_trail, 'Symantec software not detected'

