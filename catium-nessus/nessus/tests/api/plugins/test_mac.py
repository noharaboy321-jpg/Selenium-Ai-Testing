"""
Nessus plugin mac remote listener enumeration
"""
import pytest

from nessus.helpers.credentials.credential import CredentialHelper
from nessus.models.scan import ScanModel
from nessus.helpers.scan import launch_scan


@pytest.mark.scanning
@pytest.mark.plugins
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.usefixtures('load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/plugins/test_data/test_mac.json'])
class TestMac:
    """Test class for Mac tests"""

    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    # API_Tested# GET /scans/{scan_id}/trails
    def test_mac_listeners_non_sudo(self, load_test_data):
        """Non sudo user"""
        plugin_id = load_test_data['mac_listeners']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_password_credential(username=load_test_data['mac_listeners']['username'],
                                                                 password=load_test_data['mac_listeners']['password']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['mac_listeners']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id, check_audit=True)
        outputs = json_out['outputs']
        if outputs is None and audit_trail is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        if outputs:
            assert "The process 'ARDAgent' running under the user 'tenable' is listening on this port" \
                in outputs[0]['plugin_output'], 'No expected processes found'
        elif audit_trail:
            assert "Note that elevated credentials were not provided for the remote host" in audit_trail,\
                'Caveat message not found'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_mac_listeners_sudo(self, load_test_data):
        """Sudo user"""
        plugin_id = load_test_data['mac_lis_sudo']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_password_credential(username=load_test_data['mac_lis_sudo']['username'],
                                                                 password=load_test_data['mac_lis_sudo']['password'],
                                                                 elevate_privileges=
                                                                 load_test_data['mac_lis_sudo']['sudo'],
                                                                 escalation_account=
                                                                 load_test_data['mac_lis_sudo']['sudo_account'],
                                                                 escalation_password=
                                                                 load_test_data['mac_lis_sudo']['sudo_password']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['mac_lis_sudo']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert "running under the user 'root' is listening on this port" \
            in outputs[0]['plugin_output'], 'No expected processes found'
