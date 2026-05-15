"""
Nessus plugin SSH authentication
"""
import pytest

from nessus.helpers.credentials.credential import CredentialHelper
from nessus.models.scan import ScanModel
from nessus.helpers.scan import launch_scan


@pytest.mark.scanning
@pytest.mark.plugins
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.usefixtures('load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/plugins/test_data/test_ssh_auth.json'])
class TestSSHAuth:
    """Test class for SSH authentication"""

    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_ssh_password_login(self, load_test_data):
        """Verify linux host can be authenticated to via SSH password auth."""
        plugin_id = load_test_data['ssh_password']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_password_credential(username=load_test_data['ssh_password']['username'],
                                                                 password=load_test_data['ssh_password']['password']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['ssh_password']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'It was possible to log into the remote host via SSH using \'password\' authentication.' \
            in outputs[0]['plugin_output'], 'Local checks failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_ssh_kerberos_linux_login(self, load_test_data):
        """Linux kerberos login test"""
        plugin_id = load_test_data['kerberos']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_kerberos_credential(username=load_test_data['kerberos']['username'],
                                                                 password=load_test_data['kerberos']['password'],
                                                                 realm=load_test_data['kerberos']['realm'],
                                                                 kdc=load_test_data['kerberos']['kdc']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['kerberos']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_text = 'It was possible to log into the remote host via SSH using \'gssapi\' authentication.'
        assert expected_text in outputs[0]['plugin_output'], 'Login failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_ssh_kerberos_linux_login_fail(self, load_test_data):
        """Linux kerberos failed login test"""
        plugin_id = load_test_data['kerberos']['auth_fail']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_kerberos_credential(username=load_test_data['kerberos']['bad_username'],
                                                                 password=load_test_data['kerberos']['bad_password'],
                                                                 realm=load_test_data['kerberos']['realm'],
                                                                 kdc=load_test_data['kerberos']['kdc']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['kerberos']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'SSH was unable to login with any supplied credentials.' in outputs[0]['plugin_output'], \
            'Expected failed login did not occur'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    @pytest.mark.skip(reason="Thycotic Plugins being reworked under RPI-336")
    def test_ssh_thycotic_login(self, load_test_data):
        """Linux thycotic login test"""
        plugin_id = load_test_data['thycotic']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_thycotic_credential(username=load_test_data['thycotic']['username'],
                                                                 name=load_test_data['thycotic']['name'],
                                                                 url=load_test_data['thycotic']['url'],
                                                                 private_key=load_test_data['thycotic']['private_key'],
                                                                 login=load_test_data['thycotic']['login'],
                                                                 password=load_test_data['thycotic']['password']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['thycotic']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_text = 'It was possible to log into the remote host'
        assert expected_text in outputs[0]['plugin_output'], 'Login failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    @pytest.mark.skip(reason="Thycotic Plugins being reworked under RPI-336")
    def test_ssh_thycotic_login_fail(self, load_test_data):
        """Linux thycotic login fail test"""
        plugin_id = load_test_data['thycotic']['auth_fail']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_thycotic_credential(username=load_test_data['thycotic']['username'],
                                                                 name=load_test_data['thycotic']['bad_name'],
                                                                 url=load_test_data['thycotic']['url'],
                                                                 private_key=load_test_data['thycotic']['private_key'],
                                                                 login=load_test_data['thycotic']['login'],
                                                                 password=load_test_data['thycotic']['password']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['thycotic']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_text = 'SSH was unable to login with any supplied credentials'
        assert expected_text in outputs[0]['plugin_output'], 'Expected failed login did not occur'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_ssh_pub_key(self, load_test_data):
        """SSH public key authentication"""
        plugin_id = load_test_data['public_key']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_publickey_credential(api=self.cat.api,
                                                                  username=
                                                                  load_test_data['public_key']['username'],
                                                                  private_key=
                                                                  load_test_data['public_key']['private_key']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['public_key']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_text = 'It was possible to log into the remote host via SSH using \'publickey\' authentication'
        assert expected_text in outputs[0]['plugin_output'], 'Login failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_ssh_certificate(self, load_test_data):
        """SSH certificate authentication"""
        plugin_id = load_test_data['certificate']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_certificate_credential(api=self.cat.api,
                                                                    username=load_test_data['certificate']['username'],
                                                                    certificate=
                                                                    load_test_data['certificate']['certificate'],
                                                                    private_key=
                                                                    load_test_data['certificate']['private_key']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['certificate']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_text = "It was possible to log into the remote host via SSH using \'publickey\' authentication."
        assert expected_text in outputs[0]['plugin_output'], 'Login failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    @pytest.mark.skip(reason="CyberArk is configured in a special way for testing.  Should be fixed Feb 25th.")
    def test_ssh_cyberark_linux_login(self, load_test_data):
        """Linux cyberark login test"""
        plugin_id = load_test_data['cyberark']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_cyberark_credential(username=load_test_data['cyberark']['username'],
                                                                 host=load_test_data['cyberark']['host'],
                                                                 safe=load_test_data['cyberark']['safe'],
                                                                 appid=load_test_data['cyberark']['app_id'],
                                                                 folder_id=load_test_data['cyberark']['folder_id'],
                                                                 use_ssl=load_test_data['cyberark']['use_ssl'],
                                                                 verify_ssl=load_test_data['cyberark']['verify_ssl'],
                                                                 port=load_test_data['cyberark']['port'],
                                                                 elevate_privileges=
                                                                 load_test_data['cyberark']['elevate_privileges']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['cyberark']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_text = 'It was possible to log into the remote host via SSH using \'password\' authentication'
        assert expected_text in outputs[0]['plugin_output'], 'Login failed'

    def test_ssh_lieberman_linux_login(self, load_test_data):
        """Linux lieberman login test"""
        plugin_id = load_test_data['lieberman']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_lieberman_credential(host=load_test_data['lieberman']['host'],
                                                                  port=load_test_data['lieberman']['port'],
                                                                  ssl=load_test_data['lieberman']['ssl'],
                                                                  ssl_verify=load_test_data['lieberman']['ssl_verify'],
                                                                  pam_user=load_test_data['lieberman']['pam_user'],
                                                                  pam_password=load_test_data['lieberman']['pam_password'],
                                                                  username=load_test_data['lieberman']['username'],))
        scan_model.plugins = [plugin_id]
        target = load_test_data['lieberman']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_text = 'It was possible to log into the remote host via SSH using \'password\' authentication'
        assert expected_text in outputs[0]['plugin_output'], 'Login failed'
        
    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_ssh_beyondtrust_linux_login(self, load_test_data):
        """Linux beyondtrust login test"""
        plugin_id = load_test_data['beyondtrust']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_beyondtrust_credential(host=load_test_data['beyondtrust']['host'],
                                                                    port=load_test_data['beyondtrust']['port'],
                                                                    ssl=load_test_data['beyondtrust']['ssl'],
                                                                    ssl_verify=load_test_data['beyondtrust']['ssl_verify'],
                                                                    api_key=load_test_data['beyondtrust']['api_key'],
                                                                    username=load_test_data['beyondtrust']['username'],
                                                                    duration_minutes=load_test_data['beyondtrust']['duration_minutes'],
                                                                    try_private_key=False,
                                                                    try_escalation=load_test_data['beyondtrust']['try_escalation']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['beyondtrust']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_text = 'It was possible to log into the remote host via SSH using \'password\' authentication'
        assert expected_text in outputs[0]['plugin_output'], 'Login failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_ssh_beyondtrust_linux_login_private_key(self, load_test_data):
        """Linux beyondtrust login test"""
        plugin_id = load_test_data['beyondtrust']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_beyondtrust_credential(host=load_test_data['beyondtrust']['host'],
                                                                    port=load_test_data['beyondtrust']['port'],
                                                                    ssl=load_test_data['beyondtrust']['ssl'],
                                                                    ssl_verify=load_test_data['beyondtrust']['ssl_verify'],
                                                                    api_key=load_test_data['beyondtrust']['api_key'],
                                                                    username=load_test_data['beyondtrust']['username'],
                                                                    duration_minutes=load_test_data['beyondtrust']['duration_minutes'],
                                                                    try_private_key=True,
                                                                    try_escalation=load_test_data['beyondtrust']['try_escalation']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['beyondtrust']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_text = 'It was possible to log into the remote host via SSH using \'publickey\' authentication'
        assert expected_text in outputs[0]['plugin_output'], 'Login failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_ssh_beyondtrust_linux_login_private_key_escalation(self, load_test_data):
        """Linux beyondtrust login test"""
        plugin_id = load_test_data['beyondtrust']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ssh_credential(
            CredentialHelper.Host.create_ssh_beyondtrust_credential(host=load_test_data['beyondtrust']['host'],
                                                                    port=load_test_data['beyondtrust']['port'],
                                                                    ssl=load_test_data['beyondtrust']['ssl'],
                                                                    ssl_verify=load_test_data['beyondtrust']['ssl_verify'],
                                                                    api_key=load_test_data['beyondtrust']['api_key'],
                                                                    username=load_test_data['beyondtrust']['username'],
                                                                    duration_minutes=load_test_data['beyondtrust']['duration_minutes'],
                                                                    try_private_key=True,
                                                                    try_escalation=True))
        scan_model.plugins = [plugin_id]
        target = load_test_data['beyondtrust']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        # this text wont show up if we try to escalate priviledges and fail
        expected_text = 'Local security checks have been enabled for this host'
        assert expected_text in outputs[0]['plugin_output'], 'Sudo failed'

