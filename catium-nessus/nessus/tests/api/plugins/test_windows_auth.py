"""
Nessus plugin Windows authentication
"""
import pytest

from nessus.helpers.credentials.credential import CredentialHelper
from nessus.models.scan import ScanModel
from nessus.helpers.scan import launch_scan


@pytest.mark.scanning
@pytest.mark.plugins
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.usefixtures('load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/plugins/test_data/test_windows_auth.json'])
class TestWindowsAuth:
    """
    Test class for Windows auth
    """

    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_windows_password_no_domain_auth(self, load_test_data):
        """Verify Windows host can be authenticated to via password auth."""
        plugin_id = load_test_data['win_password']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_win_password_credential(username=load_test_data['win_password']['username'],
                                                                 password=load_test_data['win_password']['password'],
                                                                 domain=load_test_data['win_password']['domain'])
        )
        scan_model.plugins = [plugin_id]

        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['win_password']['target'], plugin_id)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'The SMB tests will be done as ' + load_test_data['win_password']['username'] in \
               outputs[0]['plugin_output'], 'Local checks failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_windows_password_domain_auth(self, load_test_data):
        """Verify Windows host can be authenticated to via password auth."""
        plugin_id = load_test_data['win_domain_password']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_win_password_credential(
                username=load_test_data['win_domain_password']['username'],
                password=load_test_data['win_domain_password']['password'],
                domain=load_test_data['win_domain_password']['domain'])
        )
        scan_model.plugins = [plugin_id]

        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['win_domain_password']['target'], plugin_id)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'The SMB tests will be done as ' + load_test_data['win_domain_password']['domain'] + """\\""" + \
               load_test_data['win_domain_password']['username'] in outputs[0]['plugin_output'], 'Local checks failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_windows_password_domain_auth_fail(self, load_test_data):
        """Verify Windows host can be authenticated to via password auth."""
        plugin_id = load_test_data['win_password']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_win_password_credential(
                username=load_test_data['win_domain_password']['username'],
                password=load_test_data['win_domain_password']['bad_password'],
                domain=load_test_data['win_domain_password']['domain'])
        )
        scan_model.plugins = [plugin_id]

        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['win_password']['target'], plugin_id)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'The SMB tests will be done as ' not in outputs[0]['plugin_output'], 'Local checks failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    @pytest.mark.skip(reason="Thycotic Plugins being reworked under RPI-336")
    def test_thycotic_win_login(self, load_test_data):
        """Windows thycotic login test"""
        plugin_id = load_test_data['thycotic_pass']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_windows_thycotic_credential(
                username=load_test_data['thycotic_pass']['username'],
                name=load_test_data['thycotic_pass']['secretName'],
                url=load_test_data['thycotic_pass']['url'],
                login=load_test_data['thycotic_pass']['login'],
                password=load_test_data['thycotic_pass']['password'])
        )
        scan_model.plugins = [plugin_id]
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['thycotic_pass']['target'], plugin_id)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert '- The SMB tests will be done as admin/******' in outputs[0]['plugin_output'],\
               'Login via Thycotic server failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    @pytest.mark.skip(reason="Thycotic Plugins being reworked under RPI-336")
    def test_thycotic_win_login_fail(self, load_test_data):
        """Windows thycotic login fail test"""
        plugin_id = load_test_data['thycotic_fail']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_windows_thycotic_credential(
                username=load_test_data['thycotic_fail']['username'],
                name=load_test_data['thycotic_fail']['secretName'],
                url=load_test_data['thycotic_fail']['url'],
                login=load_test_data['thycotic_fail']['login'],
                password=load_test_data['thycotic_fail']['password'])
        )
        scan_model.plugins = [plugin_id]
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['thycotic_fail']['target'], plugin_id)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert '- NULL sessions are enabled on the remote host' in outputs[0]['plugin_output'],\
               'Expected failed login did not occur'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_windows_kerberos_login(self, load_test_data):
        """Windows kerberos login test"""
        plugin_id = load_test_data['kerberos']['plugin_id']
        scan_model = ScanModel.create_model()

        scan_model.add_windows_credential(
            CredentialHelper.Host.create_windows_kerberos_credential
            (username=load_test_data['kerberos']['username'],
             password=load_test_data['kerberos']['password'],
             kdc=load_test_data['kerberos']['kdc'],
             domain=load_test_data['kerberos']['domain']))

        scan_model.plugins = [plugin_id]

        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['kerberos']['target'], plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))

        expected_text = 'The SMB tests will be done as ' + load_test_data['kerberos']['domain'] + '\\' \
                                                         + load_test_data['kerberos']['username']

        assert expected_text in outputs[0]['plugin_output'], 'Login failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_windows_kerberos_login_fail(self, load_test_data):
        """Windows kerberos login failed test"""
        plugin_id = load_test_data['kerberos']['plugin_id']
        scan_model = ScanModel.create_model()

        scan_model.add_windows_credential(
            CredentialHelper.Host.create_windows_kerberos_credential
            (username=load_test_data['kerberos']['username'],
             password=load_test_data['kerberos']['password'] + "badpass",
             kdc=load_test_data['kerberos']['kdc'],
             domain=load_test_data['kerberos']['domain']))

        scan_model.plugins = [plugin_id]

        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['kerberos']['target'], plugin_id)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))

        expected_text = 'The SMB tests will be done as ' + load_test_data['kerberos']['domain'] + '\\' \
                                                         + load_test_data['kerberos']['username']

        assert not(expected_text in outputs[0]['plugin_output']), 'Login succeeded with bad password.'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    @pytest.mark.skip(reason="CyberArk is configured in a special way for testing.  Should be fixed Feb 25th.")
    def test_smb_cyberark_windows_login(self, load_test_data):
        """Windows cyberark login test"""
        plugin_id = load_test_data['cyberark']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_windows_cyberark_credential(username=load_test_data['cyberark']['username'],
                                                                     host=load_test_data['cyberark']['host'],
                                                                     safe=load_test_data['cyberark']['safe'],
                                                                     appid=load_test_data['cyberark']['app_id'],
                                                                     folder_id=load_test_data['cyberark']['folder_id'],
                                                                     use_ssl=
                                                                     load_test_data['cyberark']['use_ssl'],
                                                                     verify_ssl=
                                                                     load_test_data['cyberark']['verify_ssl'],
                                                                     port=load_test_data['cyberark']['port'],
                                                                     elevate_privileges=
                                                                     load_test_data['cyberark']['elevate_privileges']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['cyberark']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'The SMB tests will be done as ' + load_test_data['cyberark']['username'] in \
               outputs[0]['plugin_output'], 'Local checks failed'
    
    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_smb_beyondtrust_windows_login(self, load_test_data):
        """Windows beyondtrust login test"""
        plugin_id = load_test_data['beyondtrust']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_windows_beyondtrust_credential(host=load_test_data['beyondtrust']['host'],
                                                                    port=load_test_data['beyondtrust']['port'],
                                                                    ssl=load_test_data['beyondtrust']['ssl'],
                                                                    ssl_verify=load_test_data['beyondtrust']['ssl_verify'],
                                                                    api_key=load_test_data['beyondtrust']['api_key'],
                                                                    username=load_test_data['beyondtrust']['username'],
                                                                    duration_minutes=load_test_data['beyondtrust']['duration_minutes']))
        scan_model.plugins = [plugin_id]
        target = load_test_data['beyondtrust']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'The SMB tests will be done as ' + load_test_data['beyondtrust']['username'] in \
               outputs[0]['plugin_output'], 'Local checks failed'

    def test_smb_lieberman_windows_login(self, load_test_data):
        """Windows lieberman login test"""
        plugin_id = load_test_data['lieberman']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_windows_credential(
            CredentialHelper.Host.create_windows_lieberman_credential(host=load_test_data['lieberman']['host'],
                                                                      port=load_test_data['lieberman']['port'],
                                                                      ssl=load_test_data['lieberman']['ssl'],
                                                                      ssl_verify=load_test_data['lieberman']['ssl_verify'],
                                                                      pam_user=load_test_data['lieberman']['pam_user'],
                                                                      pam_password=load_test_data['lieberman']['pam_password'],
                                                                      username=load_test_data['lieberman']['username'],
                                                                      domain=load_test_data['lieberman']['domain'],))
        scan_model.plugins = [plugin_id]
        target = load_test_data['lieberman']['target']
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, target, plugin_id)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'The SMB tests will be done as ' + load_test_data['lieberman']['domain'] + "\\" + load_test_data['lieberman']['username'] in \
               outputs[0]['plugin_output'], 'Local checks failed'
