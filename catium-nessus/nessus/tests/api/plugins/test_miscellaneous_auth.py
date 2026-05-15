"""
Nessus plugin miscellaneous authentication
"""
import pytest

from catium.lib import const
from nessus.helpers.credentials.credential import CredentialHelper
from nessus.models.scan import ScanModel
from nessus.helpers.scan import launch_scan
from nessus.lib.const import Nessus


@pytest.mark.scanning
@pytest.mark.plugins
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.usefixtures('load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/plugins/test_data/test_miscellaneous_auth.json'])
class TestMiscellaneousAuth:
    """
    Test class for miscellaneous auth
    """

    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_adsi_auth(self, load_test_data):
        """ Verify host can be authenticated to via ADSI. """
        plugin_id = load_test_data['adsi']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_adsi_credential(
            CredentialHelper.Miscellaneous.create_asdi_credential(
                domain_controller=load_test_data['adsi']['domain_controller'],
                domain=load_test_data['adsi']['domain'],
                domain_admin=load_test_data['adsi']['domain_admin'],
                domain_pwd=load_test_data['adsi']['domain_pwd'])
        )
        scan_model.plugins = [plugin_id]

        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['adsi']['target'],
                               plugin_id, Nessus.Scan.ResultTypes.ADSI)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))

        expected = load_test_data['adsi']['domain_controller'].split('.')
        expected = "DC=" + ",DC=".join(expected[1:])
        assert expected in outputs[0]['plugin_output'], 'ADSI scan failed.'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    @pytest.mark.skip(reason="Test expects an empty response. We need to rework this test")
    def test_adsi_auth_fails(self, load_test_data):
        """ Verify ADSI authentication fails with bad credentials. """
        plugin_id = load_test_data['adsi']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_adsi_credential(
            CredentialHelper.Miscellaneous.create_asdi_credential(
                domain_controller=load_test_data['adsi']['domain_controller'],
                domain=load_test_data['adsi']['domain'],
                domain_admin=load_test_data['adsi']['domain_admin'],
                domain_pwd=load_test_data['adsi']['domain_pwd'] + 'foo')
        )

        scan_model.plugins = [plugin_id]

        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['adsi']['target'],
                               plugin_id, Nessus.Scan.ResultTypes.ADSI)

        outputs = json_out['outputs']

        # All of the ADSI plugins return nothing if auth fails
        assert outputs is None, 'Scan results not empty. ADSI scan with bad creds should return nothing.'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_vmware_esx_login(self, load_test_data):
        """Verify VMWare ESX can be authenticated to with provided credentials"""
        plugin_id = load_test_data['vmware_esx']['plugin']
        scan_model = ScanModel.create_model()
        scan_model.add_vmware_esx_credential(
            CredentialHelper.Miscellaneous.create_vmware_esx_credential(username=load_test_data
                                                                        ['vmware_esx']['username'],
                                                                        password=load_test_data
                                                                        ['vmware_esx']['password'],
                                                                        dont_verify_ssl=load_test_data
                                                                        ['vmware_esx']['dont_verify_ssl'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = Nessus.Scan.ResultTypes.MISCELLANEOUS
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['vmware_esx']['target'], plugin_id,
                               scan_type)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'There are no active virtual machines' in outputs[0]['plugin_output'], \
            'Failed to log via VMWare ESX'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_vmware_vcenter_login(self, load_test_data):
        """Verify VMWare vCenter can be authenticated to with provided credentials"""
        plugin_id = load_test_data['vmware_vcenter']['plugin']
        scan_model = ScanModel.create_model()
        scan_model.add_vmware_vcenter_credential(
            CredentialHelper.Miscellaneous.create_vmware_vcenter_credential(host=load_test_data
                                                                            ["vmware_vcenter"]["host"],
                                                                            port=load_test_data
                                                                            ["vmware_vcenter"]["port"],
                                                                            username=load_test_data
                                                                            ['vmware_vcenter']['username'],
                                                                            password=load_test_data
                                                                            ['vmware_vcenter']['password'],
                                                                            https=load_test_data
                                                                            ["vmware_vcenter"]["https"],
                                                                            verify_ssl=load_test_data
                                                                            ['vmware_vcenter']['verify_ssl'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = Nessus.Scan.ResultTypes.MISCELLANEOUS
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['vmware_vcenter']['target'], plugin_id,
                               scan_type)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Active virtual machines' in outputs[0]['plugin_output'], \
            'Failed to log via VMWare vCenter'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_x509_login(self, load_test_data):
        """Verify that socket level X509 authentication works against a configured web server"""
        plugin_id = load_test_data['x509']['plugin']
        scan_type = Nessus.Scan.ResultTypes.MISCELLANEOUS
        scan_model = ScanModel.create_model()
        scan_model.add_x509_credential(
            CredentialHelper.Miscellaneous.create_x509_credential(api=self.cat.api,
                                                                  client_cer=load_test_data['x509']['client_cert'],
                                                                  client_key=load_test_data['x509']['client_key'],
                                                                  key_pwd=load_test_data['x509']['key_pwd'],
                                                                  ca_cer=load_test_data['x509']['ca_cert'])
        )
        scan_model.plugins = [plugin_id]
        scan_model.scan_webapps = const.STRING_YES
        scan_model.ssl_prob_ports = "All ports"
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['x509']['target'], plugin_id, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))

        assert 'The following sitemap was created' in outputs[0]['plugin_output'], \
            'Failed to log via X.509 credential.'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_x509_login_fails(self, load_test_data):
        """Verify that socket level X509 authentication fails when no credential is used"""
        plugin_id = load_test_data['x509']['plugin']
        scan_type = Nessus.Scan.ResultTypes.MISCELLANEOUS
        scan_model = ScanModel.create_model()
        scan_model.plugins = [plugin_id]
        scan_model.scan_webapps = const.STRING_YES
        scan_model.ssl_prob_ports = "All ports"
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['x509']['target'], plugin_id,
                                scan_type, check_audit = True)

        outputs = json_out['outputs']

        # Web crawling plugin should return nothing if auth fails
        assert outputs is None, 'Scan results not empty. X.509 scan with bad creds should return nothing.'
