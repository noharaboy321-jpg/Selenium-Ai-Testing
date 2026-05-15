"""
Nessus plugin Patch Management authentication
"""
import pytest

from nessus.helpers.credentials.credential import CredentialHelper
from nessus.models.scan import ScanModel
from nessus.helpers.scan import launch_scan
from nessus.lib.const import Nessus


@pytest.mark.scanning
@pytest.mark.plugins
@pytest.mark.usefixtures('nessus_api_login')
@pytest.mark.usefixtures('load_test_data')
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/plugins/test_data/test_patch_management_auth.json'])
class TestPatchManagementAuth:
    """
    Test class for Patch Management
    """

    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_sccm_login(self, load_test_data):
        """Verify SCCM can be authenticated to"""
        plugin_id = load_test_data['sccm_login']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_microsoft_sccm_credential(
            CredentialHelper.PatchManagement.create_microsoft_sccm_credential(
                server=load_test_data['sccm_login']['server'],
                domain=load_test_data['sccm_login']['domain'],
                username=load_test_data['sccm_login']['username'],
                password=load_test_data['sccm_login']['password'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = "patch management"
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['sccm_login']['target'],
                               plugin_id, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert '+ System Information\n\n  - Computer Name : NPW_QA_SCCM_MEM' in outputs[0]['plugin_output'], \
            'Failed to log into SCCM'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_sccm_no_missing_updates(self, load_test_data):
        """Verify SCCM no missing updates"""
        plugin_id = load_test_data['sccm_no_missing_updates']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_microsoft_sccm_credential(
            CredentialHelper.PatchManagement.create_microsoft_sccm_credential(
                server=load_test_data['sccm_no_missing_updates']['server'],
                domain=load_test_data['sccm_no_missing_updates']['domain'],
                username=load_test_data['sccm_no_missing_updates']['username'],
                password=load_test_data['sccm_no_missing_updates']['password'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = "patch management"
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['sccm_no_missing_updates']['target'],
                               plugin_id, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'SCCM is unaware of any outstanding security updates.' in outputs[0]['plugin_output'], 'Failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_sccm_missing_updates(self, load_test_data):
        """Verify SCCM missing updates"""
        plugin_id = load_test_data['sccm_missing_updates']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_microsoft_sccm_credential(
            CredentialHelper.PatchManagement.create_microsoft_sccm_credential(
                server=load_test_data['sccm_missing_updates']['server'],
                domain=load_test_data['sccm_missing_updates']['domain'],
                username=load_test_data['sccm_missing_updates']['username'],
                password=load_test_data['sccm_missing_updates']['password'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = "patch management"
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['sccm_missing_updates']['target'],
                               plugin_id, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Missing Update List' in outputs[0]['plugin_output'], 'Failed'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_wsus_login(self, load_test_data):
        """Verify WSUS login"""
        plugin_id = load_test_data['wsus_login']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_microsoft_wsus_credential(
            CredentialHelper.PatchManagement.create_microsoft_wsus_credential(
                server=load_test_data['wsus_login']['server'],
                port=load_test_data['wsus_login']['port'],
                username=load_test_data['wsus_login']['username'],
                password=load_test_data['wsus_login']['password'],
                https=load_test_data['wsus_login']['https'],
                verify_ssl=load_test_data['wsus_login']['verify_ssl'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = "patch management"
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['wsus_login']['target'],
                               plugin_id, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        expected_str = '\nWSUS Computer Information \n\n  FQDN             : npw-qa-wsus.wsus.lab.tenablesecurity.com'
        assert expected_str in outputs[0]['plugin_output'], 'Failed to log into WSUS server'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_dell_kace_login(self, load_test_data):
        """Verify Dell KACE K1000 can be authenticated to"""
        plugin_id = load_test_data['kace']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_dell_kace_credential(
            CredentialHelper.PatchManagement.create_dell_kace_credential(server=load_test_data['kace']['server'],
                                                                         port=load_test_data['kace']['port'],
                                                                         org_db_name=load_test_data['kace']
                                                                         ['org_db_name'],
                                                                         username=load_test_data['kace']['username'],
                                                                         password=load_test_data['kace']['password'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = Nessus.Scan.ResultTypes.PATCHMANAGEMENT
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['kace']['target'],
                               plugin_id, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert '+ System Information\n\n  - Name             : WIN-CDKEJKBKUNF' in outputs[0]['plugin_output'], \
            'Failed to log into Dell Kace'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugin/{plugin_id}
    def test_ibm_bigfix_login(self, load_test_data):
        """Verify IBM BigFix can be authenticated to"""
        plugin_id = load_test_data['ibm_bigfix']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_ibm_bigfix_credential(
            CredentialHelper.PatchManagement.create_ibm_bigfix_credential(server=load_test_data['ibm_bigfix']['server'],
                                                                          port=load_test_data['ibm_bigfix']['port'],
                                                                          username=load_test_data['ibm_bigfix']
                                                                          ['username'],
                                                                          password=load_test_data['ibm_bigfix']
                                                                          ['password'],
                                                                          https=load_test_data['ibm_bigfix']
                                                                          ['https'],
                                                                          verify_ssl=load_test_data['ibm_bigfix']
                                                                          ['verify_ssl'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = Nessus.Scan.ResultTypes.PATCHMANAGEMENT
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['ibm_bigfix']['target'],
                               plugin_id, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Credentialed checks : yes' in outputs[0]['plugin_output'], \
            'Failed to log into IBM BigFix'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_redhat_satellite5_login(self, load_test_data):
        """Verify Red Hat Satellite 5 can be authenticated to"""
        plugin_id = load_test_data['redhat_satellite5']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.add_redhat_satellite5_credential(
            CredentialHelper.PatchManagement.create_redhat_satellite5_credential(server=load_test_data
                                                                                 ['redhat_satellite5']['server'],
                                                                                 port=load_test_data
                                                                                 ['redhat_satellite5']['port'],
                                                                                 username=load_test_data
                                                                                 ['redhat_satellite5']['username'],
                                                                                 password=load_test_data
                                                                                 ['redhat_satellite5']['password'],
                                                                                 verify_ssl=load_test_data
                                                                                 ['redhat_satellite5']['verify_ssl'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = Nessus.Scan.ResultTypes.PATCHMANAGEMENT
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['redhat_satellite5']['target'],
                               plugin_id, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'According to the Red Hat Satellite server' in outputs[0]['plugin_output'], \
            'Failed to log into Red Hat Satellite 5'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_redhat_satellite6_login(self, load_test_data):
        """Verify Red Hat Satellite 6 can be authenticated to"""
        plugins = load_test_data['redhat_satellite6']['enable_plugins']
        plugin_id = load_test_data['redhat_satellite6']['plugin_id']
        scan_model = ScanModel.create_model()
        scan_model.enable_plugin_debugging = load_test_data['redhat_satellite6']['enable_plugin_debugging']
        scan_model.add_redhat_satellite6_credential(
            CredentialHelper.PatchManagement.create_redhat_satellite6_credential(server=load_test_data
                                                                                 ['redhat_satellite6']['server'],
                                                                                 port=load_test_data
                                                                                 ['redhat_satellite6']['port'],
                                                                                 username=load_test_data
                                                                                 ['redhat_satellite6']['username'],
                                                                                 password=load_test_data
                                                                                 ['redhat_satellite6']['password'],
                                                                                 https=load_test_data
                                                                                 ['redhat_satellite6']['https'],
                                                                                 verify_ssl=load_test_data
                                                                                 ['redhat_satellite6']['verify_ssl'])
        )
        scan_model.plugins = plugins
        scan_type = Nessus.Scan.ResultTypes.PATCHMANAGEMENT
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['redhat_satellite6']['target'],
                                            plugin_id, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert '+ System Information' or '+ Host Information' in outputs[0]['plugin_output'], \
            'Failed to log into Red Hat Satellite 6'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_symantec_altiris_windows_login(self, load_test_data):
        """Verify Symantec Altiris can be authenticated to with Windows credentials"""
        plugin_id = load_test_data['altiris_windows']['plugin']
        scan_model = ScanModel.create_model()
        scan_model.add_symantec_altiris_credential(
            CredentialHelper.PatchManagement.create_symantec_altiris_credential(server=load_test_data
                                                                                ['altiris_windows']['server'],
                                                                                port=
                                                                                load_test_data['altiris_windows']
                                                                                ['port'],
                                                                                username=load_test_data
                                                                                ['altiris_windows']['username'],
                                                                                password=load_test_data
                                                                                ['altiris_windows']['password'],
                                                                                db_name=load_test_data
                                                                                ['altiris_windows']['db_name'],
                                                                                use_windows_auth=load_test_data
                                                                                ['altiris_windows']
                                                                                ['use_windows_auth'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = Nessus.Scan.ResultTypes.PATCHMANAGEMENT
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['altiris_windows']['target'], plugin_id,
                               scan_type)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Managed By       : RE-ALTIRIS-CMS.tenaltiris.com' in outputs[0]['plugin_output'], \
            'Failed to log into Symantec Altiris'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_symantec_altiris_not_windows_login(self, load_test_data):
        """Verify Symantec Altiris can be authenticated to with non-Windows credentials"""
        plugin_id = load_test_data['altiris_not_windows']['plugin']
        scan_model = ScanModel.create_model()
        scan_model.add_symantec_altiris_credential(
            CredentialHelper.PatchManagement.create_symantec_altiris_credential(server=load_test_data
                                                                                ['altiris_not_windows']['server'],
                                                                                port=load_test_data
                                                                                ['altiris_not_windows']['port'],
                                                                                username=load_test_data
                                                                                ['altiris_not_windows']['username'],
                                                                                password=load_test_data
                                                                                ['altiris_not_windows']['password'],
                                                                                db_name=load_test_data
                                                                                ['altiris_windows']['db_name'],
                                                                                use_windows_auth=load_test_data
                                                                                ['altiris_not_windows']
                                                                                ['use_windows_auth'])
        )
        scan_model.plugins = [plugin_id]
        scan_type = Nessus.Scan.ResultTypes.PATCHMANAGEMENT
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['altiris_not_windows']['target'], plugin_id,
                               scan_type)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Managed By       : RE-ALTIRIS-CMS.tenaltiris.com' in outputs[0]['plugin_output'], \
            'Failed to log into Symantec Altiris'
