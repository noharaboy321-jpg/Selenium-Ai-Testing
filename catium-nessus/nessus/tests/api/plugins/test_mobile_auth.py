"""
Nessus plugin Mobile Devices authentication
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
@pytest.mark.parametrize('test_data_file', ['nessus/tests/api/plugins/test_data/test_mobile_auth.json'])
class TestMobileAuth:
    """
    Test class for Mobile auth
    """

    cat = None

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_airwatch_login(self, load_test_data):
        """Verify airwatch can be authenticated to using AW cloud service."""
        plugin_id_report = load_test_data['airwatch']['plugin_id_report']
        scan_model = ScanModel.create_model()
        scan_model.add_airwatch_credential(
            CredentialHelper.Mobile.create_airwatch_credential(api_url=load_test_data['airwatch']['api_url'],
                                                               port=load_test_data['airwatch']['port'],
                                                               username=load_test_data['airwatch']['username'],
                                                               password=load_test_data['airwatch']['password'],
                                                               api_key=load_test_data['airwatch']['api_key'],
                                                               https=load_test_data['airwatch']['https'],
                                                               verify_ssl=load_test_data['airwatch']['verify_ssl']))
        scan_model.uuid = load_test_data['airwatch']['uuid']
        scan_type = Nessus.Scan.ResultTypes.MOBILE
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['airwatch']['target'], plugin_id_report,
                               scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'AirWatch' in outputs[0]['plugin_output'] and 'Managed By' in outputs[0]['plugin_output'],\
            'AirWatch MDM Authentication'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_mobile_iron_login(self, load_test_data):
        """Verify mobile iron can be authenticated to. """
        plugin_id_report = load_test_data['mobileiron']['plugin_id_report']
        scan_model = ScanModel.create_model()
        scan_model.add_mobile_iron_credential(
            CredentialHelper.Mobile.create_mobile_iron_credential(
                portal_url=load_test_data['mobileiron']['portal_url'], port=load_test_data['mobileiron']['port'],
                username=load_test_data['mobileiron']['username'], password=load_test_data['mobileiron']['password'],
                https=load_test_data['mobileiron']['https'], verify_ssl=load_test_data['mobileiron']['verify_ssl']))
        scan_model.uuid = load_test_data['mobileiron']['uuid']
        scan_type = "mobile"
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['mobileiron']['target'], plugin_id_report,
                               scan_type)
        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'MobileIron' in outputs[0]['plugin_output'] and 'Managed By' in outputs[0]['plugin_output'],\
            'MDM Mobile Device Reporting'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_good_mdm_login(self, load_test_data):
        """Verify Good MDM can be authenticated to. """
        plugin_id_report = load_test_data['goodmdm']['plugin_id_report']
        scan_model = ScanModel.create_model()
        scan_model.add_good_mdm_credential(
            CredentialHelper.Mobile.create_good_mdm_credential(server=load_test_data['goodmdm']['server'],
                                                               port=load_test_data['goodmdm']['port'],
                                                               domain=load_test_data['goodmdm']['domain'],
                                                               username=load_test_data['goodmdm']['username'],
                                                               password=load_test_data['goodmdm']['password'],
                                                               https=load_test_data['goodmdm']['https'],
                                                               verify_ssl=load_test_data['goodmdm']['verify_ssl']))
        scan_model.uuid = load_test_data['goodmdm']['uuid']
        scan_type = "mobile"
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['goodmdm']['target'], plugin_id_report,
                               scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'Good MDM' in outputs[0]['plugin_output'] and 'Managed By' in \
            outputs[0]['plugin_output'], 'MDM Mobile Device Reporting'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_apple_profile_manager_login(self, load_test_data):
        """Verify apple profile manager can be authenticated to. """
        plugin_id_report = load_test_data['apm']['plugin_id_report']
        scan_model = ScanModel.create_model()
        scan_model.add_apple_profile_manager_credential(
            CredentialHelper.Mobile.create_apple_profile_manager_credential(
                server=load_test_data['apm']['server'], port=load_test_data['apm']['port'],
                username=load_test_data['apm']['username'], password=load_test_data['apm']['password'],
                https=load_test_data['apm']['https'], verify_ssl=load_test_data['apm']['verify_ssl']))
        scan_model.uuid = load_test_data['apm']['uuid']
        scan_model.apm_force_updates = load_test_data['apm']['apm_force_updates']
        scan_type = Nessus.Scan.ResultTypes.MOBILE
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['apm']['target'], plugin_id_report, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'profile_manager' in outputs[0]['plugin_output'] and 'Managed By' in outputs[0]['plugin_output'],\
            'Apple Profile Manager Authentication'

    # API_Tested# GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
    def test_maas360_login(self, load_test_data):
        """Verify maas360 can be authenticated to. """
        plugin_id_report = load_test_data['maas360']['plugin_id_report']
        scan_model = ScanModel.create_model()
        scan_model.add_maas360_credential(
            CredentialHelper.Mobile.create_maas360_credential(
                root_url=load_test_data['maas360']['root_url'], platform_id=load_test_data['maas360']['platform_id'],
                billing_id=load_test_data['maas360']['billing_id'], app_id=load_test_data['maas360']['app_id'],
                app_version=load_test_data['maas360']['app_version'],
                app_access_key=load_test_data['maas360']['app_access_key'],
                username=load_test_data['maas360']['username'], password=load_test_data['maas360']['password']))
        scan_model.uuid = load_test_data['maas360']['uuid']
        scan_type = Nessus.Scan.ResultTypes.MOBILE
        json_out, audit_trail = launch_scan(self.cat.api, scan_model, load_test_data['maas360']['target'],
                               plugin_id_report, scan_type)

        outputs = json_out['outputs']
        if outputs is None:
            pytest.fail('plugin did not fire: ' + str(json_out))
        assert 'MaaS360' in outputs[0]['plugin_output'] and 'Managed By' in \
            outputs[0]['plugin_output'], 'MaaS360 Authentication'
