"""
Tests for license restrictions
"""
import pytest

from catium.helpers.testdata import get_file_path


@pytest.fixture()
def use_api_v2(request: 'SubRequest'):
    # header needed for "plugins" to be returned from /editor/scan/ calls
    # TODO - should we add this by default everywhere?
    request.instance.cat.api.add_header({'X-API-Version': "2"})
    yield True
    request.instance.cat.api.remove_header('X-API-Version')


@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'use_api_v2')
class TestPluginsLicenseRestrictions:
    """
    NES-8895, NES-8896, NES-8888, NES-8939

    For the purposes of this test class, restrictions are as follows:

    - plugin family 'Backdoors':      allowed on Pro and Manager
    - plugin family 'Mobile Devices': restricted on Pro, allowed on Manager

    (defined in restrictions.json)
    """

    def get_server_type(self):
        properties = self.cat.api.server.properties()
        return properties['license']['type']

    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    def test_get_families_unrestricted(self, request):
        """
        NES-8888
        Verifies that even restricted families are always included in full plugin families list

        Scenarios tested:
        [x] Pro: Test that plugin families does not include 'Mobile Devices'
        [x] Manager: Test that plugin families does include 'Mobile Devices'
        """
        families = self.cat.api.plugins.families()
        families = [f['name'] for f in families['families']]
        # TODO - decide whether this is correct behavior
        assert 'Mobile Devices' in families

    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'Advanced'}])
    def test_scan_families_restricted(self, create_scan):
        """
        NES-8888
        Verifies that a from-defaults advanced scan has the appropriate restriction applied

        Scenarios tested:
        [x] Test that created scan's plugin families includes unrestricted 'Backdoors'
        [x] Pro: Test that created scan's plugin families does not include 'Mobile Devices'
        [x] Manager: Test that created scan's plugin families does include 'Mobile Devices'
        """
        scan_id = create_scan['scan']['id']
        details = self.cat.api.editor.get_scan(scan_id)
        families = details['plugins']['families'].keys()

        assert 'Backdoors' in families
        typ = self.get_server_type()
        if typ == 'professional':
            assert 'Mobile Devices' not in families
        elif typ == 'manager':
            assert 'Mobile Devices' in families
        else:
            assert False, "Unhandled license type %s" % typ

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan_explicit_mobile.json'),
         'scan_type': 'Advanced'}])
    def test_scan_families_restricted_explicit(self, create_scan):
        """
        NES-8888
        Verifies that a restricted plugin family is ignored on scan creation

        Scenarios tested:
        [x] Test that scan's plugin families always includes 'Backdoors'
        [x] Pro: Test that creating a scan with {'Mobile Devices': 'enabled'} is ignored
        [x] Manager: Test that creating a scan with {'Mobile Devices': 'enabled'} is respected
        """
        scan_id = create_scan['scan']['id']
        details = self.cat.api.editor.get_scan(scan_id)
        families = details['plugins']['families'].keys()

        assert 'Backdoors' in families
        typ = self.get_server_type()
        if typ == 'professional':
            assert 'Mobile Devices' not in families
        elif typ == 'manager':
            assert 'Mobile Devices' in families
        else:
            assert False, "Unhandled license type %s" % typ

    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    def test_template_restricted_families(self):
        """
        NES-8888
        Verifies that plugin families are properly restricted in templates

        Scenarios tested:
        [x] Test that Advanced Network Scan template always includes 'Backdoors'
        [x] Pro: Test that Advanced template does not include 'Mobile Devices'
        [x] Manager: Test that Advanced template does include 'Mobile Devices'
        """
        templates = self.cat.api.editor.get_templates('scan')['templates']
        uuids_by_name = {t['name']: t['uuid'] for t in templates}
        advanced_uuid = uuids_by_name['advanced']

        details = self.cat.api.editor.details('scan', advanced_uuid)
        families = details['plugins']['families'].keys()

        assert 'Backdoors' in families
        typ = self.get_server_type()
        if typ == 'professional':
            assert 'Mobile Devices' not in families
        elif typ == 'manager':
            assert 'Mobile Devices' in families
        else:
            assert False, "Unhandled license type %s" % typ

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'Advanced'}])
    def test_get_scan_plugins_by_family(self, create_scan):
        """
        NES-8888
        Verifies that looking up a plugin list by family respects restrictions

        Scenarios tested:
        [x] Test that we can get plugins for 'Backdoors'
        [x] Pro: Test that looking up 'Mobile Devices' returns empty list
        [x] Manager: Test that looking up 'Mobile Devices' returns non-empty list
        """
        all_families = self.cat.api.plugins.families()
        family_id_by_name = {f['name']: f['id'] for f in all_families['families']}

        scan_id = create_scan['scan']['id']
        details = self.cat.api.editor.get_scan(scan_id)

        backdoor_plugins = self.cat.api.editor.get_family('scan', scan_id, family_id_by_name['Backdoors'])
        backdoor_plugins = backdoor_plugins['plugins']
        assert len(backdoor_plugins) > 0, 'Empty list for "Backdoors" plugin family'

        mobile_plugins = self.cat.api.editor.get_family('scan', scan_id, family_id_by_name['Mobile Devices'])
        mobile_plugins = mobile_plugins['plugins']

        typ = self.get_server_type()
        if typ == 'professional':
            assert mobile_plugins == None, 'Non-empty list of "Mobile Devices" plugins returned'
        elif typ == 'manager':
            assert len(mobile_plugins) > 0, 'Empty list of "Mobile Devices" plugins returned'
        else:
            assert False, "Unhandled license type %s" % typ
