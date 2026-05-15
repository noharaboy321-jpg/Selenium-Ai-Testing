"""
Unit Test
"""
import pytest


@pytest.mark.unittest
@pytest.mark.usefixtures('nessus_class_api_login')
class TestNessusPluginsEndpoint:
    """Tests for the Nessus plugins endpoint"""

    cat = None

    # API_Tested# GET /plugins/families
    def test_get_families(self):
        """
        Verifies that a list of families can be retrieved
        
        Scenarios tested:
            [x] Test that a list of families can be retrieved
        """
        families = self.cat.api.plugins.families()
        assert len(families['families']) > 0, 'No families returned'

    # API_Tested# GET /plugins/families/{family_id}
    def test_get_plugins_for_family(self):
        """
        Verifies that a list of plugins can be retrieved for a specific family ID
        
        Scenarios tested:
            [x] Test that a list of plugins can be retrieved for a specific family ID
            [] Test retrieving a non-existent family ID returns no list and fails
        """
        families = self.cat.api.plugins.families()
        assert len(families['families']) > 0, 'No families returned'

        family_id = families['families'][0]['id']
        plugins = self.cat.api.plugins.family_details(family_id)
        assert plugins['id'] == family_id
        assert len(plugins['plugins']) > 0

    # API_Tested# GET /plugins/plugin/{plugin_id}
    def test_get_plugin_details(self):
        """Verifies that details can be retrieved for a specific plugin"""
        families = self.cat.api.plugins.families()
        assert len(families['families']) > 0, 'No families returned'

        family_id = families['families'][0]['id']
        plugins = self.cat.api.plugins.family_details(family_id)
        assert plugins['id'] == family_id
        assert len(plugins['plugins']) > 0

        plugin_id = plugins['plugins'][0]['id']
        plugin = self.cat.api.plugins.plugin_details(plugin_id)
        assert plugin['id'] == plugin_id
