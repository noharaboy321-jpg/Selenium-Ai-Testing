"""
Unit Test
"""
import pytest


@pytest.mark.unittest
@pytest.mark.usefixtures('nessus_class_api_login')
class TestNessusSettingsEndpoint:
    """Unit tests for Nessus Settings Endpoint"""

    cat = None

    # API_Tested# GET /settings/advanced
    def test_get_list(self):
        """Tests the settings/advanced endpoint method

        Scenarios tested:
          [x] Successfully get advanced settings
          [ ] Successfully set various valid advanced settings
          [ ] Fail to set advanced settings if it's invalid
        """
        response = self.cat.api.settings.get_list()
        assert 'preferences' in response, 'Missing field "preferences" from response'
        assert len(response['preferences']) > 1, 'Expected one or more settings present, got 1 or less'
