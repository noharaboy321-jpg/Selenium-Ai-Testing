"""
:copyright: Tenable Network Security, 2017
:date: July 5, 2017
:author: @cdombrowski
"""
import pytest

from nessus.helpers.system import get_nessus_version
from nessus.lib.const.constants import API


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusSettings:
    """
    Class to handle testing various Nessus settings.  Tests should include retrieving advanced settings, verifying
    correct settings are enabled, and verifying the data being returned by the API matches the expected values.
    """

    cat = None

    # TODO: Refactor the skip check using the version marker once it is implemented (CAT-1561).
    @pytest.mark.skipif(get_nessus_version() != "6.12.0",
                        reason="This test requires version 2 of the Nessus API.")
    @pytest.mark.parametrize('set_api_header', [{"api_version": "1"}, {"api_version": "2"}], indirect=True)
    # API_Tested# GET /settings/advanced
    def test_nessus_settings_restart_required(self, set_api_header):
        """
        Tests that the expected settings are set to 'required restart: true'
        """
        preferences = self.cat.api.settings.get_list()['preferences']
        if set_api_header == "1":
            with pytest.raises(KeyError, message='Should return a KeyError if using v1 of the Nessus API.'):
                _ = {setting['name']: setting['require_restart'] for setting in preferences}
        else:
            advanced_settings = {setting['name']: setting['require_restart'] for setting in preferences if
                                 setting['name'] not in API.Settings.AdvancedSettings.RESTART_NOT_REQUIRED}
            for name, require_restart in advanced_settings.items():
                assert require_restart is True, \
                    "Advanced Setting: {} should require a restart, but is currently set to false.".format(name)
