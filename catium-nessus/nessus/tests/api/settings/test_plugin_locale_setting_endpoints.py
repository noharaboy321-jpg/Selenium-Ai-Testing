"""
Nessus Plugin locale Settings Endpoint verification

:copyright: Tenable Network Security, 2024
:date: Aug 30, 2024
:modified date: Oct 23. 2024
:author: @krpatel
"""

from http import HTTPStatus

import pytest

from catium.lib.log.log import create_logger
from nessus.lib.const import Nessus

log = create_logger()


@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login')
class TestPluginLocaleEndpoints:
    """
    Testcases related to setting endpoints of plugin locales.
    """

    def __init__(self):
        self.cat = None

    # API_Tested# GET /
    @pytest.mark.xray(test_key='NES-18518')
    @pytest.mark.usefixtures('enable_plugin_locales')
    def test_details_of_plugin_locales_endpoint(self, get_locale_detail, enable_plugin_locales):
        """
        [NES-18518] API: GET/plugin-locales-details: get the details of plugin locales and check the default locale

        """
        assert get_locale_detail, "endpoint is not giving details"
        assert get_locale_detail["locale"] == Nessus.About.PluginLocales.DEFAULT_LOCALE, "locales are not available"
        assert len(get_locale_detail["current"]) >= 3, "less than 3 locales are available"

    # API_Tested# SET /
    @pytest.mark.xray(test_key='NES-18519')
    @pytest.mark.parametrize('data',
                             [{"default_plugin_locale": "zh_CN", "current": ["zh_CN"], "enabled": True},
                              {"default_plugin_locale": "zh_TW", "current": ["zh_TW"], "enabled": True},
                              {"default_plugin_locale": "ja", "current": ["ja"], "enabled": True}])
    def test_selecting_locales_as_default(self, data, set_locale_detail, get_locale_detail):
        """
        [NES-18519] API: PUT/settings/plugin-detail-locale: select and apply each available locales as default

        """
        assert get_locale_detail["locale"] == data["default_plugin_locale"], "plugin locales not set correctly."

    # API_Tested# POST /
    @pytest.mark.xray(test_key='NES-18517')
    @pytest.mark.usefixtures('nessus_api_login', 'disable_plugin_locales')
    def test_disable_plugin_locales_endpoint(self, get_locale_detail, disable_plugin_locales):
        """
        [NES-18517]: API: PUT/plugin-locales-details: disable the plugin locales

        """
        detail = get_locale_detail
        if detail['enabled'] is True:
            log.debug('locales were enabled. disabling now...')
        else:
            log.debug('locales were disabled already, override the setting')
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code

@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
class TestLocaleEndpoint:
    """
    Testcase related to setting endpoints of plugin locale.
    """

    def __init__(self):
        self.cat = None

    @pytest.mark.xray(test_key='NES-18516')
    @pytest.mark.usefixtures('nessus_api_login', 'enable_plugin_locales')
    def test_enable_plugin_locales_endpoint(self, get_locale_detail, enable_plugin_locales):
        """
        [NES-18516]: API: PUT/plugin-locales-details: enable the plugin locales

        """
        detail = get_locale_detail
        if detail['enabled'] is True:
            log.debug('locales were enabled already. override the setting')
        else:
            log.debug('locales were disabled, enabling now...')
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code
