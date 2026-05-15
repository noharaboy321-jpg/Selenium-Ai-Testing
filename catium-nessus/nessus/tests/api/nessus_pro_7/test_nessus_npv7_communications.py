"""
:copyright: Tenable Network Security, 2017
:date: October 3, 2017
:last_modified: July 15, 2020
:author: @pellsworth, @kpanchal
"""
import pytest

from catium.lib.log import create_logger
from nessus.helpers.server import expect_http_error

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login', 'no_automation_api_key')
class TestNessusCommunicationPro7:
    """
    Test various "communication" endpoints are not allowed in NPv7
    """

    cat = None

    # API_Tested# POST /settings/network/ldap/test
    def test_nessus_ldap_test_settings(self):
        """Tests LDAP settings"""
        with expect_http_error(code=403):
            try:
                self.cat.api.settings.test_ldap_settings(settings={}, stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    # API_Tested# PUT /settings/network/ldap
    def test_nessus_ldap_create_user(self):
        """Tests LDAP user creation"""
        with expect_http_error(code=403):
            try:
                self.cat.api.settings.set_ldap_settings(settings={}, stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))

    # API_Tested# POST /settings/network/ldap/search
    def test_nessus_ldap_search_user(self):
        """Tests LDAP user search"""
        with expect_http_error(code=403):
            try:
                self.cat.api.settings.search_ldap(name='bogus', stream=True)
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))
