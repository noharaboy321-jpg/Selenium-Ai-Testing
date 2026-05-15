"""
Nessus test cases related to Policies with Credentials > Plaintext Authentication
:copyright: Tenable Network Security, 2017
:date: May 23, 2018
:author: @ntarwani
"""

import copy
import pytest
from catium.helpers.testdata import get_file_path
from catium.lib.const import os, WAIT_NORMAL
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.plaintext_authentication import PlainTextAuthentication
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.policies_pipeline_3
@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestUIPlaintextAuthForm:
    """NQA- 1221- Automated tests related to Policy > Credentials > Plaintext Authentication"""

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    @pytest.mark.parametrize("auth_type, test_data", [(API.Credentials.PlaintextAuthentication.FTP,  # NQA-1222
                                                       {'username': 'admin', 'password': 'admin'}),
                                                      (API.Credentials.PlaintextAuthentication.IMAP,  # NQA-1223
                                                       {'username': 'admin', 'password': 'admin'}),
                                                      (API.Credentials.PlaintextAuthentication.IPMI,  # NQA-1224
                                                       {'username': 'admin', 'password': 'admin'}),
                                                      (API.Credentials.PlaintextAuthentication.NNTP,  # NQA-1225
                                                       {'username': 'admin', 'password': 'admin'}),
                                                      (API.Credentials.PlaintextAuthentication.POP2,  # NQA-1226
                                                       {'username': 'admin', 'password': 'admin'}),
                                                      (API.Credentials.PlaintextAuthentication.POP3,  # NQA-1227
                                                       {'username': 'admin', 'password': 'admin'}),
                                                      (API.Credentials.PlaintextAuthentication.HTTP,  # NQA-1228
                                                       {'http_auth_type': 'Basic/Digest authentication',
                                                        'username': 'admin', 'password': 'admin',
                                                        'login_method': 'GET', 're_authenticate_delay': 22,
                                                        'follow_redirection': 22, 'invert_authenticated_regex': True,
                                                        'use_authenticated_regex': True,
                                                        'case_insensitive_authenticated_regex': True}),
                                                      (API.Credentials.PlaintextAuthentication.HTTP,  # NQA-1229
                                                       {'http_auth_type': 'Automatic authentication',
                                                        'username': 'admin', 'password': 'admin',
                                                        'login_method': 'POST', 're_authenticate_delay': 22,
                                                        'follow_redirection': 22, 'invert_authenticated_regex': True,
                                                        'use_authenticated_regex': True,
                                                        'case_insensitive_authenticated_regex': True}),
                                                      (API.Credentials.PlaintextAuthentication.HTTP,  # NQA-1230
                                                       {'http_auth_type': 'HTTP login form',
                                                        'username': 'admin', 'password': 'admin',
                                                        'login_page': 'admin',
                                                        'login_submission_page': 'nessus', 'login_parameters': 'admin',
                                                        'check_authentication': 'admin', 'regex_to_verify': 'admin',
                                                        'login_method': 'POST', 're_authenticate_delay': 22,
                                                        'follow_redirection': 22, 'invert_authenticated_regex': True,
                                                        'use_authenticated_regex': True,
                                                        'case_insensitive_authenticated_regex': True}),
                                                      (API.Credentials.PlaintextAuthentication.SNMPV12,  # NQA-1232
                                                       {'community_string': 'private', 'udp_port': 22,
                                                        'additional_udp_port1': 22, 'additional_udp_port2': 22,
                                                        'additional_udp_port3': 22}),
                                                      (API.Credentials.PlaintextAuthentication.TELNET_RSH_REXEC,
                                                       # NQA-1233
                                                       {'username': 'admin', 'password': "admin",
                                                        'patch_audits_over_telnet': True,
                                                        'patch_audits_over_rsh': True,
                                                        'patch_audits_over_rexec': True})])
    def test_plain_text_auth(self, create_policy, auth_type, test_data):
        """
        NQA-1222- Verify Advanced scan is saved with Plaintext Authentication > FTP
        NQA-1223- Verify Advanced scan is saved with Plaintext Authentication > IMAP
        NQA-1224- Verify Advanced scan is saved with Plaintext Authentication > IPMI
        NQA-1225- Verify Advanced scan is saved with Plaintext Authentication > NNTP
        NQA-1226- Verify Advanced scan is saved with Plaintext Authentication > POP2
        NQA-1227- Verify Advanced scan is saved with Plaintext Authentication > POP3
        NQA-1228- Verify Advanced scan is saved with Plaintext Authentication > HTTP and authentication method
                  'HTTP Login form'
        NQA-1229- Verify Advanced scan is saved with Plaintext Authentication > HTTP and authentication method
                  'Automatic authentication'
        NQA-1230- Verify Advanced scan is saved with Plaintext Authentication > HTTP and authentication method
                  'Basic/Digest authentication'
        NQA-1232- Verify Advanced scan is saved with Plaintext Authentication > SNMPv1/v2c
        NQA-1233- Verify Advanced scan is saved with Plaintext Authentication > telnet/rsh/rexec

        1. Navigate to Polices > New Policy
        2. Enter Policy details
        3. Go to credentials tab and select Plaintext Authentication
        4. Fill input fields for the sub categories
        5. Save the policy
        6. Open the saved policy
        5. Verify the data saved is retained.
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        plain_text = PlainTextAuthentication.get_auth_type(pt_auth=auth_type)
        assert plain_text.opened_form_value == auth_type, '%s form is not open' % auth_type

        LoadingCircle(WAIT_NORMAL)

        plain_text.fill_form(**test_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(plain_text.active_credentials) == 1, 'More than 1 credentials are available'

        plain_text.open_saved_credentials_component(form_name=auth_type)
        plain_text_data = copy.deepcopy(test_data)
        if 'password' in plain_text_data.keys():
            plain_text_data['password'] = '********'
        assert plain_text.get_form_data() == plain_text_data, 'Data saved is missing or incorrect'

        policy_form.back_to_policies.click()

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    @pytest.mark.parametrize('auth_type, test_data', [(API.Credentials.PlaintextAuthentication.HTTP,  #NQA-1231
                                                       {'http_auth_type': 'HTTP cookies import',
                                                        'login_method': 'GET', 're_authenticate_delay': 22,
                                                        'follow_redirection': 22, 'invert_authenticated_regex': True,
                                                        'use_authenticated_regex': True,
                                                        'case_insensitive_authenticated_regex': True})])
    def test_http_cookies_import(self, create_policy, auth_type, test_data):
        """
        NQA-1231: Verify Advanced scan is saved with Plaintext Authentication > HTTP and
                            authentication method 'HTTP cookies import'
        1. Navigate to Polices > New Policy
        2. Enter Policy details
        3. Go to credentials tab and select Plaintext Authentication
        4. Fill input fields for the sub categories
        5. Save the policy
        6. Open the saved policy
        5. Verify the data saved is retained.
        """
        key_path = os.path.abspath(get_file_path('nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))
        policy_name = create_policy
        policy_form = NewPolicyForm()

        plain_text = PlainTextAuthentication.get_auth_type(pt_auth=auth_type)
        assert plain_text.opened_form_value == auth_type, '%s form is not open' % auth_type

        LoadingCircle(WAIT_NORMAL)
        plain_text.fill_form(**test_data, add_cookies_file=key_path)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(plain_text.active_credentials) == 1, 'More than 1 credentials are available'

        plain_text.open_saved_credentials_component(form_name=auth_type)
        assert plain_text.get_form_data() == test_data, 'Data saved is missing or incorrect'
        assert "api_pub_key_target_priv_key" in \
               plain_text.add_cookies_file.get_attribute('data-value'), \
            'api_pub_key_target_priv_key file is not available'

        policy_form.back_to_policies.click()
