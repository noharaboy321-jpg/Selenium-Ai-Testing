"""
 Nessus Credentials tab under Policy form related test cases for Host > Windows
:Copyright: Tenable Network Security, 2018
:Date: May 18, 2018
:Modified Date: May 23, 2018
:Author: @jchavda
"""

import pytest

from catium.lib.const import WAIT_SHORT
from nessus.lib.const import API
from nessus.pageobjects.credentials.host import Password, KerBeros, Hash, ThycoticSecretServer, BeyondTrust
from nessus.pageobjects.policies.policies_page import PolicyList, NewPolicyForm, log
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.policies_pipeline_3
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestPolicyWindowPage:
    """
    NQA-1176: Automation tests for 'advanced scan' under New Policy > 'Scanner' tab is saved successfully with values
    given under credentials ->Category 'Host' and 'Windows'
    """

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    def test_password_windows_policy(self, create_policy):
        """
        NQA-1177: Verify Advanced scan under Policy is saved with Host > ‘Windows’ > authentication method as 'Password'
        1. Navigate to Policies > New Policy > Scanner > Advanced Scan
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type 'Password'
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()
        password_form_data = {'auth': 'Password', 'username': 'administrator', 'password': 'admin', 'domain': 'tenable'}
        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': False, 'enable_admin_shares': False}

        password = Password(host_type=API.Credentials.Host.Types.WINDOWS)
        assert password.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST, \
            'Category Type is missing'
        assert password.opened_form_value == API.Credentials.Host.Types.WINDOWS, 'Windows form is not open'

        password.fill_password_windows_form(**password_form_data)
        password.fill_global_settings_for_windows(**global_credential_data)
        password.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(password.active_credentials) == 1, "More than 1 credentials are available"

        password.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)
        password_form_data.update({'password': '********'})
        assert password.get_password_windows_form_data() == password_form_data, 'Data saved is incorrect or missing'
        assert password.get_global_settings_for_windows() == global_credential_data, \
            'global credential settings are incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    def test_kerberos_windows_policy(self, create_policy):
        """
        NQA-1179: Verify Advanced scan under Policy is saved with Host > ‘Windows’ > authentication method as 'Kerberos'
        1. Navigate to Policies > New Policy > Scanner > Advanced Scan
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type 'Kerberos'
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        kerberos_form_data = {'auth': 'Kerberos', 'username': 'administrator', 'password': 'admin',
                              'key_dis_center': 'npwkdc.lab.tenablesecurity.com',
                              'kdc_port': '88', 'domain': 'tenable'}

        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': True, 'enable_admin_shares': True}

        kerberos = KerBeros(host_type=API.Credentials.Host.Types.WINDOWS)
        assert kerberos.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST, \
            'Category Type is missing'
        assert kerberos.opened_form_value == API.Credentials.Host.Types.WINDOWS, 'Windows form is not open'

        kerberos.fill_kerberos_windows_form(**kerberos_form_data)
        kerberos.js_scroll_into_view(policy_form.save_button)
        kerberos.fill_global_settings_for_windows(**global_credential_data)
        kerberos.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(kerberos.active_credentials) == 1, "More than 1 credentials are available"

        kerberos.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)
        kerberos_form_data.update({'password': '********'})
        assert kerberos.get_kerberos_windows_form_data() == kerberos_form_data, \
            'Data saved is incorrect or missing'
        assert kerberos.get_global_settings_for_windows() == global_credential_data, \
            'Data saved is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    @pytest.mark.parametrize("hash_type", ['LM Hash', 'NTLM Hash'])
    def test_hash_windows_policy(self, create_policy, hash_type):
        """
        NQA-1180: Verify Advanced scan under Policy is saved with Host > ‘Windows’ > authentication method as 'LM HASH'
        1. Navigate to Policies > New Policy > Scanner > Advanced Scan
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type LM HASH' and 'NTLM Hash' one by one
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        hash_form_data = {'auth': hash_type, 'username': 'administrator', 'hash_field': 'admin', 'domain': 'tenable'}
        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': True, 'enable_admin_shares': True}

        hash = Hash(host_type=API.Credentials.Host.Types.WINDOWS)
        assert hash.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST, \
            'Category Type is missing'
        assert hash.opened_form_value == API.Credentials.Host.Types.WINDOWS, 'Windows form is not open'

        hash.fill_windows_hash_form(**hash_form_data)
        hash.fill_global_settings_for_windows(**global_credential_data)
        hash.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(hash.active_credentials) == 1, "More than 1 credentials are available"

        hash.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)
        hash_form_data.update({'hash_field': '********'})
        assert hash.get_hash_windows_form_data() == hash_form_data, 'Data saved is incorrect or missing'
        assert hash.get_global_settings_for_windows() == global_credential_data, 'Data saved is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    def test_thycotic_server_windows_policy(self, create_policy):
        """
        NQA-1181: Verify Advanced scan under Policy is saved with Host > ‘Windows’ > authentication method as
                 'Thycotic Server'
        1. Navigate to Policies > New Policy > Scanner > Advanced Scan
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type 'Thycotic Server'
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()

        thycotic_form_data = {'auth': 'Thycotic Secret Server', 'username': 'administrator', 'secret_name': 'admin',
                              'server_url': 'test@tenable.com', 'login_name': 'admin',
                              'thycotic_password': 'root', 'organization': 'tenable',
                              'thycotic_domain': 'tenable', 'ssl_certificate_element': True,
                              'domain_name': 'tenable'}

        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': True, 'enable_admin_shares': True}

        thycotic_server = ThycoticSecretServer(host_type=API.Credentials.Host.Types.WINDOWS)
        assert thycotic_server.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST, \
            'Category Type is missing'
        assert thycotic_server.opened_form_value == API.Credentials.Host.Types.WINDOWS, 'Windows form is not open'

        thycotic_server.fill_thycotic_form(host_type=API.Credentials.Host.Types.WINDOWS, **thycotic_form_data)
        thycotic_server.js_scroll_into_view(policy_form.save_button)
        thycotic_server.fill_global_settings_for_windows(**global_credential_data)
        thycotic_server.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(thycotic_server.active_credentials) == 1, "More than 1 credentials are available"

        thycotic_server.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)
        thycotic_form_data.update({'thycotic_password': '********'})
        assert thycotic_server.get_thycotic_windows_form_data(
            host_type=API.Credentials.Host.Types.WINDOWS) == thycotic_form_data, \
            'Data saved is incorrect or missing'
        assert thycotic_server.get_global_settings_for_windows() == global_credential_data, \
            'Data saved is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    def test_beyond_trust_windows_policy(self, create_policy):
        """
        NQA-1182: Verify Advanced scan under Policy is saved with Host > ‘Windows’ > authentication method as
                  'Beyond Trust'
        1. Navigate to Policies > New Policy > Scanner > Advanced Scan
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type 'Beyond Trust'
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()
        beyond_trust_form_data = {'auth': 'BeyondTrust', 'username': 'administrator',
                                  'domain': 'tenable', 'port': '443', 'host': 'test@tenable.com', 'api_user': 'admin',
                                  'api_key': 'admin', 'checkout_duration': '2',
                                  'use_ssl': True, 'verify_ssl': True}

        beyond_trust_form_data1 = {'auth': 'BeyondTrust', 'username': 'administrator',
                                   'domain': 'tenable', 'port': '443', 'host': 'test@tenable.com', 'api_user': 'admin',
                                   'checkout_duration': '2', 'use_ssl': True, 'verify_ssl': True}

        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': True, 'enable_admin_shares': True}

        beyond_trust = BeyondTrust(host_type=API.Credentials.Host.Types.WINDOWS)
        assert beyond_trust.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST, \
            'Category Type is missing'
        assert beyond_trust.opened_form_value == API.Credentials.Host.Types.WINDOWS, 'Windows form is not open'

        beyond_trust.fill_beyond_trust_form(host_type=API.Credentials.Host.Types.WINDOWS, **beyond_trust_form_data)
        beyond_trust.js_scroll_into_view(policy_form.save_button)
        beyond_trust.fill_global_settings_for_windows(**global_credential_data)
        beyond_trust.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()
        assert len(beyond_trust.active_credentials) == 1, "More than 1 credentials are available"
        beyond_trust.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)

        log.info(f"data is {beyond_trust.get_windows_beyond_trust_form_data()}")
        assert beyond_trust.get_windows_beyond_trust_form_data() == beyond_trust_form_data1, \
            'Data saved is incorrect or missing'
        assert beyond_trust.get_global_settings_for_windows() == global_credential_data, \
            'Data saved is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)
