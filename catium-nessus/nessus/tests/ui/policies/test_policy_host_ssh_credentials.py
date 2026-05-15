"""
Nessus Credentials tab under Policy form related test cases For Host -> SSH
:copyright: Tenable Network Security, 2017
:date: May 16, 2018
:last_modified: May 21, 2018
:author: @ntarwani
"""
import os

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.host import KerBeros, Password, PublicKey, Certificate, \
    ThycoticSecretServer, BeyondTrust
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.policies_pipeline_1
@pytest.mark.usefixtures('login')
class TestPoliciesCredentialsHostSSH:
    """Credentials form related test cases"""

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_public_key_ssh_credentials(self, create_policy):
        """
        NQA-1196- Fill form for Advanced Scan > Credentials > Host > SSH under New Policy
        1. Navigate to 'Advanced scan' template from scanner tab under New Policy
        2. Give valid name and target
        3. Go to Credentials tab and select Host > SSH > Public key
        4. Fill the form
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        key_path = os.path.abspath(get_file_path(
            'nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))
        public_key_form_data = {'auth': 'public key', 'username': 'root', 'elevate_privilege': 'Nothing'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        policy_name = create_policy
        policy_form = NewPolicyForm()

        public_key = PublicKey(host_type='SSH')
        assert public_key.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        public_key.fill_public_key_ssh_form(**public_key_form_data, key_path=key_path,
                                            passphrase='root')
        public_key.fill_global_setting_form(**global_credential_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        assert len(public_key.active_credentials) == 1, "More than 1 credentials are available"

        public_key.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        public_key_form_data.update({'passphrase': '********'})
        assert public_key.get_public_key_ssh_form_data() == public_key_form_data, 'Data saved is incorrect or missing'
        assert public_key.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert "api_pub_key_target_priv_key" in public_key.private_key_element.get_attribute('data-value'), \
            "uploaded file is not available"

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_certificate_ssh_credentials(self, create_policy):
        """
        NQA-1197- Fill form for Advanced Scan > Credentials > Host > SSH under New Policy
        1. Navigate to 'Advanced scan' template from scanner tab under New Policy
        2. Give valid name and target
        3. Go to Credentials tab and select Host > SSH > Certificate and elevate privilege as .k5login
        4. Fill the form
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        key_path = os.path.abspath(get_file_path(
            'nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))
        certificate_form_data = {'auth': 'certificate', 'username': 'root', 'elevate_privilege': '.k5login'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        policy_form = NewPolicyForm()
        policy_name = create_policy

        certificate = Certificate(host_type=API.Credentials.Host.Types.SSH)
        assert certificate.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        certificate.fill_ssh_certificate_form(**certificate_form_data, cert_path=key_path,
                                              key_path=key_path, passphrase='root', escalation_account='root')
        certificate.fill_global_setting_form(**global_credential_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        assert len(certificate.active_credentials) == 1, "More than 1 credentials are available"

        certificate.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        certificate_form_data.update({'passphrase': '********', 'escalation_account': '********'})
        assert certificate.get_certificate_ssh_form_data(
            certificate_form_data['elevate_privilege']) == certificate_form_data, 'Data saved is incorrect or missing'
        assert certificate.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert "api_pub_key_target_priv_key" in certificate.private_key_element.get_attribute('data-value'), \
            "uploaded file is not available"

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_kerberos_ssh_credentials(self, create_policy):
        """
        NQA-1192- Fill form for Advanced Scan > Credentials > Host > SSH under New Policy
        1. Navigate to 'Advanced scan' template from scanner tab under New Policy
        2. Give valid name and target
        3. Go to Credentials tab and select Host > SSH > Kerberos and elevate privilege as dzdo
        4. Fill the form
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        keberos_form_data = {'auth': 'Kerberos', 'username': 'root', 'kdc': 'npwkdc.lab.tenablesecurity.com',
                             'realm': 'NPWCENTOSKERBEROS'}
        elevate_privilege_data = {'elevate_privilege': 'dzdo', 'account_name': 'root', 'location': '/usr/bin'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        policy_form = NewPolicyForm()
        policy_name = create_policy

        kerberos = KerBeros(host_type=API.Credentials.Host.Types.SSH)
        assert kerberos.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        kerberos.fill_kerberos_ssh_form(username=keberos_form_data['username'], password='password',
                                        key_dis_center=keberos_form_data['kdc'], realm=keberos_form_data['realm'])
        kerberos.fill_elevate_cred_dzdo_su(elevate_privilege_value=elevate_privilege_data['elevate_privilege'],
                                           user=elevate_privilege_data['account_name'], password='password',
                                           location=elevate_privilege_data['location'])

        kerberos.fill_global_setting_form(**global_credential_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        assert len(kerberos.active_credentials) == 1, "More than 1 credentials are available"

        kerberos.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        keberos_form_data.update({'password': '********'})
        elevate_privilege_data.update({'password': '********'})
        assert kerberos.get_kerberos_ssh_form_data() == keberos_form_data, 'Data saved is incorrect or missing'
        assert kerberos.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert kerberos.get_elevate_cred_dzdo_su_name(
            elevate_privilege_value=elevate_privilege_data['elevate_privilege']) == elevate_privilege_data, \
            'Data saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_password_with_pbrun_ssh_credentials(self, create_policy):
        """
        NQA-1193- Fill form for Advanced Scan > Credentials > Host > SSH under New Policy
        1. Navigate to 'Advanced scan' template from scanner tab under New Policy
        2. Give valid name and target
        3. Go to Credentials tab and select Host > SSH > Password and elevate privilege as pbrun
        4. Fill the form
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        password_form_data = {'auth': 'password', 'username': 'root'}
        password_privilege_data = {'elevate_privilege': 'pbrun', 'location': '/usr/bin'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        policy_form = NewPolicyForm()
        policy_name = create_policy

        password = Password(host_type=API.Credentials.Host.Types.SSH)
        assert password.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        password.fill_password_ssh_form(**password_form_data, password='admin')
        password.fill_elevate_pbrun(elevate_privilege_value=password_privilege_data['elevate_privilege'],
                                    password='admin',
                                    location=password_privilege_data['location'])
        password.fill_global_setting_form(**global_credential_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        assert len(password.active_credentials) == 1, "More than  1 credentials are available"

        password.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        password_form_data.update({'password': '********'})
        password_privilege_data.update({'password': '********'})
        assert password.get_password_ssh_form_data() == password_form_data, 'Data saved is incorrect or missing'
        assert password.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert password.get_elevate_cred_pbrun(
            elevate_privilege_value=password_privilege_data['elevate_privilege']) == password_privilege_data, \
            'Data saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_public_key_with_su_elevate_ssh_credentials(self, create_policy):
        """
        NQA-1198- Fill form for Advanced Scan > Credentials > Host > SSH under New Policy and elevate previleges as 'su'
        1. Navigate to 'Advanced scan' template from scanner tab under New Policy
        2. Give valid name and target
        3. Go to Credentials tab and select Host > SSH > Public key and elevate privilege as su
        4. Fill the form
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        key_path = os.path.abspath(get_file_path(
            'nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))
        public_key_form_data = {'auth': 'public key', 'username': 'root', 'elevate_privilege': 'su'}
        elevate_su_user_credential = {'elevate_privilege': 'su', 'su_login': 'root', 'location': '/usr/bin'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        policy_form = NewPolicyForm()
        policy_name = create_policy

        public_key = PublicKey(host_type=API.Credentials.Host.Types.SSH)
        assert public_key.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        public_key.fill_public_key_ssh_form(**public_key_form_data, key_path=key_path, passphrase='root')
        public_key.fill_elevate_su_user_credential(**elevate_su_user_credential, su_password='root')
        public_key.fill_global_setting_form(**global_credential_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        assert len(public_key.active_credentials) == 1, "More than 1 credentials are available"

        public_key.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        public_key_form_data.update({'passphrase': '********'})
        elevate_su_user_credential.update({'su_password': '********'})
        assert public_key.get_public_key_ssh_form_data() == public_key_form_data, 'Data saved is incorrect or missing'
        assert public_key.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert public_key.get_elevate_su_credential_values(
            elevate_privilege_value=elevate_su_user_credential['elevate_privilege']) == elevate_su_user_credential, \
            'Data saved is incorrect or missing'
        assert "api_pub_key_target_priv_key" in public_key.private_key_element.get_attribute('data-value'), \
            "uploaded file is not available"

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_password_su_sudo_elevate_ssh_credentials(self, create_policy):
        """
        NQA-1194- Fill form for Advanced Scan > Credentials > Host > SSH under New Policy
        1. Navigate to 'Advanced scan' template from scanner tab under New Policy
        2. Give valid name and target
        3. Go to Credentials tab and select Host > SSH > Password and elevate privilege as su+sudo
        4. Fill the form
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        password_form_data = {'auth': 'password', 'username': 'root'}
        password_privilege_data = {'elevate_privilege': 'su+sudo', 'su_user': 'admin', 'sudo_user': 'root',
                                   'location': 'tenable'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        policy_form = NewPolicyForm()
        policy_name = create_policy

        password = Password(host_type=API.Credentials.Host.Types.SSH)
        assert password.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        password.fill_password_ssh_form(**password_form_data, password='admin')
        password.fill_su_sudo_user_cred(**password_privilege_data, password='admin')
        password.fill_global_setting_form(**global_credential_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        assert len(password.active_credentials) == 1, "More than 1 credentials are available"

        password.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        password_form_data.update({'password': '********'})
        password_privilege_data.update({'password': '********'})
        assert password.get_password_ssh_form_data() == password_form_data, 'Data saved is incorrect or missing'
        assert password.get_elevate_cred_sudo_su_name(
            elevate_privilege_value=password_privilege_data['elevate_privilege']) == password_privilege_data, \
            'Data saved is incorrect or missing'
        assert password.get_global_setting_form() == global_credential_data, \
            'global credential settings are incorrect or missing'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_thycotic_ssh_credentials(self, create_policy):
        """
        NQA-1195- Fill form for Advanced Scan > Credentials > Host > SSH under New Policy
        1. Navigate to 'Advanced scan' template from scanner tab under New Policy
        2. Give valid name and target
        3. Go to Credentials tab and select Host > SSH > Thycotic Server
        4. Fill the form
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        thycotic_form_data = {'auth': 'Thycotic Secret Server', 'username': 'root', 'secret_name': 'admin',
                              'server_url': 'test@tenable.com', 'login_name': 'admin', 'organization': 'tenable',
                              'thycotic_domain': 'tenable', 'ssl_certificate_element': False,
                              'use_private_key_element': True}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        policy_form = NewPolicyForm()
        policy_name = create_policy

        thycotic_credential = ThycoticSecretServer(host_type=API.Credentials.Host.Types.SSH)
        assert thycotic_credential.opened_form_value == API.Credentials.Host.Types.SSH, \
            "Thycotic Server form is not open"

        thycotic_credential.fill_thycotic_form(**thycotic_form_data, thycotic_password='root')
        thycotic_credential.fill_global_setting_form(**global_credential_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        assert len(thycotic_credential.active_credentials) == 1, "More than 1 credentials are available"

        thycotic_credential.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)
        thycotic_form_data.update({'thycotic_password': '********'})
        assert thycotic_credential.get_thycotic_ssh_form_data(host_type=API.Credentials.Host.Types.SSH) == \
               thycotic_form_data, 'Data saved is incorrect or missing'
        assert thycotic_credential.get_global_setting_form() == global_credential_data, \
            'Data saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                Nessus.Scan.ScanTemplateTabs.SCANNER_TAB)], indirect=True)
    def test_beyond_trust_ssh_credentials(self, create_policy):
        """
        NQA-1199- Fill form for Advanced Scan > Credentials > Host > SSH under New Policy
        1. Navigate to 'Advanced scan' template from scanner tab under New Policy
        2. Give valid name and target
        3. Go to Credentials tab and select Host > SSH > Beyond Trust
        4. Fill the form
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        beyond_trust_form_data = {'auth': 'BeyondTrust', 'username': 'root', 'port': '443',
                                  'host': 'test@tenable.com', 'api_user': 'admin', 'api_key': 'admin',
                                  'checkout_duration': '2', 'use_ssl': False, 'verify_ssl': False, 'private_key': True,
                                  'privilege_escalation': True}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        policy_name = create_policy
        policy_form = NewPolicyForm()

        beyond_trust = BeyondTrust(host_type=API.Credentials.Host.Types.SSH)
        assert beyond_trust.opened_form_value == API.Credentials.Host.Types.SSH, \
            "Beyond Trust form is not open"

        beyond_trust.fill_beyond_trust_form(host_type=API.Credentials.Host.Types.SSH,
                                            **beyond_trust_form_data)
        beyond_trust.fill_global_setting_form(**global_credential_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        assert len(beyond_trust.active_credentials) == 1, "More than 1 credentials are available"

        beyond_trust.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)
        assert beyond_trust.get_ssh_beyond_trust_form_data() == beyond_trust_form_data, \
            'Data saved is incorrect or missing'
        assert beyond_trust.get_global_setting_form() == global_credential_data, \
            'Data saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.SideNavResources.POLICIES)
        LoadingCircle(WAIT_SHORT)
