"""
Nessus Credentials tab under Policy/Scan form related test cases For Host -> SSH

:copyright: Tenable Network Security, 2017
:date: Jan 30, 2018
:last_modified: jul 16, 2018
:author: @mameta, @ntarwani, @jchavda
"""
import os

import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT
from catium.lib.log.log import create_logger
from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.credentials.host import KerBeros, Password, PublicKey, Certificate, \
    ThycoticSecretServer, BeyondTrust
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.usefixtures('login')
class TestUICredentialsForm:
    """Credentials -> Category 'Host' -> SSH form related test cases"""

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_public_key_ssh_credentials(self, create_scan):
        """
        NQA-1074 : Verify Advanced scan is saved with Host -> ‘SSH’ and authentication method as ‘public key’

        NQA-1279 : Verify Validations while edit for Advanced Scan with Credentials: Host > SSH
        Auth Method: Public Key
        1. Repeat steps 1 to 7 from NQA-1074
        2. Remove Private Key file and hit ‘Save’
        3. Validation message should appear
        """

        key_path = os.path.abspath(get_file_path(
            'nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))
        public_key_form_data = {'auth': 'public key', 'username': 'root', 'elevate_privilege': 'Nothing',
                                'passphrase': '********'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        scan_name = create_scan
        public_key = PublicKey(host_type='SSH')
        LoadingCircle(WAIT_SHORT)

        assert public_key.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST
        assert public_key.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        public_key.fill_public_key_ssh_form(username=public_key_form_data['username'],
                                            key_path=key_path,
                                            passphrase='root',
                                            elevate_privilege=public_key_form_data['elevate_privilege'])

        public_key.fill_global_setting_form(preferred_port=global_credential_data['preferred_port'],
                                            known_hosts=key_path,
                                            client_version=global_credential_data['client_version'],
                                            use_least_privilege=global_credential_data['use_least_privilege'])
        save_and_configure_scan(class_object=public_key, scan_name=scan_name)

        assert len(public_key.active_credentials) == 1, "More than 1 credentials are available"
        public_key.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        assert public_key.get_public_key_ssh_form_data() == public_key_form_data, 'Data saved is incorrect or missing'
        assert public_key.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert "api_pub_key_target_priv_key" in public_key.private_key_element.get_attribute('data-value'), \
            "uploaded file is not available"
        assert "api_pub_key_target_priv_key" in public_key.known_hosts_file.get_attribute('data-value'), \
            "uploaded file is not available"

        public_key.remove_attached_file(data_name='Private key').click()
        public_key.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Credentials.private_key, \
            'Error Notification is missing for blank Private Key'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_certificate_ssh_credentials(self, create_scan):
        """
        NQA-1075 : Verify Advanced scan is saved with Host -> ‘SSH’ and authentication method as ‘Certificate’

        NQA-1279 : Verify Validations while edit for Advanced Scan with Credentials: Host > SSH
        Auth Method: Certificate and elevate privilege as .k5login
        1. Repeat steps 1 to 7 from NQA-1075
        2. Remove Escalation account and hit ‘Save’
        3. Validation message should appear
        """
        key_path = os.path.abspath(get_file_path(
            'nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))
        certificate_form_data = {'auth': 'certificate', 'username': 'root', 'elevate_privilege': '.k5login',
                                 'passphrase': '********', 'escalation_account': '********'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        scan_name = create_scan
        certificate = Certificate(host_type=API.Credentials.Host.Types.SSH)
        LoadingCircle(WAIT_SHORT)

        assert certificate.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST
        assert certificate.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        certificate.fill_ssh_certificate_form(username=certificate_form_data['username'], cert_path=key_path,
                                              key_path=key_path, passphrase='root',
                                              elevate_privilege=certificate_form_data['elevate_privilege'],
                                              escalation_account='root')

        certificate.fill_global_setting_form(preferred_port=global_credential_data['preferred_port'],
                                             client_version=global_credential_data['client_version'],
                                             use_least_privilege=global_credential_data['use_least_privilege'])
        save_and_configure_scan(class_object=certificate, scan_name=scan_name)

        assert len(certificate.active_credentials) == 1, "More than 1 credentials are available"
        certificate.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        assert certificate.get_certificate_ssh_form_data(
            certificate_form_data['elevate_privilege']) == certificate_form_data, 'Data saved is incorrect or missing'
        assert certificate.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert "api_pub_key_target_priv_key" in certificate.private_key_element.get_attribute('data-value'), \
            "uploaded file is not available"

        assert certificate.check_required_field_validation(
            class_instance=certificate, element='escalation_account_element', element_args={
                'elevate_privilege_value': certificate_form_data['elevate_privilege']}), \
            'Error Notification is missing for blank Escalation account.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_kerberos_ssh_credentials(self, create_scan):
        """
        NQA-1077 : Verify Advanced scan is saved with Host -> ‘SSH’ and authentication method as ‘Kerberos’

        NQA-1279 : Verify Validations while edit for Advanced Scan with Credentials: Host > SSH
        Auth Method: Kerberos and elevate privilege as 'dzdo'
        1. Repeat steps 1 to 7 from NQA-1077
        2. Remove Key Distribution Center and hit ‘Save’
        3. Validation message should appear
        """
        kerberos_form_data = {'auth': 'Kerberos', 'username': 'root', 'kdc': 'npwkdc.lab.tenablesecurity.com',
                              'realm': 'NPWCENTOSKERBEROS', 'password': '********'}
        elevate_privilege_data = {'elevate_privilege': 'dzdo', 'account_name': 'root', 'location': '/usr/bin',
                                  'password': '********'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        scan_name = create_scan
        kerberos = KerBeros(host_type=API.Credentials.Host.Types.SSH)

        assert kerberos.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST
        assert kerberos.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        kerberos.fill_kerberos_ssh_form(username=kerberos_form_data['username'], password='password',
                                        key_dis_center=kerberos_form_data['kdc'], realm=kerberos_form_data['realm'])

        kerberos.fill_elevate_cred_dzdo_su(elevate_privilege_value=elevate_privilege_data['elevate_privilege'],
                                           user=elevate_privilege_data['account_name'], password='password',
                                           location=elevate_privilege_data['location'])

        kerberos.fill_global_setting_form(preferred_port=global_credential_data['preferred_port'],
                                          client_version=global_credential_data['client_version'],
                                          use_least_privilege=global_credential_data['use_least_privilege'])
        save_and_configure_scan(class_object=kerberos, scan_name=scan_name)

        assert len(kerberos.active_credentials) == 1, "More than 1 credentials are available"
        kerberos.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        assert kerberos.get_kerberos_ssh_form_data() == kerberos_form_data, 'Data saved is incorrect or missing'
        assert kerberos.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert kerberos.get_elevate_cred_dzdo_su_name(
            elevate_privilege_value=elevate_privilege_data['elevate_privilege']) == elevate_privilege_data, \
            'Data saved is incorrect or missing'

        assert kerberos.check_required_field_validation(class_instance=kerberos, element='key_dis_center_element',
                                                        element_args={'host_type': API.Credentials.Host.Types.SSH}), \
            'Error Notification is missing for blank Key Distribution Center'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_password_with_pbrun_ssh_credentials(self, create_scan):
        """
        NQA-1078 : Verify Advanced scan is saved with Host -> ‘SSH’ and authentication method as ‘Password’

        NQA-1279 : Verify Validations while edit for Advanced Scan with Credentials: Host > SSH
        Auth Method: Password and elevate privilege as 'pbrun'
        1. Repeat steps 1 to 7 from NQA-1078
        2. Remove Password and hit ‘Save’
        3. Validation message should appear
        """
        password_form_data = {'auth': 'password', 'username': 'root', 'password': '********'}
        password_privilege_data = {'elevate_privilege': 'pbrun', 'location': '/usr/bin', 'password': '********'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        scan_name = create_scan
        password = Password(host_type=API.Credentials.Host.Types.SSH)

        assert password.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST
        assert password.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        password.fill_password_ssh_form(username=password_form_data['username'], password='admin')
        password.fill_elevate_pbrun(elevate_privilege_value=password_privilege_data['elevate_privilege'],
                                    password='admin',
                                    location=password_privilege_data['location'])

        password.fill_global_setting_form(preferred_port=global_credential_data['preferred_port'],
                                          client_version=global_credential_data['client_version'],
                                          use_least_privilege=global_credential_data['use_least_privilege'])
        save_and_configure_scan(class_object=password, scan_name=scan_name)

        assert len(password.active_credentials) == 1, "More than  1 credentials are available"
        password.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        assert password.get_password_ssh_form_data() == password_form_data, 'Data saved is incorrect or missing'
        assert password.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert password.get_elevate_cred_pbrun(
            elevate_privilege_value=password_privilege_data['elevate_privilege']) == password_privilege_data, \
            'Data saved is incorrect or missing'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_public_key_with_su_elevate_ssh_credentials(self, create_scan):
        """
        NQA-1080 : Verify Advanced scan is saved with Host -> ‘SSH’ and authentication method as ‘public key’
        and 'elevate privileges with' as 'su'

        NQA-1279 : Verify Validations while edit for Advanced Scan with Credentials: Host > SSH
        Auth Method: Public key and elevate privilege as su
        1. Repeat steps 1 to 7 from NQA-1080
        2. Remove username and hit ‘Save’
        3. Validation message should appear
        """
        key_path = os.path.abspath(get_file_path(
            'nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))
        public_key_form_data = {'auth': 'public key', 'username': 'root', 'elevate_privilege': 'su',
                                'passphrase': '********'}
        elevate_su_user_credential = {'elevate_privilege': 'su', 'su_login': 'root',
                                      'su_password': '********', 'location': '/usr/bin'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        scan_name = create_scan
        public_key = PublicKey(host_type=API.Credentials.Host.Types.SSH)
        LoadingCircle(WAIT_SHORT)

        public_key.credentials_type.select_by_visible_text('Host')

        assert public_key.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST
        assert public_key.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        public_key.fill_public_key_ssh_form(username=public_key_form_data['username'],
                                            key_path=key_path,
                                            passphrase='root',
                                            elevate_privilege=public_key_form_data['elevate_privilege'])
        public_key.fill_elevate_su_user_credential(su_login=elevate_su_user_credential['su_login'],
                                                   su_password='root', location=elevate_su_user_credential['location'])

        public_key.fill_global_setting_form(preferred_port=global_credential_data['preferred_port'],
                                            client_version=global_credential_data['client_version'],
                                            use_least_privilege=global_credential_data['use_least_privilege'])
        save_and_configure_scan(class_object=public_key, scan_name=scan_name)

        assert len(public_key.active_credentials) == 1, "More than 1 credentials are available"
        public_key.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        assert public_key.get_public_key_ssh_form_data() == public_key_form_data, 'Data saved is incorrect or missing'
        assert public_key.get_global_setting_form() == global_credential_data, 'Data saved is incorrect or missing'
        assert public_key.get_elevate_su_credential_values(
            elevate_privilege_value=elevate_su_user_credential['elevate_privilege']) == elevate_su_user_credential, \
            'Data saved is incorrect or missing'
        assert "api_pub_key_target_priv_key" in public_key.private_key_element.get_attribute('data-value'), \
            "uploaded file is not available"

        assert public_key.check_required_field_validation(class_instance=public_key, element='username_element',
                                                          error_message='username'), \
            'Error Notification is missing for blank Username'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_password_su_sudo_elevate_ssh_credentials(self, create_scan):
        """
        NQA-1081 : Verify Advanced scan is saved with Host -> ‘SSH’ and authentication method as ‘Password’
        and 'elevate privileges with' as 'su+sudo'

        NQA-1279 : Verify Validations while edit for Advanced Scan with Credentials: Host > SSH
        Auth Method: Password and elevate privilege as 'su+sudo'
        1. Repeat steps 1 to 7 from NQA-1081
        2. Remove su user and hit ‘Save’
        3. Validation message should appear
        """
        password_form_data = {'auth': 'password', 'username': 'root', 'password': '********'}
        password_privilege_data = {'elevate_privilege': 'su+sudo', 'su_user': 'admin', 'sudo_user': 'root',
                                   'location': 'tenable', 'password': '********'}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        scan_name = create_scan
        password = Password(host_type=API.Credentials.Host.Types.SSH)

        assert password.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST
        assert password.opened_form_value == API.Credentials.Host.Types.SSH, 'SSH form is not open'

        password.fill_password_ssh_form(username=password_form_data['username'],
                                        password='admin')

        password.fill_su_sudo_user_cred(su_user=password_privilege_data['su_user'],
                                        sudo_user=password_privilege_data['sudo_user'],
                                        password='admin',
                                        location=password_privilege_data['location'])

        password.fill_global_setting_form(preferred_port=global_credential_data['preferred_port'],
                                          client_version=global_credential_data['client_version'],
                                          use_least_privilege=global_credential_data['use_least_privilege'])
        save_and_configure_scan(class_object=password, scan_name=scan_name)

        assert len(password.active_credentials) == 1, "More than 1 credentials are available"
        password.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        assert password.get_password_ssh_form_data() == password_form_data, 'Data saved is incorrect or missing'
        assert password.get_elevate_cred_sudo_su_name(
            elevate_privilege_value=password_privilege_data['elevate_privilege']) == password_privilege_data, \
            'Data saved is incorrect or missing'

        assert password.get_global_setting_form() == global_credential_data, \
            'Global credential settings are incorrect or missing'

        assert password.check_required_field_validation(class_instance=password,
                                                        element='su_user_element'), \
            'Error Notification is missing for blank Su User'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_thycotic_ssh_credentials(self, create_scan):
        """
        NQA-1082 : Verify Advanced scan is saved with Host -> ‘SSH’
        and authentication method as ‘Thycotic Secret Server’.

        NQA-1279 : Verify Validations while edit for Advanced Scan with Credentials: Host > SSH
        Auth Method: Thycotic Secret Server
        1. Repeat steps 1 to 7 from NQA-1082
        2. Remove Thycotic secret server URL and hit ‘Save’
        3. Validation message should appear
        """
        scan_name = create_scan
        thycotic_form_data = {'auth': 'Thycotic Secret Server', 'username': 'root', 'secret_name': 'admin',
                              'server_url': 'test@tenable.com', 'login_name': 'admin',
                              'thycotic_password': '********', 'organization': 'tenable',
                              'thycotic_domain': 'tenable', 'ssl_certificate_element': False,
                              'use_private_key_element': True}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        thycotic_credential = ThycoticSecretServer(host_type=API.Credentials.Host.Types.SSH)
        thycotic_credential.fill_thycotic_form(username=thycotic_form_data['username'],
                                               secret_name=thycotic_form_data['secret_name'],
                                               server_url=thycotic_form_data['server_url'],
                                               login_name=thycotic_form_data['login_name'],
                                               thycotic_password='root',
                                               organization=thycotic_form_data['organization'],
                                               thycotic_domain=thycotic_form_data['thycotic_domain'],
                                               ssl_certificate_element=thycotic_form_data['ssl_certificate_element'],
                                               use_private_key_element=thycotic_form_data['use_private_key_element'])

        thycotic_credential.fill_global_setting_form(preferred_port=global_credential_data['preferred_port'],
                                                     client_version=global_credential_data['client_version'],
                                                     use_least_privilege=global_credential_data['use_least_privilege'])
        save_and_configure_scan(class_object=thycotic_credential, scan_name=scan_name)

        assert len(thycotic_credential.active_credentials) == 1, "More than 1 credentials are available"
        thycotic_credential.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        assert thycotic_credential.get_thycotic_ssh_form_data(host_type=API.Credentials.Host.Types.SSH) == \
               thycotic_form_data, 'Data saved is incorrect or missing'
        assert thycotic_credential.get_global_setting_form() == global_credential_data, \
            'Data saved is incorrect or missing'

        assert thycotic_credential.check_required_field_validation(class_instance=thycotic_credential,
                                                                   element='server_url_element',
                                                                   element_args={'host_type':
                                                                                     API.Credentials.Host.Types.SSH}), \
            'Error Notification is missing for blank Thycotic secret server URL'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_beyond_trust_ssh_credentials(self, create_scan):
        """
        NQA-1099 : Verify Advanced scan is saved with Host -> ‘SSH’ and authentication method as ‘BeyondTrust’.

        NQA-1279 : Verify Validations while edit for Advanced Scan with Credentials: Host > SSH
        Auth Method: Beyond Trust
        1. Go to Advanced Scan and create scan with Credentials > Host > Beyond Trust
        2. Save the scan
        3. Click on the created scan
        4. Go to credentials tab and verify values are retained
        5. Remove Checkout duration and hit 'Save'
        6. Validation message should appear
        """
        scan_name = create_scan
        beyond_trust_form_data = {'auth': 'BeyondTrust', 'username': 'root', 'port': '443',
                                  'host': 'test@tenable.com', 'api_user': 'admin', 'api_key': 'admin',
                                  'checkout_duration': '2', 'use_ssl': False, 'verify_ssl': False, 'private_key': True,
                                  'privilege_escalation': True}
        beyond_trust_form_data1 = {'auth': 'BeyondTrust', 'username': 'root', 'port': '443',
                                   'host': 'test@tenable.com', 'api_user': 'admin',
                                   'checkout_duration': '2', 'use_ssl': False, 'verify_ssl': False, 'private_key': True,
                                   'privilege_escalation': True}
        global_credential_data = {'preferred_port': '42', 'client_version': 'OpenSSH_6.0', 'use_least_privilege': True}

        beyond_trust = BeyondTrust(host_type=API.Credentials.Host.Types.SSH)

        beyond_trust.fill_beyond_trust_form(host_type=API.Credentials.Host.Types.SSH,
                                            username=beyond_trust_form_data['username'],
                                            host=beyond_trust_form_data['host'],
                                            port=beyond_trust_form_data['port'],
                                            api_user=beyond_trust_form_data['api_user'],
                                            api_key=beyond_trust_form_data['api_key'],
                                            checkout_duration=beyond_trust_form_data['checkout_duration'],
                                            use_ssl=beyond_trust_form_data['use_ssl'],
                                            verify_ssl=beyond_trust_form_data['verify_ssl'],
                                            private_key=beyond_trust_form_data['private_key'],
                                            privilege_escalation=beyond_trust_form_data['privilege_escalation'])

        beyond_trust.fill_global_setting_form(preferred_port=global_credential_data['preferred_port'],
                                              client_version=global_credential_data['client_version'],
                                              use_least_privilege=global_credential_data['use_least_privilege'])
        save_and_configure_scan(class_object=beyond_trust, scan_name=scan_name)

        assert len(beyond_trust.active_credentials) == 1, "More than 1 credentials are available"
        beyond_trust.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SSH)

        assert beyond_trust.get_ssh_beyond_trust_form_data() == beyond_trust_form_data1, \
            'Data saved is incorrect or missing'
        assert beyond_trust.get_global_setting_form() == global_credential_data, \
            'Data saved is incorrect or missing'

        assert beyond_trust.check_required_field_validation(class_instance=beyond_trust,
                                                            element='beyond_trust_checkout_duration_element',
                                                            element_args={'host_type':
                                                                              API.Credentials.Host.Types.SSH},
                                                            error_message='checkout_duration_element'), \
            'Error Notification is missing for blank Checkout Duration'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)
