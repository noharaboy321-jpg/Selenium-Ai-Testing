"""
Nessus Credentials tab under Policy/Scan form related test cases for Host > Windows

:copyright: Tenable Network Security, 2018
:date: April 26, 2018
:last_modified: jul 16, 2018
:author: @ntarwani, @jchavda
"""
import pytest

from catium.lib.const import WAIT_SHORT
from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.host import KerBeros, Password, ThycoticSecretServer, BeyondTrust, Hash
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.usefixtures('login')
class TestUICredentialsWindowsForm:
    """ NQA-1100- Credentials > Host > Windows form related Test Cases"""

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_password_windows_credentials(self, create_scan):
        """
        NQA- 1101- Windows form with Authentication type "Password"
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type 'Password'
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1283 : Verify Validations while edit for Advanced Scan with Credentials: Host > Windows
        Auth Method: Password
        1. Repeat steps 1 to 7 from NQA-1101
        2. Remove Username and hit ‘Save’
        3. Validation message should appear
        """
        scan_name = create_scan
        password_form_data = {'auth': 'Password', 'username': 'administrator', 'password': 'admin', 'domain': 'tenable'}
        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': False, 'enable_admin_shares': False}

        password = Password(host_type=API.Credentials.Host.Types.WINDOWS)
        password.fill_password_windows_form(**password_form_data)
        password.fill_global_settings_for_windows(**global_credential_data)
        save_and_configure_scan(class_object=password, scan_name=scan_name)

        assert len(password.active_credentials) == 1, "More than 1 credentials are available"
        password.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)
        password_form_data.update({'password': '********'})
        assert password.get_password_windows_form_data() == password_form_data, 'Data saved is incorrect or missing'

        assert password.get_global_settings_for_windows() == global_credential_data, \
            'Global credential settings are incorrect or missing'
        assert password.check_required_field_validation(class_instance=password, element='username_element',
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
    @pytest.mark.parametrize("hash_type", ["LM Hash", "NTLM Hash"])
    def test_hash_windows_credentials(self, create_scan, hash_type):
        """
        NQA- 1104- Windows form with Authentication type "LM Hash"
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type 'LM HASH' and 'NTLM Hash' one by one
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1283 : Verify Validations while edit for Advanced Scan with Credentials: Host > Windows
        Auth Method: LM Hash , NTLM Hash
        1. Repeat steps 1 to 7 from NQA-1104 , NQA-1105
        2. Remove Hash and hit ‘Save’
        3. Validation message should appear
        """
        scan_name = create_scan
        hash_form_data = {'auth': hash_type, 'username': 'administrator', 'hash_field': 'admin', 'domain': 'tenable'}
        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': True, 'enable_admin_shares': True}

        hash = Hash(host_type=API.Credentials.Host.Types.WINDOWS)
        hash.fill_windows_hash_form(**hash_form_data)

        hash.fill_global_settings_for_windows(**global_credential_data)

        save_and_configure_scan(class_object=hash, scan_name=scan_name)

        assert len(hash.active_credentials) == 1, "More than 1 credentials are available"
        hash.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)
        hash_form_data.update({'hash_field': '********'})
        assert hash.get_hash_windows_form_data() == hash_form_data, 'Data saved is incorrect or missing'
        assert hash.get_global_settings_for_windows() == global_credential_data, 'Data saved is incorrect or missing'
        assert hash.check_required_field_validation(class_instance=hash, element='password_element',
                                                    error_message='hash_element'), \
            'Error Notification is missing for blank Hash'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_thycotic_server_windows_credentials(self, create_scan):
        """
        NQA- 1106- Windows form with Authentication type "Thycotic Server"
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type 'Thycotic Server'
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1283 : Verify Validations while edit for Advanced Scan with Credentials: Host > Windows
        Auth Method: Thycotic Secret Server
        1. Repeat steps 1 to 7 from NQA-1106
        2. Remove Thycotic secret name and hit ‘Save’
        3. Validation message should appear
        """
        scan_name = create_scan

        thycotic_form_data = {'auth': 'Thycotic Secret Server', 'username': 'administrator', 'secret_name': 'admin',
                              'server_url': 'test@tenable.com', 'login_name': 'admin',
                              'thycotic_password': 'admin', 'organization': 'tenable',
                              'thycotic_domain': 'tenable', 'ssl_certificate_element': True,
                              'domain_name': 'tenable'}

        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': True, 'enable_admin_shares': True}

        thycotic_server = ThycoticSecretServer(host_type=API.Credentials.Host.Types.WINDOWS)
        thycotic_server.fill_thycotic_form(host_type=API.Credentials.Host.Types.WINDOWS, **thycotic_form_data)
        thycotic_server.js_scroll_into_view(ScansPage().save_button)
        thycotic_server.fill_global_settings_for_windows(**global_credential_data)
        save_and_configure_scan(class_object=thycotic_server, scan_name=scan_name)

        assert len(thycotic_server.active_credentials) == 1, "More than 1 credentials are available"
        thycotic_server.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)
        thycotic_form_data.update({'thycotic_password': '********'})
        assert thycotic_server.get_thycotic_windows_form_data(host_type=API.Credentials.Host.Types.WINDOWS) == \
               thycotic_form_data, 'Data saved is incorrect or missing'
        assert thycotic_server.get_global_settings_for_windows() == global_credential_data, \
            'Data saved is incorrect or missing'
        assert thycotic_server.check_required_field_validation(class_instance=thycotic_server,
                                                               element='server_url_element',
                                                               element_args={'host_type':
                                                                                 API.Credentials.Host.Types.WINDOWS}), \
            'Error Notification is missing for blank Thycotic Secret Server URL'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_beyond_trust_windows_credentials(self, create_scan):
        """
        NQA- 1107- Windows form with Authentication type "Beyond Trust"
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type 'Beyond trust'
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1283 : Verify Validations while edit for Advanced Scan with Credentials: Host > Windows
        Auth Method: Beyond Trust
        1. Repeat steps 1 to 7 from NQA-1107
        2. Remove Beyond Trust API key and hit ‘Save’
        3. Validation message should appear
        """
        scan_name = create_scan

        beyond_trust_form_data = {'auth': 'BeyondTrust', 'username': 'administrator', 'domain': 'tenable',
                                  'port': '443', 'host': 'test@tenable.com', 'api_user': 'admin', 'api_key': 'admin',
                                  'checkout_duration': '2', 'use_ssl': True, 'verify_ssl': True}
        beyond_trust_form_data1 = {'auth': 'BeyondTrust', 'username': 'administrator', 'domain': 'tenable',
                                  'port': '443', 'host': 'test@tenable.com', 'api_user': 'admin',
                                  'checkout_duration': '2', 'use_ssl': True, 'verify_ssl': True}

        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': True, 'enable_admin_shares': True}

        beyond_trust = BeyondTrust(host_type=API.Credentials.Host.Types.WINDOWS)
        beyond_trust.fill_beyond_trust_form(host_type=API.Credentials.Host.Types.WINDOWS, **beyond_trust_form_data)
        scan_page = ScansPage()
        beyond_trust.js_scroll_into_view(scan_page.save_button)
        beyond_trust.fill_global_settings_for_windows(**global_credential_data)
        save_and_configure_scan(class_object=beyond_trust, scan_name=scan_name)

        assert len(beyond_trust.active_credentials) == 1, "More than 1 credentials are available"
        beyond_trust.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)

        assert beyond_trust.get_windows_beyond_trust_form_data() == beyond_trust_form_data1, \
            'Data saved is incorrect or missing'
        assert beyond_trust.get_global_settings_for_windows() == global_credential_data, \
            'Data saved is incorrect or missing'
        assert beyond_trust.check_required_field_validation(class_instance=beyond_trust,
                                                            element='beyond_trust_api_key_element',
                                                            element_args={'host_type': API.Credentials.Host.Types.
                                                            WINDOWS}), \
            'Error Notification is missing for blank Beyond Trust API key'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.nessus_home
    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_kerberos_windows_credentials(self, create_scan):
        """
        NQA- 1103- Windows form with Authentication type "Kerberos"
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Host > Windows
        4. Fill the form with authentication type 'Kerberos'
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1283 : Verify Validations while edit for Advanced Scan with Credentials: Host > Windows
        Auth Method: Kerberos
        1. Repeat steps 1 to 7 from NQA-1103
        2. Remove Key Distribution Center and hit ‘Save’
        3. Validation message should appear
        """
        scan_name = create_scan

        kerberos_form_data = {'auth': 'Kerberos', 'username': 'administrator', 'password': 'admin',
                              'key_dis_center': 'npwkdc.lab.tenablesecurity.com', 'kdc_port': '88',
                              'domain': 'tenable'}

        global_credential_data = {'never_send_credentials': True, 'do_not_use_ntlm': True,
                                  'start_remote_registry': True, 'enable_admin_shares': True}

        kerberos = KerBeros(host_type=API.Credentials.Host.Types.WINDOWS)
        kerberos.fill_kerberos_windows_form(**kerberos_form_data)
        scan_page = ScansPage()
        kerberos.js_scroll_into_view(scan_page.save_button)
        kerberos.fill_global_settings_for_windows(**global_credential_data)

        save_and_configure_scan(class_object=kerberos, scan_name=scan_name)

        assert len(kerberos.active_credentials) == 1, "More than 1 credentials are available"
        kerberos.open_saved_credentials_component(form_name=API.Credentials.Host.Types.WINDOWS)
        kerberos_form_data.update({'password': '********'})
        assert kerberos.get_kerberos_windows_form_data() == kerberos_form_data, \
            'Data saved is incorrect or missing'
        assert kerberos.get_global_settings_for_windows() == global_credential_data, \
            'Data saved is incorrect or missing'
        assert kerberos.check_required_field_validation(
            class_instance=kerberos, element='key_dis_center_element',
            element_args={'host_type': API.Credentials.Host.Types.WINDOWS}), \
            'Error Notification is missing for blank Key Distribution Center'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)
