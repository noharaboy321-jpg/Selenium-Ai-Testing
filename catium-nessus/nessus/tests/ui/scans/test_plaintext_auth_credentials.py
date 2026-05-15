"""
Test file for Nessus Credentials tab under Policy/Scan form related test cases For Plaintext Authentication

:copyright: Tenable Network Security, 2018
:date: May 09, 2018
:last_modified: July 12, 2018
:author: @mameta, @kpanchal
"""
import copy
import pytest
from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT, os, WAIT_NORMAL
from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.credentials.plaintext_authentication import PlainTextAuthentication
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestPlainTextAuthCredentials:
    """NQA-1132: Automation tests for 'advanced scan' under 'Scanner' tab is saved successfully with values
                 given under credentials ->Category 'Plaintext Authentication'"""

    @pytest.mark.parametrize("auth_type, test_data, element_to_validate", [
        (API.Credentials.PlaintextAuthentication.FTP, {'username': 'admin', 'password': 'admin'}, None),  # NQA-1133

        (API.Credentials.PlaintextAuthentication.IMAP, {'username': 'admin', 'password': 'admin'}, None),  # NQA-1134

        (API.Credentials.PlaintextAuthentication.IPMI, {'username': 'admin', 'password': 'admin'}, None),  # NQA-1135

        (API.Credentials.PlaintextAuthentication.NNTP, {'username': 'admin', 'password': 'admin'}, None),  # NQA-1136

        (API.Credentials.PlaintextAuthentication.POP2,
         {'username': 'admin', 'password': 'admin'}, 'username'),  # NQA-1137

        (API.Credentials.PlaintextAuthentication.POP3, {'username': 'admin', 'password': 'admin'}, None),  # NQA-1138

        (API.Credentials.PlaintextAuthentication.HTTP,
         {'http_auth_type': 'Automatic authentication', 'username': 'admin', 'password': 'admin',
          'login_method': 'POST', 're_authenticate_delay': 22, 'follow_redirection': 22,
          'invert_authenticated_regex': True, 'use_authenticated_regex': True,
          'case_insensitive_authenticated_regex': True}, 'username'),  # NQA-1140

        (API.Credentials.PlaintextAuthentication.HTTP,
         {'http_auth_type': 'HTTP login form', 'username': 'admin', 'password': 'admin', 'login_page': 'admin',
          'login_submission_page': 'nessus', 'login_parameters': 'admin', 'check_authentication': 'admin',
          'regex_to_verify': 'admin', 'login_method': 'POST', 're_authenticate_delay': 22, 'follow_redirection': 22,
          'invert_authenticated_regex': True, 'use_authenticated_regex': True,
          'case_insensitive_authenticated_regex': True}, 'login_page'),  # NQA-1139

        (API.Credentials.PlaintextAuthentication.SNMPV12,
         {'community_string': 'private', 'udp_port': 22, 'additional_udp_port1': 22, 'additional_udp_port2': 22,
          'additional_udp_port3': 22}, None),  # NQA-1143

        (API.Credentials.PlaintextAuthentication.TELNET_RSH_REXEC,
         {'username': 'admin', 'password': "admin", 'patch_audits_over_telnet': True, 'patch_audits_over_rsh': True,
          'patch_audits_over_rexec': True}, 'password')])  # NQA-1144
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_plaintext_authentication_credentials(self, create_scan, auth_type, test_data, element_to_validate):
        """
        NQA-1133: Verify Advanced scan is saved with Plaintext Authentication > FTP
        NQA-1134: Verify Advanced scan is saved with Plaintext Authentication > IMAP
        NQA-1135: Verify Advanced scan is saved with Plaintext Authentication > IPMI
        NQA-1136: Verify Advanced scan is saved with Plaintext Authentication > NNTP
        NQA-1137: Verify Advanced scan is saved with Plaintext Authentication > POP2
        NQA-1138: Verify Advanced scan is saved with Plaintext Authentication > POP3
        NQA-1140: Verify Advanced scan is saved with Plaintext Authentication > HTTP and
                        authentication method 'Automatic authentication'
        NQA-1141: Verify Advanced scan is saved with Plaintext Authentication > HTTP and
                        authentication method 'Basic/Digest authentication'
        NQA-1143: Verify Advanced scan is saved with Plaintext Authentication > SNMPv1/v2c
        NQA-1144: Verify Advanced scan is saved with Plaintext Authentication > telnet/rsh/rexec
        1. Navigate to My Scans > New Scan
        2. Enter Scan details
        3. Go to credentials tab and select Plaintext Authentication
        4. Fill input fields for the sub categories
        5. Save the scan
        6. Open the saved scan
        7. Verify the data saved is retained.

        NQA-1285: Verify mandatory field validation while edit for Advanced scan with credentials ->
        Plaintext Authentication

        HTTP:
        1)  Authentication method -> Automatic Authentication
            - Repeat steps 1 to 7 from NQA-1140.
            - Under HTTP and Authentication method 'Automatic Authentication', remove Username and save the scan.
            - Validation message should appear.

        2) Authentication method -> Basic/Digest Authentication
            - Repeat steps 1 to 7 from NQA-1141.
            - Under HTTP and Authentication method 'Basic/Digest Authentication', remove Password and save the scan.
            - Validation message should appear.

        3) Authentication method -> HTTP Login form
            - Repeat steps 1 to 7 from NQA-1139.
            - Under HTTP and Authentication method 'HTTP Login form', remove Login Page and save the scan.
            - Validation message should appear.

        POP2:
            - Repeat steps 1 to 7 from NQA-1137.
            - Under POP2, remove Username and save the scan.
            - Validation message should appear.

        telnet/rsh/rexec:
            - Repeat steps 1 to 7 from NQA-1144.
            - Under telnet/rsh/rexec, remove Password and save the scan.
            - Validation message should appear.
        """
        scan_name = create_scan
        plain_text = PlainTextAuthentication.get_auth_type(pt_auth=auth_type)
        assert plain_text.opened_form_value == auth_type, '%s form is not open' % auth_type

        LoadingCircle(WAIT_NORMAL)
        plain_text.fill_form(**test_data)
        save_and_configure_scan(class_object=plain_text, scan_name=scan_name)
        assert len(plain_text.active_credentials) == 1, 'More than 1 credentials are available'

        plain_text.open_saved_credentials_component(form_name=auth_type)

        plain_text_data = copy.deepcopy(test_data)
        if 'password' in plain_text_data.keys():
            plain_text_data['password'] = '********'

        assert plain_text.get_form_data() == plain_text_data, 'Data saved is incorrect or missing'

        if element_to_validate:
            if auth_type == API.Credentials.PlaintextAuthentication.HTTP and \
                            test_data['http_auth_type'] in ['Automatic authentication', 'Basic/Digest authentication']:
                assert plain_text.check_required_field_validation(
                    class_instance=plain_text, element=element_to_validate,
                    element_args={'http_auth_type': test_data['http_auth_type']}), \
                    'Error notification for blank {} is missing.'.format(element_to_validate)
            elif auth_type == API.Credentials.PlaintextAuthentication.TELNET_RSH_REXEC:
                plain_text.password.clear()
                plain_text.save_button.click()
                assert Notifications().errors[-1] == 'Error: Password (unsafe!) is required.'
            else:
                assert plain_text.check_required_field_validation(class_instance=plain_text,
                                                                  element=element_to_validate), \
                    'Error notification for blank {} is missing.'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('auth_type, test_data', [(API.Credentials.PlaintextAuthentication.HTTP,
                                                       {'http_auth_type': 'HTTP cookies import',
                                                        'login_method': 'GET', 're_authenticate_delay': 22,
                                                        'follow_redirection': 22, 'invert_authenticated_regex': True,
                                                        'use_authenticated_regex': True,
                                                        'case_insensitive_authenticated_regex': True})])
    def test_http_cookies_import(self, create_scan, auth_type, test_data):
        """
        NQA-1142: Verify Advanced scan is saved with Plaintext Authentication > HTTP and authentication method
        'HTTP cookies import'
        1. Navigate to My Scans > New Scan
        2. Enter Scan details
        3. Go to credentials tab and select Plaintext Authentication
        4. Fill input fields for the sub categories
        5. Save the scan
        6. Open the saved scan
        7. Verify the data saved is retained.

        NQA-1285: Verify mandatory field validation while edit for Advanced scan with credentials ->
        Plaintext Authentication

        HTTP:
        4) Authentication method -> HTTP cookie import
            - Repeat steps 1 to 7 from NQA-1142.
            - Under HTTP and Authentication method 'HTTP cookie import', remove Cookie file and save the scan.
            - Validation message should appear.
        """
        key_path = os.path.abspath(get_file_path('nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))
        scan_name = create_scan

        plain_text = PlainTextAuthentication.get_auth_type(pt_auth=auth_type)
        assert plain_text.opened_form_value == auth_type, '%s form is not open' % auth_type

        LoadingCircle(WAIT_NORMAL)
        plain_text.fill_form(**test_data, add_cookies_file=key_path)
        save_and_configure_scan(class_object=plain_text, scan_name=scan_name)
        assert len(plain_text.active_credentials) == 1, 'More than 1 credentials are available'

        plain_text.open_saved_credentials_component(form_name=auth_type)
        if 'password' in test_data.keys():
            test_data['password'] = '********'

        assert plain_text.get_form_data() == test_data, 'Data saved is incorrect or missing'
        assert "api_pub_key_target_priv_key" in \
               plain_text.add_cookies_file.get_attribute('data-value'), \
            'api_pub_key_target_priv_key file is not available'

        plain_text.remove_cookies_file.click()
        plain_text.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Credentials.required_cookies_file, \
            'Error notification is missing after removing cookies file.'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)
