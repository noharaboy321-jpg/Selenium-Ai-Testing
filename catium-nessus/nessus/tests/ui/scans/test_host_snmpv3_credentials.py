"""
Nessus Credentials tab under Scan form related test cases For Host -> SNMPv3

:copyright: Tenable Network Security, 2018
:date: Apr 25, 2018
:last_modified: jul 13, 2018
:author: @jchavda, @krpatel
"""
import pytest

from selenium.webdriver import ChromeOptions
from catium.lib.const import WAIT_SHORT
from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.host import SNMPv3
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.fixture()
def chrome_options():
    """Set chrome options."""
    options = ChromeOptions()

    prefs = {"profile.password_manager_leak_detection": False}
    options.add_experimental_option('prefs', prefs)
    return options

@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestSnmpvCredentialForm:
    """
    NQA-1108 : Credentials -> Category 'Host' -> 'SNMPv3 form related Test cases
    NQA-1278 : Verify mandatory field validation while edit for Advanced scan with credentials -> Host
    """
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize("snmpv3_form_data, element_to_validate", [({'username': 'administrator',
                                                                         'port': API.Credentials.Host.Ports.SNMP,
                                                                         'security_level': 'No authentication '
                                                                                           'and no privacy'},
                                                                        'username'),
                                                                       ({'username': 'administrator',
                                                                         'port': API.Credentials.Host.Ports.SNMP,
                                                                         'security_level': 'Authentication without '
                                                                                           'privacy',
                                                                         'authentication_algo': 'SHA1',
                                                                         'auth_password': 'admin'},
                                                                        'authentication_password_element'),
                                                                       ({'username': 'administrator',
                                                                         'port': API.Credentials.Host.Ports.SNMP,
                                                                         'security_level': 'Authentication without '
                                                                                           'privacy',
                                                                         'authentication_algo': 'MD5',
                                                                         'auth_password': 'admin'},
                                                                        'authentication_password_element'),
                                                                       ({'username': 'administrator',
                                                                         'port': API.Credentials.Host.Ports.SNMP,
                                                                         'security_level': 'Authentication and privacy',
                                                                         'authentication_algo': 'SHA1',
                                                                         'auth_password': 'admin',
                                                                         'privacy_algo': 'AES',
                                                                         'privacy_password': 'admin'},
                                                                        'privacy_password'),
                                                                       ({'username': 'administrator',
                                                                         'port': API.Credentials.Host.Ports.SNMP,
                                                                         'security_level': 'Authentication and privacy',
                                                                         'authentication_algo': 'SHA1',
                                                                         'auth_password': 'admin',
                                                                         'privacy_algo': 'DES',
                                                                         'privacy_password': 'admin'}, None),
                                                                       ({'username': 'administrator',
                                                                         'port': API.Credentials.Host.Ports.SNMP,
                                                                         'security_level': 'Authentication and privacy',
                                                                         'authentication_algo': 'MD5',
                                                                         'auth_password': 'admin',
                                                                         'privacy_algo': 'DES',
                                                                         'privacy_password': 'admin'},
                                                                        'privacy_password'),
                                                                       ({'username': 'administrator',
                                                                         'port': API.Credentials.Host.Ports.SNMP,
                                                                         'security_level': 'Authentication and privacy',
                                                                         'authentication_algo': 'MD5',
                                                                         'auth_password': 'admin',
                                                                         'privacy_algo': 'AES',
                                                                         'privacy_password': 'admin'}, None)])
    def test_snmpv3_form_credentials(self, create_scan, snmpv3_form_data, element_to_validate):
        """
        NQA-1108 : Verify 'advanced scan' under 'Scanner' tab is saved with credentials -> 'Host' -> 'SNMPv3'
        1. Navigate Advanced scan template
        2. Give name and target
        3. Go to Credential --> Host --> SNMPv3
        4. Fill the form
        5. Save scan
        6. Click on created scan
        7. Verify saved values are retained

        NQA-1284 : Verify Validations while edit for Advanced Scan with Credentials: Host > SNMPv3
        Security Level- No Auth No privacy
        1. Repeat steps 1 to 7 from NQA-1109
        2. Remove username and hit 'Save' button
        3. Validation message should appear

        Security Level- Authentication without privacy
        1. Repeat steps 1 to 7 from NQA-1110
        2. Remove authentication password and hit 'Save' button
        3. Validation message should appear

        Security Level- Authentication and privacy
        1. Repeat steps 1 to 7 from NQA-1111
        2. Remove privacy password and hit 'Save' button
        3. Validation message should appear
        """
        scan_form_data = snmpv3_form_data
        scan_name = create_scan

        snmpv_page = SNMPv3(host_type=API.Credentials.Host.Types.SNMPV3)
        LoadingCircle(WAIT_SHORT)

        assert snmpv_page.get_credentials_types(category_name='Host') == API.Credentials.Host.Types.HOST_LIST, \
            'Category Type is missing'
        assert snmpv_page.opened_form_value == API.Credentials.Host.Types.SNMPV3, 'SNMPv3 form is not open'

        snmpv_page.fill_snmpv3_form(**scan_form_data)
        save_and_configure_scan(class_object=snmpv_page, scan_name=scan_name)

        assert len(snmpv_page.active_credentials) == 1, "More than 1 credentials are available"
        LoadingCircle(WAIT_SHORT)
        snmpv_page.open_saved_credentials_component(form_name=API.Credentials.Host.Types.SNMPV3)

        scan_form_data_to_compare = dict(
            filter(lambda i: i[0] not in ('auth_password', 'privacy_password'), scan_form_data.items()))
        assert snmpv_page.get_snmpv3_form_data() == scan_form_data_to_compare, 'Data saved is incorrect or missing'

        if element_to_validate:
            assert snmpv_page.check_required_field_validation(class_instance=snmpv_page, element=element_to_validate,
                                                              element_args={'data_group': snmpv3_form_data[
                                                                  'security_level']}), \
                'Error Notification is missing for blank {}'.format(element_to_validate)

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)
