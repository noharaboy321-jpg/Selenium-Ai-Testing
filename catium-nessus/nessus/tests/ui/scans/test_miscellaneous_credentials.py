"""
Nessus Credentials tab under Policy/Scan form related test cases for Miscellaneous.

:copyright: Tenable Network Security, 2018
:date: May 11, 2018
:last_modified: July 11, 2018
:author: @kpanchal, @mameta
"""
import copy
import os
import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT
from catium.lib.webium.wait import wait
from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.credentials.miscellaneous import Miscellaneous
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.scans.scans_page import ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestMiscellaneousCredentialsForm:
    """ This class covers Miscellaneous credential form related test """

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize("misc_type, test_data, element_to_validate",
                             [(API.Credentials.Miscellaneous.ADSI, {
                                 'domain_controller': '127.0.0.1', 'domain': '192.168.156.40', 'domain_admin': 'admin',
                                 'domain_pass': 'p@ssw0rd'}, 'domain_controller'),  # NQA-1155

                              (API.Credentials.Miscellaneous.F5,    # NQA-1156
                               {'user_name': 'admin', 'port': 4445, 'https': True,
                                'ssl_cert': True, 'password': 'p@ssw0rd'}, 'username'),
                              (API.Credentials.Miscellaneous.F5,
                               {'user_name': 'admin', 'port': 4445, 'https': True,
                                'ssl_cert': False, 'password': 'p@ssw0rd'}, None),  # NQA-1156
                              (API.Credentials.Miscellaneous.F5,
                               {'user_name': 'admin', 'port': 4445, 'https': False,
                                'ssl_cert': None, 'password': 'p@ssw0rd'}, None),  # NQA-1156

                              (API.Credentials.Miscellaneous.IBM_SERIES,    # NQA-1157
                               {'user_name': 'admin', 'password': 'p@ssw0rd'}, 'password'),

                              (API.Credentials.Miscellaneous.OPEN_STACK,
                               {'user_name': 'admin', 'password': 'p@ssw0rd',
                                'tenant_name': 'admin', 'port': 4445,
                                'https': True, 'ssl_cert': True}, 'username'),  # NQA-1158
                              (API.Credentials.Miscellaneous.OPEN_STACK,
                               {'user_name': 'admin', 'password': 'p@ssw0rd',
                                'tenant_name': 'admin', 'port': 4445,
                                'https': True, 'ssl_cert': False}, None),  # NQA-1158
                              (API.Credentials.Miscellaneous.OPEN_STACK,
                               {'user_name': 'admin', 'password': 'p@ssw0rd',
                                'tenant_name': 'admin', 'port': 4445,
                                'https': False, 'ssl_cert': None}, None),  # NQA-1158

                              (API.Credentials.Miscellaneous.PALO_ALTO,     # NQA-1159
                               {'user_name': 'admin', 'port': 4445, 'https': True,
                                'ssl_cert': True, 'password': 'p@ssw0rd'}, 'username'),
                              (API.Credentials.Miscellaneous.PALO_ALTO,
                               {'user_name': 'admin', 'port': 4445, 'https': True,
                                'ssl_cert': False, 'password': 'p@ssw0rd'}, None),  # NQA-1159
                              (API.Credentials.Miscellaneous.PALO_ALTO,
                               {'user_name': 'admin', 'port': 4445, 'https': False,
                                'ssl_cert': None, 'password': 'p@ssw0rd'}, None),  # NQA-1159

                              (API.Credentials.Miscellaneous.RHEV,
                               {'user_name': 'admin', 'port': 4445, 'ssl_cert': True,
                                'password': 'p@ssw0rd'}, 'username'),  # NQA-1160
                              (API.Credentials.Miscellaneous.RHEV,
                               {'user_name': 'admin', 'port': 4445, 'ssl_cert': False,
                                'password': 'p@ssw0rd'}, None),  # NQA-1160

                              (API.Credentials.Miscellaneous.VMWARE_ESX,
                               {'user_name': 'admin', 'ssl_cert': False,
                                'password': 'p@ssw0rd'}, 'username'),  # NQA-1161
                              (API.Credentials.Miscellaneous.VMWARE_ESX,
                               {'user_name': 'admin', 'ssl_cert': True,
                                'password': 'p@ssw0rd'}, None),  # NQA-1161

                              (API.Credentials.Miscellaneous.VMWARE_VCENTER,
                               {'vcenter_host': '127.0.0.1', 'vcenter_port': 4445,
                                'user_name': 'admin', 'password': 'p@ssw0rd', 'https': True,
                                'ssl_cert': True}, 'vcenter_host'),  # NQA-1162
                              (API.Credentials.Miscellaneous.VMWARE_VCENTER,
                               {'vcenter_host': '127.0.0.1', 'vcenter_port': 4445,
                                'user_name': 'admin', 'password': 'p@ssw0rd', 'https': True,
                                'ssl_cert': False}, None),  # NQA-1162
                              (API.Credentials.Miscellaneous.VMWARE_VCENTER,
                               {'vcenter_host': '127.0.0.1', 'vcenter_port': 4445,
                                'user_name': 'admin', 'password': 'p@ssw0rd', 'https': False,
                                'ssl_cert': None}, None)])  # NQA-1162
    def test_miscellaneous_credential_forms(self, create_scan, misc_type, test_data, element_to_validate):
        """
        NQA-1155 : Verify Advanced scan is saved with Miscellaneous > ADSI
        NQA-1156 : Verify Advanced scan is saved with Miscellaneous > F5
        NQA-1157 : Verify Advanced scan is saved with Miscellaneous > IBM iSeries
        NQA-1158 : Verify Advanced scan is saved with Miscellaneous > OpenStack
        NQA-1159 : Verify Advanced scan is saved with Miscellaneous > Palo Alto networks PAN-OS
        NQA-1160 : Verify Advanced scan is saved with Miscellaneous > RHEV
        NQA-1161 : Verify Advanced scan is saved with Miscellaneous > VMware ESX SOAP API
        NQA-1162 : Verify Advanced scan is saved with Miscellaneous > VMware vCenter SOAP API
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select subcategories of Miscellaneous.
        4. Verify form input fields of related subcategories
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1280 Verify mandatory field validation while edit for Advanced scan with credentials -> Miscellaneous
        1. Repeat steps 1 to 7 from above
        2. Under each test case remove required field and hit ‘Save’
        3. Validation message should appear
        """
        scan_name = create_scan
        misc_inst = Miscellaneous.get_misc_inst(misc_type)
        misc_inst.fill_form(**test_data)
        save_and_configure_scan(class_object=misc_inst, scan_name=scan_name)
        misc_inst.open_saved_credentials_component(form_name=misc_type)

        updated_test_data = copy.deepcopy(test_data)

        for key in ('domain_pass', 'password'):
            if key in updated_test_data.keys():
                updated_test_data[key] = '********'

        if 'ssl_cert' in updated_test_data.keys() and updated_test_data['ssl_cert'] is None:
            del updated_test_data['ssl_cert']

        assert misc_inst.get_form_values() == updated_test_data, "Entered data and Filled data is different."

        if element_to_validate:
            assert misc_inst.check_required_field_validation(class_instance=misc_inst, element=element_to_validate), \
                'Error notification for blank {} is missing.'.format(element_to_validate)
        HeaderBasePage().scan_link.click()

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_x509_credential_form(self, create_scan):
        """
        NQA-1163 : Verify Advanced scan is saved with Miscellaneous > X.509
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Miscellaneous > X.509
        4. Verify following input fields:
        - Client Certificate
        - Client key
        - Password for key
        - CA Certificate to trust
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1280 Verify mandatory field validation while edit for Advanced scan with credentials -> Miscellaneous
        1. Repeat steps 1 to 7 from -NQA-1163-
        2. Under X.509 remove 'Client certificate' file and hit ‘Save’
        3. Validation message should appear
        """
        key_path = os.path.abspath(get_file_path('nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))
        scan_name = create_scan
        misc_inst = Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.X509)
        misc_inst.fill_form(client_cert=key_path, client_key=key_path, pass_key='p@ssw0rd', ca_cert_path=key_path)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=misc_inst, scan_name=scan_name)
        misc_inst.open_saved_credentials_component(form_name=API.Credentials.Miscellaneous.X509)

        assert "api_pub_key_target_priv_key" in misc_inst.client_cert.get_attribute('data-value'), \
            "Uploaded file is not available."

        assert "api_pub_key_target_priv_key" in misc_inst.client_key.get_attribute('data-value'), \
            "Uploaded file is not available."

        assert "********" in misc_inst.pass_for_key.value, "Entered data and Filled data is different."

        assert "api_pub_key_target_priv_key" in misc_inst.ca_cert_to_trust.get_attribute('data-value'), \
            "Uploaded file is not available."

        misc_inst.remove_attached_file(data_name="Client certificate").click()
        LoadingCircle(WAIT_SHORT)
        assert misc_inst.get_add_file_link(data_name="Client certificate").is_displayed(), \
            "Add File link for client certificate is not displayed"

        ScansPage().save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Credentials.client_certificate, \
            'scan saved successfully and did not get error notification for missing required "Add File" field'

        HeaderBasePage().scan_link.click()
