"""
 Nessus Credential tab under Policy related test cases for Miscellaneous.
:Copyright: Tenable Network Security, 2018
:Date: May 23, 2018
:Modified Date: May 24, 2018
:Author: @jchavda
"""
import os
import pytest

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT
from nessus.lib.const import API
from nessus.pageobjects.credentials.miscellaneous import Miscellaneous
from nessus.pageobjects.policies.policies_page import PolicyList, NewPolicyForm
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.policies_pipeline_1
@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestMiscellaneousPolicy:
    """
    NQA-1235: This page class covers Miscellaneous under Policy related Test cases
    """
    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    @pytest.mark.parametrize("misc_type, form_data", [
        (API.Credentials.Miscellaneous.ADSI, {'domain_controller': '127.0.0.1', 'domain': '192.168.156.40',
                                              'domain_admin': 'admin',
                                              'domain_pass': 'p@ssw0rd'}),  # NQA-1236
        (API.Credentials.Miscellaneous.F5, {'user_name': 'admin', 'port': 4445, 'https': True,
                                            'ssl_cert': True, 'password': 'p@ssw0rd'}),  # NQA-1237
        (API.Credentials.Miscellaneous.F5, {'user_name': 'admin', 'port': 4445, 'https': True,
                                            'ssl_cert': False, 'password': 'p@ssw0rd'}),  # NQA-1237
        (API.Credentials.Miscellaneous.F5, {'user_name': 'admin', 'port': 4445, 'https': False,
                                            'ssl_cert': None, 'password': 'p@ssw0rd'}),
        (API.Credentials.Miscellaneous.IBM_SERIES, {'user_name': 'admin', 'password': 'p@ssw0rd'}),  # NQA-1238
        (API.Credentials.Miscellaneous.OPEN_STACK, {'user_name': 'admin', 'password': 'p@ssw0rd',
                                                    'tenant_name': 'admin', 'port': 4445,
                                                    'https': True, 'ssl_cert': True}),  # NQA-1239
        (API.Credentials.Miscellaneous.OPEN_STACK, {'user_name': 'admin', 'password': 'p@ssw0rd',
                                                    'tenant_name': 'admin', 'port': 4445,
                                                    'https': True, 'ssl_cert': False}),  # NQA-1239
        (API.Credentials.Miscellaneous.OPEN_STACK, {'user_name': 'admin', 'password': 'p@ssw0rd',
                                                    'tenant_name': 'admin', 'port': 4445,
                                                    'https': False, 'ssl_cert': None}),  # NQA-1239
        (API.Credentials.Miscellaneous.PALO_ALTO, {'user_name': 'admin', 'port': 4445, 'https': True,
                                                   'ssl_cert': True, 'password': 'p@ssw0rd'}),  # NQA-1240
        (API.Credentials.Miscellaneous.PALO_ALTO, {'user_name': 'admin', 'port': 4445, 'https': True,
                                                   'ssl_cert': False, 'password': 'p@ssw0rd'}),  # NQA-1240
        (API.Credentials.Miscellaneous.PALO_ALTO, {'user_name': 'admin', 'port': 4445, 'https': False,
                                                   'ssl_cert': None, 'password': 'p@ssw0rd'}),  # NQA-1240
        (API.Credentials.Miscellaneous.RHEV, {'user_name': 'admin', 'port': 4445, 'ssl_cert': True,
                                              'password': 'p@ssw0rd'}),  # NQA-1241
        (API.Credentials.Miscellaneous.RHEV, {'user_name': 'admin', 'port': 4445, 'ssl_cert': False,
                                              'password': 'p@ssw0rd'}),  # NQA-1241
        (API.Credentials.Miscellaneous.VMWARE_ESX, {'user_name': 'admin', 'ssl_cert': False,
                                                    'password': 'p@ssw0rd'}),  # NQA-1242
        (API.Credentials.Miscellaneous.VMWARE_ESX, {'user_name': 'admin', 'ssl_cert': True,
                                                    'password': 'p@ssw0rd'}),  # NQA-1242
        (API.Credentials.Miscellaneous.VMWARE_VCENTER, {'vcenter_host': '127.0.0.1', 'vcenter_port': 4445,
                                                        'user_name': 'admin', 'password': 'p@ssw0rd', 'https': True,
                                                        'ssl_cert': True}),  # NQA-1243
        (API.Credentials.Miscellaneous.VMWARE_VCENTER, {'vcenter_host': '127.0.0.1', 'vcenter_port': 4445,
                                                        'user_name': 'admin', 'password': 'p@ssw0rd', 'https': True,
                                                        'ssl_cert': False}),  # NQA-1243
        (API.Credentials.Miscellaneous.VMWARE_VCENTER, {'vcenter_host': '127.0.0.1', 'vcenter_port': 4445,
                                                        'user_name': 'admin', 'password': 'p@ssw0rd', 'https': False,
                                                        'ssl_cert': None})])
    def test_miscellaneous_credential(self, create_policy, misc_type, form_data):
        """
        NQA-1236 : Verify Advanced scan is saved with Miscellaneous > ADSI
        NQA-1237 : Verify Advanced scan is saved with Miscellaneous > F5
        NQA-1238 : Verify Advanced scan is saved with Miscellaneous > IBM iSeries
        NQA-1239 : Verify Advanced scan is saved with Miscellaneous > OpenStack
        NQA-1240 : Verify Advanced scan is saved with Miscellaneous > Palo Alto networks PAN-OS
        NQA-1241 : Verify Advanced scan is saved with Miscellaneous > RHEV
        NQA-1242 : Verify Advanced scan is saved with Miscellaneous > VMware ESX SOAP API
        NQA-1243 : Verify Advanced scan is saved with Miscellaneous > VMware vCenter SOAP API

        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials --> Miscellaneous --> Sub Category one by one
        4. Verify form input fields of related subcategories
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()
        misc_page = Miscellaneous.get_misc_inst(misc_type)
        misc_page.fill_form(**form_data)
        misc_page.save_button.click()

        for password in ('domain_pass', 'password'):
            if password in form_data.keys():
                form_data[password] = '********'

        if 'ssl_cert' in form_data.keys() and form_data['ssl_cert'] is None:
            del form_data['ssl_cert']

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        misc_page.open_saved_credentials_component(form_name=misc_type)
        assert misc_page.get_form_values() == form_data, 'Data saved is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    def test_x509_miscellaneous_credential(self, create_policy):
        """
        NQA-1244: Verify Advanced scan is saved with Miscellaneous -> X.509
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials --> Miscellaneous --> X.509
        4. Verify form input fields of related subcategories
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        key_path = os.path.abspath(get_file_path('nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key'))

        policy_name = create_policy
        policy_form = NewPolicyForm()
        misc_page = Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.X509)
        misc_page.fill_form(client_cert=key_path, client_key=key_path, pass_key='p@ssw0rd', ca_cert_path=key_path)
        misc_page.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        misc_page.open_saved_credentials_component(form_name=API.Credentials.Miscellaneous.X509)
        assert "api_pub_key_target_priv_key" in misc_page.client_cert.get_attribute('data-value'), \
            "Uploaded file is not available for Client Certificate"

        assert "api_pub_key_target_priv_key" in misc_page.client_key.get_attribute('data-value'), \
            "Uploaded file is not available for Client Key"

        assert "********" in misc_page.pass_for_key.value, "Password key is incorrect or missing"

        assert "api_pub_key_target_priv_key" in misc_page.ca_cert_to_trust.get_attribute('data-value'), \
            "Uploaded file is not available for CA Certificate to trust"

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)
