"""
 Nessus Credentials tab under Policy form related test cases For Host -> Patch Management
:Copyright: Tenable Network Security, 2018
:Date: May 27, 2018
:Modified Date: May 31, 2018
:Author: @jchavda
"""
import pytest

from catium.lib.const import WAIT_SHORT
from nessus.lib.const import API
from nessus.pageobjects.credentials.patch_management import MicrosoftSCCM, DellKaceK1000, PatchManagement, \
    SymantecAltiris
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList
from nessus.pageobjects.shared.loading import LoadingCircle


@pytest.mark.policies_pipeline_1
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestPolicyPatchManagement:
    """
    NQA-1206: Automation tests for New Policy > 'advanced scan' under 'Scanner' tab is saved successfully with
    values given under credentials ->Category 'Patch Management'
    """

    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    def test_dell_kace_credential(self, create_policy):
        """
        NQA-1207: Verify Advanced scan is saved with Patch Management > Dell Kace K1000
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Patch Management > Dell Kace K1000
        4. Fill the form
        5. Save the Policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()
        dell_kace = {'server': '10.10.13.11', 'username': 'admin', 'password': 'admin', 'port': '3301',
                     'org_db_name': 'ORG 1'}
        patch_page = DellKaceK1000(patch_type=API.Credentials.PatchManagement.Types.DELL_KACE)
        LoadingCircle(WAIT_SHORT)
        patch_page.fill_dell_kace_form(**dell_kace)

        assert len(patch_page.active_credentials) == 1, 'More than 1 credentials are available'
        patch_page.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        patch_page.open_saved_credentials_component(form_name=API.Credentials.PatchManagement.Types.DELL_KACE)
        dell_kace.update({'password': '********'})
        assert patch_page.get_dell_kace_form() == dell_kace, 'Data is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    @pytest.mark.parametrize("form_data", [{'form_name': API.Credentials.PatchManagement.Types.REDHAT_SATELLITE6,
                                            'server': '172.26.25.16', 'port': '443', 'username': 'admin',
                                            'password': 'admin',
                                            'https_toggle': True, 'verify_ssl': True},  # NQA-1211
                                           {'form_name': API.Credentials.PatchManagement.Types.REDHAT_SATELLITE6,
                                            'server': '172.26.25.16', 'port': '443',
                                            'username': 'admin', 'password': 'admin',
                                            'https_toggle': True, 'verify_ssl': False},  # NQA-1211
                                           {'form_name': API.Credentials.PatchManagement.Types.REDHAT_SATELLITE6,
                                            'server': '172.26.25.16', 'port': '443',
                                            'username': 'admin', 'password': 'admin',
                                            'https_toggle': False, 'verify_ssl': None},  # NQA-1211
                                           {'form_name': API.Credentials.PatchManagement.Types.IBM_BIGFIX,
                                            'server': '172.26.22.35', 'port': '443',
                                            'username': 'admin', 'password': 'admin',
                                            'https_toggle': True, 'verify_ssl': True},  # NQA-1208
                                           {'form_name': API.Credentials.PatchManagement.Types.IBM_BIGFIX,
                                            'server': '172.26.22.35', 'port': '443',
                                            'username': 'admin', 'password': 'admin',
                                            'https_toggle': True, 'verify_ssl': False},  # NQA-1208
                                           {'form_name': API.Credentials.PatchManagement.Types.IBM_BIGFIX,
                                            'server': '172.26.22.35', 'port': '443',
                                            'username': 'admin', 'password': 'admin',
                                            'https_toggle': False, 'verify_ssl': None},  # NQA-1208
                                           {'form_name': API.Credentials.PatchManagement.Types.MICROSOFT_WSUS,
                                            'server': '172.26.22.35', 'port': '443',
                                            'username': 'admin', 'password': 'admin',
                                            'https_toggle': True, 'verify_ssl': True},  # NQA-1210
                                           {'form_name': API.Credentials.PatchManagement.Types.MICROSOFT_WSUS,
                                            'server': '172.26.22.35', 'port': '443',
                                            'username': 'admin', 'password': 'admin',
                                            'https_toggle': True, 'verify_ssl': False},  # NQA-1210
                                           {'form_name': API.Credentials.PatchManagement.Types.MICROSOFT_WSUS,
                                            'server': '172.26.22.35', 'port': '443',
                                            'username': 'admin', 'password': 'admin',
                                            'https_toggle': False, 'verify_ssl': None},  # NQA-1210
                                           {'form_name': API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5,
                                            'server': '172.26.25.16', 'port': '443',
                                            'username': 'admin', 'password': 'admin', 'https_toggle': None,
                                            'verify_ssl': True},  # NQA-1212
                                           {'form_name': API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5,
                                            'server': '172.26.25.16', 'port': '443',
                                            'username': 'admin', 'password': 'admin', 'https_toggle': None,
                                            'verify_ssl': False}])  # NQA-1212
    def test_ibm_wsus_server_credential(self, create_policy, form_data):
        """
        NQA-1208: Verify Advanced scan is saved with Patch Management > IBM Tivoli Endpoint Manager(BigFix)
        NQA-1210: Verify Advanced scan is saved with Patch Management > Microsoft WSUS
        NQA-1211: Verify Advanced scan is saved with Patch Management > Red Hat Satellite 6 server
        NQA-1212: Verify Advanced scan is saved with Patch Management > Red Hat Satellite 5 server
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Patch Management > Sub category one by one
        4. Fill the form
        5. Save the Policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()
        patch_type = form_data['form_name']

        for element in ['https_toggle', 'verify_ssl']:
            if element in form_data.keys() and form_data[element] is None:
                del form_data[element]

        patch_page = PatchManagement(patch_type=patch_type)
        LoadingCircle(WAIT_SHORT)
        patch_page.fill_red_hat_microsoft_and_ibm_form(**form_data)
        patch_page.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()

        assert len(patch_page.active_credentials) == 1, 'More than 1 credentials are available'

        if patch_type == API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5:
            patch_page.open_saved_credentials_component(
                form_name=API.Credentials.PatchManagement.Types.REDHAT_SATELLITE5_FORM_NAME)
        else:
            patch_page.open_saved_credentials_component(form_name=patch_type)

        form_data.update({'password': '********'})
        assert patch_page.get_red_hat_microsoft_and_ibm_data(patch_type) == form_data, 'Data is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    def test_microsoft_sccm_credential(self, create_policy):
        """
        NQA-1209: Verify Advanced scan is saved with Patch Management > Microsoft SCCM
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Patch Management > Microsoft SCCM
        4. Fill the form
        5. Save the Policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()
        form_data = {'server': '10.10.13.11', 'username': 'admin', 'password': 'admin', 'domain': 'tenable'}

        ms_sccm_page = MicrosoftSCCM(patch_type=API.Credentials.PatchManagement.Types.MICROSOFT_SCCM)
        LoadingCircle(WAIT_SHORT)
        ms_sccm_page.fill_microsoft_sccm_form(**form_data)

        assert len(ms_sccm_page.active_credentials) == 1, 'More than 1 credentials are available'
        ms_sccm_page.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        ms_sccm_page.open_saved_credentials_component(form_name=API.Credentials.PatchManagement.Types.MICROSOFT_SCCM)
        form_data.update({'password': '********'})
        assert ms_sccm_page.get_microsoft_sccm_data() == form_data, 'Data is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_policy", [("Advanced Scan", API.Permissions.Types.SCANNER)], indirect=True)
    def test_symantec_altiris_credential(self, create_policy):
        """
        NQA-1213: Verify Advanced scan is saved with Patch Management > Symantec Altiris
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Patch Management > Symantec Altiris
        4. Fill the form
        5. Save the Policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policy
        policy_form = NewPolicyForm()
        form_data = {'username': 'admin', 'port': '5690', 'db_name': 'Symantec_CMDB',
                     'password': 'admin', 'server': '172.26.25.16', 'use_win_auth': True}

        symantec_page = SymantecAltiris(patch_type=API.Credentials.PatchManagement.Types.SYMANTEC_ALTIRIS)
        LoadingCircle(WAIT_SHORT)
        symantec_page.fill_symantec_altiris_form(**form_data)

        assert len(symantec_page.active_credentials) == 1, 'More than 1 credentials are available'
        symantec_page.save_button.click()

        PolicyList().click_on_policy(policy_name)
        policy_form.credentials.click()
        symantec_page.open_saved_credentials_component(form_name=API.Credentials.PatchManagement.Types.SYMANTEC_ALTIRIS)
        form_data.update({'password': '********'})
        assert symantec_page.get_symantec_form_data() == form_data, 'Data is incorrect or missing'

        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)
