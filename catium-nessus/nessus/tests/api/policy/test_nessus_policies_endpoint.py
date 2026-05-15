"""
Nessus Policy Endpoint verification

Test cases for Create Policy, Import Policy,
Copy Policy, Configure Policy,
Delete Policy

:copyright: Tenable Network Security, 2017
:date: May 21, 2017
:last_modified: May 13, 2021
:author: @sshah, @jchavda, @dkothari, @kpanchal
"""

import tempfile
from http import HTTPStatus

import pytest
import requests

from catium.helpers.testdata import get_file_path
from catium.lib.util import random_name
from catium.lib.util.util import random_string
from nessus.helpers.policy import create_policy_helper


@pytest.mark.extended_smoke
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusPolicyEndpoint:
    """Tests for Nessus policy Endpoint"""

    cat = None

    @pytest.mark.parametrize('create_policy', [
        pytest.param({"template_name": "advanced"}, marks=(
                pytest.mark.nessus_mat, pytest.mark.nessus_pro, pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                pytest.mark.nessus_home)),  # NQA-573,
        pytest.param({"template_name": "cloud_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-574
        pytest.param({"template_name": "basic"}, marks=(
                pytest.mark.nessus_mat, pytest.mark.nessus_pro, pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                pytest.mark.nessus_home)),  # NQA-577,
        pytest.param({"template_name": "patch_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-578,
        pytest.param({"template_name": "discovery"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                            pytest.mark.nessus_expert)),  # NQA-480,
        pytest.param({"template_name": "pci"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-581,
        pytest.param({"template_name": "malware"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert)),  # NQA-582,
        {"template_name": "mdm"},  # NQA-583,
        {"template_name": "mobile"},  # NQA-584,
        pytest.param({"template_name": "offline"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert)),  # NQA-585,
        pytest.param({"template_name": "asv"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-586,
        {"template_name": "compliance"},  # NQA-587,
        pytest.param({"template_name": "scap"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                       pytest.mark.nessus_expert)),  # NQA-590,
        pytest.param({"template_name": "webapp"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                         pytest.mark.nessus_expert)),  # NQA-591,
        pytest.param({"template_name": "agent_advanced"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-592,
        pytest.param({"template_name": "agent_basic"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager_mat)), # NQA-593,
        {"template_name": "agent_malware"},  # NQA-594,
        {"template_name": "agent_compliance"},  # NQA-595,
        {"template_name": "agent_scap"}
    ], indirect=True)
    # API_Tested# POST /policies/{policy_id}/copy
    def test_copy_policy(self, create_policy):
        """
        Copies a policy.

        Scenarios tested:
            [x] Test copying a policy is successful
            [] Test copying a policy that does not exist fails
        """
        copy = self.cat.api.policies.copy(create_policy['policy_id'])
        copy_id = copy['id']
        get_policies = self.cat.api.policies.get_policies()
        policies = get_policies['policies']

        assert copy_id in [policy['id'] for policy in policies], 'Failed to copy policy'

        self.cat.api.policies.delete(copy_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.nessus_smoke
    @pytest.mark.parametrize('create_policy', [
        pytest.param({"template_name": "basic"}, marks=(
                pytest.mark.nessus_mat, pytest.mark.nessus_pro, pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                pytest.mark.nessus_home)),  # NQA-453,
        pytest.param({"template_name": "advanced"}, marks=(
                pytest.mark.nessus_mat, pytest.mark.nessus_pro, pytest.mark.nessus_manager, pytest.mark.nessus_expert,
                pytest.mark.nessus_home)),  # NQA-449,
        pytest.param({"template_name": "cloud_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-450
        pytest.param({"template_name": "webapp"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                         pytest.mark.nessus_expert)),  # NQA-467,
        {"template_name": "agent_advanced"},  # NQA-468,
        pytest.param({"template_name": "discovery"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                            pytest.mark.nessus_expert)),  # NQA-456,
        pytest.param({"template_name": "agent_basic"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-469,
        pytest.param({"template_name": "asv"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-462,
        pytest.param({"template_name": "pci"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-457,
        pytest.param({"template_name": "malware"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert)),  # NQA-458,
        {"template_name": "agent_malware"},  # #NQA-470,
        {"template_name": "mdm"},  # NQA-459,
        pytest.param({"template_name": "patch_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-454,
        {"template_name": "mobile"},  # NQA-460,
        {"template_name": "compliance"},  # NQA-463,
        {"template_name": "agent_compliance"},  # NQA-471,
        pytest.param({"template_name": "scap"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                       pytest.mark.nessus_expert)),  # NQA-466,
        {"template_name": "agent_scap"},  # NQA-472,
        pytest.param({"template_name": "offline"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert))
    ], indirect=True)
    # API_Tested# POST /policies/
    def test_create_policy(self, create_policy):
        """
        Creates a policy.

        Scenarios tested:
            [x] Test creating a policy successfully
            [] Test creating policies that are invalid
        """
        policy_id = create_policy['policy_id']
        policies = self.cat.api.policies.get_policies()['policies']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert policy_id in [policy['id'] for policy in policies], 'Failed to create policy'

    @pytest.mark.parametrize('policies', [
        pytest.param('nessus_policy_advanced_scan_policy.nessus', marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
            pytest.mark.nessus_manager, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-521
        'nessus_policy_host_discovery_policy.nessus',  # NQA-528, #NQA-537
        'nessus_policy_internal_pci_Network_scan_policy.nessus',  # NQA-529
        'nessus_policy_web_application_test_policy.nessus',  # NQA-539
        pytest.param('nessus_policy_advanced_agent_scan_policy.nessus', marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),
        # NQA-540
        pytest.param('nessus_policy_basic_agent_scan_policy.nessus', marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-541
        'nessus_policy_malware_scan_agent_policy.nessus',  # NQA-542
        'nessus_policy_policy_compliance_auditing_agent_policy.nessus',  # NQA-543
        pytest.param('nessus_policy_basic_network_scan_policy.nessus', marks=(pytest.mark.nessus_mat,
            pytest.mark.nessus_pro, pytest.mark.nessus_expert, pytest.mark.nessus_manager, pytest.mark.nessus_home)),  # NQA-525
        'nessus_policy_audit_cloud_infrastructure_policy.nessus',  # NQA-522
        'nessus_policy_credentialed_patch_audit.nessus',  # NQA-526
        'nessus_policy_malware_scan_policy.nessus',  # NQA-530
        'nessus_policy_mdm_config_audit_policy.nessus',  # NQA-531
        'nessus_policy_mobile_device_scan_policy.nessus',  # NQA-532
        'nessus_policy_pci_quarterly_external_scan_policy.nessus',  # NQA-534
        'nessus_policy_intel_amt_security_bypass_policy.nessus',  # NQA-600
        'nessus_policy_wannacry_ransomware.nessus',  # NQA-606
        'nessus_policy_offline_config_audit_policy.nessus',  # NQA-533
        pytest.param('nessus_policy_policy_compliance_auditing_policy.nessus', marks=(pytest.mark.nessus_mat,
            pytest.mark.nessus_manager, pytest.mark.nessus_pro, pytest.mark.nessus_expert))])  # NQA-535
    # API_Tested# POST /policies/import/{file}
    def test_import_policy(self, policies):
        """
        Test import policies
        :param policies: policy file to be uploaded
        :return: Returns the policy object.

        Scenarios tested:
            [x] Test importing policies successfully
            [] Test importing an invalid policy (e.g. a nessus with invalid XML)

        """
        file = get_file_path('nessus/tests/api/policy/test_data/' + policies)

        fileuploaded = self.cat.api.file.upload(file=file)
        response = self.cat.api.policies.import_policy(file=fileuploaded)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        self.cat.api.policies.delete(response['id'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('policies', ['nessus_policy_scap_and_oval_auditing_policy.nessus',  # NQA-538
                                          'nessus_policy_scap_and_oval_agent_auditing_policy.nessus'])  # NQA-544
    # API_Tested# POST /policies/import/{file}
    def test_import_policy_scap(self, policies):
        """
        Test import policies
        :param policies: policy file to be uploaded
        :return:

        Scenarios Tested:
            [x] Test uploading policy file successfully that includes SCAP
            [] Test uploading a non-existent policy fails
        """

        file = get_file_path('nessus/tests/api/policy/test_data/' + policies)
        fileuploaded = self.cat.api.file.upload(file=file)

        try:
            self.cat.api.policies.import_policy(file=fileuploaded)
        except requests.HTTPError:
            pass

        assert self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR, \
            'Expected Internal Server Error, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.parametrize('create_policy', [
        pytest.param({"template_name": "advanced"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
            pytest.mark.nessus_manager, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-545,
        pytest.param({"template_name": "cloud_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-546
        pytest.param({"template_name": "basic"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
            pytest.mark.nessus_manager, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-549,
        pytest.param({"template_name": "patch_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-550,
        pytest.param({"template_name": "discovery"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                            pytest.mark.nessus_expert)),  # NQA-452,
        pytest.param({"template_name": "pci"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-553,
        pytest.param({"template_name": "malware"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert)),  # NQA-554,
        {"template_name": "mdm"},  # NQA-555,
        pytest.param({"template_name": "offline"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert)),  # NQA-557,
        pytest.param({"template_name": "asv"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-558,
        {"template_name": "compliance"},  # NQA-559,
        pytest.param({"template_name": "discovery"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                            pytest.mark.nessus_expert)),  # NQA-561,
        pytest.param({"template_name": "scap"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                       pytest.mark.nessus_expert)),  # NQA-562,
        pytest.param({"template_name": "webapp"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                         pytest.mark.nessus_expert)),  # NQA-563,
        pytest.param({"template_name": "agent_advanced"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-564,
        pytest.param({"template_name": "agent_basic"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-565,
        {"template_name": "agent_malware"},  # NQA-466,
        {"template_name": "agent_compliance"},  # NQA-467,
        {"template_name": "agent_scap"},  # NQA-468,
        {"template_name": "mobile"},  # NQA-556,
    ], indirect=True)
    # API_Tested# DELETE /policies/{policy_id}
    def test_delete_policy(self, create_policy):
        """
        Verifies policy can be deleted"
        :param create_policy: create policy fixture object and after that, policy_id used to delete used to delete
        policy.
        :return: Returned if the server deleted the policy.

        Scenarios Tested:
            [x] Test creating a policy fixture object, delete that policy using its id, and delete successfully
            [] Test deleting a policy that does not exist
        """
        policy_id = create_policy['policy_id']
        self.cat.api.policies.delete(policy_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.parametrize('create_policy', [
        pytest.param({"template_name": "basic"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
            pytest.mark.nessus_manager, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-501,
        pytest.param({"template_name": "advanced"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
            pytest.mark.nessus_manager, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-497,
        pytest.param({"template_name": "cloud_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-498
        pytest.param({"template_name": "webapp"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                         pytest.mark.nessus_expert)),  # NQA-515,
        pytest.param({"template_name": "agent_advanced"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-516,
        pytest.param({"template_name": "discovery"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                            pytest.mark.nessus_expert)),  # NQA-504,
        pytest.param({"template_name": "agent_basic"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-517,
        pytest.param({"template_name": "malware"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert)),  # NQA-506,
        pytest.param({"template_name": "patch_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-502,
        {"template_name": "mobile"},  # NQA-508,
        {"template_name": "compliance"},  # NQA-511,
        pytest.param({"template_name": "asv"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-510,
        pytest.param({"template_name": "pci"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-505,
        {"template_name": "agent_malware"},  # #NQA-518,
        {"template_name": "mdm"},  # NQA-507,
        {"template_name": "agent_compliance"},  # NQA-519,
        pytest.param({"template_name": "scap"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                       pytest.mark.nessus_expert)),  # NQA-514,
        {"template_name": "agent_scap"},  # NQA-520,
        pytest.param({"template_name": "offline"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert))], indirect=True)
    # API_Tested# GET /policies/{policy_id}/export
    def test_export_policy(self, create_policy):
        """
        Verifies policies can be exported
        :param create_policy: create policy fixture object and policy_id is used in export.
        :return: Returns the policy in nessus format.

        Scenarios tested:
            [x] Test exporting a policy successfully using a policy_id
            [] Test exporting a policy that does not exist
        """
        policy_id = create_policy['policy_id']
        self.cat.api.policies.export(policy_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.parametrize('create_policy', [
        pytest.param({"template_name": "basic"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
            pytest.mark.nessus_manager, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-477,
        pytest.param({"template_name": "advanced"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
            pytest.mark.nessus_manager, pytest.mark.nessus_expert, pytest.mark.nessus_home)),  # NQA-473,
        pytest.param({"template_name": "cloud_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-747
        pytest.param({"template_name": "webapp"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                         pytest.mark.nessus_expert)),  # NQA-491,
        {"template_name": "agent_advanced"},  # NQA-492,
        pytest.param({"template_name": "discovery"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                            pytest.mark.nessus_expert)),  # NQA-480,
        pytest.param({"template_name": "agent_basic"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-493,
        pytest.param({"template_name": "asv"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-486,
        pytest.param({"template_name": "pci"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),  # NQA-481,
        pytest.param({"template_name": "malware"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert)),  # NQA-482,
        {"template_name": "agent_malware"},  # #NQA-494,
        {"template_name": "mdm"},  # NQA-483,
        pytest.param({"template_name": "patch_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),  # NQA-478,
        {"template_name": "mobile"},  # NQA-484,
        {"template_name": "compliance"},  # NQA-487,
        {"template_name": "agent_compliance"},  # NQA-495,
        pytest.param({"template_name": "scap"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                       pytest.mark.nessus_expert)),  # NQA-490,
        pytest.param({"template_name": "agent_scap"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_manager)),  # NQA-496,
        pytest.param({"template_name": "offline"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert))], indirect=True)
    # API_Tested# PUT /policies/{policy_id}
    def test_configure_policy(self, create_policy):
        """
        Verifies existing policy can be edited by policy name.
        :param create_policy: create policy fixture object and further policy_id, payload passed in configuring policy.
        :return: Returns success response if policy configuration was changed by policy name.

        Scenarios tested:
            [x] Tests existing policy can be edited by policy name
            [] Tests editing a policy that does not exist fails

        """
        policy_new_name = random_name(prefix='update-policy-')
        payload = {"settings": {"name": policy_new_name}}
        self.cat.api.policies.configure(create_policy['policy_id'], payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        act_policy_name = self.cat.api.policies.details(create_policy['policy_id'])['settings']['name']

        assert act_policy_name == policy_new_name, \
            'Expected %s, got %s instead.' % (policy_new_name, act_policy_name)

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    # API_Tested# POST /policies/
    def test_create_multiple_policy(self, get_policy_templates):
        """

        Scenarios tested:
            [x] Tests that creating two policies with the same name will append a value to the second policy
        """

        policy1_detail = create_policy_helper(self.cat.api, get_policy_templates, policy_type="basic",
                                              policy_name='Policy_test')
        policy2_detail = create_policy_helper(self.cat.api, get_policy_templates, policy_type="basic",
                                              policy_name='Policy_test')

        assert policy1_detail['policy_name'] != policy2_detail['policy_name'], 'Both Policies have same name'

        self.cat.api.policies.delete(policy1_detail['policy_id'])
        self.cat.api.policies.delete(policy2_detail['policy_id'])

    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    # /policies:DELETE
    def test_bulk_delete_policy(self, get_policy_templates):
        """
        STA-27: Create additional tests for Policies.
        Verifies that multiple policies can be deleted.

        Scenarios tested:
            [x] Test that multiple policies can be deleted
            [] Test a single policy can be deleted
            [] Test attempting to delete an undefined policy fails
        """
        for policy in ('basic', 'advanced', 'cloud_audit', 'webapp', 'malware'):
            policy_name = random_name(prefix="New-policy {} -".format(policy))
            create_policy_helper(self.cat.api, get_policy_templates, policy_type=policy, policy_name=policy_name)

        get_policies = self.cat.api.policies.get_policies()['policies']
        policy_ids = [policy['id'] for policy in get_policies]
        self.cat.api.policies.bulk_delete(id_list=policy_ids)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Get list of policies in container
        policies = self.cat.api.policies.get_policies()['policies']
        if policies:
            assert policy_ids not in [policy['id'] for policy in policies], 'Failed to delete policy'
        else:
            assert policies is None, 'Failed to delete policy'

    # API_Tested# GET /policies/{policy_id}/export/prepare
    @pytest.mark.parametrize('create_policy', [
        pytest.param({"template_name": "basic"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                        pytest.mark.nessus_manager, pytest.mark.nessus_expert)),
        pytest.param({"template_name": "advanced"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                           pytest.mark.nessus_manager, pytest.mark.nessus_expert)),
        pytest.param({"template_name": "cloud_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),
        pytest.param({"template_name": "webapp"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                         pytest.mark.nessus_expert)),
        {"template_name": "agent_advanced"},
        pytest.param({"template_name": "discovery"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                            pytest.mark.nessus_expert)),
        {"template_name": "agent_basic"},
        pytest.param({"template_name": "asv"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                      pytest.mark.nessus_expert)),
        pytest.param({"template_name": "pci"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                      pytest.mark.nessus_manager, pytest.mark.nessus_expert)),
        pytest.param({"template_name": "malware"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert)),
        {"template_name": "agent_malware"},
        {"template_name": "mdm"},
        pytest.param({"template_name": "patch_audit"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                              pytest.mark.nessus_expert)),
        {"template_name": "mobile"},
        {"template_name": "compliance"},
        {"template_name": "agent_compliance"},
        pytest.param({"template_name": "scap"}, marks=(pytest.mark.nessus_mat, pytest.mark.nessus_pro,
                                                       pytest.mark.nessus_manager, pytest.mark.nessus_expert)),
        {"template_name": "agent_scap"},
        pytest.param({"template_name": "offline"}, marks=(pytest.mark.nessus_pro, pytest.mark.nessus_manager,
                                                          pytest.mark.nessus_expert))], indirect=True)
    def test_prepare_export_policy(self, create_policy):
        """
        STA-27: Create additional tests for Policies.
        Verifies that policy detail can be exported for specific policy id.

        Scenarios tested:
            [x] Tests that policy can be prepared for export
        """
        policy_id = create_policy['policy_id']
        self.cat.api.policies.prepare_export(policy_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.parametrize('create_policy', [
        pytest.param({"template_name": "advanced"}, marks=pytest.mark.nessus_pro), {"template_name": "agent_advanced"}],
                             indirect=True)
    def test_export_import_preserves_plugins(self, create_policy):
        """
        CS-28340: Verify that plugin selection is maintained when exporting/importing advanced agent policy.

        Scenarios tested:
        [x] modify plugin selection
        [x] export and import a policy and test that plugin selection was preserved
        """
        policy_id = create_policy['policy_id']

        # disable all 'Backdoors' plugins, enable one plugin in 'RPC'
        payload = {
            "plugins": {
                "Backdoors": {"status": "disabled"},
                "RPC": {
                    "status": "mixed",
                    "individual": {
                        "53333": "enabled",
                        "53334": "disabled"
                    },
                    "mixedDefault": "disabled"
                }
            }
        }
        self.cat.api.policies.configure(policy_id, payload)

        def check_plugins(when):
            plugins = self.cat.api.policies.details(policy_id)['plugins']

            assert plugins['CGI abuses']['status'] in ['enabled', 'mixed'], \
                'unrelated plugin family is disabled %s' % when

            assert plugins['Backdoors']['status'] == 'disabled', \
                "plugin family wasn't disabled %s" % when

            assert plugins['RPC']['status'] in ['mixed'], \
                "plugin family wasn't set to mixed %s" % when

            assert plugins['RPC']['individual']['53333'] == 'enabled', \
                "individual plugin wasn't enabled %s" % when

            assert '53334' not in plugins['RPC']['individual'], \
                "individual plugin doesn't seem to have been disabled %s.  status: %s" % (
                    when, plugins['RPC']['individual']['53334'])

        # sanity check
        check_plugins('before export/import')

        # export (to a string)
        exported = self.cat.api.policies.export(policy_id)

        # import the exported data
        with tempfile.NamedTemporaryFile(mode='w') as f:
            f.write(exported)
            f.flush()
            fileuploaded = self.cat.api.file.upload(file=f.name)
        response = self.cat.api.policies.import_policy(file=fileuploaded)
        new_policy_id = response['id']

        # check that enabled/disabled was preserved
        check_plugins('after export/import')

        # clean up
        self.cat.api.policies.delete(new_policy_id)

    @pytest.mark.parametrize('create_policy', [{"template_name": "advanced"}, {"template_name": "basic"},
                                               {"template_name": "advanced_dynamic"}, {"template_name": "malware"},
                                               {"template_name": "patch_audit"}])
    @pytest.mark.parametrize('credential_type', ['SSH', 'Windows'])
    def test_edit_credentials_in_created_scan_policy(self, create_policy, credential_type):
        """
        NES-12208: [API] Edit/delete credentials in the scan policy [SSH, Windows, SSH key]

        Scenarios tested:
        [x] Verify credentials details can be edited successfully from created scan policy.
        """
        data_value = {}
        policy_id = None
        policy_uuid = None
        data_list_to_be_verify = ['username', 'password', 'edited_username', 'edited_password']

        for data_item in data_list_to_be_verify:
            data_value[data_item] = random_string()

        policy_name = random_name(prefix=create_policy["template_name"] + " scan policy-")

        try:
            templates = self.cat.api.editor.get_templates('policy')['templates']

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            for template in templates:
                if create_policy["template_name"] == template['name']:
                    policy_uuid = template['uuid']
                    break

            credential_type_details = {
                'Windows': [{'auth_method': "Password", 'username': data_value["username"],
                             'password': data_value["password"]}],
                'SSH': [{"auth_method": "password", "custom_password_prompt": "", "elevate_privileges_with": "Nothing",
                         "password": data_value["password"], "username": data_value["username"]}]}

            credential_data = {'add': {'Host': {credential_type: credential_type_details[credential_type]}}}
            policy_data = {'uuid': policy_uuid, 'settings': {"name": policy_name}, 'credentials': credential_data}

            policy_id = self.cat.api.policies.create(payload=policy_data)['policy_id']

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            policy_details = self.cat.api.policies.details(policy_id=policy_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert policy_details['credentials']['edit'][str(policy_id + 1)]['username'] == data_value[
                'username'], "Failed to create scan policy with credential data."

            credential_type_details[credential_type][0]['username'] = data_value["edited_username"]
            credential_type_details[credential_type][0]['password'] = data_value["edited_password"]
            credential_data = {'edit': {policy_id + 1: credential_type_details[credential_type][0]}}

            self.cat.api.policies.configure(policy_id=policy_id, payload={'credentials': credential_data})

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            policy_details = self.cat.api.policies.details(policy_id=policy_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert policy_details['credentials']['edit'][str(policy_id + 1)]['username'] == data_value[
                'edited_username'], "Failed to edit created scan policy with credential data."
        finally:
            self.cat.api.policies.delete(policy_id=policy_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

    @pytest.mark.parametrize('create_policy', [{"template_name": "advanced"}, {"template_name": "basic"},
                                               {"template_name": "advanced_dynamic"}])
    @pytest.mark.parametrize('credential_type', ['SSH', 'Windows'])
    def test_delete_credentials_from_created_scan_policy(self, create_policy, credential_type):
        """
        NES-12208: [API] Edit/delete credentials in the scan policy [SSH, Windows, SSH key]

        Scenarios tested:
        [x] Verify credentials details can be deleted successfully from created scan policy.
        """
        data_value = {}
        policy_id = None
        policy_uuid = None
        data_list_to_be_verify = ['username', 'password']

        for data_item in data_list_to_be_verify:
            data_value[data_item] = random_string()

        policy_name = random_name(prefix=create_policy["template_name"] + " scan policy-")

        try:
            templates = self.cat.api.editor.get_templates('policy')['templates']

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            for template in templates:
                if create_policy["template_name"] == template['name']:
                    policy_uuid = template['uuid']
                    break

            credential_type_details = {
                'Windows': [{'auth_method': "Password", 'username': data_value["username"],
                             'password': data_value["password"]}],
                'SSH': [{"auth_method": "password", "custom_password_prompt": "", "elevate_privileges_with": "Nothing",
                         "password": data_value["password"], "username": data_value["username"]}]}

            credential_data = {'add': {'Host': {credential_type: credential_type_details[credential_type]}}}
            policy_data = {'uuid': policy_uuid, 'settings': {"name": policy_name}, 'credentials': credential_data}

            policy_id = self.cat.api.policies.create(payload=policy_data)['policy_id']

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            policy_details = self.cat.api.policies.details(policy_id=policy_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert policy_details['credentials']['edit'][str(policy_id + 1)]['username'] == data_value[
                'username'], "Failed to create scan policy with credential data."

            self.cat.api.policies.configure(policy_id=policy_id, payload={'credentials': {'delete': [policy_id + 1]}})

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            policy_details = self.cat.api.policies.details(policy_id=policy_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert 'credentials' not in policy_details, "Failed to delete credentials from created scan policy."
        finally:
            self.cat.api.policies.delete(policy_id=policy_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code
