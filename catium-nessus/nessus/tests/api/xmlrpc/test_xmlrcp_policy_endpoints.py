"""
Nessus XML RPC policy Endpoint verification

:copyright: Tenable Network Security, 2018
:date: Jan 11, 2019
:last_modified: Mar 16, 2022
:author: @lambaliya, @kpanchal
"""
from http import HTTPStatus

import pytest


@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home_mat
@pytest.mark.nessus_manager_mat
@pytest.mark.nessus_pro_mat
@pytest.mark.usefixtures('nessus_xmlrpc_api_login')
class TestXmlrpcPolicyEndpoint:
    """STA-100: Implement test cases for xmlrpc policy endpoints"""

    cat = None
    test_params = {'policy_name': 'xml_rpc_policy-test'}

    # API_Tested# POST xmlrpc/policy/add
    @pytest.mark.parametrize('test_params', (test_params,))
    @pytest.mark.parametrize('add_xmlrpc_policy', (test_params,), indirect=True)
    def test_add_xmlrpc_policy(self, add_xmlrpc_policy, test_params):
        """
        STA-100: Implement test cases for xmlrpc policy endpoints xmlrpc/policy/add

        Scenarios tested:
            [x] Successfully add policy
        """
        policy_root = add_xmlrpc_policy

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        policy_name_element = policy_root.find("./contents/policy/policyName")

        assert policy_name_element is not None, "reply/contents/policy/policyName element not found"

        assert policy_name_element.text == test_params['policy_name'], "Name of created policy not fond"

    # API_Tested# POST xmlrpc/policy/delete
    @pytest.mark.parametrize('policy_ids', ['123', '32,34,54'])
    def test_delete_xmlrpc_policy(self, nessus_xmlrpc_api_login, policy_ids):
        """
        STA-100: Implement test cases for xmlrpc policy endpoints xmlrpc/policy/delete

        Scenarios tested:
            [x] Successfully delete policy
        """
        api = nessus_xmlrpc_api_login
        policy_root = api.xmlrpc.delete_policy(policy_ids)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        policy_id_ele = policy_root.findall("./contents/policyID")

        assert policy_id_ele is not None, "policyID element not found"

        # compare passed policy ids and received policy ids from delete response
        assert [ele.text for ele in policy_root.findall("./contents/policyID")] == policy_ids.split(","), \
            "Deleted policy ID is not returned in xml response"
