"""
Nessus Credentials tab under Policy form related test cases for Cloud Services category.

:copyright: Tenable Network Security, 2018
:date: May 28, 2018
:Modified on: June 19, 2022
:author: @kpanchal, @krpatel
"""
import pytest

from catium.lib.util.util import random_name
from nessus.lib.const import API, Nessus
from nessus.pageobjects.credentials.cloud_services import AmazonAWS, MicrosoftAzure, RackSpace, SalesForce
from nessus.pageobjects.policies.new_policy_form import NewPolicyForm
from nessus.pageobjects.policies.policies_page import PolicyList


@pytest.mark.policies_pipeline_1
@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestCloudServicesCredentialsForm:
    """This class covers Cloud Services credential form related test under new policies."""

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("amazon_aws_form_data", [{'regions_to_access': "China", 'https_switch': False,
                                                       'ssl_certificate': True},
                                                      {'regions_to_access': "GovCloud", 'https_switch': False,
                                                       'ssl_certificate': True, 'us_gov_east_1': True,
                                                       'us_gov_west_1': True},
                                                      {'us_east_1': True, 'us_east_2': True, 'us_west_1': True,
                                                       'us_west_2': True, 'ca_central_1': True, 'eu_west_1': True,
                                                       'eu_west_2': True, 'eu_central_1': True, 'ap_northeast_1': True,
                                                       'ap_northeast_2': True, 'ap_southeast_1': True,
                                                       'ap_southeast_2': True, 'ap_south_1': True, 'sa_east_1': True,
                                                       'regions_to_access': "Rest of the World",
                                                       'https_switch': True, 'ssl_certificate': True}])
    def test_amazon_aws_credential_form(self, create_policies, amazon_aws_form_data):
        """
        NQA-1204 : Verify Advanced scan is saved with Cloud Services > Amazon AWS

        1. Navigate to 'Advanced scan' template from New Policy > Scanner
        2. Give valid name and target
        3. Go to Credentials tab and select Cloud Services > Amazon AWS
        4. Verify following input fields:
        - AWS Access key ID
        - AWS secret key
        Regions to Access:
        - China
        - HTTPS(toggle)
        - Verify SSL(Checkbox) is present if HTTPS toggle is on
        - Rest of the world
        - us-east-1(checkbox)
        - us-east-2(checkbox)
        - us-west-1(checkbox)
        - us-west-2(checkbox)
        - ca-central-1(checkbox)
        - eu-west-1(checkbox)
        - eu-west-2(checkbox)
        - eu-central-1(checkbox)
        - ap-northeast-1(checkbox)
        - ap-northeast-2(checkbox)
        - ap-southeast-1(checkbox)
        - ap-southeast-2(checkbox)
        - ap-south-1(checkbox)
        - sa-east-1(checkbox)
        - us-gov-west-1(checkbox)
        - HTTPS(toggle)
        - Verify SSL(Checkbox) is present if HTTPS toggle is on
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policies[0]
        policy_form = NewPolicyForm()
        amazon_aws_form = AmazonAWS(cloud_type=API.Credentials.CloudServices.Types.AMAZON_AWS)

        assert amazon_aws_form.opened_form_value == API.Credentials.CloudServices.Types.AMAZON_AWS, \
            'Amazon AWS form is not opened.'

        amazon_aws_form.fill_amazon_aws_form(**amazon_aws_form_data, access_key='admin', secret_key='admin')
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(amazon_aws_form.active_credentials) == 1, 'More than 1 credentials are available.'

        amazon_aws_form.open_saved_credentials_component(form_name=API.Credentials.CloudServices.Types.AMAZON_AWS)

        assert amazon_aws_form.get_amazon_aws_data() == amazon_aws_form_data, \
            'Entered data and saved data are different.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize('microsoft_azure_form_data', [{'auth_method': 'Password', 'username': 'admin',
                                                            'password': 'P@ssw0rd', 'application_id': '1234',
                                                            'subscription_id': '1234'},
                                                           {'auth_method': 'Key', 'application_id': '1234',
                                                            'subscription_id': '1234', 'client_secret': 'P@ssw0rd',
                                                            'tenant_id': "1234"}])
    def test_microsoft_azure_credential_form(self, create_policies, microsoft_azure_form_data):
        """
        NQA-1202 : Verify Advanced scan is saved with Cloud Services > Microsoft Azure

        1. Navigate to 'Advanced scan' template from New Policy > Scanner
        2. Give valid name and target
        3. Go to Credentials tab and select Cloud Services > Microsoft Azure
        4. Verify following input fields:
        - Username
        - Password
        - Client Id
        - Subscription Id
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        policy_name = create_policies[0]
        policy_form = NewPolicyForm()
        microsoft_azure_form = MicrosoftAzure(cloud_type=API.Credentials.CloudServices.Types.MICROSOFT_AZURE)

        assert microsoft_azure_form.opened_form_value == API.Credentials.CloudServices.Types.MICROSOFT_AZURE, \
            'Microsoft Azure form is not opened.'
        auth_method = microsoft_azure_form_data['auth_method']
        microsoft_azure_form.fill_microsoft_azure_form(**microsoft_azure_form_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(microsoft_azure_form.active_credentials) == 1, 'More than 1 credentials are available.'

        microsoft_azure_form.open_saved_credentials_component(form_name=API.Credentials.CloudServices.Types.
                                                              MICROSOFT_AZURE)
        if auth_method == "Password":
            microsoft_azure_form_data.update({'password': "*" * len(microsoft_azure_form_data['password'])})
        elif auth_method == "Key":
            microsoft_azure_form_data.update({'client_secret': "*" * len(microsoft_azure_form_data['client_secret'])})
        microsoft_azure_form_data.pop('auth_method')
        assert microsoft_azure_form.get_microsoft_azure_data(auth_method=auth_method) == microsoft_azure_form_data, \
            'Entered data and saved data are different.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    @pytest.mark.parametrize("auth_method", ["API-Key", "Password"])
    def test_rackspace_credential_form(self, create_policies, auth_method):
        """
        NQA-1203 : Verify Advanced scan is saved with Cloud Services > Rackspace

        1. Navigate to 'Advanced scan' template from New Policy > Scanner
        2. Give valid name and target
        3. Go to Credentials tab and select Cloud Services > Rackspace
        4. Verify following input fields:
        - Auth Method
        - Password
        - API KEY
        - Username
        - Password or API Key
        - Dallas Fort Worth (checkbox)
        - Chicago (checkbox)
        - Northen Virginia (checkbox)
        - London (checkbox)
        - Sydney (checkbox)
        - Hongkong (checkbox)
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        rackspace_form_data = {'auth_method': auth_method, 'username': 'admin', 'password': 'P@ssw0rd',
                               'dallas_fort': False, 'chicago_ord': False, 'northen_virginia': False, 'london': False,
                               'sydney': False, 'hongkong': False}

        policy_name = create_policies[0]
        policy_form = NewPolicyForm()

        rackspace_form = RackSpace(cloud_type=API.Credentials.CloudServices.Types.RACKSPACE)

        assert rackspace_form.opened_form_value == API.Credentials.CloudServices.Types.RACKSPACE, \
            'Rackspace form is not opened.'

        rackspace_form.fill_rackspace_form(**rackspace_form_data)
        rackspace_form.auth_method.select_by_visible_text(auth_method)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(rackspace_form.active_credentials) == 1, 'More than 1 credentials are available.'

        rackspace_form.open_saved_credentials_component(form_name=API.Credentials.CloudServices.Types.RACKSPACE)
        rackspace_form_data.update({'password': '********'})

        assert rackspace_form.get_rackspace_data() == rackspace_form_data, \
            'Entered data and saved data are different.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {'template_name': Nessus.TemplateNames.ADVANCED, 'type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         'policy_name': random_name(prefix="Policy of {} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_salesforce_credential_form(self, create_policies):
        """
        NQA-1201 : Verify Advanced scan is saved with Cloud Services > Salesforce.com

        1. Navigate to 'Advanced scan' template from New Policy > Scanner
        2. Give valid name and target
        3. Go to Credentials tab and select Cloud Services > Salesforce.com
        4. Verify following input fields:
        - Username
        - Password
        5. Save the policy
        6. Click on created policy
        7. Verify the values saved are retained
        """
        salesforce_form_data = {'username': 'admin', 'password': 'P@ssw0rd'}

        policy_name = create_policies[0]
        policy_form = NewPolicyForm()

        salesforce_form = SalesForce(cloud_type=API.Credentials.CloudServices.Types.SALESFORCE)

        assert salesforce_form.opened_form_value == API.Credentials.CloudServices.Types.SALESFORCE, \
            'Salesforce.com form is not opened.'

        salesforce_form.fill_sales_force_form(**salesforce_form_data)
        policy_form.save_button.click()

        PolicyList().click_on_policy(policy_name=policy_name)
        policy_form.credentials.click()

        assert len(salesforce_form.active_credentials) == 1, 'More than 1 credentials are available.'

        salesforce_form.open_saved_credentials_component(form_name=API.Credentials.CloudServices.Types.SALESFORCE)
        salesforce_form_data.update({'password': '********'})

        assert salesforce_form.get_sales_force_data() == salesforce_form_data, \
            'Entered data and saved data are different.'
