"""
Nessus Credentials tab under Policy/Scan form related test cases For Host -> Cloud Services

:copyright: Tenable Network Security, 2017
:date: May 2, 2018
:last_modified: July 19, 2018
:author: @ntarwani, @kpanchal
"""
import pytest

from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.credentials.cloud_services import MicrosoftAzure, RackSpace, AmazonAWS, SalesForce
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_home
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestUICredentialsCloudServicesForm:
    """NQA-1115: Advanced Scan > Credentials > Cloud Services related Test Cases"""

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_salesforce_cloud_services_credentials(self, create_scan):
        """
        NQA-1116- Fill form for Advanced Scan > Credentials > Cloud Services > Salesforce
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Cloud Services > SalesForce
        4. Fill the form
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1277: Verify mandatory field validation while edit for Advanced scan with credentials -> cloud services
        Salesforce.com:
            - Repeat steps 1 to 7 from NQA-1116.
            - Under Salesforce.com remove username and hit ‘Save’.
            - Validation message should appear.
        """
        scan_name = create_scan
        sales_force_form = {'username': 'admin', 'password': 'admin'}

        sales_force = SalesForce(cloud_type=API.Credentials.CloudServices.Types.SALESFORCE)
        assert sales_force.opened_form_value == API.Credentials.CloudServices.Types.SALESFORCE, \
            'Salesforce form is not opened.'

        sales_force.fill_sales_force_form(**sales_force_form)
        save_and_configure_scan(class_object=sales_force, scan_name=scan_name)
        assert len(sales_force.active_credentials) == 1, 'More than 1 credentials are available.'

        sales_force.open_saved_credentials_component(form_name=API.Credentials.CloudServices.Types.SALESFORCE)
        sales_force_form.update({'password': '********'})
        assert sales_force.get_sales_force_data() == sales_force_form, 'Data saved is missing or incorrect.'

        assert sales_force.check_required_field_validation(class_instance=sales_force, element='username'), \
            "Error notification for blank 'Username' is missing."

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('microsoft_azure_form_data', [{'auth_method': 'Password', 'username': 'admin',
                                                            'password': 'P@ssw0rd', 'application_id': '1234',
                                                            'subscription_id': '1234'},
                                                           {'auth_method': 'Key', 'application_id': '1234',
                                                            'subscription_id': '1234', 'client_secret': 'P@ssw0rd',
                                                            'tenant_id': "1234"}])
    def test_microsoft_azure_credentials(self, create_scan, microsoft_azure_form_data):
        """
        NQA-1117- Fill form for Advanced Scan > Credentials > Cloud Services > Microsoft Azure
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Cloud Services > Microsoft Azure
        4. Fill the form
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1277: Verify mandatory field validation while edit for Advanced scan with credentials -> cloud services
        Microsoft Azure:
            - Repeat steps 1 to 7 from NQA-1117.
            - Under Microsoft Azure remove Client id and hit ‘Save’.
            - Validation message should appear.
        """
        element = None
        scan_name = create_scan
        microsoft_azure_test_data = microsoft_azure_form_data
        auth_method = microsoft_azure_test_data['auth_method']
        microsoft_azure = MicrosoftAzure(cloud_type=API.Credentials.CloudServices.Types.MICROSOFT_AZURE)

        assert microsoft_azure.opened_form_value == API.Credentials.CloudServices.Types.MICROSOFT_AZURE, \
            'Microsoft Azure form is not opened.'

        microsoft_azure.fill_microsoft_azure_form(**microsoft_azure_test_data)
        save_and_configure_scan(class_object=microsoft_azure, scan_name=scan_name)

        assert len(microsoft_azure.active_credentials) == 1, 'More than one active credential is present.'

        microsoft_azure.open_saved_credentials_component(form_name=API.Credentials.CloudServices.Types.MICROSOFT_AZURE)

        if auth_method == "Key":
            microsoft_azure_test_data.update({'client_secret': "*" * len(microsoft_azure_test_data['client_secret'])})
            microsoft_azure.application_id_for_key = microsoft_azure.application_id[1]
            element = 'application_id_for_key'
        elif auth_method == "Password":
            microsoft_azure_test_data.update({'password': "*" * len(microsoft_azure_test_data['password'])})
            microsoft_azure.application_id_for_password = microsoft_azure.application_id[0]
            element = 'application_id_for_password'

        expected_azure_data = microsoft_azure.get_microsoft_azure_data(auth_method=auth_method)

        for key, value in microsoft_azure_test_data.items():
            if key in list(expected_azure_data.keys()):
                assert microsoft_azure_test_data[key] == expected_azure_data[key], \
                    'Data saved is missing or incorrect "{}" field.'.format(key)

        assert microsoft_azure.check_required_field_validation(class_instance=microsoft_azure, element=element), \
            "Error notification for blank 'Client Id' is missing."

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
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
    def test_amazon_aws_credentials(self, create_scan, amazon_aws_form_data):
        """
        NQA-1119- Fill form for Advanced Scan > Credentials > Cloud Services > Amazon AWS
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Cloud Services > Amazon AWS
        4. Fill the form
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1277: Verify mandatory field validation while edit for Advanced scan with credentials -> cloud services
        Amazon AWS:
            - Repeat steps 1 to 7 from NQA-1119.
            - Under Amazon AWS remove AWS Access key id and hit ‘Save’.
            - Validation message should appear.
        """
        scan_name = create_scan

        amazon_aws = AmazonAWS(cloud_type=API.Credentials.CloudServices.Types.AMAZON_AWS)
        assert amazon_aws.opened_form_value == API.Credentials.CloudServices.Types.AMAZON_AWS, \
            'Amazon AWS form is not opened.'

        amazon_aws.fill_amazon_aws_form(**amazon_aws_form_data, access_key='admin', secret_key='admin')
        save_and_configure_scan(class_object=amazon_aws, scan_name=scan_name)
        assert len(amazon_aws.active_credentials) == 1, 'More than one active credential is present.'

        amazon_aws.open_saved_credentials_component(form_name=API.Credentials.CloudServices.Types.AMAZON_AWS)
        assert amazon_aws.get_amazon_aws_data() == amazon_aws_form_data, 'Data saved is missing or incorrect.'

        assert amazon_aws.check_required_field_validation(class_instance=amazon_aws, element='access_key'), \
            "Error notification for blank 'AWS Access Key ID' is missing."

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize("auth_method", ["API-Key", "Password"])
    def test_rackspace_credentials(self, create_scan, auth_method):
        """
        NQA-1118- Fill form for Advanced Scan > Credentials > Cloud Services >  Rackspace
        1. Navigate to 'Advanced scan' template from scanner tab
        2. Give valid name and target
        3. Go to Credentials tab and select Cloud Services > Rackspace
        4. Fill the form
        5. Save the scan
        6. Click on created scan
        7. Verify the values saved are retained

        NQA-1277: Verify mandatory field validation while edit for Advanced scan with credentials -> cloud services
        RackSpace:
            - Repeat steps 1 to 7 from NQA-1118.
            - Under RackSpace remove Password/API key and hit ‘Save’.
            - Validation message should appear.
        """
        scan_name = create_scan

        rackspace_form_data = {'auth_method': auth_method, 'username': 'admin', 'password': 'admin',
                               'dallas_fort': False, 'chicago_ord': False, 'northen_virginia': False, 'london': False,
                               'sydney': False, 'hongkong': False}

        rackspace = RackSpace(cloud_type=API.Credentials.CloudServices.Types.RACKSPACE)
        assert rackspace.opened_form_value == API.Credentials.CloudServices.Types.RACKSPACE, \
            'Rackspace form is not opened.'

        rackspace.fill_rackspace_form(**rackspace_form_data)
        save_and_configure_scan(class_object=rackspace, scan_name=scan_name)
        assert len(rackspace.active_credentials) == 1, 'More than one credential is present.'

        rackspace.open_saved_credentials_component(form_name=API.Credentials.CloudServices.Types.RACKSPACE)
        rackspace_form_data.update({'password': '********'})
        assert rackspace.get_rackspace_data() == rackspace_form_data, 'Data saved is missing or incorrect.'

        rackspace.password.clear()
        rackspace.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Credentials.password_or_api_key_error, \
            "Error notification for blank 'Password or API Key' is missing."

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
