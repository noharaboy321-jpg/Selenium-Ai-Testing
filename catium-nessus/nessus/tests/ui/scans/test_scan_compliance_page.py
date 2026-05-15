"""
Nessus compliance tab under Scan form related test cases
:copyright: Tenable Network Security, 2017
:date: June 04, 2018
:last_modified: March 29, 2024
:author: @mameta, @kpanchal, @krpatel
"""
import os

import pytest

from catium.helpers.testdata import get_file_path, load_testdata
from catium.lib.const import WAIT_SHORT
from nessus.helpers.scan import save_and_configure_scan
from nessus.lib.const import API, Nessus
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.credentials.cloud_services import AmazonAWS, MicrosoftAzure, RackSpace, SalesForce
from nessus.pageobjects.credentials.database import Database
from nessus.pageobjects.credentials.host import PublicKey, Password
from nessus.pageobjects.credentials.miscellaneous import Miscellaneous
from nessus.pageobjects.credentials.mobile_credential import AppleProfileManager
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.usefixtures('login')
class TestUIComplianceForm:
    """NQA-1269: Verify 'advanced scan' is saved successfully with values given under compliance tab"""
    key_path = os.path.abspath(get_file_path("nessus/tests/api/plugins/test_data/api_pub_key_target_priv_key"))

    compliance_type = load_testdata('nessus/tests/ui/test_data/compliance_data.json')
    for key in compliance_type:
        if 'config_file' in compliance_type[key].keys():
            compliance_type[key]["config_file"] = key_path

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [
        {'compliance_type': "TNS Alcatel-Lucent TiMOS/Nokia SR-OS Best Practice Audit", 'data': compliance_type[
            "alcatel_timos_data"], 'form_name': ComplianceConst.ALCATEL},
        {'compliance_type': "DISA STIG Arista MLS DCS-7000 Series L2S v1r3", 'data': compliance_type["arista_eos_data"],
         'form_name': ComplianceConst.ARISTA},
        pytest.param({'compliance_type': "TNS BlueCoat ProxySG Benchmark", 'data': compliance_type[
            "bluecoat_proxysg_data"], 'form_name': ComplianceConst.BLUECOAT_PROXYSG}, marks=pytest.mark.xfail(
            reason="'TNS BlueCoat ProxySG Benchmark' compliance type is not present under 'BlueCoat ProxySG' "
                   "compliance category.")),
        {'compliance_type': "Tenable Best Practices Brocade FabricOS", 'data': compliance_type[
            "brocade_fabric_os_data"], 'form_name': ComplianceConst.BROCADE_FABRICOS},
        {'compliance_type': "CIS Cisco Firewall v8.x L1 v4.2.0", 'data': compliance_type["cisco_data"],
         'form_name': ComplianceConst.CISCO},
        {'compliance_type': "TNS Extreme ExtremeXOS Best Practice Audit", 'data': compliance_type["extreme_data"],
         'form_name': ComplianceConst.EXTREME_EXTREMEXOS},
        {'compliance_type': "TNS FireEye", 'data': compliance_type["fireeye_data"],
         'form_name': ComplianceConst.FIREEYE},
        {'compliance_type': "TNS Fortigate FortiOS Best Practices", 'data': compliance_type["fortigate_data"],
         'form_name': ComplianceConst.FORTIGATE_FORTIOS},
        {'compliance_type': "TNS HP ProCurve", 'data': compliance_type["hp_procurve_data"],
         'form_name': ComplianceConst.HP_PROCURVE},
        {'compliance_type': "TNS Huawei VRP Best Practice Audit", 'data': compliance_type["huawei_data"],
         'form_name': ComplianceConst.HUAWEI_VRP},
        {'compliance_type': "CIS Juniper OS Benchmark v2.1.0 L1", 'data': compliance_type["juniper_data"],
         'form_name': ComplianceConst.JUNIPER_OS},
        {'compliance_type': "TNS NetApp Data ONTAP 7G", 'data': compliance_type["net_app_data"],
         'form_name': ComplianceConst.NETAPP_DATA_ONTAP},
        {'compliance_type': "TNS SonicWALL v5.9", 'data': compliance_type["sonicwall_data"],
         'form_name': ComplianceConst.SONICWALL},
        {'compliance_type': "TNS Best Practice WatchGuard Audit 1.0.0", 'data': compliance_type["watchguard_data"],
         'form_name': ComplianceConst.WATCHGUARD}])
    def test_scan_compliance_page(self, create_scan, input_fields):
        """ Verify 'advanced scan' is saved successfully with values given under compliance tab
            and values should be retained"""
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])

        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)

        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"

        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])
        input_fields['data']['config_file'] = "api_pub_key_target_priv_key"

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "CIS Amazon Web Services Foundations v5.0.0 L1",
                                               'data': compliance_type["amazon_data"],
                                               'form_name': ComplianceConst.AMAZON}])
    def test_amazon_compliance(self, create_scan, input_fields):
        """ Verify 'advanced scan' is saved successfully with values given under
            CIS Amazon Web Services Foundations Audit compliance and values should be retained"""
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)
        amazon_aws_form_data = {'regions_to_access': "China", 'https_switch': False, 'ssl_certificate': True}

        amazon_aws = AmazonAWS(cloud_type=API.Credentials.CloudServices.Types.AMAZON_AWS)
        LoadingCircle(WAIT_SHORT)
        amazon_aws.fill_amazon_aws_form(**amazon_aws_form_data, access_key='admin', secret_key='admin')

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "CIS MySQL 5.6 Enterprise Database L2 v2.0.0",
                                               'data': compliance_type["mysql_database_data"],
                                               'form_name': ComplianceConst.MYSQL}])
    def test_mysql_database_compliance(self, create_scan, input_fields):
        """ Verify 'advanced scan' is saved successfully with values given under
            CIS MySQL 5.6 Enterprise Database L2 v2.0.0 compliance and values should be retained  """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)
        database = Database(host_type=API.Credentials.Types.CATEGORY_DATABASE)

        database_form = {'port': '5432', "database_type": "MySQL"}
        database.fill_db2_or_postgresql_or_mysql_form(**database_form)

        password_form_data = {'authentication_type': 'Password', 'username': 'root', 'password': 'admin'}
        database.fill_password_database_form(**password_form_data)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)

        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"

        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "DISA F5 BIG-IP Local Traffic Manager STIG v2r4",
                                               'data': compliance_type["f_five_data"],
                                               'form_name': ComplianceConst.F_FIVE}])
    def test_f_five_compliance(self, create_scan, input_fields):
        """ Verify 'advanced scan' is saved successfully with values given under
            DISA F5 BIG-IP Local Traffic Manager STIG v2r4 compliance and values should be retained """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)

        f_five_credential_data = {'user_name': 'admin', 'port': 4445, 'https': True,
                                  'ssl_cert': True, 'password': 'p@ssw0rd'}
        misc_inst = Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.F5)
        misc_inst.fill_form(**f_five_credential_data)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "IBM System i Security Reference for V7R2",
                                               'data': compliance_type["ibm_iseries_data"],
                                               'form_name': ComplianceConst.IBM}])
    def test_ibm_iseries_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
            IBM System i Security Reference for V7R2 compliance and values should be retained """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)
        ibm_iseries_data = {'user_name': 'admin', 'password': 'p@ssw0rd'}
        misc_inst = Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.IBM_SERIES)
        misc_inst.fill_form(**ibm_iseries_data)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "CIS Microsoft 365 Foundations v5.0.0 L2 E5",
                                               'data': compliance_type["microsoft_azure_data"],
                                               'form_name': "Microsoft 365 Foundations"}])
    @pytest.mark.parametrize('microsoft_azure_form_data', [{'auth_method': 'Password', 'username': 'admin',
                                                            'password': 'P@ssw0rd', 'application_id': '1234',
                                                            'subscription_id': '1234'},
                                                           {'auth_method': 'Key', 'application_id': '1234',
                                                            'subscription_id': '1234', 'client_secret': 'P@ssw0rd',
                                                            'tenant_id': "1234"}])
    def test_microsoft_azure_compliance(self, create_scan, input_fields, microsoft_azure_form_data):
        """Verify 'advanced scan' is saved successfully with values given under
            TNS Microsoft Azure Best Practices Audit v1.0 compliance and values should be retained """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)
        microsoft_azure = MicrosoftAzure(cloud_type=API.Credentials.CloudServices.Types.MICROSOFT_AZURE)
        microsoft_azure.fill_microsoft_azure_form(**microsoft_azure_form_data)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "MobileIron - DISA Samsung Android 7 with Knox 2.x "
                                                                  "v1r1",
                                               'data': compliance_type["apple_profile_manager_data"],
                                               'form_name': ComplianceConst.MOBILEIRON}])
    def test_apple_profile_manager_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
            Apple Profile Manager - TNS Best Practices Audit v1.1.0 compliance and values should be retained """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)
        apm_form_data = {'server': '172.26.16.75', 'port': API.Credentials.Mobile.Ports.PORT, 'username': 'tenable',
                         'password': 'nessus', 'force_device': True, 'device_update_timeout': '10'}

        apm_form = AppleProfileManager(mobile_credential_type=API.Credentials.Mobile.APM)
        apm_form.fill_apple_profile_manager_form(**apm_form_data)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "Tenable Best Practices OpenStack v2.0.0",
                                               'data': compliance_type["tns_openstack_data"],
                                               'form_name': ComplianceConst.OPENSTACK}])
    def test_openstack_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
            Tenable Best Practices OpenStack v2.0.0 compliance and values should be retained """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])
        LoadingCircle(WAIT_SHORT)

        open_stack_data = {'user_name': 'admin', 'password': 'p@ssw0rd', 'tenant_name': 'admin', 'port': 4445,
                           'https': True, 'ssl_cert': True}

        misc_inst = Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.OPEN_STACK)
        misc_inst.fill_form(**open_stack_data)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "CIS Palo Alto Firewall 7 Benchmark L1 v1.0.0",
                                               'data': compliance_type["palo_alto_firewall_data"],
                                               'form_name': ComplianceConst.PALO_ALTO}])
    def test_palo_alto_firewall_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
            CIS Palo Alto Firewall 7 Benchmark L1 v1.0.0 compliance and values should be retained """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])
        LoadingCircle(WAIT_SHORT)

        palo_alto_credentials = {'user_name': 'admin', 'port': 4445, 'https': True, 'ssl_cert': True,
                                 'password': 'admin'}
        misc_inst = Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.PALO_ALTO)
        misc_inst.fill_form(**palo_alto_credentials)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "Tenable Best Practices RackSpace v2.0.0",
                                               'data': compliance_type["rackspace_data"],
                                               'form_name': ComplianceConst.RACK_SPACE}])
    def test_rackspace_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
            Tenable Best Practices RackSpace v2.0.0 compliance and values should be retained """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])
        LoadingCircle(WAIT_SHORT)

        rackspace_credentials = {'auth_method': "API-Key", 'username': 'admin', 'password': 'admin',
                                 'dallas_fort': False, 'chicago_ord': False, 'northen_virginia': False, 'london': False,
                                 'sydney': False, 'hongkong': False}
        rackspace = RackSpace(cloud_type=API.Credentials.CloudServices.Types.RACKSPACE)
        rackspace.fill_rackspace_form(**rackspace_credentials)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "TNS Salesforce Best Practices Audit v1.2.0",
                                               'data': compliance_type["salesforce_data"],
                                               'form_name': ComplianceConst.SALESFORCE}])
    def test_salesforce_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
           TNS Salesforce Best Practices Audit v1.2.0 compliance and values should be retained """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])
        LoadingCircle(WAIT_SHORT)

        sales_force_credentials = {'username': 'admin', 'password': 'admin'}
        sales_force = SalesForce(cloud_type=API.Credentials.CloudServices.Types.SALESFORCE)
        sales_force.fill_sales_force_form(**sales_force_credentials)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "CIS AIX 5.3/6.1 L1 v1.1.0",
                                               'data': compliance_type["cis_aix_unix_data"],
                                               'form_name': ComplianceConst.CIS_AIX}])
    def test_cis_aix_unix_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
           CIS AIX 5.3/6.1 L1 v1.1.0 compliance and values should be retained"""
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)
        public_key_form_data = {'auth': 'public key', 'username': 'root', 'elevate_privilege': 'Nothing',
                                'passphrase': 'admin'}

        public_key = PublicKey(host_type='SSH')
        LoadingCircle(WAIT_SHORT)
        public_key.fill_public_key_ssh_form(username=public_key_form_data['username'],
                                            key_path=self.key_path,
                                            passphrase='root',
                                            elevate_privilege=public_key_form_data['elevate_privilege'])

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "TNS File Analysis - Adult Media Content",
                                               'data': compliance_type["audit_media_content_data"],
                                               'form_name': ComplianceConst.AUDIT_MEDIA_CONTENT}])
    def test_audit_media_content_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
           TNS File Analysis - Adult Media Content compliance and values should be retained"""
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)

        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)
        public_key_form_data = {'auth': 'public key', 'username': 'root', 'elevate_privilege': 'Nothing',
                                'passphrase': 'admin'}

        public_key = PublicKey(host_type='SSH')
        LoadingCircle(WAIT_SHORT)
        public_key.fill_public_key_ssh_form(username=public_key_form_data['username'],
                                            key_path=self.key_path,
                                            passphrase='root',
                                            elevate_privilege=public_key_form_data['elevate_privilege'])

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "CIS VMware ESXi 5.1 v1.0.1 Level 1",
                                               'data': compliance_type["vmware_esxi_level_one_data"],
                                               'form_name': ComplianceConst.VMWARE}])
    def test_vmware_esxi_level_one_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
           CIS VMware ESXi 5.1 v1.0.1 Level 1 compliance and values should be retained"""
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)
        vmware_credentials = {'vcenter_host': '127.0.0.1', 'vcenter_port': 4445, 'user_name': 'admin',
                              'password': 'p@ssw0rd', 'https': True, 'ssl_cert': False}

        misc_inst = Miscellaneous.get_misc_inst(API.Credentials.Miscellaneous.VMWARE_VCENTER)
        misc_inst.fill_form(**vmware_credentials)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.sensor_manager
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_scan", [{'template_name': 'Advanced Scan',
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "CIS IBM DB2 9 Benchmark v3.0.1 Level 1 OS Windows",
                                               'data': compliance_type["cis_ibm_level_one_windows_data"],
                                               'form_name': ComplianceConst.IBM}])
    def test_cis_ibm_level_one_windows_compliance(self, create_scan, input_fields):
        """Verify 'advanced scan' is saved successfully with values given under
           CIS IBM DB2 9 Benchmark v3.0.1 Level 1 OS Windows compliance and values should be retained"""
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        LoadingCircle(WAIT_SHORT)
        compliance_page.fill_compliance_form(**input_fields['data'])

        LoadingCircle(WAIT_SHORT)
        password_credentials = {'auth': 'Password', 'username': 'administrator', 'password': 'admin',
                                'domain': 'tenable'}
        password = Password(host_type=API.Credentials.Host.Types.WINDOWS)
        password.fill_password_windows_form(**password_credentials)

        LoadingCircle(WAIT_SHORT)
        save_and_configure_scan(class_object=compliance_page, scan_name=scan_name,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert len(compliance_page.active_compliances) == 1, "More than 1 compliance are available"
        compliance_page.open_saved_compliance_component(form_name=input_fields['form_name'])

        assert compliance_page.get_filled_compliance_form_values() == input_fields['data'], \
            "'Data saved is either incorrect or missing'"
        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_SHORT)

# TODO: Four compliance categories are not covered in this test file because of NES-7698
#       (‘Audit File’ field is not persist under compliance tab in saved scan)
