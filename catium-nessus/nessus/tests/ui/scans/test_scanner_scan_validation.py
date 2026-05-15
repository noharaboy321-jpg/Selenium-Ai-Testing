""""
Nessus test cases related to scanner tab's scan creation

:copyright: Tenable Network Security, 2017
:date: June 21, 2018
:last_modified: Sep 06, 2022
:author: @rdutta, @jamreliya, @ntarwani, @kpanchal, @krpatel.ctr
"""

import pytest
from packaging.version import parse

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_SHORT, WAIT_NORMAL, TIME_THREE_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.controls.upload_field import UploadField
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.scan import save_and_configure_scan, delete_created_scan, scan_save_launch_and_status_verification
from nessus.helpers.system import get_nessus_version, is_expert
from nessus.lib.const import API, Nessus
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.message.messages import Messages
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.credentials.cloud_services import AmazonAWS
from nessus.pageobjects.credentials.credentials_page import Credentials
from nessus.pageobjects.credentials.database import MongoDB
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.credentials.mobile_credential import AirWatch
from nessus.pageobjects.dynamic_plugins.dynamic_plugins_page import DynamicPlugin
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.plugins.plugins_page import Plugin
from nessus.pageobjects.scans.new_scan_form import ScanTemplatePage, NewScanForm
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.scap.scap_page import ScapAndOvalForm
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestScansValidation:
    """Covers scanner scan validation related test cases."""
    cat = None

    @pytest.mark.nessus_home
    @pytest.mark.usefixtures('nessus_api_login')
    def test_scan_templates_list(self):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-1)
            1. Create a new scan.
            2. Get list of all scanner scan templates and back to scans page.
            3. Verify all above templates listed if you directly navigating to ‘<IP>: port/#/scans/reports/new’.
        """
        scan_page = ScansPage()

        # create new scan by clicking on 'New Scan' button on scan page
        scan_page.new_scan_button.click()
        wait(lambda: scan_page.is_element_present('scanner'), waiting_for='')

        if is_expert():
            scan_templates_list = Nessus.TemplateNames.SCAN_TEMPLATE_LIST_EXPERT[1:] \
                if parse(get_nessus_version()) < parse('8.1.0') else Nessus.TemplateNames.SCAN_TEMPLATE_LIST_EXPERT
        else:
            scan_templates_list = Nessus.TemplateNames.SCAN_TEMPLATE_LIST \
                if parse(get_nessus_version()) < parse('8.1.0') else Nessus.TemplateNames.SCAN_TEMPLATE_LIST

        assert set(scan_page.get_all_scan_templates(
            Nessus.Scan.ScanTemplateTabs.SCANNER_TAB.lower())) == set(scan_templates_list), \
            'Any of the scan template is missing under scanner tab'

        scan_page.back_to_folder.click()
        LoadingCircle(WAIT_NORMAL)

        # fetch scan template list by navigating to <IP>: port/#/scans/reports/new URL directly
        ScanTemplatePage().open()
        wait(lambda: scan_page.is_element_present('scanner'), waiting_for='')

        assert set(scan_page.get_all_scan_templates(
            Nessus.Scan.ScanTemplateTabs.SCANNER_TAB.lower())) == set(scan_templates_list), \
            'Any of the Scan template is missing while navigating directly to ‘<IP>: port/#/scans/reports/new’ URL'

    @pytest.mark.parametrize("templates", Nessus.TemplateNames.SCAN_TEMPLATES_REQUIRED_HOST)
    def test_upload_target_field(self, templates):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-3)
        1. Navigate to scan templates page while creating a scan
        2. Fill all required fields and keep blank for targets.
        3. Hit ‘Save’ will throw an error “Error: Targets is required.”
        4. Upload a file in ‘Upload Targets’ field without fill up the ‘Targets’ field
        5. Hit ‘save’ and verify success notifications.
        """
        scan_name = random_name(prefix="{} - ".format(templates))

        # Create scan with upload target field for different scan templates
        scan_page = ScansPage()
        scan_page.create_new_scan(scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, scan_template=templates,
                                  scan_name=scan_name, add_configuration=True)

        if templates == Nessus.TemplateNames.ADVANCED_DYNAMIC:
            DynamicPlugin().manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
                {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
                 Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'}])

        scan_form_page = NewScanForm()
        scan_form_page.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.target_required_error, \
            "Scan should not saved successfully without Target host."

        # upload target host file
        target_file = get_file_path('nessus/tests/ui/scan/test_data/Host_Target.txt')
        LoadingCircle(TIME_THREE_SECONDS)
        UploadField(scan_form_page.upload_targets).file = target_file
        LoadingCircle(WAIT_NORMAL)

        # add required credentials and compliance
        if templates in [Nessus.TemplateNames.AUDIT_PATCH, Nessus.TemplateNames.MALWARE,
                         Nessus.TemplateNames.COMPLIANCE_AUDIT]:
            windows_form_data = {'auth': 'Password', 'username': 'administrator', 'password': 'admin',
                                 'domain': 'tenable'}
            Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(**windows_form_data)
            LoadingCircle(WAIT_NORMAL)

            if templates == Nessus.TemplateNames.COMPLIANCE_AUDIT:
                scan_form_page.js_scroll_into_view(scan_form_page.compliance)
                compliance_page = Compliance()
                LoadingCircle(WAIT_SHORT)
                compliance_page.click_compliance_type(category_name=ComplianceConst.WINDOWS,
                                                      compliance_type="Upload a custom Windows audit file")
                LoadingCircle(WAIT_SHORT)
                compliance_page.add_audit_and_config_file(
                    audit_file_path='nessus/tests/ui/scan/test_data/',
                    audit_file_name='CIS_Red_Hat_EL6_Server_L1_v2.0.2.audit')

        elif templates == Nessus.TemplateNames.SCAP_OVAL:
            Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, domain=Nessus.Scan.Target.AWS_LINUX_TARGET_2,
                auth=API.Credentials.Host.WindowsAuthTypes.PASSWORD)

            test_data = {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_SCAP, 'form_details': [{
                'version': '1.2', 'benchmark_id': 'Windows_7_STIG', 'profile_id': 'Windows - 1_Classified',
                'stream_id': '1234567', 'result_type': 'Full results w/o system characteristics',
                'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]}

            scan_form_page.js_scroll_into_view(scan_form_page.scap)
            ScapAndOvalForm().open_form_and_fill_details(form_information=[test_data])

        scan_form_page.js_scroll_into_view(scan_form_page.save_button)
        scan_form_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Error: scan not saved with uploaded target host file"

        # remove created scan
        wait(lambda: scan_page.is_element_present("scan_searchbox"), waiting_for="scan list gets loaded properly")
        delete_created_scan(scan_name=scan_name)

    @pytest.mark.usefixtures('nessus_api_login')
    @pytest.mark.parametrize("scan_template", Nessus.TemplateNames.SCAN_TEMPLATE_LIST)
    def test_required_field(self, scan_template):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 9-10)
        # NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-2/6)
            1. Navigate to scan templates page while creating a scan
            2. Verify that on clicking each template, a form will open which will have ‘Name ‘, ‘Targets’
                as the required field and it has respective tabs
            3. Verify that ‘Dashboard’ and ‘Folder’ field in scan form are drop-down fields.
            4. Verify ‘Dashboard’ drop-down will contain only two options ‘Enabled/Disabled’ with disabled as default
            5. Verify ‘Folder’ drop-down must contain all folder list including ‘Trash’ and ‘My Scans’
                with ‘My Scans’ as default value.
            6. Verify ’Save’ and ‘Cancel’ button.
            7. Also verify ‘Launch’ as an option is present under ‘Save’ button drop-down.
        """
        # skip test if template having upgrade banner attribute
        if scan_template in [template['title'] for template in
                             self.cat.api.editor.get_templates('scan')['templates'] if template['manager_only']]:
            pass
        else:
            # get folder list from side navigation
            LoadingCircle(WAIT_SHORT)
            side_nav_folder_list = SideNav().get_all_sidenav_folders_name()
            side_nav_folder_list.remove('All Scans')

            # navigate to scan template page
            scan_template_page = ScanTemplatePage()
            scan_template_page.open()
            LoadingCircle(WAIT_SHORT)

            # select scan template
            scan_template_page.click_by_scan(scan_text=scan_template)
            LoadingCircle(WAIT_NORMAL)

            scan_form_page = NewScanForm()
            assert scan_form_page.name_field.get_attribute('aria-required') == 'true', \
                'Required flag is missing from Name Field'

            if scan_form_page.is_element_present('targets_textarea'):
                assert scan_form_page.targets_textarea.get_attribute('aria-required') == 'true', \
                    'Required flag is missing from Target Field'

            if scan_template in [Nessus.TemplateNames.ADVANCED_DYNAMIC]:
                assert all([scan_form_page.is_element_present('credentials'),
                            scan_form_page.is_element_present('dynamic_plugins')]), \
                    'one of the tab is not present in {}'.format(scan_template)

            elif scan_template == Nessus.TemplateNames.SCAP_OVAL:
                assert all([scan_form_page.is_element_present('credentials'),
                            scan_form_page.is_element_present('scap'),
                            scan_form_page.is_element_present('plugin')]), \
                    'one of the tab is not present in {}'.format(scan_template)

            elif scan_template == Nessus.TemplateNames.OFFLINE_AUDIT:
                assert all([scan_form_page.is_element_present('compliance'),
                            scan_form_page.is_element_present('plugin')]), \
                    'one of the tab is not present in {}'.format(scan_template)

            elif scan_template in [Nessus.TemplateNames.PCI_EXTERNAL, Nessus.TemplateNames.RIPPLE_20_REMOTE_SCAN,
                                   Nessus.TemplateNames.HOST_DISCOVERY, Nessus.TemplateNames.ZEROLOGON_REMOTE_SCAN,
                                   Nessus.TemplateNames.LOG4SHELL_REMOTE_CHECKS, Nessus.TemplateNames.PING_ONLY_DISCOVERY]:
                assert scan_form_page.is_element_present('plugin'), \
                    'plugins tab is not present in {}'.format(scan_template)

            elif scan_template in [Nessus.TemplateNames.AUDIT_CLOUD,
                                   Nessus.TemplateNames.MDM_AUDIT, Nessus.TemplateNames.COMPLIANCE_AUDIT]:
                assert all([scan_form_page.is_element_present('credentials'),
                            scan_form_page.is_element_present('compliance'),
                            scan_form_page.is_element_present('plugin')]), \
                    'one of the tab is not present in {}'.format(scan_template)

            else:
                assert all([scan_form_page.is_element_present('credentials'),
                            scan_form_page.is_element_present('plugin')]), \
                    'one of the tab is not present in {}'.format(scan_template)

            # get attribute of dashboard and select folder
            assert scan_form_page.select_folder.get_attribute('data-type') == 'select', \
                "Folder field don't have drop-down attribute"

            assert scan_form_page.select_folder.text == 'My Scans', "Folder don't have My Scans option as by default."

            dropdown_folder_list = [folder['label'] for folder in scan_form_page.select_folder.option_values]

            assert dropdown_folder_list.sort() == side_nav_folder_list.sort(), \
                'Mismatch found in Folder drop down list and side navigation folder list'

            scan_form_page.js_scroll_into_view(element=scan_form_page.save_button)
            LoadingCircle(WAIT_SHORT)
            assert scan_form_page.save_button.is_displayed(), 'Save button is not visible'
            assert scan_form_page.cancel_button.is_displayed(), 'Cancel button is not visible'

            scan_form_page.save_action_dropdown.click()
            assert scan_form_page.launch_option.is_displayed(), 'Launch drop-down option is not visible'

            # check plugin tab and eye icon on plugin tab is visible
            if scan_template != Nessus.TemplateNames.ADVANCED_DYNAMIC:
                assert scan_form_page.plugin.is_displayed(), \
                    'Plugins tab is not visible for {} template'.format(scan_template)

            if scan_template not in [Nessus.TemplateNames.ADVANCED, Nessus.TemplateNames.ADVANCED_DYNAMIC]:
                assert scan_form_page.plugin_eye_icon.is_displayed(), 'Eye icon is not visible on Plugins tab'

                # verify tool tip is visible for eye icon of plugin tab
                scan_form_page.js_scroll_into_view(element=scan_form_page.plugin)
                scan_form_page.move_to_element(scan_form_page.plugin_eye_icon)
                LoadingCircle(WAIT_SHORT)
                assert scan_form_page.plugin_eye_icon_tip_msg.text == Messages.ToolTip.plugin_tab_eye_icon_tool_tip, \
                    'Eye icon tool tip is not same as expected.'

                # check visibility of disable_all and enable_all button on plugin page
                plugin_page = Plugin()
                assert not plugin_page.is_element_present('disable_all'), 'Disable all plugins button is visible'
                assert not plugin_page.is_element_present('enable_all'), 'Enable all plugins button is visible'

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.AUDIT_CLOUD, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.AUDIT_CLOUD)),
         'keep_original_scan_name': True, 'add_configuration': True}]}], indirect=True)
    def test_validate_audit_cloud_template(self, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-4)
        1. Navigate to scan templates page while creating a scan having ‘Audit Cloud Infrastructure’ template.
        2. Verify that ‘Targets’ and ‘Upload Targets’ field does not exist.
        3. Provide name and click on save button, it will throw an error ‘Error: At least one audit must be added to
             this policy in the ‘Compliance’ section ’
        4. Add a related compliance file, hit ‘Save’ and verify success notifications.
        """
        # check visibility of target field and should not save without required compliance
        scan_form_page = NewScanForm()
        assert not scan_form_page.is_element_present('targets_textarea'), \
            'Targets field should not visible for this template.'
        assert not scan_form_page.is_element_present('upload_targets'), \
            'Upload Target field should not visible for this template.'
        scan_form_page.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.audit_policy_validation, \
            "Scan should not saved successfully without required compliance."

        # add required credentials and compliance
        AmazonAWS(cloud_type=API.Credentials.CloudServices.Types.AMAZON_AWS).fill_amazon_aws_form(
            access_key='admin', secret_key='admin', regions_to_access='China', https_switch=False, ssl_certificate=True)

        compliance_page = Compliance()
        LoadingCircle(WAIT_SHORT)
        compliance_page.click_compliance_type(category_name=ComplianceConst.AMAZON_AWS,
                                              compliance_type="Upload a custom Amazon AWS audit file")
        LoadingCircle(WAIT_SHORT)
        compliance_page.add_audit_and_config_file(
            audit_file_path='nessus/tests/ui/scan/test_data/',
            audit_file_name='CIS_Red_Hat_EL6_Server_L1_v2.0.2.audit')

        scan_form_page.js_scroll_into_view(scan_form_page.save_button)
        scan_form_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan not saved after adding required compliance."

    @pytest.mark.nessus_home
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.AUDIT_PATCH, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.AUDIT_PATCH)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_credential_patch_audit_template(self, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-5)
        1. Navigate to scan templates page while creating a scan having ‘Credentialed Patch Audit’ template.
        2. Fill basic configuration and click on ‘Save’ button, verify it will throw an error
        3. Fill credentials, hit ‘Save’ and verify success notifications.
        """

        # add required credential
        scan_form_page = NewScanForm()
        mongo_db_form_data = {'username': 'root', 'database': 'mongoDB', 'port': '27018', 'password': 'root'}
        MongoDB(host_type=API.Credentials.Database.Types.MONGODB).fill_monogodb_database_form(**mongo_db_form_data)
        LoadingCircle(WAIT_SHORT)

        scan_form_page.save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            "Scan not saved after adding required credentials."

    @pytest.mark.nessus_home
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.MALWARE, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.MALWARE)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_malware_template(self, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-7)
        1. Navigate to scan templates page while creating a scan having ‘Malware Scan’ template.
        2. Fill basic configuration and click on ‘Save’ button, verify it will throw an error as
             ‘Error: One of the following credentials must be added to this policy: Windows, SSH’.
        3. Verify that the Categories dropdown under ‘Credentials’ tab contains only two options (‘Host’, ‘All’)
             and ‘Host as the default option
        """

        NewScanForm().save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies. \
            malware_credential_validation, "Scan should not saved successfully without required credentials."

        # check drop down option on credential page
        credential_page = Credentials()
        LoadingCircle(WAIT_SHORT)
        assert credential_page.get_category_type_list() == ['All', 'API Gateway', 'Host'], \
            'Any drop-down option is missing for Malware credential tab'
        assert credential_page.credentials_type.get_value_selected() == 'Host', \
            "Malware Credential template don't have Host as default drop down option"

        # add required credential
        windows_form_data = {'auth': 'Password', 'username': 'administrator', 'password': 'admin', 'domain': 'tenable'}
        Password(host_type=API.Credentials.Host.Types.WINDOWS).fill_password_windows_form(**windows_form_data)

        NewScanForm().save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.save_scan, \
            'Malware scan should save successfully after adding required credential'

    @pytest.mark.nessus_home
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         'add_configuration': True}]}], indirect=True)
    def test_cancel_button_functionality(self, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-9)
        1. Navigate to scan templates page while creating a scan having ‘Advanced Scan’ template
        2. Fill basic configuration and click on ‘Cancel’ button.
        3. Verify it will re-direct you to ‘<IP> : <Port>/#//scans/reports/new’ without saving any data.
        """
        scan_name = create_scans[0]
        scan_page = ScansPage()
        scan_page.cancel_button.click()
        LoadingCircle(WAIT_SHORT)

        assert '/#/scans/reports/new' in get_driver_no_init().current_url, 'Scan template page is not opened'

        # verify scan is not saved
        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)
        scan_list = ScanList()
        assert scan_name not in scan_list.get_all_scans(), 'Clicking on Cancel button should not save scan.'

    @pytest.mark.nessus_home
    def test_filter_on_template_list(self):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-11)
        1. Try to search some scan template by its name from search box
        2. Verify template list are filtered with search string.
        """
        # navigate to scan template page
        scan_template_page = ScanTemplatePage()
        scan_template_page.open()
        LoadingCircle(WAIT_SHORT)

        scan_template_page.template_searchbox.value = 'ad'
        LoadingCircle(WAIT_SHORT)

        assert all(['ad' in template.lower() for template in scan_template_page.get_all_scan_templates(
            scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB.lower())]), \
            'Template filter is not working as expected'

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_compliance_tab_and_categories(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans. (step 10)
        1. Create new scan using Advanced Scan
        2. Go to Compliance tab
        3. Verify Compliance Category dropdown is displayed and the default value is All
        4. Select any other Category say 'Amazon AWS'
        5. Go to some other tab and come back to compliance
        6. Verify the category selected remains same
        7. Save the scan
        8. Go to some other nessus page and navigate to created scan > Compliance tab
        9. Verify the default category is All
        """
        scan_page_form = NewScanForm()
        scan_page_form.compliance.click()

        compliance = Compliance()
        assert compliance.compliance_type.is_displayed(), 'Categories dropdown is not displayed'
        assert compliance.compliance_type.value == "all", 'Default option should be All'

        compliance.compliance_type.select_by_visible_text(ComplianceConst.AMAZON_AWS)
        scan_page_form.plugin.click()
        scan_page_form.compliance.click()
        assert compliance.compliance_type.value == ComplianceConst.AMAZON_AWS, \
            'The selected option should remain after we switch the tabs'

        save_and_configure_scan(scan_name=create_scans[0], class_object=compliance,
                                tab_to_navigate=Nessus.Scan.ScanFeatureTabs.COMPLIANCE)
        assert compliance.compliance_type.value == "all", \
            'Default option should be All when we navigate to other pages and come back to scan form '

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_compliance_filter(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans. (step 10)
        1. Create new scan using Advanced Scan
        2. Go to Compliance tab
        3. Select any category from the dropdown
        4. Verify the subcategories listing according to the category selected
        5. Enter some string in search textbox
        6. Verify the listing according to the search string
        """
        scan_page_form = NewScanForm()
        scan_page_form.compliance.click()

        compliance = Compliance()
        compliance.compliance_type.select_by_visible_text(ComplianceConst.AMAZON_AWS)

        for category in compliance.get_sub_category_list(data_compliance=ComplianceConst.AMAZON_AWS):
            assert category.get_attribute('data-parent') == ComplianceConst.AMAZON_AWS, \
                'The listing of categories is not proper'

        compliance.search_textbox.value = "Amazon"
        for compliance_cate in compliance.get_compliance_type_after_filter(ComplianceConst.AMAZON_AWS):
            assert "Amazon" in compliance_cate, 'Search is not working properly'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_credentials_tab_and_categories(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans. (step 11)
        1. Create new scan using Advanced Scan
        2. Go to Credentials tab
        3. Verify Credentials Category dropdown is displayed and the default value is All
        4. Select any other Category say 'Cloud Services'
        5. Go to some other tab and come back to credentials
        6. Verify the category selected remains same
        7. Save the scan
        8. Go to some other nessus page and navigate to created scan > Credentials tab
        9. Verify the default category is Host
        """
        scan_page_form = NewScanForm()
        scan_page_form.credentials.click()

        credentials = Credentials()
        assert credentials.credentials_type.is_displayed(), 'Categories dropdown is not displayed'
        assert credentials.credentials_type.value == API.Credentials.Types.CATEGORY_HOST, \
            'Default option should be Host'

        credentials.credentials_type.select_by_visible_text(API.Credentials.Types.CATEGORY_CLOUD_SERVICES)
        scan_page_form.plugin.click()
        scan_page_form.credentials.click()
        assert credentials.credentials_type.value == API.Credentials.Types.CATEGORY_CLOUD_SERVICES, \
            'The selected option should remain after we switch the tabs'

        save_and_configure_scan(scan_name=create_scans[0], class_object=credentials)
        assert credentials.credentials_type.value == API.Credentials.Types.CATEGORY_HOST, \
            'Default option should be All when we navigate to other pages and come back to scan form '

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize("create_scans", [{'scans_details': [
        {"scan_template": Nessus.TemplateNames.ADVANCED, "scan_type": Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
         "scan_name": random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)),
         "target_ip": Nessus.Scan.Target.LINUX_TARGET, 'add_configuration': True}]}], indirect=True)
    def test_credentials_filter(self, create_scans):
        """
        NQA-1086-Automation tests for Scans - Scanner Editing for created scans. (step 11)
        1. Create new scan using Advanced Scan
        2. Go to Credentials tab
        3. Select any category from the dropdown
        4. Verify the subcategories listing according to the category selected
        5. Enter some string in search textbox
        6. Verify the listing according to the search string
        """
        scan_page_form = NewScanForm()
        scan_page_form.credentials.click()

        credentials = Credentials()

        credentials.credentials_type.select_by_visible_text(API.Credentials.Types.CATEGORY_CLOUD_SERVICES)
        for category in credentials.get_sub_category_list(
                data_credentials=API.Credentials.Types.CATEGORY_CLOUD_SERVICES):
            assert category.get_attribute('data-parent') == API.Credentials.Types.CATEGORY_CLOUD_SERVICES, \
                'The listing of categories is not proper'

        credentials.credentials_type.select_by_visible_text("All")
        credentials.search_category.value = "Red Hat"
        for cred_category in credentials.get_credentials_type_after_filter(
                API.Credentials.Types.CATEGORY_PATCH_MANAGEMENT):
            assert "Red Hat" in cred_category, 'Search is not working properly'

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)

    @pytest.mark.parametrize('scan_templates', Nessus.TemplateNames.SCAN_TEMPLATES_REQUIRED_HOST)
    def test_invalid_target_host(self, scan_templates):
        """
        # NQA-1301 : Automation tests for Dynamic Scan. (step: 9)
        Test to validate wrong/invalid scan target gives user error notes in scan results

        1. Click on 'New Scan' under My Scan and select scan templates
        2. Fill up scan name and invalid target host like 'abcd.xyz' on General Setting page
        3. Fill required data to save the scan and verify success notifications
        4. Launch the scan and verify that after completed scan invalid target should be displayed under Notes panel
        """
        scan_name = random_name(prefix="{} - ".format(scan_templates))

        invalid_target_ip = "abcd.xyzabc"

        # Create scan with invalid scan target
        ScansPage().create_new_scan(scan_type=Nessus.Scan.ScanTemplateTabs.SCANNER_TAB, scan_template=scan_templates,
                                    scan_name=scan_name, target_ip=invalid_target_ip, add_configuration=True)

        # Fill required data to save the scan according to scan template
        if scan_templates in [Nessus.TemplateNames.AUDIT_PATCH, Nessus.TemplateNames.MALWARE,
                              Nessus.TemplateNames.COMPLIANCE_AUDIT, Nessus.TemplateNames.SCAP_OVAL]:
            Password(host_type=API.Credentials.Host.Types.SSH).fill_password_ssh_form(
                username=Nessus.USERNAME, password=Nessus.PASSWORD, auth=API.Credentials.Host.SSHAuthTypes.PASSWORD)

        if scan_templates == Nessus.TemplateNames.ADVANCED_DYNAMIC:
            DynamicPlugin().manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
                {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
                 Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'}])

        if scan_templates == Nessus.TemplateNames.COMPLIANCE_AUDIT:
            compliance_page = Compliance()
            compliance_page.click_compliance_type(category_name=ComplianceConst.ADTRAN_AOS,
                                                  compliance_type="Upload a custom {} audit file".
                                                  format(ComplianceConst.ADTRAN_AOS))
            LoadingCircle(WAIT_SHORT)
            compliance_page.add_audit_and_config_file(audit_file_path='nessus/tests/api/plugins/test_data/',
                                                      audit_file_name='api_pub_key_target_priv_key')

        if scan_templates == Nessus.TemplateNames.SCAP_OVAL:
            ScapAndOvalForm().open_form_and_fill_details(
                form_information=[{'count_of_forms': 1, 'form_type': API.Scap.Types.LINUX_OVAL,
                                   'form_details': [{'definition_file_name': 'U_RedHat_6_V1R9_STIG_OVAL.zip',
                                                     'definition_file_path': 'nessus/tests/ui/scan/test_data/'}]}])

        # Verify scan save and completed successfully
        assert scan_save_launch_and_status_verification(
            scan_name=scan_name, scan_folder_name=Nessus.Scan.Folder.MY_SCANS), \
            'Scan has not been completed successfully.'

        # Navigate to 'Notes' tab in scan results page
        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=scan_name)
        LoadingCircle(WAIT_NORMAL)

        scan_details_page = ScanViewPage()
        scan_details_page.notes_tab.click()
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for notes list to be loaded')

        #  Verify error notes in results
        error_list = [getattr(row, 'scan_notes') for row in scan_list.rows]
        for error_note in error_list:
            assert 'Invalid Target' in error_note, "Error note for invalid scan target is invisible."

        assert all([Messages.NotificationMessages.Scans.invalid_target in error_list[1],
                    Messages.NotificationMessages.Scans.unresolved_target.format(invalid_target_ip)
                    in error_list[0]]), 'Error messages in notes section is invisible in scan results.'

        scan_details_page.back_link.click()
        sleep(sleep_time=WAIT_NORMAL, reason='waiting for scan page to be loaded')

        # Clean up code for created scan
        delete_created_scan(scan_name=scan_name)

    def test_scanner_tab_scan_template_categories_for_new_scan(self):
        """
        NES-9857 - UI automation for Scan Library Org NES-9820

        Scenarios:
            [x] Verify that scan templates under scanner tab are organized in three categories
            "Discovery", "Vulnerabilities" and "Compliance".

        Steps:
        1. Login to Nessus.
        2. Click on "My Scan" and go to "scanner" tab.
        3. Verify Scan templates are organized in three categories.
        4. Verify Scan template categories are "Discovery", "Vulnerabilities" and "Compliance".
        5. Verify scan templates list for each scan category.
        6. Verify "Vulnerabilities" category has "Basic Network Scan" and "Advanced Scan" at first two places.
        7. Logout from Nessus.
        """
        scan_page = ScansPage()

        # create new scan by clicking on 'New Scan' button on scan page
        scan_page.new_scan_button.click()
        wait(lambda: scan_page.is_element_present('scanner'), waiting_for='Scan templates to load properly')

        category_names = scan_page.get_all_scan_categories_names()

        # Verifying scan templates categories
        assert set(category_names) == set(Nessus.TemplateCategories.SCAN_TEMPLATE_CATEGORIES_LIST), \
            "Scan templates categories are not matching in scanner tab"

        vulnerabilities_scan_list = scan_page.get_scan_templates_list_for_given_category(
            category_name=Nessus.TemplateCategories.VULNERABILITIES)

        # Verifying scan templates list for "Discovery"
        if is_expert():
            assert set(scan_page.get_scan_templates_list_for_given_category(
                category_name=Nessus.TemplateCategories.DISCOVERY)) == set(
                Nessus.TemplateNames.SCAN_DISCOVERY_TEMPLATE_LIST_EXPERT), "Scan template list for 'Discovery' is not matching"
        else:
            assert set(scan_page.get_scan_templates_list_for_given_category(
                category_name=Nessus.TemplateCategories.DISCOVERY)) == set(
                Nessus.TemplateNames.SCAN_DISCOVERY_TEMPLATE_LIST), "Scan template list for 'Discovery' is not matching"

        # Verifying scan templates list for "Vulnerabilities"
        assert set(vulnerabilities_scan_list) == set(Nessus.TemplateNames.SCAN_VULNERABILITIES_TEMPLATE_LIST), \
            "Scan template list for 'Vulnerabilities' is not matching"

        # Verifying scan templates list for "Compliance"
        assert set(scan_page.get_scan_templates_list_for_given_category(
            category_name=Nessus.TemplateCategories.COMPLIANCE)) == set(
            Nessus.TemplateNames.SCAN_COMPLIANCE_TEMPLATE_LIST), "Scan template list for 'Compliance' is not matching"

        # Verify that "Vulnerabilities" category has "Basic Network Scan" and "Advanced Scan" at first two places.
        assert vulnerabilities_scan_list[0] == Nessus.TemplateNames. \
            BASIC_NETWORK and vulnerabilities_scan_list[1] == Nessus.TemplateNames.CREDENTIAL_VALIDATION, \
            "First two scan templates for vulnerabilities are not 'Basic Network Scan' and 'Advanced Scan'"


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestScansValidationForManager:
    """Covers scanner scan validation related test cases for Nessus Manager."""

    @pytest.mark.parametrize("templates", Nessus.TemplateNames.SCAN_TEMPLATE_LIST)
    def test_visibility_of_dashboard_field(self, templates):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-2)
        1. Verify ‘Dashboard’ drop-down will contain only two options ‘Enabled/Disabled’ with disabled as default
        """
        if templates not in [Nessus.TemplateNames.AUDIT_CLOUD, Nessus.TemplateNames.MDM_AUDIT,
                             Nessus.TemplateNames.MOBILE_DEVICE, Nessus.TemplateNames.OFFLINE_AUDIT]:
            # select scan template
            scan_template_page = ScanTemplatePage()
            scan_template_page.open()
            LoadingCircle(WAIT_SHORT)
            scan_template_page.click_by_scan(scan_text=templates)
            LoadingCircle(WAIT_NORMAL)
            scan_form_page = NewScanForm()

            assert scan_form_page.select_dashboard.get_attribute('data-type') == 'checkbox', \
                "Dashboard field don't have Checkbox attribute"

            assert scan_form_page.select_dashboard.is_displayed() and not \
                scan_form_page.select_dashboard.is_selected(), \
                'Either Show dashboard Checkbox is not displayed or it is checked'

    @pytest.mark.parametrize('create_scans', [
        {'scans_details': [
            {'scan_template': Nessus.TemplateNames.MOBILE_DEVICE, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
             'scan_name': random_name(prefix='{} Scan- '.format(Nessus.TemplateNames.MOBILE_DEVICE)),
             'add_configuration': True}]},
        {'scans_details': [
            {'scan_template': Nessus.TemplateNames.MDM_AUDIT, 'scan_type': Nessus.Scan.ScanTemplateTabs.SCANNER_TAB,
             'scan_name': random_name(prefix='{} Scan- '.format(Nessus.TemplateNames.MDM_AUDIT)),
             'add_configuration': True}]}], indirect=True)
    def test_mobile_device_and_mdm_template(self, create_scans):
        """
        #NQA-1265 : Automation tests for creation of Scans-Scanner templates.(step-8)
        1. Navigate to scan templates page while creating a scan having ‘Mobile Device Scan’ template.
        2. Verify that ‘Targets’ and ‘Upload Targets’ field does not exist.
        3. Fill basic configuration and click on save button, it will throw an error
        4. Repeat above steps for scan having ‘MDM Config Audit’ template
        """
        # check visibility of target field
        scan_form_page = NewScanForm()

        assert not scan_form_page.is_element_present('targets_textarea'), 'Target field should not be ' \
                                                                          'visible for this template'
        assert not scan_form_page.is_element_present('upload_targets'), 'Upload target field should not be visible ' \
                                                                        'for this template'
        # save scan without credentials
        scan_form_page.save_button.click()
        notification = Notifications()

        if Nessus.TemplateNames.MOBILE_DEVICE in create_scans[0]:
            assert notification.errors[-1] == Messages.NotificationMessages.Policies.mobile_device_validation, \
                'scan should not save successfully without adding required credential'
        else:
            assert notification.errors[-1] == Messages.NotificationMessages.Policies.audit_policy_validation, \
                'scan should not save successfully without adding required credential'

        # add required credential and save scan
        form_data = {'api_url': 'as705.awmdm.com/airwatchservices/0/', 'username': 'apiuser',
                     'password': 'Sapphire123!@#', 'api_key': '1UQH4IQQAAG6A45QAUAA'}
        AirWatch(mobile_credential_type=API.Credentials.Mobile.AIRWATCH).fill_airwatch_form(**form_data)

        if Nessus.TemplateNames.MDM_AUDIT in create_scans[0]:
            compliance_page = Compliance()
            LoadingCircle(WAIT_SHORT)
            compliance_page.click_compliance_type(category_name=ComplianceConst.MOBILE_DEVICE_MANAGER,
                                                  compliance_type="Upload a custom {} audit file".
                                                  format(ComplianceConst.MOBILE_DEVICE_MANAGER))
            LoadingCircle(WAIT_SHORT)
            compliance_page.add_audit_and_config_file(
                audit_file_path='nessus/tests/ui/scan/test_data/',
                audit_file_name='CIS_Red_Hat_EL6_Server_L1_v2.0.2.audit')

        scan_form_page.save_button.click()

        assert notification.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Scan should save successfully after adding required credentials'
