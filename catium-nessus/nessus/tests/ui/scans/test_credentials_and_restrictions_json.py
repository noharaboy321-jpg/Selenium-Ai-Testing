"""
Nessus Credentials tab under Policy/Scan form related test cases For Host -> Cloud Services

:copyright: Tenable Network Security, 2019
:date: Mar 5, 2019
:last_modified: Nov 09, 2020
:author: @yshah, @kpanchal
"""

import os
import pytest
from selenium.common.exceptions import StaleElementReferenceException
from selenium.webdriver.support.expected_conditions import visibility_of_element_located, \
    invisibility_of_element_located

from catium.helpers.testdata import load_testdata
from catium.lib.const import TIME_TEN_SECONDS
from catium.lib.ssh.ssh import SSH
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.nessuscli.helper import path_join
from nessus.helpers.scan import tamper_with_data_and_restart_server, update_plugins_and_restart_server, \
    delete_template_file, restart_server
from nessus.helpers.system import get_nessus_type_using_api
from nessus.lib.config.environment_variables import NESSUS_DATA_DIR
from nessus.lib.const.compliance_constants import ComplianceConst
from nessus.lib.const.constants import Nessus, API
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView
from nessus.pageobjects.compliances.compliance_page import Compliance
from nessus.pageobjects.credentials.cloud_services import AmazonAWS
from nessus.pageobjects.dynamic_plugins.dynamic_plugins_page import DynamicPlugin
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.policies.new_policy_form import PolicyTemplatePage, NewPolicyForm
from nessus.pageobjects.policies.policies_page import PoliciesPage, PolicyList
from nessus.pageobjects.scans.new_scan_form import ScanTemplatePage, NewScanForm
from nessus.pageobjects.scans.scan_basic_settings_page import BasicSetting
from nessus.pageobjects.scans.scan_trash_page import ScansTrashPage
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.scap.scap_page import SCAP
from nessus.pageobjects.sidenav.sidenav import SideNav


def create_advanced_scan(scan_name: str, flag: bool) -> None:
    """
    create advanced scan

    :param str scan_name: scan name
    :param bool flag: True to create scan as False to go to advanced scan template
    :return: None 
    """
    HeaderBasePage().scan_link.click()
    scan_page = ScansPage()
    wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='scan list')

    scan_page.new_scan_button.click()
    scan_page.select_scan_type(type_of_scan=API.Permissions.Types.SCANNER)

    # Wait till 'Advanced scan' template appears on the page
    def advance_scan_template_visibility():
        try:
            return Nessus.TemplateNames.ADVANCED in scan_page.get_all_scan_templates(
                scan_type= API.Permissions.Types.SCANNER)
        except StaleElementReferenceException:
            return False
    wait(lambda: advance_scan_template_visibility(), waiting_for="Advanced Scan template to get loaded!")

    # Retrying for five times so that advanced scan template to get successfully clicked!
    for _ in range(5):
        try:
            scan_page.click_by_scan(scan_text=Nessus.TemplateNames.ADVANCED)
            break
        except StaleElementReferenceException:
            continue

    if flag:
        wait(lambda: visibility_of_element_located(scan_page.name_field), waiting_for='Scan form to open')
        scan_page.fill_new_scan_detail(scan_name=scan_name, host_ip=Nessus.Scan.Target.LOCALHOST)
        scan_page.save_button.click()


def configure_scan(scan_name: str, flag: bool) -> None:
    """
    configure created scan    
  
    :param str scan_name: scan name
    :param bool flag: True to edit scan as False to click on configure button
    :return: None
    """
    ScanList().click_on_scan(scan_name=scan_name)
    scan_view_page = ScanViewPage()
    wait(lambda: visibility_of_element_located(scan_view_page.configure_button), waiting_for='scan view page to load')
    scan_view_page.configure_button.click()

    if flag:
        scan_page = ScansPage()
        scan_page.name_field.clear()
        scan_page.name_field.value = "Edited {}".format(scan_name)
        scan_page.save_button.click()


def create_policy(policy_name: str, flag: bool) -> None:
    """
    create policy with advanced scan template

    :param str policy_name: policy name
    :param bool flag: True to create policy with advanced scan template as False
    :return: None
    """
    policies_page = PoliciesPage()
    wait(lambda: SideNav().get_sidenav_element(Nessus.SideNavResources.POLICIES))
    SideNav().get_sidenav_element(Nessus.SideNavResources.POLICIES).click()
    wait(lambda: visibility_of_element_located(policies_page.scan_templates_link))
    wait(lambda: policies_page.new_policy_button, timeout_seconds=TIME_TEN_SECONDS)
    policies_page.new_policy_button.click()
    PolicyTemplatePage().click_by_policy(policy_text=Nessus.TemplateNames.ADVANCED)

    if flag:
        new_policy_form = NewPolicyForm()
        new_policy_form.add_policy(policy_name=policy_name,
                                   policy_description='Creating policy for {}'.format(Nessus.TemplateNames.ADVANCED))
        new_policy_form.save_button.click()


def edit_policy(policy_name: str, flag: bool) -> None:
    """
    edit created policy

    :param policy_name: policy name
    :param flag: True to edit policy with advanced scan template as False
    :return: None
    """
    SideNav().get_sidenav_element(Nessus.SideNavResources.POLICIES).click()
    wait(lambda: visibility_of_element_located(PoliciesPage().scan_templates_link))

    PolicyList().click_on_policy(policy_name=policy_name)

    if flag:
        new_policy_form = NewPolicyForm()
        new_policy_form.add_policy(policy_name="Edited {}".format(policy_name),
                                   policy_description='Creating policy for {}'.format(Nessus.TemplateNames.ADVANCED))
        new_policy_form.save_button.click()


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login')
class TestCredentialJson:
    """ NES-8915: Automated test UI """

    compliance_type = load_testdata('nessus/tests/ui/test_data/compliance_data.json')

    @pytest.mark.nessus_expert
    def test_visibility_of_compliance_tab_in_advanced_scan(self):
        """
        Scenario Tested:
        [x] Verify that the Compliance tab displays under Advanced Scan template
        """
        ScansPage().new_scan_button.click()
        ScanTemplatePage().click_by_scan(scan_text=Nessus.TemplateNames.ADVANCED)
        scan_form = NewScanForm()
        wait(lambda: visibility_of_element_located(scan_form.compliance))

        assert scan_form.is_element_present("compliance"), "Compliance tab is not visible"

    @pytest.mark.nessus_expert
    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': API.Permissions.Types.SCANNER},
                                             {'template_name': Nessus.TemplateNames.ADVANCED_DYNAMIC,
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_create_and_modify_scan(self, create_scan):
        """
        Scenario Tested:
        [x] Verify that Advanced scans can be created/saved/modified/run successfully
        [x] Verify that Advanced Dynamic scans can be created/saved/modified/run successfully
        """
        scan_name = create_scan
        NewScanForm().save_button.click()

        if Nessus.TemplateNames.ADVANCED_DYNAMIC in scan_name:
            dynamic_plugins = DynamicPlugin()
            dynamic_plugins.manage_dynamic_plugins(add_plugins=True, preview_plugins=False, plugins_filter_list=[
                {Nessus.Filter.INDEX: 1, Nessus.Filter.KEY: Nessus.Filter.FilterKeys.PLUGIN_NAME,
                 Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS, Nessus.Filter.VALUE: 'nessus'}])
            dynamic_plugins.save_button.click()

        scan_list = ScanList()
        assert scan_name in scan_list.get_all_scans(), "Scan not found in list."

        scan_list.click_on_scan(scan_name=scan_name)
        ScanViewPage().configure_button.click()

        scan_page = ScansPage()
        scan_page.name_field.clear()
        new_scan_name = "Edited {}".format(scan_name)
        scan_page.name_field.value = new_scan_name
        scan_page.save_button.click()

        notifications = Notifications()
        assert notifications.successes[-1] == Messages.NotificationMessages.save_scan, 'Scan name did not updated'

        HeaderBasePage().scan_link.click()
        scan_page.refresh()
        scan_page.loaded()

        assert new_scan_name in scan_list.get_all_scans(), "Scan not found in list."

        assert scan_list.launch_scan_and_wait_for_status(scan_name=new_scan_name, status=API.Scan.Status.COMPLETED), \
            'Scan has not been completed successfully.'

        scan_list.delete_scan(scan_name=new_scan_name)
        ScansTrashPage().delete_scan_from_trash(scan_name=new_scan_name)

    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    @pytest.mark.parametrize('input_fields', [{'compliance_type': "CIS Amazon Web Services Foundations v5.0.0 L1",
                                               'data': compliance_type["amazon_data"],
                                               'form_name': ComplianceConst.AMAZON_AWS}])
    def test_advanced_scan_with_compliance(self, create_scan, input_fields):
        """
        Scenario Tested:
        [x] Create an Advanced Scan with Compliance settings, and verify that it runs correctly
        """
        scan_name = create_scan
        compliance_page = Compliance.get_compliance_type(input_fields['compliance_type'])
        compliance_page.fill_compliance_form(**input_fields['data'])

        amazon_aws_form_data = {'regions_to_access': "China", 'https_switch': False, 'ssl_certificate': True}

        amazon_aws = AmazonAWS(cloud_type=API.Credentials.CloudServices.Types.AMAZON_AWS)
        amazon_aws.fill_amazon_aws_form(**amazon_aws_form_data, access_key='admin', secret_key='admin')

        scans_page = ScansPage()
        scans_page.js_scroll_into_view(scans_page.save_button)
        scans_page.save_button.click()

        notifications = Notifications()
        assert notifications.successes[-1] == Messages.NotificationMessages.save_scan, \
            'Success notifications for saving scan is mismatched or missing.'

        scan_list = ScanList()
        assert scan_name in scan_list.get_all_scans(), "Scan not found in list."

        assert scan_list.launch_scan_and_wait_for_status(scan_name=scan_name, status=API.Scan.Status.COMPLETED), \
            'Scan has not been completed successfully.'

        scan_list.delete_scan(scan_name=scan_name)
        ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

    @pytest.mark.nessus_expert
    def test_visibility_of_options_in_resources(self):
        """
        Scenario Tested:

        For Nessus Pro:
        [x] Verify 'Customized Reports' and 'Plugin Rules' options are visible under 'Resources' in side navigation.
        [x] Verify 'Agents' option is not visible under 'Resources' in side navigation.

        For Nessus Manager:
        [x] Verify 'Customized Reports' is not visible and 'Plugin Rules' is visible under 'Resources' in side
            navigation.
        [x] Verify 'Agents' option is visible under 'Resources' in side navigation.
        """
        side_nav = SideNav()
        customized_reports_element = side_nav.get_sidenav_element(Nessus.SideNavResources.CUSTOMIZED_REPORTS)
        plugin_rules_element = side_nav.get_sidenav_element(Nessus.SideNavResources.PLUGIN_RULES)
        agents_element = side_nav.get_sidenav_element(Nessus.SideNavResources.AGENTS)

        assert visibility_of_element_located(
            (plugin_rules_element.we_by, plugin_rules_element.we_value))(get_driver_no_init()), \
            "'Plugin Rules' option is not visible in side navigation panel under 'Resources'."

        if get_nessus_type_using_api() == Nessus.Professional.NESSUS_PROFESSIONAL:
            assert visibility_of_element_located(
                (customized_reports_element.we_by, customized_reports_element.we_value))(get_driver_no_init()), \
                "'Customized Reports' option is not visible in side navigation panel under 'Resources'."
        elif get_nessus_type_using_api() == Nessus.Manager.NESSUS_MANAGER:
            assert invisibility_of_element_located(customized_reports_element), \
                "'Customized Reports' option is visible in side navigation panel under 'Resources'."

        assert invisibility_of_element_located(agents_element), "'Agents' option is visible in side navigation " \
                                                                "panel under 'Resources'."

    @pytest.mark.nessus_expert
    def test_visibility_of_options_in_settings(self):
        """
        Scenario Tested:
        
        For Nessus Pro:
        [x] Verify 'SMTP Server' and 'Remote Link' options are visible under 'Settings' in side navigation.
        [x] Verify 'LDAP Server' option is not visible under 'Settings' in side navigation.
        [x] Verify 'Users' option is not visible under 'Accounts' in side navigation.
        
        For Nessus Manager:
        [x] Verify 'SMTP Server' is visible and 'Remote Link' is not visible under 'Settings' in side navigation.
        [x] Verify 'LDAP Server' option is visible under 'Settings' in side navigation.
        [x] Verify 'Users' option is visible under 'Accounts' in side navigation.
        """
        HeaderBasePage().settings_link.click()
        side_nav = SideNav()
        smtp_server_element = side_nav.get_sidenav_element(Nessus.SideNavSettings.SMTP_SERVER)
        remote_link_element = side_nav.get_sidenav_element(Nessus.SideNavSettings.REMOTE_LINK)
        ldap_server_element = side_nav.get_sidenav_element(Nessus.SideNavSettings.LDAP_SERVER)
        users_element = side_nav.get_sidenav_element(Nessus.SideNavAccounts.USERS)

        assert visibility_of_element_located(
            (smtp_server_element.we_by, smtp_server_element.we_value))(get_driver_no_init()), \
            "'SMTP Server' option is not visible in side navigation panel under 'Settings'."

        if get_nessus_type_using_api() == Nessus.Professional.NESSUS_PROFESSIONAL:
            assert visibility_of_element_located(
                (remote_link_element.we_by, remote_link_element.we_value))(get_driver_no_init()), \
                "'Remote Link' option is not visible in side navigation panel under 'Settings'."

            assert invisibility_of_element_located(ldap_server_element), "'LDAP Server' option is visible in side " \
                                                                         "navigation panel under 'Settings'."

            assert invisibility_of_element_located(users_element), \
                "'Users' option is visible in side navigation panel under 'Accounts'."

        elif get_nessus_type_using_api() == Nessus.Manager.NESSUS_MANAGER:
            assert invisibility_of_element_located(remote_link_element), \
                "'Remote Link' option is visible in side navigation panel under 'Settings'."

            assert visibility_of_element_located(
                (ldap_server_element.we_by, ldap_server_element.we_value))(get_driver_no_init()), \
                "'LDAP Server' option is not visible in side navigation panel under 'Settings'."

            assert visibility_of_element_located(
                (users_element.we_by, users_element.we_value))(get_driver_no_init()), \
                "'Users' option is not visible in side navigation panel under 'Accounts'."

    @pytest.mark.nessus_expert
    def test_visibility_of_scanning_host_limit(self):
        """
        Scenario Tested:

        For Nessus Pro:
        [x] Verify 'Scanning Host Limit' label is not visible in product labels.
        
        For Nessus Manager:
        [x] Verify 'Scanning Host Limit' label is visible in product labels.
        """
        overview_page = OverView()
        overview_page.open()
        wait(lambda: overview_page.update_activation_code_tip.is_displayed(), waiting_for='Overview page to load')

        if get_nessus_type_using_api() == Nessus.Professional.NESSUS_PROFESSIONAL:
            assert 'Licensed Hosts' not in overview_page.get_about_page_labels(element=overview_page.product_labels), \
                "'Licensed Hosts' is visible in product labels."
        elif get_nessus_type_using_api() == Nessus.Manager.NESSUS_MANAGER:
            assert 'Licensed Hosts' in overview_page.get_about_page_labels(element=overview_page.product_labels), \
                "'Licensed Hosts' is not visible in product labels."

    @pytest.mark.nessus_expert
    @pytest.mark.parametrize('scan_template', [Nessus.TemplateNames.ADVANCED, Nessus.TemplateNames.SCAP_OVAL])
    def test_visibility_of_elements_in_new_scan_form(self, scan_template):
        """
        Scenario Tested:

        For Nessus Pro:
        [x] Verify 'Live Results' checkbox is visible in scan form while creating new advanced scan.
        [x] Verify 'Show Dashboard' checkbox is not visible in scan form while creating new advanced scan.
        [x] Verify 'Attach Report' toggle is visible in scan form while creating new advanced scan.
        [x] Verify 'Mobile Device Manager' category is not available in Compliance.

        For Nessus Manager:
        [x] Verify 'Live Results' checkbox is not visible in scan form while creating new advanced scan.
        [x] Verify 'Show Dashboard' checkbox is visible in scan form while creating new advanced scan.
        [x] Verify 'Attach Report' toggle is not visible in scan form while creating new advanced scan.
        [x] Verify 'Mobile Device Manager' category is available in Compliance.
        """
        scan_page = ScansPage()
        scan_page.new_scan_button.click()
        scan_page.select_scan_type(type_of_scan=API.Permissions.Types.SCANNER)
        scan_page.click_by_scan(scan_text=scan_template)
        wait(lambda: scan_page.name_field.is_displayed(), waiting_for='Scan form to load')

        if scan_template == Nessus.TemplateNames.ADVANCED:
            if get_nessus_type_using_api() == Nessus.Professional.NESSUS_PROFESSIONAL:
                assert scan_page.is_element_present('live_results'), "'Live Results' checkbox is not visible."

                assert not scan_page.is_element_present('show_dashboard'), "'Show Dashboard' checkbox is visible."

                basic_setting = BasicSetting()
                basic_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                                     link_text=Nessus.Scan.SettingsBasicSubMenu.NOTIFICATIONS)

                assert basic_setting.is_element_present('attach_report_toggle'), \
                    "'Attach Report' toggle is not visible under notification of basic setting."

                assert 'Mobile Device Manager' not in Compliance().get_category_type_list(), \
                    "'Mobile Device Manager' category is available in compliance categories."
            elif get_nessus_type_using_api() == Nessus.Manager.NESSUS_MANAGER:
                assert not scan_page.is_element_present('live_results'), "'Live Results' checkbox is visible."

                assert scan_page.is_element_present('show_dashboard'), "'Show Dashboard' checkbox is not visible."

                basic_setting = BasicSetting()
                basic_setting.click_link_inside_link(setting_value=API.PoliciesSettings.SettingsTypes.BASIC,
                                                     link_text=Nessus.Scan.SettingsBasicSubMenu.NOTIFICATIONS)

                assert not basic_setting.is_element_present('attach_report_toggle'), \
                    "'Attach Report' toggle is visible under notification of basic setting."

                assert 'Mobile Device Manager' in Compliance().get_category_type_list(), \
                    "'Mobile Device Manager' category is not available in compliance categories."
        else:
            scap_form = SCAP()

            assert all([scap_form.is_element_present('linux_scap'), scap_form.is_element_present('linux_oval'),
                        scap_form.is_element_present('windows_scap'), scap_form.is_element_present('windows_oval')]), \
                "'SCAP' and 'OVAL' options for windows and linux are not visible."

    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_create_scan_and_policy_after_tampered_credentials_json(self, create_scan):
        """
        NES-8913: Automated test UI

        Scenario Tested:
        [x] Tampering with credentials.json will not allow user to create or modify scan.
        [x] Tampering with credentials.json will not allow user to create or modify policies.
        """
        scan_page = ScansPage()
        created_scan_name = create_scan
        NewScanForm().save_button.click()
        wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='scan list')
        created_policy = random_name(prefix='Test policy - ')
        create_policy(policy_name=created_policy, flag=True)

        with SSH() as ssh:
            data = ssh.read_from_file(remote_file_path=os.path.join(NESSUS_DATA_DIR, 'templates', 'credentials.json'))

        try:
            tamper_with_data_and_restart_server(
                file_path=path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates', 'credentials.json']), data='abc')

            configure_scan(scan_name=created_scan_name, flag=False)
            wait(lambda: visibility_of_element_located(scan_page.server_error),
                 waiting_for='visibility of error message')

            assert scan_page.server_error.text == '500 - Internal Server Error', \
                'Error message is missing or mismatch while editing existing scan.'

            create_advanced_scan(scan_name=random_name(prefix='Test scan - '), flag=False)
            wait(lambda: visibility_of_element_located(scan_page.server_error),
                 waiting_for='visibility of error message')

            assert scan_page.server_error.text == '500 - Internal Server Error', \
                'Error message is missing or mismatch while creating new scan.'

            create_policy(policy_name=random_name(prefix='Test policy - '), flag=False)
            wait(lambda: visibility_of_element_located(scan_page.server_error),
                 waiting_for='visibility of error message')

            assert scan_page.server_error.text == '500 - Internal Server Error', \
                'Error message is missing or mismatch while creating new policy.'

            edit_policy(policy_name=created_policy, flag=False)
            wait(lambda: visibility_of_element_located(scan_page.server_error),
                 waiting_for='visibility of error message')

            assert scan_page.server_error.text == '500 - Internal Server Error', \
                'Error message is missing or mismatch while editing existing policy.'

            tamper_with_data_and_restart_server(
                file_path=path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates', 'credentials.json']), data=data)

            scan_name = random_name(prefix='Test scan - ')
            create_advanced_scan(scan_name=scan_name, flag=True)
            notifications = Notifications()

            assert notifications.successes[-1] == Messages.NotificationMessages.save_scan, \
                'Success notifications for saving scan is mismatched or missing.'

            ScanList().delete_scan(scan_name=scan_name)
            ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

            NotificationActions().remove_all()
            policy_name = random_name(prefix='Test policy - ')
            create_policy(policy_name=policy_name, flag=True)

            assert notifications.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
                'Success notifications for saving policy is mismatched or missing.'

            PolicyList().delete_policy(policy_name=policy_name)
        finally:
            tamper_with_data_and_restart_server(
                file_path=path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates', 'credentials.json']), data=data)

    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_create_scan_and_policy_after_tampered_restrictions_json(self, create_scan):
        """
        NES-8913: Automated test UI

        Scenario Tested:
        [x] Tampering with restrictions.json will not allow user to create or modify scan.
        [x] Tampering with restrictions.json will not allow user to create or modify policies.
        """
        created_scan_name = create_scan
        NewScanForm().save_button.click()
        wait(lambda: visibility_of_element_located(ScansPage().scan_searchbox))
        notifications = Notifications()

        created_policy = random_name(prefix='Test policy - ')
        create_policy(policy_name=created_policy, flag=True)

        with SSH() as ssh:
            data = ssh.read_from_file(remote_file_path=os.path.join(NESSUS_DATA_DIR, 'templates', 'restrictions.json'))

        try:
            tamper_with_data_and_restart_server(file_path=path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                                   'restrictions.json']), data='abc')

            configure_scan(scan_name=created_scan_name, flag=True)

            assert notifications.errors[-1] == Messages.NotificationMessages.policy_restriction_error, \
                'Error notifications on saving scan is mismatched or missing.'

            NotificationActions().remove_all()
            create_advanced_scan(scan_name=random_name(prefix='Test scan - '), flag=True)

            assert notifications.errors[-1] == Messages.NotificationMessages.policy_restriction_error, \
                'Error notifications on saving scan is mismatched or missing.'

            NotificationActions().remove_all()
            create_policy(policy_name=random_name(prefix='Test policy - '), flag=True)

            assert notifications.errors[-1] == Messages.NotificationMessages.policy_restriction_error, \
                'Error notifications on saving policy is mismatched or missing.'

            edit_policy(policy_name=created_policy, flag=True)

            assert notifications.errors[-1] == Messages.NotificationMessages.policy_restriction_error, \
                'Error notifications on saving policy is mismatched or missing.'

            tamper_with_data_and_restart_server(file_path=path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                                   'restrictions.json']), data=data)

            scan_name = random_name(prefix='Test scan - ')
            create_advanced_scan(scan_name=scan_name, flag=True)

            assert notifications.successes[-1] == Messages.NotificationMessages.save_scan, \
                'Success notifications for saving scan is mismatched or missing.'

            ScanList().delete_scan(scan_name=scan_name)
            ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

            NotificationActions().remove_all()
            policy_name = random_name(prefix='Test policy - ')
            create_policy(policy_name=policy_name, flag=True)

            assert notifications.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
                'Success notifications for saving policy is mismatched or missing.'

            PolicyList().delete_policy(policy_name=policy_name)
        finally:
            tamper_with_data_and_restart_server(file_path=path_join(path_dir_list=[NESSUS_DATA_DIR, 'templates',
                                                                                   'restrictions.json']), data=data)

    @pytest.mark.skip(reason='Failing and needs to be looked at further')
    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_create_scan_and_policy_after_delete_restrictions_json(self, create_scan):
        """
        NES-8913: Automated test UI

        Scenario Tested:
        [x] Delete restrictions.json and updating plugin will allow user to create scans.
        [x] Delete restrictions.json and updating plugin will allow user to create policies.
        """
        try:
            scan_name = create_scan
            NewScanForm().save_button.click()

            delete_template_file(file='restrictions.json')

            restart_server()

            update_plugins_and_restart_server()

            create_advanced_scan(scan_name=scan_name, flag=True)
            notifications = Notifications()

            assert notifications.successes[-1] == Messages.NotificationMessages.save_scan, \
                'Success notifications for saving scan is mismatched or missing.'

            ScanList().delete_scan(scan_name=scan_name)
            ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

            NotificationActions().remove_all()
            policy_name = random_name(prefix='Test policy - ')
            create_policy(policy_name=policy_name, flag=True)

            assert notifications.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
                'Success notifications for saving policy is mismatched or missing.'

            PolicyList().delete_policy(policy_name=policy_name)
        finally:
            update_plugins_and_restart_server()

    @pytest.mark.skip(reason='Failing and needs to be looked at further')
    @pytest.mark.parametrize("create_scan", [{'template_name': Nessus.TemplateNames.ADVANCED,
                                              'scan_type': API.Permissions.Types.SCANNER}], indirect=True)
    def test_create_scan_and_policy_after_delete_credentials_json(self, create_scan):
        """
        NES-8913: Automated test UI

        Scenario Tested:
        [x] Delete credentials.json and updating plugin will allow user to create scans.
        [x] Delete credentials.json and updating plugin will allow user to create policies.
        """
        try:
            scan_name = create_scan
            NewScanForm().save_button.click()

            delete_template_file(file='credentials.json')

            restart_server()

            update_plugins_and_restart_server()

            create_advanced_scan(scan_name=scan_name, flag=True)
            notifications = Notifications()

            assert notifications.successes[-1] == Messages.NotificationMessages.save_scan, \
                'Success notifications for saving scan is mismatched or missing.'

            ScanList().delete_scan(scan_name=scan_name)
            ScansTrashPage().delete_scan_from_trash(scan_name=scan_name)

            NotificationActions().remove_all()
            policy_name = random_name(prefix='Test policy - ')
            create_policy(policy_name=policy_name, flag=True)

            assert notifications.successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
                'Success notifications for saving policy is mismatched or missing.'

            PolicyList().delete_policy(policy_name=policy_name)
        finally:
            update_plugins_and_restart_server()
