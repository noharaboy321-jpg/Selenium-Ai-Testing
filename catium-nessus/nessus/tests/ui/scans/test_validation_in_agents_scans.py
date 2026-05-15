"""
Nessus test cases related to agents scans

:copyright: Tenable Network Security, 2018
:date: Jun 05, 2018
:last modified: July 05, 2022
:author: @rdutta, @jchavda, @kpanchal, @krpatel
"""

import pytest

from catium.lib.const import WAIT_SHORT, WAIT_NORMAL
from catium.lib.const.base_constants import TIME_THREE_SECONDS
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.scan import delete_created_scan
from nessus.lib.const import API, Nessus, random_name, Prefixes
from nessus.lib.message.messages import Messages
from nessus.pageobjects.agents.agent_group_page import AgentGroupsList, AgentGroupsPage, CreateGroupWindowPage
from nessus.pageobjects.generic.generic_modals import UnsavedChangesModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.scans.new_scan_form import ScanType, NewScanForm
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.scap.scap_page import ScapAndOvalForm
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
@pytest.mark.parametrize("create_agent_groups", [{'agent_group_details': [
    {'agent_group_name': Prefixes.AGENT_GROUP}]}], indirect=True)
class TestValidationOnAgentScan:
    """
    Covers test cases related to validations of agent scans
    #NQA-1267: Automation tests for creation and editing of Scans – Agent templates.
    """

    def test_visibility_of_elements_for_agent_scan_page(self, create_agent_groups):
        """
        Test to verify default elements for all agent scan templates
        1. Verify that /scans/reports/new” url will navigate to policy template page and will consist of Agent tab.
        2. Verify that on clicking the agent tab, five templates list will be present (Advanced Agent San,
           Basic Agent Scan, Malware Scan, Policy Compliance Auditing, SCAP and Oval Agent Auditing ).
        """
        HeaderBasePage().scan_link.click()

        SideNav().click_by_link_text(Nessus.Scan.Folder.MY_SCANS)
        LoadingCircle(WAIT_NORMAL)

        scan_page = ScansPage()
        scan_page.new_scan_button.click()
        scan_type = ScanType()
        scan_type.select_scan_type(type_of_scan=Nessus.Scan.ScanTemplateTabs.AGENT_TAB)
        assert '/scans/reports/new' in scan_page.current_url, 'Scan template page is not opened'
        assert set(scan_type.get_all_scan_templates(
            scan_type=API.Permissions.Types.AGENT)) == set(Nessus.TemplateNames.AGENT_TEMPLATE_LIST), \
            'All templates are not present in Agent Tab'

    @pytest.mark.parametrize("scan_template", Nessus.TemplateNames.AGENT_TEMPLATE_LIST)
    def test_required_fields_for_agents_scan(self, scan_template, create_agent_groups):
        """
        Test to verify required elements for all agent scan templates
        3. Verify that on clicking every template, form page open and each template have a required name
           and Agent group field.
        4. Verify that on providing the name and saving scan will give an error “Error: Agent Group is required.”
        """
        agent_group = create_agent_groups[0]
        HeaderBasePage().scan_link.click()

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)
        scan_page = ScansPage()
        scan_page.create_new_scan(scan_template=scan_template, scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                                  scan_name='')

        # Each template have a required name and Agent group field.
        LoadingCircle(WAIT_SHORT)

        assert scan_page.name_field.is_displayed() and scan_page.name_field.get_attribute('aria-required'), \
            'Required name field is not displayed.'

        assert scan_page.group_required_badge.is_displayed(), 'Agent group Required badge is not present on ui'

        scan_page.save_button.click()

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scans.required_scan_name, \
            'Validation Error is not displayed for Name'

        LoadingCircle(WAIT_NORMAL)
        NotificationActions().remove_all()
        scan_page.name_field.value = "agent_scan"
        scan_page.save_button.click()

        # Saving scan will give an error “Error: Agent Group is required if Agent group is None

        assert Notifications().errors[-1] == Messages.NotificationMessages.Scans.required_agent_group, \
            'Validation Error is not displayed for Agent group'

        scan_page.select_agent_group.select_by_visible_text(agent_group)
        scan_page.save_button.click()
        LoadingCircle(WAIT_NORMAL)
        AgentGroupsPage().open()

    @pytest.mark.parametrize("scan_template", Nessus.TemplateNames.AGENT_TEMPLATE_LIST)
    def test_agent_group_and_scan_window_field(self, create_agent_groups, scan_template):
        """
        Test to verify agents related elements for all agent scan templates
        5. Verify that Agent Groups field is a dropdown and contain all the created agent groups list as option
           as well a link ‘add agent group’, clicking on the link will navigate to URL “scans/agent-groups”.
        6. Verify that in the form group exist “Scan window” field and it contains a drop-down as well as pen icon with
           tool tip ‘Custom Scan window’. Click on the custom icon will change the drop-down
           to minute field with 60 default value and X-icon.
        """
        AgentGroupsPage().open()
        LoadingCircle(WAIT_NORMAL)
        group_list = AgentGroupsList().get_all_groups()
        LoadingCircle(WAIT_SHORT)
        HeaderBasePage().scan_link.click()

        SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
        LoadingCircle(WAIT_NORMAL)
        scan_page = ScansPage()
        scan_page.create_new_scan(scan_template=scan_template, scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                                  scan_name=random_name(prefix=scan_template), add_configuration=True)

        group_dropdown = scan_page.get_agent_group_list()
        group_dropdown.remove('Shared\nAdd an Agent Group')

        #  Verify ‘Agent Groups’ drop-down contains all the created agent groups list
        assert group_list == group_dropdown, 'All agent group are not present in Agent groups list'

        # Check URL after click on Add An Agent Group
        assert scan_page.select_agent_group.get_attribute('data-type') == 'multi_select', \
            'Agent group field is not drop down'

        scan_page.select_agent_group.select_by_visible_text('Add an Agent Group')
        assert 'sensors/agent-groups' in scan_page.current_url, 'Agent group page is not opened'

        # Check Scan window is present
        scan_page.back()
        LoadingCircle(WAIT_SHORT)
        assert scan_page.is_element_present('select_scan_window'), 'Scan window element is not present'

        # Check Tooltip
        scan_page.move_to_element(scan_page.custom_scan_window)
        assert scan_page.get_custom_scan_tooltip() == 'Custom Scan Window', 'Tooltip is not displayed '

        # Check Default value of scan window, minute field with 60 default value.
        scan_page.custom_scan_window.click()
        assert all([(int(scan_page.scan_window_textfield.value) == 60),
                    scan_page.scan_window_description.text == 'minutes']), 'Default Value of Scan window is different'

    @pytest.mark.parametrize("scan_template", Nessus.TemplateNames.AGENT_TEMPLATE_LIST)
    def test_default_values_for_all_agents_scan_templates(self, create_agent_groups, scan_template):
        """
        Test to verify defaults values for all agent scan templates
        7. Verify that Dashboard and Folder field in scan agent form are dropdown fields. Dashboard dropdown
        will contain two options enabled and disabled with disabled as default value,  whereas folder dropdown must
        contain the entire folder list including Trash and My Scans with My Scans as a default value.
        """
        HeaderBasePage().scan_link.click()

        side_nav = SideNav()
        folders = side_nav.get_all_sidenav_folders_name()
        folders.remove('All Scans')

        side_nav.get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        scan_page = ScansPage()
        scan_page.create_new_scan(scan_template=scan_template, scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB,
                                  scan_name=random_name(prefix=scan_template), add_configuration=True)

        # Check Dashboard drop down list and default value
        assert scan_page.select_dashboard.get_attribute('data-type') == 'checkbox', 'Dashboard field is not drop down'
        assert not scan_page.select_dashboard.is_selected(), 'Default value is different'

        # Check Folder drop down list and default value
        assert scan_page.select_folder.get_attribute('data-type') == 'select', 'Folder field is not drop down'
        assert scan_page.select_folder.get_text_selected() == 'My Scans', 'Default value of Folder is different'

        # below sort is applied as folder list while creating scan comes in sorted order
        folders.sort()
        LoadingCircle(WAIT_SHORT)
        scan_page.select_folder.click()
        assert scan_page.get_folder_db_dropdown_value(scan_page.select_folder) == folders, \
            'All folder are not present in list'

    @pytest.mark.parametrize("scan_template", Nessus.TemplateNames.AGENT_TEMPLATE_LIST)
    def test_save_cancel_button_for_all_agents_scan_templates(self, create_agent_groups, scan_template):
        """
        Test to verify  action elements for all agent scan templates
        8. Verify that on clicking any template, scan form page will open and it will have ’Save’ and ‘Cancel’
        button. ‘Launch’ as an option is present under Save button.
        9. Verify that clicking on ‘Cancel’ button present on form page will re-direct to url ‘/scans/reports/new’
        without saving any data.
        """
        HeaderBasePage().scan_link.click()

        SideNav().get_sidenav_element(element_name=Nessus.Scan.Folder.MY_SCANS).click()
        scan_template_type_page = ScanType()
        scan_template_type_page.open()
        LoadingCircle(WAIT_NORMAL)

        scan_template_type_page.select_scan_type(type_of_scan=Nessus.Scan.ScanTemplateTabs.AGENT_TAB)
        LoadingCircle(TIME_THREE_SECONDS)
        scan_template_type_page.click_by_scan(scan_text=scan_template)
        LoadingCircle(TIME_THREE_SECONDS)

        scan_form = NewScanForm()
        assert all([scan_form.save_button.is_displayed(), scan_form.cancel_button.is_displayed()]), \
            "'Save' and 'Cancel' buttons are not visible for {} template.".format(scan_template)

        scan_form.save_action_dropdown.click()
        assert scan_form.launch_option.is_displayed(), "launch option is not present under Save action drop-down."

        scan_form.cancel_button.click()
        assert "/scans/reports/new" in get_driver_no_init().current_url, \
            "New Scan form page is not re-directed to 'Scans' page after clicking on 'Cancel' button."


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestValidatePreRequisiteForAgentScan:
    """ NQA-1292 : Test to validate warning pop-up while creating agents scan."""

    @pytest.mark.parametrize("scan_template", Nessus.TemplateNames.AGENT_TEMPLATE_LIST)
    def test_warning_pop_up_while_creating_agent_scan(self, scan_template):
        """
        Pre-requisite: No agent group should listed in agent_groups tab under 'Agents' page
        1. Navigate to 'agent' tab in scan_template page for creating a scan
        2. Hit 'Advanced Agent Scan' template.
        3. Verify pop-up opened up and asking you to create an agent-group
        4. Hit the pop-up and it should take you to the agent-group page, verify url (/#/scans/agent-groups).
        5. Create an agent group and verify now it allow you to create an agent scan without throwing any pop-up alert.
        6. Repeat above steps for all other agent scan templates.
        """
        agent_group_window_page = CreateGroupWindowPage()
        agent_group_window_page.open()
        LoadingCircle(WAIT_NORMAL)

        # Check Agent group list and Skip the test if any agent-group already exists
        group_list = AgentGroupsList()
        if group_list.get_all_groups():
            pytest.xfail('Cannot check the warning pop-up as one or more agent group already exists.')

        group_name = random_name(prefix='NQA-1292-AgentGroup-')

        scan_template_page = ScanType()
        scan_template_page.open()
        LoadingCircle(TIME_THREE_SECONDS)
        scan_template_page.agent.click()
        scan_template_page.click_by_scan(scan_text=scan_template)
        LoadingCircle(WAIT_SHORT)

        # Verify pop-up opened up and asking you to create an agent-group
        modal_window = UnsavedChangesModal()
        assert all([modal_window.is_element_present('modal'),
                    modal_window.unsaved_changes_title.text == 'No Agent Groups']), 'Agent group pop-up is invisible'

        modal_window.action_button.click()
        LoadingCircle(TIME_THREE_SECONDS)
        assert 'sensors/agent-groups' in get_driver_no_init().current_url, 'Agent group page is not opened'

        # Create an agent group and verify now it allows you to create an agent scan without throwing any pop-up alert.
        agent_group_window_page.create_group(group_name=group_name)
        scan_template_page.open()
        scan_template_page.agent.click()
        scan_template_page.click_by_scan(scan_text=scan_template)
        assert not modal_window.is_element_present('modal'), 'Agent group pop-up is visible'

        scan_form = NewScanForm()
        scan_name = random_name(prefix="{} - ".format(scan_template))
        scan_form.fill_new_scan_detail(scan_name=scan_name, agent_group=group_name)
        if scan_template == Nessus.TemplateNames.SCAP_OVAL_AGENT:
            scap_page = ScapAndOvalForm()
            scap_page.open_form_and_fill_details(form_information=[
                {'count_of_forms': 1, 'form_type': API.Scap.Types.WINDOWS_OVAL,
                 'form_details': [{'definition_file_name': 'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
                                   'definition_file_path': 'nessus/tests/api/scan/test_data/'}]}])
        scan_form.save_button.click()
        LoadingCircle(TIME_THREE_SECONDS)
        assert scan_name in ScanList().get_all_scans(), 'Scan name is not available in scan list'

        # Delete Created Scan and Agent group.
        delete_created_scan(scan_name=scan_name)
        agent_group_window_page.open()
        group_list.delete_group(group_name)
        LoadingCircle(WAIT_NORMAL)
        assert group_name not in group_list.get_all_groups(), '{} is not deleted'.format(group_name)


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login')
class TestAgentScanTemplateCategories:
    """Testcases related to Scan Library Org"""

    def test_agent_tab_scan_template_categories_for_new_scan(self):
        """
        NES-9857 - UI automation for Scan Library Org NES-9820

        Scenarios:
            [x] Verify that scan templates under agent tab are organized in two categories
            "Discovery" and "Vulnerabilities".

        Steps:
        1. Login to Nessus.
        2. Click on "My Scan" and go to "Agent" tab.
        3. Verify Scan templates are organized in two categories.
        4. Verify Scan template categories are "Discovery" and "Vulnerabilities".
        5. Verify scan templates list for both scan category.
        6. Verify "Vulnerabilities" category has "Basic Agent Scan" and "Advanced Agent Scan" at first two places.
        7. Logout from Nessus.
        """

        scan_page = ScansPage()

        # create new scan by clicking on 'New Scan' button on scan page
        scan_page.new_scan_button.click()
        wait(lambda: scan_page.is_element_present('scanner'), waiting_for='Scan templates to load properly')

        scan_page.select_scan_type(type_of_scan=Nessus.Scan.ScanTemplateTabs.AGENT_TAB)

        category_names_agents = scan_page.get_all_scan_categories_names()

        # Verifying scan templates categories
        assert set(category_names_agents) == set(Nessus.TemplateCategories.AGENT_TEMPLATE_CATEGORIES_LIST), \
            "Scan templates categories are not matching in agent tab"

        agent_vulnerabilities_scan_list = scan_page.get_scan_templates_list_for_given_category(
            category_name=Nessus.TemplateCategories.VULNERABILITIES,
            scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB.lower())

        # Verifying scan templates list for "Vulnerabilities"
        assert set(agent_vulnerabilities_scan_list) == set(Nessus.TemplateNames.AGENT_VULNERABILITIES_TEMPLATE_LIST), \
            "Scan template list for 'Vulnerabilities' is not matching"

        # Verifying scan templates list for "Compliance"
        assert set(scan_page.get_scan_templates_list_for_given_category(
            category_name=Nessus.TemplateCategories.COMPLIANCE,
            scan_type=Nessus.Scan.ScanTemplateTabs.AGENT_TAB.lower())) == set(
            Nessus.TemplateNames.AGENT_COMPLIANCE_TEMPLATE_LIST), "Scan template list for 'Compliance' is not matching"

        # Verify that "Vulnerabilities" category has 'Basic Agent Scan' and 'Advanced Agent Scan' at first two places.
        assert agent_vulnerabilities_scan_list[0] == Nessus.TemplateNames. \
            BASIC_AGENT and agent_vulnerabilities_scan_list[1] == Nessus.TemplateNames.ADVANCED_AGENT, \
            "First two scan templates for vulnerabilities are not 'Basic Agent Scan' and 'Advanced Scan'"
