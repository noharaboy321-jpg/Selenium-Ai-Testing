""""
Nessus test cases related to Policies main page.

:copyright: Tenable Network Security, 2017
:date: February 14, 2018
:last_modified: Aug 5, 2022
:author: @rdutta, @kpanchal, @krpatel.ctr
"""

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located, \
    visibility_of_element_located

from catium.lib.config import Config
from catium.lib.const import WAIT_SHORT, WAIT_NORMAL
from catium.lib.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.system import is_expert, is_home
from nessus.lib.const import API, Nessus, SortOrder
from nessus.lib.message.messages import Messages
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.header_base import HeaderBasePage
from nessus.pageobjects.header.notifications import Notifications, NotificationActions
from nessus.pageobjects.policies.new_policy_form import PolicyTemplatePage, NewPolicyForm
from nessus.pageobjects.policies.policies_page import PoliciesPage, PolicyList
from nessus.pageobjects.scans.new_scan_form import ScanTemplatePage, ScanType
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav


@pytest.mark.policies_pipeline_3
@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_legacy
@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('login', 'nessus_api_login')
class TestPoliciesMainPage:
    """
    Covers Policies main page related test cases.
    # NQA-1063 : Automation tests for Scans-policies-Main Page.
    """
    cat = None
    @pytest.mark.nessus_smoke
    def test_visibility_of_default_elements_in_policies_page(self):
        """
        Test default elements in policies page.
        1. Login and verify "Policies" tab present under resources in sidenav.
        2. Navigate to "Policies" page and verify page having title ‘Policies’.
        3. Also verify visibility of "Import"/"New Policy" button.
        """
        folder_element = SideNav().get_sidenav_element(element_name=Nessus.SideNavResources.POLICIES)

        assert visibility_of_element_located((folder_element.we_by, folder_element.we_value))(get_driver_no_init()), \
            '"Policies" tab is not visible in sidenav under "Resources".'

        policies_page = PoliciesPage()
        policies_page.open()
        wait(lambda: policies_page.is_element_present("scan_templates_link"),
             waiting_for="policy page gets loaded properly")

        assert policies_page.get_page_heading == Nessus.SideNavResources.POLICIES.split(" ")[0], \
            'You are not in Policies page.'

        assert all([policies_page.import_button.is_displayed(),
                    policies_page.new_policy_button.is_displayed()]), 'All default elements are not visible.'

    def test_visibility_of_create_a_new_policy_link_in_empty_policies_list(self):
        """
        Test "Create a new policy" link is present if no policy listed in policies page.
        1. Navigate to "Policies" page and if no policies are present, then verify empty list showing proper message.
        2. also verify it will have ‘create a new policy’ link.
        """
        policies_page = PoliciesPage()
        policies_page.open()
        wait(lambda: policies_page.is_element_present("scan_templates_link"),
             waiting_for="policy page gets loaded properly")

        if not policies_page.is_element_present("create_a_new_policy_link"):
            policies_page.delete_policies(select_all=True)

        assert PolicyList().object_table.empty_results.text.rsplit(' ', 4)[0] == Messages.NotificationMessages. \
            Policies.empty_policy_list, 'Empty message is missing or mismatched.'

        assert policies_page.create_a_new_policy_link.is_displayed(), '"create a new policy" link is invisible.'

    @pytest.mark.xray(test_key='NES-14020')
    def test_create_new_policy_link(self):
        """
        Test "Create a new policy" link in policies page.
        NES-14020: Verify create new policy link will navigate to policy templates.

        1. Navigate to "Policies" page and click on the ‘Create a new policy’ link
        2. Verify it will take you to the policy template selection page for policy creation.

        Scenario Tested:
        [x] Verify that user redirects to the policy templates after clicking on "Create a new policy" link.
        """
        policies_page = PoliciesPage()
        policies_page.open()
        wait(lambda: policies_page.is_element_present("scan_templates_link"),
             waiting_for="policy page gets loaded properly")

        if not policies_page.is_element_present("create_a_new_policy_link"):
            policies_page.delete_policies(select_all=True)

        policies_page.create_a_new_policy_link.click()
        policy_template_page = PolicyTemplatePage()
        wait(lambda: policy_template_page.is_element_present("search_template_field"),
             waiting_for="policy templates gets loaded")

        assert policy_template_page.get_page_heading == API.Policies.POLICY_TEMPLATE_PAGE_HEADER, \
            'You are not navigated to policy template page.'

        assert get_driver_no_init().current_url.endswith("scans/policies/new"), \
            "User does not redirect to policy templates page after clicking on 'Create a new policy' link."

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED,
                                                API.Permissions.Types.SCANNER)], indirect=True)
    def test_visibility_of_searchbox_with_non_empty_policies_list(self, create_policy):
        """
        Test "policy_searchbox" is present with non empty policies list in policies page.
        1. Navigate to "Policies" page and create at least 1 policy.
        2. Verify that the search box with search icon is present at the top.
        3. Enter some string and verify "search_icon" is invisible and "remove_search" icon visible now.
        4. Clear the search string and verify vice-versa of step 3.
        """
        policy_name = create_policy
        NewPolicyForm().save_button.click()
        LoadingCircle(WAIT_SHORT)

        policies_page = PoliciesPage()
        assert all([policies_page.policies_searchbox.is_displayed(),
                    policies_page.search_icon.is_displayed()]), 'Searchbox with search icon is invisible.'

        policies_page.apply_search_on_policies(search_key=policy_name)
        LoadingCircle(WAIT_SHORT)
        assert all([(not policies_page.search_icon.is_displayed()),
                    policies_page.clear_search_icon.is_displayed()]), \
            'Search_icon is visible and clear_search_icon is invisible.'

        policies_page.clear_search_icon.click()
        LoadingCircle(WAIT_SHORT)
        assert all([policies_page.search_icon.is_displayed(),
                    (not policies_page.clear_search_icon.is_displayed())]), \
            'Search_icon is invisible and clear_search_icon is visible.'

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.WEB_APP,
                                                API.Permissions.Types.SCANNER)], indirect=True)
    def test_clear_selected_item_link(self, create_policy):
        """
        Test "clear_selected_item" link.
        1. Navigate to "Policies" page and create at least 1 policy.
        2. Verify there is no "clear_selected_item" link.
        3. Check the created policy and verify visibility of "clear_selected_item" link.
        4. Click the link and verify policy is unchecked now and also repeat step 2.
        """
        NewPolicyForm().save_button.click()
        LoadingCircle(WAIT_SHORT)
        assert invisibility_of_element_located(
            (By.CSS_SELECTOR, 'a[data-domselect="clear-all"]'))(get_driver_no_init()), \
            '"clear_selected_item" link is visible.'

        policy_list = PolicyList()
        policy_list.select_policies(policies_list=[create_policy])
        LoadingCircle(WAIT_SHORT)

        policies_page = PoliciesPage()
        assert visibility_of_element_located((policies_page.clear_selected_item_link.we_by,
                                              policies_page.clear_selected_item_link.we_value))(get_driver_no_init()), \
            '"clear_selected_item" link is invisible.'

        policies_page.clear_selected_item_link.click()
        assert not policy_list.is_policy_selected(policies_list=[create_policy]), 'Policy(s) are not unchecked yet.'

    def test_invisibility_of_policies_searchbox_in_empty_policies_list(self):
        """
        Test "policy_searchbox" is absent if no policies listed in policies page.
        1. Navigate to "Policies" page
        2. If no policies are present, then policy searchbox should invisible.
        """
        PoliciesPage().open()
        LoadingCircle(WAIT_NORMAL)

        if PolicyList().get_all_policies():
            # pytest.skip('Policies list is not empty, this can be tested only with empty Policies list.')
            pytest.xfail(reason='Policies list is not empty, this can be tested only with empty Policies list.')
        else:
            assert invisibility_of_element_located((By.ID, 'searchbox'))(get_driver_no_init()), \
                'Policy search box is visible.'

    def test_scan_template_link(self):
        """
        Test "scan templates" link in policies page.
        1. Navigate to "Policies" page and click on the ‘scan templates’ link under page description.
        2. Verify it will take you to the Scan template selection page.
        3. Also verify page url as "<host:port>/#/scans/reports/new”
        """
        policies_page = PoliciesPage()
        policies_page.open()
        LoadingCircle(WAIT_NORMAL)

        policies_page.scan_templates_link.click()
        LoadingCircle(WAIT_SHORT)
        assert ScanTemplatePage().get_page_heading == Nessus.Scan.SCAN_TEMPLATE_PAGE_HEADER, \
            'You are not navigated to scan template page.'

        assert get_driver_no_init().current_url == "{}/#/scans/reports/new".format(Config.CAT_URL), \
            'Page URL is mismatched with expected URL.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.FIND_AI, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.BASIC_NETWORK, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.ADVANCED_DYNAMIC, "type": API.Permissions.Types.SCANNER}]}],
                             indirect=True)
    def test_visibility_of_export_and_remove_icon_for_each_listed_policies(self, create_policies):
        """Test visibility of 'export icon' and 'X icon' for each listed policy row."""
        PoliciesPage().open()
        policy_list = PolicyList()
        policy_list.loaded()

        for policy in policy_list.rows:
            if policy.policy_name in create_policies:
                assert all([policy.export.is_displayed(), policy.remove.is_displayed()]), \
                    '"export icon" and "X icon" is invisible.'

    @pytest.mark.parametrize("import_policy", [{"file_name": 'Advanced_all_plugIns_with_compliance.nessus',
                                                "file_path": 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    def test_import_policy(self, import_policy):
        """
        Test to import policy file.
        1. Navigate to "Policies" page and click on "import" button.
        2. Try to upload a file with .nessus extensions.
        3. Verify it should throw you success notification.
        4. Also verify policy is listed in policies list.
        """
        imported_policy_file = import_policy

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policy_import_initiated, \
            'Successful policy import notifications for valid file format is mismatched or missing.'

        policy_list = PolicyList()
        assert imported_policy_file in policy_list.get_all_policies(), \
            'Imported policy is not listed under policies list.'

        policy_list.click_on_policy(policy_name=imported_policy_file)
        policy_form = NewPolicyForm()
        assert policy_form.get_page_heading == "{} / Configuration".format(imported_policy_file), \
            'Imported policy name mismatched.'
        policy_form.back_to_policies.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("import_policy", [{"file_name": 'Basic_Network_Scan_Result.db',
                                                "file_path": 'nessus/tests/ui/scans/test_data/'},
                                               {"file_name": 'NQA_1063_TEXT.txt',
                                                "file_path": 'nessus/tests/ui/scans/test_data/'},
                                               {"file_name": 'NQA_1063.log',
                                                "file_path": 'nessus/tests/ui/scans/test_data/'},
                                               {"file_name": 'NQA_1063_PNG.png',
                                                "file_path": 'nessus/tests/ui/scans/test_data/'},
                                               {"file_name": 'NQA_1063_HTML.html',
                                                "file_path": 'nessus/tests/ui/scans/test_data/'},
                                               {"file_name": 'NQA_1063_CSV.csv',
                                                "file_path": 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    def test_import_policy_with_invalid_file_format(self, import_policy):
        """
        Test to import policy file of different invalid format.
        1. Navigate to "Policies" page and click on "import" button.
        2. Try to upload a file with any other format except .nessus
        3. Verify it should throw you error notification.
        """

        assert Notifications().errors[-1] == Messages.NotificationMessages.Policies.invalid_import_format, \
            'Policy import error notifications for invalid file format is mismatched or missing.'

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)
                                               ], indirect=True)
    def test_create_new_policy(self, create_policy):
        """
        Test to create a new policy.
        1. Navigate to "Policies" page and click on "New Policy" button.
        2. Select a template and fill details, hit "Save".
        3. Verify success notifications.
        4. Verify policy is listed in policies list.
        """
        policy_name = create_policy
        NewPolicyForm().save_button.click()

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policy_saved, \
            'Success notifications for saved policy is mismatched or missing.'

        assert policy_name in PolicyList().get_all_policies(), 'Created policy is not listed in policies list.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.FIND_AI, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.WEB_APP, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.BASIC_NETWORK, "type": API.Permissions.Types.SCANNER,
         "policy_name": "Advance Basic scanner"}]}], indirect=True)
    def test_policies_count_visible_next_to_searchbox_matched_with_policylist_count(self, create_policies):
        """
        Test to match policies count visible next to searchbox in policies page with list value.
        1. Navigate to "Policies" page and create some policies.
        2. Get the count of policies list and verify it is same with the count visible next to searchbox in the page.
        3. Put some search string in searchbox and repeat step 2.
        4. Check some of filtered policies from list and repeat step 2.
        """
        policies_page = PoliciesPage()
        policies_list = PolicyList()
        assert policies_page.get_total_policies_count == len(policies_list.rows), 'Total policies count is mismatched.'

        LoadingCircle(WAIT_SHORT)
        selected_policies = 0
        for policy in policies_list.rows:
            if "Advance" in policy.name.text:
                policy.select.check()
                selected_policies += 1
                LoadingCircle(WAIT_SHORT)

        assert policies_page.get_selected_policies_count == selected_policies, 'Selected policies count is mismatched.'

        policies_page.apply_search_on_policies(search_key="Advanced")
        LoadingCircle(WAIT_SHORT)
        assert policies_page.get_filtered_policies_count == len(policies_list.rows), \
            'Filtered policies count is mismatched.'

        policies_page.clear_search_icon.click()

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER,
         "policy_name": random_name(prefix="Test_create_policy_")},
        {"template_name": Nessus.TemplateNames.FIND_AI, "type": API.Permissions.Types.SCANNER,
         "policy_name": random_name(prefix="Test_policy_")},
        {"template_name": Nessus.TemplateNames.WEB_APP, "type": API.Permissions.Types.SCANNER,
         "policy_name": random_name(prefix="Test_policy_")},
        {"template_name": Nessus.TemplateNames.BASIC_NETWORK, "type": API.Permissions.Types.SCANNER,
         "policy_name": random_name(prefix="Test_policy_")}]}], indirect=True)
    def test_search_policies(self, create_policies):
        """
        Test to searching policies based on both name and template name.
        1. Navigate to "Policies" page.
        2. Enter some string relates to listed policies name
        3. Verify list is updated with the search item as well as the count.
        4. Repeat above 2 steps with policy template name
        """
        search_strings = ["ad", "Advanced", "Test_c"]
        policies_page = PoliciesPage()

        for string_name in search_strings:
            policies_page.apply_search_on_policies(search_key=string_name)
            LoadingCircle(WAIT_SHORT)
            assert policies_page.verify_search_result(search_key=string_name), \
                'Search failed with provided search string.'

        policies_page.clear_search_icon.click()

    @pytest.mark.parametrize("sort", SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize("column_to_sort", ["Name", "Template", "Last Modified"])
    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {"template_name": Nessus.TemplateNames.BASIC_NETWORK, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.FIND_AI, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.HOST_DISCOVERY, "type": API.Permissions.Types.SCANNER}]}], indirect=True)
    def test_sort_policies_list_by_column_values(self, sort, column_to_sort, create_policies):
        """
        Test to sort list column values
        1. Navigate to "Policies" page and create some policies
        2. Click on 'sort' icon on last modified column and verify list should be present in sorted order.
        3. Repeat above for "Name" and "Template" column.
        """
        PoliciesPage().open()
        LoadingCircle(WAIT_NORMAL)
        column_mapping = {"Name": "policy_name",
                          "Template": "policy_template_name",
                          "Last Modified": "policy_last_modified"}
        map_attribute = column_mapping[column_to_sort]

        policies_list = PolicyList()
        expected_policies_list = sorted([getattr(policy, map_attribute) for policy in policies_list.rows],
                                        key=lambda k: k.lower(), reverse=(sort == SortOrder.DESCENDING))

        rendered_policies_list = sort_on_column_values(page_class_instance=policies_list, sort=sort,
                                                       column_name=column_to_sort)
        assert expected_policies_list == [getattr(policy, map_attribute) for policy in rendered_policies_list], \
            '{} is not sorted in {} order.'.format(column_to_sort, sort)

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.FIND_AI, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.BASIC_NETWORK, "type": API.Permissions.Types.SCANNER}]}], indirect=True)
    def test_all_listed_policies_should_listed_as_user_defined_templates(self, create_policies):
        """
        Test all listed policies are present as each different user defined template to create a scan.
        1. Navigate to "Policies" page and click "scan templates" link
        2. Click "user defined" tab.
        3. Verify it has all the policies as template that are present in the policy list.
        """
        LoadingCircle(WAIT_SHORT)
        all_listed_policies = PolicyList().get_all_policies()
        PoliciesPage().scan_templates_link.click()

        scan_type = ScanType()
        scan_type.user_defined_tab.click()
        listed_scan_templates = scan_type.get_all_scan_templates(scan_type=API.Permissions.Types.USER_DEFINED)

        assert all_listed_policies == listed_scan_templates, \
            'All policies are not listed as user defined scan templates.'

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)], indirect=True)
    def test_more_button(self, create_policy):
        """
        Test to verify visibility of "more" button.
        1. Navigate to "Policies" page and create a policy.
        2. Verify "More" button is invisible.
        3. Select one policy from list and verify "More" button is visible now.
        4. Also verify sub-options are visible under more button.
        """
        created_policy_name = create_policy
        NewPolicyForm().save_button.click()
        LoadingCircle(WAIT_SHORT)

        policies_page = PoliciesPage()
        assert not policies_page.more_button.is_displayed(), '"More" button is visible.'

        PolicyList().select_policies(policies_list=[created_policy_name])
        assert visibility_of_element_located((policies_page.more_button.we_by,
                                              policies_page.more_button.we_value))(get_driver_no_init()), \
            '"More" button is invisible.'

        assert not all([policies_page.copy_option.is_displayed(), policies_page.export_option.is_displayed(),
                        policies_page.delete_option.is_displayed()]), \
            '"copy" and "delete" option visible without expanding "More" dropdown.'

        policies_page.more_button.click()
        assert all([policies_page.copy_option.is_displayed(), policies_page.export_option.is_displayed(),
                    policies_page.delete_option.is_displayed()]), \
            '"copy" and "delete" option under "More" dropdown is invisible.'

        policies_page.clear_selected_item_link.click()

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)
                                               ], indirect=True)
    def test_copy_policy(self, create_policy):
        """
        Test to copy a policy.
        1. Navigate to "Policies" page and create a policy.
        2. Select the policy from list and click "copy" option under "More" button.
        4. Verify it will create copy of that policy and both present in the list.
        """
        created_policy_name = create_policy
        NewPolicyForm().save_button.click()
        LoadingCircle(WAIT_NORMAL)
        HeaderBasePage().clear_notification_history()

        PoliciesPage().copy_policies(policy_list=[created_policy_name])

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policy_copied, \
            'Success notifications for copy of policy is mismatched or missing.'

        policy_list = PolicyList()
        assert all([created_policy_name in policy_list.get_all_policies(),
                    "Copy of {}".format(created_policy_name) in policy_list.get_all_policies()]), \
            'Copied policy along with original policy does not exists in policy list.'

        policy_list.delete_policy(policy_name="Copy of {}".format(created_policy_name))

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.FIND_AI, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.BASIC_NETWORK, "type": API.Permissions.Types.SCANNER}]}], indirect=True)
    def test_copy_of_all_policies(self, create_policies):
        """
        Test to copy all policies
        1. Navigate to "Policies" page and create more than one policy
        2. Check the "Select-All" checkbox and click "copy" option under "More" button.
        3. Verify copy of every policy present in the list.
        """
        LoadingCircle(WAIT_NORMAL)
        policy_list = PolicyList()
        listed_policies = policy_list.get_all_policies()

        NotificationActions().remove_all()
        PoliciesPage().copy_policies(select_all=True)

        assert Notifications().successes[-1] == Messages.NotificationMessages.Policies.policies_copied, \
            'Success notifications for copy of more than one policies is mismatched or missing.'

        for policy in listed_policies:
            all_policies = policy_list.get_all_policies()
            assert all([policy in all_policies,
                        "Copy of {}".format(policy) in all_policies]), \
                'All copied policy along with their original policy does not exists in policy list.'

        for policy in policy_list.rows:
            if policy.name.text.startswith("Copy of"):
                policy.remove.click()
                ActionCloseModal().accept_action()
                LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)
                                               ], indirect=True)
    def test_export_policy(self, create_policy):
        """
        Test to export a policy.
        1. Navigate to "Policies" page and create a policy.
        2. Select the policy from list and click "export" option under "More" button.
        4. Click on that will download the file.
        """
        created_policy_name = create_policy
        NewPolicyForm().save_button.click()
        LoadingCircle(WAIT_NORMAL)

        policies_page = PoliciesPage()
        policies_page.open()
        LoadingCircle(WAIT_NORMAL)
        policies_page.export_policy(policy_name=created_policy_name)

        policies_page.clear_selected_item_link.click()
        LoadingCircle(WAIT_SHORT)

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)
                                               ], indirect=True)
    def test_export_policy_through_export_icon_of_corresponding_row(self, create_policy):
        """
        Test to export a policy
        1. Navigate to "Policies" page and create one policy.
        2. Verify export icon is present before X-icon in listed policy.
        3. Click on that will download the file.
        """
        NewPolicyForm().save_button.click()
        PolicyList().export_policy(policy_name=create_policy)
        LoadingCircle(WAIT_NORMAL)

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {"template_name": Nessus.TemplateNames.FIND_AI, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.ADVANCED, "type": API.Permissions.Types.SCANNER}]}], indirect=True)
    def test_invisibility_of_export_option_for_more_than_one_selected_policies(self, create_policies):
        """
        Test to verify invisibility of "export" icon if you have selected more than one policies from the list.
        1. Navigate to "Policies" page and create more than one policy.
        2. Select more than one policy from list and click "More" button.
        3. Verify "export" option is not visible.
        """
        LoadingCircle(WAIT_NORMAL)
        PolicyList().select_policies(policies_list=create_policies)

        policies_page = PoliciesPage()
        policies_page.more_button.click()
        assert invisibility_of_element_located((policies_page.export_option.we_by,
                                                policies_page.export_option.we_value))(get_driver_no_init()), \
            '"Export" option under "More" dropdown is visible.'

    @pytest.mark.parametrize("create_policy", [
        (Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)], indirect=True)
    def test_delete_policy(self, create_policy):
        """
        Test to delete a policy
        1. Navigate to "Policies" page and create one policy
        2. Select the policy from list and click "delete" option under "More" button.
        3. Verify the confirmation pop-up occurs and accept it.
        4. Verify policy will get deleted successfully and list must get updated.
        """
        NewPolicyForm().save_button.click()
        LoadingCircle(WAIT_SHORT)

        PoliciesPage().delete_policies(policy_list=[create_policy])

        assert create_policy not in PolicyList().get_all_policies(), 'Deleted policy exists in policy list.'

    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)
                                               ], indirect=True)
    def test_delete_policy_through_x_icon(self, create_policy):
        """
        Test to delete a policy through "X" icon present in corresponding row
        1. Navigate to "Policies" page and create one policy
        2. Policy should listed in policies list.
        3. Click on X-icon, accept the confirmation pop-up
        4. Verify policy will get deleted successfully and list must get updated.
        """
        NewPolicyForm().save_button.click()
        LoadingCircle(WAIT_SHORT)

        policy_list = PolicyList()
        policy_list.delete_policy(policy_name=create_policy)

        assert create_policy not in policy_list.get_all_policies(), 'Deleted policy exists in policy list.'

    @pytest.mark.parametrize("create_policies", [{'policies_details': [
        {"template_name": Nessus.TemplateNames.BASIC_NETWORK, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.FIND_AI, "type": API.Permissions.Types.SCANNER},
        {"template_name": Nessus.TemplateNames.HOST_DISCOVERY, "type": API.Permissions.Types.SCANNER}]}], indirect=True)
    def test_delete_all_policies(self, create_policies):
        """
        Test to delete all policies
        1. Navigate to "Policies" page and create more than one policy
        2. Check the "Select-All" checkbox and click "delete" option under "More" button.
        3. Verify the confirmation pop-up occurs and accept it.
        4. Verify policies will get deleted successfully and list must get updated.
        """
        LoadingCircle(WAIT_NORMAL)
        PoliciesPage().delete_policies(select_all=True)

        policy_list = PolicyList()
        assert len(policy_list.get_all_policies()) == 0, 'Deleted policy exists in policy list.'

    def test_scanner_tab_scan_template_categories_for_new_policy(self):
        """
        NES-9857 - UI automation for Scan Library Org NES-9820

        Scenarios:
            [x] Verify that scan templates under scanner tab on create policy page are organized in
            three categories "Discovery", "Vulnerabilities" and "Compliance".

        Steps:
        1. Login to Nessus.
        2. Click on "Create New Policy" and go to "scanner" tab.
        3. Verify Scan templates are organized in three categories.
        4. Verify Scan template categories are "Discovery", "Vulnerabilities" and "Compliance".
        5. Verify scan templates list for each scan category.
        6. Verify "Vulnerabilities" category has "Basic Network Scan" and "Advanced Scan" at first two places.
        7. Logout from Nessus.
        """
        policy_page = PoliciesPage()
        policy_page.open()
        wait(lambda: policy_page.is_element_present('policies_searchbox') or policy_page.is_element_present(
            'create_a_new_policy_link'), waiting_for='Policy page to loaded properly')
        policy_page.new_policy_button.click()

        scan_type = ScanType()
        wait(lambda: scan_type.is_element_present('scanner'), waiting_for='Scan templates to load properly')

        category_names = scan_type.get_all_scan_categories_names()

        # Verifying scan templates categories
        assert set(category_names) == set(Nessus.TemplateCategories.SCAN_TEMPLATE_CATEGORIES_LIST), \
            "Scan templates categories are not matching in scanner tab"

        vulnerabilities_scan_list = scan_type.get_scan_templates_list_for_given_category(
            category_name=Nessus.TemplateCategories.VULNERABILITIES)

        # Verifying scan templates list for "Discovery"
        if is_expert():
            assert set(scan_type.get_scan_templates_list_for_given_category(
                category_name=Nessus.TemplateCategories.DISCOVERY)) == set(
                Nessus.TemplateNames.SCAN_DISCOVERY_TEMPLATE_LIST_EXPERT), "Scan template list for 'Discovery' is not matching"
        else:
            assert set(scan_type.get_scan_templates_list_for_given_category(
                category_name=Nessus.TemplateCategories.DISCOVERY)) == set(
                Nessus.TemplateNames.SCAN_DISCOVERY_TEMPLATE_LIST), "Scan template list for 'Discovery' is not matching"

        # Verifying scan templates list for "Vulnerabilities"
        if is_home():
            assert set(vulnerabilities_scan_list) == set(Nessus.TemplateNames.SCAN_VULNERABILITIES_TEMPLATE_LIST_HOME), \
                "Scan template list for 'Vulnerabilities' is not matching"
        else:
            assert set(vulnerabilities_scan_list) == set(Nessus.TemplateNames.SCAN_VULNERABILITIES_TEMPLATE_LIST), \
                "Scan template list for 'Vulnerabilities' is not matching"

        # Verifying scan templates list for "Compliance"
        assert set(scan_type.get_scan_templates_list_for_given_category(
            category_name=Nessus.TemplateCategories.COMPLIANCE)) == set(
            Nessus.TemplateNames.SCAN_COMPLIANCE_TEMPLATE_LIST), "Scan template list for 'Compliance' is not matching"

        # Verify that "Vulnerabilities" category has "Basic Network Scan" and "Advanced Scan" at first two places.
        assert vulnerabilities_scan_list[0] == Nessus.TemplateNames. \
            BASIC_NETWORK and vulnerabilities_scan_list[1] == Nessus.TemplateNames.CREDENTIAL_VALIDATION, \
            "First two scan templates for vulnerabilities are not 'Basic Network Scan' and 'Credential validation'"
