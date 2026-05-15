"""
Nessus test cases related to Customized Reports page.

:copyright: Tenable Network Security, 2021
:date: Aug 26, 2021
:last_modified: Sept 23, 2021
:author: @kpanchal.ctr, @vsoni.ctr
"""
import random
import re
from random import randint

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import invisibility_of_element_located
from selenium.webdriver.support.expected_conditions import visibility_of_element_located
from waiting import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const.base_constants import WAIT_NORMAL, WAIT_SHORT
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.wait import wait
from nessus.helpers.scan import revert_save_as_default_option_to_system
from nessus.helpers.sort import sort_on_column_values
from nessus.helpers.system import is_pro, is_home
from nessus.helpers.utility import get_downloaded_files_chrome
from nessus.lib.const import Nessus, API
from nessus.lib.const import SortOrder
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import HostsList
from nessus.pageobjects.customized_reports.customized_reports import CustomizedReportsPage, NewReportTemplateForm, \
    TemplateReportChapter, ReportTemplateList
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.header.notifications import Notifications
from nessus.pageobjects.scans.scan_view_page import ScanViewPage, ScanExportPage
from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.pageobjects.sidenav.sidenav import SideNav

log = create_logger()


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('login', 'nessus_api_login')
class TestCustomizedReportsPage:
    """ Covers customized reports page related test cases """

    cat = None
    report_chapter = Nessus.CustomizedReports
    format_constant = API.Scan.UIExportFormats

    @staticmethod
    def verify_invisibility_of_dynamic_web_elements(chapter: str, locator_value: str) -> None:
        """
        Verifies invisibility of web elements in given chapter for given locator value

        :param str chapter: chapter name in which invisibility to be check
        :param str locator_value: dynamic web element locator value
        :return: None
        """
        if locator_value in ['scan', 'host']:
            data_key = '{}_information'.format(locator_value)

            locator_value = '//div[contains(text(), "{}")]/parent::div/following::div[1]//div[' \
                            'contains(@data-key, "{}")]/div[contains(@class, "option-checkbox")]'. \
                format(chapter, data_key)

        assert invisibility_of_element_located((By.XPATH, locator_value))(get_driver_no_init()), \
            "Configurable options are getting displayed for '{}' chapter which should not be.".format(
                chapter)

    def create_custom_report_template(self, template_name: str, template_description: str = "",
                                      all_chapters: bool = False) -> None:
        """
        Creates new custom report template with given template name and description

        :param str template_name: Report template name
        :param str template_description: Report template description
        :param bool all_chapters: True if need to add all chapters else False
        :return: None
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()

        custom_report_page.new_report_template_button.click()
        new_report_template_form = NewReportTemplateForm()
        wait(lambda: new_report_template_form.is_element_present("template_name_field"),
             waiting_for="Report template form get loaded")

        new_report_template_form.template_name_field.value = template_name
        new_report_template_form.template_description_area.value = template_description
        all_report_chapters = self.report_chapter.CHAPTER_LIST
        chapter_list = all_report_chapters if all_chapters else random.sample(all_report_chapters, k=3)

        for chapter in chapter_list:
            new_report_template_form.add_chapter_button.click()

            add_chapter_modal = ActionCloseModal()
            wait(lambda: add_chapter_modal.is_element_present("modal"),
                 waiting_for="'Add a Report Chapter' modal get displayed")

            TemplateReportChapter().get_element_of_select_chapter(chapter_name=chapter).click()
            add_chapter_modal.action_button.click()

        new_report_template_form.save_template_button.click()
        wait(lambda: custom_report_page.is_element_present("search_report_template_field"),
             waiting_for="Custom report template list gets loaded")

    def delete_custom_report_template(self, template_name: str = "") -> None:
        """
        Deletes custom report template of given template name from report template lists

        :param str template_name: custom report template name that to be deleted
        :return: None
        """
        custom_report_templates = self.cat.api.reports.get_report_templates()

        if template_name:
            template_ids = [template['id'] for template in custom_report_templates if template['name'] == template_name]
        else:
            template_ids = [template['id'] for template in custom_report_templates if template['system'] == 0]

        for template_id in template_ids:
            self.cat.api.reports.delete_custom_template(template_id=template_id)

    def test_verify_report_template_tab_elements_visibility(self):
        """
        NES-13386 : Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation
        Scenario Tested:
            [x] Verify that below required elements on report template tab are visible
                -  Report Template Logo icon
                -  Page title header
                - 'Report Templates' tab (and focused)
                - 'Name and Logo' tab (Visible for Nessus 'Pro' and not visible for 'Manager')
                -  New 'Report Templates' button
                -  Tab description
                -  Search template place holder
                -  Total templates count
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()
        wait(lambda: custom_report_page.is_element_present('new_report_template_button'),
             waiting_for="customized report page to get loaded")
        assert custom_report_page.page_title_in_header.text == "Customized Reports", \
            "Report Template page header is incorrect."
        assert custom_report_page.is_element_present('report_templates_tab'), \
            "'Report Templates' tab is not visible on customized reports page."
        if is_pro():
            assert custom_report_page.is_element_present('name_and_logo_tab'), \
                "'Name and Logo' tab is not visible in customized reports page for 'Nessus Professional'."
        else:
            assert not custom_report_page.is_element_present('name_and_logo_tab'), \
                "'Name and Logo' tab is not visible in customized reports page for 'Nessus Manager'."
        assert custom_report_page.is_element_present('new_report_template_button'), \
            "'New Report Template' tab is not visible in customized reports page."
        assert custom_report_page.is_element_present('report_template_logo'), \
            "Report Template logo is not visible in customized reports page."
        assert custom_report_page.report_templates_description.text == "You can manage your report templates here.", \
            "'Report Templates' tab description is incorrect."
        assert custom_report_page.report_templates_tab.get_attribute('class') == "on", \
            "'Report Templates' tab is not focused by default."
        assert custom_report_page.template_search_box.get_attribute('placeholder') == 'Search Report Templates', \
            "Search box for report templates has incorrect tooltip."
        assert len(ReportTemplateList().get_all_templates()) == int(custom_report_page.total_templates_count.text), \
            "Report templates count besides search box is incorrect."

    @pytest.mark.parametrize("create_custom_template",
                             [[{"id": "remediations", "option_values": {}},
                               {"id": "compliance", "option_values": {}}]], indirect=True)
    def test_verify_report_templates_table(self, create_custom_template):
        """
        NES-13386 : Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation
        Scenario Tested:
            [x] Verify that report template table is populated correctly.
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()
        wait(lambda: custom_report_page.is_element_present('new_report_template_button'),
             waiting_for="customized report page to get loaded")
        report_templates_list = ReportTemplateList()
        assert [column_name.text for column_name in report_templates_list.columns if
                column_name.text != ""] == Nessus.SystemReportTemplates.TemplatesTable.ALL_COLUMNS, \
            "Report Template column names or column order is incorrect."

        # Verify that report templates table is populated correctly.
        for row in report_templates_list.rows:
            assert row.template_name != "Template name is empty."
            assert row.template_type in [Nessus.SystemReportTemplates.TemplateType.SYSTEM,
                                         Nessus.SystemReportTemplates.TemplateType.CUSTOM], \
                "Template type is incorrect."
            if row.template_type == 'System':
                assert not row.remove_icon_displayed, "Remove icon is present even though for 'System' template."
                assert row.template_last_modified == "N/A", "Last modified time for system template is not 'N/A'"
            else:
                assert row.remove_icon_displayed, "Remove icon is not present for 'Custom' report template."
                assert re.search(r' at \d{1,2}[:]\d{1,2} [AP]M', row.template_last_modified), \
                    "Last modified time for custom report template is displayed in incorrect format."

    def test_verify_new_report_template_button_is_functioning(self):
        """
        NES-13401 [Automation]: Verify "New Report Template" button is clickable and it will open a blank template
                                with various customization options

        Scenario Tested:
        [x] Verify that "New Report Template" button is visible and clickable.
        [x] Verify that user can navigate to blank template with various customization options after clicking on
            "New Report Template" button.
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()

        assert all([custom_report_page.new_report_template_button.is_displayed(),
                    custom_report_page.new_report_template_button.is_enabled()]), \
            "'New Report Template' is either missing or not clickable on Customized Reports page"

        custom_report_page.new_report_template_button.click()
        new_report_template_form = NewReportTemplateForm()
        wait(lambda: new_report_template_form.is_element_present("template_name_field"),
             waiting_for="Report template form get loaded")

        for element in ["template_name_field", "template_description_area", "add_chapter_button",
                        "save_template_button", "cancel_button"]:
            assert new_report_template_form.is_element_present(element_name=element), \
                "User does not navigate to 'New Report Template' form or '{}' is missing in new report template form."

    def test_verify_add_a_chapter_button_is_functioning(self):
        """
        NES-13402 [Automation]: Verify that user is able to add new chapter by clicking "Add a Chapter" button

        Scenario Tested:
        [x] Verify that "Add a Chapter" button is visible and clickable.
        [x] Verify that user can select a chapter from available chapter list displayed in "Add a Report Chapter" modal.
        """
        template_name = random_name(prefix="Report_template-")

        try:
            custom_report_page = CustomizedReportsPage()
            custom_report_page.open()

            custom_report_page.new_report_template_button.click()
            new_report_template_form = NewReportTemplateForm()
            wait(lambda: new_report_template_form.is_element_present("template_name_field"),
                 waiting_for="Report template form get loaded")

            new_report_template_form.template_name_field.value = template_name

            assert all([new_report_template_form.add_chapter_button.is_displayed(),
                        new_report_template_form.add_chapter_button.is_enabled()]), \
                "'Add a Chapter' is either missing or not clickable in new report template form."

            new_report_template_form.add_chapter_button.click()
            add_chapter_modal = ActionCloseModal()
            wait(lambda: add_chapter_modal.is_element_present("modal"),
                 waiting_for="'Add a Report Chapter' modal get displayed")

            report_chapter_modal = TemplateReportChapter()
            chapter_constant = self.report_chapter.ReportChapters

            assert all([add_chapter_modal.is_element_present("modal_title"),
                        add_chapter_modal.modal_title.text == chapter_constant.ADD_CHAPTER_MODAL_TITLE,
                        report_chapter_modal.is_element_present("add_report_chapter_modal_content"),
                        add_chapter_modal.is_element_present("action_button"),
                        add_chapter_modal.is_element_present("cancel_button")]), \
                "'Add a Report chapter' modal is not getting displayed properly."

            chapter_desc_dict = self.report_chapter.CHAPTER_DESCRIPTION_DICT
            chapter_list = list(chapter_desc_dict.keys())

            for chapter in chapter_list:
                report_chapter_modal.get_element_of_select_chapter(chapter_name=chapter).click()

                assert report_chapter_modal.chapter_description.text == chapter_desc_dict[chapter], \
                    "Report chapter description for '{}' is either missing or incorrect.".format(chapter)

            template_to_be_select = random.sample(chapter_list, k=1)[0]
            report_chapter_modal.get_element_of_select_chapter(chapter_name=template_to_be_select).click()
            add_chapter_modal.cancel_button.click()

            assert not add_chapter_modal.is_element_present("modal"), \
                "'Add a Report Chapter' modal is still present after clicking on 'Cancel' button."

            assert new_report_template_form.empty_chapter.text == chapter_constant.EMPTY_CHAPTER_MESSAGE, \
                "Report chapter is getting added even after click on 'Cancel' button from 'Add a Report Chapter' modal."

            new_report_template_form.add_chapter_button.click()
            report_chapter_modal.get_element_of_select_chapter(chapter_name=template_to_be_select).click()
            add_chapter_modal.action_button.click()
            new_report_template_form.save_template_button.click()

            assert Notifications().successes[-1] == Messages.NotificationMessages.CustomizedReports. \
                REPORT_TEMPLATE_SAVED, "Success message for saving scan is mismatched or missing."

            wait(lambda: custom_report_page.is_element_present("search_report_template_field"),
                 waiting_for="Custom report templates list gets loaded properly")

            assert template_name in ReportTemplateList().get_all_templates(), "Failed to create custom report template."
        finally:
            self.delete_custom_report_template(template_name=template_name)

    @pytest.mark.parametrize("create_custom_template", [
        [{"id": "remediations", "option_values": {}}, {"id": "compliance", "option_values": {}}]], indirect=True)
    def test_verify_user_can_remove_added_chapters_from_report(self, create_custom_template):
        """
        NES-13403 [Automation]: Verify user is able to remove chapter by clicking 'X'

        Scenario Tested:
        [x] Verify that user should be able to remove added chapters form report.
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()

        ReportTemplateList().click_on_report_template(template_name=create_custom_template['template_name'])

        new_report_template_form = NewReportTemplateForm()
        wait(lambda: new_report_template_form.is_element_present("template_name_field"),
             waiting_for="Report template form get loaded")

        chapter_value = random.sample([chapter['id'] for chapter in create_custom_template['chapters']], k=1)[0]
        chapter_name = [name for name, value in self.report_chapter.CHAPTERS_DICT.items() if value == chapter_value][0]
        new_report_template_form.get_element_of_delete_chapter(chapter_name=chapter_name).click()

        delete_chapter_modal = ActionCloseModal()
        chapter_constant = self.report_chapter.ReportChapters

        assert all([delete_chapter_modal.modal_title.text == chapter_constant.DELETE_CHAPTER_MODAL_TITLE,
                    delete_chapter_modal.modal_content.text == chapter_constant.DELETE_CHAPTER_WARNING,
                    delete_chapter_modal.is_element_present("action_button"),
                    delete_chapter_modal.is_element_present("cancel_button")]), \
            "'Delete chapter' modal is not getting displayed properly."

        delete_chapter_modal.cancel_button.click()

        assert not delete_chapter_modal.is_element_present("modal"), \
            "'Delete Chapter' modal is still present after clicking on 'Cancel' button."

        assert chapter_name in new_report_template_form.get_added_chapters_name(), \
            "'{}' chapter gets deleted after clicking on 'Cancel' button from 'Delete Chapter' modal.".format(
                chapter_name)

        new_report_template_form.get_element_of_delete_chapter(chapter_name=chapter_name).click()
        delete_chapter_modal.action_button.click()
        delete_chapter_modal.wait_for_modal_closed()

        assert chapter_name not in new_report_template_form.get_added_chapters_name(), \
            "Unable to delete '{}' chapter from report template form.".format(chapter_name)

    def test_verify_user_can_create_custom_report_template(self):
        """
        NES-13405 [Automation]: Verify user is able to save custom report successfully and redirected back to
                                'Report Templates' table

        Scenario Tested:
        [x] Verify that User can create custom report template successfully.
        [x] Verify that saved template must be displayed in the template table under 'Report Templates' tab with
            'Custom' template type.
        """
        template_name = random_name(prefix="Report_template-")

        try:
            self.create_custom_report_template(template_name=template_name)

            assert Notifications().successes[-1] == Messages.NotificationMessages.CustomizedReports. \
                REPORT_TEMPLATE_SAVED, "Success message for saving scan is mismatched or missing."

            report_template_list = ReportTemplateList()

            assert template_name in report_template_list.get_all_templates(), "Failed to create custom report template."

            for row in report_template_list.rows:
                if row.template_name == template_name:
                    assert row.template_type == "Custom", \
                        "Report template created by user does not save with report type 'Custom' ."
        finally:
            self.delete_custom_report_template(template_name=template_name)

    @pytest.mark.parametrize("create_custom_template", [
        [{"id": "remediations", "option_values": {}}, {"id": "compliance", "option_values": {}},
         {"id": "hosts_vulns", "option_values": {"count": 5}}, {"id": "year_old_vulns", "option_values": {"count": 5}},
         {"id": "known_accounts_details", "option_values": {"count": 5}}]], indirect=True)
    def test_verify_visibility_of_up_and_down_arrows_to_move_chapters(self, create_custom_template):
        """
        NES-13406 [Automation]: Verify options for list of added chapter(s)

        Scenario Tested:
        [x] verify that each chapter having '↑'(tooltip : Move chapter up) , '↓'(tooltip : Move chapter down):
            - Only '↑'(Up) on chapter at bottom
            - Only '↓'(Down) on chapter at top
            - Both ('↑' , '↓') on rest of the chapters between top and bottom
            - 'X' symbols (tooltip : Delete chapter)
            - 'i' symbol (description about chapter that is same as showing under Add a report chapter popup)
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()

        ReportTemplateList().click_on_report_template(template_name=create_custom_template['template_name'])

        new_report_template_form = NewReportTemplateForm()
        wait(lambda: new_report_template_form.is_element_present("template_name_field"),
             waiting_for="Report template form get loaded")

        added_chapters = new_report_template_form.get_added_chapters_name()
        top_chapter, bottom_chapter = added_chapters[0], added_chapters[-1]
        up_arrow = self.report_chapter.ReportChapters.UP_ARROW
        down_arrow = self.report_chapter.ReportChapters.DOWN_ARROW
        chapter_desc_dict = self.report_chapter.CHAPTER_DESCRIPTION_DICT

        for chapter in added_chapters:
            chapter_desc_icon = new_report_template_form.get_element_of_chapter_description_icon(chapter_name=chapter)
            move_chapter_up_arrow = new_report_template_form.get_element_of_move_chapter_up_down_arrow(
                chapter_name=chapter, arrow_position=up_arrow)
            move_chapter_down_arrow = new_report_template_form.get_element_of_move_chapter_up_down_arrow(
                chapter_name=chapter, arrow_position=down_arrow)
            chapter_delete_icon = new_report_template_form.get_element_of_delete_chapter(chapter_name=chapter)

            assert all([chapter_desc_icon.is_displayed(), chapter_desc_icon.get_attribute(
                "title") == chapter_desc_dict[chapter]]), "Either Chapter description icon is missing or " \
                                                          "description message is incorrect in tooltip."

            if chapter in [top_chapter, bottom_chapter]:
                expected_arrow_position = up_arrow.lower() if chapter == top_chapter else down_arrow.lower()
                locator_value = './/div[contains(text(), "{}")]//following-sibling::div//i[contains(' \
                                '@class, "{}-arrow")]'.format(chapter, expected_arrow_position)

                if chapter == top_chapter:
                    assert all([move_chapter_down_arrow.is_displayed(), move_chapter_down_arrow.get_attribute(
                        "title") == self.report_chapter.ReportChapters.MOVE_CHAPTER_DOWN]), \
                        "Either move chapter down arrow is missing on chapter at top or tooltip message is incorrect."
                else:
                    assert all([move_chapter_up_arrow.is_displayed(), move_chapter_up_arrow.get_attribute(
                        "title") == self.report_chapter.ReportChapters.MOVE_CHAPTER_UP]), \
                        "Either move chapter up arrow is missing on chapter at bottom or tooltip message is incorrect."

                assert invisibility_of_element_located((By.XPATH, locator_value))(get_driver_no_init()), \
                    "'{}' arrow is getting displayed for '{}' chapter which should not be.".format(
                        expected_arrow_position.capitalize(), chapter)
            else:
                assert all([move_chapter_up_arrow.is_displayed(), move_chapter_up_arrow.get_attribute(
                    "title") == self.report_chapter.ReportChapters.MOVE_CHAPTER_UP,
                            move_chapter_down_arrow.is_displayed(), move_chapter_down_arrow.get_attribute(
                        "title") == self.report_chapter.ReportChapters.MOVE_CHAPTER_DOWN]), \
                    "Either move chapter up and down arrows are missing on chapter between top and bottom or " \
                    "tooltip message is incorrect."

            assert all([chapter_delete_icon.is_displayed(), chapter_delete_icon.get_attribute(
                "title") == self.report_chapter.ReportChapters.DELETE_CHAPTER]), \
                "Either delete chapter icon is missing on '{}' chapter or tooltip message is incorrect.".format(chapter)

    @pytest.mark.parametrize("create_custom_template", [
        [{"id": "remediations", "option_values": {}}, {"id": "compliance", "option_values": {}},
         {"id": "hosts_vulns", "option_values": {"count": 5}}, {"id": "year_old_vulns", "option_values": {"count": 5}},
         {"id": "known_accounts_details", "option_values": {"count": 5}}]], indirect=True)
    @pytest.mark.parametrize('chapter_position', [report_chapter.ReportChapters.UP_ARROW,
                                                  report_chapter.ReportChapters.DOWN_ARROW])
    def test_user_can_change_chapter_position_by_clicking_up_down_arrows(self, create_custom_template,
                                                                         chapter_position):
        """
        NES-13404 [Automation]: Verify user is able to change position of a chapter by clicking Up(↑ )and down (↓ )
                                arrow

        Scenario Tested:
        [x] Verify that user can change the position of chapters by clicking Up(↑)and down (↓) arrows
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()

        ReportTemplateList().click_on_report_template(template_name=create_custom_template['template_name'])

        new_report_template_form = NewReportTemplateForm()
        wait(lambda: new_report_template_form.is_element_present("template_name_field"),
             waiting_for="Report template form get loaded")

        chapters_with_initial_position = new_report_template_form.get_added_chapters_name()
        added_chapters = chapters_with_initial_position.copy()
        up_arrow = self.report_chapter.ReportChapters.UP_ARROW
        down_arrow = self.report_chapter.ReportChapters.DOWN_ARROW

        for chapter in chapters_with_initial_position[1: -1]:
            move_chapter_up_arrow = new_report_template_form.get_element_of_move_chapter_up_down_arrow(
                chapter_name=chapter, arrow_position=up_arrow)
            move_chapter_down_arrow = new_report_template_form.get_element_of_move_chapter_up_down_arrow(
                chapter_name=chapter, arrow_position=down_arrow)

            if chapter_position == up_arrow:
                move_chapter_up_arrow.click()
            else:
                move_chapter_down_arrow.click()

            current_chapter_index = added_chapters.index(chapter)
            expected_index = current_chapter_index - 1 if chapter_position == up_arrow else \
                current_chapter_index + 1

            added_chapters.insert(expected_index, added_chapters.pop(current_chapter_index))
            chapters_with_new_position = new_report_template_form.get_added_chapters_name()

            assert added_chapters == chapters_with_new_position, \
                "Failed to move the chapters at '{}' position in custom report template.".format(chapter_position)

            if expected_index == 0 or expected_index == (len(added_chapters) - 1):
                expected_arrow_position = up_arrow.lower() if chapter_position == up_arrow else down_arrow.lower()
                locator_value = './/div[contains(text(), "{}")]//following-sibling::div//i[contains(' \
                                '@class, "{}-arrow")]'.format(chapter, expected_arrow_position)

                assert invisibility_of_element_located((By.XPATH, locator_value))(get_driver_no_init()), \
                    "'{}' arrow is getting displayed for '{}' chapter after moved the chapter at top which " \
                    "should not be.".format(up_arrow, chapter)

    @pytest.mark.parametrize("create_custom_template", [
        [{"id": "remediations", "option_values": {}}, {"id": "compliance", "option_values": {}}]], indirect=True)
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
         'file_path': 'nessus/tests/ui/scans/test_data/', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize("is_hide", [True, False])
    def test_verify_hide_system_templates_checkbox_functioning(self, create_custom_template, import_scan_via_api,
                                                               is_hide):
        """
        NES-13427 [Automation]: Verify that "Hide system templates" checkbox is functioning properly

        Scenario Tested:
        [x] Verify on selecting "hide System templates", it should hide the System type templates from the template
            list under "Generate Report"
        [x] Verify on un-select "hide System templates", it should display the System type templates along with
            custom templates in template list under "Generate Report"
        """
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=import_scan_via_api[0])

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"), waiting_for="Report button get displayed")
        scan_view_page.report_button.click()

        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("hide_system_template_checkbox"),
             waiting_for="Selected report options get displayed")

        scan_export_page.hide_system_template_checkbox.check() if is_hide else \
            scan_export_page.hide_system_template_checkbox.uncheck()

        for report_format in [self.format_constant.FORMAT_PDF, self.format_constant.FORMAT_HTML]:
            report_format_element = scan_view_page.get_element_for_report_format_radio_button(
                report_format=report_format)

            if not report_format_element.is_selected():
                report_format_element.click()

            assert scan_export_page.is_element_present("custom_template_header"), \
                "Custom templates header is missing or mismatch under 'Generate Report' modal for '{}' format.".format(
                    report_format)

            if is_hide:
                assert not scan_export_page.is_element_present("system_template_header"), \
                    "System templates header is still visible even after selecting 'Hide system templates' checkbox."
            else:
                assert scan_export_page.is_element_present("system_template_header"), \
                    "System templates header is not visible even if 'Hide system templates' checkbox is uncheck."

        scan_export_page.cancel_button.click()

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus', 'encrypted': True,
         'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.parametrize("enter_description", [True, False])
    def test_selected_custom_report_template_shows_relevant_description(self, import_scan_via_api, enter_description):
        """
        NES-13428 [Automation]: Verify on selecting reports relevant template description should be displayed under
                                Template description area

        Scenario Tested:
        [x] Verify on selecting report template, relevant template description should be displayed under
            'Template description' area in report launcher
        [x] Verify when there is no description mentioned in custom report then it will leave that space blank under
            'Template description' in report launcher
        """
        template_name = random_name(prefix="Report_template-")
        template_description = "Custom report template created by Automation" if enter_description else ""

        try:
            self.create_custom_report_template(template_name=template_name, template_description=template_description)
            report_template_list = ReportTemplateList()

            assert template_name in report_template_list.get_all_templates(), "Failed to create custom report template."

            SideNav().get_sidenav_element(Nessus.Scan.Folder.MY_SCANS).click()
            ScanList().click_on_scan(scan_name=import_scan_via_api[0])

            scan_view_page = ScanViewPage()
            wait(lambda: scan_view_page.is_element_present("report_button"), waiting_for="Report button get displayed")
            scan_view_page.report_button.click()

            scan_export_page = ScanExportPage()
            wait(lambda: scan_export_page.is_element_present("hide_system_template_checkbox"),
                 waiting_for="Selected report options get displayed")

            for report_format in [self.format_constant.FORMAT_PDF, self.format_constant.FORMAT_HTML]:
                report_format_element = scan_view_page.get_element_for_report_format_radio_button(
                    report_format=report_format)

                if not report_format_element.is_selected():
                    report_format_element.click()

                sleep(WAIT_NORMAL, reason="waiting for default template get selected")
                scan_export_page.select_report_template_from_generate_report_modal(template_name=template_name)
                expected_template_description = scan_export_page.report_template_description.text

                if enter_description:
                    assert expected_template_description == template_description, \
                        "On selecting custom report template, relevant template description is not showing under " \
                        "'Template description' area"
                else:
                    assert expected_template_description == "", \
                        "Custom report template description is getting displayed under 'Template description' area " \
                        "even if there is no description entered while creating template."

            scan_export_page.cancel_button.click()
        finally:
            self.delete_custom_report_template(template_name=template_name)

    @pytest.mark.parametrize("create_custom_template", [
        [{"id": "remediations", "option_values": {}}, {"id": "compliance", "option_values": {}}]], indirect=True)
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus', 'encrypted': True,
         'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    def test_verify_generate_report_modal_content(self, create_custom_template, import_scan_via_api):
        """
        NES-13433 [Automation]: Verify content under "Generate Report" page

        Scenario Tested:
        [x] Verify content under "Generate Report" page
        [x] Verify that new report launcher UI will be displayed for "PDF" and "HTML" report format only
        """
        custom_report_template = create_custom_template['template_name']
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=import_scan_via_api[0])

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"), waiting_for="Report button get displayed")
        scan_view_page.report_button.click()

        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("hide_system_template_checkbox"),
             waiting_for="Selected report options get displayed")
        report_format_constant = self.format_constant

        for report_format in [report_format_constant.FORMAT_PDF, report_format_constant.FORMAT_HTML,
                              report_format_constant.FORMAT_CSV]:
            report_format_element = scan_view_page.get_element_for_report_format_radio_button(
                report_format=report_format)
            report_format_label = scan_view_page.get_element_for_report_format_radio_button(
                report_format=report_format, label_element=True).text

            assert all([report_format_element.is_displayed(), report_format_label == report_format]), \
                "Export report format option '{}' is not getting visible or mismatch the report format label.".format(
                    report_format)

            if report_format == report_format_constant.FORMAT_PDF:
                assert "checked" in report_format_element.get_css_classes(), \
                    "Export report format option '{}' is not getting selected by default.".format(report_format)

            if not report_format_element.is_selected():
                report_format_element.click()

            if report_format in [report_format_constant.FORMAT_PDF, report_format_constant.FORMAT_HTML]:
                assert all([scan_export_page.is_element_present("hide_system_template_checkbox"),
                            scan_export_page.is_element_present("hide_system_template_label"),
                            scan_export_page.hide_system_template_label.text == report_format_constant.
                           HIDE_SYSTEM_TEMPLATES]), \
                    "'Hide system templates' checkbox or it's label is missing or mismatch."

                assert all([scan_export_page.is_element_present("custom_template_header"),
                            scan_export_page.is_element_present("system_template_header")]), \
                    "'Custom' or 'System' template headers are missing or mismatch for '{}' format.".format(
                        report_format)

                assert all([scan_export_page.is_element_present("template_description_div"),
                            scan_export_page.is_element_present("template_description_label"),
                            scan_export_page.template_description_label.text == report_format_constant.
                           TEMPLATE_DESCRIPTION_LABEL, scan_export_page.is_element_present("filter_applied_div"),
                            scan_export_page.is_element_present("filter_applied_label"),
                            scan_export_page.filter_applied_label.text == report_format_constant.
                           FILTER_APPLIED_LABEL]), "'Template Description' or 'Filter Applied' labels are missing " \
                                                   "or mismatch for '{}' report format.".format(report_format)

                system_templates = Nessus.CustomizedReports.DEFAULT_TEMPLATES
                system_templates.extend([custom_report_template])

                if is_pro():
                    system_templates.extend(Nessus.CustomizedReports.PRO_REPORT_TEMPLATES)

                for template in system_templates:
                    scan_export_page.select_report_template_from_generate_report_modal(template_name=template)
                    template_desc_dict = Nessus.CustomizedReports.TEMPLATE_DESCRIPTION_DICT

                    expected_template_description = 'Created By Automation' if template == custom_report_template \
                        else template_desc_dict[template]

                    assert scan_export_page.report_template_description.text == expected_template_description, \
                        "Template description for '{}' template is missing or mismatch.".format(template)

                if report_format == report_format_constant.FORMAT_PDF:
                    formatting_text = Nessus.Scan.Results.Export.EXPORT_FORMATTING_TEXT

                    assert all([scan_export_page.is_element_present("formatting_option_label"),
                                scan_export_page.formatting_option_label.text == report_format_constant.
                               FORMATTING_OPTIONS_LABEL, scan_export_page.is_element_present(
                            "formatting_option_checkbox"), scan_export_page.formatting_option_checkbox.is_selected(),
                                scan_export_page.is_element_present("formatting_option_text"),
                                scan_export_page.formatting_option_text.text == formatting_text]), \
                        "'Formatting options' checkbox is missing or either it's label or message is mismatched."
                else:
                    assert not scan_export_page.is_element_present("formatting_option_checkbox"), \
                        "'Formatting options' checkbox is getting visible for 'HTML' format which should not be."
            else:
                assert not all([scan_export_page.is_element_present("hide_system_template_checkbox"),
                                scan_export_page.is_element_present("custom_template_header"),
                                scan_export_page.is_element_present("system_template_header"),
                                scan_export_page.is_element_present("template_description_label"),
                                scan_export_page.is_element_present("filter_applied_label"),
                                scan_export_page.is_element_present("formatting_option_checkbox")]), \
                    "Anyone from 'Hide system templates', 'Custom or System templates header', " \
                    "'Template Descriptions', 'Filter Applied' or 'Formatting option checkbox' is getting visible " \
                    "for '{}' format which should not be.".format(report_format)

            assert all([scan_export_page.is_element_present("save_as_default"),
                        not scan_export_page.save_as_default.is_selected()]), \
                "'Save as default' checkbox is missing or getting selected by default for '{}' format.".format(
                    report_format)

    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus', 'encrypted': True,
         'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.parametrize("apply_filter", [True, False])
    def test_user_can_see_applied_filter_value_under_filter_applied_section(self, import_scan_via_api, apply_filter):
        """
        NES-13430 [Automation]: Verify user is able to see applied filters under "Filters Applied" section while
                                generating PDF/HTML report on scan result page

        Scenario's Tested:
        [x] Verify when there is no filters applied on scan results then "Filters Applied" area will remain blank
        [x] Verify user can see applied filter values under "Filters Applied" section while generating PDF/HTML
            report from scan result page
        """
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=import_scan_via_api[0])

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("filter_link"), waiting_for="Vulnerabilities gets loaded")
        host_names = [host.host_name.text for host in HostsList().rows]
        scan_view_page.vulnerability_tab.click()

        filter_data = {
            'Single_filter': [{Nessus.Filter.KEY: Nessus.Filter.FilterKeys.HOSTNAME,
                               Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.EQUAL_TO,
                               Nessus.Filter.VALUE: random.sample(host_names, k=1)[0]}],
            'Multiple_filter': [{Nessus.Filter.KEY: Nessus.Filter.FilterKeys.SEVERITY,
                                 Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.NOT_EQUAL_TO,
                                 Nessus.Filter.VALUE: Nessus.Scan.Severity.CRITICAL},
                                {Nessus.Filter.KEY: Nessus.Filter.FilterKeys.HOSTNAME,
                                 Nessus.Filter.OPERATOR: Nessus.Filter.FilterOperators.CONTAINS,
                                 Nessus.Filter.VALUE: random.sample(host_names, k=1)[0]}]}

        for filter_type in list(filter_data.keys()):
            if apply_filter:
                for data in filter_data[filter_type]:
                    scan_view_page.apply_filter(key=data.get(Nessus.Filter.KEY), value=data.get(Nessus.Filter.VALUE),
                                                operator=data.get(Nessus.Filter.OPERATOR))

            scan_view_page.report_button.click()
            scan_export_page = ScanExportPage()
            wait(lambda: scan_export_page.is_element_present("hide_system_template_checkbox"),
                 waiting_for="Selected report options get displayed")

            for report_format in [self.format_constant.FORMAT_PDF, self.format_constant.FORMAT_HTML]:
                report_format_element = scan_view_page.get_element_for_report_format_radio_button(
                    report_format=report_format)

                if not report_format_element.is_selected():
                    report_format_element.click()

                if apply_filter:
                    expected_filter_values = []

                    for data in filter_data[filter_type]:
                        filter_value = " ".join([data.get(Nessus.Filter.KEY), data.get(Nessus.Filter.OPERATOR),
                                                 data.get(Nessus.Filter.VALUE)])
                        expected_filter_values.append(filter_value)

                    assert scan_export_page.get_applied_filter_value_from_report_launcher() == expected_filter_values, \
                        "'Filters Applied' section shows invalid filter result value list."
                else:
                    assert all([scan_export_page.is_element_present("default_filter_applied_value"),
                                scan_export_page.default_filter_applied_value.text == "None"]), \
                        "'Filters Applied' section is showing random values for '{}' format even if there is no " \
                        "filters applied on scan results.".format(report_format)

            scan_export_page.cancel_button.click()

            if apply_filter:
                scan_view_page.clear_filter()
                ActionCloseModal().wait_for_modal_closed()
            else:
                break

    def test_visibility_of_configurable_options_in_chapters(self):
        """
        NES-13429 [Automation]: Verify configurable options for chapters

        Scenario's Tested:
        [x] Verify that below listed four chapters are non-configurable.
            - Compliance
            - Remediations
            - Summary of Operating Systems
            - Summary of Vulnerabilities by Host
        [x] Verify that all chapters are configurable except above listed four chapters.
        """
        template_name = random_name(prefix="Report_template-")
        template_description = "Custom report template created by Automation"

        try:
            self.create_custom_report_template(template_name=template_name, template_description=template_description,
                                               all_chapters=True)
            report_template_list = ReportTemplateList()

            assert template_name in report_template_list.get_all_templates(), "Failed to create custom report template."

            report_template_list.click_on_report_template(template_name=template_name)
            new_report_template_form = NewReportTemplateForm()
            wait(lambda: new_report_template_form.is_element_present("template_name_field"),
                 waiting_for="Report template form get loaded")

            added_chapters = new_report_template_form.get_added_chapters_name()
            chapter_constant = Nessus.CustomizedReports

            for chapter in added_chapters:
                if chapter in [chapter_constant.COMPLIANCE, chapter_constant.REMEDIATIONS, chapter_constant.OS_SYSTEM,
                               chapter_constant.VULN_HOSTS_SUMMARY]:
                    count_field_value = '//div[contains(text(), "{}")]/parent::div/following::div[1]//input'.format(
                        chapter)
                    vulns_details_label = '//div[contains(text(), "{}")]/parent::div/following::div[1]//div[contains(' \
                                          '@class, "section-title")]'.format(chapter)

                    for locator_value in [count_field_value, 'scan', 'host', vulns_details_label]:
                        self.verify_invisibility_of_dynamic_web_elements(chapter=chapter, locator_value=locator_value)

                elif chapter in [chapter_constant.DETAILED_VULNS_BY_HOST, chapter_constant.DETAILED_VULNS_BY_PLUGINS]:
                    count_field_value = '//div[contains(text(), "{}")]/parent::div/following::div[1]//input'.format(
                        chapter)

                    assert invisibility_of_element_located((By.XPATH, count_field_value))(get_driver_no_init()), \
                        "Count field is getting displayed for '{}' chapter which should not be.".format(
                            chapter)

                    for key in ['scan', 'host']:
                        if chapter == chapter_constant.DETAILED_VULNS_BY_HOST:
                            checkbox_element = new_report_template_form.get_element_of_scan_and_host_info_checkbox(
                                chapter_name=chapter, scan_or_host=key)
                            label_element = new_report_template_form.get_element_of_scan_and_host_info_checkbox(
                                chapter_name=chapter, scan_or_host=key, label_element=True)

                            assert all([checkbox_element.is_displayed(), label_element.is_displayed(),
                                        "checked" in checkbox_element.get_css_classes(), label_element.text ==
                                        "{} Information".format(key.capitalize())]), \
                                "Either scan and host information checkboxes are not visible and selected or it's " \
                                "labels are getting mismatch in '{}' chapter.".format(chapter)
                        else:
                            self.verify_invisibility_of_dynamic_web_elements(chapter=chapter, locator_value=key)

                    vulns_details_options_checkbox = \
                        new_report_template_form.get_element_of_vulns_details_option_checkbox(chapter_name=chapter)

                    for option_checkbox_element in vulns_details_options_checkbox:
                        assert all([option_checkbox_element.is_displayed(),
                                    "checked" in option_checkbox_element.get_css_classes()]), \
                            "Vulnerabilities options are not getting displayed or selected by default in '{}' " \
                            "chapter.".format(chapter)

                    vulns_details_options_name = new_report_template_form.get_vulns_details_options_name(
                        chapter_name=chapter)

                    assert vulns_details_options_name.sort() == chapter_constant.VULNS_DETAILS_OPTIONS.sort(), \
                        "Vulnerabilities options labels are incorrect in '{}' chapter.".format(chapter)

                else:
                    vulns_details_label = '//div[contains(text(), "{}")]/parent::div/following::div[1]//div[contains(' \
                                          '@class, "section-title")]'.format(chapter)

                    for locator_value in ['scan', 'host', vulns_details_label]:
                        self.verify_invisibility_of_dynamic_web_elements(chapter=chapter, locator_value=locator_value)

                    default_count_dict = {chapter_constant.KNOWN_ACCOUNTS_DETAILS: '5', 'other_chapters': '25',
                                          chapter_constant.TOP_X_VULNS: '10'}
                    expected_count = default_count_dict['other_chapters'] if chapter.startswith("Summary of") else \
                        default_count_dict[chapter]

                    count_label_element = new_report_template_form.get_element_of_count_field(chapter_name=chapter,
                                                                                              label_element=True)
                    count_field_element = new_report_template_form.get_element_of_count_field(chapter_name=chapter)

                    assert all([count_label_element.is_displayed(), count_label_element.text == "Count",
                                count_field_element.is_displayed(), count_field_element.get_attribute("value") ==
                                expected_count]), "Count input field is either not visible or it's label or default " \
                                                  "count is getting mismatched."

            new_report_template_form.cancel_button.click()
            wait(lambda: CustomizedReportsPage().is_element_present("search_report_template_field"),
                 waiting_for="Custom report template list gets loaded")
        finally:
            self.delete_custom_report_template(template_name=template_name)

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
         'file_path': 'nessus/tests/ui/scans/test_data/', 'encrypted': True}], indirect=True)
    def test_generate_scan_report_when_no_custom_template_available(self, import_scan_via_api):
        """
        NES-13451 [Automation]: Verify when there is no any custom templates created and try to generate report from
                                scan result

        Scenario's Tested:
        [x] Verify that user should not be able to generate scan report when no custom templates available and system
            templates are hidden.
        [x] Verify that when no custom templates available and system templates are hidden then
            "No custom template created." message should be display.
        [x] Verify that when no custom templates available and system templates are hidden then "Generate Report"
            button should be disabled.
        """
        self.delete_custom_report_template()

        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=import_scan_via_api[0])

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"), waiting_for="Report button get displayed")
        scan_view_page.report_button.click()

        scan_export_page = ScanExportPage()
        wait(lambda: ActionCloseModal().is_element_present("modal"),
             waiting_for="'Generate Report' modal gets displayed")

        if is_home():
            assert all([not scan_export_page.is_element_present("hide_system_template_checkbox"),
                        not scan_export_page.is_element_present("custom_template_header"),
                        scan_export_page.is_element_present("system_template_header")]), \
                "'Hide system templates' checkbox is getting visible for Nessus Home which should not be."
        else:
            scan_export_page.hide_system_template_checkbox.check()
            sleep(WAIT_SHORT, reason="It takes little bit time to hide system templates")
            expected_msg_to_be_display = self.report_chapter.ReportTemplates.NO_CUSTOM_TEMPLATES_MESSAGE

            assert all([scan_export_page.is_element_present("system_template_header"),
                        scan_export_page.system_template_header.text == expected_msg_to_be_display]), \
                "'{}' message is either not visible or mismatched when no custom templates available and system " \
                "templates are hidden".format(expected_msg_to_be_display)

            assert 'disabled' in scan_export_page.generate_report_button.get_css_classes(), \
                "'Generate Report' button is getting enabled even if no custom templates available and system " \
                "templates are hidden"

            scan_export_page.hide_system_template_checkbox.check()

        scan_export_page.cancel_button.click()

    @pytest.mark.parametrize('create_template', [True, False])
    def test_back_to_report_templates_link_functioning_properly(self, create_template):
        """
        NES-13452 [Automation]: Verify 'Back to Report Templates' breadcrumb working

        Scenario's Tested:
        [x] Verify 'Back to Report Templates' breadcrumb working while creating new report template as well as for
            existing report template.
        """
        template_name = random_name(prefix="Report_template-")

        try:
            if create_template:
                self.create_custom_report_template(template_name=template_name)
                report_template_list = ReportTemplateList()

                assert template_name in report_template_list.get_all_templates(), \
                    "Failed to create custom report template."

                report_template_list.click_on_report_template(template_name=template_name)
            else:
                custom_report_page = CustomizedReportsPage()
                custom_report_page.open()
                custom_report_page.new_report_template_button.click()

            new_report_template_form = NewReportTemplateForm()
            wait(lambda: new_report_template_form.is_element_present("template_name_field"),
                 waiting_for="Report template form get loaded")
            expected_back_link_text = self.report_chapter.ReportTemplates.BACK_TO_REPORT_TEMPLATE_LINK

            assert all([new_report_template_form.is_element_present("back_to_report_template_link"),
                        new_report_template_form.back_to_report_template_link.text == expected_back_link_text]), \
                "'{}' link is missing or mismatch on new report template form.".format(expected_back_link_text)

            new_report_template_form.back_to_report_template_link.click()

            assert new_report_template_form.current_url.endswith("/scans/custom-reports"), \
                "User does not navigate to 'Customized Reports' page after clicking on '' link from new report " \
                "template form.".format(expected_back_link_text)
        finally:
            if create_template:
                self.delete_custom_report_template(template_name=template_name)

    @pytest.mark.parametrize("create_custom_template", [
        [{"id": "remediations", "option_values": {}}, {"id": "compliance", "option_values": {}}]], indirect=True)
    @pytest.mark.parametrize('import_scan_via_api', [
        {'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
         'file_path': 'nessus/tests/ui/scans/test_data/', 'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('report_format', [API.Scan.UIExportFormats.FORMAT_PDF,
                                               API.Scan.UIExportFormats.FORMAT_HTML])
    @pytest.mark.parametrize("save_as_default", [False, True])
    def test_verify_save_as_default_working_for_new_report_launcher(self, create_custom_template, import_scan_via_api,
                                                                    report_format, save_as_default):
        """
        NES-13446 [Automation]: Verify 'Save as default' option working properly

        Scenario's Tested:
        [x] Verify 'Save as default' option working properly for PDF/HTML report format in new report launcher.
        """
        ScansPage().refresh()
        ScanList().click_on_scan(scan_name=import_scan_via_api[0])

        scan_view_page = ScanViewPage()
        wait(lambda: scan_view_page.is_element_present("report_button"), waiting_for="Report button get displayed")
        scan_view_page.report_button.click()

        scan_export_page = ScanExportPage()
        wait(lambda: scan_export_page.is_element_present("hide_system_template_checkbox"),
             waiting_for="Selected report options get displayed")

        scan_export_page.hide_system_template_checkbox.check() if save_as_default else \
            scan_export_page.hide_system_template_checkbox.uncheck()
        scan_export_page.save_as_default.check() if save_as_default else scan_export_page.save_as_default.uncheck()
        scan_export_page.js_scroll_into_view(element=scan_export_page.generate_report_button)
        scan_export_page.generate_report_button.click()

        generate_report_modal = ActionCloseModal()
        generate_report_modal.wait_for_modal_closed()

        downloaded_files = get_downloaded_files_chrome()

        log.info("Downloaded file path :: :: %s", downloaded_files)
        scan_name = import_scan_via_api[0]
        file_name = scan_name.split(".")[0]

        assert file_name in downloaded_files, "Scan results does not exported successfully."

        scan_view_page.js_scroll_into_view(element=scan_view_page.report_button)
        scan_view_page.report_button.click()
        sleep(WAIT_NORMAL, reason="It takes little bit time to hide system templates")

        assert scan_export_page.is_element_present("custom_template_header"), \
            "Custom templates header is missing or mismatch under 'Generate Report' modal for '{}' format.".format(
                report_format)

        if save_as_default:
            assert not scan_export_page.is_element_present("system_template_header"), \
                "System templates header is still visible even after selecting 'Hide system templates' checkbox."

            scan_export_page.hide_system_template_checkbox.uncheck()
            scan_export_page.save_as_default.check()

            scan_export_page.js_scroll_into_view(element=scan_export_page.generate_report_button)
            scan_export_page.generate_report_button.click()
            generate_report_modal.wait_for_modal_closed()
        else:
            assert scan_export_page.is_element_present("system_template_header"), \
                "System templates header is not visible even if 'Hide system templates' checkbox is uncheck."

    def test_verify_system_template_can_not_be_deleted(self):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation

        Scenarios Tested:
            [x] Verify that system template can not be deleted
            [x] Verify that custom template can be deleted.
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()
        wait(lambda: custom_report_page.is_element_present('new_report_template_button'),
             waiting_for="customized report page to get loaded")
        for row in ReportTemplateList().rows:
            assert not row.remove_icon_displayed if row.template_type == "System" else row.remove_icon_displayed, \
                "User is able to see the remove icon for 'System' template or " \
                "not able to see the remove icon for 'Custom' template."

    def test_verify_that_system_template_can_not_be_edited(self):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation

        Scenarios Tested:
            [x] Verify that system template can not be edited.
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()
        wait(lambda: custom_report_page.is_element_present('new_report_template_button'),
             waiting_for="customized report page to get loaded")

        system_templates = Nessus.SystemReportTemplates.MANAGER_SYSTEM_TEMPLATES \
            if self.cat.api.server.properties()['nessus_type'] == Nessus.Manager.NESSUS_MANAGER \
            else Nessus.SystemReportTemplates.PRO_SYSTEM_TEMPLATES
        edit_system_template_name = list(system_templates)[randint(0, len(system_templates) - 1)]

        report_template_form = NewReportTemplateForm()
        report_template_list = ReportTemplateList()
        report_template_list.click_on_report_template(template_name=edit_system_template_name)
        wait(lambda: report_template_form.is_element_present('template_name_field'),
             waiting_for="Report template page to be opened.")

        assert not report_template_form.is_element_present('save_template_button'), \
            "'Save' button is visible on 'System' template edit page."
        assert report_template_form.is_element_present('cancel_button'), \
            "'Close' button is not visible for "

        # Verify that Name and description for system template can not be edited.
        for element in [report_template_form.template_name_field, report_template_form.template_description_area]:
            try:
                element.clear()
                raise AssertionError(
                    "User is able to modify the template name or template description for 'System' template.")
            except Exception as e:
                assert "invalid element state: Element is not currently interactable and may not be manipulated" \
                       in e.__str__()

        report_template_form.cancel_button.click()

    def test_verify_custom_report_template_can_not_have_empty_name(self):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation

        Scenarios Tested:
            [x] Verify that custom report template can not have empty name.
        """
        new_report_template = NewReportTemplateForm()
        new_report_template.open()
        wait(lambda: new_report_template.is_element_present('template_name_field'),
             waiting_for="Report template page to be opened.")

        new_report_template.move_to_element(new_report_template.save_template_button)
        new_report_template.save_template_button.click()

        # Verify error notification while saving template without name.
        assert Notifications().errors[-1] == Messages.NotificationMessages.CustomizedReports. \
            EMPTY_TEMPLATE_NAME_ERROR, "Error Notification while saving custom template without name is incorrect."

    def test_verify_custom_report_template_can_not_have_empty_chapters(self):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation

        Scenarios Tested:
            [x] Verify that custom report template can not be saved with empty chapters.
        """
        new_report_template = NewReportTemplateForm()
        new_report_template.open()
        wait(lambda: new_report_template.is_element_present('template_name_field'),
             waiting_for="Report template page to be opened.")

        new_report_template.template_name_field.value = random_name(prefix="Automation - ")
        new_report_template.move_to_element(new_report_template.save_template_button)
        new_report_template.save_template_button.click()

        # Verify error while saving custom template without chapters.
        assert Notifications().errors[-1] == Messages.NotificationMessages.CustomizedReports. \
            EMPTY_CHAPTERS_ERROR, "Error notification while saving template without chapters is incorrect."

    @pytest.mark.parametrize('search_keyword', ['host', 'compliance', 'remediations', 'incorrect_value'])
    def test_search_box_of_customized_template(self, search_keyword):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation

        Scenarios Tested:
            [x] Verify that search box functions properly for report templates table.
        """
        system_templates = Nessus.SystemReportTemplates.MANAGER_SYSTEM_TEMPLATES \
            if self.cat.api.server.properties()['nessus_type'] == Nessus.Manager.NESSUS_MANAGER \
            else Nessus.SystemReportTemplates.PRO_SYSTEM_TEMPLATES
        expected_list = [template for template in system_templates if search_keyword.lower() in template.lower()]

        customized_reports_page = CustomizedReportsPage()
        customized_reports_page.open()
        wait(lambda: customized_reports_page.is_element_present('new_report_template_button'),
             waiting_for="customized report page to get loaded")

        total_templates = int(customized_reports_page.total_templates_count.text)
        customized_reports_page.search_report_template_field.value = search_keyword

        report_template_list = ReportTemplateList()

        # Verify that templates populates as per the search keyword given in search box.
        try:
            wait(lambda: set(report_template_list.get_all_templates()) == set(expected_list),
                 waiting_for="Search results to get populated.", timeout_seconds=WAIT_NORMAL)
        except TimeoutExpired:
            raise AssertionError("Search results are incorrect based on search input given.")

        assert int(customized_reports_page.searched_templates_count.text) == len(expected_list)

        customized_reports_page.remove_search_icon.click()
        # Verify that all templates populated once user clicks on 'remove' icon on search box.
        try:
            wait(lambda: len(report_template_list.get_all_templates()) == total_templates,
                 waiting_for="Search results to get removed and all templates to get populated",
                 timeout_seconds=WAIT_NORMAL)
        except TimeoutExpired:
            raise AssertionError("All templates have not been displayed even after "
                                 "user click on 'remove' icon in search box.")

    def test_verify_customized_report_is_present_in_side_navigation(self):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation

        Scenarios Tested:
            [x] Verify that 'Customized Reports' is present in 'Resources' section of side navigation panel.'
        """
        side_nav = SideNav()
        assert [link.text for link in side_nav.resources_section_links] == \
               ['  Policies', 'Plugin Rules', 'Customized Reports'], "'Customized report' is not present in " \
                                                                     "resources section of side navigation panel"

    def test_verify_customized_report_hide_show_works_properly(self):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation

        Scenarios Tested:
            [x] Verify that 'Customized Reports' gets hidden/shown based on hide_show link in resources section'
        """
        side_nav = SideNav()
        hide_show_link_element = side_nav.get_section_show_hide_link(section_name="Resources",
                                                                     side_nav_sub_option='Customized Reports')
        customized_report_link = side_nav.get_sidenav_element(element_name='Customized Reports')
        try:
            # Verify show/hide title
            assert hide_show_link_element.text == "Hide", "Show hide link text is different"

            hide_show_link_element.click()

            assert invisibility_of_element_located((customized_report_link.we_by, customized_report_link.we_value)), \
                "'Customized Report' is still visible after hiding 'Resources' section in side navigation panel."

            # Verify show/hide title
            assert hide_show_link_element.text == "Show", "Show hide link text is different"

            hide_show_link_element.click()

            assert visibility_of_element_located((customized_report_link.we_by, customized_report_link.we_value)), \
                "'Customized Report' is still not visible after showing 'Resources' section in side navigation panel."
        finally:
            if hide_show_link_element.text == "Show":
                hide_show_link_element.click()

    @pytest.mark.parametrize('sort', SortOrder.VALID_ORDERS)
    @pytest.mark.parametrize('column_to_sort', ['Template Name', 'Type', 'Last Modified'])
    @pytest.mark.parametrize("create_custom_template",
                             [[{"id": "remediations", "option_values": {}},
                               {"id": "compliance", "option_values": {}}]], indirect=True)
    def test_sorting_in_report_templates_list(self, sort, column_to_sort, create_custom_template):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation

        Scenarios Tested:
            [x] Verify sorting works properly for below columns in customized report templates.
                - Template Name
                - Template Type
                - Last Modified
        """
        custom_report_page = CustomizedReportsPage()
        custom_report_page.open()
        wait(lambda: custom_report_page.is_element_present('new_report_template_button'),
             waiting_for="customized report page to get loaded")

        column_mapping = {'Template Name': 'template_name', 'Type': 'template_type',
                          'Last Modified': 'template_last_modified'}
        report_templates = ReportTemplateList()
        report_templates.loaded()

        map_attribute = column_mapping[column_to_sort]
        expected_sorted_vulnerability_list = sorted([getattr(
            template, map_attribute) for template in report_templates.rows], reverse=(sort == SortOrder.DESCENDING),
            key=lambda s: s.lower())

        rendered_vulnerability_list = sort_on_column_values(page_class_instance=report_templates,
                                                            sort=sort, column_name=column_to_sort)

        rendered_sorted_vulnerability_list = [getattr(template, map_attribute) for template in
                                              rendered_vulnerability_list]

        # Verify that after sorting, user is getting expected order for report templates
        assert expected_sorted_vulnerability_list == rendered_sorted_vulnerability_list, \
            "{} column is not sorted in {} order".format(column_to_sort, sort)

    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize("create_custom_template", [
        [{"id": "remediations", "option_values": {}}, {"id": "compliance", "option_values": {}}]], indirect=True)
    @pytest.mark.parametrize("format_type", [API.Scan.UIExportFormats.FORMAT_PDF, API.Scan.UIExportFormats.FORMAT_HTML,
                                             API.Scan.UIExportFormats.FORMAT_CSV])
    @pytest.mark.parametrize("save_as_default", [False, True])
    def test_pdf_html_and_csv_data_options_after_save_as_default(self, import_scan_via_api, create_custom_template,
                                                                 format_type, save_as_default):
        """
        NES-8600: [Testing] Automation Testing for Save as default and Select All/Clear options
        NES-8998: Automation UI for Nessus .csv Export

        Scenarios tested:
        [x] Verify that we will load the default options if there is a default one.
        """
        scan_name = import_scan_via_api[0]
        scan_page = ScansPage()
        scan_page.refresh()

        scan_list = ScanList()
        scan_list.click_on_scan(scan_name=scan_name)

        try:
            scan_view_page = ScanViewPage()
            wait(lambda: scan_view_page.is_element_present("report_button"))

            scan_view_page.report_button.click()
            generate_report_modal = ActionCloseModal()
            wait(lambda: generate_report_modal.modal, waiting_for='CSV export modal to open')

            scan_view_page.get_element_for_report_format_radio_button(report_format=format_type).click()
            sleep(WAIT_NORMAL, reason="It takes little bit time to move on selected report format")
            scan_export_page = ScanExportPage()
            options_name = []

            if format_type == API.Scan.UIExportFormats.FORMAT_CSV:
                options_name = scan_export_page.get_text_from_custom_option_check_box(
                    element=scan_export_page.export_csv_options)

                scan_export_page.select_all_link.click()
                scan_export_page.select_and_deselect_all_options(option_name=options_name[1::2], flag=False)
            else:
                scan_export_page.hide_system_template_checkbox.check()

            if save_as_default:
                scan_export_page.save_as_default.check()

            scan_export_page.generate_report_button.click()
            generate_report_modal.wait_for_modal_closed()

            scan_view_page.back_link.click()
            scan_file = get_file_path('nessus/tests/ui/scans/test_data/' + 'Lab_Scan.nessus')
            file_uploaded = self.cat.api.file.upload(file=scan_file, encrypted=True)
            response = self.cat.api.scans.import_scan(file_uploaded)

            scan_page.refresh()
            wait(lambda: visibility_of_element_located(scan_page.scan_searchbox), waiting_for='scan list to load')

            scan_list.click_on_scan(scan_name=response['scan']['name'])
            wait(lambda: scan_view_page.is_element_present("report_button"))

            scan_view_page.report_button.click()
            wait(lambda: ActionCloseModal().modal, waiting_for='CSV export modal to open')

            scan_view_page.get_element_for_report_format_radio_button(report_format=format_type).click()
            scan_export_page = ScanExportPage()
            wait(lambda: scan_export_page.is_element_present("clear_link") or scan_export_page.is_element_present(
                "hide_system_template_checkbox"), waiting_for="Selected report options get displayed")

            if save_as_default:
                if format_type == API.Scan.UIExportFormats.FORMAT_CSV:
                    for option in options_name[1::2]:
                        assert not scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                            "Export option '{}' under '{}' is still selected even after save as default '{}'.".format(
                                option, format_type, save_as_default)

                    for option in options_name[::2]:
                        assert scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                            "Export option '{}' under '{}' is not selected after save as default '{}'.".format(
                                option, format_type, save_as_default)
                else:
                    assert all([scan_export_page.is_element_present("custom_template_header"),
                                not scan_export_page.is_element_present("system_template_header")]), \
                        "'System' templates are still getting displayed even after save as default option '{}' with " \
                        "selecting 'Hide system templates' checkbox.".format(save_as_default)
            else:
                if format_type == API.Scan.UIExportFormats.FORMAT_CSV:
                    for option in options_name[:13]:
                        assert scan_export_page.get_custom_option_checkbox(option_name=option).is_selected(), \
                            "Export option {} under {} is getting deselected even after save as default '{}'.".format(
                                option, format_type, save_as_default)
                else:
                    assert all([scan_export_page.is_element_present("custom_template_header"),
                                scan_export_page.is_element_present("system_template_header")]), \
                        "'System' templates are not getting displayed even after save as default option '{}' with " \
                        "selecting 'Hide system templates' checkbox.".format(save_as_default)

            scan_export_page.cancel_button.click()
            scan_view_page.back_link.click()
            self.cat.api.scans.delete(response['scan']['id'])
        finally:
            revert_save_as_default_option_to_system(scan_name=scan_name, export_format=format_type)


@pytest.mark.nessus_home
@pytest.mark.usefixtures('login')
class TestCustomizedReportForHome:
    """
    Tests related to 'Customized Reports' feature for 'Nessus Home'
    """

    def test_customized_report_is_not_present_in_home(self):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation

        Scenarios Tested:
            [x] Verify that 'Customized Reports' is not present in 'Resources' section for 'Nessus Home'.
        """
        side_nav = SideNav()
        resources_section_tabs = [link.text for link in side_nav.resources_section_links]
        assert resources_section_tabs == ['  Policies', 'Plugin Rules'] and 'Customized Reports' \
               not in resources_section_tabs, "'Customized report' is present in resources section for 'Nessus Home'."
