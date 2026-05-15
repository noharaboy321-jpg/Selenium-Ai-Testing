"""
Nessus page object classes for Customized Reports

:copyright: Tenable Network Security, 2017
:date: Aug 26, 2021
:last_modified: Aug 31, 2021
:author: @kpanchal.ctr
"""
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from catium.lib.cat_registry import cat_registry
from catium.lib.log.log import create_logger
from catium.lib.webium.controls.click import Clickable
from catium.lib.webium.controls.table import GenericTableRow, GenericBaseTable
from catium.lib.webium.controls.text_field import TextField
from catium.lib.webium.find import Find, Finds
from nessus.lib.const import Nessus
from nessus.pageobjects.basepage import NessusBasePage
from nessus.pageobjects.generic.generic_modals import ActionCloseModal
from nessus.pageobjects.generic.object_list import ObjectList

log = create_logger()


@cat_registry.route(r'/scans/custom-reports')
class CustomizedReportsPage(NessusBasePage):
    """ Page Object for Customized Reports Page in Nessus Pro """

    page_title_in_header = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    new_report_template_button = Find(Clickable, by=By.CSS_SELECTOR, value='#new-report-template')
    report_templates_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Report Templates"]')
    name_and_logo_tab = Find(Clickable, by=By.CSS_SELECTOR, value='#tabs a[data-name="Name and Logo"]')
    search_report_template_field = Find(TextField, by=By.CSS_SELECTOR, value='#searchbox input')
    searched_templates_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Results"] b')
    total_templates_count = Find(by=By.CSS_SELECTOR, value='span[data-domselect="Total Records"] b')
    remove_search_icon = Find(by=By.CSS_SELECTOR, value='i[data-domselect="removeSearchIcon"]')
    report_template_logo = Find(by=By.CSS_SELECTOR, value='i.custom-reports')
    report_templates_description = Find(by=By.CSS_SELECTOR, value='.description-copy')
    template_search_box = Find(by=By.CSS_SELECTOR, value='input[data-domselect="searchInput"]')

    def __init__(self):
        super().__init__()
        self.required_elements = ['search_report_template_field']

    @property
    def get_page_heading(self):
        """ Return page title from header of your current nessus page """
        return self.page_title_in_header.text


class ReportTemplateRecord(GenericTableRow):
    """ Defines the key names for Template Records returned by Template List """

    name = Find(by=By.CSS_SELECTOR, value='td:nth-child(1)')
    type = Find(by=By.CSS_SELECTOR, value='td:nth-child(2)')
    last_modified = Find(by=By.CSS_SELECTOR, value='td:nth-child(3)')
    remove = Find(by=By.CSS_SELECTOR, value='td[title="Delete"]')
    remove_icon = Find(by=By.CSS_SELECTOR, value='td[title="Delete"] i')

    @property
    def template_name(self):
        """ Returns name of the template """
        return self.name.text

    @property
    def template_type(self):
        """ Returns type of the template """
        return self.type.text

    @property
    def template_last_modified(self):
        """ Returns last modified time of the template """
        return self.last_modified.text

    @property
    def remove_icon_displayed(self):
        """ Return True if remove_icon is displayed else return False """
        try:
            return self.remove_icon.is_displayed()
        except NoSuchElementException:
            return False


class ReportTemplateList(ObjectList):
    """ Returns a list containing Templates displayed on the Customized Reports Page."""

    configure_button = None
    object_table = Find(GenericBaseTable, value="content")
    generics_map = {GenericTableRow: ReportTemplateRecord}

    def __init__(self):
        super().__init__()
        self.loaded()

    def get_all_templates(self) -> list:
        """
        Returns the list of custom report templates

        :return: list of report templates
        :rtype: list
        """
        try:
            return [template.template_name for template in self.rows]
        except NoSuchElementException:
            return []

    def click_on_report_template(self, template_name: str) -> None:
        """
        Click on report template of given name

        :param str template_name: report template name
        :return: None
        """
        for report_template in self.rows:
            if report_template.template_name == template_name:
                report_template.click()
                break
        else:
            log.warning("Template: '{}' not found in the report template list".format(template_name))


@cat_registry.route(r'scans/custom-reports/edit')
class NewReportTemplateForm(NessusBasePage):
    """ Page Object for New custom report template creation page in Nessus """

    title_in_header = Find(by=By.CSS_SELECTOR, value='#titlebar h1')
    back_to_report_template_link = Find(Clickable, by=By.CSS_SELECTOR,
                                        value='.title-box a')
    template_name_field = Find(TextField, by=By.CSS_SELECTOR, value='input[data-name="Template Name"]')
    template_description_area = Find(TextField, by=By.CSS_SELECTOR, value='textarea[data-name="Template Description"]')
    add_chapter_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-action="add-report-chapter"]')
    save_template_button = Find(Clickable, by=By.CSS_SELECTOR, value='button[data-action="save-template"]')
    cancel_button = Find(Clickable, by=By.CSS_SELECTOR, value='a[data-action="cancel-edit-template"]')
    empty_chapter = Find(by=By.CSS_SELECTOR, value='span[class*="empty-chapters"]')
    chapter_title = Finds(by=By.CSS_SELECTOR, value='div[class="chapter-title"]')

    def get_element_of_chapter_description_icon(self, chapter_name: str) -> WebElement:
        """
        Returns web element of description icon of given chapter name from report template form

        :param str chapter_name: chapter name
        :return: Web element of given chapter's description icon
        :rtype: WebElement
        """
        return Find(by=By.XPATH, value='.//div[contains(text(), "{}")]//i[contains(@class, "chapter-question")]'.format(
            chapter_name), context=self)

    def get_element_of_move_chapter_up_down_arrow(self, chapter_name: str, arrow_position: str) -> WebElement:
        """
        Returns web element of description icon of given chapter name from report template form

        :param str chapter_name: chapter name
        :param str arrow_position: arrow position like up or down
        :return: Web element of given chapter's arrow position icon
        :rtype: WebElement
        """
        expected_arrow = "up" if arrow_position == Nessus.CustomizedReports.ReportChapters.UP_ARROW else "down"

        return Find(by=By.XPATH, value='.//div[contains(text(), "{}")]//following-sibling::div//i[contains('
                                       '@class, "{}-arrow")]'.format(chapter_name, expected_arrow), context=self)

    def get_element_of_delete_chapter(self, chapter_name: str) -> WebElement:
        """
        Returns web element of delete chapter icon of given name from report template form

        :param str chapter_name: chapter name to be removed
        :return: Web element of given chapter's delete icon
        :rtype: WebElement
        """
        return Find(by=By.XPATH, value='.//div[contains(text(), "{}")]//following-sibling::div//i[contains('
                                       '@class, "remove")]'.format(chapter_name), context=self)

    def get_added_chapters_name(self) -> list:
        """
        Returns added chapters name from report template form

        :return: added chapters name
        :rtype: list
        """
        return [chapter.text for chapter in self.chapter_title]

    def get_element_of_count_field(self, chapter_name: str, label_element: bool = False) -> WebElement:
        """
        Returns web element of count field under given chapter name

        :param str chapter_name: report chapter name
        :param bool label_element: True if need report label element else False
        :return: Web element of given chapter's count field
        :rtype: WebElement
        """
        locator_value = 'label' if label_element else 'input'

        return Find(by=By.XPATH, value='//div[contains(text(), "{}")]/parent::div/following::div[1]//{}'.format(
            chapter_name, locator_value), context=self)

    def get_element_of_scan_and_host_info_checkbox(self, chapter_name: str, scan_or_host: str,
                                                   label_element: bool = False) -> WebElement:
        """
        Returns web element of scan or host information checkbox under given chapter name

        :param str chapter_name: report chapter name
        :param str scan_or_host: scan or host info option name
        :param bool label_element: True if need report label element else False
        :return: Web element of given chapter's scan or host information checkbox
        :rtype: WebElement
        """
        data_key = '{}_information'.format(scan_or_host)
        locator_value = 'span' if label_element else 'div[contains(@class, "option-checkbox")]'

        return Find(by=By.XPATH, value='//div[contains(text(), "{}")]/parent::div/following::div[1]//div[contains('
                                       '@data-key, "{}")]/{}'.format(chapter_name, data_key, locator_value),
                    context=self)

    def get_element_of_vulns_details_option_checkbox(self, chapter_name: str,
                                                     label_element: bool = False) -> WebElement:
        """
        Returns web element of vulnerabilities details option checkbox under given chapter name

        :param str chapter_name: report chapter name
        :param bool label_element: True if need report label element else False
        :return: Web element of given chapter's vulnerabilities details option checkbox
        :rtype: WebElement
        """
        locator_value = 'span' if label_element else 'div[contains(@class, "option-checkbox")]'

        return Finds(by=By.XPATH, value='//div[contains(text(), "{}")]/parent::div/following::div[1]//div[contains('
                                        '@class, "section-title")]/following::{}'.format(chapter_name, locator_value),
                     context=self)

    def get_element_of_vulns_details_title(self, chapter_name: str) -> WebElement:
        """
        Returns web element of vulnerabilities details title under given chapter name

        :param str chapter_name: report chapter name
        :return: Web element of given chapter's vulnerabilities details title
        :rtype: WebElement
        """
        return Find(by=By.XPATH, value='//div[contains(text(), "{}")]/parent::div/following::div[1]//div[contains('
                                       '@class, "section-title")]'.format(chapter_name), context=self)

    def get_vulns_details_options_name(self, chapter_name: str) -> list:
        """
        Returns list of vulnerabilities options name from given chapter name

        :param str chapter_name: report chapter name
        :return: vulnerabilities options name
        :rtype: list
        """
        vulns_options_label_elements = self.get_element_of_vulns_details_option_checkbox(chapter_name=chapter_name,
                                                                                         label_element=True)

        return [option_label.text for option_label in vulns_options_label_elements]


class TemplateReportChapter(ActionCloseModal):
    """ Page class to select chapter from 'Add a Report Chapter' modal """

    chapter_list = Find(by=By.CSS_SELECTOR, value='select[class*="available-chapters-list"]')
    add_report_chapter_modal_content = Find(by=By.CSS_SELECTOR, value='div[class*="add-report-chapter-content"]')
    chapter_description = Find(by=By.CSS_SELECTOR, value='div[class*="chapter-description"]')

    def get_element_of_select_chapter(self, chapter_name: str) -> Find:
        """
        Returns web element for given chapter name from "Add a Report Chapter" modal

        :param str chapter_name: Chapter name that to be selected
        :return: Web element of given chapter
        :rtype: WebElement
        """
        return Find(by=By.CSS_SELECTOR, value='select[class*="available-chapters-list"] option[value="{}"]'.format(
            Nessus.CustomizedReports.CHAPTERS_DICT[chapter_name]), context=self)
