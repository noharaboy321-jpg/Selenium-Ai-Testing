"""
Test cases for Nessus Reports Endpoints

:copyright: Tenable Network Security, 2018
:date: August 16, 2018
:last_modified: May 04, 2021
:author: @ntarwani, @lestevez, @kpanchal, @krpatel
"""
import base64
import os
import random
from http import HTTPStatus

import PyPDF2
import pdfplumber
import pytest
from bs4 import BeautifulSoup
from requests.exceptions import HTTPError
from waiting import wait

from catium.helpers.testdata import get_file_path, load_testdata
from catium.lib.const import TIME_THIRTY_MINUTES
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS, WAIT_NORMAL
from catium.lib.log.log import create_logger
from catium.lib.util import random_name
from nessus.helpers.policy import create_policy_helper
from nessus.helpers.report_template import get_all_system_templates
from nessus.helpers.scan import create_scan_helper, get_plugin_id_of_highest_cvss_v3_score, get_scan_report_template_id, \
    get_plugin_id_of_highest_cvss_v4_score
from nessus.helpers.server import expect_http_error
from nessus.helpers.settings import get_current_advanced_setting_value
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.config import NessusConfig
from nessus.lib.const import Nessus
from nessus.lib.const.constants import API
from nessus.models.scan import ScanModel

log = create_logger()


@pytest.mark.usefixtures('nessus_api_login')
class TestReportsEndpoints:
    """"""
    cat = None

    # API_Tested# GET /reports/config
    # API_Tested# PUT /reports/config
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_save_and_get_reports(self):
        """
        STA-29: Create additional tests for Reports
        Verify that customized reports can be saved and retrieved

        Scenarios tested:
            [x] Successfully update custom reports with a new message and logo.
            [x] Successfully revert the custom reports to an empty message/logo
            [ ] Try updating the custom reports with an image that is too big
        """
        file_path = os.path.abspath(get_file_path('nessus/tests/api/reports/test_data/NPLogo.jpg'))

        image = open(file_path, 'rb').read()
        image_str = base64.b64encode(image).decode("utf-8")
        data = {"message": "test_report", "logo": "data:image/png;base64,%s" % image_str}

        self.cat.api.reports.configure_reports(data)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        report = self.cat.api.reports.get_report_configuration()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code
        assert data == report, 'The customized report data is incorrect or missing'

        # revert the customized reports
        revert_data = {"message": "", "logo": ""}
        self.cat.api.reports.configure_reports(revert_data)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    def test_save_and_get_default_report_options(self):
        """
        Verify default report options can be saved and retrieved
        """

        valid_formats = ['pdf', 'csv', 'html']
        invalid_formats = ['nessus', 'db']

        options = {
            'data_options': {
                'hide_system_templates': False,
                'page_breaks': True,
                'template_id': 1337
            },
            'format': 'pdf'
        }

        csv_options = {
            "data_options": {
                "csvColumns": {
                    "id": True,
                    "cve": True,
                    "cvss_base_score": True,
                    "risk": True,
                    "hostname": True,
                    "protocol": True,
                    "port": True,
                    "plugin_name": True,
                    "synopsis": True,
                    "description": True,
                    "solution": True,
                    "see_also": True,
                    "plugin_output": True,
                    "stig_severity": False,
                    "cvss3_base_score": True,
                    "cvss_temporal_score": False,
                    "cvss3_temporal_score": True,
                    "risk_factor": False,
                    "references": True,
                    "plugin_information": False,
                    "exploitable_with": False
                },
                "template_id": None,
            },
            "format": "csv"
        }

        for valid_format in valid_formats:
            self.cat.api.reports.get_default(valid_format)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

        for invalid_format in invalid_formats:
            try:
                self.cat.api.reports.get_default(invalid_format)
            except HTTPError:
                # catch HTTPError to prevent test from stopping
                pass
            assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                'Expected 400, got %s instead' % self.cat.api.http_status_code

        for valid_format in valid_formats:
            options['format'] = valid_format

            if valid_format == 'csv':
                self.cat.api.reports.save_default(csv_options)
            else:
                self.cat.api.reports.save_default(options)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

            get_default = self.cat.api.reports.get_default(valid_format)
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead' % self.cat.api.http_status_code

            if valid_format == 'csv':
                assert get_default['data_options']['csvColumns'] == csv_options['data_options']['csvColumns']
                assert get_default['data_options']['template_id'] == csv_options['data_options']['template_id']
                assert get_default['format'] == csv_options['format']
            else:
                assert get_default['data_options']['hide_system_templates'] == options['data_options'][
                    'hide_system_templates']
                assert get_default['data_options']['template_id'] == options['data_options']['template_id']
                assert get_default['data_options']['page_breaks'] == options['data_options']['page_breaks']
                assert get_default['format'] == options['format']

        for invalid_format in invalid_formats:
            try:
                self.cat.api.reports.save_default({'format': invalid_format})
            except HTTPError:
                # catch HTTPError to prevent test from stopping
                pass
            assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                'Expected 400, got %s instead' % self.cat.api.http_status_code

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    @pytest.mark.parametrize('export_format', [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML])
    @pytest.mark.parametrize('template_name', ["Complete List of Vulnerabilities by Host", "Compliance",
                                               "Detailed Vulnerabilities By Host",
                                               "Detailed Vulnerabilities By Host with Compliance/Remediations",
                                               "Detailed Vulnerabilities By Plugin",
                                               "Detailed Vulnerabilities By Plugin with Compliance/Remediations",
                                               "Remediations", "Summary of Exploitable Vulnerabilities",
                                               "Summary of Hosts with Vulnerabilities",
                                               "Summary of Known/Default Accounts", "Summary of Operating Systems",
                                               "Summary of Unsupported Software",
                                               "Summary of Vulnerabilities Older Than One Year",
                                               "Top 10 Vulnerabilities", "Vulnerability Operations"])
    def test_export_scan_with_different_report_types(self, import_scan, export_format, template_name):
        """
        NES-12165: [API] Verify new report types introduced in 8.12.0/8.13.0 Nessus Pro
        NES-12548: [Automation] Verify C level reports can be exported

        Scenarios Tested:
            [x] Verify new report types introduced in 8.12.0/8.13.0 Nessus Pro like Exploitable vulns,
                Unsupported softwares, OS enumeration
            [x] Verify "C level" (Top 10) reports can be exported in HTML and PDF format.
            [x] chapter - 'exploitable_vulns', export format - PDF or HTML
            [x] chapter - 'top10', export format - PDF or HTML
            [x] chapter - 'hosts_vulns', export format - PDF or HTML
            [x] chapter - 'known_accounts', export format - PDF or HTML
            [x] chapter - 'oses_found', export format - PDF or HTML
            [x] chapter - 'unsupported_software', export format - PDF or HTML
            [x] chapter - 'year_old_vulns', export format - PDF or HTML
        """
        template_id = get_scan_report_template_id(api=self.cat.api, template_name=template_name)
        export = None
        scan_id = import_scan

        # export scan with different export formats and templates
        try:
            export = self.cat.api.scans.export(scan_id, export_format=export_format, template_id=template_id)
        except HTTPError:
            raise Exception("Error while exporting scan report with format - {} and template name - ".format(
                export_format, template_name))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get %s state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify that downloaded file is not empty
        assert len(download.content) > 0, "Downloaded file is empty"

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Advanced_Scan_for_Top_10_vulns_igmoy3.nessus',
                                                      'file_path': 'nessus/tests/api/scan/test_data/'}], indirect=True)
    @pytest.mark.parametrize('change_severity_base_setting', [True, False])
    @pytest.mark.parametrize('severity_base_value', ['cvss_v2', 'cvss_v3'])
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_HTML, API.Scan.ExportFormats.FORMAT_PDF])
    def test_top_10_report_exported_based_on_selected_severity_base(
            self, import_scan_via_api, change_severity_base_setting, severity_base_value, report_format):
        """
        NES-12579: [API-Automation] Verify 'Top 10 Vulnerabilities' reports export honors severity base
        NES-12785: [API-Automation] Verify Top 10 Most Prevalent Vulnerabilities section in report
        NES-12795: [API-Automation] Verify report after updating severity base from advanced setting and from scan
                    result page.

        Scenario Tested:
        [x] Verify 'Top 10 Vulnerabilities' reports export honors severity base.
        [x] Verify Top 10 Most Prevalent Vulnerabilities section should be present in exported
            'Top 10 Vulnerabilities' report.
        [x] Verify report after updating severity base from advanced setting and from scan result page.
        """
        expected_vuln_count = {}
        vulns_count_cvss_v3 = {"Critical": "25(4)", "High": "68(19)", "Medium": "35(2)"}
        vulns_count_cvss_v2 = {"Critical": "3(0)", "High": "43(12)", "Medium": "75(12)"}

        scan_id = import_scan_via_api['id']

        if change_severity_base_setting:
            default_severity_value = get_current_advanced_setting_value(api=self.cat.api, setting_name='severity_basis')

            if severity_base_value != default_severity_value:
                setting_payload = {"setting.0.name": "severity_basis", "setting.0.value": severity_base_value,
                                   "setting.0.action": "edit"}

                self.cat.api.settings.update(settings=setting_payload)

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code
        else:
            self.cat.api.scans.update_severity_base(scan_id=scan_id, payload={"severity_base": severity_base_value})

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_details = self.cat.api.scans.details(scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert severity_base_value == scan_details['info']['current_severity_base'], \
            "Failed to change the severity basis value."

        current_severity = severity_base_value.replace("_", " ").split()
        severity_base_display_value = ' '.join([current_severity[0].upper(), current_severity[1] + '.0'])

        assert severity_base_display_value == scan_details['info']['current_severity_base_display'], \
            "Displayed severity base value '{}' is different from current severity base value '{}'.".format(
                severity_base_display_value, severity_base_value)

        export = self.cat.api.scans.export(scan_id=scan_id, export_format=report_format,
                                           template_id=get_scan_report_template_id(
                                               api=self.cat.api, template_name="Top 10 Vulnerabilities"))

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get "%s" state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert download, "An exported file was not downloaded."

        file_path = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(scan_id))

        try:
            with open(file_path + ".{}".format(report_format), "wb") as file:
                for block in download.iter_content(1024):
                    file.write(block)
                file.close()

            expected_vuln_list = []
            severity_base = severity_base_value.split('_')
            expected_severity_base_value = ' '.join([severity_base[0].upper(), '{}.0'.format(severity_base[1])])
            section_title = API.Scan.ReportTypes.ReportContent.PREVALENT_VULNERABILITIES_SECTION_TITLE
            table_title = API.Scan.ReportTypes.ReportContent.PREVALENT_VULNERABILITIES_TABLE_TITLE
            table_desc = API.Scan.ReportTypes.ReportContent.PREVALENT_VULNERABILITIES_TABLE_DESCRIPTION

            if report_format == API.Scan.ExportFormats.FORMAT_PDF:
                pdf_reader = pdfplumber.open(file_path + ".{}".format(report_format))

                try:
                    page_data = pdf_reader.pages[3].extract_text().split('\n')

                    cvss_vulns_located_at = page_data.index(
                        '{}: all(exploitable)'.format(severity_base_display_value)) + 1
                    expected_vuln_list = page_data[cvss_vulns_located_at].split()
                    expected_vuln_count = {page_data[cvss_vulns_located_at + 1].split()
                                           [i].capitalize(): expected_vuln_list[i] for i in range(0, 3)}

                    assert expected_severity_base_value in "".join(page_data), \
                        "Severity basis value '{}' is missing on exported report for '{}' format.".format(
                            severity_base_value, report_format)

                    for page in [10, 11, 12]:
                        page_data = pdf_reader.pages[page].extract_text().split('\n')

                        if page == 12:
                            assert section_title in page_data, \
                                "Top 10 Most Prevalent Vulnerabilities section is not present in exported report."
                        elif page in [13, 15]:
                            expected_prevalent_table_title = '(VPR)' if page == 11 else '({})'.format(
                                expected_severity_base_value)

                            assert table_title + '{}'.format(expected_prevalent_table_title) in page_data, \
                                "Top 10 Most Prevalent Vulnerabilities table title is not present in exported report."

                            assert table_desc in "".join(page_data), \
                                "Top 10 Most Prevalent Vulnerabilities table description is missing in exported report."
                finally:
                    pdf_reader.close()

            elif report_format == API.Scan.ExportFormats.FORMAT_HTML:
                with open(file_path + ".{}".format(report_format), mode='rb') as file_obj:
                    html_content = BeautifulSoup(file_obj.read())

                    for tr in html_content.find_all('tbody')[2].find_all('tr'):
                        for td in tr.find_all('td'):
                            expected_vuln_list.append(td.text)

                    expected_vuln_list = expected_vuln_list[3:9]
                    expected_vuln_count = {expected_vuln_list[i + 3].capitalize(): expected_vuln_list[i] for i in
                                           range(0, 3)}

                    for value in [expected_severity_base_value, section_title, table_title + '(VPR)',
                                  table_title + '({})'.format(expected_severity_base_value), table_desc]:
                        assert html_content.body.find_all(value).source.name, \
                            "Value '{}' is missing on exported report for '{}' format.".format(value, report_format)

            total_exploitable_vulns_count = vulns_count_cvss_v2 if severity_base_value == "cvss_v2" else \
                vulns_count_cvss_v3

            assert total_exploitable_vulns_count == expected_vuln_count, \
                "Scan report is not getting exported in '{}' format based on selected severity base.".format(
                    report_format)
        finally:
            os.remove(file_path + ".{}".format(report_format))

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'Advanced_scan_p34639.nessus'}}], indirect=True)
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_HTML, API.Scan.ExportFormats.FORMAT_PDF])
    @pytest.mark.parametrize('filter_param', [
        {"filter.0.quality": "eq", "filter.0.filter": "severity", "filter.0.value": "3", "filter.search_type": "and"},
        {"filter.0.quality": "gt", "filter.0.filter": "cvss_base_score", "filter.0.value": "5",
         "filter.search_type": "and"},
        {"filter.0.quality": "eq", "filter.0.filter": "plugin_id", "filter.0.value": "51192",
         "filter.search_type": "and"},
        {"filter.0.quality": "lt", "filter.0.filter": "cvss_temporal_score", "filter.0.value": "4.2",
         "filter.search_type": "and"},
        {"filter.0.quality": "qa", "filter.0.filter": "exploit_available", "filter.0.value": "true",
         "filter.search_type": "and"}])
    def test_top_10_report_export_honors_filters(self, import_scan, report_format, filter_param):
        """
        NES-12578: [Automation] Verify C level reports export honors filters

        Scenario Tested:
        [x] Verify C level reports export honors filters and only filtered records are exported.
        """
        query = ''
        scan_id = import_scan

        for key, value in filter_param.items():
            query += "{}={}&".format(key, value)

        query_params = '?{}includeHostDetailsForHostDiscovery=true'.format(query)

        exploitable_vulnerabilities = self.cat.api.scans.details(scan_id=scan_id, query=query_params)['vulnerabilities']

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        filtered_plugin_ids = [plugin['plugin_id'] for plugin in exploitable_vulnerabilities]

        export = self.cat.api.scans.export(
            scan_id=scan_id, export_format=report_format, template_id=get_scan_report_template_id(
                api=self.cat.api, template_name="Top 10 Vulnerabilities"), filter_params=filter_param)

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get "%s" state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert download, "Exported file was not downloaded."

        file_path = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(scan_id))

        try:
            with open(file_path + ".{}".format(report_format), "wb") as file:
                for block in download.iter_content(1024):
                    file.write(block)
                file.close()

            exported_plugin_ids = []

            with open(file_path + ".{}".format(report_format), mode='rb') as file_obj:
                if report_format == API.Scan.ExportFormats.FORMAT_PDF:
                    pdf_reader = PyPDF2.PdfFileReader(file_obj)

                    for page_num in range(pdf_reader.numPages):
                        page_data = pdf_reader.getPage(page_num).extractText()

                        if 'Plugin ID' in ' '.join(page_data.split('\n')[4:6]):
                            plugin_ids = [value for value in page_data.split('\n') if value.isdigit()][1::2]

                            [exported_plugin_ids.append(plugin_id) for plugin_id in plugin_ids if plugin_id not in
                             exported_plugin_ids]

                elif report_format == API.Scan.ExportFormats.FORMAT_HTML:
                    html_content = BeautifulSoup(file_obj.read())

                    [exported_plugin_ids.append(plugin_id.text) for plugin_id in
                     [item for item in html_content.find_all('a')][14:] if plugin_id.text not in exported_plugin_ids]

            assert all([int(item.strip()) in filtered_plugin_ids for item in exported_plugin_ids]), \
                "Scan report is not getting exported in '{}' format based on selected severity base.".format(
                    report_format)
        finally:
            os.remove(file_path + ".{}".format(report_format))

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_PDF])
    @pytest.mark.parametrize('severity_base_value', ['cvss_v2', 'cvss_v3'])
    def test_severity_base_in_column_title(self, import_scan, report_format, severity_base_value):
        """
        NES-12827 : [API-Automation] : Verify the report column title should respect the severity selection
        Scenario Tested:
            [x] Verify that correct severity base is reflected in scan report executive summary.
        """
        scan_id = import_scan
        self.cat.api.scans.update_severity_base(scan_id=scan_id, payload={"severity_base": severity_base_value})

        # Generate scan report executive summary in PDF format.
        export = self.cat.api.scans.export(scan_id=scan_id, export_format=report_format, chapters='vuln_hosts_summary')

        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get "%s" state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert download, "Exported file was not downloaded."

        file_path = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(scan_id))

        try:
            with open(file_path + ".{}".format(report_format), "wb") as file:
                for block in download.iter_content(1024):
                    file.write(block)
                file.close()

            expected_severity_base = severity_base_value.split('_')[0].upper() + "\n" + severity_base_value.split(
                '_')[1].upper() + ".0"

            if report_format == API.Scan.ExportFormats.FORMAT_PDF:
                pdf_reader = pdfplumber.open(file_path + ".{}".format(report_format))
                # Verify column title for severity base in scan report.
                try:
                    assert expected_severity_base in pdf_reader.pages[3].extract_table()[0], \
                        "Severity base column title does not reflected in scan report."
                finally:
                    pdf_reader.close()
        finally:
            os.remove(file_path + ".{}".format(report_format))

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('scan_type', ['policy_scan', 'live_scan'])
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML])
    def test_top_10_report_can_be_generated_for_policy_and_live_scan(self, get_policy_templates, scan_type,
                                                                     report_format):
        """
        NES-12751: [API-Automation] Verify that C level report can be generated for Policy and Live Scan with
                    PDF/HTML format

        Scenario Tested:
        [x] Verify that 'Top 10 Vulnerabilities' report can be generated for Policy Scan with PDF/HTML format
        """
        file_path = get_file_path('nessus/tests/api/scan/test_data/Advanced_scan_for_live_results.json')

        if scan_type == "policy_scan":
            policy_details = create_policy_helper(self.cat.api, get_policy_templates, policy_type='advanced',
                                                  policy_name=random_name(prefix="advanced-policy-"))

            config = {'policy_id': policy_details['policy_id'], 'text_targets': Nessus.Scan.Target.AWS_LINUX_TARGET_1}

            scan_details = self.cat.api.scans.create(ScanModel(name=random_name(prefix="automation-scan-"), **config))
        else:
            scan_details = create_scan_helper(self.cat.api, file_name=file_path, template_title='advanced')

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        scan_id = scan_details['scan']['id'] if scan_type == "policy_scan" else scan_details[0]['scan']['id']

        try:
            if scan_type == "live_scan":
                scan_config_data = load_testdata(file_path)
                scan_config_data["settings"]["live_results"] = True

                for key in scan_config_data["plugins"].keys():
                    scan_config_data["plugins"][key]["status"] = "disabled"

                self.cat.api.scans.configure(scan_id=scan_id, payload=scan_config_data)

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code

            self.cat.api.scans.launch(scan_id=scan_id)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                            timeout=TIME_THIRTY_MINUTES)

            if scan_type == "live_scan":
                scan_config_data = load_testdata(file_path)

                for key in scan_config_data["plugins"].keys():
                    if scan_config_data["plugins"][key]["status"] == "disabled":
                        scan_config_data["plugins"][key]["status"] = "enabled"

                self.cat.api.scans.configure(scan_id=scan_id, payload=scan_config_data)

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code

                self.cat.api.scans.launch(scan_id=scan_id)

                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code

                wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                timeout=TIME_THIRTY_MINUTES)

            export = self.cat.api.scans.export(scan_id=scan_id, export_format=report_format, chapters='top10')

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            # wait for to get ready state and max wait for two minutes.
            wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
                 timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get "%s" state' % API.Status.READY,
                 sleep_seconds=WAIT_NORMAL)

            download = self.cat.api.scans.download(scan_id, export[0])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert all([download, len(download.content) > 0]), "An exported file was not downloaded."
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Basic_Network_Scan_Result.db', 'password': 'nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/',
                                                      'encrypted': True}], indirect=True)
    @pytest.mark.parametrize('select_option', ['host', 'vulnerability'])
    @pytest.mark.parametrize('apply_filter', [True, False])
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML])
    def test_top_10_report_can_be_generated_for_selected_host_and_vulnerabilities(
            self, import_scan_via_api, apply_filter, report_format, select_option):
        """
        NES-12749: [API-Automation] Verify that C level report can be generated with selected Hosts and Vulnerabilities
        NES-12750: [API-Automation] Verify that C level report can be generated with filtered criteria from Hosts tab

        Scenario Tested:
        [x] Verify that 'Top 10 Vulnerabilities' report can be generated with few selected Hosts and Vulnerabilities.
        [x] Verify that 'Top 10 Vulnerabilities' report can be generated with filtered criteria Hosts and
            Vulnerabilities.
        """
        scan_id = import_scan_via_api['id']

        scan_details = self.cat.api.scans.details(scan_id=scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        filter_details = {
            'host': [{"filter.0.quality": "eq", "filter.0.filter": "hostname", "filter.0.value": "172.26.48.10",
                      "filter.search_type": "and"}, [host['host_id'] for host in scan_details['hosts']], "host_ids"],
            'vulnerability': [{"filter.0.quality": "eq", "filter.0.filter": "severity", "filter.0.value": "2",
                               "filter.search_type": "and"}, [vulnerability['plugin_id'] for vulnerability in
                                                              scan_details['vulnerabilities']], "plugin_ids"]}

        filter_params = filter_details[select_option][0] if apply_filter else filter_details[select_option][1]

        if apply_filter:
            export = self.cat.api.scans.export(scan_id=scan_id, export_format=report_format, chapters='top10',
                                               filter_params=filter_params)
        else:
            random_ids = random.choices(population=filter_params, k=int(len(filter_params) / 2))

            export = self.cat.api.scans.export(scan_id=scan_id, export_format=report_format, chapters='top10',
                                               extra_filters={filter_details[select_option][2]: random_ids})

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get "%s" state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert all([download, len(download.content) > 0]), "An exported file was not downloaded."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Advanced_Scan_for_Top_10_vulns_igmoy3.nessus',
                                                      'file_path': 'nessus/tests/api/scan/test_data/'}], indirect=True)
    @pytest.mark.parametrize('severity_base_value', ['cvss_v3'])
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_PDF])
    def test_verify_top_10_vuln_reports_after_modifying_severity(self, import_scan_via_api, severity_base_value,
                                                                 report_format):
        """
        NES-12772: [API-Automation] : Modify Scan result and generate C level report with PDF format

        Scenario Tested:
        [x] Verify that modified scan severity does reflected in "Top 10 Vulnerabilities" report in PDF format
        """
        scan_id = import_scan_via_api['id']
        self.cat.api.scans.update_severity_base(scan_id=scan_id, payload={"severity_base": severity_base_value})

        scan_details = self.cat.api.scans.details(scan_id=scan_id)
        host_id = scan_details['hosts'][0]['host_id']

        high_severity_plugin_ids = [vuln['plugin_id'] for vuln in scan_details['vulnerabilities'] if vuln[
            'severity'] == 3]
        expected_plugin_id = get_plugin_id_of_highest_cvss_v3_score(
            nessus_api=self.cat.api, plugin_ids=high_severity_plugin_ids, host_id=host_id, scan_id=scan_id)

        # Verify that initially the vulnerability's severity is 'High'
        assert self.cat.api.scans.get_host_vulnerability(host_id=host_id, plugin_id=expected_plugin_id,
                                                         scan_id=scan_id)['info']['plugindescription']['severity'] == 3

        # Update the severity
        payload = {'type': API.Severity.CRITICAL, 'host': scan_details['hosts'][0]['hostname']}
        self.cat.api.scans.update_plugin_severity(scan_id=scan_id, plugin_id=expected_plugin_id, payload=payload)

        # Verify that severity is updated to 'Critical'.
        assert self.cat.api.scans.get_host_vulnerability(host_id=host_id, plugin_id=expected_plugin_id,
                                                         scan_id=scan_id)['info']['plugindescription']['severity'] == 4

        export = self.cat.api.scans.export(
            scan_id=scan_id, export_format=report_format, template_id=get_scan_report_template_id(
                api=self.cat.api, template_name="Top 10 Vulnerabilities"))

        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get "%s" state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert download, "Exported file was not downloaded."

        file_path = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(scan_id))

        try:
            with open(file_path + ".{}".format(report_format), "wb") as file:
                for block in download.iter_content(1024):
                    file.write(block)
                file.close()

            if report_format == API.Scan.ExportFormats.FORMAT_PDF:
                pdf_reader = pdfplumber.open(file_path + ".{}".format(report_format))

                try:
                    # Verify that vulnerability is listed in top 10 critical vulnerabilities list
                    assert Nessus.TopTenVulnerabilitiesReport.TOP_TEN_CRITICAL_CVSS_V3 in pdf_reader.pages[
                        7].extract_text() and str(expected_plugin_id) in pdf_reader.pages[
                               7].extract_text(), "Plugin of which severity modified is not listed inside top " \
                                                  "ten critical vulnerabilities table."

                    # Verify that vulnerability is not listed in top 10 high vulnerabilities list
                    assert Nessus.TopTenVulnerabilitiesReport.TOP_TEN_HIGH_CVSS_V3 in pdf_reader.pages[
                        11].extract_text() and str(expected_plugin_id) not in pdf_reader.pages[
                               11].extract_text(), "Plugin of which severity modified is listed inside top ten " \
                                                  "high vulnerabilities table."
                finally:
                    pdf_reader.close()
        finally:
            os.remove(file_path + ".{}".format(report_format))

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'Advanced_Scan_for_Top_10_vulns_igmoy3.nessus',
                                                      'file_path': 'nessus/tests/api/scan/test_data/'}], indirect=True)
    @pytest.mark.parametrize('severity_base_value', ['cvss_v3', 'cvss_v2'])
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_PDF])
    def test_verify_content_in_exported_top_ten_vulns_report(self, import_scan_via_api, severity_base_value,
                                                             report_format):
        """
        NES-12799 : [API-Automation] : Verify the content of Exported C level report with PDF/HTML format
        Scenario Tested:
            [x] Verify that C Level report content for PDF format
        """
        scan_id = import_scan_via_api['id']
        self.cat.api.scans.update_severity_base(scan_id=scan_id, payload={"severity_base": severity_base_value})

        export = self.cat.api.scans.export(
            scan_id=scan_id, export_format=report_format, template_id=get_scan_report_template_id(
                api=self.cat.api, template_name="Top 10 Vulnerabilities"))

        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get "%s" state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert download, "Exported file was not downloaded."

        file_path = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(scan_id))

        try:
            with open(file_path + ".{}".format(report_format), "wb") as file:
                for block in download.iter_content(1024):
                    file.write(block)
                file.close()

                pdf_reader = pdfplumber.open(file_path + ".{}".format(report_format))
                try:
                    page_zero_content_list = pdf_reader.pages[0].extract_text().split('\n')
                    page_two_content_list = pdf_reader.pages[1].extract_text().split('\n')
                    page_five_content_list = pdf_reader.pages[5].extract_text()
                    page_seven_content_list = pdf_reader.pages[7].extract_text()
                    page_nine_content_list = pdf_reader.pages[9].extract_text()
                    page_ten_content_list = pdf_reader.pages[11].extract_text()
                    page_thirteen_content_list = pdf_reader.pages[13].extract_text()
                    page_fifteen_content_list = pdf_reader.pages[15].extract_text()

                    severity_base = Nessus.TopTenVulnerabilitiesReport.CVSS_V3 if severity_base_value == "cvss_v3" \
                        else Nessus.TopTenVulnerabilitiesReport.CVSS_V2
                    top_ten_critical_cvss = Nessus.TopTenVulnerabilitiesReport.TOP_TEN_CRITICAL_CVSS_V3 if \
                        severity_base_value == "cvss_v3" else Nessus.TopTenVulnerabilitiesReport. \
                        TOP_TEN_CRITICAL_CVSS_V2
                    top_ten_high_cvss = Nessus.TopTenVulnerabilitiesReport.TOP_TEN_HIGH_CVSS_V3 if \
                        severity_base_value == "cvss_v3" else Nessus.TopTenVulnerabilitiesReport.TOP_TEN_HIGH_CVSS_V2
                    top_ten_most_prevalent_cvss = Nessus.TopTenVulnerabilitiesReport.TOP_TEN_MOST_PREVALENT_CVSS_V3 \
                        if severity_base_value == "cvss_v3" else Nessus.TopTenVulnerabilitiesReport. \
                        TOP_TEN_MOST_PREVALENT_CVSS_V2

                    # Verify that report is populated correctly.
                    assert Nessus.TopTenVulnerabilitiesReport.TOP_TEN_VULNS_TITLE in page_zero_content_list, \
                        "Top Ten Vulnerabilities Report title is incorrect."
                    table_of_contents_from_report = [content.split('..')[0].strip('•').lstrip() for content in
                                                     page_two_content_list]
                    expected_table_of_contents = Nessus.TopTenVulnerabilitiesReport.TABLE_OF_CONTENTS_LIST_CVSS_V3 if \
                        severity_base_value == "cvss_v3" else \
                        Nessus.TopTenVulnerabilitiesReport.TABLE_OF_CONTENTS_LIST_CVSS_V2
                    assert table_of_contents_from_report == expected_table_of_contents, \
                        "Table of contents are incorrect."

                    assert Nessus.TopTenVulnerabilitiesReport.TOP_TEN_CRITICAL_VPR in page_five_content_list, \
                        "Top Ten critical vulnerabilities as per VPR score are not displayed on C level report."
                    assert Nessus.TopTenVulnerabilitiesReport.VPR in page_five_content_list and severity_base not in \
                           page_five_content_list, "VPR column is not present or severity base column is present on " \
                                                   "VPR based top ten critical vulnerabilities."

                    assert top_ten_critical_cvss in page_seven_content_list, \
                        "Top Ten critical vulnerabilities as per CVSS score are not displayed on C level report."
                    assert Nessus.TopTenVulnerabilitiesReport.VPR not in page_seven_content_list and severity_base in \
                           page_seven_content_list, "VPR column is present or severity base column is not present on " \
                                                    "CVSS based top ten critical vulnerabilities."

                    assert Nessus.TopTenVulnerabilitiesReport.TOP_TEN_HIGH_VPR in page_nine_content_list, \
                        "Top Ten High Vulnerabilities as per VPR score  are not displayed on C level report."
                    assert Nessus.TopTenVulnerabilitiesReport.VPR in page_nine_content_list and severity_base not in \
                           page_nine_content_list, "VPR column is not present or severity base column is present on " \
                                                   "VPR based top ten high vulnerabilities."

                    assert top_ten_high_cvss in page_ten_content_list, \
                        "Top Ten High Vulnerabilities as per CVSS score  are not displayed on C level report."
                    assert Nessus.TopTenVulnerabilitiesReport.VPR not in page_ten_content_list and severity_base in \
                           page_ten_content_list, "VPR column is present or severity base column is not present on " \
                                                  "CVSS based top ten high vulnerabilities."

                    assert Nessus.TopTenVulnerabilitiesReport.TOP_TEN_MOST_PREVALENT_VPR in page_thirteen_content_list, \
                        "Top Ten Most Prevalent Vulnerabilities as per VPR score  are not displayed on C level report."
                    assert Nessus.TopTenVulnerabilitiesReport.VPR in page_thirteen_content_list and severity_base not in \
                           page_thirteen_content_list, "VPR column is not present or severity base column is present " \
                                                       "on VPR based top ten most prevalent vulnerabilities."

                    assert top_ten_most_prevalent_cvss in page_fifteen_content_list, \
                        "Top Ten Most Prevalent Vulnerabilities as per CVSS score  are not displayed on C level report."
                    assert Nessus.TopTenVulnerabilitiesReport.VPR not in page_fifteen_content_list and severity_base \
                           in page_fifteen_content_list, "VPR column is present or severity base column is not " \
                                                         "present on CVSS based top ten most prevalent vulnerabilities"
                finally:
                    pdf_reader.close()
        finally:
            os.remove(file_path + ".{}".format(report_format))

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_custom_template",
                             [[{"id": "exploitable_vulns", "option_values": {"count": 25}}],
                              [{"id": "remediations", "option_values": {}},
                               {"id": "top10", "option_values": {"count": 10}}],
                              [{"id": "remediations", "option_values": {}},
                               {"id": "compliance", "option_values": {}},
                               {"id": "exploitable_vulns", "option_values": {"count": 25}}],
                              [{"id": "hosts_vulns", "option_values": {"count": 25}},
                               {"id": "year_old_vulns", "option_values": {"count": 25}},
                               {"id": "known_accounts_details", "option_values": {"count": 5}}]], indirect=True)
    def test_create_custom_template_using_various_chapters(self, create_custom_template):
        """
        NES-13317 : [API-Automation] : Design automation tests for new features in customized report
        Scenario Tested:
            Verify that custom template for scan reports can be generated using one or more than two chapters as below.
            [x] Using chapter  - 'exploitable_vulns'
            [x] Using chapters - 'remediations' and 'top10'
            [x] Using chapters - 'remediations' , 'compliance' and 'exploitable_vulns'
            [x] Using chapters - 'hosts_vulns', 'year_old_vulns' and 'known_accounts_details'
        """
        template_details = self.cat.api.reports.get_custom_template_details(
            template_id=create_custom_template.get('template_id'))

        assert template_details['chapters'] == create_custom_template.get('chapters'), \
            "Used chapters are not present in custom template details."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_custom_template",
                             [[{"id": "remediations", "option_values": {}},
                               {"id": "compliance", "option_values": {}},
                               {"id": "exploitable_vulns", "option_values": {"count": 25}}]], indirect=True)
    @pytest.mark.parametrize('additional_chapters', [[{"id": "year_old_vulns", "option_values": {"count": 25}},
                                                      {"id": "known_accounts_details", "option_values": {"count": 5}}]])
    @pytest.mark.parametrize('modify', ['name', 'description', 'add_chapter', 'remove_chapter', 'add_chapters',
                                        'remove_chapters'])
    def test_editing_of_custom_template(self, create_custom_template, modify, additional_chapters):
        """
        NES-13317 : [API-Automation] : Design automation tests for new features in customized report
        Scenario Tested:
            Modify custom template by modifying below items.
            [x] Name
            [x] Description
            [x] Add one chapter
            [x] Add multiple chapters
            [x] Remove one chapter
            [x] Remove multiple chapters
        """
        template_id = create_custom_template['template_id']
        template_details = self.cat.api.reports.get_custom_template_details(template_id=template_id)

        if modify == "name":
            new_template_name = random_name(prefix="automation-template-")
            template_details['name'] = new_template_name
            self.cat.api.reports.edit_custom_template(template_id=template_id, data=template_details)
            assert self.cat.api.reports.get_custom_template_details(template_id=template_id)[
                       'name'] == new_template_name, "Custom template Name has not been modified successfully."

        elif modify == "description":
            template_description = random_name(prefix="This template is created by automation test")
            template_details['description'] = template_description
            self.cat.api.reports.edit_custom_template(template_id=template_id, data=template_details)
            assert self.cat.api.reports.get_custom_template_details(template_id=template_id)[
                       'description'] == template_description, \
                "Custom template description has not been modified successfully."

        elif modify in ["remove_chapter", "remove_chapters"]:
            updated_chapters = template_details['chapters'][:-1 if modify == "remove_chapter" else -2]
            template_details['chapters'] = updated_chapters
            self.cat.api.reports.edit_custom_template(template_id=template_id, data=template_details)
            assert self.cat.api.reports.get_custom_template_details(template_id=template_id)[
                       'chapters'] == updated_chapters, \
                "Chapter/s has not been added successfully in existing custom template"

        elif modify in ["add_chapter", "add_chapters"]:
            updated_chapters = template_details['chapters']
            updated_chapters.append(additional_chapters[0])
            if modify == "add_chapters":
                updated_chapters.append(additional_chapters[1])
            template_details['chapters'] = updated_chapters
            self.cat.api.reports.edit_custom_template(template_id=template_id, data=template_details)
            assert self.cat.api.reports.get_custom_template_details(template_id=template_id)[
                       'chapters'] == updated_chapters, \
                "Chapter/s have not been removed from custom template successfully."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_custom_template",
                             [[{"id": "hosts_vulns", "option_values": {"count": 25}},
                               {"id": "year_old_vulns", "option_values": {"count": 25}},
                               {"id": "known_accounts_details", "option_values": {"count": 5}}]], indirect=True)
    def test_delete_custom_template(self, create_custom_template):
        """
        NES-13317 : [API-Automation] : Design automation tests for new features in customized report
        Scenario Tested:
            [x] Verify that custom template can be deleted successfully.
        """
        self.cat.api.reports.delete_custom_template(template_id=create_custom_template['template_id'])

        assert create_custom_template['template_name'] not in [
            template['name'] for template in self.cat.api.reports.get_report_templates() if template['system'] == 0], \
            "Template is not deleted successfully."

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("create_custom_template",
                             [[{"id": "hosts_vulns", "option_values": {"count": 25}},
                               {"id": "year_old_vulns", "option_values": {"count": 25}},
                               {"id": "known_accounts_details", "option_values": {"count": 5}}]], indirect=True)
    @pytest.mark.parametrize('chapters', [[{"id": "hosts_vulns", "option_values": {"count": 25}},
                                           {"id": "year_old_vulns", "option_values": {"count": 25}},
                                           {"id": "known_accounts_details", "option_values": {"count": 5}}]])
    def test_verify_custom_template_can_not_have_duplicate_name(self, create_custom_template, chapters):
        """
        NES-13317 : [API-Automation] : Design automation tests for new features in customized report
        Scenario Tested:
            [x] Verify that custom template can not be created using duplicate template name.
        """
        duplicate_template_name = create_custom_template['template_name']

        with expect_http_error(code=409, look_for='The same template name exists already'):
            self.cat.api.reports.create_custom_template(data={
                "name": duplicate_template_name, "description": "Created By Automation", "chapters": chapters})

    @pytest.mark.nessus_mat
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.nessus_home
    def test_by_default_system_templates(self):
        """
        NES-13386: Automate 'Customized Report' tab in NM/NP/Home using UI/API-automation
        Scenarios Tested:
            [x] Verify by default system templates are present in Nessus Manager/Pro.
        """
        nessus_type = self.cat.api.server.properties()['nessus_type']
        expected_templates = {Nessus.Manager.NESSUS_MANAGER: Nessus.SystemReportTemplates.MANAGER_SYSTEM_TEMPLATES,
                              Nessus.Professional.NESSUS_PROFESSIONAL:
                                  Nessus.SystemReportTemplates.PRO_SYSTEM_TEMPLATES,
                              Nessus.Essentials.NESSUS_ESSENTIALS: Nessus.SystemReportTemplates.HOME_SYSTEM_TEMPLATES}
        assert set(get_all_system_templates(api=self.cat.api)) == expected_templates[nessus_type]

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize("create_custom_template",
                             [[{"id": "remediations", "option_values": {}},
                               {"id": "compliance", "option_values": {}}],
                              [{"id": "vuln_by_host", "option_values": {
                                  "cvss_base_score": True, "cvss_temporal_score": True, "cvss3_base_score": True,
                                  "cvss3_temporal_score": True, "description": True, "exploitable_with": True,
                                  "host_information": True, "plugin_information": True, "plugin_output": True,
                                  "references": True, "risk_factor": True, "scan_information": True, "see_also": True,
                                  "solution": True, "stig_severity": True, "synopsis": True}},
                               {"id": "remediations", "option_values": {}}],
                              [{"id": "remediations", "option_values": {}},
                               {"id": "exploitable_vulns", "option_values": {"count": 25}},
                               {"id": "known_accounts", "option_values": {"count": 25}}]], indirect=True)
    @pytest.mark.parametrize('export_format', [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML])
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'advance_scan_c7kspv.nessus'}},
                                             {'scan': {"filename": 'Basic_Network_Scan_g5br3m.nessus'}}], indirect=True)
    def test_publish_report_using_custom_template(self, export_format, import_scan, create_custom_template):
        """
        NES-13441 : Publish report using customized report templates and for different scan types
        Scenario Tested:
            [x] Verify that scan report can be exported using customized report template and it is non-empty.
        """
        template_id = create_custom_template.get('template_id')
        template_name = create_custom_template.get('template_name')
        export = None
        scan_id = import_scan

        # export scan with different export formats and templates
        try:
            export = self.cat.api.scans.export(scan_id, export_format=export_format, template_id=template_id)
        except HTTPError:
            raise Exception("Error while exporting scan report with format - {} and template name - ".format(
                export_format, template_name))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get %s state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify that downloaded file is not empty
        assert len(download.content) > 0, "Downloaded file is empty"

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'Basic_Network_Scan_g5br3m.nessus'}},
                                             {'scan': {"filename": 'credential_Patch_audit_fst5sk.nessus'}},
                                             {'scan': {"filename": 'host_discovery_scan_dhame5.nessus'}},
                                             {'scan': {"filename": 'intel_amt_security_bypass_scan_ffclnc.nessus'}},
                                             {'scan': {"filename": 'internal_pci_network_scan_i5jc01.nessus'}},
                                             {'scan': {"filename": 'malware_scan_5bal9i.nessus'}},
                                             {'scan': {"filename": 'mdm_config_audit_scan_arjq1m.nessus'}},
                                             {'scan': {"filename": 'mobile_device_scan_qp10bz.db', "encrypted": True,
                                                       "password": "test1234"}},
                                             {'scan': {"filename": 'pci_quarterly_external_scan_3rzkfz.db',
                                                       "encrypted": True, "password": "test1234"}},
                                             {'scan': {"filename": 'policy_compliance_auditing_c175xd.db',
                                                       "encrypted": True, "password": "test1234"}}],
                             indirect=True)
    @pytest.mark.parametrize('export_format', [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML])
    @pytest.mark.parametrize('template_name', ["Detailed Vulnerabilities By Host with Compliance/Remediations",
                                               "Remediations"])
    def test_export_scan_report_for_different_scan_types(self, import_scan, export_format, template_name):
        """
        NES-13441 : Publish report using customized report templates and for different scan types
        Scenario Tested:
            [x] Verify that scan report can be exported for different scan types listed below.
                - Basic Network scan
                - Credentialed patch audit scan
                - Host Discovery scan
                - Intel AMT security bypass scan
                - Internal PCI Network scan
                - Malware scan
                - MDM Config Audit scan
                - Mobile Device Scan
                - PCI Quarterly External scan
                - Policy Compliance Auditing Scan
        """
        template_id = get_scan_report_template_id(api=self.cat.api, template_name=template_name)
        export = None
        scan_id = import_scan

        # export scan with different export formats and templates
        try:
            export = self.cat.api.scans.export(scan_id, export_format=export_format, template_id=template_id)
        except HTTPError:
            raise Exception("Error while exporting scan report with format - {} and template name - ".format(
                export_format, template_name))

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get %s state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download = self.cat.api.scans.download(scan_id, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify that downloaded file is not empty
        assert len(download.content) > 0, "Downloaded file is empty"

    @pytest.mark.xray(test_key='NES-18126')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('import_scan_via_api', [{'file_name': 'cvssv4_test_plugin_scan.nessus',
                                                      'file_path': 'nessus/tests/ui/scans/test_data/'}], indirect=True)
    @pytest.mark.parametrize('severity_base_value', ['cvss_v4'])
    @pytest.mark.parametrize('report_format', [API.Scan.ExportFormats.FORMAT_PDF])
    def test_verify_top_10_vuln_reports_shows_cvssv4_data(self, import_scan_via_api, severity_base_value,
                                                          report_format):
        """
        NES-18126 : Verify the reports contain correct cvss v4 data.

        Scenario Tested:
        [x] Report of PDF formate is showing the cvss v4 severity data.
        """
        import_scan_id = import_scan_via_api['id']
        self.cat.api.scans.update_severity_base(scan_id=import_scan_id, payload={"severity_base": severity_base_value})

        details_of_scan = self.cat.api.scans.details(scan_id=import_scan_id)
        host_id = details_of_scan['hosts'][0]['host_id']

        # getting cvssv4 plugin ids from scan
        severity_high_plugin_ids = [vuln['plugin_id'] for vuln in details_of_scan['vulnerabilities'] if vuln[
            'severity'] == 3]

        # getting expected high severity plugin id
        expected_cvssv4_plugin_id = get_plugin_id_of_highest_cvss_v4_score(
            nessus_api=self.cat.api, plugin_ids=severity_high_plugin_ids, host_id=host_id, scan_id=import_scan_id)

        # Verify that the severity is 'High'
        assert self.cat.api.scans.get_host_vulnerability(host_id=host_id, plugin_id=expected_cvssv4_plugin_id,
                                                         scan_id=import_scan_id)['info']['plugindescription'][
                   'severity'] == 3

        # Export the scan result
        scan_export = self.cat.api.scans.export(
            scan_id=import_scan_id, export_format=report_format, template_id=get_scan_report_template_id(
                api=self.cat.api, template_name="Top 10 Vulnerabilities"))

        wait(lambda: self.cat.api.scans.export_status(import_scan_id, scan_export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Scan export to get "%s" state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # download the file
        download = self.cat.api.scans.download(import_scan_id, scan_export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert download, "Exported file was not downloaded."

        file_path = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(import_scan_id))

        try:
            with open(file_path + ".{}".format(report_format), "wb") as file:
                for block in download.iter_content(1024):
                    file.write(block)
                file.close()

            if report_format == API.Scan.ExportFormats.FORMAT_PDF:
                pdf_reader = pdfplumber.open(file_path + ".{}".format(report_format))

                try:

                    # Verify top 10 High vulnerabilities list has vuln.
                    assert Nessus.TopTenVulnerabilitiesReport.TOP_TEN_HIGH_CVSS_V4 in pdf_reader.pages[
                        11].extract_text() and str(expected_cvssv4_plugin_id) in pdf_reader.pages[
                               11].extract_text(), "CVSS v4 vuln. is not available in top high vuln section."
                finally:
                    pdf_reader.close()
        finally:
            os.remove(file_path + ".{}".format(report_format))

