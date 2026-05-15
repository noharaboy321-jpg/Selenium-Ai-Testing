"""
:copyright: Tenable Network Security, 2017
:date: October 24, 2017
:author: @lestevez
"""
from http import HTTPStatus

import pytest
from nessus.helpers.waiters import wait_for_export_to_complete
from nessus.lib.const import API
from catium.helpers.testdata import get_file_path


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusExportsEndpointPro7:
    """
    Tests to make sure the custom exports endpoints can be used via the API in Nessus Pro 7.
    """

    cat = None

    # API_Tested# POST /scans/{scan_id}/export
    @pytest.mark.skip('As discussed, not in scope for Musikaar team to fix this, hence skipping.')
    def test_export_scan(self):
        """ Exporting scan is the only allowed scan API """

        # import scan
        file_path = get_file_path('nessus/tests/api/nessus_pro_7/test_data/host_scan.nessus')
        fileuploaded = self.cat.api.file.upload(file=file_path, encrypted=None)
        scan_imported = self.cat.api.scans.import_scan(file=fileuploaded, folder_id=None, password=None)

        self.cat.api.disable_automation_api_key()

        vulnerability_sections = {
            'synopsis': True,
            'description': False,
            'see_also': False,
            'solution': True,
            'risk_factor': True,
            'cvss3_base_score': True,
            'cvss3_temporal_score': True,
            'cvss_base_score': True,
            'cvss_temporal_score': True,
            'stig_severity': True,
            'references': True,
            'exploitable_with': True,
            'plugin_information': True,
            'plugin_output': True
        }

        formatting_options = {
            'page_breaks': False
        }

        host_sections = {
            'scan_information': True,
            'host_information': True
        }

        # check if format available
        scan_format_details = self.cat.api.scans.export_format_details(scan_imported['scan']['id'],
                                                                       scan_imported['scan']['id'])
        assert any(API.Scan.ExportFormats.FORMAT_PDF == format['value'] for format in
                   scan_format_details['formats']['format'])

        for host_section in scan_format_details['report_options']['hostSections']:
            assert host_section['key'] in host_sections.keys(), 'Host section is not available.'

        for format_option in scan_format_details['report_options']['formattingOptions']:
            assert format_option['key'] in formatting_options.keys(), 'Format option is not available.'

        for report_option in scan_format_details['report_options']['vulnerabilitySections']:
            assert report_option['key'] in vulnerability_sections.keys(), 'Report option is not available.'

        report_contents = {
            'vulnerabilitySections': vulnerability_sections,
            'formattingOptions': formatting_options,
            'hostSections': host_sections
        }

        # export scan
        export = self.cat.api.scans.export(scan_imported['scan']['id'], export_format=API.Scan.ExportFormats.FORMAT_PDF,
                                           report_contents=report_contents, password=None)

        # Get the export status and verify 200 response
        export_status = self.cat.api.scans.export_status(scan_imported['scan']['id'], export[0])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify export status was retrieved
        assert export_status, "Export status was not retrieved."

        # wait for to get ready state and max wait for 30 sec
        wait_for_export_to_complete(api=self.cat.api, scan_id=scan_imported['scan']['id'], file_id=export[0])

        # Download the exported file
        download = self.cat.api.scans.download(scan_imported['scan']['id'], export[0])

        # assert scan export status is retrieved
        assert download, "File was not downloaded."

        # export scan without report_contents
        export_1 = self.cat.api.scans.export(scan_imported['scan']['id'], export_format=API.Scan.ExportFormats.
                                             FORMAT_PDF, password=None)

        # Get the export status and verify 200 response
        export_status_1 = self.cat.api.scans.export_status(scan_imported['scan']['id'], export_1[0])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify export status was retrieved
        assert export_status_1, "export_1 status was not retrieved."

        # wait for to get ready state and max wait for 30 sec
        wait_for_export_to_complete(api=self.cat.api, scan_id=scan_imported['scan']['id'], file_id=export[0])

        # Download the exported file
        download_1 = self.cat.api.scans.download(scan_imported['scan']['id'], export_1[0])

        # assert scan export status is retrieved
        assert download_1, "File (download_1) was not downloaded."

        self.cat.api.enable_automation_api_key()

        # Delete the imported scan
        self.cat.api.scans.delete(scan_imported['scan']['id'])
