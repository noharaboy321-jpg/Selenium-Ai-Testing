"""
Nessus Scan export related endpoint verification

Test cases for export scan/scan history

:copyright: Tenable Network Security, 2019
:date: Nov 02, 2020
:last_modified: May 13, 2021
:author: @vsoni, @kpanchal
"""

import csv
import io
import os
from http import HTTPStatus

import pytest
from requests.exceptions import HTTPError
from waiting import wait

from catium.helpers.testdata import get_file_path
from catium.lib.const import WAIT_NORMAL
from catium.lib.const.base_constants import TIME_SIXTY_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.helpers.scan import get_scan_report_template_id
from nessus.helpers.settings import get_current_advanced_setting_value
from nessus.helpers.system import is_manager
from nessus.lib.config import NessusConfig
from nessus.lib.const import API

log = create_logger()


@pytest.mark.scanning
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusScanExport:
    """Tests related to scan export feature"""

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.xfail(reason="Refer JIRA ID SCE-2733")
    @pytest.mark.parametrize('scan', [{"filename": 'Entire_Home_Lab_d04l5k.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'advance_scan_c7kspv.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'basic_network_scan_59ro29.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'credential_Patch_audit_fst5sk.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-680
                                      {"filename": 'host_discovery_scan_dhame5.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-682
                                      {"filename": 'intel_amt_security_bypass_scan_ffclnc.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-683
                                      {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'malware_scan_5bal9i.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-685
                                      {"filename": 'mdm_config_audit_scan_arjq1m.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-686
                                      {"filename": 'mobile_device_scan_mr21e2.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'pci_quarterly_external_scan_s4hruv.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'policy_compliance_auditing_jsp7c7.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'scap_and_oval_auditing_scan_udk5xk.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'wannacry_ransomware_0bnkcb.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'web_application_test_scan_zuni9y.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'offline_config_audit_scan_rb06f6.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                                      {"filename": 'Audit_Cloud_Infrastructure_0xmbqp.nessus',
                                       "export_format": API.Scan.ExportFormats.FORMAT_CSV}])
    # API_Tested# POST /scans/{scan_id}/export
    def test_export_scan_csv(self, scan):
        """
            Verifies the scan export status can be retrieved and can be downloaded.

            Scenarios tested:
              [x] Successfully export scans as CSV with no user selected options
              [x] Successfully export scans as CSV with only legacy options selected
              [x] Successfully export scans as CSV with all options selected
              [x] Successfully export scans as CSV with some options selected
        """
        if not is_manager():
            expected_severity_base_value = 'cvss_v3'
            default_severity_value = get_current_advanced_setting_value(api=self.cat.api, setting_name='severity_basis')

            if default_severity_value != expected_severity_base_value:
                setting_payload = {"setting.0.name": "severity_basis", "setting.0.value": expected_severity_base_value,
                                   "setting.0.action": "edit"}

                self.cat.api.settings.update(settings=setting_payload)

        # import scan
        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])
        fileuploaded = self.cat.api.file.upload(file=file, encrypted=scan.get('encrypted', None))
        import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None, password=scan.get('password', None))

        # check if format available
        formats = self.cat.api.scans.export_format_details(import_scan['scan']['id'], import_scan['scan']['id'])
        assert any(scan['export_format'] == export_format['value'] for export_format in formats['formats']['format'])

        test_options = [
            {
                "report_contents": {},
                "result_file": scan['filename'] + ".no_options.csv"
            },
            {
                "report_contents": {
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
                        "cvss3_base_score": False,
                        "cvss_temporal_score": False,
                        "cvss3_temporal_score": False,
                        "risk_factor": False,
                        "references": False,
                        "plugin_information": False,
                        "exploitable_with": False,
                    }
                },
                "result_file": scan['filename'] + ".no_options.csv"  # default options is the same as no options
            },
            {
                "report_contents": {
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
                        "stig_severity": True,
                        "cvss3_base_score": True,
                        "cvss_temporal_score": True,
                        "cvss3_temporal_score": True,
                        "risk_factor": True,
                        "references": True,
                        "plugin_information": True,
                        "exploitable_with": True,
                    }
                },
                "result_file": scan['filename'] + ".all_options.csv"  # default options is the same as no options
            },
            {
                "report_contents": {
                    "csvColumns": {
                        "id": True,
                        "cve": True,
                        "cvss_base_score": True,
                        "risk": True,
                        "hostname": True,
                        "protocol": False,
                        "port": True,
                        "plugin_name": False,
                        "synopsis": False,
                        "description": False,
                        "solution": True,
                        "see_also": False,
                        "plugin_output": True,
                        "stig_severity": False,
                        "cvss3_base_score": True,
                        "cvss_temporal_score": False,
                        "cvss3_temporal_score": True,
                        "risk_factor": True,
                        "references": False,
                        "plugin_information": True,
                        "exploitable_with": True,
                    }
                },
                "result_file": scan['filename'] + ".some_options.csv"  # default options is the same as no options
            },
        ]

        for test_option in test_options:
            # export scan with report_contents
            export = self.cat.api.scans.export(import_scan['scan']['id'], export_format=scan['export_format'],
                                               report_contents=test_option["report_contents"])

            # Get the export status and verify 200 response
            export_status = self.cat.api.scans.export_status(import_scan['scan']['id'], export[0])
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            # Verify export status was retrieved
            assert export_status, "Export status was not retrieved."

            # wait for to get ready state and max wait for 30 sec
            wait(lambda: self.cat.api.scans.export_status(import_scan['scan']['id'], export[0]) == API.Status.READY,
                 timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Scan to go state %s' % API.Status.READY,
                 sleep_seconds=WAIT_NORMAL)

            # Download the exported file
            download = self.cat.api.scans.download(import_scan['scan']['id'], export[0])

            # assert scan export status is retrieved
            assert download, "File was not downloaded."
            if "result_file" in test_option:
                result_file_path = get_file_path('nessus/tests/api/scan/test_data/' + test_option["result_file"])
                print('result_file_path = ' + result_file_path)
                with open(result_file_path, "rb") as result_file:
                    for downloaded_block in download.iter_content(128):
                        result_block = result_file.read(128)
                        assert downloaded_block == result_block, "CSV Result not correct"
                        if downloaded_block != result_block:
                            break
                result_file.close()

        # Delete the imported scan
        self.cat.api.scans.delete(import_scan['scan']['id'])

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.parametrize('scan',
                             [pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_NESSUS}),  # NQA-675
                              pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_HTML}),  # NQA-675
                              pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_CSV}),  # NQA-675
                              pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_PDF}),  # NQA-675
                              pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_DB, "password": "test1234"}),  # NQA-675

                              pytest.param({"filename": 'basic_network_scan_59ro29.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_NESSUS}),  # NQA-679
                              pytest.param({"filename": 'basic_network_scan_59ro29.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_HTML}),  # NQA-679
                              pytest.param({"filename": 'basic_network_scan_59ro29.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_CSV}),  # NQA-679
                              pytest.param({"filename": 'basic_network_scan_59ro29.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_PDF}),  # NQA-679
                              pytest.param({"filename": 'basic_network_scan_59ro29.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_DB, "password": "test1234"}),  # NQA-679

                              {"filename": 'credential_Patch_audit_fst5sk.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},
                              # NQA-680
                              {"filename": 'credential_Patch_audit_fst5sk.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},  # NQA-680
                              {"filename": 'credential_Patch_audit_fst5sk.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-680
                              {"filename": 'credential_Patch_audit_fst5sk.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},  # NQA-680
                              {"filename": 'credential_Patch_audit_fst5sk.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-680

                              {"filename": 'host_discovery_scan_dhame5.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},  # NQA-682
                              {"filename": 'host_discovery_scan_dhame5.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},  # NQA-682
                              {"filename": 'host_discovery_scan_dhame5.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-682
                              {"filename": 'host_discovery_scan_dhame5.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},  # NQA-682
                              {"filename": 'host_discovery_scan_dhame5.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-682

                              {"filename": 'intel_amt_security_bypass_scan_ffclnc.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},  # NQA-683
                              {"filename": 'intel_amt_security_bypass_scan_ffclnc.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},  # NQA-683
                              {"filename": 'intel_amt_security_bypass_scan_ffclnc.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-683
                              {"filename": 'intel_amt_security_bypass_scan_ffclnc.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},  # NQA-683
                              {"filename": 'intel_amt_security_bypass_scan_ffclnc.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-683

                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},
                              # NQA-684
                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},
                              # NQA-684
                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                              # NQA-684
                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},
                              # NQA-684
                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-684

                              {"filename": 'malware_scan_5bal9i.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},  # NQA-685
                              {"filename": 'malware_scan_5bal9i.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},  # NQA-685
                              {"filename": 'malware_scan_5bal9i.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-685
                              {"filename": 'malware_scan_5bal9i.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},  # NQA-685
                              {"filename": 'malware_scan_5bal9i.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA- 685

                              {"filename": 'mdm_config_audit_scan_arjq1m.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},  # NQA-686
                              {"filename": 'mdm_config_audit_scan_arjq1m.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},  # NQA-686
                              {"filename": 'mdm_config_audit_scan_arjq1m.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-686
                              {"filename": 'mdm_config_audit_scan_arjq1m.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},  # NQA-686
                              {"filename": 'mdm_config_audit_scan_arjq1m.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-686

                              {"filename": 'mobile_device_scan_mr21e2.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},  # NQA-687
                              {"filename": 'mobile_device_scan_mr21e2.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},  # NQA-687
                              {"filename": 'mobile_device_scan_mr21e2.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-687
                              {"filename": 'mobile_device_scan_mr21e2.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},  # NQA-687
                              {"filename": 'mobile_device_scan_mr21e2.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},

                              {"filename": 'pci_quarterly_external_scan_s4hruv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},
                              # NQA-689
                              {"filename": 'pci_quarterly_external_scan_s4hruv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},
                              # NQA-689
                              {"filename": 'pci_quarterly_external_scan_s4hruv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                              # NQA-689
                              {"filename": 'pci_quarterly_external_scan_s4hruv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},
                              # NQA-689
                              {"filename": 'pci_quarterly_external_scan_s4hruv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-689

                              pytest.param({"filename": 'policy_compliance_auditing_jsp7c7.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_NESSUS}),  # NQA-690
                              pytest.param({"filename": 'policy_compliance_auditing_jsp7c7.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_HTML}),  # NQA-690
                              pytest.param({"filename": 'policy_compliance_auditing_jsp7c7.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_CSV}),  # NQA-690
                              pytest.param({"filename": 'policy_compliance_auditing_jsp7c7.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_PDF}),  # NQA-690
                              pytest.param({"filename": 'policy_compliance_auditing_jsp7c7.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_DB, "password": "test1234"}),  # NQA-690

                              pytest.param({"filename": 'scap_and_oval_auditing_scan_udk5xk.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_NESSUS}),  # NQA-691
                              pytest.param({"filename": 'scap_and_oval_auditing_scan_udk5xk.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_HTML}),  # NQA-691
                              pytest.param({"filename": 'scap_and_oval_auditing_scan_udk5xk.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_CSV}),  # NQA-691
                              pytest.param({"filename": 'scap_and_oval_auditing_scan_udk5xk.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_PDF}),  # NQA-691
                              pytest.param({"filename": 'scap_and_oval_auditing_scan_udk5xk.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_DB, "password": "test1234"}),  # NQA- 691

                              {"filename": 'wannacry_ransomware_0bnkcb.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},  # NQA-693
                              {"filename": 'wannacry_ransomware_0bnkcb.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},  # NQA-693
                              {"filename": 'wannacry_ransomware_0bnkcb.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-693
                              {"filename": 'wannacry_ransomware_0bnkcb.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},  # NQA-693
                              {"filename": 'wannacry_ransomware_0bnkcb.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-693

                              {"filename": 'web_application_test_scan_zuni9y.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},
                              # NQA-694
                              {"filename": 'web_application_test_scan_zuni9y.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},
                              # NQA-694
                              {"filename": 'web_application_test_scan_zuni9y.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                              # NQA-694
                              {"filename": 'web_application_test_scan_zuni9y.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},
                              # NQA-694
                              {"filename": 'web_application_test_scan_zuni9y.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-694
                              {"filename": 'offline_config_audit_scan_rb06f6.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},
                              # NQA-688
                              {"filename": 'offline_config_audit_scan_rb06f6.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},
                              # NQA-688
                              {"filename": 'offline_config_audit_scan_rb06f6.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                              # NQA-688
                              {"filename": 'offline_config_audit_scan_rb06f6.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},
                              # NQA-688
                              {"filename": 'offline_config_audit_scan_rb06f6.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-688

                              {"filename": 'Audit_Cloud_Infrastructure_0xmbqp.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},
                              # NQA-676
                              {"filename": 'Audit_Cloud_Infrastructure_0xmbqp.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},
                              # NQA-676
                              {"filename": 'Audit_Cloud_Infrastructure_0xmbqp.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},
                              # NQA-676
                              {"filename": 'Audit_Cloud_Infrastructure_0xmbqp.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"},  # NQA-676
                              {"filename": 'advance_scan_c7kspv.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML,
                               "chapters": "vuln_by_host"}])  # NQA-159 step 3
    # API_Tested# POST /scans/{scan_id}/export
    def test_export_scan(self, scan):
        """
            Verifies the scan export status can be retrieved and can be downloaded.

            Scenarios tested:
              [x] Successfully export scans as CSV
              [x] Successfully export scans as PDF
              [x] Successfully export scans as HTML
              [x] Successfully export scans as XML (.nessus)
              [x] Successfully export scans as sqlite3 (Nessus DB)
              [ ] Try to export a scan but provide invalid chapters
              [ ] Try to export a scan but provide an invalid export format
              [ ] Try to export as a Nessus DB but provide no password
              [ ] Try to export a scan that's currently running
        """
        # import scan
        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])
        fileuploaded = self.cat.api.file.upload(file=file, encrypted=scan.get('encrypted', None))
        import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None, password=scan.get('password', None))

        # check if format available
        formats = self.cat.api.scans.export_format_details(import_scan['scan']['id'], import_scan['scan']['id'])
        format_list = formats['formats']['export'] if scan['export_format'] in ['nessus', 'db'] \
            else formats['formats']['format']
        assert any(scan['export_format'] == export_format['value'] for export_format in format_list)

        vulnerability_sections = {
            'synopsis': True,
            'description': False,
            'see_also': False,
            'solution': True,
            'risk_factor': True,
            'cvss3_base_score': True,
            'cvss3_temporal_score': True,
            'cvss_base_score': False,
            'cvss_temporal_score': False,
            'stig_severity': True,
            'references': False,
            'exploitable_with': True,
            'plugin_information': True,
            'plugin_output': True
        }

        host_sections = {
            'scan_information': True,
            'host_information': True
        }

        formatting_options = {
            'page_breaks': True
        }

        report_contents = {
            'vulnerabilitySections': vulnerability_sections,
            'hostSections': host_sections,
            'formattingOptions': formatting_options
        }

        # export scan with report_contents
        export = self.cat.api.scans.export(import_scan['scan']['id'], export_format=scan['export_format'],
                                           password=scan.get('password', None), chapters=scan.get('chapters', None),
                                           template_id=get_scan_report_template_id(
                                               api=self.cat.api,
                                               template_name="Complete List of Vulnerabilities by Host") if
                                           scan['export_format'] in [API.Scan.ExportFormats.FORMAT_PDF,
                                                                     API.Scan.ExportFormats.FORMAT_HTML] else None,
                                           report_contents=report_contents)

        # Get the export status and verify 200 response
        export_status = self.cat.api.scans.export_status(import_scan['scan']['id'], export[0])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify export status was retrieved
        assert export_status, "Export status was not retrieved."

        # wait for to get ready state and max wait for 30 sec
        wait(lambda: self.cat.api.scans.export_status(import_scan['scan']['id'], export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Scan to go state %s' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download = self.cat.api.scans.download(import_scan['scan']['id'], export[0])

        # assert scan export status is retrieved
        assert download, "File was not downloaded."

        # export scan without report_contents
        export_1 = self.cat.api.scans.export(import_scan['scan']['id'], export_format=scan['export_format'],
                                             password=scan.get('password', None), chapters=scan.get('chapters', None),
                                             template_id=get_scan_report_template_id(
                                                 api=self.cat.api,
                                                 template_name="Complete List of Vulnerabilities by Host") if
                                             scan['export_format'] in [API.Scan.ExportFormats.FORMAT_PDF,
                                                                       API.Scan.ExportFormats.FORMAT_HTML] else None)

        # Get the export status and verify 200 response
        export_status_1 = self.cat.api.scans.export_status(import_scan['scan']['id'], export_1[0])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify export status was retrieved
        assert export_status_1, "export_1 status was not retrieved."

        # wait for to get ready state and max wait for 30 sec
        wait(lambda: self.cat.api.scans.export_status(import_scan['scan']['id'], export_1[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Scan to go state %s' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download_1 = self.cat.api.scans.download(import_scan['scan']['id'], export_1[0])

        # assert scan export status is retrieved
        assert download_1, "File (download_1) was not downloaded."

        # Delete the imported scan
        self.cat.api.scans.delete(import_scan['scan']['id'])

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('scan', [
        {"filename": 'Entire_Home_Lab_d04l5k.nessus', "export_format": API.Scan.ExportFormats.FORMAT_HTML},
        {"filename": 'Entire_Home_Lab_d04l5k.nessus', "export_format": API.Scan.ExportFormats.FORMAT_PDF},
        {"filename": 'Entire_Home_Lab_d04l5k.nessus', "export_format": API.Scan.ExportFormats.FORMAT_CSV}])
    # API_Tested# POST /scans/{scan_id}/export
    def test_export_scan_with_selections(self, scan):
        """
            Verifies the scan report with selected hosts or vulnerabilities

            Scenarios tested:
              [x] Successfully export scans as CSV with selected hosts
              [x] Successfully export scans as CSV with selected vulnerabilities
              [x] Successfully export scans as PDF with selected hosts
              [x] Successfully export scans as PDF with selected vulnerabilities
              [x] Successfully export scans as HTML with selected hosts
              [x] Successfully export scans as HTML with selected vulnerabilities
        """
        # import scan
        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])
        fileuploaded = self.cat.api.file.upload(file=file, encrypted=scan.get('encrypted', None))
        import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None, password=scan.get('password', None))

        # check if format available
        formats = self.cat.api.scans.export_format_details(import_scan['scan']['id'], import_scan['scan']['id'])
        assert any(scan['export_format'] == export_format['value'] for export_format in formats['formats']['format'])

        vulnerability_sections = {
            'synopsis': True,
            'description': False,
            'see_also': False,
            'solution': True,
            'risk_factor': True,
            'cvss3_base_score': True,
            'cvss3_temporal_score': True,
            'cvss_base_score': False,
            'cvss_temporal_score': False,
            'stig_severity': True,
            'references': False,
            'exploitable_with': True,
            'plugin_information': True,
            'plugin_output': True
        }

        host_sections = {
            'scan_information': True,
            'host_information': True
        }

        formatting_options = {
            'page_breaks': True
        }

        report_contents = {
            'vulnerabilitySections': vulnerability_sections,
            'hostSections': host_sections,
            'formattingOptions': formatting_options
        }

        filters = [
            {
                # search by host selection
                "host_ids": [1, 2, 3]
            },
            {
                # the search actually seems to use stringed ids, so test for that
                "host_ids": ["2"]
            },
            {
                # search by vuln selection
                "plugin_ids": [79638, 102683, 100464]
            },
            {
                # drilldown to vuln uses a stringed id
                "plugin_ids": ["79638"]
            },
            {
                # combination of host drilldown and vuln selection
                "host_ids": ["1"],
                "plugin_ids": [11219]
            }
        ]

        def verify_csv(csv_contents, extra_filters):
            """ Check the "Plugin ID" and "Host" columns of a CSV download against filters """

            # convert hostname to host ids for this scan
            host_id_lookup = {'192.168.15.201': 1, '192.168.15.200': 2, '192.168.15.199': 3}
            csvfile = io.StringIO(csv_contents.decode('utf-8'))
            csv_reader = csv.reader(csvfile, delimiter=',', quotechar='"', escapechar='\\')
            _ = next(csv_reader)

            for line in csv_reader:
                vuln = int(line[0])
                host = line[4]
                host_id = host_id_lookup[host] if host in host_id_lookup else -1

                if 'host_ids' in extra_filters:
                    assert host_id in extra_filters['host_ids'] or str(host_id) in extra_filters['host_ids'], \
                        "CSV contained a host not filtered for: %s" % host
                if 'plugin_ids' in extra_filters:
                    assert vuln in extra_filters['plugin_ids'] or str(vuln) in extra_filters['plugin_ids'], \
                        "CSV contained a plugin id not filtered for: %d" % vuln

        for extraFilters in filters:

            # export scan with report_contents
            export = self.cat.api.scans.export(import_scan['scan']['id'], export_format=scan['export_format'],
                                               password=scan.get('password', None), chapters=scan.get('chapters', None),
                                               template_id=get_scan_report_template_id(
                                                   api=self.cat.api,
                                                   template_name="Complete List of Vulnerabilities by Host") if
                                               scan['export_format'] in [API.Scan.ExportFormats.FORMAT_PDF,
                                                                         API.Scan.ExportFormats.FORMAT_HTML] else None,
                                               report_contents=report_contents, extra_filters=extraFilters)

            # Get the export status and verify 200 response
            export_status = self.cat.api.scans.export_status(import_scan['scan']['id'], export[0])
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            # Verify export status was retrieved
            assert export_status, "Export status was not retrieved."

            # wait for to get ready state and max wait for 30 sec
            wait(lambda: self.cat.api.scans.export_status(import_scan['scan']['id'], export[0]) == API.Status.READY,
                 timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Scan to go state %s' % API.Status.READY,
                 sleep_seconds=WAIT_NORMAL)

            # Download the exported file
            download = self.cat.api.scans.download(import_scan['scan']['id'], export[0])

            # assert scan export status is retrieved
            assert download, "File was not downloaded."

            # export scan without report_contents
            export_1 = self.cat.api.scans.export(import_scan['scan']['id'], export_format=scan['export_format'],
                                                 password=scan.get('password', None),
                                                 chapters=scan.get('chapters', None),
                                                 template_id=get_scan_report_template_id(
                                                     api=self.cat.api,
                                                     template_name="Complete List of Vulnerabilities by Host") if
                                                 scan['export_format'] in [API.Scan.ExportFormats.FORMAT_PDF,
                                                                           API.Scan.ExportFormats.FORMAT_HTML]
                                                 else None, extra_filters=extraFilters)

            # Get the export status and verify 200 response
            export_status_1 = self.cat.api.scans.export_status(import_scan['scan']['id'], export_1[0])
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            # Verify export status was retrieved
            assert export_status_1, "export_1 status was not retrieved."

            # wait for to get ready state and max wait for 30 sec
            wait(lambda: self.cat.api.scans.export_status(import_scan['scan']['id'], export_1[0]) == API.Status.READY,
                 timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Scan to go state %s' % API.Status.READY,
                 sleep_seconds=WAIT_NORMAL)

            # Download the exported file
            download_1 = self.cat.api.scans.download(import_scan['scan']['id'], export_1[0])
            if scan['export_format'] == API.Scan.ExportFormats.FORMAT_CSV:
                verify_csv(download_1.content, extraFilters)

            # assert scan export status is retrieved
            assert download_1, "File (download_1) was not downloaded."

        # Delete the imported scan
        self.cat.api.scans.delete(import_scan['scan']['id'])

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.incompatible
    @pytest.mark.parametrize('scan',
                             [pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_NESSUS}),  # NQA-766
                              pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_HTML}),  # NQA-766
                              pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_CSV}),  # NQA-766
                              pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_PDF}),  # NQA-766
                              pytest.param({"filename": 'advance_scan_c7kspv.nessus',
                                            "export_format": API.Scan.ExportFormats.FORMAT_DB, "password": "test1234"}),  # NQA-766

                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_NESSUS},  # NQA-767
                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_HTML},  # NQA-767
                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_CSV},  # NQA-767
                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_PDF},  # NQA-767
                              {"filename": 'internal_pci_network_scan_i5jc01.nessus',
                               "export_format": API.Scan.ExportFormats.FORMAT_DB,
                               "password": "test1234"}])  # NQA-767
    # API_Tested# POST /scans/{scan_id}/export
    def test_export_scan_history(self, scan):
        """
            Verifies the scan export history can be retrieved.

            Scenarios tested:
              [x] Successfully export a specific scan history item
              [ ] Try exporting a scan history item that doesn't exist
              [ ] Try exporting a scan history item for a scan that doesn't exist
        """

        # import scan
        file = get_file_path('nessus/tests/api/scan/test_data/' + scan['filename'])
        fileuploaded = self.cat.api.file.upload(file=file, encrypted=scan.get('encrypted', None))
        import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None, password=scan.get('password', None))

        # Get history id
        details = self.cat.api.scans.details(import_scan['scan']['id'])
        history_id = details['history'][0]['history_id']

        # export scan history
        export = self.cat.api.scans.export(import_scan['scan']['id'], export_format=scan['export_format'],
                                           password=scan.get('password', None), history_id=history_id,
                                           template_id=get_scan_report_template_id(
                                               api=self.cat.api,
                                               template_name="Complete List of Vulnerabilities by Host") if
                                           scan['export_format'] in [API.Scan.ExportFormats.FORMAT_PDF,
                                                                     API.Scan.ExportFormats.FORMAT_HTML] else None)

        # Getting supported export formats
        supported_export_formats = [export_format['name'] for export_format in
                                    self.cat.api.scans.export_format_details(
                                        import_scan['scan']['id'], import_scan['scan']['id'])['formats']['format']]
        log.debug("Supported export formats are : {}".format(supported_export_formats))
        with SSH() as ssh:
            log.debug("Java version is : {}".format(ssh.execute(command="java -version")))

        # Get the export status and verify 200 response
        export_status = self.cat.api.scans.export_status(import_scan['scan']['id'], export[0])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify export status was retrieved
        assert export_status, "Export status was not retrieved."

        # wait for to get ready state and max wait for 30 sec
        wait(lambda: self.cat.api.scans.export_status(import_scan['scan']['id'], export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='Scan to go state %s' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download = self.cat.api.scans.download(import_scan['scan']['id'], export[0])

        # assert scan export status is retrieved
        assert download, "File was not downloaded."

        # Delete the imported scan
        self.cat.api.scans.delete(import_scan['scan']['id'])

    @pytest.mark.nessus_manager
    @pytest.mark.incompatible
    @pytest.mark.parametrize('import_scan', [{
        'scan': {"filename": 'Engine_Test_-_Compliance_Targeted_qo3sdk.nessus'}}], indirect=True)
    @pytest.mark.parametrize('export_format', [API.Scan.ExportFormats.FORMAT_PDF, API.Scan.ExportFormats.FORMAT_HTML])
    @pytest.mark.parametrize('chapter', ['vuln_hosts_summary', 'custom;vuln_by_plugin',
                                         'vuln_hosts_summary;compliance_exec', 'custom;compliance',
                                         'custom;remediations',
                                         'custom;vuln_by_host;compliance;remediations;vulnerabilities'])
    def test_export_scan_report_using_different_chapters(self, import_scan, export_format, chapter):
        """
        NES-12235 : [API] Verify export scan reports in NM

        Scenarios Tested:
            Verify that scan report can be exported for below chapters and file formats
            [x] chapter - 'vuln_hosts_summary', export format - PDF or HTML
            [x] chapter - 'custom;vuln_by_plugin', export format - PDF or HTML
            [x] chapter - 'vuln_hosts_summary;compliance_exec', export format - PDF or HTML
            [x] chapter - 'custom;compliance', export format - PDF or HTML
            [x] chapter - 'custom;remediations', export format - PDF or HTML
            [x] chapter - 'custom;vuln_by_host;compliance;remediations;vulnerabilities', export format - PDF or HTML
        """
        scan_id = import_scan

        # export scan with different export formats and chapters
        try:
            export = self.cat.api.scans.export(scan_id, export_format=export_format, chapters=chapter)
        except HTTPError:
            raise Exception("Error while exporting scan report with format - {} and chapter - ".format(
                export_format, chapter))

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.cat.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2, waiting_for='Scan export to get %s state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download = self.cat.api.scans.download(scan_id, export[0])

        # Verify that downloaded file is not empty
        assert len(download.content) > 0, "Downloaded file is empty"

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('import_scan', [{'scan': {"filename": 'Microsoft_Security_Guidelines_Scan_dgd41f.db',
                                                       "password": "Tenable123", "encrypted": True}}], indirect=True)
    def test_scan_results_after_exported_filtered_compliance_scan(self, import_scan):
        """
        NES-12399: [API] Automated test case for CS-38176

        Steps:
        1. Import nessusdb scan
        2. Click Compliance Tab > Add Filter > Audit Severity = Passed
        3. Click Export > Nessus
        4. Import Nessus or Open exported Nessus and see no results.

        Scenario Tested:
        [x] Verify that user can get the scan results successfully by importing the scan that is exported with
            filtered compliance.
        """
        filter_dict = {"filter.0.quality": "eq", "filter.0.filter": "audit_severity", "filter.0.value": "PASSED",
                       "filter.search_type": "and"}

        export = self.cat.api.scans.export(scan_id=import_scan, export_format=API.Scan.ExportFormats.FORMAT_NESSUS,
                                           extra_filters=filter_dict)

        # Get the export status and verify 200 response
        export_status = self.cat.api.scans.export_status(import_scan, export[0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify export status was retrieved
        assert export_status, "Export status was not retrieved."

        # wait for to get ready state and max wait for 30 sec
        wait(lambda: self.cat.api.scans.export_status(import_scan, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS, waiting_for='export status to get %s' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download = self.cat.api.scans.download(import_scan, export[0])

        # assert scan export status is retrieved
        assert download, "Exported file was not downloaded."

        file_name = os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, 'exported_file_{}'.format(import_scan))

        with open(file_name + ".nessus", "wb") as file:
            for block in download.iter_content(1024):
                file.write(block)
            file.close()

        log.debug("[download_scan]: Exported Scan file saved at %s.nessus", file_name)

        try:
            fileuploaded = self.cat.api.file.upload(file=file_name + ".nessus", encrypted=True)
            import_scan = self.cat.api.scans.import_scan(fileuploaded, folder_id=None, password=None)

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            scan_details = self.cat.api.scans.details(import_scan['scan']['id'])

            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            assert scan_details['info'] and scan_details['compliance'], \
                "Failed to get the scan results after importing the filtered compliance scan."

            assert all([True for compliance_detail in scan_details['compliance'] if compliance_detail[
                'severity'] == 1]), "Failed to get filtered compliance results from imported scan."
        finally:
            self.cat.api.scans.delete(import_scan['scan']['id'])
