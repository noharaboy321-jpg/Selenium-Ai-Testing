import json
import os
import tempfile
import uuid

import pytest
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.const import TIME_SIXTY_SECONDS, WAIT_NORMAL, TIME_TEN_MINUTES
from catium.lib.util import random_string
from requests import HTTPError

from nessus.lib.config import NessusConfig
from nessus.apiobjects.nessus_api import NessusAPI

from waiting import wait
from nessus.helpers.scan import create_scan_helper, get_scan_report_template_id, download_and_save_exported_scan_file

from nessus.lib.const.constants import API, Nessus, Scanner


"""
Nessus ASD Scan data

Test cases for ASD reports and exports
ASD helper class

:copyright: Tenable Network Security, 20122
:date: Dec 08, 2022
:last_modified: Dec 09, 2022
:author: @kdodson
"""


@pytest.mark.nessus_expert
@pytest.mark.usefixtures('nessus_api_login')
class TestAsdScans:
    cat = None

    @pytest.mark.xray(test_key='NES-16770')
    @pytest.mark.parametrize('report_format', [
        API.Scan.ExportFormats.FORMAT_PDF,
        API.Scan.ExportFormats.FORMAT_HTML,
        API.Scan.ExportFormats.FORMAT_CSV
    ])
    def test_asd_report_formats(self, report_format):
        """
        NES-16770: Validate reporting on completed ASD scan0

        Scenario Tested:
        Create and Launch ASD scan
        Wait for completed ASD scan
        Create and download a report in report_format
        Validate the downloaded report data
        """
        scan_id = None
        asd_helper = AsdHelper(api=self.cat.api)
        try:
            # Creating the payload, the scan, and then launching the scan and waiting till it is finished
            payload = asd_helper.get_asd_payload()
            scan_id = asd_helper.create_and_launch(payload=payload)

            # Downloading the report with a report template if needed
            report_template_id = None
            if report_format != API.Scan.ExportFormats.FORMAT_CSV:
                report_template_id = get_scan_report_template_id(
                    api=self.cat.api,
                    template_name=Nessus.SystemReportTemplates.DETIALED_VULNS_BY_HOST
                )
            download_response = asd_helper.generate_report_or_export_and_download_file(
                scan_id=scan_id,
                report_format=report_format,
                template_id=report_template_id
            )

            # Validating returned data
            assert len(download_response.content) > 0, "Downloaded file is empty"
            attachment_header = download_response.headers["content-disposition"]
            assert "attachment" in attachment_header and "filename" in attachment_header, \
                f"The file desired was not returned {attachment_header}"
            if report_format == API.Scan.ExportFormats.FORMAT_PDF:
                assert ".pdf" in attachment_header, f"A pdf file did not return, {attachment_header}"
            elif report_format == API.Scan.ExportFormats.FORMAT_HTML:
                assert ".html" in attachment_header, f"A html file did not return, {attachment_header}"
            elif report_format == API.Scan.ExportFormats.FORMAT_CSV:
                assert ".csv" in attachment_header, f"A csv file was not returned, {attachment_header}"
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)

    @pytest.mark.xray(test_key='NES-16771')
    @pytest.mark.parametrize('export_format', [
        API.Scan.ExportFormats.FORMAT_NESSUS,
        API.Scan.ExportFormats.FORMAT_DB,
    ])
    def test_asd_exports(self, export_format):
        """
        NES-16771: Validate exporting of completed ASD scan

        Scenario Tested:
        Create and Launch ASD scan
        Wait for completed ASD scan
        Create and download exports
        Validate the downloaded export data
        """
        scan_id = None
        asd_helper = AsdHelper(api=self.cat.api)
        try:
            # Creating the payload, the scan, and then launching the scan and waiting till it is finished
            payload = asd_helper.get_asd_payload()
            scan_id = asd_helper.create_and_launch(payload=payload)

            # Downloading an export with a password if needed
            password = None
            if export_format == API.Scan.ExportFormats.FORMAT_DB:
                password = "test123"
            download_response = asd_helper.generate_report_or_export_and_download_file(
                scan_id=scan_id,
                report_format=export_format,
                password=password
            )

            # Validating returned data
            assert len(download_response.content) > 0, "Downloaded file is empty"
            attachment_header = download_response.headers["content-disposition"]
            assert "attachment" in attachment_header and "filename" in attachment_header, \
                f"The file desired was not returned {attachment_header}"
            if export_format == API.Scan.ExportFormats.FORMAT_NESSUS:
                assert ".nessus" in attachment_header, f"A nessus file did not return, {attachment_header}"
            elif export_format == API.Scan.ExportFormats.FORMAT_DB:
                assert ".db" in attachment_header, f"A DB file did not return, {attachment_header}"
        finally:
            self.cat.api.scans.delete(scan_id=scan_id)


class AsdHelper:
    # A Helper method to generate ASD specific reports through the API
    def __init__(self, api: NessusAPI):
        self.api = api
        self.data_file = None

    @staticmethod
    def create_completed_scan(api: NessusAPI, hostname: str = None) -> ResponseObject:
        asd_helper = AsdHelper(api=api)
        payload = asd_helper.get_asd_payload(hostname=hostname)
        scan: ResponseObject = asd_helper.create_and_launch_full(payload=payload)
        return scan

    @staticmethod
    def get_asd_payload(hostname: str = None):
        if hostname is None:
            hostname = "tenable.com"
        # generating and returning a basic asd payload
        payload = {
            "uuid": str(uuid.uuid4()),
            "settings": {"domain_discovery_domains": hostname,
                "launch_now": False,
                "enabled": False,
                "name": f"{hostname}-{random_string()}",
                "description": f"{hostname} ASD Scan",
                "folder_id": 3
            }
        }

        return payload

    def create_and_launch_full(self, payload: dict, completion: bool = True) -> ResponseObject:
        # Converting the payload into a datafile
        data_file = next(self.create_data_file(payload=payload))

        # Create and launch the scan through an api
        scan, scan_model = create_scan_helper(
            api_handler=self.api,
            file_name=data_file.name,
            template_title=Nessus.Scan.TemplateNames.ASD
        )

        scan_id = scan['scan']['id']
        if completion:
            self.launch_scan_and_wait_for_completion(scan_id=scan_id)

        return scan

    def create_and_launch(self, payload: dict, completion: bool = True) -> int:
        scan = self.create_and_launch_full(payload=payload, completion=completion)
        scan_id = scan['scan']['id']

        return scan_id

    def create_data_file(self, payload: dict):
        # Create a data file with the payload given - have to not delete until after yield
        self.data_file = tempfile.NamedTemporaryFile(mode="w+t", delete=False)
        json_str = json.dumps(payload)
        self.data_file.write(json_str)
        self.data_file.close()

        yield self.data_file

        self.data_file.delete = True
        self.data_file.close()

    def launch_scan_and_wait_for_completion(self, scan_id: int):
        # Launch scan and wait for completion by checking the status of scan detailss
        self.api.scans.launch(scan_id)
        wait(lambda: self.api.scans.details(
            scan_id)['info']['status'] in [API.Scan.Status.COMPLETED],
             sleep_seconds=WAIT_NORMAL, waiting_for=Scanner.Strings.SCAN_TO_START,
             timeout_seconds=TIME_TEN_MINUTES)

    def generate_report_or_export_and_download_file(
            self,
            scan_id: int,
            report_format: str,
            template_id: int = None,
            password: str = None
    ):
        # Getting a report or an export based on the data passed in and then downloading it once it is ready
        try:
            export = self.api.scans.export(scan_id, export_format=report_format, template_id=template_id, password=password)
        except HTTPError as e:
            raise Exception(f"Error while exporting scan report with format - {report_format}")

        self.api.response.raise_for_status()

        # wait for to get ready state and max wait for two minutes.
        wait(lambda: self.api.scans.export_status(scan_id, export[0]) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2,
             waiting_for='Scan export to get %s state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        # Download the exported file
        download = self.api.scans.download(scan_id, export[0])
        self.api.response.raise_for_status()

        return download

    def export_and_download_to_file(self, scan_id: int, export_format: str, password: str = None) -> str:
        """
        We export the scan, wait for it, download it to a file, and then return the filename
        """
        export = self.api.scans.export(scan_id=scan_id, export_format=export_format, password=password)
        if not export:
            raise Exception("Did not get expected scan export data")

        file_id = export[0]

        wait(lambda: self.api.scans.export_status(scan_id, file_id) == API.Status.READY,
             timeout_seconds=TIME_SIXTY_SECONDS * 2,
             waiting_for='Scan export to get %s state' % API.Status.READY,
             sleep_seconds=WAIT_NORMAL)

        import pathlib
        file_name = str(pathlib.PurePath(os.path.join(NessusConfig.CAT_NESSUS_DB_DIRECTORY, f'exported_file_{scan_id}')))

        download_and_save_exported_scan_file(file_path=file_name, api=self.api, file_format="." + export_format,
                                             scan_id=scan_id, file_id=file_id)

        return file_name

    def import_asd_scan(self, file_name: str, password: str = None):
        uploaded_file = self.api.file.upload(
            file=file_name,
            encrypted=True
        )

        # Todo: Check if we can do os.remove(file_name) from here

        imported_scan = self.api.scans.import_scan(uploaded_file, folder_id=None, password=password)
        return imported_scan

