"""
Test cases for Nessus Reports Data
"""
import pytest
from http import HTTPStatus
from waiting import wait
from requests.exceptions import HTTPError

from catium.lib.const import TIME_THIRTY_SECONDS
from nessus.lib.const import API


@pytest.mark.usefixtures('nessus_api_login')
class TestReportData:
    """Tests involving report data, but not testing any particular endpoints"""
    cat = None

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.flaky_test
    @pytest.mark.parametrize('import_scan',
        [{'scan': {'filename': 'Non-UTF8_scan.db', 'encrypted': True, 'password': 'test1234'}}], indirect=True)
    def test_non_ascii_plugin_output(self, import_scan):
        """
        CS-29739 Test sanitization of non-ASCII data in reports.

        The imported scan result contains the following three samples of plugin output (some were hand-modified):
        - ASCII: 'Port 8845/tcp was found to be open'
        - UTF-8: 'Port 8834/tcp was found to be opén'
        - ISO-8859-1: 'Port 57704/tcp was found to be op\xE9n'

        Scenarios tested:
        [x] Test that ASCII plugin output is reported correctly
        [x] Test that UTF-8 plugin output is reported correctly
        [x] Test that non-UTF-8 and non-ASCII plugin output does not break reporting
        """

        scan_id = import_scan
        response = self.cat.api.scans.export(scan_id=scan_id,
                                             export_format=API.Scan.ExportFormats.FORMAT_HTML,
                                             report_contents={'vulnerabilitySections': {'plugin_output': True}},
                                             chapters='vuln_by_host')
        token_id = response[1]

        wait(lambda: self.cat.api.tokens.status(token_id=token_id)['status'] == 'ready',
             timeout_seconds=TIME_THIRTY_SECONDS, waiting_for="download to become ready")

        html_report = self.cat.api.tokens.download_file(token_id=token_id)
        with open('/tmp/mcd.html', 'wb') as f:
            f.write(html_report)
        assert 'Port 8845/tcp was found to be open'.encode('utf-8') in html_report, \
            'Expected ASCII string not found'
        assert 'Port 8834/tcp was found to be opén'.encode('utf-8') in html_report, \
            'Expected UTF-8 string not found'
        assert 'Port 57704/tcp was found to be op?n'.encode('utf-8') in html_report, \
            'Expected non-UTF-8 conversion not found'
