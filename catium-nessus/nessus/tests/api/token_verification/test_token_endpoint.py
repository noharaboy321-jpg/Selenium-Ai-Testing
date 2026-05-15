"""
Nessus token based download Endpoints Unit Test

:copyright: Tenable Network Security, 2018
:date: August 17, 2018
:last_modified: July 15, 2020
:author: @jamreliya, @ntarwani, @kpanchal
"""
from http import HTTPStatus

import pytest
from waiting import wait

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_THIRTY_SECONDS, WAIT_NORMAL, WAIT_SHORT
from nessus.helpers.server import expect_http_error
from nessus.lib.const import API


@pytest.mark.nessus_mat
@pytest.mark.nessus_home
@pytest.mark.nessus_manager
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login')
class TestTokenEndpoint:
    """
    Test for Token Endpoint. STA-21
    """

    cat = None

    # API_Tested# GET /tokens/{token}/download
    # API_Tested# GET /tokens/{token}/status

    @pytest.mark.parametrize('import_scan', [{'scan': {'filename': 'advance_scan_c7kspv.nessus'}}, ], indirect=True)
    def test_download_using_token(self, import_scan):
        """
        STA-33: Create tests for Tokens
        
        Scenarios tested:
        [x] Export scan and get token of the exported file
        [x] Check that the file is ready to download
        [x] Download the file
        [ ] Get a download for a token that doesn't exist
        [ ] Get status for a token that doesn't exist 
        """

        scan_id = import_scan

        # export scan result to get token of exported scan file
        file_token_id = self.cat.api.scans.export(scan_id=scan_id,
                                                  export_format=API.Scan.ExportFormats.FORMAT_NESSUS)[1]

        # check scan result  file is ready to download
        response = self.cat.api.tokens.status(token_id=file_token_id)
        assert response['status'] in ['ready', 'loading'], 'File is not ready for download'

        # download scan result file
        self.cat.api.tokens.download(token_id=file_token_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# POST /tokens/{token}/cancel
    def test_cancel_token(self):
        """
        STA-107: Create test for /tokens/{token}/cancel

        Scenarios tested:
        [X] Generate bug-report and get the token
        [X] Remove the token for the bug-report
        """
        token = self.cat.api.server.post_bug_report(data={"full_mode": 1, "scrub_mode": 1},
                                                    stream=True)["token"]

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Cancel the token
        self.cat.api.tokens.cancel(token_id=token)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Verify that after cancelling token, user can not download the bug-report file using the same token
        with expect_http_error(code=HTTPStatus.NOT_FOUND, look_for="The requested file was not found"):
            self.cat.api.tokens.download(token)
