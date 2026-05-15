"""
Test cases for Nessus Miscellaneous Endpoints 

:copyright: Tenable Network Security, 2018
:date: August 17, 2018
:last_modified: Dec 13, 2021
:author: @bkumawat.ctr, @jchavda, @kpanchal
"""
import json
from http import HTTPStatus

import pytest
from requests.exceptions import HTTPError

from catium.helpers.testdata import get_file_path
from catium.lib.util.util import random_string
from nessus.lib.const import API


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login')
class TestMiscEndPoints:
    """Test cases for Nessus Miscellaneous Endpoints"""
    cat = None

    # API_Tested # GET /api
    def test_get_api_information(self):
        """
        STA-34: Verify that API information is retrieved

        Scenarios tested:
        [x] Retrieves nessus6-api.html
        [x] Verify the file contains "html"
        """
        api_info = self.cat.api.misc.get_api()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        assert 'html' in api_info.text, 'API info response does not contains content of nessus6-api.html file'

    # API_Tested # GET /getcert
    @pytest.mark.nessus_mat
    def test_get_certification(self):
        """
        STA-34: Verify that certificate is retrieved

        Scenarios tested:
        [x] Retrieves cert_info.info
        [x] Verify the cert contains "BEGIN CERTIFICATE"
        """
        cert_info = self.cat.api.misc.get_cert()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead' % self.cat.api.http_status_code

        assert 'BEGIN CERTIFICATE' in cert_info.text, 'Certificate is not available in response'

    # API_Tested # GET /{file}
    @pytest.mark.parametrize('file_data', [
        {'file_name': 'html5.html', 'status_code': HTTPStatus.OK},
        {'file_name': 'nessus6.js', 'status_code': HTTPStatus.OK},
        {'file_name': 'nessus6-api.css', 'status_code': HTTPStatus.OK},
        {'file_name': 'favicon.ico', 'status_code': HTTPStatus.OK},
        {'file_name': 'nessus6.html', 'status_code': HTTPStatus.OK}])
    def test_get_file_content(self, file_data):
        """
        STA-34: Verify that api call returns contents of specified file from www folder
        STA-104: Verify returns contents of nessus6.html

        Scenarios tested:
        [x] Retrieves the five files from the www folder
        [x] Verify each file is not empty
        """
        file = self.cat.api.misc.get_file(file_data['file_name'])

        assert self.cat.api.http_status_code == file_data['status_code'], 'Invalid status code in response'

        assert len(file.text), 'Length of file should not be empty'

    # API_Tested # GET /{file}
    @pytest.mark.parametrize('file_data', [{'file_name': 'arrow.png'}, {'file_name': 'credentials.json'}])
    def test_get_invalid_file_content(self, file_data):
        """
        STA-34: Verify that api call returns error for invalid file format

        Scenarios tested:
        [x] Attempt to GET two files and get the "invalid file format" error
        
        Note: File must be .html, .js, .css, or .ico
        """
        with pytest.raises(HTTPError):
            self.cat.api.misc.get_file(file_data['file_name'])

    # API_Tested # GET /images/{file}
    @pytest.mark.parametrize('file_data', [
        {'file_name': 'nessus-email-logo-6.gif', 'status_code': HTTPStatus.OK},
        {'file_name': 'nessus-report-logo-6.png', 'status_code': HTTPStatus.OK}])
    def test_get_image(self, file_data):
        """
        STA-34: Verify that api call returns specified file with an extension of .png or .gif

        Scenarios tested:
        [x] Retrieves a .gif and .png file and that the response is not empty.
        [ ] Retrieve a file that does not exist
        """
        image_file = self.cat.api.misc.get_image(file_data['file_name'])

        assert self.cat.api.http_status_code == file_data['status_code'], 'Invalid status code in response'

        assert image_file, 'Response should not be empty'

    # API_Tested # GET /images/{file}
    @pytest.mark.parametrize('file_data', [{'file_name': 'favicon.ico'}])
    def test_get_invalid_image(self, file_data):
        """
        STA-34: Verify that api call returns error for invalid image file format

        Scenarios tested:
        [x] Retrieves a file with an invalid format
        """
        with pytest.raises(HTTPError):
            self.cat.api.misc.get_image(file_data['file_name'])

    # API_Tested POST /file/upload
    @pytest.mark.parametrize("test_data", [
        {"file_path": 'nessus/tests/api/scan/test_data/', "file_name": 'advanced_scan_gxxyl6.db'},
        {"file_path": 'nessus/tests/api/scan/test_data/', "file_name": 'advance_scan_c7kspv.nessus'}])
    def test_file_upload(self, test_data):
        """
        STA-104: Implement test case for /file/upload
        NES-15570 [API-Automation]: Add API tests to verify file upload/delete endpoints

        Scenarios tested:
        [x] Successfully upload file
        """
        file_path = get_file_path(test_data['file_path'] + test_data['file_name'])

        response = self.cat.api.misc.upload_file(file_path)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all(['fileuploaded' in response, response['fileuploaded'] == test_data['file_name']]), \
            "Failed to upload '{}' file.".format(test_data['file_name'])

    # API_Tested POST /file/delete
    @pytest.mark.parametrize("test_data", [
        {"file_path": 'nessus/tests/api/scan/test_data/', "file_name": 'advanced_scan_gxxyl6.db'},
        {"file_path": 'nessus/tests/api/scan/test_data/', "file_name": 'advance_scan_c7kspv.nessus'}])
    def test_delete_uploaded_file(self, test_data):
        """
        NES-15570 [API-Automation]: Add API tests to verify file upload/delete endpoints

        Scenarios tested:
        [x] Verify that uploaded file should be delete successfully
        """
        file_path = get_file_path(test_data['file_path'] + test_data['file_name'])

        self.cat.api.misc.upload_file(file_path)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        response = self.cat.api.misc.delete_file(file=test_data['file_name'])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert all(['File deleted' in response, response['File deleted'] == test_data['file_name']]), \
            "Failed to delete uploaded '{}' file.".format(test_data['file_name'])

    # API_Tested POST /file/delete
    @pytest.mark.parametrize("file_format", [API.Scan.ExportFormats.FORMAT_DB, API.Scan.ExportFormats.FORMAT_NESSUS])
    def test_delete_file_that_does_not_exist(self, file_format):
        """
        NES-15570 [API-Automation]: Add API tests to verify file upload/delete endpoints

        Scenarios tested:
        [x] Verify that It should give an error while deleting the file which is not exist.
        """
        random_file = "{}.{}".format(random_string(string_length=10), file_format)

        with pytest.raises(HTTPError):
            self.cat.api.misc.delete_file(file=random_file)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

        expected_error_msg = "File does not exist"
        error_msg_from_response = json.loads(self.cat.api.http_text)['error']

        assert error_msg_from_response == expected_error_msg, \
            "Expected '{}' error msg, got '{}' instead.".format(expected_error_msg, error_msg_from_response)
