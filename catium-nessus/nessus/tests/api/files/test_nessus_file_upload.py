"""
Nessus File upload endpoint verification

Test cases for File upload

:copyright: Tenable Network Security, 2017
:date: Sept 08, 2017
:last_modified: July 15, 2020
:author: @jamreliya, @kpanchal
"""

from http import HTTPStatus

import pytest

from catium.helpers.testdata import get_file_path


@pytest.mark.nessus_mat
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusFileUploadEndpoint:
    """Tests for Nessus scan Endpoint"""

    cat = None

    # API_Tested# POST /file/upload/{no_enc}/{file}
    @pytest.mark.parametrize('file', [{'filename': 'advance_scan_c7kspv.nessus'},
                                      {'filename': 'advanced_scan_gxxyl6.db', "encrypted": True, "password": "test1234"}
                                      ])
    def test_upload_file(self, file):
        """
        NQA - 880 : API - File - Upload a file
        :param file: Name of the file to upload, file will be fetched from s3 bucket
        :return: None
        """
        file_path = get_file_path('nessus/tests/api/scan/test_data/' + file['filename'])

        self.cat.api.file.upload(file=file_path, encrypted=file.get('encrypted', None))
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
