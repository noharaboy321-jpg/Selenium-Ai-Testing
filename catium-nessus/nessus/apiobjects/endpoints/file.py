"""
Nessus File Endpoint
"""
import mimetypes
import os
import uuid

from catium.lib.log.log import create_logger
from nessus.apiobjects import routes
from catium.lib.api.base_api_object import ResponseObject
from catium.lib import const


class FileEndpoint(object):
    """File API Endpoint"""

    UPLOAD_DO_NOT_RENAME = set([
        'CiscoIOSOffline_PolicyTestFile.txt',
        'CIS_Cisco_v2.2_Level_1.audit',
        'U_Windows_7_V1R27_STIG_SCAP_1-1_Benchmark.zip',
    ])

    def __init__(self, cls):
        self._cls = cls

    def upload(self, file: str, encrypted: bool=False) -> str:
        """
        Uploads a file

        :param str file: Absolute path to file
        :param bool encrypted: True if uploading an encrypted file, otherwise False. Default: False.
        :returns: Name of file uploaded
        :raises: FileNotFoundError
        """
        if os.path.exists(file) is False:
            log = create_logger()
            log.debug(os.listdir("cached_testdata/nessus/tests/api/scan/test_data/"))
            log.debug('================policy folder start =============')
            log.debug(os.listdir("cached_testdata/nessus/tests/api/policy/test_data/"))
            raise FileNotFoundError('The file "%s" does not exist.' % file)

        # Components of multipart POST to Nessus
        mime_type = mimetypes.guess_type(file)[0]

        if mime_type is None:
            mime_type = 'application/octet-stream'

        # Nessus will error if you upload the same filename 100+ times
        # (it appends a number suffix on conflicts, up to "-99").
        #
        # We originally fixed this by appending a random string to
        # every upload, but other tests then failed because they
        # required that particular files are uploaded under their own
        # exact name.
        #
        # For now, work around the issue by renaming all files except
        # the specific files which need to be uploaded under the exact
        # name.
        #
        # In the long term we could fix this in Nessus by having it
        # support multiple uploads more gracefully (e.g. appending a
        # random string instead of a numeric counter, or allowing >100).

        upload_filename = os.path.basename(file)

        if upload_filename not in FileEndpoint.UPLOAD_DO_NOT_RENAME:
            parts = upload_filename.split('.')
            upload_filename = parts[0] + '-' + str(uuid.uuid4())[-8:]
            if len(parts) > 1:
                upload_filename += '.' + '.'.join(parts[1:])

        files = [
            ('Filedata', (upload_filename, open(file, 'rb'), mime_type))
        ]

        params = {'no_enc': 1} if encrypted else None
        response = self._cls.request(const.HTTPMethods.POST, routes.FILE + '/upload', params=params, files=files)
        response = ResponseObject(response)
        return response['fileuploaded']
