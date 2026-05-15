"""
Nessus Miscellaneous Endpoint
"""

from requests import Response

from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from nessus.apiobjects import routes


class MiscEndpoint(object):
    """Miscellaneous API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def get_api(self) -> Response:
        """
        Get API information

        :return: content of nessus6-api.html file
        :rtype: Response
        """
        response = self._cls.request(const.HTTPMethods.GET, '/api')
        return response

    def get_cert(self) -> Response:
        """
        Get the certificate for nessus

        :return: certificate of nessus
        :rtype: Response
        """
        response = self._cls.request(const.HTTPMethods.GET, '/getcert')
        return response

    def get_image(self, image_name: str) -> Response:
        """
        Get the specified image file

        :param str image_name: name of image file in /www or /www/images path
        :return: image file
        :rtype: Response
        """
        response = self._cls.request(const.HTTPMethods.GET, '/images/' + image_name)
        return response

    def get_installer(self, file: str) -> ResponseObject:
        """
        Get the installer

        :param str file: file name available in /www/installers or /www path
        :return: specified installer file
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '/installers/' + file)
        return ResponseObject(response)

    def get_file(self, file: str) -> Response:
        """
        Get the specified file

        :param str file: return content of file from /www path
        :return: content of file
        :rtype: Response
        """
        response = self._cls.request(const.HTTPMethods.GET, '/' + file)
        return response

    def upload_file(self, file: str) -> ResponseObject:
        """
        Upload a file

        :param str file: file name to upload
        :return: Name of file uploaded
        :rtype: ResponseObject
        """
        files = [('Filedata', (file, open(file, 'rb'), 'application/octet-stream'))]

        response = self._cls.request(const.HTTPMethods.POST, routes.FILE + '/upload', files=files)
        return ResponseObject(response)

    def delete_file(self, file: str) -> ResponseObject:
        """
        Delete given file

        :param str file: file name to be deleted
        :return: Name of deleted file
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.DELETE, routes.FILE + '/delete', json={"file": file})
        return ResponseObject(response)
