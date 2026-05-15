"""
Nessus Folders Endpoint
"""
from nessus.apiobjects import routes
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger

log = create_logger()


class FoldersEndpoint(object):
    """Folders API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def create(self, name: str) -> ResponseObject:
        """
        Creates a new folder for the current user

        :param str name: The name for the folder
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.FOLDERS, json={'name': name})
        return ResponseObject(response)

    def delete(self, folder_id: int):
        """
        Deletes a folder

        :param int folder_id: ID of the folder to delete
        """
        self._cls.request(const.HTTPMethods.DELETE, routes.FOLDERS + '/' + str(folder_id))
        log.debug('Deleted folder ID "%s"', folder_id)

    def edit(self, folder_id: int, name: str):
        """
        Rename a folder for the current user

        :param int folder_id: ID of the folder to edit
        :param str name: The name for the folder
        """
        self._cls.request(const.HTTPMethods.PUT, routes.FOLDERS + '/' + str(folder_id), json={'name': name})

    def get_folders(self) -> ResponseObject:
        """Returns the current users scan folders"""
        response = self._cls.request(const.HTTPMethods.GET, routes.FOLDERS)
        return ResponseObject(response)
