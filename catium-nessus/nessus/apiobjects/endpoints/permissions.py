"""
Nessus Permissions Endpoint

Permissions are used to provide access rights to a given object.
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.errors import CatiumAPIFieldError
from catium.lib.log import create_logger
from nessus.apiobjects import routes
from nessus.lib.const import API

log = create_logger()


class PermissionsEndpoint(object):
    """Permissions API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def change(self, object_type: str, object_id: int, acls: list) -> ResponseObject:
        """
        Change the permissions for an object

        ACLs Expected Format:
            [{"type": "default", "permissions": 16},
             {"type": "user", "permissions": 64, "name": "admin", "id": 1, "owner": 1}
            ]

        .. note:: Types and Permissions can be pulled from const.API.Permissions

        :param str object_type: Type of object.
            Supported Options: const.API.Permissions.Types.*
        :param int object_id: Object ID
        :param list acls: List of permission dict(s)
        :returns: ResponseObject
        :raises: CatiumAPIFieldError, for invalid ``object_types``
        """
        if object_type not in API.Permissions.Types.VALID_TYPES:
            raise CatiumAPIFieldError('Invalid object type specified: %s.' % object_type)

        resource = '%s/%s/%s' % (routes.PERMISSIONS, object_type, object_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=acls)
        log.debug('Changed permission for object type "%s" (ID: %s): %s.', object_type, object_id, str(acls))
        return ResponseObject(response)

    def get_permissions(self, object_type: str, object_id: int) -> ResponseObject:
        """
        Returns the current objects permissions

        :param str object_type: Type of object.
            Supported Options: const.API.Permissions.Types.*
        :param int object_id: Object ID
        :returns: ResponseObject
        :raises: CatiumAPIFieldError, for invalid ``object_types``
        """
        if object_type not in API.Permissions.Types.VALID_TYPES:
            raise CatiumAPIFieldError('Invalid object type specified: %s.' % object_type)
        resource = '%s/%s/%s' % (routes.PERMISSIONS, object_type, object_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        log.debug('Retrieving permissions for object type "%s" (ID: %s).', object_type, object_id)
        return ResponseObject(response)
