"""
Nessus Exclusions Endpoint
"""
from nessus.apiobjects import routes
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.log import create_logger

log = create_logger()


class ExclusionsEndpoint(object):
    """Exclusions API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def create(self, scanner_id: str, payload: dict) -> ResponseObject:
        """
        Create a new exclusion

        :param str name: Name for the exclusion
        :param str scanner_id: scanner id
        :return: ResponseObject
        """
        resource = '%s/%s/agents/exclusions' % (routes.SCANNERS, scanner_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=payload)
        return ResponseObject(response)

    def delete(self, exclusion_id: int, scanner_id):
        """
        Delete exclusion

        :param int exclusion_id: Exclusion ID
        """
        resource = '%s/%s/agents/exclusions/%s' % (routes.SCANNERS, scanner_id,str(exclusion_id))
        self._cls.request(const.HTTPMethods.DELETE, resource)
        log.debug('Deleted exclusion ID ' + str(exclusion_id))

    def get_exclusions(self,scanner_id) -> ResponseObject:
        """
        Returns current exclusions

        :return: ResponseObject
        """
        resource = '%s/%s/agents/exclusions' % (routes.SCANNERS, scanner_id)

        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)
