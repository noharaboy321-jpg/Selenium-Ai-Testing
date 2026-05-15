"""
Nessus Policies Endpoint
"""
from http import HTTPStatus

from requests.exceptions import RequestException

from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from catium.lib.errors import CatiumAPIObjectNotFoundError
from catium.lib.log import create_logger
from nessus.apiobjects import routes

log = create_logger()


class PoliciesEndpoint(object):
    """Policies API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def configure(self, policy_id: int, payload: dict) -> ResponseObject:
        """
        Configure an existing Policy

        .. note:: See https://qa-develop.cloud.aws.tenablesecurity.com/api#/resources/policies/configure for payload

        :param int policy_id: Policy ID to edit
        :param dict payload: Policy configuration parameters
        :returns: ResponseObject
        """
        resource = '%s/%s' % (routes.POLICIES, policy_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=payload)
        return ResponseObject(response)

    def copy(self, policy_id: int) -> ResponseObject:
        """
        Copies a policy

        :param int policy_id: Policy ID to copy
        :returns: ResponseObject
        """
        resource = '%s/%s/copy' % (routes.POLICIES, policy_id)
        response = self._cls.request(const.HTTPMethods.POST, resource)
        return ResponseObject(response)

    def create(self, payload: dict, stream: bool = False) -> ResponseObject:
        """
        Create a Policy

        :param dict payload: Policy creation parameters
        :param bool stream: True if need to get response text else False
        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.POLICIES, json=payload, stream=stream)
        policy = ResponseObject(response)
        log.debug('Created Policy ID "%s".', policy['policy_id'])
        log.debug('Policy ID "%s" was created using template UUID %s', policy['policy_id'], payload['uuid'])
        return policy

    def delete(self, policy_id: int) -> ResponseObject:
        """
        Delete a Policy

        :param int policy_id: Policy ID
        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.DELETE, routes.POLICIES + '/' + str(policy_id))
        log.debug('Deleted policy ID "%s"', policy_id)
        return ResponseObject(response)

    def details(self, policy_id: int) -> ResponseObject:
        """
        Returns details for the given policy

        :param int policy_id: Policy ID
        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.POLICIES + '/' + str(policy_id))
        return ResponseObject(response)

    def import_policy(self, file: str) -> ResponseObject:
        """
        Import an existing Policy

        .. note:: See catium/helpers/tenablecloud/policy.py for helpers

        :param str file: Name of the file to import, returned from the file:upload endpoint
        :returns: ResponseObject
        """
        payload = {'file': file}
        response = self._cls.request(const.HTTPMethods.POST, routes.POLICIES + '/import', json=payload)
        return ResponseObject(response)

    def export(self, policy_id: int) -> str:
        """
        Export the given policy

        :param int policy_id: Policy ID
        :returns: policy, in XML format
        :raises: CatiumAPIObjectNotFoundError
        """
        response = None
        try:
            resource = '%s/%s/export' % (routes.POLICIES, policy_id)
            response = self._cls.request(const.HTTPMethods.GET, resource)
            return response.text
        except RequestException as exception:
            if response.http_status_code == HTTPStatus.NOT_FOUND:
                raise CatiumAPIObjectNotFoundError('Policy ID "%s" does not exist.' % policy_id)
            log.debug('Policy export failed: %s.', exception)

    def get_policies(self) -> ResponseObject:
        """
        Returns the policy list

        :returns: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.POLICIES)
        return ResponseObject(response)

    def bulk_delete(self, id_list: list) -> ResponseObject:
        """
        Delete all policies
        :param list id_list: list of policy id
        :returns: policy id list
        :rtype:ResponseObject
        """
        payload = {"ids": id_list}
        response = self._cls.request(const.HTTPMethods.DELETE, routes.POLICIES, json=payload)

        return ResponseObject(response)

    def prepare_export(self, policy_id: int) -> ResponseObject:
        """
        Prepare export for a policy
        :param int policy_id : policy id
        :returns: policy id
        :rtype: ResponseObject
        """
        resource = '%s/%s/export/prepare' % (routes.POLICIES, policy_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)
