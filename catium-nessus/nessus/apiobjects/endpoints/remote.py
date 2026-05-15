"""
Nessus Remote scanner Endpoint

:copyright: Tenable Network Security, 2019
:date: August 21, 2018
:last_modified: Dec 25, 2019
:author: @ntarwani, @yshah, @vsoni, @jchavda, @kpanchal
"""
import json

import requests

from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from nessus.apiobjects import routes


class RemoteEndpoint(object):
    """Remote API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def get_cert(self) -> ResponseObject:
        """
        Retrieves information about certificates

        :returns: Response for GET request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '%s/cert' % routes.REMOTE)
        return ResponseObject(response)

    def get_properties(self) -> ResponseObject:
        """
        Returns remote properties
        :returns: Response for GET request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, '%s/properties' % routes.REMOTE)
        return ResponseObject(response)

    def delete_remote_agent(self) -> ResponseObject:
        """
        Method to delete the remote agent

        :return: Response for DELETE request
        :rtype: ResponseObject
        """
        resource = routes.REMOTE_AGENT
        response = self._cls.request(const.HTTPMethods.DELETE, resource)
        return ResponseObject(response)

    def edit_remote_agent(self, payload: dict) -> ResponseObject:
        """
        Method to Edit the remote agent

        :param dict payload: To edit remote agent
        :return: Response for PUT request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.PUT, routes.REMOTE_AGENT, json=payload)
        return ResponseObject(response)

    def configure_remote_agent(self, data: dict) -> ResponseObject:
        """
        Edit the remote agent
        :param dict data: Payload to be passed for PUT request
        :return: Response for PUT request
        :rtype: ResponseObject
        """
        resource = routes.REMOTE_AGENT
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def get_remote_agent_jobs(self) -> ResponseObject:
        """
        Returns remote agent jobs
        :return: Response message containing agent job detail
        :rtype: ResponseObject
        """
        resource = '%s/jobs' % routes.REMOTE_AGENT
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def configure_remote_agent_job(self, job_uuid: str, data: dict) -> ResponseObject:
        """
        Edit the remote agent job
        :param str job_uuid: job uuid
        :param dict data: Payload to be passed for PUT request
        :return: Response for PUT request
        :rtype: ResponseObject
        """
        resource = '%s/jobs/%s' % (routes.REMOTE_AGENT, job_uuid)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def get_policy_for_agent_remote_job(self, job_uuid: str) -> ResponseObject:
        """
        Returns policy for agent job
        :param str job_uuid: uuid for the job to retrieve the policy
        :return: Response for GET request
        :rtype: ResponseObject
        """
        resource = '%s/jobs/%s/policy' % (routes.REMOTE_AGENT, job_uuid)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def upload_agent_job(self, job_uuid: str, file: str, payload: dict) -> ResponseObject:
        """
        Upload remote agent jobs

        :param str job_uuid: remote scanner jon UUID
        :param str file: file path
        :param dict payload: payload for scanner job request; default is empty dict
        :return: response for uploaded jobs
        :rtype: ResponseObject
        """

        files = [
            ('Postdata', (None, json.dumps(payload), 'application/json')),
            ('Filedata', (file, open(file, 'rb'), 'application/octet-stream'))
        ]

        resource = "{}/jobs/{}/upload".format(routes.REMOTE_AGENT, job_uuid)
        return ResponseObject(self._cls.request(const.HTTPMethods.POST, resource, files=files, json=payload))

    def get_remote_agent_updates(self, params: dict) -> ResponseObject:
        """
        Returns updates for Remote agent
        :param dict params: dict of platform and distribution information
        :return: Response for GET request
        :rtype: ResponseObject
        """
        resource = '%s/updates' % routes.REMOTE_AGENT
        response = self._cls.request(const.HTTPMethods.GET, resource, params=params)
        return ResponseObject(response)

    def get_remote_agent_plugins(self, params: dict, stream: bool = False) -> requests.Response:
        """
        Returns plugins for Remote agent
        :param dict params: dict of platform and distribution information
        :param bool stream: True if need to get response text else False
        :return: Response for GET request
        :rtype: dict
        """
        resource = '%s/plugins' % routes.REMOTE_AGENT
        response = self._cls.request(const.HTTPMethods.GET, resource, params=params, stream=stream)
        return response

    def get_remote_agent_core(self, distro: str, platform: str, stream: bool = False,
                              upgrade_distro: str = None, sleep_time: int = 0,
                              ui_version: str = None, version: str = None) -> requests.Response:
        """
        Returns Core information for Remote agent
        :param str distro: distro of the host to download core update
        :param str platform: platform of the host to download core update
        :param bool stream: True if need to get response text else False
        :param str upgrade_distro: upgrade_distro of the host to download core update
        :param int sleep_time: sleep time for core update request
        :param str ui_version: UI version for which core updates need to be fetched
        :param str version: The agent profile version to be fetched
        :return: Response message for GET request
        :rtype: dict
        """
        resource = '{}/core?distro={}&platform={}'.format(routes.REMOTE_AGENT, distro, platform)

        if upgrade_distro:
            resource = '{}&upgrade_distro={}'.format(resource, upgrade_distro)

        if sleep_time:
            resource += "?sleep_time={}".format(str(sleep_time))

        if ui_version:
            resource += "?ui_version={}".format(ui_version)

        if version:
            resource += "?version={}".format(version)

        response = self._cls.request(const.HTTPMethods.GET, resource, stream=stream)

        # In this case, we are not returning a ResponseObject, because we want to stream this.
        return response

    def get_differential_updates(self, platform_distro: str, target_feed_id: int, current_feed_id: int, formats: str,
                                 remote_agent_token: str, stream: bool = False) -> ResponseObject:
        """
        Returns differential updates for the agent
        :param str platform_distro: platform distro
        :param int target_feed_id: feed id for target machine
        :param int current_feed_id: feed id of current machine
        :param str formats: format in which distro is to be retrieved
        :param str remote_agent_token: MS-Agent token to be added as a header
        :param bool stream: True if need to get response text else False
        :return: Response for GET request
        :rtype: ResponseObject
        """
        resource = '%s/platforms/%s/plugins/%s/diff/%s/formats/%s' % (
            routes.REMOTE_AGENT, platform_distro, target_feed_id, current_feed_id, formats)

        header = {'MS-Agent': "token={}".format(remote_agent_token)}
        response = self._cls.request(const.HTTPMethods.GET, resource, headers=header, verify=False, stream=stream)
        return ResponseObject(response)

    def set_remote_agent_settings(self, payload) -> None:
        """
        Set remote agent settings
        :param dict payload: payload to set remote agent settings
        :return: None
        """
        resource = '%s/settings' % routes.REMOTE_AGENT
        self._cls.request(const.HTTPMethods.POST, resource, json=payload)

    def add_remote_scanner(self, data: dict) -> ResponseObject:
        """
        Method to add remote scanner

        :param dict data: Payload to be passed
        :return: Response for POST request
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, routes.REMOTE_SCANNER, json=data)
        return ResponseObject(response)

    def delete_remote_scanner(self) -> ResponseObject:
        """
        Method to delete the remote scanner

        :return: Response for DELETE request
        :rtype: ResponseObject as requests.Response
        """
        response = self._cls.request(const.HTTPMethods.DELETE, routes.REMOTE_SCANNER)
        return response

    def configure_remote_scanner(self, data: dict) -> ResponseObject:
        """
        Edit the remote scanner
        :param dict data: Payload to be passed for PUT request
        :return: Response for PUT request
        :rtype: ResponseObject
        """
        resource = routes.REMOTE_SCANNER
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def get_remote_scanner_jobs(self) -> ResponseObject:
        """
        Returns remote scanner jobs
        :return: Response message containing agent job detail
        :rtype: ResponseObject
        """
        resource = '%s/jobs' % routes.REMOTE_SCANNER
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def configure_remote_scanner_job(self, job_uuid: str, data: dict) -> ResponseObject:
        """
        Edit the remote scanner job
        :param str job_uuid: job uuid
        :param dict data: Payload to be passed for PUT request
        :return: Response for PUT request
        :rtype: ResponseObject
        """
        resource = '%s/jobs/%s' % (routes.REMOTE_SCANNER, job_uuid)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def get_policy_for_scanner_remote_job(self, job_uuid: str) -> ResponseObject:
        """
        Returns policy for scanner job
        :param str job_uuid: uuid for the job to retrieve the policy
        :return: Response for GET request
        :rtype: ResponseObject
        """
        resource = '%s/jobs/%s/policy' % (routes.REMOTE_SCANNER, job_uuid)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def upload_file_to_scanner_job(self, job_uuid: str, file: str, payload: dict) -> ResponseObject:
        """
        Uploads file to scanner job

        :param str job_uuid: remote scanner jon UUID
        :param str file: file path
        :param dict payload: payload for scanner job request; default is empty dict
        :return: response for remote scanner jobs
        :rtype: ResponseObject
        """

        files = [
            ('Postdata', (None, json.dumps(payload), 'application/json')),
            ('Filedata', (file, open(file, 'rb'), 'application/octet-stream'))
        ]

        resource = "{}/jobs/{}/upload".format(routes.REMOTE_SCANNER, job_uuid)
        return ResponseObject(self._cls.request(const.HTTPMethods.POST, resource, files=files, json=payload))

    def configure_cache_for_remote_scanner(self, job_uuid: str, file: str) -> ResponseObject:
        """
        Configure cache for Remote Scanner
        :param str job_uuid: job uuid for configuration
        :param str file: file path
        :return: Response for POST request
        :rtype: ResponseObject
        """

        files = [
            ('Filedata', (file, open(file, 'rb'), 'application/octet-stream'))
        ]
        resource = '%s/jobs/%s/cache' % (routes.REMOTE_SCANNER, job_uuid)
        response = self._cls.request(const.HTTPMethods.POST, resource, files=files)
        return ResponseObject(response)

    def get_remote_scanner_update(self, distro: str, stream: bool = False) -> ResponseObject:
        """
        Returns updates for Remote scanner

        :param str distro: distro of platform
        :param bool stream: True if need to get response text else False
        :return: Response message for GET request
        :rtype: ResponseObject
        """
        resource = '%s/updates?distro=%s' % (routes.REMOTE_SCANNER, distro)
        response = self._cls.request(const.HTTPMethods.GET, resource, stream=stream)

        return response if stream else ResponseObject(response)

    def get_remote_scanner_plugins(self, remote_scanner_token: str, stream: bool = False) -> requests.Response:
        """
        Returns plugins for Remote scanner
        :param str remote_scanner_token: It is token returned while creating remote scanner
        :param bool stream: True if need to get response text else False
        :return: Response message for GET request
        :rtype: ResponseObject as requests.Response
        """
        resource = '%s/plugins' % routes.REMOTE_SCANNER
        header = {'MS-Scanner': "token={}".format(remote_scanner_token)}
        response = self._cls.request(const.HTTPMethods.GET, resource, headers=header, verify=False, stream=stream)
        return response

    def get_remote_scanner_core(self, distro: str, stream: bool = False) -> ResponseObject:
        """
        Returns Core information for Remote scanner

        :param str distro: distro of platform
        :param bool stream: True if need to get response text else False
        :return: Response message for GET request
        :rtype: ResponseObject as requests.Response
        """
        resource = '%s/core?distro=%s' % (routes.REMOTE_SCANNER, distro)
        response = self._cls.request(const.HTTPMethods.GET, resource, stream=stream)
        return response

    def get_remote_scanner_aws(self) -> ResponseObject:
        """
        Returns AWS information for Remote scanner
        :return: Response message for GET request
        :rtype: ResponseObject
        """
        resource = '%s/aws' % routes.REMOTE_SCANNER
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def configure_remote_scanner_with_aws(self, data: dict) -> ResponseObject:
        """
        Configure remote scanner with aws
        :param dict data: payload to be passed
        :return: Response for PUT request
        :rtype: ResponseObject
        """
        resource = '%s/aws' % routes.REMOTE_SCANNER
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return ResponseObject(response)

    def edit_remote_scanner(self, registration_code: str = None) -> requests.Response:
        """
        Edit Remote scanner

        :param str registration_code: Sets the registration code for the scanner
        :return: Response for PUT request
        :rtype: ResponseObject as requests.Response
        """
        payload = {'registration_code': registration_code}
        response = self._cls.request(const.HTTPMethods.PUT, routes.REMOTE_SCANNER, json=payload)
        return response

    def edit_remote_scanner_directive(self, directive_id: str, data: dict) -> requests.Response:
        """
        modify status of remote scanner directive
        :param str directive_id: directive_id for remote scanner
        :param dict data: payload to be passed
        :return: Response for PUT request
        :rtype: requests.Response
        """
        resource = '%s/directive/%s' % (routes.REMOTE_SCANNER, directive_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return response

    def remote_scanner_directive_file_upload(self, directive_id: str, file: str, data: dict) -> requests.Response:
        """
        Uploads file to remote scanner directive

        :param str directive_id: remote scanner directive_id
        :param str file: file path
        :param dict data: payload for directive file upload request
        :return: response for remote scanner directive file upload
        :rtype: requests.Response
        """
        files = [
            ('Postdata', (None, json.dumps(data), 'application/json')),
            ('Filedata', (file, open(file, 'rb'), 'application/octet-stream'))
        ]

        resource = '%s/directive/%s' % (routes.REMOTE_SCANNER, directive_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=data, files=files)
        return response

    def remote_agent_directive_file_upload(self, directive_id: str, file: str, data: dict) -> requests.Response:
        """
        Uploads file to remote Agent directive

        :param str directive_id: remote agent directive_id
        :param str file: file path
        :param dict data: payload for directive file upload request
        :return: response for remote agent directive file upload
        :rtype: requests.Response
        """
        files = [
            ('Postdata', (None, json.dumps(data), 'application/json')),
            ('Filedata', (file, open(file, 'rb'), 'application/octet-stream'))]

        resource = '%s/directive/%s' % (routes.REMOTE_AGENT, directive_id)
        response = self._cls.request(const.HTTPMethods.POST, resource, json=data, files=files)
        return response

    def edit_remote_agent_directive(self, directive_id: str, data: dict) -> requests.Response:
        """
        Modify status of remote agent directive

        :param str directive_id: directive_id for remote agent
        :param dict data: payload to be passed
        :return: Response for PUT request
        :rtype: requests.Response
        """
        resource = '%s/directive/%s' % (routes.REMOTE_AGENT, directive_id)
        response = self._cls.request(const.HTTPMethods.PUT, resource, json=data)
        return response

    def get_remote_agent_config(self, config_id: str) -> ResponseObject:
        """
        Returns remote agent config
        :return: agent config
        :rtype: ResponseObject
        """
        resource = '%s/config/%s' % (routes.REMOTE_AGENT, config_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)
