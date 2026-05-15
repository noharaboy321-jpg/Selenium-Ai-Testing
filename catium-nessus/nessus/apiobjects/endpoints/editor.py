"""
Nessus Editor Endpoint

"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from nessus.apiobjects import routes


class EditorEndpoint(object):
    """Editor API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    # TODO Handle file download
    def audits(self, audit_type: str, object_id: int, file_id: int):
        """
        Export the given audit file

        :param str audit_type: Type of template to retrieve
            Supported Options: const.API.Types.SCAN and const.API.Types.POLICY
        :param int object_id: Unique ID of the object
        :param int file_id: ID of the file to export
        :returns: The audit file, raw file content
        """
        resource = '%s/%s/%s/audits/%s' % (routes.EDITOR, audit_type, object_id, file_id)
        self._cls.request(const.HTTPMethods.GET, resource)

    def details(self, template_type: str, template_uuid: str) -> ResponseObject:
        """
        Returns the details for the given template

        :param str template_type: Type of template to retrieve
            Supported Options: const.API.Types.SCAN and const.API.Types.POLICY
        :param str template_uuid: Template UUID
        :returns: Template details
        """
        resource = '%s/%s/templates/%s' % (routes.EDITOR, template_type, template_uuid)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def edit(self, object_type: str, object_id: int) -> ResponseObject:
        """
        Returns the requested object

        :param str object_type: Type of object
            Supported Options: const.API.Types.SCAN and const.API.Types.POLICY
        :param int object_id: Unique ID of the object
        :returns: object data
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.EDITOR + '/' + object_type + '/' + object_id)
        return ResponseObject(response)

    def get_templates(self, object_type: str) -> ResponseObject:
        """
        Returns the templates list

        :param str object_type: Type of object
            Supported Options: const.API.Types.SCAN and const.API.Types.POLICY
        :returns: template list
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.EDITOR + '/' + object_type + '/templates')
        return ResponseObject(response)

    def plugin_description(self, object_type: str, family_id: int, plugin_id: int, policy_id: int) -> ResponseObject:
        """
        Returns the plugin description
        :param str object_type: 'scan'/'policy'
        :param str family_id: ID of the family to lookup within the policy
        :param int plugin_id: ID of the plugin to lookup within the family
        :param int policy_id: ID of the policy to lookup
        :returns: plugin output
        """
        resource = '%s/%s/%s/families/%s/plugins/%s' % (routes.EDITOR, object_type, policy_id, family_id, plugin_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_templates_families(self, object_type: str, template_uuid: str) -> ResponseObject:
        """
        Get the template families
        :param str object_type: 'scan'/'policy'
        :param str template_uuid: Template UUID
        :return: families response
        :rtype: ResponseObject
        """
        resource = '%s/%s/templates/%s/families' % (routes.EDITOR, object_type, template_uuid)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_templates_family(self, object_type: str, template_uuid: str, family_id: int) -> ResponseObject:
        """
        Get details for a specific family template
        :param str object_type: 'scan'/'policy'
        :param str template_uuid: Template UUID
        :param int family_id: Family ID
        :return: Family response
        :rtype: ResponseObject
        """
        resource = '%s/%s/templates/%s/families/%s' % (routes.EDITOR, object_type, template_uuid, family_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_families(self, object_type: str, object_id: int) -> ResponseObject:
        """
        Get the scan or policies families
        :param str object_type: 'scan'/'policy'
        :param int object_id: value of scan_id or policy_id
        :return: ResponseObject
        """
        resource = '%s/%s/%s/families' % (routes.EDITOR, object_type, object_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_family(self, object_type: str, object_id: int, family_id: int) -> ResponseObject:
        """
        Get details for a specific family of scan or policies
        :param str object_type: 'scan'/'policy'
        :param int object_id: value of scan_id or policy_id
        :param int family_id: Family ID
        :return: ResponseObject
        """
        resource = '%s/%s/%s/families/%s' % (routes.EDITOR, object_type, object_id, family_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_plugin(self, object_type: str, template_uuid: str, family_id: int, plugin_id: int) -> ResponseObject:
        """
        Get details for a specific family template
        """
        resource = '%s/%s/templates/%s/families/%s/plugins/%s' % \
                   (routes.EDITOR, object_type, template_uuid, family_id, plugin_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def prepare_audit_download(self, object_type: str, object_id: str, file_id: int) -> ResponseObject:
        """
        Get details for a specific family template
        """
        resource = '%s/%s/%s/audits/%s/prepare' % (routes.EDITOR, object_type, object_id, file_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)

    def get_scan(self, scan_id: int) -> ResponseObject:
        """
        Get details for a specific scan
        """
        resource = '%s/scan/%d' % (routes.EDITOR, scan_id)
        response = self._cls.request(const.HTTPMethods.GET, resource)
        return ResponseObject(response)
