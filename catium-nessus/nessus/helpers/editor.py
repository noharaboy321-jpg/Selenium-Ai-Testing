"""
Nessus Editor helpers

:copyright: Tenable Network Security, 2018
:date: Aug 20, 2018
:author: @lambaliya.ctr
"""

from http import HTTPStatus

from nessus.apiobjects.nessus_api import NessusAPI


def get_and_validate_template_families(nessus_api: NessusAPI, object_type: str, template_uuid: str) -> dict:
    """
    Validate and return template families
    :param NessusAPI nessus_api: object for accessing nessus apis
    :param str object_type: scan/policy
    :param str template_uuid: Template UUID
    :return: families
    :rtype: dict
    """
    template_families = nessus_api.editor.get_templates_families(object_type=object_type, template_uuid=template_uuid)
    if nessus_api.http_status_code != HTTPStatus.OK:
        raise AssertionError('Expected 200, got %s instead.' % nessus_api.http_status_code)
    if len(template_families['families']) < 1:
        raise AssertionError('No template families returned.')
    return template_families['families']


def get_and_validate_specific_template_family(nessus_api: NessusAPI, object_type: str, template_uuid: str,
                                              family_id: int) -> dict:
    """
    Validate and returns specific family detail for specific template
    :param NessusAPI nessus_api: object for accessing nessus apis
    :param str object_type: scan/policy
    :param str template_uuid: Template UUID
    :param int family_id: Family ID 
    :return: Detail of specific template family
    :rtype: dict
    """
    template_family_detail_resp = nessus_api.editor.get_templates_family(object_type, template_uuid, family_id)
    if nessus_api.http_status_code != HTTPStatus.OK:
        raise AssertionError('Expected 200, got %s instead.' % nessus_api.http_status_code)
    if len(template_family_detail_resp['plugins']) < 1:
        raise AssertionError('No plugins for specific family returned.')
    return template_family_detail_resp


def get_and_validate_created_scan_or_policy_families(nessus_api: NessusAPI, object_type: str, object_id: int) -> dict:
    """
    Validate and return families of specific scan/policy
    :param NessusAPI nessus_api: object for accessing nessus apis
    :param str object_type: scan/policy
    :param int object_id: scan_id/policy_id 
    :return: Families for specific scan or policy
    :rtype: dict
    """
    families = nessus_api.editor.get_families(object_type=object_type, object_id=object_id)
    if nessus_api.http_status_code != HTTPStatus.OK:
        raise AssertionError('Expected 200, got %s instead.' % nessus_api.http_status_code)
    if len(families['families']) < 1:
        raise AssertionError('No families returned.')
    return families['families']


def get_and_validate_created_specific_scan_or_policy_family(nessus_api: NessusAPI, object_type: str, object_id: int,
                                                            family_id: int) -> dict:
    """
    Validate and return specific family of specific scan/policy
    :param NessusAPI nessus_api: object for accessing nessus apis
    :param str object_type: scan/policy
    :param int object_id: scan_id/policy_id 
    :param int family_id: Family ID
    :return: Specific family for a specific scan/policy
    :rtype: dict
    """
    template_family_detail_resp = nessus_api.editor.get_family(object_type, object_id, family_id)
    if nessus_api.http_status_code != HTTPStatus.OK:
        raise AssertionError('Expected 200, got %s instead.' % nessus_api.http_status_code)
    if len(template_family_detail_resp['plugins']) < 1:
        raise AssertionError('No plugins for specific family returned.')
    return template_family_detail_resp
