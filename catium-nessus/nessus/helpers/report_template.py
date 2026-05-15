"""
Nessus helpers for Custom report templates
:copyright: Tenable Network Security, 2021
:date: Aug 19, 2021
:last_modified: Sep 03, 2021
:author: @vsoni
"""

from nessus.apiobjects.nessus_api import NessusAPI


def get_custom_template_id(api: NessusAPI, template_name: str, template_type: str = 'custom') -> int:
    """
    This helper method provides custom template id
    :param NessusAPI api: Instance of NessusAPI object
    :param str template_type: Type of template (custom/system)
    :param str template_name: Name of custom template
    """
    template_type = 0 if template_type == 'custom' else 1
    return [template['id'] for template in api.reports.get_report_templates() if template[
        'system'] == template_type and template['name'] == template_name][0]


def get_all_system_templates(api: NessusAPI) -> list:
    """
    Returns list of system templates.
    :param NessusAPI api: Instance of NessusAPI object
    :return: List of system templates.
    :rtype: list
    """
    return [template['name'] for template in api.reports.get_report_templates() if template[
        'system'] == 1]
