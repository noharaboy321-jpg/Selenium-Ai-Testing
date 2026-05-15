"""
Nessus Reports Endpoint

:copyright: Tenable Network Security, 2018
:date: August 16, 2018
:last_modified: January 28, 2019
:author: @ntarwani, @lestevez
"""
from catium.lib import const
from catium.lib.api.base_api_object import ResponseObject
from nessus.apiobjects import routes


class ReportsEndpoint(object):
    """Reports API Endpoint"""

    def __init__(self, cls):
        self._cls = cls

    def get_report_configuration(self) -> ResponseObject:
        """
        Get reports configuration
        :return: Response for report configuration
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, routes.REPORTS)
        return ResponseObject(response)

    def configure_reports(self, data: dict) -> ResponseObject:
        """
        Update the reports configuration
        :param dict data: dictionary containing configuration data
        :return: Response message for configure reports
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.PUT, routes.REPORTS, json=data)
        return ResponseObject(response)

    def get_default(self, format: str) -> ResponseObject:
        """
        Get default export report options for selected format
        :param str format: (html, pdf) export format
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.GET, 'reports/templates/default?format=%s' % (format))
        return ResponseObject(response)

    def save_default(self, data: dict) -> ResponseObject:
        """
        Save default export report options for selected format
        :param dict data: dictionary containing report options
        :rtype: ResponseObject
        """
        response = self._cls.request(const.HTTPMethods.POST, 'reports/templates/default', json=data)
        return ResponseObject(response)

    def get_report_templates(self) -> ResponseObject:
        """
        Gives all templates for report generation in 'PDF'/'HTML' format.
        """
        response = self._cls.request(const.HTTPMethods.GET, 'reports/custom/templates')
        return ResponseObject(response)

    def get_custom_template_details(self, template_id: int) -> ResponseObject:
        """
        Provides details of custom template
        """
        response = self._cls.request(const.HTTPMethods.GET, 'reports/custom/templates/{}'.format(template_id))
        return ResponseObject(response)

    def create_custom_template(self, data: dict) -> ResponseObject:
        """
        Creates Custom template in Nessus.
        """
        response = self._cls.request(const.HTTPMethods.POST, 'reports/custom/templates', json=data)
        return ResponseObject(response)

    def edit_custom_template(self, template_id: int, data: dict) -> None :
        """
        Modifies custom template in Nessus.
        """
        self._cls.request(const.HTTPMethods.PUT, 'reports/custom/templates/{}'.format(template_id), json=data)

    def delete_custom_template(self, template_id: int) -> None :
        """
        Deletes custom template
        """
        response = self._cls.request(const.HTTPMethods.DELETE, 'reports/custom/templates/{}'.format(template_id))
        return ResponseObject(response)
