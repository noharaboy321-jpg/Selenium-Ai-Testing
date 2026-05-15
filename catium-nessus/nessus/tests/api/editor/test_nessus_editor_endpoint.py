"""
Nessus Editor/Plugin Endpoint verification

Test cases for Nessus API Editor and
 Plugins related tests

:copyright: Tenable Network Security, 2017
:date: Jun 8, 2017
:last_modified: July 15, 2020
:author: @sshah, @dkothari, @kpanchal, @krpatel
"""

import base64
from http import HTTPStatus
from catium.lib.log import create_logger

import pytest

from catium.helpers.testdata import get_file_path
from nessus.lib.const import API

log = create_logger()

@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.extended_smoke
@pytest.mark.usefixtures('wait_for_plugin_families_to_be_available', 'nessus_api_login')
class TestNessusEditorEndpoint:
    """Tests for Nessus editor Endpoint"""

    cat = None

    # NQA-876
    # API_Tested# GET /editor/policy/templates
    @pytest.mark.nessus_mat
    @pytest.mark.nessus_home
    def test_get_policy_template_list(self, get_policy_templates):
        """
        Test getting a list of policy templates

        Scenarios tested:
          [x] Successfully get list of policy templates
        """
        num_policy_templates_list = get_policy_templates

        verify_first_record_details = get_policy_templates[0].keys()
        assert 'name' in verify_first_record_details, 'Failed to get name in first record of policy template details'
        assert 'uuid' in verify_first_record_details, 'Failed to get uuid in first record of policy template details'
        assert 'desc' in verify_first_record_details, \
            'Failed to get description in first record of policy template details'
        assert 'title' in verify_first_record_details, 'Failed to get title in first record of policy template details'

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert len(num_policy_templates_list) > 0, 'No list of policy templates returned'

    # NQA-877
    # API_Tested# GET /editor/scan/templates
    @pytest.mark.nessus_mat
    @pytest.mark.nessus_home
    def test_get_scan_template_list(self, get_scan_templates):
        """
        Test getting a list of scan templates

        Scenarios tested:
          [x] Successfully get list of scan templates
        """
        num_scan_templates_list = get_scan_templates

        verify_first_record_details = get_scan_templates[0].keys()
        assert 'name' in verify_first_record_details, 'Failed to get name in first record of scan template details'
        assert 'uuid' in verify_first_record_details, 'Failed to get uuid in first record of scan template details'
        assert 'desc' in verify_first_record_details, \
            'Failed to get description in first record of scan template details'
        assert 'title' in verify_first_record_details, 'Failed to get title in first record of scan template details'

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert len(num_scan_templates_list) > 0, 'No list of scan templates returned'

    # API_Tested# GET /editor/{type}/templates
    @pytest.mark.parametrize('type', ['scan', 'policy'])
    def test_get_template_icons(self, get_scan_templates, type):
        """
        Test that icons are being returned for policies and scans.
        Scenarios tested:
        [x] Test that "icon" is present on scan templates
        [x] Test that "icon" is present on policy templates
        [x] Test that one of the icons looks right
        """
        templates = self.cat.api.editor.get_templates(type)['templates']
        by_name = {}
        for template in templates:
            assert 'icon' in template, 'Template %s is missing an icon' % template['name']
            by_name[template['name']] = template['icon']

        expected_basic = ('<?xml version="1.0" encoding="utf-8"?><!DOCTYPE svg PUBLIC "-//' +
                          'W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg ve' +
                          'rsion="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/19' +
                          '99/xlink" width="64" height="64" viewBox="0 0 64 64"><path fill="#6fbf4a" d="M7 ' +
                          '37.944c0 0.552-0.448 1-1 1s-1-0.448-1-1c0-0.552 0.448-1 1-1s1 0.448 1 1z"></path' +
                          '><path fill="#6fbf4a" d="M11 37.944c0 0.552-0.448 1-1 1s-1-0.448-1-1c0-0.552 0.4' +
                          '48-1 1-1s1 0.448 1 1z"></path><path fill="#6fbf4a" d="M55 37.944c0 0.552-0.448 1' +
                          '-1 1s-1-0.448-1-1c0-0.552 0.448-1 1-1s1 0.448 1 1z"></path><path fill="#6fbf4a" ' +
                          'd="M59 37.944c0 0.552-0.448 1-1 1s-1-0.448-1-1c0-0.552 0.448-1 1-1s1 0.448 1 1z"' +
                          '></path><path fill="#6fbf4a" d="M32.578 60.551l-7.504-40.858-3.619 19.307h-7.455' +
                          'c-0.553 0-1-0.449-1-1s0.447-1 1-1h5.744l5.26-33.592 7.738 40.691 6.645-28.148 5.' +
                          '098 21.049h5.516c0.551 0 1 0.449 1 1s-0.449 1-1 1h-7.086l-3.332-11.402-7.004 32.' +
                          '953z"></path></svg>')
        assert base64.b64decode(by_name['basic']).decode('utf-8') == expected_basic, \
            "Icon payload isn't the expected string"

    # NQA-872
    # API_Tested# GET /editor/policy/templates/{template_uuid}
    def test_get_policy_template_details(self, get_policy_templates):
        """
        Returns details for the given template.

        Scenarios tested:
          [x] Successfully get a policy template by uuid
          [ ] Attempt to get a non-existent policy template uuid
        """
        for template in get_policy_templates:
            details = self.cat.api.editor.details(API.Types.POLICY, template['uuid'])
            assert len(details) > 0, "No policy template details returned"

    # NQA-873
    # API_Tested# GET /editor/scan/templates/{template_uuid}
    def test_get_scan_template_details(self, get_scan_templates):
        """
        Returns details for the given template.

        Scenarios tested:
          [x] Successfully get a policy template by uuid
          [ ] Attempt to get a non-existent scan template uuid
        """
        for template in get_scan_templates:
            details = self.cat.api.editor.details(API.Types.SCAN, template['uuid'])
            assert len(details) > 0, "No scan template details returned"

    # NQA-878
    # API_Tested# GET /editor/policy/{policy_id}/families/{family_id}/plugins/{plugin_id}
    @pytest.mark.nessus_home
    def test_get_plugin_description(self, create_policy, get_plugin_families):
        """
        Returns plugin description information for 19506 plugin id.

        Scenarios tested:
          [x] Successfully get a plugin for a family in a policy
          [ ] Attempt to get a non-existent plugin from a family in a policy
          [ ] Attempt to get a plugin from a non-existent family in a policy
          [ ] Attempt to get a plugin from a family in a non-existent policy
        """
        policy = create_policy
        plugin_family = get_plugin_families
        plugin_details = self.cat.api.editor.plugin_description(API.Types.POLICY, plugin_family[-1]['id'], 19506,
                                                                policy['policy_id'])
        # Verify plugin description is returned for 19506 plugin id
        assert len(plugin_details['plugindescription']) > 0, "No plugin description were returned for 19506 plugin id."

    # NQA-888
    # API_Tested# GET /plugins/families
    @pytest.mark.nessus_mat
    @pytest.mark.nessus_home
    def test_get_plugin_families(self, get_plugin_families):
        """
        Verifies that a list of plugin families can be retrieved
        
        Scenarios tested:
            [x] Test that list of plugin families can be retrieved
        """
        number_of_plugin_families = len(get_plugin_families)
        assert number_of_plugin_families > 0, 'Could not retrieve plugin families.'

    # NQA-889
    # API_Tested# GET /plugins/families/{family_id}
    @pytest.mark.nessus_home
    def test_get_plugin_family_details(self, get_plugin_families):
        """
        Verifies that details for a plugin family can be retrieved
        
        Scenarios tested:
            [x] Test that details for a plugin family can be retrieved
            [] Test requesting details for a non-existent plugin family fails
        """
        for plugin_family in get_plugin_families:
            details = self.cat.api.plugins.family_details(plugin_family['id'])
            assert details, 'Could not retrieve plugin family details.'

    # NQA-890
    # API_Tested# GET /plugins/plugin/{plugin_id}
    @pytest.mark.nessus_home
    def test_get_plugin_details(self, get_plugins):
        """
        Verifies that details for a plugin can be retrieved
        
        Scenarios tested:
            [x] Test that details for a plugin can be retrieved
            [] Test requesting details for a non-existent plugin family fails
        """
        plugin = get_plugins[0]
        plugin_id = plugin['id']
        details = self.cat.api.plugins.plugin_details(plugin_id)
        details_name = details['name']
        plugin_name = plugin['name']
        assert details_name == plugin_name, 'Failed to retrieve plugin details'

    # NQA-874
    # API_Tested# GET /editor/policy/{policy_id}
    @pytest.mark.nessus_home
    def test_get_details_editor_policy(self, create_policy):
        """
        Verifies details of a policy

        Scenarios tested:
          [x] Successfully get a policy by id
          [ ] Attempt to get a non-existent policy
        """
        policy_id = str(create_policy['policy_id'])
        self.cat.api.editor.edit(API.Types.POLICY, policy_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # NQA-875
    # API_Tested# GET /editor/scan/{scan_id}
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [{'scan_json_path':
        get_file_path(
            'nessus/tests/api/editor/test_data/test_basic_network_scan.json'),
        'scan_type': 'basic'}],
                             indirect=True)
    def test_get_details_editor_scan(self, create_scan):
        """
        Verifies details of a scan

        Scenarios tested:
          [x] Successfully get a scan by id
          [ ] Attempt to get a non-existent scan
        """
        scan_id = str(create_scan['scan']['id'])
        self.cat.api.editor.edit(API.Types.SCAN, scan_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # NQA-870
    # API_Tested# GET /editor/policy/{policy_id}/audits/{file_id}
    @pytest.mark.incompatible
    @pytest.mark.parametrize('create_policy', [{"template_name": "offline"}], indirect=True)
    def test_export_policy_audit_file(self, create_policy):
        """
        Verifies export policy audit file

        Scenarios tested:
          [x] Successfully get audit file details for a policy
          [ ] Attempt to get non-existent audit file details for an existing policy
          [ ] Attempt to get audit file details from a non-existent policy
          [ ] Attempt to get audit file details without permissions
        """
        created_policy_id = str(create_policy['policy_id'])
        details = self.cat.api.editor.edit(API.Types.POLICY, created_policy_id)

        log.info(f"please find the details:-- {details}")

        file_id = None
        for audit_details in details["compliance"]["data"]:
            for audit_sub_dir_details in audit_details['audits']:
                if audit_sub_dir_details['name'] == API.Audits.CISCO_AUDIT_FILE_NAME:
                    file_id = audit_sub_dir_details['id']
        assert file_id, "Unable to find file_id in Custom CISCO IOS audit file"
        self.cat.api.editor.audits(API.Types.POLICY, created_policy_id, file_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # NQA-871
    # API_Tested# GET /editor/scan/{scan_id}/audits/{file_id}
    @pytest.mark.xfail(reason='Need to work on ESQO-799')
    @pytest.mark.parametrize('test_data_file', [{'scan_json_path':
                                                     get_file_path(
                                                         'nessus/tests/api/editor/test_data/test_offline_config_audit_scan.json'),
                                                 'scan_type': 'offline'}],
                             indirect=True)
    def test_export_scan_audit_file(self, create_scan):
        """
        Verifies export scan audit file

        Scenarios tested:
          [x] Successfully get audit file details for a scan
          [ ] Attempt to get audit file details for non-existent scan
          [ ] Attempt to get audit file details for non-existent audit file
          [ ] Attempt to get audit file details without permissions
        """
        scan_id = str(create_scan['scan']['id'])
        details = self.cat.api.editor.edit(API.Types.SCAN, scan_id)

        file_id = None
        for audit_details in details["compliance"]["data"]:
            for audit_sub_dir_details in audit_details['audits']:
                if audit_sub_dir_details['name'] == API.Audits.CISCO_AUDIT_FILE_NAME:
                    file_id = audit_sub_dir_details['id']
        assert file_id, "Unable to find file_id in Custom CISCO IOS audit file"
        self.cat.api.editor.audits(API.Types.SCAN, scan_id, file_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# GET /editor/scan/templates
    @pytest.mark.xfail(reason="NES-9881 Waiting for order/category attributes to be merged to feed")
    @pytest.mark.nessus_home
    def test_get_templates_order_and_category(self):
        """
        NES-9820
        Test that scan templates have order and policy attributes filled
        and that the values are unique.

        Scenarios tested:
          [x] Test that scan templates all have "order" attributes
          [x] Test that scan templates all have "category" attributes
          [x] Test that scan templates all unique "order" + "category"
          [ ] Test that non-scan template types have "order" and/or "category"
        """
        templates = self.cat.api.editor.get_templates('scan')['templates']

        # these templates are known not to have category/order
        unordered_templates = ['custom', 'ghost']

        # check each template for order, category, and uniqueness
        values = {}
        for template in templates:
            if template['name'] in unordered_templates:
                continue
            assert 'order' in template and template['order'] is not None
            assert 'category' in template and template['category'] is not None
            combined = template['category'] + str(template['order'])
            assert combined not in values, \
                'Detected non-unique value: %s and %s both have category %s and order %d' % (
                    values[combined], template['name'], template['category'], template['order'])
            values[combined] = template['name']
