"""
Nessus Scan Editor/Plugin Endpoint verification

Test cases for Nessus API Scan Editor and Plugins related tests

:copyright: Tenable Network Security, 2018
:date: Aug 20, 2018
:last_modified: July 15, 2020
:author: @lambaliya.ctr ,@dkothari, @kpanchal, @krpatel
"""

from http import HTTPStatus

import pytest

import nessus.helpers.editor as editor_helper
from catium.helpers.testdata import get_file_path
from nessus.lib.const import API


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusScanEditorEndpoint:
    """Tests for Nessus scan editor Endpoint"""

    cat = None

    # STA-25
    # API_Tested# GET /editor/scan/templates/{template_uuid}/families
    @pytest.mark.nessus_mat
    @pytest.mark.nessus_home
    def test_get_scan_template_families(self, get_scan_templates):
        """
        Get and validate template families

        Scenarios tested:
          [x] Successfully get families for existing scan template
          [ ] Attempt to get families for non-existent scan template
        """
        template = get_scan_templates
        editor_helper.get_and_validate_template_families(self.cat.api, object_type=API.Types.SCAN,
                                                         template_uuid=template[-1]['uuid'])

    # STA-25
    # API_Tested# GET /editor/scan/templates/{template_uuid}/families/{family_id}
    @pytest.mark.nessus_home
    def test_get_scan_template_family(self, get_scan_templates):
        """
        Get and validate specific template

        Scenarios tested:
          [x] Successfully get family for existing scan template
          [ ] Attempt to get family for non-existent scan template
          [ ] Attempt to get non-existent family for scan template
        """
        template = get_scan_templates
        template_families = editor_helper.get_and_validate_template_families(
            self.cat.api, object_type=API.Types.SCAN, template_uuid=template[-1]['uuid'])
        family = next(iter(template_families.values()))
        editor_helper.get_and_validate_specific_template_family(
            self.cat.api, object_type=API.Types.SCAN, template_uuid=template[-1]['uuid'], family_id=family['id'])

    # STA-25 and STA-105
    # API_Tested# GET /editor/{type}/templates/{template_uuid}/families/{family_id}/plugins/{plugin_id:int}
    @pytest.mark.nessus_home
    def test_get_scan_template_plugins(self, get_scan_templates):
        """
        Get and validate plugins of specific template scan

        Scenarios tested:
            [x] Successfully get the plugin definition for a specific scan template
        """
        templates = get_scan_templates
        template_families = editor_helper.get_and_validate_template_families(self.cat.api, object_type=API.Types.SCAN,
                                                                             template_uuid=templates[-1]['uuid'])
        family = next(iter(template_families.values()))
        template_family_detail = editor_helper.get_and_validate_specific_template_family(
            self.cat.api, object_type=API.Types.SCAN, template_uuid=get_scan_templates[-1]['uuid'],
            family_id=family['id'])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert template_family_detail['plugins'], 'No plugins for specific family returned.'
        plugin_id = template_family_detail['plugins'][0]['id']
        plugin = self.cat.api.editor.get_plugin(object_type=API.Types.SCAN,
                                                template_uuid=get_scan_templates[-1]['uuid'], family_id=family['id'],
                                                plugin_id=plugin_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert plugin, "No plugin found with id {}".format(plugin_id)

    # STA-25
    # API_Tested# GET /editor/scan/{id}/families
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [{'scan_json_path': get_file_path('nessus/tests/api/editor/test_data/'
                                                'test_basic_network_scan.json'), 'scan_type': 'basic'}],
                             indirect=True)
    def test_get_created_scan_families(self, create_scan):
        """
        Get and validate scan families

        Scenarios tested:
          [x] Successfully get families for a scan
          [ ] Attempt to get families for a non-existent scan
        """
        scan_id = create_scan['scan']['id']
        editor_helper.get_and_validate_created_scan_or_policy_families(self.cat.api, object_type=API.Types.SCAN,
                                                                       object_id=scan_id)

    # STA-25
    # API_Tested# GET /editor/scan/{id}/families/{id}
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [{'scan_json_path': get_file_path('nessus/tests/api/editor/'
                                                'test_data/test_basic_network_scan.json'), 'scan_type': 'basic'}],
                             indirect=True)
    def test_get_created_scan_family(self, create_scan):
        """
        Get and validate scan's specific family

        Scenarios tested:
          [x] Successfully get family for a scan
          [ ] Attempt to get family for a non-existent scan
          [ ] Attempt to get non-existent family for a scan
        """
        scan_id = create_scan['scan']['id']
        families = editor_helper.get_and_validate_created_scan_or_policy_families(
            self.cat.api, object_type=API.Types.SCAN, object_id=scan_id)
        family = next(iter(families.values()))
        editor_helper.get_and_validate_created_specific_scan_or_policy_family(
            self.cat.api, object_type=API.Types.SCAN, object_id=scan_id, family_id=family['id'])

    # STA-25s
    # API_Tested# GET /editor/scan/{id}/audits/{file_id}/prepare
    @pytest.mark.xfail(reason='Need to work on ESQO-799')
    @pytest.mark.parametrize('test_data_file', [{'scan_json_path':
        get_file_path('nessus/tests/api/editor/test_data/test_offline_config_audit_scan.json'), 'scan_type': 'offline'}],
                    indirect=True)
    def test_prepare_scan_audit_file(self, create_scan):
        """
        Verifies prepare scan audit file

        Scenarios tested:
          [x] Successfully prepare an audit file download
          [ ] Attempt to prepare a download for a non-existent audit file
          [ ] Attempt to prepare a download for a non-existent scan
          [ ] Attempt to prepare a download without permissions
        """
        scan_id = str(create_scan['scan']['id'])
        details = self.cat.api.editor.edit(API.Types.SCAN, scan_id)

        file_id = None
        for audit_details in details["compliance"]["data"]:
            for audit_sub_dir_details in audit_details['audits']:
                if audit_sub_dir_details['name'] == API.Audits.CISCO_AUDIT_FILE_NAME:
                    file_id = audit_sub_dir_details['id']
                    break
        assert file_id, "Unable to find file_id in Custom CISCO IOS audit file"
        self.cat.api.editor.prepare_audit_download(API.Types.SCAN, scan_id, file_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # STA-105
    # API_Tested# GET editor/{type}/{id}/families/{family_id}/plugins/{plugin_id:int}
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [{'scan_json_path': get_file_path('nessus/tests/api/editor/test_data/'
                                                'test_basic_network_scan.json'), 'scan_type': 'basic'}],
                             indirect=True)
    def test_get_plugin_description(self, create_scan):
        """
        STA-105: Implement additional test cases for Editor endpoints
        editor/{type}/{id}/families/{family_id}/plugins/{plugin_id:int}

        Scenarios tested:
          [x] Successfully get plugin description information
        """
        scan_id = create_scan['scan']['id']

        families = editor_helper.get_and_validate_created_scan_or_policy_families(self.cat.api,
                                                                                  object_type=API.Types.SCAN,
                                                                                  object_id=scan_id)
        family = next(iter(families.values()))
        scan_family_detail = editor_helper.get_and_validate_created_specific_scan_or_policy_family(self.cat.api,
                                                                                                   object_type=
                                                                                                   API.Types.SCAN,
                                                                                                   object_id=scan_id,
                                                                                                   family_id=
                                                                                                   family['id'])

        plugin_details = self.cat.api.editor.plugin_description(API.Types.SCAN, family['id'],
                                                                scan_family_detail['plugins'][0]['id'], scan_id)
        assert plugin_details['plugindescription'], \
            "No plugin description were returned for {} plugin id.".format(scan_family_detail['plugins'][0]['id'])
