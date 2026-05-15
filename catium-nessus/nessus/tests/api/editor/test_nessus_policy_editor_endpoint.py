"""
Nessus Policy Editor/Plugin Endpoint verification

Test cases for Nessus API Policy Editor and Plugins related tests

:copyright: Tenable Network Security, 2018
:date: Aug 20, 2018
:last_modified: July 15, 2020
:author: @lambaliya.ctr, @dkothari, @kpanchal
"""

from http import HTTPStatus

import pytest

import nessus.helpers.editor as editor_helper
from nessus.lib.const import API


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusPolicyEditorEndpoint:
    """Tests for Nessus policy editor Endpoint"""

    cat = None

    # STA-25
    # API_Tested# GET /editor/policy/templates/{template_uuid}/families
    @pytest.mark.nessus_mat
    @pytest.mark.nessus_home
    def test_get_policy_template_families(self, get_policy_templates):
        """
        Get and validate template families

        Scenarios tested:
          [x] Successfully get policy template families
          [ ] Attempt to get families for non-existent policy template
        """
        template = get_policy_templates
        editor_helper.get_and_validate_template_families(self.cat.api, object_type=API.Types.POLICY,
                                                         template_uuid=template[-1]['uuid'])

    # STA-25
    # API_Tested# GET /editor/policy/templates/{template_uuid}/families/{family_id}
    @pytest.mark.nessus_home
    def test_get_policy_template_family(self, get_policy_templates):
        """
        Get and validate specific template family

        Scenarios tested:
          [x] Successfully get policy template family
          [ ] Attempt to get non-existent family from policy template
          [ ] Attempt to get family from non-existent policy template
        """
        template_families = editor_helper.get_and_validate_template_families(self.cat.api, object_type=API.Types.POLICY,
                                                                             template_uuid=get_policy_templates
                                                                             [-1]['uuid'])
        family = next(iter(template_families.values()))
        editor_helper.get_and_validate_specific_template_family(self.cat.api, object_type=API.Types.POLICY,
                                                                template_uuid=get_policy_templates[-1]['uuid'],
                                                                family_id=family['id'])

    # STA-25 and STA-105
    # API_Tested# GET /editor/{type}/templates/{template_uuid}/families/{family_id}/plugins/{plugin_id:int}
    @pytest.mark.nessus_home
    def test_get_policy_template_plugins(self, get_policy_templates):
        """
        Get and validate plugins of specific template policy

        Scenarios tested:
            [x] Successfully get the plugins associated with a template policy
            [x] Verify a specfic plugin can be retrieved for a specific plugin id
        """
        template_families = editor_helper.get_and_validate_template_families(self.cat.api,
                                                                             object_type=API.Types.POLICY,
                                                                             template_uuid=get_policy_templates
                                                                             [-1]['uuid'])
        family = next(iter(template_families.values()))
        template_family_detail = editor_helper.get_and_validate_specific_template_family(
            self.cat.api, object_type=API.Types.POLICY, template_uuid=get_policy_templates[-1]['uuid'],
            family_id=family['id'])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert template_family_detail['plugins'], 'No plugins for specific family returned.'
        plugin_id = template_family_detail['plugins'][0]['id']
        plugin = self.cat.api.editor.get_plugin(object_type=API.Types.POLICY,
                                                template_uuid=get_policy_templates[-1]['uuid'],
                                                family_id=family['id'], plugin_id=plugin_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert plugin, "No plugin found with id {}".format(plugin_id)

    # STA-25
    # API_Tested# GET /editor/policy/{id}/families
    @pytest.mark.nessus_home
    def test_get_created_policy_families(self, create_policy):
        """
        Get and validate policies families

        Scenarios tested:
          [x] Successfully get policy families
          [ ] Attempt to get families for non-existent policy
        """
        policy_id = create_policy['policy_id']
        editor_helper.get_and_validate_created_scan_or_policy_families(self.cat.api, object_type=API.Types.POLICY,
                                                                       object_id=policy_id)

    # STA-25
    # API_Tested# GET /editor/policy/{id}/families/{id}
    @pytest.mark.nessus_home
    def test_get_created_policy_family(self, create_policy):
        """
        Get and validate policies' specific family

        Scenarios tested:
          [x] Successfully get a policy family
          [ ] Attempt to get a non-existent family for a policy
          [ ] Attempt to get a family for a non-existent policy
        """
        policy_id = create_policy['policy_id']
        families = editor_helper.get_and_validate_created_scan_or_policy_families(
            self.cat.api, object_type=API.Types.POLICY, object_id=policy_id)
        family = next(iter(families.values()))
        editor_helper.get_and_validate_created_specific_scan_or_policy_family(
            self.cat.api, object_type=API.Types.POLICY, object_id=policy_id, family_id=family['id'])

    # STA-25
    # API_Tested# GET /editor/policy/{id}/audits/{file_id}/prepare
    @pytest.mark.incompatible
    @pytest.mark.parametrize('create_policy', [{"template_name": "offline"}], indirect=True)
    def test_prepare_policy_audit_file(self, create_policy):
        """
        Verifies export policy audit file

        Scenarios tested:
          [x] Successfully prepare an audit download
          [ ] Attempt to prepare a download for a non-existent policy
          [ ] Attempt to prepare a download for a non-existent audit of an existing policy
          [ ] Attempt to prepare a download without permissions
        """
        created_policy_id = str(create_policy['policy_id'])
        details = self.cat.api.editor.edit(API.Types.POLICY, created_policy_id)

        file_id = None
        for audit_details in details["compliance"]["data"]:
            for audit_sub_dir_details in audit_details['audits']:
                if audit_sub_dir_details['name'] == API.Audits.CISCO_AUDIT_FILE_NAME:
                    file_id = audit_sub_dir_details['id']
                    break
        assert file_id, "Unable to find file_id in Custom CISCO IOS audit file"
        self.cat.api.editor.prepare_audit_download(API.Types.POLICY, created_policy_id, file_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
