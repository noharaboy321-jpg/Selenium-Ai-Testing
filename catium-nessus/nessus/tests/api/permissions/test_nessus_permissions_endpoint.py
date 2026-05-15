"""
Nessus Permissions Endpoint verification

Test cases for Get Permission object list,
Change Permission object

:copyright: Tenable Network Security, 2017
:date: Jun 15, 2017
:last_modified: Feb 17, 2023
:author: @sshah, @vsoni, @kpanchal, @krpatel
"""
from http import HTTPStatus

import pytest
from requests import HTTPError

from catium.helpers.testdata import load_testdata
from catium.lib.const import TIME_FIVE_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.server import expect_http_error
from nessus.helpers.users import create_user
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API
from nessus.lib.const.constants import Nessus
from nessus.models.scan import ScanModel

log = create_logger()

# API response object fields
EXPECTED_PAYLOAD_FIELDS = ['display_name', 'id', 'name', 'owner', 'permissions', 'type']
DEFAULT_USE_PERMISSION = {'acls': [{"type": API.Permissions.Types.DEFAULT,
                                    "permissions": API.Permissions.Policy.CAN_USE}]}
DEFAULT_EDIT_PERMISSION = {'acls': [{"type": API.Permissions.Types.DEFAULT,
                                     "permissions": API.Permissions.Policy.CAN_EDIT}]}
DEFAULT_NO_ACCESS = {'acls': [{"type": API.Permissions.Types.DEFAULT,
                               "permissions": API.Permissions.Policy.NO_ACCESS}]}


def get_payload_to_create_scan_using_policy_and_new_user_perm(template_uuid: str, user_id: int, policy_id: int,
                                                              scan_target: str, scan_name: str):
    """
    This function returns payload to create scan for specific user using given policy
    :param str template_uuid: template uuid to create scan
    :param int user_id: User ID
    :param int policy_id: Policy ID to create scan
    :param str scan_target: Scan target to perform scan
    :param str scan_name: Scan name
    :return:
    """
    scan_payload = load_testdata(
        'nessus/tests/api/permissions/test_data/create_scan_using_policy_and_new_user.json')
    scan_payload['settings']['acls'][1]['id'] = scan_payload['settings']['acls'][1]['owner'] = user_id
    scan_payload['uuid'] = template_uuid
    scan_payload['settings']['policy_id'] = policy_id
    # scan_payload['settings']['folder_id'] = "3" ## Removing this cause of NES-16093
    scan_payload['settings']['text_targets'] = scan_target
    scan_payload['settings']['name'] = scan_name

    return scan_payload


def modify_permission_of_policy(policy_id: int, permission_objects: dict, nessus_api: NessusAPI) -> None:
    """
    Modify policy permission for given user or group.
    :param int policy_id: Policy ID
    :param dict permission_objects: permission objects for permission set
    :param NessusAPI nessus_api: Instance of NessusAPI
    :return: None
    """
    object_type = API.Permissions.Types.POLICY
    nessus_api.permissions.change(object_type, policy_id, permission_objects)


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusPolicyPermissionsEndpoint:
    """
    Tests for Nessus Permissions Endpoint

    Scenarios missing:
        [ ] Permission tests for non-policy objects (scan, scanner, agent-group)
        [ ] Trying to modify permissions for objects that you don't have permission to modify.
    """

    cat = None

    # NQA-855
    # API_Tested# GET /permissions/policy/{policy_id}
    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_get_permission_list(self, create_policy):
        """
        Returns the current object permissions list of object-type policy.

        Scenarios tested:
            [x] Get a list of permissions for a policy
            [ ] Get a list of permissions for a policy that doesn't exist
        """
        object_id = create_policy['policy_id']
        object_type = API.Permissions.Types.POLICY
        get_permission_objects = self.cat.api.permissions.get_permissions(object_type, object_id)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert 'acls' in get_permission_objects, 'The "acls" field is expected in the get permissions list API response'

        for permission_object in get_permission_objects['acls']:
            assert sorted(permission_object) == sorted(EXPECTED_PAYLOAD_FIELDS), \
                'Permission object "%s" is malformed, missing expected field' % str(permission_object)

    # NQA-856
    # API_Tested# PUT /permissions/policy/{policy_id}/{acls}
    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_permission_change(self, create_policy):
        """
        Verifies a permission can be changed for a particular object-type policy.

        Scenarios tested:
            [x] Update the permissions for a given policy
            [ ] Update permissions for a policy that doesn't exist
            [ ] Update permissions for a policy with invalid permission data
        """
        object_id = create_policy['policy_id']
        object_type = API.Permissions.Types.POLICY
        permission_objects = self.cat.api.permissions.get_permissions(object_type, object_id)

        permission_objects['acls'][0] = [{"type": API.Permissions.Types.DEFAULT,
                                          "permissions": API.Permissions.Policy.CAN_USE}]
        self.cat.api.permissions.change(object_type, object_id, permission_objects['acls'][0])

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        for permission_object in permission_objects['acls'][0]:
            # Verify changed permissions value of object-type policy
            assert permission_object['permissions'] == API.Permissions.Policy.CAN_USE, \
                "Unable to change policy object type permissions"

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD],
                                                        [API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_user_cant_use_policy_by_default(self, create_policy, create_users_using_api):
        """
        NES-12185 : [API] Verify policy permissions for Standard/Administrative user

        Scenario Tested:
            [x] Verify that user does not have permission to use policy by default (Standard/ Administrative)
        """
        created_user = create_users_using_api[0]
        object_id = create_policy['policy_id']

        template_uuid = [policy['template_uuid'] for policy in self.cat.api.policies.get_policies()[
            'policies'] if policy['id'] == object_id][0]

        user_api = NessusAPI()
        user_api.login(username=created_user['name'], password=created_user['password'])

        scan_name = random_name(prefix="new-scan-")
        scan_payload = get_payload_to_create_scan_using_policy_and_new_user_perm(template_uuid=template_uuid,
                                                                                 user_id=created_user['id'],
                                                                                 policy_id=object_id,
                                                                                 scan_target=Nessus.Scan.Target.
                                                                                 LOCALHOST, scan_name=scan_name)

        # Verify that user is not able to use the policy using default permission
        with pytest.raises(HTTPError):
            user_api.scans.create_raw(payload=scan_payload)

        assert user_api.http_status_code == HTTPStatus.NOT_FOUND, \
            'Expected 404, got %s instead.' % user_api.http_status_code

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD],
                                                        [API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_user_cant_edit_policy_by_default(self, create_policy, create_users_using_api):
        """
        NES-12185 : [API] Verify policy permissions for Standard/Administrative user

        Scenario Tested:
            [x] Verify that user does not have permission to edit policy by default (Standard/ Administrative)
        """

        created_user = create_users_using_api[0]

        user_api = NessusAPI()
        user_api.login(username=created_user['name'], password=created_user['password'])

        policy_new_name = random_name(prefix='update-policy-')
        payload = {"settings": {"name": policy_new_name}}

        # Verify that user is not able to edit policy using default permissions
        with pytest.raises(HTTPError):
            user_api.policies.configure(create_policy['policy_id'], payload)

        assert user_api.http_status_code == HTTPStatus.NOT_FOUND, \
            'Expected 404, got %s instead.' % user_api.http_status_code

    # API_Tested# PUT /permissions/policy/{policy_id}/{acls}
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD],
                                                        [API.Permissions.User.ADMINISTRATOR]], indirect=True)
    @pytest.mark.parametrize('revoke_permission', [True, False])
    @pytest.mark.parametrize('default_permission', [True, False])
    @pytest.mark.parametrize('group_permission', [True, False])
    @pytest.mark.usefixtures('nessus_api_login', 'create_policy', 'create_users_using_api', 'nessus_create_group')
    def test_user_or_group_can_use_policy_after_use_permission_granted(self, create_policy, create_users_using_api,
                                                                       revoke_permission, default_permission,
                                                                       group_permission):
        """
        NES-12185 : [API] Verify policy permissions for Standard/Administrative user

        Scenario Tested:
            [x] Verify that user can use policy after permission granted
                via default permission/ user specific permission or user group permission.
            [x] Verify that user is no longer able to use policy after the granted permission is revoked.
        """
        created_user = create_users_using_api[0]
        object_id = create_policy['policy_id']

        if group_permission:
            self.cat.api.groups.add_user(group_id=self.cat.group_id, user_id=created_user['id'])

        template_uuid = [policy['template_uuid'] for policy in self.cat.api.policies.get_policies()[
            'policies'] if policy['id'] == object_id][0]

        user_api = NessusAPI()
        user_api.login(username=created_user['name'], password=created_user['password'])

        permission_objects = DEFAULT_USE_PERMISSION if default_permission else {
            'acls': [{"type": 'group' if group_permission else 'user',
                      "id": self.cat.group_id if group_permission else created_user['id'],
                      "permissions": API.Permissions.Policy.CAN_USE}]}

        modify_permission_of_policy(policy_id=object_id, permission_objects=permission_objects,
                                    nessus_api=self.cat.api)

        scan_name = random_name(prefix="new-scan-")
        scan_payload = get_payload_to_create_scan_using_policy_and_new_user_perm(template_uuid=template_uuid,
                                                                                 user_id=created_user['id'],
                                                                                 policy_id=object_id,
                                                                                 scan_target=Nessus.Scan.Target.
                                                                                 LOCALHOST, scan_name=scan_name)

        user_api.scans.create_raw(payload=scan_payload)

        # Verify that user is able to use policy to create a scan
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert scan_name in [scan['name'] for scan in user_api.scans.get_scans()['scans']], \
            "User - {} is not able to use policy to create a scan after modifying policy permission to 'can use'" \
            "".format(created_user['name'])

        if revoke_permission:
            permission_objects = DEFAULT_NO_ACCESS if default_permission else {
                'acls': [{"type": 'group' if group_permission else 'user',
                          "id": self.cat.group_id if group_permission else created_user['id'],
                          "permissions": API.Permissions.Policy.NO_ACCESS}]}

            modify_permission_of_policy(policy_id=object_id, permission_objects=permission_objects,
                                        nessus_api=self.cat.api)

            # Verify that user is no longer able to use policy after permission revoked
            with pytest.raises(HTTPError):
                user_api.scans.create_raw(payload=scan_payload)

            assert user_api.http_status_code == HTTPStatus.NOT_FOUND, \
                'Expected 404, got %s instead.' % user_api.http_status_code

    # API_Tested# PUT /permissions/policy/{policy_id}/{acls}
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD],
                                                        [API.Permissions.User.ADMINISTRATOR]], indirect=True)
    @pytest.mark.parametrize('revoke_permission', [True, False])
    @pytest.mark.parametrize('default_permission', [True, False])
    @pytest.mark.parametrize('group_permission', [True, False])
    @pytest.mark.usefixtures('nessus_api_login', 'create_policy', 'create_users_using_api', 'nessus_create_group')
    def test_user_or_group_can_edit_policy_after_edit_permission_granted(self, create_policy, create_users_using_api,
                                                                         revoke_permission, default_permission,
                                                                         group_permission):
        """
        NES-12185 : [API] Verify policy permissions for Standard/Administrative user

        Scenario Tested:
            [x] Verify that user can edit policy after permission granted
                via default permission/ user specific permission or user group permission.
            [x] Verify that user is no longer able to edit policy after the granted permission is revoked.
        """
        created_user = create_users_using_api[0]
        object_id = create_policy['policy_id']

        if group_permission:
            self.cat.api.groups.add_user(group_id=self.cat.group_id, user_id=created_user['id'])

        user_api = NessusAPI()
        user_api.login(username=created_user['name'], password=created_user['password'])

        permission_objects = DEFAULT_EDIT_PERMISSION if default_permission else {
            'acls': [{"type": 'group' if group_permission else 'user',
                      "id": self.cat.group_id if group_permission else created_user['id'],
                      "permissions": API.Permissions.Policy.CAN_EDIT}]}

        modify_permission_of_policy(policy_id=object_id, permission_objects=permission_objects,
                                    nessus_api=self.cat.api)

        policy_new_name = random_name(prefix='update-policy-')
        payload = {"settings": {"name": policy_new_name}}

        user_api.policies.configure(create_policy['policy_id'], payload)

        # Verify that user has successfully edited policy after permission granted
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert policy_new_name in [policy['name'] for policy in user_api.policies.get_policies()['policies']], \
            "User - {} is not able to edit policy after when default permission is set to 'can edit" \
            "".format(created_user['name'])
        assert policy_new_name in [policy['name'] for policy in self.cat.api.policies.get_policies()['policies']], \
            "New policy name is not updated/reflected for admin user"

        if revoke_permission:
            permission_objects = DEFAULT_NO_ACCESS if default_permission else {
                'acls': [{"type": 'group' if group_permission else 'user',
                          "id": self.cat.group_id if group_permission else created_user['id'],
                          "permissions": API.Permissions.Policy.NO_ACCESS}]}

            modify_permission_of_policy(policy_id=object_id, permission_objects=permission_objects,
                                        nessus_api=self.cat.api)

            payload["settings"]["name"] = random_name(prefix='update-policy-')

            # Verify that user is no longer able to edit policy after permission revoked
            with pytest.raises(HTTPError):
                user_api.policies.configure(create_policy['policy_id'], payload)

            assert user_api.http_status_code == HTTPStatus.NOT_FOUND, \
                'Expected 404, got %s instead.' % user_api.http_status_code

    # API_Tested# PUT /permissions/policy/{policy_id}/{acls}
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD],
                                                        [API.Permissions.User.ADMINISTRATOR]], indirect=True)
    @pytest.mark.parametrize('group_permission', [True, False])
    @pytest.mark.usefixtures('nessus_api_login', 'create_policy', 'create_users_using_api', 'nessus_create_group')
    def test_user_or_group_cant_edit_policy_when_perm_set_to_use(self, create_policy, create_users_using_api,
                                                                 group_permission):
        """
        NES-12185 : [API] Verify policy permissions for Standard/Administrative user

        Scenario Tested:
            [x] Verify that user can not edit policy if user has only use access for particular policy
        """
        created_user = create_users_using_api[0]
        object_id = create_policy['policy_id']

        user_api = NessusAPI()
        user_api.login(username=created_user['name'], password=created_user['password'])

        if group_permission:
            self.cat.api.groups.add_user(group_id=self.cat.group_id, user_id=created_user['id'])

        permission_objects = {'acls': [{"type": 'group' if group_permission else 'user',
                                        "id": self.cat.group_id if group_permission else created_user['id'],
                                        "permissions": API.Permissions.Policy.CAN_USE}]}

        modify_permission_of_policy(policy_id=object_id, permission_objects=permission_objects,
                                    nessus_api=self.cat.api)

        policy_new_name = random_name(prefix='update-policy-')
        payload = {"settings": {"name": policy_new_name}}

        # Verify that user can not edit policy when permission is only set to use the policy.
        with expect_http_error(code=HTTPStatus.FORBIDDEN, look_for='You are not authorized to perform this request'):
            user_api.policies.configure(create_policy['policy_id'], payload)

        assert user_api.http_status_code == HTTPStatus.FORBIDDEN, \
            'Expected 403, got %s instead.' % user_api.http_status_code


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusScanPermissionsEndpoint:
    """Tests for Nessus Scan Permissions Endpoint"""
    cat = None

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD],
                                                        [API.Permissions.User.ADMINISTRATOR]], indirect=True)
    @pytest.mark.parametrize('scan_permission', [API.Permissions.Scan.CAN_VIEW, API.Permissions.Scan.CAN_CONTROL,
                                                 API.Permissions.Scan.CAN_CONFIGURE])
    @pytest.mark.parametrize('group_permission', [True, False])
    @pytest.mark.parametrize('scan_verify', ['scan_creation', 'copy_scan', 'revoke_permission'])
    @pytest.mark.usefixtures('nessus_api_login', 'create_users_using_api', 'nessus_create_group')
    def test_verify_user_or_group_permissions_for_scan_creation_copy_and_revoke_permission(
            self, create_users_using_api, scan_permission, group_permission, scan_verify):
        """
        NES-12212 : [API] Verify Scan/copy of scan can be created with group permission

        Scenario Tested:
            [x] Verify that scan can be created with user/group permission set as view/control/configure.
            [x] Verify that scan can be copied when permission set as view/control/configure for user/group.
            [x] Verify that scan permission set as view/control/configure can be changed to 'NO_ACCESS' (for user/group)
        """
        created_user = create_users_using_api[0]
        if group_permission:
            self.cat.api.groups.add_user(group_id=self.cat.group_id, user_id=created_user['id'])

        config = {'acls': [{"type": 'group' if group_permission else 'user',
                            "id": self.cat.group_id if group_permission else created_user['id'],
                            "permissions": scan_permission}],
                  'description': 'Created by Automation', 'text_targets': Nessus.Scan.Target.LOCALHOST}

        scan_id = self.cat.api.scans.create(ScanModel(name=random_name(prefix="automation-scan-"), **config))[
            'scan']['id']
        user_api = NessusAPI()
        user_api.login(username=created_user['name'], password=created_user['password'])

        # Verify that scan exist for particular user or users present in particular user-group.
        assert [scan for scan in user_api.scans.get_scans()['scans'] if scan['id'] == scan_id], \
            "Scan does not exist with user/group permission assigned to it."

        # Verify if scan has been created with proper scan permissions.
        if scan_verify == 'scan_creation':
            assert user_api.scans.details(scan_id)['info']['user_permissions'] == scan_permission, \
                "User scan permission is not same as what has been set while scan creation."
            assert [permission for permission in self.cat.api.scans.details(scan_id)['info']['acls'] if permission[
                'id'] in [self.cat.group_id, created_user['id']] and permission['type'] in ['group', 'user']][0][
                       'permissions'] == scan_permission, \
                "For system admin user, scan permissions for particular group/user is not correct."

        # Verify that scan copy operation is successful for scans which has user/group permissions assigned to it.
        elif scan_verify == 'copy_scan':
            copied_scan_id = self.cat.api.scans.copy(scan_id)['id']
            try:
                assert {scan_id, copied_scan_id}.issubset(set([scan['id'] for scan in user_api.scans.get_scans()[
                    'scans']])), "Scan which has user/group assigned to it has not been copied successfully."
            finally:
                self.cat.api.scans.delete(copied_scan_id)

        # Verify that user/group scan permission revoked after changing permission to "NO_ACCESS"
        elif scan_verify == 'revoke_permission':
            permission_objects = {'acls': [{"type": 'group' if group_permission else 'user',
                                            "id": self.cat.group_id if group_permission else created_user['id'],
                                            "permissions": API.Permissions.Scan.NO_ACCESS}]}
            self.cat.api.permissions.change(API.Permissions.Types.SCAN, scan_id, permission_objects)
            user_scans = user_api.scans.get_scans()['scans']
            assert user_scans is None or scan_id not in [scan['id'] for scan in user_scans], \
                "Scan exists for particular user even after revoking user/group permission."
            assert not [permission for permission in self.cat.api.scans.details(scan_id)['info']['acls'] if permission[
                'id'] in [self.cat.group_id, created_user['id']] and permission['type'] in ['group', 'user']], \
                "For system admin user, scan permission for user/group still exist."

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.STANDARD],
                                                        [API.Permissions.User.ADMINISTRATOR],
                                                        [API.Permissions.User.BASIC]], indirect=True)
    @pytest.mark.parametrize('scan_permission', [API.Permissions.Scan.CAN_VIEW])
    @pytest.mark.parametrize('scan_state', [API.Scan.Status.RUNNING, API.Scan.Status.PAUSED, API.Scan.Status.CANCELED])
    def test_verify_scan_state_for_shared_users(self, create_users_using_api, scan_permission, scan_state):
        """
        NES-12643 : [API-Automation] Scan state (running/paused/cancelled) is transparent
                    to all users with whom scan is shared

        Scenario Tested:
            [x] Verify that once admin user launch/pause/stop the scan, other users with whom scan is shared
                can also see the scan state as reflected.
        """
        config = {'acls': [{"type": 'user', "id": create_users_using_api[0]['id'],
                            "permissions": scan_permission}],
                  'description': 'Created by Automation', 'text_targets': Nessus.Scan.Target.LOCALHOST}

        scan_id = self.cat.api.scans.create(ScanModel(name=random_name(prefix="automation-scan-"), **config))[
            'scan']['id']
        self.cat.api.scans.launch(scan_id=scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING, timeout=TIME_FIVE_MINUTES)

        if scan_state == API.Scan.Status.PAUSED:
            self.cat.api.scans.pause(scan_id=scan_id)
        elif scan_state == API.Scan.Status.CANCELED:
            self.cat.api.scans.stop(scan_id=scan_id)

        assert wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=scan_state, timeout=TIME_FIVE_MINUTES), \
            "Scan is not in {} state after five minutes of wait.".format(scan_state)
        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])

        # Verify that scan state for shared users is same as scan owner
        assert user_api.scans.get_status(scan_id=scan_id) == self.cat.api.scans.get_status(scan_id=scan_id), \
            "Scan is not in {} state for shared user.".format(scan_state)

    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.BASIC]], indirect=True)
    @pytest.mark.parametrize('scan_permission', [API.Permissions.Scan.CAN_CONFIGURE])
    @pytest.mark.parametrize('scan_operation', ['launch', 'configure'])
    def test_basic_user_can_not_launch_or_configure_shared_scan(self, create_users_using_api, scan_permission,
                                                                scan_operation):
        """
        NES-12644: Once admin user gives permission of scan to basic user,
                   basic user can only view the scan, can not execute/configure scan.
        Scenario Tested:
            [x] Basic user can not execute/configure shared scan.
        """
        config = {'acls': [{"type": 'user', "id": create_users_using_api[0]['id'],
                            "permissions": scan_permission}],
                  'description': 'Created by Automation', 'text_targets': Nessus.Scan.Target.LOCALHOST}

        scan_id = self.cat.api.scans.create(ScanModel(name=random_name(prefix="automation-scan-"), **config))[
            'scan']['id']

        user_api = NessusAPI()
        user_api.login(username=create_users_using_api[0]['name'], password=create_users_using_api[0]['password'])

        # Verify error while basic user launch/configure shared scan
        with expect_http_error(code=403):
            try:
                if scan_operation == "launch":
                    re = user_api.scans.launch(scan_id=scan_id, stream=True)
                elif scan_operation == "configure":
                    payload = ScanModel(name=random_name(prefix="new_scan_name"), **config).create_payload()
                    re = user_api.scans.configure(scan_id=scan_id, payload=payload, stream=True)

                for chunk in re.iter_content(chunk_size=1024 * 1024):
                    if chunk:  # filter out keep-alive new chunks
                        log.debug("Got a chunk!")
            except Exception as err:
                log.warning("Some unknown connection error occurs: {}".format(err))


def update_and_get_agent_group_permissions(nessus_api: NessusAPI, agent_group_id: int, payload: dict) -> list:
    """
    Update Agent group permissions and then returns the update permissions list
    :param NessusAPI nessus_api: Instance of NessusAPI
    :param int agent_group_id: Agent group ID
    :param dict payload: payload to update agent group permissions
    :return: Agent group permissions (after update)
    :rtype: list
    """
    nessus_api.permissions.change(object_type='agent-group', object_id=agent_group_id, acls=payload)
    updated_permissions = nessus_api.permissions.get_permissions(object_type='agent-group',
                                                                 object_id=agent_group_id)['acls']
    return updated_permissions


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAgentGroupPermissions:
    """
    Tests related to Agent group permissions
    """
    cat = None

    # API_Tested# GET permissions/agent-group/{agent_group_id}
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    def test_verify_default_permissions_for_agent_group(self, create_agent_group_with_new_endpoint):
        """
        NES-12156 : [API] Agent group permission

        Scenarios tested:
            [X] Verify that all users/group have "CAN_USE" permission for agent group by default
        """
        agent_group_id = create_agent_group_with_new_endpoint[0]['id']
        default_permission = self.cat.api.permissions.get_permissions(object_type='agent-group',
                                                                      object_id=agent_group_id)['acls']

        # Verify by default permission for new agent group
        assert [group_permission for group_permission in default_permission if group_permission[
            'permissions'] == API.Permissions.AgentGroup.CAN_USE and group_permission['type'] == 'default'], \
            "New agent group does not have use access (by default)"

    # API_Tested# GET permissions/agent-group/{agent_group_id}
    # API_Tested# POST permissions/agent-group/{agent_group_id}
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.BASIC, API.Permissions.User.ADMINISTRATOR,
                                                         API.Permissions.User.STANDARD]], indirect=True)
    @pytest.mark.parametrize('multiple_users', [False, True])
    def test_verify_agent_group_permissions_for_user(self, create_agent_group_with_new_endpoint,
                                                     create_users_using_api, multiple_users):
        """
        NES-12156 : [API] Agent group permission

        Scenarios tested:
            [X] Verify that any specific user can have permission to use agent group
            [x] Verify that list of users can have permission to use agent group
        """
        agent_group_id = create_agent_group_with_new_endpoint[0]['id']
        created_users = create_users_using_api if multiple_users else [create_users_using_api[0]]

        payload = {"acls": [{"permissions": API.Permissions.AgentGroup.NO_ACCESS, "type": "default"}]}

        # Updating payload to modify agent group permission as per single/multiple users
        for user in created_users:
            payload['acls'].append({'id': user['id'], 'permissions': API.Permissions.AgentGroup.CAN_USE,
                                    'type': 'user'})

        updated_permissions = update_and_get_agent_group_permissions(
            nessus_api=self.cat.api, agent_group_id=int(agent_group_id), payload=payload)

        # Verify that by default, there is no access to use the agent group.
        assert [group_permission for group_permission in updated_permissions if group_permission[
            'permissions'] == API.Permissions.AgentGroup.NO_ACCESS and group_permission['type'] == 'default'], \
            "Default permission is not set to 'no access' after updating agent group permissions."

        # Verify the specific users have permission to use the access group.
        for user in created_users:
            assert [group_permission for group_permission in updated_permissions if group_permission[
                'id'] == user['id'] and group_permission['permissions'] == API.Permissions.AgentGroup.
                        CAN_USE and group_permission['type'] == 'user'], \
                "User - {} does not have use access after updating agent group permission".format(user['name'])

    # API_Tested# GET permissions/agent-group/{agent_group_id}
    # API_Tested# POST permissions/agent-group/{agent_group_id}
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.BASIC, API.Permissions.User.ADMINISTRATOR,
                                                         API.Permissions.User.STANDARD]], indirect=True)
    @pytest.mark.parametrize('multiple_user_groups', [False, True])
    @pytest.mark.usefixtures('nessus_api_login', 'create_agent_group_with_new_endpoint', 'create_users_using_api',
                             'nessus_create_group')
    def test_verify_agent_group_permissions_for_user_group(self, create_agent_group_with_new_endpoint,
                                                           create_users_using_api, multiple_user_groups):
        """
        NES-12156 : [API] Agent group permission

        Scenarios tested:
            [X] Verify that any specific user group can have permission to use agent group
            [x] Verify that list of user groups can have permission to use agent group
        """
        created_users = create_users_using_api
        user_group_ids = [self.cat.group_id]
        agent_group_id = create_agent_group_with_new_endpoint[0]['id']

        payload = {"acls": [{"permissions": API.Permissions.AgentGroup.NO_ACCESS, "type": "default"}]}

        # Updating user group by adding users
        for user in created_users:
            self.cat.api.groups.add_user(group_id=user_group_ids[0], user_id=user['id'])

        payload['acls'].append({'id': user_group_ids[0], 'permissions': API.Permissions.AgentGroup.CAN_USE,
                                'type': 'group'})

        # Adding new user group (which will have one user) and updating payload for the same user group.
        if multiple_user_groups:
            new_user_group = self.cat.api.groups.create(name=random_name(prefix="user-group"))
            new_user = create_user(api=self.cat.api, username=random_name("automation-"), password=random_name(
                "automation-"), permissions=API.Permissions.User.ADMINISTRATOR)
            self.cat.api.groups.add_user(group_id=new_user_group['id'], user_id=new_user['id'])
            payload['acls'].append({'id': new_user_group['id'], 'permissions': API.Permissions.AgentGroup.CAN_USE,
                                    'type': 'group'})
            user_group_ids.append(new_user_group['id'])

        try:
            updated_permissions = update_and_get_agent_group_permissions(
                nessus_api=self.cat.api, agent_group_id=int(agent_group_id), payload=payload)

            # Verify that specific user group or list of user groups have use access to agent group
            for user_group_id in user_group_ids:
                assert [group_permission for group_permission in updated_permissions if group_permission[
                    'permissions'] == API.Permissions.AgentGroup.CAN_USE and group_permission['type'] == 'group' and
                        group_permission['id'] == user_group_id], \
                    "User group having id - {} does not have use access " \
                    "after updating agent group permissions.".format(user_group_id)
        finally:
            # Deleting additional user group/ user added during test
            if multiple_user_groups:
                self.cat.api.groups.delete(group_id=new_user_group['id'])
                self.cat.api.users.delete(user_id=new_user['id'])

    # API_Tested# GET permissions/agent-group/{agent_group_id}
    # API_Tested# POST permissions/agent-group/{agent_group_id}
    @pytest.mark.parametrize('create_agent_group_with_new_endpoint', [(random_name(prefix='agent-group-'),)],
                             indirect=True)
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.BASIC, API.Permissions.User.ADMINISTRATOR,
                                                         API.Permissions.User.STANDARD]], indirect=True)
    @pytest.mark.usefixtures('nessus_api_login', 'create_agent_group_with_new_endpoint', 'create_users_using_api',
                             'nessus_create_group')
    def test_verify_agent_group_permissions_for_user_and_group(self, create_agent_group_with_new_endpoint,
                                                               create_users_using_api):
        """
        NES-12156 : [API] Agent group permission

        Scenarios tested:
            [X] Verify that specific user and user group can have permission to use agent group
        """
        created_users = create_users_using_api
        user_group_id = self.cat.group_id
        agent_group_id = create_agent_group_with_new_endpoint[0]['id']

        payload = {"acls": [{"permissions": API.Permissions.AgentGroup.NO_ACCESS, "type": "default"}]}

        for user in created_users[1:]:
            self.cat.api.groups.add_user(group_id=user_group_id, user_id=user['id'])

        # Updating payload to add "use" access to user and user-group
        payload['acls'].append({'id': user_group_id, 'permissions': API.Permissions.AgentGroup.CAN_USE,
                                'type': 'group'})
        payload['acls'].append({'id': created_users[0]['id'], 'permissions': API.Permissions.AgentGroup.CAN_USE,
                                'type': 'user'})

        updated_permissions = update_and_get_agent_group_permissions(
            nessus_api=self.cat.api, agent_group_id=int(agent_group_id), payload=payload)

        # Verify that user and user group have use access to agent group
        assert [group_permission for group_permission in updated_permissions if group_permission[
            'permissions'] == API.Permissions.AgentGroup.CAN_USE and group_permission[
                    'type'] == 'group' and group_permission['id'] == user_group_id], \
            "User group does not have use access after updating agent group permissions."
        assert [group_permission for group_permission in updated_permissions if group_permission[
            'permissions'] == API.Permissions.AgentGroup.CAN_USE and group_permission[
                    'type'] == 'user' and group_permission['id'] == created_users[0]['id']], \
            "User does not have use access after updating agent group permissions."
