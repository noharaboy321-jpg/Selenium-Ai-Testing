"""
Nessus To Tenable IO Migration Feature Related Test cases

:copyright: Tenable Network Security, 2020
:date: Nov 26, 2020
:last_modified: Dec 14, 2020
:author: @kpanchal, @vsoni
"""
import json

import pytest
from collections import defaultdict
from random import randint
from waiting import wait

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.const.base_constants import WAIT_NORMAL, TIME_TEN_MINUTES, TIME_FIVE_MINUTES, TIME_THIRTY_MINUTES, \
    TIME_THIRTY_SECONDS, TIME_TWO_MINUTES, TIME_FIVE_SECONDS
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name, random_string
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.scan import create_scan_helper
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const.constants import Nessus, API, Scanner
from nessus.models.scan import ScanModel
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI
from tenableio.lib.config.tenableio_environment_variables import TenableIOConfig
from tenableio.lib.const.constants import Passwords

log = create_logger()


@pytest.mark.usefixtures('nessus_api_login')
class TestNessusMigrationEndpoint:
    """ Tests for Nessus migration Endpoint """

    cat = None

    @staticmethod
    def get_scan_details(nessus_api: NessusAPI, scan_id: int) -> dict:
        """
        Returns scan details of given scan id

        :param NessusAPI nessus_api: API object
        :param scan_id: scan id
        :return: scan details
        :rtype: dict
        """
        scan_details = nessus_api.scans.details(scan_id=scan_id)

        return scan_details

    @staticmethod
    def create_schedule_scan_for_migration(nessus_api: NessusAPI) -> dict:
        """
        Creates scheduled scan

        :param NessusAPI nessus_api: API object
        :return: scheduled scan info
        :rtype: dict
        """
        config = {'enabled': True, 'starttime': '20300101T120000', 'timezone': 'US/Samoa', 'launch': 'ONETIME',
                  'rrules': 'FREQ=ONETIME', 'description': 'Created by Automation', 'text_targets': '127.0.0.1'}

        schedule_scan_id = nessus_api.scans.create(ScanModel(
            name=random_name(prefix="{} - ".format(Nessus.TemplateNames.ADVANCED)), **config))['scan']['id']

        schedule_scan_info = __class__.get_scan_details(nessus_api=nessus_api, scan_id=schedule_scan_id)['info']

        return schedule_scan_info

    @staticmethod
    def create_host_discovery_scan_in_custom_folder(nessus_api: NessusAPI) -> dict:
        """
        Creates Host Discovery scan in custom folder
        :param NessusAPI nessus_api: API object
        :return: folder and created scan info
        :rtype: dict
        """
        scan_file = get_file_path('nessus/tests/api/scan/test_data/test_host_discovery_scan_target.json')
        custom_folder_name = random_name(prefix='Ui-Auto-')
        folder_info = nessus_api.folders.create(name=custom_folder_name)
        with open(scan_file, "r+") as jsonFile:
            data = json.load(jsonFile)
            data["settings"]["folder_id"] = folder_info['id']
            jsonFile.seek(0)
            json.dump(data, jsonFile)
            jsonFile.truncate()
        created_scan = create_scan_helper(nessus_api, file_name=scan_file, template_title='discovery',
                                          change_scan_name=True)
        scan_id = created_scan[0]['scan']["id"]
        nessus_api.scans.launch(scan_id=scan_id)
        wait_scan_state(api=nessus_api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)
        host_discovery_scan_details = __class__.get_scan_details(nessus_api=nessus_api, scan_id=scan_id)
        return {'name': host_discovery_scan_details['info']['name'], 'folder_name': custom_folder_name,
                'status': host_discovery_scan_details['info']['status']}

    @staticmethod
    def cancel_scan_in_trash_folder(nessus_api: NessusAPI) -> dict:
        """
        Create, launch, stop and move scan to trash folder

        :param NessusAPI nessus_api: API object
        :return: scan details
        :rtype: dict
        """
        created_scan = create_scan_helper(nessus_api, file_name=get_file_path(
            'nessus/tests/api/scan/test_data/test_wannacry_scan.json'), template_title='wannacry',
                                          change_scan_name=True)

        scan_id = created_scan[0]['scan']["id"]
        nessus_api.scans.launch(scan_id=scan_id)

        wait(lambda: nessus_api.scans.details(scan_id)['info']['status'] == API.Scan.Status.RUNNING,
             sleep_seconds=WAIT_NORMAL, waiting_for=Scanner.Strings.SCAN_TO_START, timeout_seconds=TIME_TEN_MINUTES)

        nessus_api.scans.stop(scan_id)
        wait_scan_state(api=nessus_api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED, timeout=TIME_FIVE_MINUTES)

        # Move cancelled scan into trash folder
        nessus_api.scans.move(scan_id, "2")
        cancelled_scan_info = __class__.get_scan_details(nessus_api=nessus_api, scan_id=scan_id)['info']

        return cancelled_scan_info

    @staticmethod
    def create_offline_scan(nessus_api: NessusAPI) -> dict:
        """
        Creates Offline audit scan

        :param NessusAPI nessus_api: API object
        :return: scan info
        :rtype: dict
        """
        created_scan = create_scan_helper(nessus_api, file_name=get_file_path(
            'nessus/tests/api/scan/test_data/test_offline_config_audit_scan_target.json'), template_title='offline',
                                          change_scan_name=True)

        scan_id = created_scan[0]['scan']["id"]
        nessus_api.scans.launch(scan_id=scan_id)

        wait_scan_state(api=nessus_api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                        timeout=TIME_THIRTY_MINUTES)

        offline_audit_scan_details = __class__.get_scan_details(nessus_api=nessus_api, scan_id=scan_id)

        return {'name': offline_audit_scan_details['info']['name'],
                'audit_file_name': offline_audit_scan_details['comphosts'][0]['hostname'],
                'compliance_plugin_family': offline_audit_scan_details['compliance'][0]['plugin_family']}

    @staticmethod
    def create_policy_with_credentials(nessus_api: NessusAPI) -> dict:
        """
        Created policy scan with credentials data of windows

        :param NessusAPI nessus_api: API object
        :return: policy scan details
        :rtype: dict
        """
        template_name = "malware"
        data_value = {}
        policy_uuid = None
        data_list_to_be_verify = ['username', 'password']

        for data_item in data_list_to_be_verify:
            data_value[data_item] = random_string()

        policy_name = random_name(prefix="{} scan policy-".format(template_name))
        templates = nessus_api.editor.get_templates('policy')['templates']

        for template in templates:
            if template_name == template['name']:
                policy_uuid = template['uuid']
                break

        credential_data = {'add': {'Host': {'Windows': [{'auth_method': "Password", 'username': data_value["username"],
                                                         'password': data_value["password"]}]}}}
        policy_data = {'uuid': policy_uuid, 'settings': {"name": policy_name}, 'credentials': credential_data}

        policy_id = nessus_api.policies.create(payload=policy_data)['policy_id']
        policy_details = nessus_api.policies.details(policy_id=policy_id)

        return {'name': policy_details['settings']['name'], 'credential_details': policy_details['credentials']}

    @staticmethod
    def get_folder_details(nessus_api: NessusAPI, folder_id: int) -> dict:
        """
        Returns created folder name

        :param NessusAPI nessus_api: API object
        :param int folder_id: created folder id
        :return: folder details
        :rtype: dict
        """
        for folder in nessus_api.folders.get_folders()['folders']:
            if folder['id'] == folder_id:
                return {'folder_id': folder_id, 'folder_name': folder['name']}

    @staticmethod
    def get_required_nessus_data_from_created_data(created_nessus_data: dict) -> dict:
        """
        Returns required Nessus data from the created one
        :param created_nessus_data: created nessus data details
        :return: required nessus info
        :rtype: dict
        """
        required_details = defaultdict(dict)
        for key, value in created_nessus_data.items():
            if 'scan' in key:
                for item in ['name', 'status', 'folder_name', 'credential_details', 'audit_file_name',
                             'compliance_plugin_family']:
                    if item in value:
                        required_details[key][item] = value[item]
            elif 'policy' in key and 'policy_name' in value:
                required_details[key]['{}_name'.format(key)] = value['policy_name']
            elif 'folder' in key and 'folder_name' in value:
                required_details[key]['{}_name'.format(key)] = value['folder_name']
            elif 'plugin_rule' in key and 'host_name' in value and 'plugin_id' in value:
                required_details[key]['{}_host'.format(key)] = value['host_name']
                required_details[key]['{}_id'.format(key)] = value['plugin_id']
            elif 'group' in key or 'freeze' in key:
                required_details[key]['{}_name'.format(key)] = value['name']
            elif 'real_agent' in key:
                required_details['real_agent_info']['real_agent_name'] = value['agent_name']
                required_details['agent_group_info']['agent_group_name'] = value['agent_group_name']
            elif 'settings' in key:
                required_details[key]['track_unlinked_agents'] = value['track_unlinked_agents']
                required_details[key]['auto_delete'] = value['auto_delete']
            elif 'users' in key:
                user_data = {}
                for data in value:
                    user_data[data['name']] = data['permissions']
                required_details['{}_info'.format(key)] = user_data
        return dict(required_details)

    def create_nessus_data_for_migration(self, create_scan, create_folder, create_policy, create_plugin_rules):
        """
        Creates common Nessus data like scan, policy, plugin-rule, folder, etc... in Manager and Pro
        """
        blank_folder_id = create_folder
        folder_details = self.get_folder_details(nessus_api=self.cat.api, folder_id=blank_folder_id)
        log.info("Folder without scan :: {}".format(folder_details))

        normal_scan = create_scan['scan']
        log.info("Created scan :: {}".format(normal_scan))

        schedule_scan = self.create_schedule_scan_for_migration(nessus_api=self.cat.api)
        log.info("Schedule scan :: {}".format(schedule_scan))

        host_discovery_scan = self.create_host_discovery_scan_in_custom_folder(nessus_api=self.cat.api)
        log.info("Host discovery scan info :: {}".format(host_discovery_scan))

        scan_in_trash_folder = self.cancel_scan_in_trash_folder(nessus_api=self.cat.api)
        log.info("Scan info from trash folder :: {}".format(scan_in_trash_folder))

        scan_with_audit_file = self.create_offline_scan(nessus_api=self.cat.api)
        log.info("Scan with audit file :: {}".format(scan_with_audit_file))

        normal_policy = create_policy
        log.info("Created policy :: {}".format(normal_policy))

        policy_scan_with_credential = self.create_policy_with_credentials(nessus_api=self.cat.api)
        log.info("Policy scan with credential :: {}".format(policy_scan_with_credential))

        created_plugin_rule = create_plugin_rules[0]
        log.info("Created plugin rule :: {}".format(created_plugin_rule))

        nessus_data = {'blank_folder': folder_details, 'normal_scan': normal_scan, 'schedule_scan': schedule_scan,
                       'host_discovery_scan': host_discovery_scan, 'scan_in_trash_folder': scan_in_trash_folder,
                       'scan_with_audit_file': scan_with_audit_file, 'normal_policy': normal_policy,
                       'policy_scan_with_credential': policy_scan_with_credential,
                       'created_plugin_rule': created_plugin_rule}

        required_nessus_data = __class__.get_required_nessus_data_from_created_data(created_nessus_data=nessus_data)

        return required_nessus_data

    @pytest.mark.nessus_manager_migration
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)],
                             indirect=True)
    @pytest.mark.parametrize('create_plugin_rules', [
        {'plugin_list': [{"host": random_name(prefix="plugin_rule_"), "plugin_id": randint(1000, 2000),
                          "type": "exclude"}]}], indirect=True)
    @pytest.mark.parametrize("agent_config_settings", [
        {"payload": {"auto_delete": {"enabled": True, "expiration": 30}, "track_unlinked_agents": True,
                     "auto_unlink": {"enabled": False}}}], indirect=True)
    @pytest.mark.usefixtures('create_folder', 'create_tenable_io_container',
                             'create_agent_group_with_real_agent', 'create_exclusion',
                             'nessus_create_group', 'agent_config_settings')
    def test_nessus_manager_migration_to_tenable_io(self, create_scan, create_folder, create_policy,
                                                    create_plugin_rules, create_agent_group_with_real_agent,
                                                    create_exclusion, nessus_create_group, create_tenable_io_container):
        """
        NES-12322: [API Automation]: Nessus upgrade assistant (Migration)

        Scenario Tested:
            [x] Verify that Nessus manager user data like empty folder, folder with scan, normal scan, schedule scan,
                audit scan, scan in trash folder, normal policy, credentialed policy, plugin rule, agent, agent group,
                user group, blackout window gets migrated to Tenable.io successfully.
        """
        created_nessus_data = self.create_nessus_data_for_migration(
            create_scan=create_scan, create_folder=create_folder, create_policy=create_policy,
            create_plugin_rules=create_plugin_rules)

        created_manager_data = {'agent_settings': self.cat.api.agents.get_config(), 'user_group': nessus_create_group,
                                'created_real_agent_info': create_agent_group_with_real_agent,
                                'created_freeze_window': create_exclusion[0]}

        required_manager_data = self.get_required_nessus_data_from_created_data(
            created_nessus_data=created_manager_data)

        created_nessus_data.update(required_manager_data)

        log.info("Required NM data for migration :: {}".format(created_nessus_data))

        log.info("Created Nessus Manager data for migration :: {}".format(created_nessus_data))
        migration_details = migrate_nessus_to_tenable_io(container_details=create_tenable_io_container)
        self.cat.api.login()

        tenable_api = migration_details['tenable_api']
        scanner_name = migration_details['scanner_name']

        assert validate_data_migrated_to_tenable_io_successfully(
            tenable_api=tenable_api, created_data=created_nessus_data, nessus_type="manager",
            scanner_name=scanner_name), "Nessus Manager data did not migrate to tenable.io successfully."

    @pytest.mark.nessus_pro_migration
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_advanced_scan.json'),
         'scan_type': 'advanced'}], indirect=True)
    @pytest.mark.parametrize("create_policy", [(Nessus.TemplateNames.ADVANCED, API.Permissions.Types.SCANNER)],
                             indirect=True)
    @pytest.mark.parametrize('create_plugin_rules', [
        {'plugin_list': [{"host": random_name(prefix="plugin_rule_"), "plugin_id": randint(1000, 2000),
                          "type": "exclude"}]}], indirect=True)
    @pytest.mark.usefixtures('create_folder', 'create_tenable_io_container')
    def test_nessus_pro_migration_to_tenable_io(self, create_scan, create_folder, create_policy, create_plugin_rules,
                                                create_tenable_io_container):
        """
        NES-12322: [API Automation]: Nessus upgrade assistant (Migration)

        Scenario Tested:
            [x] Verify that Nessus pro user data like empty folder, folder with scan, normal scan, schedule scan,
                audit scan, scan in trash folder, normal policy, credentialed policy, plugin rule
                gets migrated to Tenable.io successfully.
        """
        required_nessus_pro_data = self.create_nessus_data_for_migration(
            create_scan=create_scan, create_folder=create_folder, create_policy=create_policy,
            create_plugin_rules=create_plugin_rules)

        log.info("Created Nessus Pro data for migration :: {}".format(required_nessus_pro_data))
        migration_details = migrate_nessus_to_tenable_io(container_details=create_tenable_io_container)
        self.cat.api.login()

        tenable_api = migration_details['tenable_api']
        scanner_name = migration_details['scanner_name']

        assert validate_data_migrated_to_tenable_io_successfully(
            tenable_api=tenable_api, created_data=required_nessus_pro_data, nessus_type="pro",
            scanner_name=scanner_name), "Nessus Pro data did not migrate to tenable.io successfully."


def migrate_nessus_to_tenable_io(container_details: dict, nessus_api: NessusAPI = NessusAPI()) -> dict:
    """
    Perform Migration of Nessus to Tenable.io
    :param dict container_details: Tenable.io container details
    :param Nessus API nessus_api:Instance of Nessus API
    :return: Tenable API with admin user logged in and linked scanner name
    :rtype: dict
    """
    tenable_api = TenableCloudAPI(url=TenableIOConfig.CAT_TIO_URL)
    tenable_api.login(username=container_details['container'].model.contact,
                      password=container_details['container'].model.password)
    nessus_api.login()
    nessus_username = nessus_api.session.get()['username']
    nessus_api.session.edit(name=nessus_username + '@' + container_details['domain'],
                            email=nessus_username + '@' + container_details['domain'])

    admin_username = "%s@%s" % (nessus_username, container_details['domain'])
    payload = {"username": admin_username, "password": Passwords.STRONG, "permissions": 64, "name": admin_username,
               "email": admin_username, "type": "local"}
    tenable_api.users.create(payload=payload)

    scanner_name = random_name(prefix='migrate_scanner-')
    api_key_resp = tenable_api.session.generate_keys()
    upgrade_payload = {'key': api_key_resp['accessKey'], 'secret': api_key_resp['secretKey'], 'port': '443',
                       'domain': container_details['domain'], 'name': scanner_name, 'host': TenableIOConfig.CAT_TIO_URL}

    log.debug('Starting Migration...')
    nessus_api.migration.start(data=upgrade_payload)
    tenable_api.logout()

    wait(lambda: nessus_api.migration.status()['status'] == 'finished',
         timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=TIME_THIRTY_SECONDS,
         waiting_for='Migration to get finished')
    log.info("Basic migration finished. Now going for extended migration!!")

    # Basic Migration Finished, now performing "Extended Migration" functionality
    nessus_api.migration.end_migration(finish='true')
    wait_for_scanner_to_be_ready(api=nessus_api)
    sleep(TIME_TWO_MINUTES, reason="Extended migration to get started")
    wait_for_scanner_to_be_ready(api=nessus_api)
    tenable_api.login(username=admin_username, password=Passwords.STRONG)
    return {'tenable_api': tenable_api, 'scanner_name': scanner_name}


def validate_data_migrated_to_tenable_io_successfully(tenable_api: TenableCloudAPI, created_data: dict,
                                                      nessus_type: str, scanner_name: str) -> bool:
    """
    This function validates if Nessus data gets migrated to tenable.io successfully or not
    :param TenableCloudAPI tenable_api: Instance of TenableCloudAPI
    :param dict created_data: Created data in Nessus
    :param str nessus_type: Nessus type (manager/pro)
    :param str scanner_name: Name of linked scanner
    :return: True if all required data migrated to Tenable.io else False
    :rtype: bool
    """
    try:
        # Verify that linked scanner is present in tenable.io
        all_scanners = tenable_api.scanners.get_list()['scanners']
        assert scanner_name in [scanner['name'] for scanner in all_scanners]
        linked_scanner_id = [scanner['id'] for scanner in all_scanners if scanner['name'] == scanner_name][0]

        # Verify that all folders migrated to tenable.io
        all_folders = tenable_api.folders.get_list()['folders']
        assert {created_data['blank_folder']['blank_folder_name'], created_data['host_discovery_scan'][
            'folder_name']}.issubset(set([folder['name'] for folder in all_folders])), \
            "Folder with scan and/or folder without scan did not migrate to Tenable.io"

        # Verify that all required scans are present in tenable.io
        all_scans = tenable_api.scans.get_list()['scans']
        normal_scan_name = created_data['normal_scan']['name'] + " - " + scanner_name
        schedule_scan_name = created_data['schedule_scan']['name'] + " - " + scanner_name
        scan_in_trash = created_data['scan_in_trash_folder']['name'] + " - " + scanner_name
        scan_with_audit = created_data['scan_with_audit_file']['name'] + " - " + scanner_name
        scan_in_custom_folder = created_data['host_discovery_scan']['name'] + " - " + scanner_name

        assert {normal_scan_name, scan_in_trash, schedule_scan_name, scan_with_audit, scan_in_custom_folder}.issubset(
            set([scan['name'] for scan in all_scans])), "Scans did not migrate to tenable.io successfully."

        # Verify that scan is present with schedule in tenable.io
        assert [scan for scan in all_scans if scan['name'] == schedule_scan_name and scan['timezone'] and scan[
            'rrules'] == "FREQ=ONETIME" and scan['enabled']], "Schedule scan did not migrate successfully."

        scan_in_trash_info = tenable_api.scans.get_scan_info(scan_id=[scan['id'] for scan in all_scans if scan[
            'name'] == scan_in_trash][0])['info']

        # Verify that scan is present in trash folder
        assert scan_in_trash_info['folder_id'] == [folder['id'] for folder in all_folders if folder[
            'name'] == Nessus.Scan.Folder.TRASH][0], "Migrated scan is not present in trash folder."

        # Verify the offline config audit scan migrated to tenable.io successfully.
        assert tenable_api.scans.get_scan_info(scan_id=[scan['id'] for scan in all_scans if scan[
            'name'] == scan_with_audit][0])['info']['policy'] == Nessus.TemplateNames.OFFLINE_AUDIT, \
            "Offline config audit scan template is incorrect"

        # Verify that scan is present in custom folder (as created in Nessus)
        assert tenable_api.scans.get_scan_info(scan_id=[scan['id'] for scan in all_scans if scan[
            'name'] == scan_in_custom_folder][0])['info']['folder_id'] == [
            folder['id'] for folder in all_folders if folder['name'] == created_data['host_discovery_scan'][
                'folder_name']][0], "Migrated scan is not present in custom folder after migration."

        # Verify that all policies are migrated to tenable.io successfully.
        all_policies = tenable_api.policies.get_list()['policies']
        normal_policy_name = created_data['normal_policy']['normal_policy_name'] + " - " + scanner_name
        policy_with_credential = created_data['policy_scan_with_credential']['name'] + " - " + scanner_name

        assert {normal_policy_name, policy_with_credential}.issubset([policy['name'] for policy in all_policies]), \
            "Policies did not migrate to tenable io successfully."

        # Verify policy credentials in tenable.io
        assert list(tenable_api.policies.details(policy_id=[policy['id'] for policy in all_policies if policy[
            'name'] == policy_with_credential][0])['credentials']['edit'].values()) == list(
            created_data['policy_scan_with_credential']['credential_details']['edit'].values()), \
            "Policy's credentials did not migrate successfully."

        # Verify Plugin rule migrated to tenable.io in recast rules
        assert [rule for rule in tenable_api.recast.get_recast_rules()['rules'] if rule[
            'custom'][0] == created_data['created_plugin_rule']['created_plugin_rule_host']], \
            "plugin rule did not migrate to tenable io"
        log.info("All scans : {}".format([scan['name'] for scan in all_scans]))

        # Verify agent/agent-group/user-group/blackout-window migrated to Tenable.io successfully.
        if nessus_type == "manager":
            agent_config_details = tenable_api.agent_settings.get_config(scanner_id=linked_scanner_id)

            assert created_data['user_group']['user_group_name'] in [group['name'] for group in
                                                                     tenable_api.groups.get_groups()['groups']], \
                "User group did not migrate to tenable.io"

            assert created_data['created_freeze_window']['created_freeze_window_name'] in [
                exclusion['name'] for exclusion in tenable_api.agent_blackout_windows.get_list(
                    scanner_id=linked_scanner_id)['exclusions']], "Blackout window did not migrate to tenable.io"
            try:
                wait(lambda: created_data['real_agent_info']['real_agent_name'] in [
                    agent['name'] for agent in tenable_api.agents.get_agents(scanner_id=linked_scanner_id)['agents']],
                     sleep_seconds=TIME_FIVE_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
                     waiting_for="Nessus Agent to link with Tenable.io")
            except:
                raise AssertionError("Agent did not migrate to Tenable.io")

            assert created_data['agent_group_info']['agent_group_name'] in [
                agent_group['name'] for agent_group in tenable_api.agent_groups.get_list(
                    scanner_id=linked_scanner_id)['groups']], "Agent group did not migrate to tenable.io"

            log.info("Agent config details : {}".format(agent_config_details))
        return True
    except AssertionError:
        return False
