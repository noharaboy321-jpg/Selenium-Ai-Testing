"""
Sensor Proxy related test cases

:copyright: Tenable Network Security, 2019
:date: Nov 11, 2019
:last_modified: Jan 12, 2021
:author: @kpanchal
"""
import subprocess
from http import HTTPStatus

import pytest
import re
from waiting import wait

from catium.lib import const
from catium.lib.const.base_constants import TIME_FIVE_SECONDS, TIME_FIVE_MINUTES, TIME_THIRTY_MINUTES, WAIT_NORMAL, \
    TIME_ONE_HOUR, TIME_FIFTEEN_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_name, generate_request_uuid
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.agents import get_agent_id_from_list
from nessus.helpers.dockernessus.lib.system import FileTools
from nessus.helpers.nessus_agent import is_log_entries
from nessus.helpers.scanner import scanner_token
from nessus.helpers.sensor_proxy.sensor_proxy import get_log_message_from_log_files, unlink_agent_from_master, \
    unlink_nessus_scanner_from_master, unlink_sensor_proxy_from_tenable_io, check_scanner_status, \
    check_agent_status, get_process_id, get_socket_count, reload_sensor_proxy, relink_agent_to_master, \
    link_sensor_proxy_to_tenable_io, modify_json_file_value, take_up_down_network_in_docker_container, \
    delete_file_from_container, link_sensors_to_sensor_proxy, deploy_nessus_scanner, \
    set_fix_parameter_in_nessus_or_agent_container, deploy_real_agent, \
    verify_log_msg_from_backend_logs
from nessus.lib.config import NessusConfig
from nessus.lib.const.constants import API, Nessus, NessusAgentFilePath
from nessus.tests.conftest import link_scanner_to_master, link_agent_to_master, fake_sp_agent, add_remote_scanner_sp
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI
from tenableio.helpers.metadata.scanner import ScannerMetadata
from tenableio.models.scan_model import ScanModel

log = create_logger()


@pytest.mark.sensor_proxy
class TestSensorProxy:
    """ Covers Sensor Proxy Server related test cases. """

    @staticmethod
    def verify_sensors_linking_log_messages(sensor_type: str, master: str, sp_details: dict) -> None:
        """
        Verifies sensors to master linking success logs messages

        :param sensor_type: sensor type scanner or agent
        :param master: master type Sensor Proxy/Tenable.io
        :param sp_details: sensor proxy container details
        :return: None
        """
        log_message = get_log_message_from_log_files(search_text='[sensorlink]', **sp_details,
                                                     log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split()
        log.info('Sidecar log message for {} to {} :: {}'.format(sensor_type, master, log_message))

        link_success_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7],
                                         log_message[8]])

        success_message = API.Settings.SensorProxy.SCANNER_LINK_SUCCESS if sensor_type == API.Settings.SensorProxy. \
            SCANNER else API.Settings.SensorProxy.AGENT_LINK_SUCCESS

        # Verifies success message of Sensors (Nessus scanner/Agent) linking from sidecar.log file
        assert all([log_message[3] == '[sensorlink]', link_success_message == success_message]), \
            '\'{}\' is not getting linked successful with Sensor proxy.'.format(sensor_type)

        access_log_message = get_log_message_from_log_files(
            search_text='/remote/{}'.format(sensor_type), log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
            **sp_details).split(' "')[1].split()
        log.info('access log message for {} to {} :: {}'.format(sensor_type, master, access_log_message))

        # Verifies the sensors job endpoint '/remote/agent' is displayed in log message of access.log file
        assert '/remote/{}'.format(sensor_type) in access_log_message[1], 'Remote agent job endpoint is missing ' \
                                                                          'or mismatched.'

        # Verifies the sensors job response code after linking Sensors (Nessus scanner/Agent) to Sensor Proxy
        assert all([access_log_message[0] == const.HTTPMethods.POST.upper(), int(access_log_message[3]) ==
                    HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

    @staticmethod
    def verify_scan_status_launched_through_sensor_proxy(api: None, scan_id: int) -> None:
        """
        Verifies scan state transitions are functioning after launching through sensor proxy

        :param api: instance of TenableCloudAPI
        :param scan_id: id of launched scan
        :return: None
        """
        if not api:
            api = TenableCloudAPI()
        scan_status_list = []

        def scan_status(s_id):
            status = api.scans.get_status(s_id)
            log.info('Scan status :: {}'.format(status))
            scan_status_list.append(status)

            return status == API.Scan.Status.COMPLETED

        wait(lambda: scan_status(s_id=scan_id), sleep_seconds=WAIT_NORMAL, timeout_seconds=TIME_THIRTY_MINUTES * 3,
             waiting_for='Waiting for scan to be completed')

        required_scan_status = [API.Scan.Status.INITIALIZING, API.Scan.Status.PENDING, API.Scan.Status.RUNNING,
                                API.Scan.Status.COMPLETED]

        assert set(required_scan_status).issubset(set(scan_status_list)), \
            'Scan status are not getting functioning as expected like initializing -> pending -> running -> completed.'

    def test_sensor_proxy_to_tenable_io_linking(self, create_sensor_proxy_tio):
        """
        NES-10477 : Implement automated (but manually executed) tests for Sensor Proxy

        Steps:
        1. Linking to Tenable.io (use qa-develop.cloud.aws.tenablesecurity.com for now)

        Scenario Tested:
        [x] Verify that Sensor Proxy is linked to Tenable.io successfully
        """
        log_message = get_log_message_from_log_files(search_text='Linked successfully', **create_sensor_proxy_tio,
                                                     log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split()

        link_success_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7]])

        # Verifies success message of linking Sensor proxy to Tenable.io from sidecar.log file
        assert all([log_message[3] == '[link]', link_success_message == API.Settings.SensorProxy.
                   SENSOR_PROXY_LINKED]), 'Sensor proxy is not getting linked successful with Tenable.io.'

    def test_nessus_scanner_to_sensor_proxy_linking(self, create_sensor_proxy_tio):
        """
        NES-10477 : Implement automated (but manually executed) tests for Sensor Proxy

        Steps:
        3. Linking and unlinking Nessus scanners through SP

        Scenario Tested:
        [x] Verify that Nessus Scanner is linked and unlinked successfully with Sensor Proxy.
        """
        scanners = link_scanner_to_master(
            docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
            ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])
        log.info('Scanner details :: {}'.format(scanners))

        log_message = get_log_message_from_log_files(search_text='[sensorlink]', **create_sensor_proxy_tio,
                                                     log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split()

        link_success_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7],
                                         log_message[8]])

        # Verifies success message of linking Nessus scanner to Sensor proxy from sidecar.log file
        assert all([log_message[3] == '[sensorlink]', link_success_message == API.Settings.SensorProxy.
                   SCANNER_LINK_SUCCESS]), 'Nessus scanner is not getting linked successful with Sensor proxy.'

        access_log_message = get_log_message_from_log_files(
            search_text=const.HTTPMethods.POST.upper(), log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
            **create_sensor_proxy_tio).split(' "')[1].split()

        # Verifies the remote scanner job endpoint '/remote/scanner' is displayed in log message of access.log file
        assert '/remote/scanner' in access_log_message[1], 'Remote scanner job endpoint is missing or mismatched.'

        # Verifies the scanner job response code after linking Nessus scanner to Sensor Proxy
        assert all([access_log_message[0] == const.HTTPMethods.POST.upper(), int(access_log_message[3]) ==
                    HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

        unlinked_response = unlink_nessus_scanner_from_master(container_name=scanners['name']).split('\n')
        unlinked_response = [response for response in unlinked_response if re.search('unlinked', response)
                             ][0].split('] ')

        # Verifies success message of unlinking Nessus scanner from Sensor proxy from sidecar.log file
        assert all([unlinked_response[1].lstrip('[') == 'scanner',
                    unlinked_response[2] == API.Settings.SensorProxy.UNLINKED_MESSAGE]), \
            'Nessus scanner is not getting unlinked successfully from Sensor proxy.'

        access_log_message = get_log_message_from_log_files(
            search_text=const.HTTPMethods.DELETE.upper(), log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
            **create_sensor_proxy_tio).split(' "')[1].split()

        # Verifies the scanner job response code after unlinking Nessus scanner from Sensor Proxy
        assert all([access_log_message[0] == const.HTTPMethods.DELETE.upper(), int(access_log_message[3]) ==
                    HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

    def test_scan_via_scanner_to_sensor_proxy(self, create_sensor_proxy_tio):
        """
        NES-10477 : Implement automated (but manually executed) tests for Sensor Proxy
        NES-10728 : Automate Sensor Proxy tests: Configuration, Sensor Removal from T.io and Blackout Windows

        Steps:
        3. Linking, using (scans, etc.), and unlinking Nessus scanners through SP

        Scenario Tested:
        [x] Verify that we are able to receive the scanner job logs after creating or launching the scan via Sensor
            Proxy.
        [x] Verify that scanner scan state transitions are functioning in T.io after launching through sensor proxy.
        """
        scanners = {}

        try:
            scanners = link_scanner_to_master(
                docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

            log.info('Scanner details :: {}'.format(scanners))
            scanner_name = scanners['name']

            container_details = create_sensor_proxy_tio['container']
            api = TenableCloudAPI()
            api.login(username=container_details.model.contact, password=container_details.model.password)

            # Wait till Scanner to be visible online
            wait(lambda: check_scanner_status(api=api, scanner_name=scanner_name), timeout_seconds=TIME_FIVE_MINUTES,
                 sleep_seconds=TIME_FIVE_SECONDS, waiting_for='Scanner to be visible online')

            # Create and launch the scan
            scan_model = ScanModel()
            scan_model.text_targets = Nessus.Scan.Target.LOCALHOST
            scan_model.name = '{} with proxy'.format(Nessus.TemplateNames.ADVANCED)
            scan_model.scanner_id = ScannerMetadata.get_id(api.scanners.get_list(), scanner_name)
            scan_id = api.scans.create(scan_model)['scan']['id']

            # Verifies that scan is successfully created with linked scanner
            assert api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % \
                                                          (HTTPStatus.OK, api.http_status_code)

            api.scans.launch(scan_id)

            # Verifies that scan is launched successfully
            assert api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % \
                                                          (HTTPStatus.OK, api.http_status_code)

            self.verify_scan_status_launched_through_sensor_proxy(api=api, scan_id=scan_id)

            access_log_message = get_log_message_from_log_files(
                search_text=const.HTTPMethods.PUT.upper(), log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                **create_sensor_proxy_tio).split(' "')[1].split()

            # Verifies the scanner job response code after linking Nessus scanner to Sensor Proxy
            assert all([access_log_message[0] == const.HTTPMethods.PUT.upper(), int(access_log_message[3]) ==
                        HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

            # Verifies the remote scanner job endpoint '/remote/scanner' is displayed in log message of access.log file
            assert '/remote/scanner' in access_log_message[1], 'Remote scanner job endpoint is missing or mismatched ' \
                                                               'in logs from access.log file.'

            access_log_message = get_log_message_from_log_files(
                search_text='/remote/scanner/jobs', log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                **create_sensor_proxy_tio).split(' "')[1].split()

            # Verifies the scanner job response code after linking Nessus scanner to Sensor Proxy
            assert all([access_log_message[0] == const.HTTPMethods.GET.upper(), int(access_log_message[3]) ==
                        HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

            # Verifies the remote scanner job endpoint '/remote/scanner/jobs' is displayed in log message after
            # launching the scan
            assert '/remote/scanner/jobs' in access_log_message[1], \
                'Remote scanner job endpoint is missing or mismatched in logs from access.log file.'
        finally:
            unlink_nessus_scanner_from_master(container_name=scanners['name'])

    def test_agent_to_sensor_proxy_linking(self, create_sensor_proxy_tio):
        """
        NES-10477 : Implement automated (but manually executed) tests for Sensor Proxy

        Steps:
        4. Linking and unlinking Agents through SP

        Scenario Tested:
        [x] Verify that Agent is linked and unlinked successfully with Sensor Proxy.
        """
        agents = link_agent_to_master(
            docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
            ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])
        log.info('Agent details :: {}'.format(agents))

        log_message = get_log_message_from_log_files(search_text='[sensorlink]', **create_sensor_proxy_tio,
                                                     log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split()

        link_success_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7],
                                         log_message[8]])

        # Verifies success message of linking Agent to Sensor proxy from sidecar.log file
        assert all([log_message[3] == '[sensorlink]', link_success_message == API.Settings.SensorProxy.
                   AGENT_LINK_SUCCESS]), 'Nessus scanner is not getting linked successful with Sensor proxy.'

        access_log_message = get_log_message_from_log_files(
            search_text=const.HTTPMethods.POST.upper(), log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
            **create_sensor_proxy_tio).split(' "')[1].split()

        # Verifies the remote agent job endpoint '/remote/agent' is displayed in log message of access.log file
        assert '/remote/agent' in access_log_message[1], 'Remote agent job endpoint is missing or mismatched.'

        # Verifies the agent job response code after linking Agent to Sensor Proxy
        assert all([access_log_message[0] == const.HTTPMethods.POST.upper(), int(access_log_message[3]) ==
                    HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

        unlinked_response = unlink_agent_from_master(container_name=agents['name']).split('] ')

        # Verifies success message of unlinking Agent from Sensor proxy from sidecar.log file
        assert all([unlinked_response[1].lstrip('[') == 'agent',
                    unlinked_response[2].rstrip('\n') == API.Settings.SensorProxy.UNLINKED_MESSAGE]), \
            'Agent is not getting unlinked successfully from Sensor proxy.'

        access_log_message = get_log_message_from_log_files(
            search_text=const.HTTPMethods.DELETE.upper(), log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
            **create_sensor_proxy_tio).split(' "')[1].split()

        # Verifies the agent job response code after unlinking Agent from Sensor Proxy
        assert all([access_log_message[0] == const.HTTPMethods.DELETE.upper(), int(access_log_message[3]) ==
                    HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

    def test_scan_via_agent_to_sensor_proxy(self, create_sensor_proxy_tio):
        """
        NES-10477 : Implement automated (but manually executed) tests for Sensor Proxy
        NES-10728 : Automate Sensor Proxy tests: Configuration, Sensor Removal from T.io and Blackout Windows

        Steps:
        4. Linking, using (scans, etc.), and unlinking Agent through SP

        Scenario Tested:
        [x] Verify that we are able to receive the agent job logs after creating or launching the scan via Sensor
            Proxy.
        [x] Verify that agent scan state transitions are functioning in T.io after launching through sensor proxy.
        """
        agents = {}

        try:
            agents = link_agent_to_master(
                docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

            log.info('Agent details :: {}'.format(agents))
            agent_name = agents['name']

            container_details = create_sensor_proxy_tio['container']
            api = TenableCloudAPI()
            api.login(username=container_details.model.contact, password=container_details.model.password)

            scanner_id = api.scanners.get_local_scanner_id()
            linked_agent_id, linked_agent_status = get_agent_id_from_list(api=api, agent_name=agent_name)
            log.info("Linked agent id :: {}".format(linked_agent_id))

            # Wait till agent to be visible online
            wait(lambda: check_agent_status(api=api, agent_name=agent_name, scanner_id=scanner_id),
                 timeout_seconds=TIME_THIRTY_MINUTES, sleep_seconds=TIME_FIVE_SECONDS, waiting_for='agent to be online')

            group_details = api.agent_groups.create(scanner_id=scanner_id, name=random_name(prefix='agent-group_'))

            log.info('Agent group details :: :: {}'.format(group_details))
            api.agent_groups.add_agent(scanner_id=scanner_id, group_id=group_details['id'], agent_id=linked_agent_id)

            added_agent = api.agent_groups.list_agents(scanner_id=scanner_id, group_id=group_details['id'])
            log.info('Agents from agent group :: :: {}'.format(added_agent))

            # Create and launch the scan
            scan_model = ScanModel()
            scan_model.name = '{} with proxy'.format(Nessus.TemplateNames.ADVANCED_AGENT)
            scan_model.default_template = Nessus.TemplateNames.ADVANCED_AGENT
            scan_model.agent_group_id = [group_details['uuid']]
            scan_id = api.scans.create(scan_model)['scan']['id']

            # Verifies that scan is successfully created with linked agent
            assert api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % \
                                                          (HTTPStatus.OK, api.http_status_code)

            api.scans.launch(scan_id)

            # Verifies that scan is launched successfully
            assert api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % \
                                                          (HTTPStatus.OK, api.http_status_code)

            self.verify_scan_status_launched_through_sensor_proxy(api=api, scan_id=scan_id)

            access_log_message = get_log_message_from_log_files(
                search_text=const.HTTPMethods.PUT.upper(), log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                **create_sensor_proxy_tio).split(' "')[1].split()

            # Verifies the agent job response code after linking Agent to Sensor Proxy
            assert all([access_log_message[0] == const.HTTPMethods.PUT.upper(), int(access_log_message[3]) ==
                        HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

            # Verifies the remote agent job endpoint '/remote/agent' is displayed in log message of access.log file
            assert '/remote/agent' in access_log_message[1], \
                'Remote agent job endpoint is missing or mismatched in logs from access.log file.'

            wait(lambda: get_log_message_from_log_files(
                search_text='/remote/agent/jobs', log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                **create_sensor_proxy_tio), timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=TIME_FIVE_SECONDS,
                 waiting_for='scanner job logs')

            access_log_message = get_log_message_from_log_files(
                search_text='/remote/agent/jobs', log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                **create_sensor_proxy_tio).split(' "')[1].split()

            # Verifies the scanner job response code after linking Nessus scanner to Sensor Proxy
            assert all([access_log_message[0] == const.HTTPMethods.GET.upper(), int(access_log_message[3]) ==
                        HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

            # Verifies the remote agent job endpoint '/remote/agent/jobs' is displayed in log message after
            # launching the scan
            assert '/remote/agent/jobs' in access_log_message[1], \
                'Remote agent job endpoint is missing or mismatched in logs from access.log file.'
        finally:
            unlink_agent_from_master(container_name=agents['name'])

    def test_sockets_not_left_laying_around_process(self, create_sensor_proxy_tio):
        """
        NES-10639 : Additional automated Sensor Proxy tests

        Steps:
        1. Link an Agent
        2. Restart SP so that the bulk route timer becomes 30 seconds (this will be noted in the logs)
        3. Have the Agent (or fake agent) request jobs a few times
        4. Wait enough time for a few bulk jobs/bulk blackout window requests to go through (in the logs)
        5. Check how many sockets are listed in the fd directory.

        Scenario Tested:
        [x] Verify that Sockets are not left laying around in /proc/<process ID of sidecar>/fd
        """
        agents = {}
        sp_container_name = create_sensor_proxy_tio['proxy_container']['Name'].replace('/', '')

        before_process_id = get_process_id(pid_file=API.Settings.SensorProxy.SIDECAR_PID_FILE,
                                           container_name=sp_container_name)
        log.info('Sidecar process id before reload Sensor Proxy :: :: {}'.format(before_process_id))

        before_socket_count = get_socket_count(pid=before_process_id, container_name=sp_container_name)
        log.info('Socket count before linking agent :: :: {}'.format(before_socket_count))

        try:
            agents = link_agent_to_master(
                docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

            log_message = get_log_message_from_log_files(search_text='[sensorlink]', **create_sensor_proxy_tio,
                                                         log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split()

            link_success_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7],
                                             log_message[8]])

            # Verifies success message of linking Agent to Sensor proxy from sidecar.log file
            assert all([log_message[3] == '[sensorlink]', link_success_message == API.Settings.SensorProxy.
                       AGENT_LINK_SUCCESS]), 'Nessus scanner is not getting linked successful with Sensor proxy.'

            access_log_message = get_log_message_from_log_files(
                search_text=const.HTTPMethods.POST.upper(), log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                **create_sensor_proxy_tio).split(' "')[1].split()

            # Verifies the remote agent job endpoint '/remote/agent' is displayed in log message of access.log file
            assert '/remote/agent' in access_log_message[1], 'Remote agent job endpoint is missing or mismatched.'

            # Verifies the agent job response code after linking Agent to Sensor Proxy
            assert all([access_log_message[0] == const.HTTPMethods.POST.upper(), int(access_log_message[3]) ==
                        HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

            # Reload/Restart Sensor Proxy
            reload_sensor_proxy(container_name=sp_container_name, process_id=before_process_id)

            after_process_id = get_process_id(pid_file=API.Settings.SensorProxy.SIDECAR_PID_FILE,
                                              container_name=sp_container_name)
            log.info('Sidecar process id after reload Sensor Proxy :: :: {}'.format(after_process_id))

            after_socket_count = get_socket_count(pid=after_process_id, container_name=sp_container_name)
            log.info('Socket count after linking agent :: :: {}'.format(after_socket_count))

            # Verifies that the process id should not be getting same after reloading Sensor proxy
            assert before_process_id != after_process_id, \
                'Sidecar process id from sidecar.pid file is getting same after reloading the Sensor Proxy.'

            # Verifies that the socket count should be getting same after reloading Sensor proxy
            assert before_socket_count == after_socket_count, \
                'Socket count is not getting same after reloading Sensor Proxy.'
        finally:
            unlink_agent_from_master(container_name=agents['name'])

    @pytest.mark.parametrize('sensor_type', [API.Settings.SensorProxy.SCANNER, API.Settings.SensorProxy.AGENT])
    def test_plugin_update_logs_via_sensor_proxy(self, create_sensor_proxy_tio, sensor_type):
        """
        NES-10477 : Implement automated (but manually executed) tests for Sensor Proxy

        Steps:
        5. Receiving software and plugin updates via SP.

        Scenario Tested:
        [x] Verify that we are able to Receive plugins updates via Sensor Proxy.
        """
        scanners = {}
        agents = {}

        try:
            container_details = create_sensor_proxy_tio['container']
            api = TenableCloudAPI()
            api.login(username=container_details.model.contact, password=container_details.model.password)

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                scanners = link_scanner_to_master(
                    docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                    ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

                log.info('Scanner details :: {}'.format(scanners))
            else:
                agents = link_agent_to_master(
                    docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                    ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

                log.info('Agent details :: {}'.format(agents))

            log_message = get_log_message_from_log_files(search_text='[sensorlink]', **create_sensor_proxy_tio,
                                                         log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split()

            link_success_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7],
                                             log_message[8]])

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                # Verifies success message of linking Nessus scanner to Sensor proxy from sidecar.log file
                assert all([log_message[3] == '[sensorlink]', link_success_message == API.Settings.SensorProxy.
                           SCANNER_LINK_SUCCESS]), 'Nessus scanner is not getting linked successful with Sensor proxy.'

                # Wait till Scanner to be visible online
                wait(lambda: check_scanner_status(api=api, scanner_name=scanners['name']),
                     timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=TIME_FIVE_SECONDS,
                     waiting_for='Scanner to be visible online')
            else:
                # Verifies success message of linking Agent to Sensor proxy from sidecar.log file
                assert all([log_message[3] == '[sensorlink]', link_success_message == API.Settings.SensorProxy.
                           AGENT_LINK_SUCCESS]), 'Agent is not getting linked successful with Sensor proxy.'

                scanner_id = api.scanners.get_local_scanner_id()

                # Wait till agent to be visible online
                wait(lambda: check_agent_status(api=api, agent_name=agents['name'], scanner_id=scanner_id),
                     timeout_seconds=TIME_ONE_HOUR, sleep_seconds=TIME_FIVE_SECONDS, waiting_for='agent to be online')

            access_log_message = get_log_message_from_log_files(
                search_text='/remote/properties', log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                **create_sensor_proxy_tio).split(' "')[1].split()

            # Verifies the sensors job response code after linking Sensors (Nessus scanner/Agent) to Sensor Proxy
            assert all([access_log_message[0] == const.HTTPMethods.GET.upper(), int(access_log_message[3]) ==
                        HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])

            endpoint_details = access_log_message[1].split('?')

            # Verifies the sensors properties endpoint '/remote/properties' is displayed in log message of access.log
            assert '/remote/properties' == endpoint_details[0], 'Remote properties endpoint is missing or mismatched.'
        finally:
            if sensor_type == API.Settings.SensorProxy.SCANNER:
                unlink_nessus_scanner_from_master(container_name=scanners['name'])
            else:
                unlink_agent_from_master(container_name=agents['name'])

    @pytest.mark.parametrize('request_type', [API.Settings.SensorProxy.PLUGINS, API.Settings.SensorProxy.CORE_UPDATE])
    def test_caching_for_multiple_plugins_and_core_update_request(self, create_sensor_proxy_tio, request_type):
        """
        NES-10639 : Additional automated Sensor Proxy tests

        Steps:
        1. Run two plugin or core update downloads at the same time (and download the full response body)
        2. Make sure that one of them missed the cache, and one of them hit the cache.

        Scenario Tested:
        [x] Verify that one of request missed the cache and another one of them hit the cache on multiple request for
            plugins and core updates via Sensor Proxy.
        """
        response = None
        api = None

        try:
            agent = fake_sp_agent(host=create_sensor_proxy_tio['proxy_container']['URL'],
                                  key=create_sensor_proxy_tio['linking_key'])

            # Request plugins with this Agent. Then, request them again and check for the cached header.
            api = NessusAPI(url=create_sensor_proxy_tio['proxy_container']['URL'])

            # Add MS-Agent header to session headers
            api.add_header({'MS-Agent': "token=%s" % agent['token']})

            for _ in range(2):
                if request_type == API.Settings.SensorProxy.PLUGINS:
                    # GET the response from /remote/agent/plugins endpoint
                    log.info('Downloading plugins.')
                    response = api.remote.get_remote_agent_plugins(
                        params={'platform': API.Settings.SensorProxy.LINUX_PLATFORM,
                                'distro': API.Settings.SensorProxy.LINUX_DISTRO}, stream=True)
                else:
                    # GET the response and headers from /remote/agent/core endpoint
                    log.info('Downloading the core update.')
                    response = api.remote.get_remote_agent_core(distro=API.Settings.SensorProxy.LINUX_DISTRO,
                                                                platform=API.Settings.SensorProxy.LINUX_PLATFORM,
                                                                stream=True)

                # Download the plugins.
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:  # filter out keep-alive new chunks
                        log.debug("Got a chunk!")

                # Verifies response code for plugins/core updates are getting successfully.
                assert api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % \
                                                              (HTTPStatus.OK, api.http_status_code)

            log.info('Response header for \'{}\' :: :: {}'.format(request_type, api._response_headers))

            # Verify the 'X-Nginx-Cache-Status' header is getting 'HIT' in response Headers
            assert 'HIT' == response.headers['X-Nginx-Cache-Status'], 'Second \'{}\' was not a cache HIT.'.format(
                request_type)

            if request_type == API.Settings.SensorProxy.PLUGINS:
                file_name = 'agent.db.gz'
            else:
                file_name = 'nessus-agent-es7-x86-64.tar.gz'

            # Verify the 'Content-Disposition' header is not getting null in response Headers
            assert response.headers['Content-Disposition'] == 'attachment; filename="{}"'.format(file_name), \
                '\'{}\' file is not downloaded successfully.'.format(request_type)

            if request_type == API.Settings.SensorProxy.PLUGINS:
                search_endpoint = '/remote/agent/plugins'
                endpoint_detail = 'platform={}&distro={}'.format(API.Settings.SensorProxy.LINUX_PLATFORM,
                                                                 API.Settings.SensorProxy.LINUX_DISTRO)
            else:
                search_endpoint = '/remote/agent/core'
                endpoint_detail = 'distro={}'.format(API.Settings.SensorProxy.LINUX_DISTRO)

            access_log_message = get_log_message_from_log_files(
                search_text=search_endpoint, log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE, full_logs=True,
                **create_sensor_proxy_tio)

            cache_type = [API.Settings.SensorProxy.HIT, API.Settings.SensorProxy.MISS]

            for i in range(2):
                log_details = access_log_message[i].split('] ')[2].split()
                log_tags = access_log_message[i].split('] ')[1].split()

                # Verifies the response code for remote agent plugins/core update via Sensor Proxy
                assert all([log_details[0].lstrip('"') == const.HTTPMethods.GET.upper(), int(log_details[3])
                            == HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(log_details[3])

                # Verifies the endpoints for remote agent plugins/core update via Sensor Proxy
                assert '{}?{}'.format(search_endpoint, endpoint_detail) in log_details[1], \
                    'Remote agent plugins/core update endpoint is missing or mismatched in logs from access.log file.'

                # Verifies the cache type for remote agent plugins/core update via Sensor Proxy
                assert log_tags[0].split(':')[1] == cache_type[i], \
                    'Agent plugins/core update was not a cache \'{}\'.'.format(cache_type[i])
        finally:
            if api:
                api.remote.delete_remote_agent()
                api.remove_header(key='MS-Agent')

    def test_sensor_removal_from_tenable_io(self, create_sensor_proxy_tio):
        """
        NES-10728: Automate Sensor Proxy tests: Configuration, Sensor Removal from T.io and Blackout Windows

        Steps:
        - Unlink an Agent from Tenable.io, it should begin to receive 401 from SP

        Scenario Tested:
        [x] Verify that Sensor Proxy should begin to receive 401 response code after removing agent from Tenable.io.
        """
        agent_name = None

        try:
            # Link agent to Tenable.io
            agent = link_agent_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                         master_host=NessusConfig.CAT_TIO_URL, master_port=443,
                                         linking_key=create_sensor_proxy_tio['linking_key'])
            log.info('Agent linked with T.io :: {}'.format(agent))

            agent_name = agent['name']

            # Login to Tenable.io and delete linked agent using API
            container_details = create_sensor_proxy_tio['container']
            api = TenableCloudAPI()
            api.login(username=container_details.model.contact, password=container_details.model.password)

            scanner_id = api.scanners.get_local_scanner_id()
            linked_agent_id, linked_agent_status = get_agent_id_from_list(api=api, agent_name=agent_name)
            log.info("Linked agent id :: {} and status :: {}".format(linked_agent_id, linked_agent_status))

            # Wait till agent to be visible online
            wait(lambda: check_agent_status(api=api, agent_name=agent_name, scanner_id=scanner_id),
                 timeout_seconds=TIME_THIRTY_MINUTES, sleep_seconds=TIME_FIVE_SECONDS, waiting_for='agent to be online')

            # Relink agent to Sensor Proxy
            relink_output = relink_agent_to_master(agent_name=agent_name, port=443,
                                                   host=create_sensor_proxy_tio['proxy_container']['URL'])
            log.info('Relink agent to SP output :: {}'.format(relink_output))

            # self.restart_container(container_name=agent_name)

            api.agents.delete(scanner_id=scanner_id, agent_id=linked_agent_id)

            # Verifies the api response code after deleting agent from T.io
            assert api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            def expected_response_code():
                log_message = get_log_message_from_log_files(search_text=const.HTTPMethods.GET.upper(),
                                                             log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                                                             **create_sensor_proxy_tio).split(' "')[1].split()

                return int(log_message[3]) == HTTPStatus.UNAUTHORIZED

            wait(expected_response_code, sleep_seconds=TIME_FIVE_SECONDS, timeout_seconds=TIME_FIVE_MINUTES,
                 waiting_for='Waiting for 401 response code from Sensor proxy after deleting agent in T.io')

            access_log_message = get_log_message_from_log_files(search_text=const.HTTPMethods.GET.upper(),
                                                                log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                                                                **create_sensor_proxy_tio).split(' "')[1].split()

            # Verifies the Agent endpoint is displayed in log message of access.log file
            assert '/remote/agent' in access_log_message[1], 'Agent linking endpoint is missing or mismatched.'

            # Verifies the Agent response code from Sensor Proxy after deleting Agent from T.io
            assert all([access_log_message[0] == const.HTTPMethods.GET.upper(), int(access_log_message[3]) ==
                        HTTPStatus.UNAUTHORIZED]), 'Expected 401, got {} instead.'.format(access_log_message[3])
        finally:
            unlink_agent_from_master(container_name=agent_name)

    def test_caching_for_differential_plugins(self, create_sensor_proxy_tio):
        """
        NES-10639 : Additional automated Sensor Proxy tests

        Scenario Tested:
        [x] Verify that differential plugins are cached via Sensor Proxy.
        """
        api = None
        current_feed_id = '201912112300'
        target_feed_id = '201912130120'
        plugin_format = 'db.gz'

        try:
            agent = fake_sp_agent(host=create_sensor_proxy_tio['proxy_container']['URL'],
                                  key=create_sensor_proxy_tio['linking_key'])
            agent_token = agent['token']

            api = NessusAPI(url=create_sensor_proxy_tio['proxy_container']['URL'])
            api.add_header({'MS-Agent': "token=%s" % agent_token})

            platform_distro = '-'.join([API.Settings.SensorProxy.WIN_PLATFORM, API.Settings.SensorProxy.WIN_DISTRO])

            api.remote.get_differential_updates(platform_distro=platform_distro, target_feed_id=target_feed_id,
                                                current_feed_id=current_feed_id, formats=plugin_format,
                                                remote_agent_token=agent_token, stream=True)

            # Verifies response code for differential plugins updates are getting successfully.
            assert api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % \
                                                          (HTTPStatus.OK, api.http_status_code)

            access_log_message = get_log_message_from_log_files(
                search_text='/remote/agent/platforms/', log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                **create_sensor_proxy_tio).split('] ')

            log_details = access_log_message[2].split()
            log_tags = access_log_message[1].split()

            # Verifies the response code for remote agent differential plugins update via Sensor Proxy
            assert all([log_details[0].lstrip('"') == const.HTTPMethods.GET.upper(), int(log_details[3])
                        == HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(log_details[3])

            endpoint_url = '/remote/agent/platforms/{}/plugins/{}/diff/{}/formats/{}'.format(
                platform_distro, target_feed_id, current_feed_id, plugin_format)

            # Verifies the endpoints for remote agent differential plugins update via Sensor Proxy
            assert endpoint_url == log_details[1], 'Remote agent plugins/core update endpoint is missing or ' \
                                                   'mismatched in logs from access.log file.'

            # Verifies the cache type for remote agent differential plugins update via Sensor Proxy
            assert log_tags[0].split(':')[1] == API.Settings.SensorProxy.MISS, \
                'Agent plugins/core update was not a cache \'{}\'.'.format(API.Settings.SensorProxy.MISS)
        finally:
            if api:
                api.remote.delete_remote_agent()
                api.remove_header(key='MS-Agent')

    @pytest.mark.parametrize('request_type', [API.Settings.SensorProxy.PLUGINS, API.Settings.SensorProxy.UPDATE,
                                              API.Settings.SensorProxy.CORE_UPDATE])
    def test_caching_for_plugins_and_core_update_request_for_scanner(self, create_sensor_proxy_tio, request_type):
        """
        NQA-10639 : Additional automated Sensor Proxy tests

        Steps:
        1. Run two plugin or core update downloads at the same time (and download the full response body)
        2. Make sure that one of them missed the cache, and one of them hit the cache.

        Scenario Tested:
        [x] Verify that one of request missed the cache and another one of them hit the cache on multiple request for
            plugins and core updates via Sensor Proxy.
        """
        response = None

        scanner = add_remote_scanner_sp(host=create_sensor_proxy_tio['proxy_container']['URL'],
                                        key=create_sensor_proxy_tio['linking_key'])
        remote_scanner_token = scanner['token']

        api = NessusAPI(url=create_sensor_proxy_tio['proxy_container']['URL'])

        for _ in range(2):
            if request_type in [API.Settings.SensorProxy.PLUGINS, API.Settings.SensorProxy.CORE_UPDATE]:
                if request_type == API.Settings.SensorProxy.PLUGINS:
                    # GET the response from /remote/scanner/plugins endpoint
                    log.info('Downloading scanner plugins.')
                    response = api.remote.get_remote_scanner_plugins(remote_scanner_token=remote_scanner_token,
                                                                     stream=True)
                else:
                    # GET the response and headers from /remote/scanner/core endpoint
                    log.info('Downloading the scanner core update.')
                    with scanner_token(api, remote_scanner_token):
                        response = api.remote.get_remote_scanner_core(distro=API.Settings.SensorProxy.LINUX_DISTRO,
                                                                      stream=True)

                # Download the plugins.
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:  # filter out keep-alive new chunks
                        log.debug("Got a chunk!")
            else:
                # GET the response and headers from /remote/scanner/update endpoint
                log.info('Downloading the scanner update.')
                with scanner_token(api, remote_scanner_token):
                    response = api.remote.get_remote_scanner_update(distro=API.Settings.SensorProxy.LINUX_DISTRO,
                                                                    stream=True)

            # Verifies response code for plugins/core updates are getting successfully.
            assert api.http_status_code == HTTPStatus.OK, 'Expected HTTP code %s, got %s instead.' % \
                                                          (HTTPStatus.OK, api.http_status_code)

        log.info('Response header for \'{}\' :: :: {}'.format(request_type, api._response_headers))

        # Verify the 'X-Nginx-Cache-Status' header is getting 'HIT' in response Headers
        assert 'HIT' == response.headers['X-Nginx-Cache-Status'], 'Second \'{}\' was not a cache HIT.'.format(
            request_type)

        if request_type in [API.Settings.SensorProxy.PLUGINS, API.Settings.SensorProxy.CORE_UPDATE]:
            if request_type == API.Settings.SensorProxy.PLUGINS:
                file_name = 'plugins.tar.gz'
            else:
                file_name = 'nessus-es7-x86-64.tar.gz'

            # Verify the 'Content-Disposition' header is not getting null in response Headers
            assert response.headers['Content-Disposition'] == 'attachment; filename="{}"'.format(file_name), \
                '\'{}\' file is not downloaded successfully.'.format(request_type)

        if request_type in [API.Settings.SensorProxy.UPDATE, API.Settings.SensorProxy.CORE_UPDATE]:
            if request_type == API.Settings.SensorProxy.UPDATE:
                search_endpoint = '/remote/scanner/updates'
            else:
                search_endpoint = '/remote/scanner/core'
            endpoint_detail = '{}?distro={}'.format(search_endpoint, API.Settings.SensorProxy.LINUX_DISTRO)
        else:
            search_endpoint = '/remote/scanner/plugins'
            endpoint_detail = search_endpoint

        access_log_message = get_log_message_from_log_files(search_text=search_endpoint, **create_sensor_proxy_tio,
                                                            log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                                                            full_logs=True)

        log_details = access_log_message[0].split('] ')[2].split()
        log_tags = access_log_message[0].split('] ')[1].split()

        # Verifies the response code for remote scanner plugins/core update via Sensor Proxy
        assert all([log_details[0].lstrip('"') == const.HTTPMethods.GET.upper(), int(log_details[3])
                    == HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(log_details[3])

        # Verifies the endpoints for remote scanner plugins/core update via Sensor Proxy
        assert endpoint_detail == log_details[1], 'Remote scanner plugins/core update endpoint is missing or ' \
                                                  'mismatched in logs from access.log file.'

        # Verifies the cache type for remote scanner plugins/core update via Sensor Proxy
        assert log_tags[0].split(':')[1] == API.Settings.SensorProxy.HIT, \
            'Remote scanner plugins/core update was not a cache \'{}\'.'.format(API.Settings.SensorProxy.HIT)

    @pytest.mark.parametrize('master', [API.Settings.SensorProxy.SENSOR_PROXY, API.Settings.SensorProxy.TENABLE_IO])
    def test_agent_to_sp_and_tenable_io_relinking(self, create_sensor_proxy_tio, master):
        """
        NES-10659: Automate Sensor proxy re-linking tests

        Steps:
        - Relinking Agents to SP (using --relink)
        - Relinking Agents to Tenable.io using --relink

        Scenario Tested:
        [x] Verify that Agent is relinked successfully to Sensor Proxy.
        [x] Verify that Agent is relinked successfully to Tenable.io.
        """
        agents = {}
        master_host = create_sensor_proxy_tio['proxy_container']['URL']
        master_port = 443

        try:
            agents = link_agent_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                          master_host=master_host, master_port=master_port,
                                          linking_key=create_sensor_proxy_tio['linking_key'])
            log.info('Agent details :: {}'.format(agents))

            if master == API.Settings.SensorProxy.TENABLE_IO:
                master_host = API.Settings.SensorProxy.TIO_SITE

            relink_output = relink_agent_to_master(agent_name=agents['name'], host=master_host,
                                                   port=master_port).split('] ')
            log.info('Relink agent to T.io output :: {}'.format(relink_output))

            # Verifies success message of relinking agent to Sensor proxy from CLI
            assert all([relink_output[1].lstrip('[') == 'agent', relink_output[2].rstrip('\n') ==
                        'Successfully Relinked to {}:{}'.format(master_host, master_port)]), \
                'Success log message is missing while relinking agent to Sensor Proxy.'

            log_message = get_log_message_from_log_files(search_text='sensorrelink', **create_sensor_proxy_tio,
                                                         log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split()

            relink_success_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7]])

            # Verifies success message of relinking Agent to Sensor proxy from sidecar.log file
            assert all([log_message[3] == '[sensorrelink]', relink_success_message == API.Settings.SensorProxy.
                       SENSOR_PROXY_RELINKED]), 'Agent is not getting relinked successful with Sensor proxy.'

            access_log_message = get_log_message_from_log_files(
                search_text='/relink', log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                **create_sensor_proxy_tio).split(' "')[1].split()

            # Verifies the remote agent job endpoint '/remote/agent' is displayed in log message of access.log file
            assert '/remote/agent/relink' in access_log_message[1], 'Remote agent job endpoint is missing or ' \
                                                                    'mismatched.'

            # Verifies the agent job response code after linking Agent to Sensor Proxy
            assert all([access_log_message[0] == const.HTTPMethods.POST.upper(), int(access_log_message[3]) ==
                        HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(access_log_message[3])
        finally:
            unlink_agent_from_master(container_name=agents['name'])

    @pytest.mark.parametrize('master', [API.Settings.SensorProxy.TENABLE_IO, API.Settings.SensorProxy.SENSOR_PROXY])
    @pytest.mark.parametrize('sensor_type', [API.Settings.SensorProxy.SCANNER, API.Settings.SensorProxy.AGENT])
    def test_linking_of_sensors_to_sensor_proxy_directly(self, create_sensor_proxy_tio, master, sensor_type):
        """
        NES-10659: Automate Sensor proxy re-linking tests

        Steps:
        - Unlink from Tenable.io and link to SP (Scanner, Agent)
            - Link scanner/Agent to Tenable.io first
            - Unlink from Tenable.io
            - Link directly to SP

        - Unlinking/linking Scanners from SP to Tenable.io:
            - Link scanner/Agent to SP first
            - Unlink from SP
            - Link directly to Tenable.io

        Scenario Tested:
        [x] Verify that Agent is relinked successfully to Sensor Proxy.
        """
        scanners = {}
        agents = {}
        master_hosts = [API.Settings.SensorProxy.TIO_SITE, create_sensor_proxy_tio['proxy_container']['URL']]
        master_port = 443

        try:
            if master == API.Settings.SensorProxy.SENSOR_PROXY:
                master_hosts.reverse()

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                scanners = link_scanner_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                                  master_host=master_hosts[0], master_port=master_port,
                                                  linking_key=create_sensor_proxy_tio['linking_key'])
            else:
                agents = link_agent_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                              master_host=master_hosts[0], master_port=master_port,
                                              linking_key=create_sensor_proxy_tio['linking_key'])

            if master == API.Settings.SensorProxy.SENSOR_PROXY:
                self.verify_sensors_linking_log_messages(sensor_type=sensor_type, master=master,
                                                         sp_details=create_sensor_proxy_tio)

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                unlink_nessus_scanner_from_master(container_name=scanners['name'])
            else:
                unlink_agent_from_master(container_name=agents['name'])

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                scanners = link_scanner_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                                  master_host=master_hosts[1], master_port=master_port,
                                                  linking_key=create_sensor_proxy_tio['linking_key'])
            else:
                agents = link_agent_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                              master_host=master_hosts[1], master_port=master_port,
                                              linking_key=create_sensor_proxy_tio['linking_key'])

            if master == API.Settings.SensorProxy.TENABLE_IO:
                self.verify_sensors_linking_log_messages(sensor_type=sensor_type, master=master,
                                                         sp_details=create_sensor_proxy_tio)
        finally:
            if sensor_type == API.Settings.SensorProxy.SCANNER:
                unlink_nessus_scanner_from_master(container_name=scanners['name'])
            else:
                unlink_agent_from_master(container_name=agents['name'])

    def test_sensor_proxy_to_tenable_io_relinking(self, create_sensor_proxy_tio):
        """
        NES-10705: Automate Sensors to Sensor Proxy linking tests with invalid linking key

        Steps:
        - Linking SP to Tenable.io without unlinking from Tenable.io first (a 409 is the expectation)

        Scenario Tested:
        [x] Verify the error (409 Conflict) log message while linking Sensor proxy to Tenable.io without unlinking from
            Tenable.io first.
        """
        relink_output = link_sensor_proxy_to_tenable_io(**create_sensor_proxy_tio).split('] ')
        log.info('Relink SP to T.io response :: {}'.format(relink_output))

        relink_error_message = API.Settings.SensorProxy.SP_TIO_LINKING_ERROR + ' (409 Conflict)'

        # Verifies error message of linking Sensor proxy to T.io
        assert all([relink_output[0].lstrip('[') == 'error', relink_output[1].lstrip('[') == 'link',
                    relink_output[2].rstrip('\n') == relink_error_message]), \
            'Getting incorrect error message while relinking Sensor Proxy to Tenable.io. Expected error log is :: ' \
            '{}'.format(relink_error_message)

        log_message = get_log_message_from_log_files(search_text='Unable to link', **create_sensor_proxy_tio,
                                                     log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split('] ')

        # Verifies error message of linking Nessus scanner to Sensor proxy from sidecar.log file
        assert all([log_message[0].split()[2].lstrip('[') == 'error', log_message[1].lstrip('[') == 'link',
                    log_message[2] == relink_error_message]), \
            'Getting incorrect error log while relinking Sensor Proxy to Tenable.io. Expected error log is :: ' \
            '{}'.format(relink_error_message)

    @pytest.mark.parametrize('sensor_type', [API.Settings.SensorProxy.SCANNER, API.Settings.SensorProxy.AGENT])
    def test_sensors_to_sp_and_tenable_io_relinking(self, create_sensor_proxy_tio, sensor_type):
        """
        NES-10705: Automate Sensors to Sensor Proxy linking tests with invalid linking key

        Steps:
        - Linking Agents to SP without unlinking from Tenable.io first (a 409 is the expectation)
        - Linking Scanners to SP without unlinking from Tenable.io first (a success is the expectation)

        Scenario Tested:
        [x] Verify the success log message while linking Scanner to Sensor proxy without unlinking from Tenable.io
            first.
        [x] Verify the error (409 Conflict) log message while linking Agent to Sensor proxy without unlinking from
            Tenable.io first.
        """
        scanner = {}
        agent = {}
        tio_host = NessusConfig.CAT_TIO_URL
        sp_host = create_sensor_proxy_tio['proxy_container']['URL']

        try:
            if sensor_type == API.Settings.SensorProxy.SCANNER:
                scanner = link_scanner_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                                 master_host=tio_host, master_port=443,
                                                 linking_key=create_sensor_proxy_tio['linking_key'])

                log.info('Scanner linked with T.io :: {}'.format(scanner))
            else:
                agent = link_agent_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                             master_host=tio_host, master_port=443,
                                             linking_key=create_sensor_proxy_tio['linking_key'])

                log.info('Agent linked with T.io :: {}'.format(agent))

            container_name = scanner['name'] if sensor_type == API.Settings.SensorProxy.SCANNER else agent['name']

            link_sensors_to_sensor_proxy(container=container_name, host=sp_host, port=443, sensor_type=sensor_type,
                                         linking_key=create_sensor_proxy_tio['linking_key'])

            log_message = get_log_message_from_log_files(search_text='[sensorlink]', **create_sensor_proxy_tio,
                                                         log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split('] ')

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                sidecar_log_message = API.Settings.SensorProxy.SCANNER_LINK_SUCCESS
            else:
                sidecar_log_message = 'Response code from linking: 409'

            # Verifies success message of linking Sensors to Sensor proxy from sidecar.log file
            assert all([log_message[1].lstrip('[') == 'sensorlink', log_message[2] == sidecar_log_message]), \
                'Getting incorrect log message for \'{}\'. Expected log message is :: :: {}'.format(
                    sensor_type, sidecar_log_message)

            access_log_message = get_log_message_from_log_files(
                search_text=const.HTTPMethods.POST.upper(), **create_sensor_proxy_tio,
                log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE).split(' "')[1].split()

            # Verifies the Sensors endpoint is displayed in log message of access.log file
            assert access_log_message[1] == '/remote/{}'.format(sensor_type), \
                'Sensor endpoint for \'{}\' is missing or mismatched.'.format(sensor_type)

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                response_code = HTTPStatus.OK
            else:
                response_code = HTTPStatus.CONFLICT

            # Verifies the Sensors response code after linking Sensors to Sensor Proxy
            assert all([access_log_message[0] == const.HTTPMethods.POST.upper(), int(access_log_message[3]) ==
                        response_code]), 'Expected {}, got {} instead.'.format(response_code, access_log_message[3])
        finally:
            if sensor_type == API.Settings.SensorProxy.SCANNER:
                unlink_nessus_scanner_from_master(container_name=scanner['name'])
            else:
                unlink_agent_from_master(container_name=agent['name'])

    @pytest.mark.parametrize('sensor_type', [API.Settings.SensorProxy.SCANNER, API.Settings.SensorProxy.AGENT])
    def test_sensors_to_sp_linking_with_invalid_key(self, create_sensor_proxy_tio, sensor_type):
        """
        NES-10705: Automate Sensors to Sensor Proxy linking tests with invalid linking key

        Steps:
        - Linking Sensors (Scanner/Agent) to SP with an invalid key

        Scenario Tested:
        [x] Verify the error (401 Unauthorized) log message while linking Sensors to Sensor proxy using invalid
            linking key
        """
        invalid_linking_key = generate_request_uuid() * 2

        if sensor_type == API.Settings.SensorProxy.SCANNER:
            scanners = link_scanner_to_master(
                docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                ['proxy_container']['URL'], master_port=443, linking_key=invalid_linking_key)

            log.info('Scanner details :: {}'.format(scanners))
        else:
            agents = link_agent_to_master(
                docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                ['proxy_container']['URL'], master_port=443, linking_key=invalid_linking_key)

            log.info('Agent details :: {}'.format(agents))

        log_message = get_log_message_from_log_files(search_text='sensorlink', **create_sensor_proxy_tio,
                                                     log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split('] ')

        invalid_link_error_message = API.Settings.SensorProxy.SENSORS_TO_SP_LINKING_ERROR + '401'

        # Verifies error message of linking Sensors to Sensor proxy with invalid linking key from sidecar.log file
        assert all([log_message[0].split()[2].lstrip('[') == 'error', log_message[1].lstrip('[') == 'sensorlink',
                    log_message[2] == invalid_link_error_message]), \
            'Getting incorrect error log while linking Sensor Proxy to Tenable.io with invalid key. Expected error ' \
            'log is :: {}'.format(invalid_link_error_message)

        access_log_message = get_log_message_from_log_files(
            search_text=const.HTTPMethods.POST.upper(), log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
            **create_sensor_proxy_tio).split(' "')[1].split()

        # Verifies the Sensors (Scanner/Agent) endpoint is displayed in log message of access.log file
        assert access_log_message[1] == '/remote/{}'.format(sensor_type), \
            '\'{}\' linking endpoint is missing or mismatched.'.format(sensor_type)

        # Verifies the Sensors (Scanner/Agent) response code after linking Sensors (Scanner/Agent) to Sensor Proxy
        assert all([access_log_message[0] == const.HTTPMethods.POST.upper(), int(access_log_message[3]) ==
                    HTTPStatus.UNAUTHORIZED]), 'Expected 401, got {} instead.'.format(access_log_message[3])

    @pytest.mark.parametrize("log_level", [Nessus.AdvancedSettings.DEBUG, Nessus.AdvancedSettings.INFO])
    def test_change_sidecar_log_levels(self, create_sensor_proxy_tio, log_level):
        """
        NES-10728: Automate Sensor Proxy tests: Configuration, Sensor Removal from T.io and Blackout Windows

        Steps:
        - Log levels ( info, debug )

        Scenario Tested:
        [x] Verify that as per set log levels- info, debug, logs should be displayed in "sidecar.log" log file.

        - log_level = info -> In sidecar.log, info logs will be displayed having '[info]' label.
        - log_level = debug -> In sidecar.log, debug logs will be displayed having '[debug]' label.
        """
        scanners = {}
        log_level_list = []

        try:
            sp_container_name = create_sensor_proxy_tio['proxy_container']['Name'].replace('/', '')

            current_log_level = get_log_message_from_log_files(search_text='Loglevel', **create_sensor_proxy_tio,
                                                               log_file=API.Settings.SensorProxy.SIDECAR_JSON_FILE
                                                               ).split(':')[1].rstrip(',')
            current_log_level = eval(current_log_level)
            log.info('Current Log level in sidecar.json :: {}'.format(current_log_level))
            log.info('Expected Log level :: {}'.format(log_level))

            before_process_id = get_process_id(pid_file=API.Settings.SensorProxy.SIDECAR_PID_FILE,
                                               container_name=sp_container_name)

            modify_json_file_value(actual_value=current_log_level, expected_value=log_level, **create_sensor_proxy_tio)

            # Reload/Restart Sensor Proxy
            reload_sensor_proxy(container_name=sp_container_name, process_id=before_process_id)

            scanners = link_scanner_to_master(
                docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

            log.info('Scanner details :: {}'.format(scanners))

            log_messages = get_log_message_from_log_files(search_text='.', **create_sensor_proxy_tio,
                                                          log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE,
                                                          full_logs=True)

            for log_line in log_messages:
                if log_line.split()[2].endswith(']'):
                    log_level_list.append(log_line.split()[2])

            log.info('Log level from sidecar.log file :: :: {}'.format(log_level_list))

            required_log_levels = {
                Nessus.AdvancedSettings.INFO: [Nessus.AdvancedSettings.INFO],
                Nessus.AdvancedSettings.DEBUG: [Nessus.AdvancedSettings.INFO, Nessus.AdvancedSettings.DEBUG]}

            # Verify the sidecar log level from 'sidecar.log' file
            assert all(['[{}]'.format(level) in log_level_list for level in required_log_levels.get(log_level)]), \
                'Sidecar log level is not same as expected. Expected log level should be \'{}\''.format(log_level)
        finally:
            unlink_nessus_scanner_from_master(container_name=scanners['name'])

    @pytest.mark.parametrize('sensor_type', [API.Settings.SensorProxy.SCANNER, API.Settings.SensorProxy.AGENT])
    def test_agent_and_nessus_can_download_plugins_via_sensor_proxy(self, create_sensor_proxy_tio, sensor_type):
        """
        NES-12425: [Integration] Nessus + SP

        Scenario Tested:
        [x] Nessus can download plugin and come online via SP
        """
        scanner_name = agent_name = container_name = None

        try:
            if sensor_type == API.Settings.SensorProxy.SCANNER:
                scanner_name = deploy_nessus_scanner(docker_network=create_sensor_proxy_tio['docker_network'])[
                    'scanner_name']
            else:
                agent_name = deploy_real_agent(docker_network=create_sensor_proxy_tio['docker_network'])['agent_name']

            container_name = scanner_name if sensor_type == API.Settings.SensorProxy.SCANNER else agent_name

            log.info("Set 'disable_core_updates' preference to 'yes' on Nessus {} side".format(sensor_type))
            set_fix_parameter_in_nessus_or_agent_container(container_name=container_name, sensor_type=sensor_type,
                                                           parameter_name='disable_core_updates', parameter_value='yes')

            log.info("Link Nessus {} to Sensor Proxy".format(sensor_type))
            link_sensors_to_sensor_proxy(container=container_name, port=443, sensor_type=sensor_type,
                                         host=create_sensor_proxy_tio['proxy_container']['URL'],
                                         linking_key=create_sensor_proxy_tio['linking_key'])

            log_message = get_log_message_from_log_files(search_text='[sensorlink]', **create_sensor_proxy_tio,
                                                         log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split()

            link_success_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7],
                                             log_message[8]])

            expected_message = API.Settings.SensorProxy.SCANNER_LINK_SUCCESS if sensor_type == API.Settings. \
                SensorProxy.SCANNER else API.Settings.SensorProxy.AGENT_LINK_SUCCESS

            # Verifies success message of linking Agent to Sensor proxy from sidecar.log file
            assert all([log_message[3] == '[sensorlink]', link_success_message == expected_message]), \
                'Nessus {} is not getting linked successful with Sensor proxy.'.format(sensor_type)

            container = create_sensor_proxy_tio['container']
            api = TenableCloudAPI()
            api.login(username=container.model.contact, password=container.model.password)

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                for log_msg in ["Updating (plugins: true, core: false)", "Downloading plugins update",
                                "Downloading plugins: complete"]:
                    assert wait(lambda: verify_log_msg_from_backend_logs(
                        scanner_name=scanner_name, log_message=log_msg, file_path=FileTools().nessusd_backendlog),
                                sleep_seconds=TIME_FIVE_SECONDS, timeout_seconds=TIME_FIFTEEN_MINUTES), \
                        "Expected log messages are missing or mismatch while downloading the nessus scanner plugins."

                log.info("Wait till scanner to be visible online")
                assert wait(lambda: check_scanner_status(api=api, scanner_name=scanner_name),
                            timeout_seconds=TIME_THIRTY_MINUTES, sleep_seconds=TIME_FIVE_SECONDS,
                            waiting_for='nessus scanner to be online'), \
                    "Failed to get Nessus scanner online after downloading the plugins."
            else:
                scanner_id = api.scanners.get_local_scanner_id()
                linked_agent_id, linked_agent_status = get_agent_id_from_list(api=api, agent_name=agent_name)

                agent_details = api.agents.details(scanner_id=scanner_id, agent_id=linked_agent_id)

                # Verifies the plugins update logs from 'backend.log' file
                for log_msg in ["Requesting full plugins update", "Downloading plugins: complete",
                                "Starting Nessus Agent"]:
                    assert is_log_entries(agent_ip=agent_details['ip'], no_of_entries=10, file=NessusAgentFilePath.
                                          NESSUS_AGENT_BACKEND_LOGS, message=log_msg,
                                          timeout_seconds=TIME_THIRTY_MINUTES), \
                        "'{}' message is missing or mismatch while downloading the nessus agent plugins.".format(
                            log_msg)

                log.info("Wait till agent gets online")
                assert wait(lambda: check_agent_status(api=api, agent_name=agent_name, scanner_id=scanner_id),
                            timeout_seconds=TIME_THIRTY_MINUTES, sleep_seconds=TIME_FIVE_SECONDS,
                            waiting_for='agent to be online'), \
                    "Failed to get agent online after downloading the plugins."
        finally:
            if sensor_type == API.Settings.SensorProxy.SCANNER:
                unlink_nessus_scanner_from_master(container_name=container_name)
            else:
                unlink_agent_from_master(container_name=container_name)

            subprocess.run(('docker stop %s' % container_name).split())

    @pytest.mark.xfail(reason='Not getting agent blackout window core updates for latest agent version.')
    def test_agent_blackout_window_core_update(self, create_sensor_proxy_tio):
        """
        NES-10728: Automate Sensor Proxy tests: Configuration, Sensor Removal from T.io and Blackout Windows

        Steps:
        - Core update blackout Windows for Agents
        """
        agent = {}

        try:
            # Login to Tenable.io and delete linked agent using API
            container_details = create_sensor_proxy_tio['container']
            api = TenableCloudAPI()
            api.login(username=container_details.model.contact, password=container_details.model.password)

            scanner_id = api.scanners.get_local_scanner_id()
            response = api.agent_blackout_windows.create(scanner_id, random_name("Auto_Blackout_window"))
            log.debug('Create blackout window response :: {}'.format(response))

            # Verifies response code after creating agent blackout window.
            assert api.http_status_code == HTTPStatus.OK, \
                'Expected status code %s, instead got %s' % (HTTPStatus.OK, api.http_status_code)

            log.debug('Log messages after creating agent blackout window')
            get_log_message_from_log_files(search_text='.', **create_sensor_proxy_tio, full_logs=True,
                                           log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE)

            # Link agent to Tenable.io
            agent = link_agent_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                         master_host=create_sensor_proxy_tio['proxy_container']['URL'], master_port=443,
                                         linking_key=create_sensor_proxy_tio['linking_key'])
            log.debug('Agent linked with Sensor proxy :: {}'.format(agent))

            response = api.agent_blackout_windows.update_config(scanner_id, software_update=False)
            log.debug('Update config response :: {}'.format(response))

            # Verifies response code for agent blackout windows core updates are getting successfully.
            assert api.http_status_code == HTTPStatus.OK, \
                'Expected status code %s, instead got %s' % (HTTPStatus.OK, api.http_status_code)

            access_log_message = get_log_message_from_log_files(search_text='.', **create_sensor_proxy_tio,
                                                                log_file=API.Settings.SensorProxy.ACCESS_LOG_FILE,
                                                                full_logs=True)

            log_details = access_log_message[0].split('] ')[2].split()
            log_tags = access_log_message[0].split('] ')[1].split()

            # Verifies the response code for remote agent blackout window core update via Sensor Proxy
            assert all([log_details[0].lstrip('"') == const.HTTPMethods.GET.upper(), int(log_details[3])
                        == HTTPStatus.OK]), 'Expected 200, got {} instead.'.format(log_details[3])

            # Verifies the endpoints for remote agent blackout window core update via Sensor Proxy
            assert '/remote/agent/updates' in log_details[1], 'Remote agent blackout window core update endpoint is ' \
                                                              'missing or mismatched in logs from access.log file.'

            # Verifies the cache type for remote agent blackout window core update via Sensor Proxy
            assert log_tags[0].split(':')[1] == API.Settings.SensorProxy.STALE, \
                'Remote agent blackout window core update was not a cache \'{}\'.'.format(
                    API.Settings.SensorProxy.STALE)
        finally:
            unlink_agent_from_master(container_name=agent['name'])

    @pytest.mark.parametrize('sensor_type', [API.Settings.SensorProxy.SCANNER, API.Settings.SensorProxy.AGENT])
    def test_sensors_unlinking_with_connection_failures(self, create_sensor_proxy_tio, sensor_type):
        """
        NES-10736: Automate Sensor Proxy tests: Linking and Unlinking with connection failures

        Steps:
        - Unlinking with a connection failure

        Scenario Tested:
        [x] Verify the error log message on unlinking Sensors from Sensor proxy while network is down.
        """
        scanners = {}
        agents = {}

        try:
            if sensor_type == API.Settings.SensorProxy.SCANNER:
                scanners = link_scanner_to_master(
                    docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                    ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

                log.debug('Scanner details :: {}'.format(scanners))
            else:
                agents = link_agent_to_master(
                    docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                    ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

                log.debug('Agent details :: {}'.format(agents))

            take_up_down_network_in_docker_container(network=create_sensor_proxy_tio['docker_network'],
                                                     container_name=create_sensor_proxy_tio['proxy_container']['URL'])

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                unlink_output = unlink_nessus_scanner_from_master(container_name=scanners['name']).split('\n')
                unlink_output = [response for response in unlink_output if re.search('error', response)][0].split('] ')
            else:
                unlink_output = unlink_agent_from_master(container_name=agents['name']).split('] ')

            log.debug('Response while trying to unlink {} from SP :: {}'.format(sensor_type, unlink_output))

            # Verifies error tag from error log of unlinking Sensors from Sensor Proxy
            assert all([unlink_output[0].lstrip('[') == 'error', unlink_output[1].lstrip('[') == sensor_type]), \
                'Error log is missing on trying to unlink agent while Sensor proxy gets down.'

            sp_down_unlink_error = API.Settings.SensorProxy.SP_DOWN_UNLINK_ERROR + '{}:443 failed'.format(
                create_sensor_proxy_tio['proxy_container']['URL'])

            # Verifies error message of unlinking Sensors to Sensor proxy while Sensor proxy gets down
            assert unlink_output[2].rstrip('\n') == sp_down_unlink_error, \
                'Getting incorrect error log. Expected error log is: {}'.format(sp_down_unlink_error)
        finally:
            take_up_down_network_in_docker_container(network=create_sensor_proxy_tio['docker_network'],
                                                     container_name=create_sensor_proxy_tio['proxy_container']['URL'],
                                                     take_up=True)

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                unlink_nessus_scanner_from_master(container_name=scanners['name'])
            else:
                unlink_agent_from_master(container_name=agents['name'])

    @pytest.mark.parametrize('sensor_type', [API.Settings.SensorProxy.SCANNER, API.Settings.SensorProxy.AGENT])
    def test_sensors_linking_with_connection_failure(self, create_sensor_proxy_tio, sensor_type):
        """
        NES-10736: Automate Sensor Proxy tests: Linking and Unlinking with connection failures

        Steps:
        - Link attempt that fails (e.g., firewall)

        Scenario Tested:
        [x] Verify the error log message on linking Sensors to Sensor proxy after blocking network traffic on Sensor
            Proxy.
        """
        try:
            take_up_down_network_in_docker_container(network=create_sensor_proxy_tio['docker_network'],
                                                     container_name=create_sensor_proxy_tio['proxy_container']['URL'])

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                link_output = link_scanner_to_master(
                    docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                    ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])
            else:
                link_output = link_agent_to_master(
                    docker_network=create_sensor_proxy_tio['docker_network'], master_host=create_sensor_proxy_tio
                    ['proxy_container']['URL'], master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

            log.debug('Output :: :: {}'.format(link_output['output']))
            link_output = link_output['output'].split('] ')

            assert all([link_output[0].lstrip('[') == 'error', link_output[1].lstrip('[') == sensor_type]), \
                'Error log is missing on trying to link sensors while Sensor proxy gets down.'

            sp_down_link_error = API.Settings.SensorProxy.SP_DOWN_LINK_ERROR + '{}:443 failed'.format(
                create_sensor_proxy_tio['proxy_container']['URL'])

            # Verifies error message of linking Sensors to Sensor proxy with invalid linking key from sidecar.log file
            assert link_output[2].rstrip('\n') == sp_down_link_error, \
                'Getting incorrect error log. Expected error log is: {}'.format(sp_down_link_error)
        finally:
            take_up_down_network_in_docker_container(network=create_sensor_proxy_tio['docker_network'],
                                                     container_name=create_sensor_proxy_tio['proxy_container']['URL'],
                                                     take_up=True)


@pytest.mark.sensor_proxy
class TestUnlinkSensorProxy:
    """ NES-10477 : Implement automated (but manually executed) tests for Sensor Proxy """

    def test_unlink_sensor_proxy_from_tenable_io(self, create_sensor_proxy_tio):
        """
        Steps:
        2. Unlinking from Tenable.io

        Scenario Tested:
        [x] Verify that Sensor Proxy is unlinked from Tenable.io successfully
        """
        sensor_proxy_details = create_sensor_proxy_tio

        unlinked_response = unlink_sensor_proxy_from_tenable_io(**create_sensor_proxy_tio).split('] ')

        # Verifies success message of unlinking Sensor proxy from Tenable.io from CLI
        assert all([unlinked_response[1].lstrip('[') == 'unlink',
                    unlinked_response[2].rstrip('\n') == API.Settings.SensorProxy.SENSOR_PROXY_UNLINKED]), \
            'Success log message is missing while unlinking Sensor Proxy to Tenable.io.'

        wait(lambda: verify_log_msg_from_backend_logs(scanner_name=sensor_proxy_details['proxy_container'][
            'Name'].replace('/', ''), log_message='[unlink]', file_path='/opt/sensor_proxy/{}'.format(
            API.Settings.SensorProxy.SIDECAR_LOG_FILE)), sleep_seconds=TIME_FIVE_SECONDS,
             timeout_seconds=TIME_FIVE_MINUTES)

        log_message = get_log_message_from_log_files(
            search_text='[unlink]', log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE, **sensor_proxy_details).split()
        unlink_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7], log_message[8]])

        # Verifies success message of unlinking Sensor proxy from Tenable.io from sidecar.log file
        assert all([log_message[3] == '[unlink]', unlink_message == API.Settings.SensorProxy.SENSOR_PROXY_UNLINKED]), \
            'Sensor proxy is not getting unlinked from Tenable.io.'

    def test_sensor_proxy_to_tenable_io_linking_with_invalid_key(self, create_sensor_proxy_tio):
        """
        NES-10705: Automate Sensors to Sensor Proxy linking tests with invalid linking key

        Steps:
        - Linking SP to Tenable.io with an invalid key

        Scenario Tested:
        [x] Verify the error (401 Unauthorized) log message while linking Sensor proxy to Tenable.io with an invalid
            linking key
        """
        valid_linking_key = create_sensor_proxy_tio['linking_key']

        try:
            invalid_linking_key = generate_request_uuid() * 2
            create_sensor_proxy_tio['linking_key'] = invalid_linking_key

            linking_output = link_sensor_proxy_to_tenable_io(**create_sensor_proxy_tio).split('] ')

            invalid_link_error_message = API.Settings.SensorProxy.SP_TIO_LINKING_ERROR + ' (401 Unauthorized)'

            # Verifies error message of linking Sensor proxy to T.io with invalid linking key
            assert all([linking_output[0].lstrip('[') == 'error', linking_output[1].lstrip('[') == 'link',
                        linking_output[2].rstrip('\n') == invalid_link_error_message]), \
                'Getting incorrect error message while linking Sensor Proxy to Tenable.io with invalid key. Expected ' \
                'error log is :: {}'.format(invalid_link_error_message)

            log_message = get_log_message_from_log_files(search_text='Unable to link', **create_sensor_proxy_tio,
                                                         log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split('] ')

            # Verifies error message of linking Sensor proxy to T.io with invalid linking key from sidecar.log file
            assert all([log_message[0].split()[2].lstrip('[') == 'error', log_message[1].lstrip('[') == 'link',
                        log_message[2] == invalid_link_error_message]), \
                'Getting incorrect error log while linking Sensor Proxy to Tenable.io with invalid key. ' \
                'Expected error log is :: {}'.format(invalid_link_error_message)
        finally:
            create_sensor_proxy_tio['linking_key'] = valid_linking_key


@pytest.mark.sensor_proxy
class TestSSLErrorOnSensorProxy:
    """ NES-10736: Automate Sensor Proxy tests: Linking and Unlinking with connection failures """

    @pytest.mark.xfail(reason='Not getting SSL certificate errors in Sensor Proxy docker container')
    @pytest.mark.parametrize('sensor_type', [API.Settings.SensorProxy.SCANNER, API.Settings.SensorProxy.AGENT])
    def test_ssl_errors_on_sensor_proxy(self, create_sensor_proxy_tio, sensor_type):
        """
        Steps:
        - Take down SP; spin up a new SP but use the same certificates.
            a. Confirm SSL errors with new, self-signed certs
            b. Confirm SSL success & normal operation when original certs (those stored in the sensor) are copied to
               /usr/local/etc/nginx/ssl/

        Scenario Tested:
        [x] Verify the SSL errors on Sensor Proxy.
        """
        scanner = {}
        agent = {}

        file_path = '/usr/local/etc/nginx/ssl/'
        container = create_sensor_proxy_tio['proxy_container']['URL']

        try:
            if sensor_type == API.Settings.SensorProxy.SCANNER:
                scanner = link_scanner_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                                 master_host=container, master_port=443,
                                                 linking_key=create_sensor_proxy_tio['linking_key'])
            else:
                agent = link_agent_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                             master_host=container, master_port=443,
                                             linking_key=create_sensor_proxy_tio['linking_key'])

            delete_file_from_container(container_name=container, file_path=file_path)
            process_id = get_process_id(pid_file=API.Settings.SensorProxy.SIDECAR_PID_FILE, container_name=container)

            # Reload/Restart Sensor Proxy
            reload_sensor_proxy(container_name=container, process_id=process_id)

            if sensor_type == API.Settings.SensorProxy.SCANNER:
                sensor_output = unlink_nessus_scanner_from_master(container_name=scanner['name'])
            else:
                sensor_output = unlink_agent_from_master(container_name=agent['name'])

            unlink_output = sensor_output.split('\n')[1].split('] ')
            log.debug("Sensors unlink output :: {}".format(sensor_output))

            # Verifies error tag from error log of unlinking Sensors from Sensor Proxy
            assert all([unlink_output[0].lstrip('[') == 'error', unlink_output[1].lstrip('[') == sensor_type]), \
                'Error log is missing on trying to unlink agent while Sensor proxy gets down.'

            sp_ssl_unlink_error = API.Settings.SensorProxy.SP_SSL_ERROR + '{}:443'.format(
                create_sensor_proxy_tio['proxy_container']['URL'])

            # Verifies error message of unlinking Sensors to Sensor proxy after removing SSL cert.
            assert unlink_output[2].rstrip('\n') == sp_ssl_unlink_error, \
                'Getting incorrect error log. Expected error log is: {}'.format(sp_ssl_unlink_error)
        finally:
            if sensor_type == API.Settings.SensorProxy.SCANNER:
                unlink_nessus_scanner_from_master(container_name=scanner['name'])
            else:
                unlink_agent_from_master(container_name=agent['name'])
