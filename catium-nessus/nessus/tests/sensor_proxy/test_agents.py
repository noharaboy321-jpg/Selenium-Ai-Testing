"""
Test the fixtures.
"""
import subprocess

import pytest
from packaging.version import parse
from waiting import wait
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.lib import const
from catium.lib.const.base_constants import TIME_TEN_MINUTES, TIME_TEN_SECONDS, TIME_FIVE_MINUTES, TIME_FIFTEEN_SECONDS
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessus_agent import get_nessus_agent_version, \
    get_expected_nessus_agent_build_and_version_for_given_channel, set_fix_parameter_in_nessus_agent, \
    get_fix_parameter_in_nessus_agent, trigger_agent_update_checks
from nessus.helpers.sensor_proxy.sensor_proxy import link_sensors_to_sensor_proxy, get_log_message_from_log_files, \
    unlink_agent_from_master, deploy_real_agent
from nessus.lib.const.constants import API
from nessus.tests.conftest import link_agent_to_master, fake_sp_agent
from tenableio.apiobjects.tenablecloud_api import TenableCloudAPI

log = create_logger()


@pytest.mark.sensor_proxy
class TestAgents:
    """ Covers Sensor Proxy Server and agent related integration test cases """

    cat = None

    def test_agent_linking(self, create_sensor_proxy_tio):
        """
        NES-12424: [Integration] Agent + SP

        Scenario Tested:
        [x] Verify that Agent can link via SP successfully.
        """
        agent = None
        found = False

        try:
            agent = link_agent_to_master(docker_network=create_sensor_proxy_tio['docker_network'],
                                         master_host=create_sensor_proxy_tio['proxy_container']['URL'],
                                         master_port=443, linking_key=create_sensor_proxy_tio['linking_key'])

            container = create_sensor_proxy_tio['container']

            api = TenableCloudAPI()
            api.login(username=container.model.contact, password=container.model.password)

            scanner_id = api.scanners.get_local_scanner_id()
            agents = api.agents.get_agents(scanner_id=scanner_id)
            real_agents = agents['agents']

            for agent in real_agents:
                if agent['name'] == agent['name']:
                    found = True
                    break

            assert found, "Could not find agent by name"

        finally:
            if agent:
                unlink_agent_from_master(container_name=agent['name'])

    def test_plugin_caching(self, create_sensor_proxy_tio):
        data = create_sensor_proxy_tio
        api = None

        try:
            agent = fake_sp_agent(host=data['proxy_container']['URL'], key=data['linking_key'])

            # Request plugins with this Agent.  Then, request them again and check for the cached header.
            api = NessusAPI(url=data['proxy_container']['URL'])

            # Add MS-Agent header to session headers
            api.add_header({'MS-Agent': "token=%s" % agent['token']})

            # GET the response and headers from /remote/agent/plugins endpoint
            log.info('Downloading plugins')
            re = api.remote.get_remote_agent_plugins(params={'platform': 'WINDOWS', 'distro': 'win-x86-64'},
                                                     stream=True)
            log.info("Download plugins response_1 :: :: {}".format(re))

            # Download the plugins.
            for chunk in re.iter_content(chunk_size=1024 * 1024):
                if chunk:  # filter out keep-alive new chunks
                    log.debug("Got a chunk!")

            log.info("Downloaded the plugins.")

            assert api.http_status_code == const.HTTPStatus.OK, \
                'Expected 200, got %s instead' % api.http_status_code

            assert re.headers['Content-Disposition'] == 'attachment; filename="agent.db.gz"', \
                "Plugins file is not downloaded successfully"

            log.info('Downloading plugins again')
            re = api.remote.get_remote_agent_plugins(params={'platform': 'WINDOWS', 'distro': 'win-x86-64'},
                                                     stream=True)
            log.info("Download plugins response_2 :: :: {}".format(re))
            assert 'HIT' in re.headers['X-Nginx-Cache-Status'], 'Second plugin update was not a cache hit.'
        finally:
            if api:
                api.remote.delete_remote_agent()
                api.remove_header(key='MS-Agent')

    def test_core_update_caching(self, create_sensor_proxy_tio):
        data = create_sensor_proxy_tio
        api = None

        try:
            agent = fake_sp_agent(host=data['proxy_container']['URL'], key=data['linking_key'])

            # Request plugins with this Agent.  Then, request them again and check for the cached header.
            api = NessusAPI(url=data['proxy_container']['URL'])

            # Add MS-Agent header to session headers
            api.add_header({'MS-Agent': "token=%s" % agent['token']})

            # GET the response and headers from /remote/agent/plugins endpoint
            log.info('Downloading the core update')
            re = api.remote.get_remote_agent_core(distro=API.Settings.SensorProxy.WIN_DISTRO,
                                                  platform=API.Settings.SensorProxy.WIN_PLATFORM, stream=True)
            log.info("Download core update response_1 :: :: {}".format(re))

            # Download the plugins.
            for chunk in re.iter_content(chunk_size=1024 * 1024):
                if chunk:  # filter out keep-alive new chunks
                    log.debug("Got a chunk!")

            log.info("Downloaded the plugins.")

            assert api.http_status_code == const.HTTPStatus.OK, \
                'Expected 200, got %s instead' % api.http_status_code

            log.info('Downloading the core update again')
            re = api.remote.get_remote_agent_core(distro=API.Settings.SensorProxy.WIN_DISTRO,
                                                  platform=API.Settings.SensorProxy.WIN_PLATFORM, stream=True)
            log.info("Download core update response_2 :: :: {}".format(re))
            assert 'HIT' in re.headers['X-Nginx-Cache-Status'], 'Second core update was not a cache hit.'
        finally:
            if api:
                api.remote.delete_remote_agent()
                api.remove_header(key='MS-Agent')


@pytest.mark.sensor_proxy
class TestNessusAgentUpgradeDowngradeViaSP:
    """ Covers Agent Upgrade/Downgrade tests when connected through Sensor Proxy Server """

    @pytest.mark.parametrize("choice_option", ["ea", "stable", "ga"])
    def test_verify_agent_can_upgrade_downgrade_when_connected_through_sensor_proxy(self, create_sensor_proxy_tio,
                                                                                    choice_option):
        """
        NES-12424: [Integration] Agent + SP

        Scenario Tested:
        [x] Agent can software update when connected through SP

        Steps:
        1. Link agent to Tenable i.o via sensor proxy.
        2. Set value for "agent_update_channel" to "ea/ga/stable".
        3. Verify the value successfully set to respected value for "agent_update_channel".
        4. Verify that agent version/build gets updated via goat-feed server.
        """
        agent_detail = deploy_real_agent(docker_network=create_sensor_proxy_tio['docker_network'], expose_port=True)

        agent_name, agent_port = agent_detail['agent_name'], agent_detail['agent_port']

        try:
            link_sensors_to_sensor_proxy(container=agent_name, host=create_sensor_proxy_tio['proxy_container']['URL'],
                                         port=443, sensor_type=API.Settings.SensorProxy.AGENT,
                                         linking_key=create_sensor_proxy_tio['linking_key'])

            log_message = get_log_message_from_log_files(search_text='[sensorlink]', **create_sensor_proxy_tio,
                                                         log_file=API.Settings.SensorProxy.SIDECAR_LOG_FILE).split()

            link_success_message = ' '.join([log_message[4], log_message[5], log_message[6], log_message[7],
                                             log_message[8]])

            # Verifies success message of linking Agent to Sensor proxy from sidecar.log file
            assert all([log_message[3] == '[sensorlink]', link_success_message == API.Settings.SensorProxy.
                       AGENT_LINK_SUCCESS]), 'Nessus agent is not getting linked successful with Sensor proxy.'

            container = create_sensor_proxy_tio['container']
            api = TenableCloudAPI()
            api.login(username=container.model.contact, password=container.model.password)
            scanner_id = api.scanners.get_local_scanner_id()

            wait(lambda: [True for agent in api.agents.get_agents(scanner_id=scanner_id)['agents'] if agent['name'] ==
                          agent_name], timeout_seconds=TIME_FIVE_MINUTES, sleep_seconds=TIME_FIFTEEN_SECONDS,
                 waiting_for='Agent %s to appear on master' % agent_name)

            ssh = SSH(port=agent_port)
            original_agent_version = get_nessus_agent_version(ssh=ssh)
            log.info("Original agent version/build is : {}".format(original_agent_version))

            expected_agent_version = get_expected_nessus_agent_build_and_version_for_given_channel(
                ssh=ssh, update_channel=choice_option)

            set_fix_parameter_in_nessus_agent(parameter_name="agent_update_channel",
                                              parameter_value=choice_option, ssh=ssh)

            # Verify that value for fix parameter "agent_update_channel" set successfully.
            assert get_fix_parameter_in_nessus_agent(ssh=ssh, parameter_name="agent_update_channel") == choice_option, \
                "Agent update channel does not saved successfully."

            trigger_agent_update_checks(ssh=ssh)

            # Agent upgrade/downgrade is not possible in agent versions less than 7.7.0
            expected_update = parse(expected_agent_version[0]) >= parse('7.7.0')

            # As build downgrade for same version is not possible, setting expected update as False
            if parse(original_agent_version[0]) == parse(expected_agent_version[0]) and \
                    int(original_agent_version[1]) > int(expected_agent_version[1]):
                expected_update = False

            if expected_update:
                # Verify that Agent version/build gets changed to expected value as per channel selected.
                try:
                    wait(lambda: get_nessus_agent_version(ssh=ssh) == expected_agent_version,
                         timeout_seconds=TIME_TEN_MINUTES, sleep_seconds=TIME_TEN_SECONDS,
                         waiting_for="Agent version to get updated as per selected channel.")
                except TimeoutExpired:
                    raise AssertionError("Agent version/build does not update to {}".format(expected_agent_version))
                log.info("Updated agent version/build is : {}".format(get_nessus_agent_version(ssh=ssh)))
            else:
                # Verify that Agent version/build remains on same version/build.
                sleep(180, reason="Waiting for the build ")
                assert get_nessus_agent_version(ssh=ssh) == original_agent_version, \
                    "Nessus version/build is not same as {} but changed to {}.".format(
                        original_agent_version, get_nessus_agent_version(ssh=ssh))
        finally:
            unlink_agent_from_master(container_name=agent_name)

            subprocess.run(('docker stop %s' % agent_name).split())
