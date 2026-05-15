"""
Nessus Plugin update
Test cases for plugin updates of nessus

:copyright: Tenable Network Security, 2025
:last_modified: April 1, 2025
:author: @krpatel.ctr
"""
import os
import time
from http import HTTPStatus
from subprocess import TimeoutExpired

import pytest

from catium.helpers.site_configuration_fetcher import get_site_environ
from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.aws.s3client import S3Client
from catium.lib.config import Config
from catium.lib.const import TIME_TEN_SECONDS, TIME_TEN_MINUTES, TIME_THIRTY_MINUTES, TIME_TWO_MINUTES
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from catium.lib.webium.wait import wait
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import stop_nessus, get_nessus_cli, get_nessusd_messages, \
    get_command, get_nessusd_dump, get_os_name
from nessus.helpers.scan import start_stop_nessus_wait_for_ready
from nessus.helpers.waiters import wait_scan_state
from nessus.lib.const import API, OperatingSystems, Nessus
from nessus.lib.message.messages import Messages
from nessus.pageobjects.about.about_page import OverView
from nessus.pageobjects.credentials.host import Password
from nessus.pageobjects.header.notifications import close_pendo_guide_container_banner_for_nessus_pro, \
    close_welcome_banner_for_nessus_pro
from nessus.pageobjects.login.login_page import LoginPage

log = create_logger()


# @pytest.mark.nessus_manager
# @pytest.mark.nessus_expert
# @pytest.mark.nessus_home
@pytest.mark.nessus_pro_mat
@pytest.mark.usefixtures('nessus_api_login')
class TestPluginSetUpdate:
    """
        Tests for plugin set updates in nessus products using tarball file.
    """

    @staticmethod
    def login_after_plugin_update() -> None:
        """
        UI Login and wait till the required login elements are not found

        :return: None
        """
        login_page = LoginPage()
        login_page.refresh()
        wait(lambda: login_page.is_element_present("username_field") and login_page.is_element_present(
            "password_field") or login_page.refresh(), sleep_seconds=TIME_TEN_SECONDS, timeout_seconds=TIME_TEN_MINUTES,
             waiting_for="Login page to appear")

        login_page.login_with_defaults()

    @staticmethod
    def update_the_nessus_with_plugin_tar_file(absolute_path: str, remote_path: str) -> bool:
        """
        Download and transfer the tar file using SFTP and then update the Nessus product using cli command.

        :param str absolute_path: path on which the tar file will be downloaded
        :param str remote_path: path on which the tar file will be transfer to host
        :return: True if plugin update successful message is available or else False
        :rtype: bool
        """

        nessus_os = get_os_name()

        with SSH() as ssh:
            if OperatingSystems.LINUX == nessus_os:
                file_remote_path = "/tmp/{}".format(remote_path)
            elif OperatingSystems.WINDOWS == nessus_os:
                file_remote_path = "C:/{}".format(remote_path)
            else:
                raise Exception("{} is not yet supported for the operation.".format(nessus_os))

            ssh.send_file(os.path.abspath(absolute_path), remote_file_path=file_remote_path)

            stop_nessus()
            command_result = ssh.execute(command=f"{get_nessus_cli()} update {file_remote_path}")

            if any([Messages.NessusCli.PLUGIN_UPDATE_SUCCESSFUL in op for op in command_result]):

                start_stop_nessus_wait_for_ready(nessus_api=NessusAPI(), status=API.Status.READY)
                sleep(TIME_TWO_MINUTES, reason='waiting for UI to be ready.')

                return True
            return False

    cat = None

    @pytest.mark.xray(test_key='SCE-4088')
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': (get_file_path('nessus/tests/api/scan/test_data/test_advanced_local_scan.json')),
         'scan_type': 'advanced'}], indirect=True)
    @pytest.mark.mat
    @pytest.mark.nessus_pro
    def test_nessus_successfully_update_the_plugin_set(self, test_data_file, create_scan_no_teardown):
        """
        Test that cover the Nessus plugin-set update using tar file

        SCE-4088 : Verify Nessus plugin set updates using tar file

        scenarios covered:
        []

        """
        try:
            scan = create_scan_no_teardown
            scan_exists = scan.scan_state()
            assert scan_exists, 'Unable to create the scan.'

            scan_id = scan.id
            api_session = self.cat.api


            # global pre_prod_pluginset
            initial_pluginset = get_site_environ('CAT_INITIAL_PLUGINSET', value_type=str)
            pre_prod_pluginset = get_site_environ('CAT_PREPROD_PLUGINSET', value_type=str)
            Nessus_IP = get_site_environ('TEST_ENV_IPS')
            # pre_prod_pluginset = '202504222135'
            # initial_pluginset = '202504132128'

            # initial_pluginset_file_path = f"feed-prod/{initial_pluginset}/plugins.tar.gz"
            # initial_plugin_file = S3Client.get_local_path(path=initial_pluginset_file_path, bucket_name='eng-dev-tenable-common-us-east-1')
            pre_prod_file_path = f"feed-prod/{pre_prod_pluginset}/plugins.tar.gz"
            pre_prod_plugin_file = S3Client.get_local_path(path=pre_prod_file_path, bucket_name='eng-dev-tenable-common-us-east-1')

            # plugin_initial_file = initial_plugin_file.split('/')[3]
            # plugin_update_file = "plugins.tar.gz"
            # log.info(f"taking initial plugin update from the {initial_plugin_file}")
            # assert self.update_the_nessus_with_plugin_tar_file(absolute_path=initial_plugin_file, remote_path=plugin_initial_file), \
            #     "Plugin update with {} failed.".format(initial_plugin_file)

            # try:
            #     api_session.logout()
            # except:
            #     pass
            # api_session.login()

            initial_properties = api_session.server.properties()

            scan_1_count = None

            if initial_properties['plugin_set'] is None:
                log.info(f"plugin set just after installation is NONE for IP {Nessus_IP}")
            else:
                log.info("initial plugin set is {} for IP {}".format(initial_properties['plugin_set'], Nessus_IP))
                initial_plugin_set = initial_properties['plugin_set']

                assert str(initial_pluginset) == initial_plugin_set, 'Initial plugin_set is not installed correctly'

                log.info("scan verification started for initial plugin-set")
                api_session.scans.launch(scan_id)
                assert api_session.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % api_session.http_status_code

                try:
                    scan_completed = wait_scan_state(api=api_session, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                             timeout=TIME_THIRTY_MINUTES)
                    assert scan_completed, "scan not completed"
                except TimeoutExpired:
                    scan_completed = wait_scan_state(api=api_session, scan_id=scan_id,
                                                     end_state=API.Scan.Status.COMPLETED,
                                                     timeout=TIME_THIRTY_MINUTES)
                    assert scan_completed, "scan not completed"


                scan_details = api_session.scans.details(scan_id)
                assert len(scan_details['vulnerabilities']) >= 1, "Scan failed to get vulnerabilities"

                scan_1_count = len(scan_details['vulnerabilities'])
                log.info(f"Initial scan vuln count is {scan_1_count} for IP {Nessus_IP}")

            plugin_preprod_file = pre_prod_plugin_file.split('/')[3]
            # plugin_update_file = "plugins.tar.gz"
            log.info(f"taking pre-prod plugin update from the {pre_prod_plugin_file} for IP {Nessus_IP}")
            assert self.update_the_nessus_with_plugin_tar_file(absolute_path=pre_prod_plugin_file, remote_path=plugin_preprod_file), \
                "Plugin update with {} failed.".format(pre_prod_plugin_file)

            try:
                api_session.logout()
            except:
                pass

            api_session.login()

            properties_after_upload = api_session.server.properties()

            if properties_after_upload['plugin_set'] is not None:
                log.info("plugin set after update is {}".format(properties_after_upload['plugin_set']))
            preprod_plugin_set = properties_after_upload['plugin_set']

            assert str(initial_pluginset) != preprod_plugin_set, 'older plugin set is not updated correctly in API'
            assert pre_prod_pluginset == preprod_plugin_set, 'pre-prod plugin set is not matched'

            log.info(f"logs verification started for {Nessus_IP}")
            get_read_file_content_command = get_command(operation="display_content")
            nessud_msg_file = get_nessusd_messages()
            with SSH() as ssh:
                nessusd_msg_file_content = ssh.execute("{} {}".format(get_read_file_content_command, nessud_msg_file))
            log.debug("Nessusd messages file content : {}".format(nessusd_msg_file_content))

            for file_line in nessusd_msg_file_content:
                if Nessus.About.PluginsetUpdate.UNWANTED_LOGS[2] in file_line:
                    log.info(nessusd_msg_file_content)
                    assert False

            get_read_file_content_command = get_command(operation="display_content")
            nessud_dump_file = get_nessusd_dump()
            with SSH() as ssh:
                nessusd_dump_file_content = ssh.execute("{} {}".format(get_read_file_content_command, nessud_dump_file))
            log.debug("Nessusd dump file content : {}".format(nessusd_dump_file_content))

            assert not [file_line for file_line in nessusd_msg_file_content if Nessus.About.PluginsetUpdate.UNWANTED_LOGS[0] in
                        file_line or Nessus.About.PluginsetUpdate.UNWANTED_LOGS[1] in file_line], \
                "Nessus crashed somewhere while processing the plugins."

            log.info(f"scan verification started for IP {Nessus_IP} with pre-prod plugin-set {pre_prod_pluginset}")
            api_session.scans.launch(scan_id)
            assert api_session.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % api_session.http_status_code

            rescan_completed = wait_scan_state(api=api_session, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                             timeout=TIME_THIRTY_MINUTES)

            assert rescan_completed,"scan not completed"

            rescan_details = api_session.scans.details(scan_id)
            assert len(rescan_details['vulnerabilities']) >= 1, "Scan failed to get vulnerabilities"

            scan_2_count = len(rescan_details['vulnerabilities'])

            if scan_1_count is None:
                pass
            else:
                log.info(f"scan_1 vuln count is {scan_1_count} and scan_2 vuln count is {scan_2_count} for {Nessus_IP}")
                assert scan_1_count <= scan_2_count or scan_2_count in range(int(scan_1_count) - 5,scan_1_count) , ("Vuln count is less than the previous scan even after running "
                                                  "with newer plugin set")

            try:
                api_session.logout()
            except:
                pass

            # try:
            #     login_page = LoginPage()
            #     login_page.refresh()
            #     login_page.do_login()
            #
            #     close_pendo_guide_container_banner_for_nessus_pro()
            #     close_welcome_banner_for_nessus_pro()
            #
            #     # self.login_after_plugin_update()
            #
            #     about_page = OverView()
            #     about_page.open()
            #     updated_plugin_set = about_page.plugin_set.text
            #
            #     assert str(initial_plugin_set) != updated_plugin_set, 'older plugin set is not updated correctly'
            #     assert str(latest_plugin_set) == updated_plugin_set, 'newer plugin set is not matched'
            #     log.info("UI checks passed")
            # except TimeoutExpired:
            #     log.info("plugin set is not verified by UI settings > about page")


        finally:
            try:
                api_session.login()
            except:
                pass
