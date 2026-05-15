"""
Nessus test cases for Server Endpoints

:copyright: Tenable Network Security, 2019
:date: August 08, 2018
:last_modified: July 21, 2020
:author: @rdutta, @mdriscoll, @kpanchal, @krpatel
"""

import os
import re
from http import HTTPStatus

import pytest
from requests.exceptions import HTTPError
from waiting import wait

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.activation_code_generator import ActivationCodeGenerator
from catium.lib.const.base_constants import TIME_THIRTY_MINUTES, TIME_TEN_MINUTES, STRING_OK, TIME_FIVE_MINUTES, \
    TIME_FIVE_SECONDS, \
    TIME_TEN_SECONDS, TIME_FIFTEEN_SECONDS, TIME_TWO_MINUTES
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util.util import random_string
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.helpers.nessuscli.logchecker import read_from_file
from nessus.helpers.scan import create_scan_helper
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.helpers.server import expect_http_error
from nessus.helpers.waiters import wait_for_scanner_status, wait_scan_state
from nessus.lib.const.constants import Nessus, API

log = create_logger()

PATH_TO_PLUGIN = 'nessus/tests/api/plugins/test_data/nessus_plugins.tar.gz'
PATH_TO_CERTIFICATE = 'nessus/tests/ui/ca-cert/test_data/rdp.cer'
PATH_TO_CERTIFICATE_WITH_EXTRA_CHAR = 'nessus/tests/ui/ca-cert/test_data/rdp_with_extra_char.cer'


@pytest.fixture()
def set_valid_custom_host(request: 'SubRequest'):
    """
    Sets the custom_host value to "plugins-internal-staging.cloud.aws.tenablesecurity.com" before test starts
    """
    payload = {"custom_host": "plugins-internal-staging.cloud.aws.tenablesecurity.com"}
    request.instance.cat.api.settings.edit_software_updates_setting(payload)
    return


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusServerEndpoint:
    """Tests for Nessus server Endpoint"""
    cat = None

    # API_Tested# GET /server/properties
    @pytest.mark.nessus_mat
    @pytest.mark.nessus_home
    def test_server_properties(self):
        """
        #STA-31: Create additional tests for Server
        Test to verify server properties

        Scenarios tested:
          [x] Successfully get server properties without login
          [ ] Successfully get server properties with login
        verify that only certain data is returned if we are non-authenticated
        """
        # Get all server properties
        server_prop = self.cat.api.server.properties()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert server_prop, 'No properties returned from server response.'
        assert 'template_version' in server_prop, 'Template version was missing from server properties'
        assert 'template_version_upgrade_necessary' in server_prop, \
            'Nessus upgrade required flag missing from server properties'
        assert 'feed_notifications' in server_prop, 'Nessus from-feed notifications missing from server properties'

    # API_Tested# POST /server/unlock
    # API_Tested# POST /server/restart
    @pytest.mark.nessus_home
    @pytest.mark.incompatible
    @pytest.mark.parametrize('configure_master_password', [{'new_password': Nessus.DEFAULT_PASSWORD}],
                             indirect=True)
    def test_unlock_server(self, configure_master_password):
        """
        #STA-31: Create additional tests for Server
        Test to unlock server with set master password

        Scenarios tested:
          [x] Successfully unlock server with master password
          [x] Successfully restart the server
          [ ] Passing a invalid master password or empty and make sure it fails
        """
        # Set a master password for server
        current_master_password = configure_master_password

        # Restart the service
        self.cat.api.server.restart()
        wait_for_scanner_status(api=self.cat.api, timeout=TIME_TEN_MINUTES, status=API.Status.LOCKED,
                                msg='Waiting for server to be in locked state after successful service restart.')

        # Unlock server with set master password
        self.cat.api.server.unlock(data={'passwd': current_master_password})
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        wait_for_scanner_status(api=self.cat.api, timeout=TIME_TEN_MINUTES, status=API.Status.READY,
                                msg='Waiting for server to be in ready state.')

        # Login to server as we need to revert the server to its default state (set master password as None)
        self.cat.api.login()
        wait_for_scanner_status(api=self.cat.api, timeout=TIME_FIVE_MINUTES, status=API.Status.READY,
                                msg='Waiting for server to be in ready state after login.')

    # API_Tested# POST /server/refresh-license
    @pytest.mark.nessus_home
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('nessus_api_login', 'set_valid_custom_host')
    def test_refresh_license(self):
        """
        Test refresh the license

        Scenarios tested:
          [x] When license not changed, successfully refresh the license without restarting nessus
          [ ] When license changed, successfully refresh the license without restarting nessus
          [ ] When license changed, successfully refresh the license and restart nessus

        We need a way to change the license in order to do the last two test cases

        """

        # Restart the service
        upload_response = self.cat.api.server.refresh_license()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert upload_response['no_update'], 'Error refresh license.'

    # API_Tested# POST /server/upload-plugins
    # API_Tested# POST /server/update-plugins
    @pytest.mark.nessus_mat
    def test_upload_and_update_plugins(self):
        """
        #STA-31: Create additional tests for Server
        Test to upload plugins and update it

        Scenarios tested:
          [x] Successfully upload and update the plugin
          [ ] Uploading an invalid plugin and updating the plugin and make sure it fails
        """
        # Get plugin file path and upload the plugin to server
        file = os.path.abspath(get_file_path(PATH_TO_PLUGIN))
        upload_response = self.cat.api.server.upload_plugins(plugins_file=file)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert upload_response['fileuploaded'], 'Plugin not uploaded successfully.'

        # check and verify update-plugins request
        update_response = self.cat.api.server.update_plugins(data={'filename': upload_response['fileuploaded']})
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert update_response['plugins_processing'] == STRING_OK.upper(), 'Plugin not updated successfully.'

        # Need to wait for uploaded plugins get compiled and scanner get into 'ready' state
        wait_for_scanner_status(api=self.cat.api, timeout=TIME_TEN_MINUTES, status=API.Status.LOADING,
                                msg='Waiting for uploaded plugins get compiled and updated successfully.')

        wait_for_scanner_status(api=self.cat.api, timeout=TIME_TEN_MINUTES, status=API.Status.READY,
                                msg='Waiting for scanner is to be in ready state.')

        # Need a login as compilation of plugins abort the current session
        self.cat.api.login()

    # API_Tested# POST /server/clear-feed-error
    @pytest.mark.nessus_home
    def test_clear_feed_error_link(self):
        """
        #STA-31: Create additional tests for Server
        Test to verify clear feed error link

        Scenarios tested:
          [x] Successfully clear feed error link
       """
        self.cat.api.server.clear_feed_error()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# PUT /server/customca
    # API_Tested# GET /server/customca
    @pytest.mark.nessus_mat
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('add_custom_ca', [{'cert_file': PATH_TO_CERTIFICATE}], indirect=True)
    def test_valid_custom_ca(self, add_custom_ca):
        """
        #STA-31: Create additional tests for Server
        Test to verify valid custom CA

        Scenarios tested:
          [x] Successfully add the custom CA
          [x] Successfully get the custom CA
        """
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        response = self.cat.api.server.get_custom_ca()
        assert response, 'Error in getting custom CA, No custom certificate has been added'

    # API_Tested# PUT /server/customca
    @pytest.mark.nessus_mat
    @pytest.mark.nessus_home
    def test_invalid_custom_ca(self):
        """
        #STA-31: Create additional tests for Server
        Test to verify invalid cert gives error in custom CA

        Scenarios tested:
          [x] Adding an invalid custom CA and failed
        """
        ca_file = os.path.abspath(get_file_path(PATH_TO_CERTIFICATE_WITH_EXTRA_CHAR))
        file_data = read_from_file(filename=ca_file)
        try:
            self.cat.api.server.edit_custom_ca(cert_data=file_data)
        except HTTPError:
            log.exception("Error in adding invalid custom certificate.")

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# PUT /server/password
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('configure_master_password', [{'new_password': random_string(10)}], indirect=True)
    def test_add_master_password(self, configure_master_password):
        """
        #STA-31: Create additional tests for Server
        Test to add master password

        Scenarios tested:
          [x] Failed to change master password if no old password passed in
          [ ] Failed to change master password if wrong old password passed in
        """
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Check server returns true against protected flag after setting up a master password
        response = self.cat.api.server.get_master_password()
        assert response['protected'], 'No master password has been added.'

    # API_Tested# PUT /server/password
    # API_Tested# GET /server/password
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('configure_master_password', [{'new_password': random_string(10)}], indirect=True)
    def test_modify_master_password(self, configure_master_password):
        """
        #STA-31: Create additional tests for Server
        Test to modify master password

        Scenarios tested:
          [x] Successfully change master password if old password passed
          [ ] When the wrong old password or no old password is passed in, it should return bad request.
        """
        # Set a master password
        current_master_password = configure_master_password
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert self.cat.api.server.get_master_password()['protected'], 'No master password has been set.'

        try:
            # Modify and reset above set master password
            self.cat.api.server.edit_master_password(data={'new_password': Nessus.DEFAULT_PASSWORD,
                                                           'old_password': current_master_password})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

            response = self.cat.api.server.get_master_password()
            assert response['protected'], 'Master password has been reset to None.'

        finally:
            # Revert the modified master password to its default, otherwise it will lock the user
            self.cat.api.server.edit_master_password(data={'new_password': current_master_password,
                                                           'old_password': Nessus.DEFAULT_PASSWORD})
            assert self.cat.api.http_status_code == HTTPStatus.OK, \
                'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# PUT /server/password
    @pytest.mark.nessus_home
    @pytest.mark.parametrize('configure_master_password', [{'new_password': Nessus.DEFAULT_PASSWORD}], indirect=True)
    def test_delete_master_password(self, configure_master_password):
        """
        #STA-31: Create additional tests for Server
        Test to delete master password
        Scenarios tested:
          [x] Successfully delete master password by not passing the new password
        """
        # Set a master password
        current_master_password = configure_master_password
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # Delete above set master password
        self.cat.api.server.edit_master_password(data={'old_password': current_master_password})
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        response = self.cat.api.server.get_master_password()
        assert not response['protected'], 'Master password has not been deleted.'

    # API_Tested# POST /server/bug-report
    # API_Tested# GET /tokens/{token_id}
    @pytest.mark.nessus_home
    @pytest.mark.parametrize("full_mode, scrub_mode", [(0, 0), (1, 0), (0, 1), (1, 1)])
    def test_get_bug_report(self, full_mode, scrub_mode):
        """
        # STA-69 Test case for /server/bug-report
        Test to download bug report

        Scenarios tested:
          [x] Successfully download bug-report with full-mode and scrub-mode
          [x] Successfully fetch the server status
        """
        token = self.cat.api.server.post_bug_report(data={"full_mode": full_mode, "scrub_mode": scrub_mode},
                                                    stream=True)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        wait(lambda: self.cat.api.tokens.status(token_id=token["token"], stream=True)["status"] == "ready",
             sleep_seconds=TIME_FIVE_SECONDS, waiting_for='Download to finish', timeout_seconds=TIME_FIVE_MINUTES * 3)
        response = self.cat.api.tokens.status(token_id=token["token"])

        assert response["message"] == "The download is ready.", "The file does not downloaded yet"

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# POST /server/register
    # API_Tested# GET /server/status
    @pytest.mark.usefixtures('nessus_api_login', 'set_valid_custom_host')
    @pytest.mark.flaky_test
    def test_register_using_activation_code(self):
        """
        STA-72 Test case for /server/register
        Test to register using activation code

        Scenarios tested:
          [x] Successfully generate activation code
          [x] Successfully register the server
          [x] Successfully fetch the server status
        """
        activation_code = ActivationCodeGenerator.generate_nessus_manager_code(ips=1024, scanners=1024, agents=1024)
        self.cat.api.server.server_register(data={"code": activation_code})
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        wait(lambda: self.cat.api.server.status()["status"] == "downloading",
             sleep_seconds=TIME_FIVE_SECONDS, waiting_for='Download to start plugin', timeout_seconds=TIME_FIVE_MINUTES)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        wait_for_scanner_status(api=self.cat.api, status=API.Status.READY,
                                timeout=TIME_TEN_MINUTES * 4, msg='Availability of Nessus scanner',
                                sleep_interval=TIME_FIVE_SECONDS)
        self.cat.api.login()

    # returns the server notifications as a dict keyed by notification title
    def get_notifications(self) -> dict:
        notifications = self.cat.api.server.get_notifications()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        assert 'feed_notifications' in notifications, 'Nessus from-feed notifications missing from server properties'
        return {x['title']: x for x in notifications['feed_notifications']}

    # API_Tested# GET /server/notifications
    # API_Tested# GET /server/notifications/:id/acknowledge
    @pytest.mark.usefixtures('load_sample_notifications')
    def test_get_notifications(self):
        """
        Test to verify that the /server/notifications endpoint works.
        Scenarios tested:
          [x] Successfully get the notifications
          [x] Successfully get the notifications with last_modified
        """

        notifications = self.cat.api.server.get_notifications()
        feed_notifications = {x['title']: x for x in notifications['feed_notifications']}

        assert 'Ack Me - test last_modified' in feed_notifications, feed_notifications
        assert 'Ack Me - test last_modified - expire in 6 seconds' in feed_notifications, feed_notifications

        notification_id = feed_notifications['Ack Me - test last_modified']['id']
        self.cat.api.server.acknowledge_notification(id=notification_id)

        notification_id = feed_notifications['Ack Me - test last_modified - expire in 6 seconds']['id']
        self.cat.api.server.acknowledge_notification(id=notification_id)

        notifications = self.cat.api.server.get_notifications(last_modified=notifications['timestamp'])
        assert len(notifications['feed_notifications']) == 0

    # API_Tested# GET /server/notifications/:id/acknowledge
    @pytest.mark.skip_acceptance
    @pytest.mark.usefixtures('load_sample_notifications')
    def test_notification_acknowledgement(self):
        """
        Test to verify that the /server/notifications/:id/acknowledge endpoint works.

        Scenarios tested:
          [x] Attempt to acknowledge a notification that does not exist
          [x] Successfully acknowledges a notification
          [x] Verify that an acknowledged notification disappears from list
          [x] Verify that it is not an error to re-acknowledge a notification
          [x] Verify that when acked and duration is not expired, the notification will not show up
          [x] Verify that when acknowledgment duration expires, the notification will show up again
        """
        with expect_http_error(code=404):
            self.cat.api.server.acknowledge_notification(id=20345)

        notes = self.get_notifications()
        assert 'Ack Me' in notes, notes
        assert notes['Ack Me'], "Unable to find notification with title 'Ack Me' in samples"
        assert not notes['Ack Me']['acknowledged'], notes['Ack Me']
        notification_id = notes['Ack Me']['id']
        self.cat.api.server.acknowledge_notification(id=notification_id)
        notes = self.get_notifications()
        assert 'Ack Me' not in notes, notes

        # test that acknowledging twice does not cause error and does not un-ack
        self.cat.api.server.acknowledge_notification(id=notification_id)
        notes = self.get_notifications()
        assert 'Ack Me' not in notes, notes

        # "Ack Me 1" will expire in 30 seconds, "Ack Me 2" will expire in 40 seconds,
        notification_id = notes['Ack Me 1']['id']
        self.cat.api.server.acknowledge_notification(id=notification_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        notification_id = notes['Ack Me 2']['id']
        self.cat.api.server.acknowledge_notification(id=notification_id)
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        # the two acked notifications shouldn't show up
        notes = self.get_notifications()
        assert 'Ack Me 1' not in notes, notes
        assert 'Ack Me 2' not in notes, notes

        sleep(TIME_FIVE_SECONDS * 14, "wait for 70 seconds so the the duration expire")
        notes = self.get_notifications()
        assert 'Ack Me 1' in notes, notes
        assert 'Ack Me 2' in notes, notes

    # API_Tested# GET /server/properties
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('load_sample_notifications')
    @pytest.mark.parametrize('check_notification', [{'title': 'Always present', 'present': True},
                                                    {'title': 'Constraint (.*DARWIN|LINUX|WINDOWS|FREEBSD)',
                                                     'present': True},
                                                    {'title': 'Never present', 'present': False}])
    def test_notification_constraints(self, check_notification):
        """
        Test /server/properties feed_notifications constraints

        Scenarios tested:
          [x] Successfully read a notification out of notifications.json
          [x] Successfully read a notification with a matching platform constraint
          [x] Verify that a notification with non-matching platform constraint is not given
        """
        notes = self.get_notifications()

        pat = check_notification['title']
        matched = any(re.match(pat, title) for title in notes)
        if check_notification['present']:
            assert matched, "Pattern '%s' was not matched in notifications [%s]" % (pat, ','.join(notes.keys()))
        else:
            assert not matched, "Pattern '%s' was matched in notification[%s]" % (pat, ','.join(notes.keys()))

    # API_Tested# GET /server/properties
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('load_sample_notifications')
    @pytest.mark.parametrize('check_notification', [{'title': 'Expired', 'present': False},
                                                    {'title': 'Inactive', 'present': False},
                                                    {'title': 'Active', 'present': True},
                                                    {'title': 'ZeroActive', 'present': True}])
    def test_notification_activation_expiration(self, check_notification):
        """
        Test /server/properties feed_notifications active/expired

        Scenarios tested:
          [x] Verify that server respects active flag
          [x] Verify that server respects expired flag
          [x] Verify that server defaults correctly on unset active/expired
        """
        notes = self.get_notifications()

        title = check_notification['title']
        if check_notification['present']:
            assert title in notes, "Notification was not found in feed_notifications"
        else:
            assert title not in notes, "Notification was present in feed_notifications"

    # API_Tested# GET /server/properties
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('load_sample_notifications')
    def test_notification_permanent(self):
        """
        Test /server/properties feed_notifications permanent flag

        Scenarios tested:
          [x] Verify that acknowledging a permanent notification has no effect
        """

        notes = self.get_notifications()
        assert 'Permanent' in notes, 'Permanent notification was not found for test'
        assert notes['Permanent']['permanent'], "Permenant notification didn't have permanent set"
        assert not notes['Permanent']['acknowledged'], 'Notification is already acknowledged'

        self.cat.api.server.acknowledge_notification(id=notes['Permanent']['id'])
        notes = self.get_notifications()
        assert 'Permanent' in notes, 'Permanent notification was not found after ack'
        assert notes['Permanent']['permanent'], "Permenant notification didn't have permanent set after ack"
        assert not notes['Permanent']['acknowledged'], 'Notification is acknowledged after ack'

    # API_Tested# GET /server/notification/history
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('load_sample_notifications')
    def test_notification_history(self):
        """
        Test /server/notification/history

        Scenarios tested:
          [x] Verify get notification history successfully
          [x] Verify get notification history with acknowledgement successfully
        """
        notes = self.get_notifications()
        assert 'Ack Me-test history' in notes, notes
        assert notes['Ack Me-test history'], "Unable to find notification with title 'Ack Me-test history' in samples"
        assert not notes['Ack Me-test history']['acknowledged'], notes['Ack Me-test history']
        notification_id = notes['Ack Me-test history']['id']

        history = self.cat.api.server.get_notification_history()

        assert 'notifications' in history
        for x in history['notifications']:
            if x['notification_id'] == notification_id:
                assert x['acknowledge_timestamp'] is None
                break

        self.cat.api.server.acknowledge_notification(id=notification_id)

        history = self.cat.api.server.get_notification_history()

        assert 'notifications' in history
        for x in history['notifications']:
            if x['notification_id'] == notification_id:
                assert x['acknowledge_timestamp'] is not None
                break

    # API_Tested# GET /server/properties
    @pytest.mark.skip_acceptance
    @pytest.mark.incompatible
    @pytest.mark.parametrize('prepare_tenable_links_file', [
        get_file_path('nessus/tests/api/server/test_data/tenable_links.json'),
        get_file_path('nessus/tests/api/server/test_data/empty_tenable_links.json'), ""], indirect=True)
    @pytest.mark.disable_logout
    def test_tenable_links(self, prepare_tenable_links_file):
        """
        Test /server/properties tenable_links

        Scenarios tested:
          [x] Verify that no tenable_links.json file won't return tenable_links property
          [x] Verify that empty links in tenable_links.json file will return 0 links in tenable_links property
          [x] Verify that the links in tenable_links.json file will be returned in tenable_links property
        """
        with SSH() as ssh:
            log.info("The file tenable_links.json is {}".format(
                ssh.path_is_file("/opt/nessus/var/nessus/tenable_links.json")))

        nessus_api = NessusAPI()
        nessus_api.login()
        server_prop = nessus_api.server.properties()
        log.info(server_prop)

        assert nessus_api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % nessus_api.http_status_code

        if not prepare_tenable_links_file or prepare_tenable_links_file.find("empty_tenable_links.json") >= 0:
            assert (not ('tenable_links' in server_prop)) \
                   or server_prop["tenable_links"] is None \
                   or len(server_prop["tenable_links"]) == 0, "tenable_links shouldn't exist from server properties"
        else:
            assert ('tenable_links' in server_prop), "tenable_links missing from server properties"
            assert (len(server_prop["tenable_links"]) == 2), "tenable_links missing from server properties"

    @pytest.mark.linux_only
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('imitate_tenable_core', 'appliance_telemetry_valid')
    # API_Tested# GET /server/telemetry
    def test_tenable_core_telemetry_endpoint(self):
        """
        Test /server/telemetry endpoint.

        Scenarios tested:
        [x] Verify "appliance" section returned if string "tenablecore" exists in /etc/os-release
        """
        response = self.cat.api.server.telemetry()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert 'nessus' in response, \
            "Appliance info is in the payload"
        assert response['install_type'] == 'standalone', \
            "Telemetry install_type was identified."

    @pytest.mark.linux_only
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('imitate_tenable_appliance', 'appliance_telemetry_broken')
    # API_Tested# GET /server/telemetry
    @pytest.mark.skip_nessustc
    def test_tenable_appliance_telemetry_endpoint(self):
        """
        Test /server/telemetry endpoint.

        Scenarios tested:
        [x] Verify "appliance" section returned if string "tenableappliance" exists in /etc/os-release
        """

        response = self.cat.api.server.telemetry()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert 'appliance' in response, \
            "Appliance info is not in the payload"
        assert response['install_type'] == 'appliance', \
            "Telemetry install_type was not identified."

    # API_Tested# GET /server/telemetry
    @pytest.mark.skip_nessustc
    def test_telemetry_endpoint(self):
        """
        Test /server/telemetry endpoint when not on TC/TA

        Scenarios tested:
        [x] Verify endpoint returns OS data
        [x] Verify "appliance" section not returned
        """

        response = self.cat.api.server.telemetry()
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        assert 'appliance' not in response, \
            "Appliance info in payload, it should not be unless /etc/os-release has appliance strings"
        assert response['install_type'] == 'standalone', \
            "Telemetry install_type was not identified."

        payload = response['nessus']

        # These are always present
        assert 'uuid' in payload
        assert 'metrics' in payload

        # These two osinfo attributes are present for every OS
        assert 'osinfo.name' in payload['metrics']
        assert payload['metrics']['osinfo.name']
        assert 'osinfo.version_id' in payload['metrics']
        assert payload['metrics']['osinfo.version_id']

    def start_stop_and_process_scan(self, scan_id):
        # start
        self.cat.api.scans.launch(scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                        timeout=TIME_FIVE_MINUTES)
        sleep(sleep_time=2 * TIME_TEN_SECONDS, reason="Waiting for the scan to run a bit")

        # stop
        # sometimes we get a 409 error as the scan has already finished
        try:
            self.cat.api.scans.stop(scan_id)
        except:
            pass

        def has_stopped():
            status = self.cat.api.scans.get_status(scan_id)
            return status not in [API.Scan.Status.RUNNING, API.Scan.Status.STOPPING]

        wait(has_stopped, timeout_seconds=TIME_FIVE_MINUTES, waiting_for='scan to stop.')

        # process
        sleep(sleep_time=TIME_FIFTEEN_SECONDS, reason="Waiting for engine to process the scan")

    @pytest.mark.skip_acceptance
    @pytest.mark.flaky_test
    @pytest.mark.usefixtures('enable_qa_mode_in_nessus', 'nessus_api_login')
    # API_Tested# GET /server/peek-telemetry
    def test_telemetry_send_on_reload(self):
        """
        Test that telemetry is sent on every reload

        Scenarios tested:
        [x] Verify that telemetry is sent
        """

        orig_telemetry = self.cat.api.server.peek_telemetry()
        assert 'start' in orig_telemetry and orig_telemetry['start'] > 0, 'telemetry timestamp not set'

        # magic values needed in testing to trigger a telemetry send, since auto_update is false
        execute(get_nessus_cli(), ['fix', '--secure', '--set', 'update_occurred=true'])
        execute(get_nessus_cli(), ['fix', '--set', 'send_telemetry=true'])

        # restart the backend
        self.cat.api.server.restart(payload={'soft': True})

        # wait for telemetry to update
        def did_telemetry_send():
            try:
                new_telemetry = self.cat.api.server.peek_telemetry()
                return new_telemetry['start'] > orig_telemetry['start']
            except:
                pass

        wait(did_telemetry_send, waiting_for='telemetry to send', timeout_seconds=TIME_FIVE_MINUTES)

    @pytest.mark.xray(test_key='NES-14892')
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('enable_qa_mode_in_nessus', 'nessus_api_login')
    def test_verify_telemetry_count_for_paused_and_cancelled_scan_status(self):
        """
        NES-12757 [API-Automation] : Verify scan telemetries will not show result for paused/Aborted/cancelled scans
        NES-14892 : Verify scan telemetries will not show result for paused/Aborted/cancelled scans.

        Scenario Tested:
        [x] Verify that telemetry count should not get increased for paused, Aborted or cancelled scans.
        """
        execute(get_nessus_cli(), ['fix', '--set', 'send_telemetry=yes'])
        execute(get_nessus_cli(), ['fix', '--set', 'telemetry_period=60'])

        wait_for_scanner_to_be_ready(api=self.cat.api)
        before_telemetry_count = self.cat.api.server.peek_telemetry()['metrics']

        created_scans_ids = []
        scan_info_dict = {'test_advanced_scan.json': 'advanced', 'test_basic_network_scan.json': 'basic',
                          'test_pci_scan.json': 'pci'}

        for scan_json_file, scan_template in scan_info_dict.items():
            created_scan = create_scan_helper(api_handler=self.cat.api, file_name=get_file_path(
                'nessus/tests/api/scan/test_data/{}'.format(scan_json_file)), template_title=scan_template)

            scan_id = created_scan[0]['scan']["id"]
            created_scans_ids.append(scan_id)

            self.cat.api.scans.launch(scan_id=scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                            timeout=TIME_FIVE_MINUTES)
            sleep(sleep_time=2 * TIME_FIFTEEN_SECONDS, reason="Waiting for the scan to run a bit")

            scan_status_dict = {'advanced': API.Scan.Status.COMPLETED, 'basic': API.Scan.Status.PAUSED,
                                'pci': API.Scan.Status.CANCELED}

            if scan_template == 'pci':
                self.cat.api.scans.stop(scan_id=scan_id)
            elif scan_template == 'basic':
                self.cat.api.scans.pause(scan_id=scan_id)

            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=scan_status_dict[scan_template],
                            timeout=TIME_TEN_MINUTES * 2)

        after_telemetry_count = self.cat.api.server.peek_telemetry()['metrics']

        assert all([
            before_telemetry_count['scans.1day.unique_hosts'] == after_telemetry_count['scans.1day.unique_hosts'],
            before_telemetry_count['scans.30days.unique_hosts'] == after_telemetry_count[
                'scans.30days.unique_hosts']]), "Telemetry count is getting increased for paused, aborted and " \
                                                "cancelled scan which should not get increased"

        self.cat.api.scans.delete_bulk_scans(id_list=created_scans_ids)

    @pytest.mark.xray(test_key='NES-14930')
    @pytest.mark.incompatible
    @pytest.mark.usefixtures('enable_qa_mode_in_nessus', 'nessus_api_login')
    def test_verify_telemetry_count_remain_same_for_imported_scan(self):
        """
        NES-12759 [API-Automation] : Verify that it should not show telemetry counts for imported scan results
        NES-14930 : Verify that it should not show telemetry counts for imported scan results

        Scenario Tested:
        [x] Verify that telemetry count should not get increased for imported scan too.
        """
        execute(get_nessus_cli(), ['fix', '--set', 'send_telemetry=yes'])
        execute(get_nessus_cli(), ['fix', '--set', 'telemetry_period=60'])

        wait_for_scanner_to_be_ready(api=self.cat.api)
        before_telemetry_count = self.cat.api.server.peek_telemetry()['metrics']

        scan_file = get_file_path('nessus/tests/api/scan/test_data/advance_scan_c7kspv.nessus')
        file_uploaded = self.cat.api.file.upload(file=scan_file, encrypted=True)

        imported_scan_id = self.cat.api.scans.import_scan(file_uploaded)['scan']['id']

        assert imported_scan_id in [scan['id'] for scan in self.cat.api.scans.get_scans()['scans']], \
            "Failed to import scan having id '{}'.".format(imported_scan_id)

        after_telemetry_count = self.cat.api.server.peek_telemetry()['metrics']

        assert all([
            before_telemetry_count['scans.1day.unique_hosts'] == after_telemetry_count['scans.1day.unique_hosts'],
            before_telemetry_count['scans.30days.scans'] == after_telemetry_count['scans.30days.scans'],
            before_telemetry_count['scans.30days.unique_hosts'] == after_telemetry_count[
                'scans.30days.unique_hosts']]), "Telemetry count is getting increased for paused, aborted and " \
                                                "cancelled scan which should not get increased"

        self.cat.api.scans.delete(scan_id=imported_scan_id)


@pytest.mark.usefixtures('nessus_api_login', 'disable_auto_update')
class TestNessusServerRegisterEndpoint:
    """Tests related to Nessus registration using new activation code"""
    cat = None

    @pytest.mark.flaky_test
    @pytest.mark.parametrize('register_data',
                             [{'code': False, 'custom_host': "plugins-internal-staging.cloud.aws.tenablesecurity.com"},
                              {'code': True, 'custom_host': "dummyhost"},
                              {'code': False, 'custom_host': "dummyhost"},
                              {'code': True, 'custom_host': "plugins-internal-staging.cloud.aws.tenablesecurity.com"}])
    @pytest.mark.parametrize('license_type', [pytest.param("Nessus Manager", marks=pytest.mark.nessus_manager),
                                              pytest.param("Nessus Professional", marks=pytest.mark.nessus_pro)])
    def test_nessus_server_register(self, register_data, license_type):
        """
        NES-12076 : API automation for Nessus registration endpoint

        Scenarios Tested:
            [x] Verify server/register endpoint gives error when activation code is correct but custom_host is incorrect
            [x] Verify server/register endpoint gives error when activation code is incorrect and custom_host is correct
            [x] Verify server/register endpoint gives error when both activation code and custom_host are incorrect
            [x] Verify successful registration using server/register endpoint
                when activation code and custom_host both are correct.
        """
        original_register_code = self.cat.api.server.properties()['license']['activation_code']
        activation_code = ActivationCodeGenerator()
        register_code = ""
        self.cat.api.settings.edit_software_updates_setting({"custom_host": register_data['custom_host']})

        # Fetch the Nessus registration code for given license_type
        if license_type == "Nessus Manager":
            register_code = activation_code.generate_nessus_manager_code(expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)
        elif license_type == "Nessus Professional":
            register_code = activation_code.generate_nessus_professional(expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)
        elif license_type == "Nessus Essential":
            register_code = activation_code.generate_code(
                code_type="home", expiration_days=Nessus.DEFAULT_EXPIRATION_DAYS)
        if not register_data['code']:
            register_code = "-".join(register_code.split('-')[::-1])

        # Register Nessus and verify the expected success/failure
        try:
            self.cat.api.server.register(code=register_code)
        except HTTPError:
            log.warning("Error while registering nessus with code : {} and custom_host : {}".format(
                register_code, register_data['custom_host']))
        finally:
            if register_data['code'] and register_data[
                'custom_host'] == "plugins-internal-staging.cloud.aws.tenablesecurity.com":
                assert self.cat.api.http_status_code == HTTPStatus.OK, \
                    'Expected 200, got %s instead.' % self.cat.api.http_status_code
            else:
                assert self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR, \
                    'Expected 500, got %s instead.' % self.cat.api.http_status_code
                assert self.cat.api._text == '{"error":"Activation failed"}', \
                    "Error text for Nessus register with invalid code and/or custom_host not matching."

        # Wait till Nessus becomes ready (if needed) and then verify expected activation code from Nessus properties.
        if register_data['code'] and register_data[
            'custom_host'] == "plugins-internal-staging.cloud.aws.tenablesecurity.com":
            try:
                wait_for_scanner_status(api=self.cat.api, status=API.Status.LOADING,
                                        timeout=TIME_TWO_MINUTES, msg='Nessus to be in loading state',
                                        sleep_interval=TIME_FIVE_SECONDS)
            finally:
                wait_for_scanner_status(api=self.cat.api, status=API.Status.READY,
                                        timeout=TIME_TEN_MINUTES, msg='Availability of Nessus scanner',
                                        sleep_interval=TIME_TEN_SECONDS)
                # New Nessus session after fresh registration.
                self.cat.api.login()
                assert register_code == self.cat.api.server.properties()['license'][
                    'activation_code'] != original_register_code, "Activation code not updated."
        else:
            assert original_register_code == self.cat.api.server.properties()['license']['activation_code'], \
                "Activation code updated."


@pytest.mark.usefixtures('nessus_api_login')
class TestNessusServerEndpointForHome:
    """Tests for Nessus server Endpoint"""
    cat = None

    @pytest.mark.nessus_home
    # API_Tested# GET /server/rss-feeds
    def test_rss_feeds(self):
        """
        Test that RSS Feeds are pulled

        Scenarios tested:
        [x] Verify that RSS Feed data is pulled
        """

        feed_items = self.cat.api.server.get_rss_feeds()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code
        pytest.xfail(reason="NES-9911 tenable_rss_feeds.json needs to be added to feed")
        assert feed_items, 'the feed data is empty'

        for items in feed_items:
            assert items['title'], 'did not find a title in one of the json items'
            assert items['description'], 'did not find a description in one of the json items'

    @pytest.mark.nessus_home
    @pytest.mark.parametrize('test_data_file', [
        pytest.param({'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_nessus_advanced_scan.json'),
                      'scan_type': 'advanced'}, marks=pytest.mark.nessus_home)], indirect=True)
    # API_Tested# GET /server/assets
    def test_get_assets(self, create_scan):
        """
        Test get the assets

        Scenarios tested:
        [x] Verify that assets data is pulled
        [x] Verify that asset hosts increased after a new scan
        [x] Verify that asset hosts not over the licensed hosts count
        """

        # Get all server properties
        server_prop = self.cat.api.server.properties()
        assert server_prop['license']['ips'] == 16
        used_ip_count = server_prop['used_ip_count']

        resp = self.cat.api.server.get_assets()
        if used_ip_count > 0:
            assert len(resp['assets']) == used_ip_count
        else:
            assert resp['assets'] is None

        # Get newly created scan information
        scan = create_scan['scan']
        scan_id = scan['id']

        # Launch scan and verify 200 response
        self.cat.api.scans.launch(scan_id, alt_targets=[Nessus.Scan.Target.LOCALHOST])
        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        result = wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.COMPLETED,
                                 timeout=TIME_THIRTY_MINUTES)

        # Verify scan is pass or fail to complete
        assert result, "Scan failed to complete."

        server_prop = self.cat.api.server.properties()
        new_used_ip_count = server_prop['used_ip_count']
        assert new_used_ip_count > 0

        resp = self.cat.api.server.get_assets()
        assert len(resp['assets']) == new_used_ip_count

        if used_ip_count == 16:
            assert new_used_ip_count == used_ip_count
        else:
            assert new_used_ip_count >= used_ip_count


@pytest.mark.sensor_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusServerEndpointForSensorManager:
    """Tests for Nessus server Endpoint for SM only"""
    cat = None

    # API_Tested# GET /server/rss-feeds
    def test_license_type_and_name(self):
        """
        Test that the correct license type is returned on SM.

        Scenarios tested:
        [x] Verify that /server/properties returns license.type 'sensor_manager'
        [x] Verify that /server/properties returns license.name 'Sensor Manager'
        """

        properties = self.cat.api.server.properties()
        assert properties['license']['name'] == 'Sensor Manager'
        assert properties['license']['type'] == 'sensor_manager'
