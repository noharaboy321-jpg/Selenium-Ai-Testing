"""
Nessus Settings Endpoints verification

:copyright: Tenable Network Security, 2018
:date: Aug 07, 2018
:last_modified: Apr 27, 2021
:author: @jchavda, @lambaliya, @kpanchal
"""

import random
import re
import string
import subprocess
from http import HTTPStatus

import pytest
from requests import HTTPError
from waiting import wait
from waiting.exceptions import TimeoutExpired

from catium.helpers.sleep_lib import sleep
from catium.helpers.testdata import get_file_path
from catium.lib.config import Config
from catium.lib.const.base_constants import TIME_FIVE_MINUTES, TIME_FIFTEEN_MINUTES, TIME_TWO_MINUTES
from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from catium.lib.util.util import random_name
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli.helper import get_command, get_nessusd_messages
from nessus.helpers.scanner import restart_scanner
from nessus.helpers.server import expect_http_error
from nessus.helpers.settings import get_setting_id
from nessus.helpers.waiters import wait_for_scanner_status, wait_scan_state
from nessus.lib.const import API

log = create_logger()


@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('revert_password_settings_to_default', 'nessus_api_login')
class TestSettingsEndpoints:
    """
    STA-32: Create additional tests for Settings
    """
    cat = None

    # API_Tested# GET /settings/complexity
    @pytest.mark.parametrize("password_complexity_settings", [
        {"payload": {"passwd_complexity": "yes", "session_timeout": "30", "passwd_max_attempts": 3,
                     "passwd_min_length": 9, "passwd_notifications": "yes"}}], indirect=True)
    def test_complexity_settings(self, password_complexity_settings):
        """
        STA-76: Implement test case for /settings/complexity
        Verify that complexity setting can be retrieved.

        Scenarios tested:
          [x] Successfully get password complexity settings
          [ ] Successfully set password complexity settings
          [ ] Fail to set password complexity settings if it's invalid

        It appears the POST /settings/complexity is in password_complexity_settings function,
        but we probably should have separate test cases for it.
        """
        password_setting = self.cat.api.settings.get_setting_complexity()

        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code

        assert password_setting['passwd_max_attempts'] == password_complexity_settings[
            'passwd_max_attempts'] and password_setting['passwd_complexity'] is True, \
            'Unable to retrieve password complexity values'

    # API_Tested# GET /settings/network/proxy
    @pytest.mark.parametrize("proxy_server_settings", [
        {"payload": {"proxy": API.Settings.ProxyServer.PROXY_HOST, "proxy_port": API.Settings.ProxyServer.PROXY_PORT,
                     "proxy_username": API.Settings.ProxyServer.PROXY_USERNAME,
                     "proxy_password": API.Settings.ProxyServer.PROXY_PASSWORD, "proxy_auth": "auto",
                     "user_agent": API.Settings.ProxyServer.PROXY_USER_AGENT}}], indirect=True)
    def test_network_proxy_settings(self, proxy_server_settings):
        """
        Verify that proxy setting can be retrieved.

        Scenarios tested:
          [x] Successfully get network proxy settings
          [ ] Successfully set network proxy settings
          [ ] Fail to set network proxy settings if it's invalid
        """
        proxy_data = self.cat.api.settings.get_proxy_setting()

        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code

        assert proxy_data['proxy'] == proxy_server_settings['proxy'], 'Unable to retrieve Proxy server values'

    # API_Tested# GET /settings/software-update
    @pytest.mark.incompatible
    def test_get_software_update_settings(self):
        """
        Verify that Software update setting can be retrieved.

        Scenarios tested:
          [x] Successfully get software update settings
        """
        response = self.cat.api.settings.get_software_updates_setting()

        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code

        assert response['update'] in ['all', 'plugins', 'disabled'], 'Failed to retrieve Software updates'

    # API_Tested# GET /settings/software-update
    # API_Tested# PUT /settings/software-update
    @pytest.mark.incompatible
    def test_edit_software_updates_settings(self):
        """
        Verify that Software update setting can be edited.

        Scenarios tested:
          [x] Successfully update software update settings
          [ ] Successfully update software update settings with payload update=all
          [ ] Successfully update software update settings with payload update=plugins
          [ ] Successfully update software update settings with payload update=disabled
          [ ] Will do nothing if the payload update has an invalid value
        """
        payload = {"custom_host": "plugins-internal-staging.cloud.aws.tenablesecurity.com", "auto_update_delay": "24"}

        self.cat.api.settings.edit_software_updates_setting(payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code

        assert payload['custom_host'] == self.cat.api.settings.get_software_updates_setting()['custom_host'], \
            'Unable to update custom host value'

        if self.cat.api.settings.get_software_updates_setting()['update'] in ['all', 'plugins']:
            assert payload['auto_update_delay'] == self.cat.api.settings.get_software_updates_setting()['delay'], \
                'Unable to update auto update delay value'

    # API_Tested# GET /settings/software-update
    # API_Tested# PUT /settings/software-update
    @pytest.mark.xfail(reason="Fix for the test yet to be merged in release.")
    def test_invalid_custom_host_in_software_updates_settings(self):
        """
        Verify that Software update custom host setting regex is working as expected.

        Scenarios tested:
          [x] Edit the custom host setting with an invalid entry
        """
        payload = {"custom_host": "I love cats", "auto_update_delay": "24"}

        with expect_http_error(code=400):
            self.cat.api.settings.edit_software_updates_setting(payload)

        assert payload['custom_host'] != self.cat.api.settings.get_software_updates_setting()['custom_host'], \
            'Unable to update custom host value'

        payload = {"custom_host": "hostname ", "auto_update_delay": "24"}

        with expect_http_error(code=400):
            self.cat.api.settings.edit_software_updates_setting(payload)

        assert payload['custom_host'] != self.cat.api.settings.get_software_updates_setting()['custom_host'], \
            'Unable to update custom host value'

    # API_Tested# DELETE /settings/software-update
    def test_delete_software_update_settings(self):
        """
        Verify http code 409 on deleting software update settings
        Notes : Response message "No finish required"

        Scenarios tested:
          [x] return 409 if no finish needed
          [ ] Successfully finish software update if not update not finish
        """
        with expect_http_error(code=409):
            self.cat.api.settings.delete_software_updates_setting()

    @pytest.mark.skip(reason='fix test or remove it')
    #  API_Tested# GET /settings/software-update/{feed_type}
    def test_get_software_settings_feed_type(self):
        """
        Verify that feed type can be retrieved.

        Scenarios tested:
          [x] Successfully start 'ui' software update
        """
        response = self.cat.api.settings.get_feed_type(feed_type='ui')

        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code

        assert response['last'], 'Invalid feed type'

    # API_Tested# POST /settings/software-update/{feed_type}
    @pytest.mark.incompatible
    def test_set_software_settings_feed_type(self):
        """
        Verify that feed type can be added.

        Scenarios tested:
          [x] Successfully start 'plugins' software update
        """
        self.cat.api.settings.set_feed_type(feed_type='plugins')

        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_legacy
@pytest.mark.usefixtures('nessus_api_login')
class TestAPISettingsEndpoints:
    """ Tests for Nessus settings Endpoints """

    cat = None

    # GET /settings/advanced
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.nessus_home_mat
    @pytest.mark.nessus_expert_mat
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_get_setting_advanced(self):
        """ STA-75: Implement test case for /settings/advanced """
        settings = self.cat.api.settings.get_list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert settings['preferences'], "'preferences' is not found in response"

    # API_Tested# GET /settings/advanced
    # API_Tested# PUT /settings/advanced
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.nessus_home_mat
    @pytest.mark.nessus_expert_mat
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('add_advance_setting', [
        {'payload': {"setting.0.action": "add", "setting.0.id": "", "setting.0.name": "testaaaa",
                     "setting.0.value": "testaaaa_value"}, "remove_added_setting": False}], indirect=True)
    def test_remove_advanced_setting(self, add_advance_setting):
        """
        STA-75: Implement test case for /settings/advanced

        Scenarios tested:
          [x] Successfully added advance setting
          [x] Successfully removed advance setting
          [x] Successfully fetch list of advanced settings
        """
        payload = add_advance_setting

        delete_payload = {'setting.0.action': 'remove', 'setting.0.id': payload['id'],
                          'setting.0.name': payload['name']}

        self.cat.api.settings.update(delete_payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        settings = self.cat.api.settings.get_list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert not any(setting['name'] == payload['name'] for setting in settings['preferences']), \
            "Removed setting is found in list of settings after deleted"

    # API_Tested# GET /settings/advanced
    # API_Tested# PUT /settings/advanced
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.nessus_home_mat
    @pytest.mark.parametrize('add_advance_setting', [
        {'payload': {"setting.0.action": "add", "setting.0.id": "", "setting.0.name": "testaaaa",
                     "setting.0.value": "testaaaa_value"}, "remove_added_setting": True}], indirect=True)
    def test_edit_advanced_setting(self, add_advance_setting):
        """
        STA-75: Implement test case for /settings/advanced

        Scenarios tested:
          [x] Successfully added advance setting
          [x] Successfully edited advance setting
          [x] Successfully fetch list of advanced settings
        """
        payload = add_advance_setting

        edit_payload = {'setting.0.action': 'edit', 'setting.0.id': payload['id'], 'setting.0.name': payload['name'],
                        'setting.0.value': 'test_edited_value'}

        self.cat.api.settings.update(edit_payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        settings = self.cat.api.settings.get_list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert any(setting['name'] == payload['name'] and setting['value'] == edit_payload['setting.0.value']
                   for setting in settings['preferences']), \
            "Edited setting is not found in list of settings after edited"

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_expert_mat
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.nessus_home_mat
    def test_min_password_len_when_complexity_set(self):
        """
        NES-12245 : [API] Verify Nessus preferences validations

        Scenario Tested:
            [x] User can not set Minimum password length value less than 8 when password complexity is set.
        """
        set_pass_complexity = {'setting.0.action': 'edit', 'setting.0.name': "passwd_complexity",
                               'setting.0.value': 'yes'}

        try:
            # Set password complexity to yes
            self.cat.api.settings.update(set_pass_complexity)

            edit_payload = {'setting.0.action': 'edit', 'setting.0.name': "min_password_len", 'setting.0.value': "4"}

            # verify that min_password_len should be more than 8 when password_complexity is set.
            with expect_http_error(code=HTTPStatus.BAD_REQUEST,
                                   look_for="min_password_len was invalid: If using enhanced password complexity, "
                                            "the minimum password length must be greater than 8."):
                self.cat.api.settings.update(edit_payload)
        finally:
            set_pass_complexity["setting.0.value"] = 'no'

            self.cat.api.settings.update(set_pass_complexity)

    def test_verify_setting_value_for_agent_auto_unlink_threshold(self):
        """
        NES-12245 : [API] Verify Nessus preferences validations

        Scenario Tested:
            [x] agent_auto_unlink_threshold value can not be higher than agent_auto_delete_threshold value.
        """
        delete_threshold_payload = {'setting.0.action': 'edit', 'setting.0.name': 'agent_auto_delete_threshold',
                                    'setting.0.value': "30"}

        # Set agent_auto_delete_threshold value to "30"
        self.cat.api.settings.update(delete_threshold_payload)

        unlink_threshold_payload = {'setting.0.action': 'edit', 'setting.0.name': 'agent_auto_unlink_threshold',
                                    'setting.0.value': "40"}

        # Verify that agent_auto_unlink_threshold value can not be higher than agent_auto_delete_threshold value.
        with expect_http_error(code=HTTPStatus.BAD_REQUEST, look_for="agent_auto_unlink_threshold was invalid: "
                                                                     "Must be less than the Auto Delete threshold."):
            self.cat.api.settings.update(unlink_threshold_payload)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_expert_mat
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.parametrize('test_data', [
        {'payload': {'setting.0.action': 'edit', 'setting.0.name': 'backend_log_level', 'setting.0.value': "debug_logs"
                     }, "look_for": "backend_log_level was invalid: Allowable values for Nessus Log Level are: "
                                    "verbose, debug, normal"},
        {'payload': {'setting.0.action': 'edit', 'setting.0.name': 'scanner_update_channel',
                     'setting.0.value': "early_available"},
         "look_for": "scanner_update_channel was invalid: Allowable values for Nessus Update Plan are: ga, ea, stable"},
        {'payload': {'setting.0.action': 'edit', 'setting.0.name': 'process_priority_custom', 'setting.0.value': 20},
         "look_for": "process_priority_custom was invalid: Maximum value for Custom Process Priority is 19"},
        {'payload': {'setting.0.action': 'edit', 'setting.0.name': 'process_priority_custom', 'setting.0.value': -21},
         "look_for": "process_priority_custom was invalid: Minimum value for Custom Process Priority is -20"},
        {'payload': {'setting.0.action': 'edit', 'setting.0.name': 'scan_history_expiration_days',
                     'setting.0.value': 2}, "look_for": "scan_history_expiration_days was invalid"},
        {'payload': {'setting.0.action': 'edit', 'setting.0.name': 'listen_port', 'setting.0.value': "25"},
         "look_for": "listen_port was invalid: This setting has been deprecated."},
        {'payload': {'setting.0.action': 'edit', 'setting.0.name': 'agent_auto_unlink_threshold',
                     'setting.0.value': "100"},
         "look_for": "agent_auto_unlink_threshold was invalid: Must be at least 30 and not greater than 90."}])
    def test_setting_preferences_with_invalid_values(self, test_data):
        """
        NES-12245 : [API] Verify Nessus preferences validations

        Scenario Tested:
            [x] User can not set backend_log_level setting value other than debug/info/verbose.
            [x] User can not set scanner_update_channel value other than ea/ga/stable.
            [x] User can not set process_priority_custom value more than 19.
            [x] User can not set process_priority_custom value less than -20.
            [x] User can not set scan_history_expiration_days value to 1 or 2.
            [x] User can not set listen_port value as it is deprecated setting.
            [x] User can not set agent_auto_unlink_threshold value to less than 30 or more than 90
        """
        # Verify user can not set the setting preference to invalid value.
        with expect_http_error(code=HTTPStatus.BAD_REQUEST, look_for=test_data.get('look_for')):
            self.cat.api.settings.update(test_data.get('payload'))

    @pytest.mark.xray(test_key='NES-17527')
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_expert_mat
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.parametrize('test_data', [
        {'payload': {'setting.0.action': 'edit', 'setting.0.name': 'scan_history_expiration_days', 'setting.0.value': "1"
                     }}])
    def test_setting_scan_history_expiration_days(self, test_data):
        """
        NES-17527 : [API] Verify API accepts 1 for scan_history_expiration_days
        Scenario Tested:
        Validate that the setting scan_history_expiration_days will take a value of 1 through the API.
        """

        self.cat.api.settings.update(test_data.get('payload'))
        assert self.cat.api.http_status_code == HTTPStatus.OK, 'Expected 200, got %s instead.' % \
                                                               self.cat.api.http_status_code

    # API_Tested# POST /settings/complexity
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.nessus_home_mat
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_expert_mat
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("password_complexity_settings", [
        {"payload": {"passwd_complexity": "yes", "session_timeout": "29", "passwd_max_attempts": 3,
                     "passwd_min_length": 9, "passwd_notifications": "no"}}], indirect=True)
    def test_set_complexity_settings(self, password_complexity_settings):
        """
        STA-76: Implement test case for /settings/complexity

        Scenarios tested:
          [x] Successfully set password complexity
          [x] Successfully fetch password complexity
        """
        password_setting = self.cat.api.settings.get_setting_complexity()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert password_setting['passwd_min_length'] == password_complexity_settings['passwd_min_length'] and not \
            password_setting['passwd_notifications'], 'Unable to retrieve password complexity values'

    # API_Tested# POST /settings/network/proxy/test
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    def test_network_proxy_settings_without_save(self):
        """
        STA-79: Implement test case for /settings/network/proxy and /settings/network/proxy/test

        Tests that we are able to test proxy server settings without saving via the Nessus API.
        """
        with pytest.raises(HTTPError):
            self.cat.api.settings.test_proxy(host=API.Settings.ProxyServer.PROXY_HOST,
                                             port=API.Settings.ProxyServer.PROXY_PORT,
                                             username=API.Settings.ProxyServer.PROXY_USERNAME,
                                             password=API.Settings.ProxyServer.PROXY_PASSWORD,
                                             user_agent=API.Settings.ProxyServer.PROXY_USER_AGENT)

        assert self.cat.api.http_status_code == HTTPStatus.INTERNAL_SERVER_ERROR, \
            'Expected 500 error to return, however {} returned'.format(self.cat.api.http_status_code)

    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize("password_complexity_settings", [
        {"payload": {"passwd_complexity": "yes", "session_timeout": "1", "passwd_max_attempts": 3,
                     "passwd_min_length": 8, "passwd_notifications": "no"}}], indirect=True)
    def test_verify_session_timeout_works_properly(self, password_complexity_settings):
        """
        NES-12194: [API] Verify "Session Timeout (mins)" is honored

        Scenarios tested:
          [x] Verify session timeout works as per password complexity settings
        """
        try:
            restart_scanner(self.cat.api)

            password_settings = self.cat.api.settings.get_setting_complexity()

            # Verify that password settings updated successfully.
            assert password_settings['session_timeout'] == int(password_complexity_settings['session_timeout'])

            sleep(int(password_complexity_settings['session_timeout']) * 60 + 61, reason="Session time-out")

            # After session time-out, verify that user gets "Invalid credentials" when old session is used.
            with expect_http_error(code=HTTPStatus.UNAUTHORIZED, look_for="Invalid Credentials"):
                self.cat.api.settings.get_setting_complexity()
        finally:
            # Reset the "session_timeout" to 30 minutes.
            self.cat.api.login()
            password_complexity_settings['session_timeout'] = "30"

            self.cat.api.settings.set_password_complexity(password_complexity_settings)
            restart_scanner(self.cat.api)

    @pytest.mark.parametrize("password_complexity_settings", [
        {"payload": {"passwd_complexity": "yes", "session_timeout": "30", "passwd_max_attempts": 3,
                     "passwd_min_length": 8, "passwd_notifications": "no"}}], indirect=True)
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_verify_account_locks_out_after_max_login_attempts(self, password_complexity_settings,
                                                               create_users_using_api):
        """
        NES-12189: [API] Verify Account locks out after set number of maximum login attempts

        Scenarios tested:
          [x] Verify Account locks out after set number of maximum login attempts
        """
        user = create_users_using_api[0]
        api = NessusAPI()

        for i in range(int(password_complexity_settings['passwd_max_attempts'])):
            with expect_http_error(code=HTTPStatus.UNAUTHORIZED, look_for="Invalid Credentials"):
                api.login(username=user['name'], password=user['password'] + "abc")

        with expect_http_error(code=HTTPStatus.UNAUTHORIZED, look_for="Account is locked out"):
            api.login(username=user['name'], password=user['password'])

    @pytest.mark.parametrize("password_complexity_settings", [
        {"payload": {"passwd_complexity": "yes", "session_timeout": "30", "passwd_max_attempts": 3,
                     "passwd_min_length": 8, "passwd_notifications": "no"}}], indirect=True)
    @pytest.mark.parametrize('create_users_using_api', [[API.Permissions.User.ADMINISTRATOR]], indirect=True)
    def test_min_password_length_as_per_settings(self, password_complexity_settings, create_users_using_api):
        """
        NES-12195: [API][Negative] Verify password with length less than "Min Password Length" is rejected

        Scenarios tested:
          [x] Verify when password complexity is enabled, user is not allowed to set "Min Password Length"
              less than password length set.
        """
        user = create_users_using_api[0]

        with expect_http_error(code=HTTPStatus.BAD_REQUEST,
                               look_for="New password failed to meet password rules. "
                                        "Password is too short (must be at least 8 chars long)"):
            self.cat.api.users.password(user_id=user['id'], current_password=user['password'],
                                        password=random_name(prefix="user")[:password_complexity_settings[
                                                                                 'passwd_min_length'] - 1])

    # API_Tested# POST /settings/complexity
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('payload', ([{"passwd_complexity": "yes", "session_timeout": "30",
                                           "passwd_max_attempts": 3, "passwd_min_length": 4,
                                           "passwd_notifications": "no"}]))
    def test_set_invalid_complexity_settings(self, payload):
        """
        NES-12195: [API][Negative] Verify password with length less than "Min Password Length" is rejected

        Scenarios tested:
          [x] Verify when password complexity is enabled, then user can not put "min_password_len" < 8
        """
        original_password_setting = self.cat.api.settings.get_setting_complexity()

        with expect_http_error(code=HTTPStatus.BAD_REQUEST,
                               look_for="When complexity is enabled minimum password length must be 8 or greater."):
            self.cat.api.settings.set_password_complexity(payload)

        assert self.cat.api.settings.get_setting_complexity() == original_password_setting, \
            "Password complexity settings are changed after bad request has been sent for changing password complexity."

    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': get_file_path('nessus/tests/api/scan/test_data/test_basic_network_scan.json'),
         'scan_type': 'basic'}], indirect=True)
    def test_verify_log_whole_attack_and_log_details_settings(self, create_scan):
        """
        NES-12201 : [API] Verify "log_details" and "log_whole_attack" is honored when enabled globally

        Scenario Tested:
            [x] Verify that after enabling "log_details" and "log_whole_attack" settings,
                if user runs a scan then all scan plugin related information gets loaded in nessusd.messages.
        """
        scan_id = create_scan['scan']['id']
        log_whole_attack_payload = {'setting.0.action': 'edit', 'setting.0.name': 'log_whole_attack',
                                    'setting.0.value': "yes"}

        self.cat.api.settings.update(log_whole_attack_payload)

        log_details_payload = {'setting.0.action': 'edit', 'setting.0.name': 'log_details', 'setting.0.value': "yes"}

        self.cat.api.settings.update(log_details_payload)
        restart_scanner(self.cat.api)

        self.cat.api.scans.launch(scan_id)
        wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.RUNNING,
                        timeout=TIME_FIVE_MINUTES)

        # Verify that scan plugin related information gets loaded in nessusd.messages.

        try:
            with SSH() as ssh:
                wait(lambda: any([message for message in ssh.execute("{} {}".format(get_command(
                    operation="display_content"), get_nessusd_messages())) if re.search(
                    r'[name=Basic network Scan] (.*?) Started with (.*?) plugins/*', message)]),
                     timeout_seconds=TIME_FIVE_MINUTES, waiting_for="Scan start message to appear in nessusd.messages.")
                wait(lambda: any([message for message in ssh.execute("{} {}".format(get_command(
                    operation="display_content"), get_nessusd_messages())) if re.search(r'/*\[plugin_id=/*', message)
                                  and re.search(r'/*\[plugin=/*', message)]), timeout_seconds=TIME_FIVE_MINUTES,
                     waiting_for="Scan plugin information to get loaded in nessusd.messages")
        except TimeoutExpired:
            raise AssertionError("Scan Plugin information does not get loaded in nessusd.messages even after "
                                 "enabling these settings : 1.log_whole_attack and 2.log_details.")

        if self.cat.api.scans.get_status(scan_id) == API.Scan.Status.RUNNING:
            self.cat.api.scans.stop(scan_id)
            wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                            timeout=TIME_FIVE_MINUTES)

    # API_Tested# GET /settings/network/proxy
    # API_Tested# PUT /settings/network/proxy
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.nessus_home_mat
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_expert_mat
    @pytest.mark.nessus_pro
    def test_nessus_proxy_server_save_settings(self):
        """
        STA-79: Implement test case for /settings/network/proxy and /settings/network/proxy/test
        Tests that we are able to set the Proxy server Settings back to default values.

        Scenarios tested:
          [x] Successfully set proxy setting
          [x] Successfully fetch list of proxy settings
        """
        payload = {"proxy": API.Settings.ProxyServer.PROXY_HOST,
                   "proxy_port": int(API.Settings.ProxyServer.PROXY_PORT),
                   "proxy_username": API.Settings.ProxyServer.PROXY_USERNAME,
                   "proxy_password": API.Settings.ProxyServer.PROXY_PASSWORD,
                   "proxy_auth": "auto",
                   "user_agent": API.Settings.ProxyServer.PROXY_USER_AGENT}

        self.cat.api.settings.set_proxy(payload=payload)

        proxy_details = self.cat.api.settings.get_proxy_setting()

        assert self.cat.api.http_status_code == HTTPStatus.OK and proxy_details.keys() == payload.keys(), \
            'Proxy server Settings failed to save.'

    # API_Tested# POST /settings/scanner/rekey
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.nessus_home_mat
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_expert_mat
    @pytest.mark.nessus_pro
    def test_rekey(self):
        """
        STA-80: Implement test case for /settings/scanner/key and /settings/scanner/rekey
        Tests the settings/scanner/rekey endpoint method

        Scenarios tested:
          [x] Successfully generate a new scanner key
        """
        response = self.cat.api.settings.rekey()

        assert 'key' in response, 'Missing field "key" from response'

        assert response['key'], 'Expected key to be present, got empty key instead'

        try:
            wait_for_scanner_status(api=self.cat.api, timeout=TIME_TWO_MINUTES, status=API.Status.LOADING,
                                    msg='Waiting for server to get "loading" state')
        except TimeoutExpired:
            log.warning("Nessus did not get 'loading' status after regenerating linking key.")

        wait_for_scanner_status(api=self.cat.api, timeout=TIME_FIFTEEN_MINUTES, status=API.Status.READY,
                                msg='Waiting for server to finish loading.')

    # API_Tested# POST /settings/scanner/rekey
    # API_Tested# GET /settings/scanner/key
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.parametrize('valid_key', [True, False])
    def test_generate_custom_linking_key(self, valid_key):
        """
        NES-12159 : [API Automation] : Verify custom Agent linking key can be placed on NM

        Scenarios Tested:
            [x] Verify that custom linking key can be placed on Nessus Manager
            [x] Verify that custom linking key (having invalid format) can not be placed on Nessus Manager.
        """
        original_key = self.cat.api.settings.get_key()['key']
        custom_key = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(64))

        if valid_key:
            response = self.cat.api.settings.rekey(payload={'key': custom_key})

            # Verify that the linking key is updated to new custom key.
            assert 'key' in response, 'Missing field "key" from response'

            assert response['key'] != original_key, \
                'Linking key in response should not be same as the original linking key.'

            assert self.cat.api.settings.get_key()['key'] == custom_key != original_key, \
                "Linking key should be updated to new linking key."

            try:
                wait_for_scanner_status(api=self.cat.api, timeout=TIME_TWO_MINUTES, status=API.Status.LOADING,
                                        msg='Waiting for server to get "loading" state')
            except TimeoutExpired:
                log.warning("Nessus did not get 'loading' status after generating custom linking key.")

            wait_for_scanner_status(api=self.cat.api, timeout=TIME_FIFTEEN_MINUTES, status=API.Status.READY,
                                    msg='Waiting for server to finish loading.')
        else:
            custom_key = custom_key[10::]

            with expect_http_error(code=400):
                self.cat.api.settings.rekey(payload={'key': custom_key})

            # Verify that the linking key is not updated and it's same as original linking key.
            assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
                "Expected 400, got {} instead".format(self.cat.api.http_status_code)

            assert self.cat.api._text == '{"error":"The key must be a 64 character alphanumeric string."}', \
                "Error message for placing linking key with invalid format is not correct."

            assert self.cat.api.settings.get_key()['key'] == original_key != custom_key, \
                "Key expected to be same, got updated"

    # API_Tested# GET /settings/scanner/key
    @pytest.mark.nessus_manager_mat
    @pytest.mark.nessus_pro_mat
    @pytest.mark.nessus_home_mat
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_expert_mat
    @pytest.mark.nessus_pro
    def test_get_key(self):
        """
        STA-80: Implement test case for /settings/scanner/key and /settings/scanner/rekey
        Tests the settings/scanner/rekey endpoint method

        Scenarios tested:
          [x] Successfully get the scanner key
        """
        response = self.cat.api.settings.get_key()

        assert 'key' in response, 'Missing field "key" from response'

        assert response['key'], 'Expected key to be present, got empty key instead'

    # API_Tested# GET /settings/advanced
    # API_Tested# PUT /settings/advanced
    @pytest.mark.skip_acceptance
    @pytest.mark.disable_logout
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.flaky_test
    @pytest.mark.usefixtures('enable_qa_mode_in_nessus', 'nessus_api_login')
    @pytest.mark.parametrize('cipherlist', ['legacy', 'edh', 'noexp', 'ALL', 'compatible', 'modern'])
    def test_ssl_cipher_list(self, cipherlist):
        """
        NES-8411 API test for SSL (TLS) settings

        Scenarios tested:
          [x] Test that each option functions and does not leave host unreachable
          [x] Test that option choice has effect
        """
        setting_id = get_setting_id(self.cat.api, 'ssl_cipher_list')
        payload = {'setting.0.action': 'edit', 'setting.0.id': setting_id, 'setting.0.name': 'ssl_cipher_list',
                   'setting.0.value': cipherlist}
        matches = re.search(r'//(.+):(\d+)', Config.CAT_URL)

        assert matches, "Couldn't find the host:port in CAT_URL of %s" % Config.CAT_URL

        scanner_host = matches.group(1)
        scanner_port = matches.group(2)

        self.cat.api.settings.update(payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        self.cat.api.server.restart({'soft': True})

        try:
            wait_for_scanner_status(api=self.cat.api, timeout=TIME_FIVE_MINUTES,
                                    status=API.Status.LOADING, msg='scanner loading.')
        except TimeoutExpired:
            log.info("Loading state not found")

        wait_for_scanner_status(api=self.cat.api, timeout=TIME_FIVE_MINUTES * 2,
                                status=API.Status.READY, msg='scanner ready.')
        NessusAPI().login()

        cipherscmd = '''
            for i in $(openssl ciphers "ALL" | perl -pe "s/:/\n/g" | sort -u); do
                openssl s_client -cipher $i -connect {host}:{port} 2>&1 </dev/null | grep -q :error: || echo $i;
            done
        '''.format(host=scanner_host, port=scanner_port)

        ciphers = subprocess.check_output(cipherscmd, shell=True, timeout=120)
        ciphers = ciphers.decode('utf-8')
        log.info("Got ciphers: %s" % ciphers)

        if cipherlist in ['noexp', 'ALL']:
            assert any([cipher_keyword for cipher_keyword in ['DES-', 'SEED'] if cipher_keyword in ciphers]), \
                "Cipher list does not contain a DES cipher"
        if cipherlist not in ['noexp', 'ALL']:
            assert 'DES-' not in ciphers, "Cipher list contains a DES cipher"
        if cipherlist in ['modern']:
            assert 'AES128-SHA' not in ciphers, "Cipher list contains a non-GCM cipher"

    @pytest.mark.nessus_home
    @pytest.mark.nessus_expert
    @pytest.mark.nessus_pro
    @pytest.mark.nessus_manager
    @pytest.mark.skip_centos7
    @pytest.mark.usefixtures("nessus_api_login")
    @pytest.mark.parametrize("test_data_file", [
        {"settings": {"niap_mode": "enforcing"}, "cleanup_settings": True,
         "expected_successful_curves": ["secp384r1", "secp521r1", "prime256v1"]},
        {"settings": {"niap_mode": "enforcing", "ssl_curve_list": "prime256v1"}, "cleanup_settings": True,
         "expected_successful_curves": ["secp384r1", "secp521r1", "prime256v1"]},
        {"settings": {"niap_mode": "enforcing", "ssl_curve_list": "secp224r1"}, "cleanup_settings": True,
         "expected_successful_curves": ["secp384r1", "secp521r1", "prime256v1"]},
        {"settings": {"niap_mode": "enforcing", "ssl_curve_list": "secp224r1:secp521r1"}, "cleanup_settings": True,
         "expected_successful_curves": ["secp384r1", "secp521r1", "prime256v1"]},
        {'settings': {"niap_mode": "non-enforcing"}, "cleanup_settings": True,
         "expected_successful_curves": ["secp384r1", "secp521r1", "prime256v1"]},
        {"settings": {"niap_mode": "non-enforcing", "ssl_curve_list": "prime256v1"}, "cleanup_settings": True,
         "expected_successful_curves": ["prime256v1"]},
        {"settings": {"niap_mode": "non-enforcing", "ssl_curve_list": "niap"}, "cleanup_settings": True,
         "expected_successful_curves": ["secp384r1", "secp521r1", "prime256v1"]},
        {"settings": {"niap_mode": "non-enforcing", "ssl_curve_list": "secp384r1:secp521r1"}, "cleanup_settings": True,
         "expected_successful_curves": ["secp384r1", "secp521r1"]}
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3440')
    def test_ssl_curve_list(self, test_data_file, configure_advanced_settings_and_env_variables):
        """
        NES-8411 API test for SSL (TLS) settings

        Scenarios tested:
          [x] Test that each option functions and does not leave host unreachable
          [x] Test that option choice has effect
        """

        expected_successful_curves = test_data_file["expected_successful_curves"]
        matches = re.search(r'//(.+):(\d+)', Config.CAT_URL)

        assert matches, "Couldn't find the host:port in CAT_URL of %s" % Config.CAT_URL

        scanner_host = matches.group(1)
        scanner_port = matches.group(2)

        wait_for_scanner_status(api=self.cat.api, timeout=TIME_FIVE_MINUTES * 2,
                                status=API.Status.READY, msg='scanner ready.')
        NessusAPI().login()

        curve_list = []
        curve_list_output = {}
        with SSH() as ssh:
            curve_output = ssh.execute("openssl ecparam -list_curves")

            for curve in curve_output:
                curve = (re.sub(":.*", "", curve))
                curve = (re.sub(" ", "", curve))
                curve_list.append(curve)
                curve_list_output[curve] = {
                    "output": ssh.execute(f"openssl s_client -curves {curve} -connect {scanner_host}:{scanner_port}")}

        for curve in curve_list_output.keys():
            curve_list_output[curve]["result"] = False
            for line in curve_list_output[curve]["output"]:
                if "BEGIN CERTIFICATE" in line:
                    curve_list_output[curve]["result"] = True
                    break
            if curve in expected_successful_curves:
                assert curve_list_output[curve]["result"], f"Curve {curve} was expected to be successful and was not."
            else:
                assert not curve_list_output[curve][
                    "result"], f"Curve {curve} was expected to not be successful, but was."


@pytest.mark.skip(
    reason='RSS widget not available on plugins-internal-staging.cloud.aws.tenablesecurity.com for the moment for release-next tests')
@pytest.mark.nessus_home
@pytest.mark.usefixtures('nessus_api_login')
class TestAPIRSSSettingEndpoint:
    """ Tests for Nessus RSS setting Endpoint """

    cat = None

    # Test RSS Widget Advanced Setting
    # API_Tested# GET /settings/advanced
    # API_Tested# PUT /settings/advanced
    def test_rss_widget(self):
        """
        Test the functionality of the RSS Widget via advanced settings can be disabled and re-enabled.

        Scenarios tested:
          [x] Test that disabling the rss widget works
          [x] Test that re-enabling the rss widget works
        """
        setting_id = get_setting_id(self.cat.api, 'disable_rss')

        payload = {'setting.0.action': 'edit', 'setting.0.id': setting_id, 'setting.0.name': 'disable_rss',
                   'setting.0.value': 'yes'}

        self.cat.api.settings.update(payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        settings = self.cat.api.settings.get_list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert any(setting['name'] == payload['setting.0.name'] and setting['value'] == payload['setting.0.value']
                   for setting in settings['preferences']), \
            "RSS setting is not found in list of settings after being changed"

        server_prop = self.cat.api.server.properties()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        for property_value in server_prop:
            if property_value == "disable_rss_widget":
                assert server_prop[property_value] is True, \
                    "RSS widget is not showing disabled in the server properties"

        payload = {'setting.0.action': 'edit', 'setting.0.id': setting_id, 'setting.0.name': 'disable_rss',
                   'setting.0.value': 'no'}

        self.cat.api.settings.update(payload)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        settings = self.cat.api.settings.get_list()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got {} instead.'.format(self.cat.api.http_status_code)

        assert any(setting['name'] == payload['setting.0.name'] and setting['value'] == payload['setting.0.value']
                   for setting in settings['preferences']), \
            "RSS setting is not found in list of settings after being changed"

        server_prop = self.cat.api.server.properties()

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        for property_value in server_prop:
            if property_value == "disable_rss_widget":
                assert server_prop[property_value] is False, \
                    "RSS widget is not showing enabled in the server properties"
