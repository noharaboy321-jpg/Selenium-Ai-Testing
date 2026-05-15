"""
Nessus CLI "Fix" Tests

Test the nessuscli fix command and subcommands.

:copyright: Tenable Network Security, 2018
:date: August 30th, 2018
:last_modified: Apr 06, 2021
:author: @kpanchal
"""
import random
import re
import string

import pytest

from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_SIXTY_SECONDS
from catium.lib.log import create_logger
from catium.lib.ssh import SSH
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.nessuscli import fix
from nessus.helpers.nessuscli.helper import get_nessus_backend_log, get_nessus_www_sever, stop_nessus, start_nessus, is_ssl_connection_successful
from nessus.helpers.scanner import wait_for_scanner_to_be_ready
from nessus.lib.config import NessusConfig
from nessus.lib.const.constants import Nessus
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const import OperatingSystems

log = create_logger()


@pytest.mark.nessus_mat
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestNessusCLIFix:
    """ Test nessuscli fix commands """

    @pytest.mark.parametrize('secure', [True, False])
    def test_fix_list(self, secure):
        output = fix.list(secure=secure)
        assert not output['stderr'], 'Error on executing fix command'
        if secure:
            assert 'registration_code:' in output['stdout'], 'registration code is not available'
        else:
            assert 'listen_port:' in output['stdout'], 'listen port is not available'

    @pytest.mark.parametrize('settings', [
        {'secure': False, 'subcommand': fix.get},
        {'secure': True, 'subcommand': fix.get},
        {'secure': False, 'subcommand': fix.set},
        {'secure': True, 'subcommand': fix.set},
        {'secure': False, 'subcommand': fix.delete},
        {'secure': True, 'subcommand': fix.delete}])
    def test_fix_bad_form(self, settings):
        get_output = settings['subcommand'](secure=settings['secure'])
        assert not get_output['stderr'], 'Error on executing fix command'

    @pytest.mark.parametrize('settings', [{'secure': False, 'setting': 'max_hosts'}, pytest.param(
        {'secure': True, 'setting': 'max_hosts'}, marks=pytest.mark.skip(reason='removed secure parameter'))])
    def test_fix_get(self, settings):
        get_output = fix.get(secure=settings['secure'], key=settings['setting'])
        assert 'The current value for' in get_output['stdout'], 'Parameter value is not available'
        assert not get_output['stderr'], 'Error on executing fix command'

    @pytest.mark.parametrize('case', [
        # max_hosts
        {'secure': False, 'setting': 'max_hosts', 'value': '50', 'valid': True, 'expected_error': None},
        {'secure': False, 'setting': 'max_hosts', 'value': '100', 'valid': True, 'expected_error': None},
        {'secure': True,  'setting': 'max_hosts', 'value': '100', 'valid': True, 'expected_error': None},
        # scan.host_timeout_minutes
        {'secure': False, 'setting': 'scan.host_timeout_minutes', 'value': '0',  'valid': True,  'expected_error': None},
        {'secure': False, 'setting': 'scan.host_timeout_minutes', 'value': '10', 'valid': True,  'expected_error': None},
        {'secure': False, 'setting': 'scan.host_timeout_minutes', 'value': '-4', 'valid': False, 'expected_error': "Minimum value for Max Scan Time Per Host (in minutes) is 0"},
    ])
    @pytest.mark.xray(test_key='SCE-4234')
    def test_fix_set(self, case):
        secure = case['secure']
        key = case['setting']
        value = case['value']
        valid = case['valid']
        expected_error = case['expected_error']

        result = fix.set(secure=secure, key=key, value=value)
        combined = (result['stdout'] + '\n' + result['stderr']).strip()

        if valid:
            # Success path assertions
            assert not result['stderr'], f"stderr present on valid set ({key}={value}): {result['stderr']!r}"
            success_frag = f"Successfully set '{key}' to '{value}'."
            assert success_frag in result['stdout'].split('\n'), (
                f"Missing success line for {key}={value}. Output: {result['stdout']!r}"
            )
            # Follow-up get check
            get_out = fix.get(secure=secure, key=key)
            expected_get_line = f"The current value for '{key}' is '{value}'."
            assert expected_get_line in get_out['stdout'].split('\n'), (
                f"Get mismatch after setting {key}={value}. Output: {get_out['stdout']!r}"
            )
            assert not get_out['stderr'], f"stderr on get after valid set ({key}={value}): {get_out['stderr']!r}"
        else:
            # Invalid path assertions
            assert expected_error, f"Missing expected_error for invalid case {key}={value}"
            assert expected_error in combined, (
                f"Expected error substring not found for invalid {key}={value}. Output: {combined!r}"
            )

    @pytest.mark.parametrize('settings', [
        {'secure': False, 'setting': 'bogus_setting', 'value': '50'},
        {'secure': True, 'setting': 'bogus_setting', 'value': '100'}])
    def test_fix_get_missing(self, settings):
        get_output = fix.get(secure=settings['secure'], key=settings['setting'])
        assert settings['setting'] in get_output['stdout'], \
            '{} value is not available in output'.format(settings['setting'])
        assert not get_output['stderr'], 'Error on executing fix command'

    @pytest.mark.parametrize('settings', [
        {'secure': False, 'setting': 'test_setting', 'value': '"1 2 3 4 5"'},
        {'secure': True, 'setting': 'test_setting', 'value': '"1 2 3 4 5"'}])
    def test_fix_delete(self, settings):
        set_output = fix.set(secure=settings['secure'], key=settings['setting'], value=settings['value'])
        delete_output = fix.delete(secure=settings['secure'], key=settings['setting'])

        assert not set_output['stderr'], 'Error on executing fix command'
        assert 'Success' in set_output['stdout'], 'Error while set value {}'.format(settings['value'])
        assert not delete_output['stderr'], 'Error on executing fix command'
        assert 'Success' in delete_output['stdout'], 'Error while delete value {}'.format(settings['value'])
        assert settings['setting'] in delete_output['stdout'], \
            '{} is not available in output'.format(settings['setting'])

    def test_list_interfaces(self):
        output = fix.list_interfaces()
        assert not output['stderr'], 'Error while get list of interfaces'
        assert output['stdout'], 'Invalid output while get list of interfaces'

    @pytest.mark.parametrize('millisecond_resolution', [True, False])
    def test_each_log_line_shows_milliseconds_timestamp(self, millisecond_resolution):
        """
        NES-12902: [CLI-Automation] Verify that each log line from "backend.log" file shows the millisecond timestamp
                    after enabling "logfile_msec" from advanced settings

        Scenario Tested:
        [x] Verify that each log line from backend.log file shows the millisecond timestamp after enabling
            "logfile_msec" from advanced settings
        """
        with SSH() as ssh:
            if NESSUS_PLATFORM not in [OperatingSystems.MAC, OperatingSystems.MAC_OS]:
                log.debug('Check installed OS')
                check_installed_os = ssh.execute(command='cat /etc/os-release')
                installed_os = check_installed_os[0].split('=')[1].split()[0].strip('"')
                log.info("Installed OS :: {}".format(installed_os))

            logfile_msec_value = 'yes' if millisecond_resolution else 'no'
            setting_detail = {'setting_name': 'logfile_msec', 'setting_value': logfile_msec_value}
            set_output = fix.set(key=setting_detail['setting_name'], value=setting_detail['setting_value'])["stdout"]

            assert any([op == "Successfully set '{}' to '{}'.".format(setting_detail['setting_name'], setting_detail[
                'setting_value']) for op in set_output.split('\n') if "Successfully set" in op]), \
                "Failed to set '{}' setting value.".format(setting_detail['setting_name'])

            backend_log = get_nessus_backend_log()
            command = "echo > {}".format(backend_log)
            command = "sh -c '{}'".format(command) if NessusConfig.CAT_SSH_USE_SUDO else command
            ssh.execute(command)

            stop_nessus()
            start_nessus()
            sleep(sleep_time=TIME_SIXTY_SECONDS, reason='for reload to take effect.')
            wait_for_scanner_to_be_ready(api=NessusAPI())
            sleep(sleep_time=TIME_SIXTY_SECONDS, reason='for reload to take effect.')

            logs = ssh.execute("cat {}".format(backend_log))

            if millisecond_resolution:
                assert all([bool(re.search(r'\.[0-9]+$', log_line.split()[0].lstrip('['))) for log_line in logs if len(
                    log_line) > 0]), "Milliseconds is missing in log timestamps after enabling millisecond " \
                                     "resolution setting."
            else:
                assert all(
                    [not bool(re.search(r'\.[0-9]+$', log_line.split()[0].lstrip('['))) for log_line in logs if len(
                        log_line) > 0]), "Milliseconds is showing in log timestamps even after disabling millisecond " \
                                         "resolution setting."

    def test_each_log_line_shows_elapsed_time_in_www_server_log_file(self):
        """
        NES-12903: [CLI-Automation] Verify that elapsed time shows at the end of each log line in www_server.log

        Scenario Tested:
        [x] Verify that elapsed time shows at the end of each log line in www_server.log
        """
        www_server_log = get_nessus_www_sever()

        with SSH() as ssh:
            logs = ssh.execute("cat {}".format(www_server_log))

        for log_line in logs:
            expected_str = log_line.split()[-1].split('=')

            assert all([expected_str[0] == 'Elapsed', bool(re.search(r'[0-9]\.[0-9]+$', expected_str[1]))]), \
                "Elapsed time is missing at the end of log line from www_server.log file."

    @pytest.mark.parametrize('ssl_mode_value,client_protocol,expected_success', [
        ('tls_1_2', 'TLSv1.2', True),
        ('tls_1_2', 'TLSv1.3', True),
        ('tls_1_3', 'TLSv1.2', False),
        ('tls_1_3', 'TLSv1.3', True),
        ('niap', 'TLSv1.2', True),
        ('niap', 'TLSv1.3', False),
    ])
    @pytest.mark.xray(test_key='SCE-4121')
    def test_ssl_mode_openssl_compatibility(self, ssl_mode_value, client_protocol, expected_success):
        """
        SCE-4121: Test ssl_mode setting with openssl s_client protocol compatibility

        Scenario Tested:
        [x] Verify ssl_mode=tls_1_2 allows TLS 1.2 and 1.3 connections
        [x] Verify ssl_mode=tls_1_3 only allows TLS 1.3 connections
        [x] Verify ssl_mode=niap only allows TLS 1.2 connections
        """
        set_output = fix.set(key=Nessus.AdvancedSettings.SSL_MODE, value=ssl_mode_value)
        assert 'Successfully set' in set_output['stdout'], \
            f'Failed to set ssl_mode to {ssl_mode_value}'
        assert not set_output['stderr'], \
            f'Error setting ssl_mode: {set_output["stderr"]}'

        # Restart Nessus to apply SSL configuration changes using enhanced API
        api = NessusAPI()
        
        stop_nessus(wait_for_stop=True, api=api)
        start_nessus(wait_level='responsive', api=api)

        with SSH() as ssh:
            openssl_cmd = f"timeout 10 openssl s_client -max_protocol {client_protocol} -connect localhost:8834 </dev/null"
            openssl_output = ssh.execute(openssl_cmd, timeout=15, sudo=False)
            openssl_stdout = '\n'.join(openssl_output) if openssl_output else ''

            if ssl_mode_value == 'niap':
                expected_protocol = client_protocol if client_protocol == 'TLSv1.2' else 'TLSv1.3'
                connection_successful = is_ssl_connection_successful(openssl_stdout, expected_protocol)
            else:
                connection_successful = is_ssl_connection_successful(openssl_stdout)

            if expected_success:
                assert connection_successful, \
                    f'openssl {client_protocol} client should succeed with ssl_mode={ssl_mode_value}. ' \
                    f'Output: {openssl_stdout[:500]}'
            else:
                assert not connection_successful, \
                    f'openssl {client_protocol} client should fail with ssl_mode={ssl_mode_value}. ' \
                    f'Output: {openssl_stdout[:500]}'


def random_alphanumeric_string(length):
    return ''.join(
        random.choices(
            string.ascii_letters + string.digits,
            k=length
        )
    )


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.nessus_cli
class TestNessusCLILinkingKeys:
    """ Test nessuscli get/set linking keys commands """

    @pytest.mark.xray(test_key='NES-17406')
    @pytest.mark.parametrize('settings', [
        {'secure': False, 'setting': 'agent_linking_key'},
        {'secure': True, 'setting': 'agent_linking_key'}])
    def test_get_agent_linking_key_via_cli(self, settings):
        """
        NES-17406 : Validate the agent linking key via fix --get cli preferences.

        Scenario Tested:
        [x] Verify new agent linking key command is working
        [x] Verify able to get the agent linking key via cli command.

        """
        get_output = fix.get(secure=settings['secure'], key=settings['setting'])
        log.debug("Command output is : {}".format(get_output))
        if not settings['secure']:
            assert "Could not retrieve value for" in get_output['stdout'], 'Expected output not matched.'
            assert not get_output['stderr'], 'Error on executing fix command.'
        else:
            assert "The current value for 'agent_linking_key' is" in get_output['stdout'], \
                'Expected output not matched.'
            assert not get_output['stderr'], 'Error on executing fix command.'

    @pytest.mark.xray(test_key='NES-17407')
    @pytest.mark.parametrize('settings', [
        {'secure': False, 'setting': 'agent_linking_key', 'value': f'{random_alphanumeric_string(64)}'},
        {'secure': True, 'setting': 'agent_linking_key', 'value': f'{random_alphanumeric_string(64)}'}])
    def test_set_agent_linking_key_via_cli(self, settings):
        """
        NES-17407 : Validate the agent linking key via fix --set cli preferences.

        Scenario Tested:
        [x] Verify new agent linking key command is working
        [x] Verify able to set the agent linking key via cli command.

        """
        set_output = fix.set(secure=settings['secure'], key=settings['setting'], value=settings['value'])
        log.debug("Command output is : {}".format(set_output))
        assert "Successfully set 'agent_linking_key' to" in set_output['stdout'], \
            'Expected output not matched.'
        assert not set_output['stderr'], 'Error on executing fix command.'

    @pytest.mark.xray(test_key='NES-16379')
    @pytest.mark.nessus_manager_mat
    @pytest.mark.parametrize('settings', [
        {'secure': False, 'setting': 'agent_linking_key', 'value': f'{random_alphanumeric_string(64)}'},
        {'secure': True, 'setting': 'agent_linking_key', 'value': f'{random_alphanumeric_string(64)}'}])
    def test_set_and_get_agent_linking_key_via_cli(self, settings):
        """
        NES-16379 : Validate set/get of Linking Keys with CLI

        Scenario Tested:
        [x] Verify new agent linking key command is working
        [x] Verify able to set the agent linking key via cli command.
        [x] Verify able to get the previously set value of linking key.
        """
        # Getting agent linking key first
        get_before_output = fix.get(secure=settings['secure'], key=settings['setting'])
        log.debug("Command output is : {}".format(get_before_output))

        if settings['secure']:
            assert "The current value for 'agent_linking_key' is" in get_before_output['stdout'], \
                'Expected output not matched.'
            assert not get_before_output['stderr'], 'Error on executing fix command.'
        else:
            assert not get_before_output['stderr'], 'Error on executing fix command.'

        # Setting new agent linking key
        set_output = fix.set(secure=settings['secure'], key=settings['setting'], value=settings['value'])
        linking_key = settings['value']
        log.debug("Command output is : {}".format(set_output))
        assert "Successfully set 'agent_linking_key' to" in set_output['stdout'], \
            'Expected output not matched.'
        assert not set_output['stderr'], 'Error on executing fix command.'

        # getting agent linking key after setting
        get_output = fix.get(secure=settings['secure'], key=settings['setting'])
        log.debug("Command output is : {}".format(get_output))

        if not settings['secure']:
            assert "Could not retrieve value for" or "The current value for" in get_before_output['stdout'], \
                'Expected output not matched.'
            assert not get_before_output['stderr'], 'Error on executing fix command.'
        else:
            assert "The current value for 'agent_linking_key' is" in get_output['stdout'], \
                'Expected output not matched.'
            assert linking_key in get_output['stdout'], 'Expected output not matched.'
            assert get_output['stdout'] != get_before_output['stdout'], 'Agent linking key is not changed'
            assert not get_output['stderr'], 'Error on executing fix command.'
