"""
Test cases to verify new agent blackout window features

:copyright: Tenable Network Security, 2019
:date: March 05, 2019
:last_modified: March 18, 2021
:author: @ntarwani, @kpanchal, @krpatel.ctr
"""
import pytest
from waiting import wait, TimeoutExpired

from catium.lib.const import TIME_FIVE_MINUTES
from catium.lib.ssh import SSH
from nessus.helpers.nessuscli import fix
from nessus.helpers.nessuscli.helper import get_nessus_cli, stop_nessus, start_nessus, get_command, \
    get_nessus_backend_log


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestNessusFixParameter:
    """Test cases related to blackout window preferences for Nessus version 8.4.0 and above"""

    @pytest.mark.nessus_manager
    def test_new_preferences_with_fresh_install(self):
        """
        AGENT-1555: agent blackout windows testing: stand-alone test automation
        Test that after fresh install, new preferences for agent blackout window are available.
        The preferences are 'bw_permanent_blackout_window', 'bw_prevent_core_updates', 'bw_prevent_plugin_updates',
                           'bw_prevent_agent_scans'
        Note: This test case will run only for Nessus version > 8.4.0
        """
        output = fix.list()
        assert not output['stderr'], 'Error on executing fix command'

        new_preferences = ['bw_permanent_blackout_window', 'bw_prevent_core_updates', 'bw_prevent_plugin_updates',
                           'bw_prevent_agent_scans']
        for pref in new_preferences:
            assert pref in output['stdout'], '{} is not listed in preferences'.format(pref)

        assert 'agent_software_update' not in output['stdout'], 'agent_software_update exists in list of preferences'

    @pytest.mark.parametrize('telemetry_period', [
        {'value': '40', 'message': "Can not set 'telemetry_period': Minimum value for Telemetry Period is 60"},
        {'value': '10081', 'message': "Can not set 'telemetry_period': Maximum value for Telemetry Period is 10080"}])
    def test_verify_incorrect_value_can_not_be_set_for_telemetry_period_value(self, telemetry_period):
        """
        NES-12480: [Automation] Verify "telemetry_period" ranges

        Scenario Tested:
            [x] Verify "telemetry_period" preference value can not be set below 60 and and more than 10080.
        """
        with SSH() as ssh:
            set_output = ssh.execute("{} fix --set telemetry_period={}".format(get_nessus_cli(), telemetry_period.get(
                'value')))

            assert any([op == telemetry_period['message'] for op in set_output])

    @pytest.mark.usefixtures('add_tag_in_logs_json_file')
    @pytest.mark.parametrize('add_tag_in_logs_json_file', [{'tag_name': 'verbose'}], indirect=True)
    @pytest.mark.skip_suse
    def test_verify_send_telemetry_value_set_to_no(self):
        """
        NES-12481: [Automation] Verify user can opt out from sending telemetry

        Scenario Tested:
            [x] Verify user can opt out from sending telemetry details by setting "send_telemetry"  to "no"
        """
        with SSH() as ssh:
            ssh.execute(command="{} fix --set send_telemetry=no".format(get_nessus_cli()))
            stop_nessus()
            start_nessus()
            try:
                wait(lambda: [log_entry for log_entry in ssh.execute("{} {}".format(
                    get_command(operation='display_content'), get_nessus_backend_log())) if
                              "Not sending startup telemetry; send_telemetry is false.".lower() in log_entry.lower()],
                     waiting_for="Required log entry to get populated", timeout_seconds=TIME_FIVE_MINUTES)
            except TimeoutExpired:
                raise AssertionError("Log entry stating send telemetry is false does not populated "
                                     "on backend.log after setting fix parameter send_telemetry to no.")

    @pytest.mark.xray(test_key='NES-15181')
    @pytest.mark.parametrize('telemetry_period', [
        {'value': '60', 'message': "Successfully set 'telemetry_period' to '60'."}])
    def test_verify_incorrect_value_can_not_be_set_for_telemetry_period_value(self, telemetry_period):
        """
        NES-15181: Verify that with the help of telemetry_period, the user is able to get telemetry in every 1 hr

        Scenario Tested:
            [x] Verify that with the help of telemetry_period, the user is able to set telemetry in every 1 hr.
            [ ] Verify that with the help of telemetry_period, the user is able to get telemetry in every 1 hr
        """
        with SSH() as ssh:
            set_output = ssh.execute("{} fix --set telemetry_period={}".format(get_nessus_cli(), telemetry_period.get(
                'value')))

            assert any([op == telemetry_period['message'] for op in set_output])
