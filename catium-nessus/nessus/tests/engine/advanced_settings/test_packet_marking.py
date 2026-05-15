"""
Tests to verify packet marking settings
:copyright: Tenable Network Security, 2023
:created: March 16, 2023
:last_modified: March 16, 2023
:author: @stellex
"""

import pytest

import ipaddress

from catium.helpers.testdata import get_file_path
from catium.lib.ssh import SSH
from nessus.lib.const.constants import Nessus

from nessus.helpers.nessuscli.fix import set, delete
from nessus.helpers.nessuscli.helper import stop_nessus, start_nessus


@pytest.mark.nessus_engine
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestPacketMarkingSetting:
    cat = None
    scan_data = {
        'scan_json_path': (get_file_path('nessus/tests/engine/advanced_settings/test_data/test_packet_marking_setting.json')),
        'scan_type': 'basic'
    }

    @pytest.mark.parametrize('rename_file', [{'file_path': '/etc/iproute2/', 'old_file_name': 'rt_tables',
                                              'new_file_name': 'rt_tables.bak', 'cleanup_file': True}], indirect=True)
    @pytest.mark.parametrize('add_test_file', [{'file_path': '/etc/iproute2/', 'file_name': 'rt_tables'}], indirect=True)
    @pytest.mark.parametrize('test_data_file', [
        {'scan_json_path': scan_data['scan_json_path'], 'scan_type': scan_data['scan_type']},
    ], indirect=True)
    @pytest.mark.xray(test_key='SCE-3472')
    def test_packet_marking_setting(self, test_data_file, nessus_api_login, create_scan_class, rename_file, add_test_file):
        """
        Sets up routing rules to require marked packets for Nessus communicating with a target. Executes a scan to
        ensure these rules are in place, then sets the Nessus packet marking setting to match. Then executes another
        scan to ensure packet marking setting allows the communication with the target.
        """

        # Get Scan related information for newly created scan and verify its 200 response
        # For local runs:
        # target_ip = ipaddress.IPv4Address("172.26.103.203")

        # For Jenkins runs:
        target_ip = ipaddress.IPv4Address(Nessus.Scan.Target.AWS_LINUX_TARGET_1)

        packet_marking_scan = create_scan_class
        scan_exists = packet_marking_scan.scan_state()

        assert scan_exists, 'Failed to create scan'

        updated_settings = {"targets": [str(target_ip)], "text_targets": str(target_ip)}

        packet_marking_scan.update_scan_settings(updated_settings)

        try:
            with SSH() as ssh:
                address = target_ip + 1
                ssh.execute("ip rule add fwmark 777 table 1", sudo=True)
                ssh.execute("sysctl -w net.ipv4.ip_forward=1", sudo=True)
                ssh.execute("ip link add dev dummy0 type dummy", sudo=True)
                ssh.execute(f"ip address add {str(address)} dev dummy0 ", sudo=True)
                ssh.execute("ip link set dummy0 up", sudo=True)
                ssh.execute(f"ip route add table 1 {str(target_ip)} via `ip route show default | awk '{{print $3}}'`", sudo=True)
                ssh.execute(f"ip route add {str(target_ip)} dev dummy0", sudo=True)

            packet_marking_scan.launch_scan()
            packet_marking_scan.get_hosts()

            # Verify scan is pass or fail to complete
            assert packet_marking_scan.hosts == {}, "Host was not correctly blocked for the scan."

            output = set("global.network.fwmark", "777", sudo=True, restart=True)

            packet_marking_scan.wait_for_scanner(login=True)
            packet_marking_scan.launch_scan()
            packet_marking_scan.get_hosts()

            # Verify scan is pass or fail to complete
            assert packet_marking_scan.hosts, "Packet marking failed to enable contact with the host."
        finally:
            with SSH() as ssh:
                ssh.execute(f"ip route delete {str(target_ip)} dev dummy0", sudo=True)
                ssh.execute(f"ip route delete table 1 {str(target_ip)}", sudo=True)
                ssh.execute("ip link set dummy0 down", sudo=True)
                ssh.execute("ip link delete dev dummy0", sudo=True)
                ssh.execute("ip rule delete fwmark 777 table 1", sudo=True)

            delete("global.network.fwmark", sudo=True, restart=True)
