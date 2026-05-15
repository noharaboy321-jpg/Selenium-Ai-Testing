"""
Testcase to verify nessusd.dump file at the end of CLI testcases execution
:copyright: Tenable Network Security, 2020
:date: June 25, 2020
:last_modified: June 25, 2020
:author: vsoni.ctr
"""
import pytest

from catium.lib.log.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.helpers.nessuscli.helper import get_nessusd_dump, get_command

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.nessus_home
@pytest.mark.nessus_smoke
class TestVerifyNessusdDumpCLI:
    """Testcase to verify nessusd.dump file at the end of CLI testcases execution"""

    def test_verify_nessusd_dump_file_for_cli(self):
        """
        NES-11582 : Automation - Add checking for anomalies in the log files

        Scenario Tested:
            [x] Verify nessusd.dump file at the end of CLI testcases execution.
        """
        get_read_file_content_command = get_command(operation="display_content")
        nessusd_dump_file = get_nessusd_dump()

        with SSH() as ssh:
            nessusd_dump_file_content = ssh.execute("{} {}".format(get_read_file_content_command, nessusd_dump_file))
        log.debug("Nessusd dump file content : {}".format(nessusd_dump_file_content))

        # Verify that Nessus does not crashed during CLI testcases execution
        assert not [file_line for file_line in nessusd_dump_file_content if "Aborted" in file_line], \
            "Nessus crashed somewhere while executing CLI testcases."
