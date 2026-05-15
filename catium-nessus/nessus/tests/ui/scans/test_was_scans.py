import time

import pytest
from catium.lib.const import TIME_FIVE_MINUTES, TIME_SIXTY_SECONDS
from catium.lib.util import random_name

from nessus.pageobjects.scans.scans_page import ScansPage, ScanList
from nessus.helpers.scan import get_scan_id
from nessus.helpers.waiters import wait_scan_state
from catium.lib.log import create_logger
from nessus.lib.const.constants import Nessus, API
from catium.lib.ssh import SSH

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.usefixtures('nessus_api_login', 'login', 'enable_was')
class TestWASScans:
    """ Test cases to cover UI functionality for WAS scans """
    cat = None

    @pytest.mark.xray(test_key='NES-18086')
    @pytest.mark.parametrize("separation_type", ["comma", "space", "newline"])
    def test_was_scope_textarea_data(self, separation_type) -> None:
        """
        NES-18086:

        Scenarios Tested:
        Enter data for File Extensions to Exclude, List of URLs, Regex For Excluded URLs in each of the following ways:
            1. Comma separated
            2. Space separated
            3. Newline separated
        Run the WAS scan.
        Verify using docker log output the data is sent correctly.
        """
        scan_name = random_name(prefix="{} separated WAS Scan - ".format(separation_type))
        try:
            # Modify input data based on separation_type
            file_extension_exclusions = "js,css,png,jpeg,gif,pdf,csv,svn-base,svg,jpg,ico,woff,woff2,exe,msi,zip"
            url_list = "http://target1.pubtarg.tenablesecurity.com,http://target2.pubtarg.tenablesecurity.com,http://target3.pubtarg.tenablesecurity.com"
            path_exclusions = "billing,organization,logout"
            if separation_type == "space":
                file_extension_exclusions = file_extension_exclusions.replace(",", " ")
                url_list = url_list.replace(",", " ")
                path_exclusions = path_exclusions.replace(",", " ")
            elif separation_type == "newline":
                file_extension_exclusions = file_extension_exclusions.replace(",", "\n")
                url_list = url_list.replace(",", "\n")
                path_exclusions = path_exclusions.replace(",", "\n")

            # Create and launch the WAS Scan
            ScansPage().create_new_scan(
                scan_type=Nessus.Scan.ScanTemplateTabs.WAS_TAB, scan_template="Scan", scan_name=scan_name,
                target_url="http://pubtarg.tenablesecurity.com", file_extension_exclusions=file_extension_exclusions,
                url_list=url_list, path_exclusions=path_exclusions,
            )
            scan_list = ScanList()
            scan_list.launch_scan(scan_name=scan_name)

            # Wait up to five minutes for the WAS scope data to appear in the docker logs
            scope_data = ',"scope":{'
            timeout = time.time() + TIME_FIVE_MINUTES
            while time.time() < timeout:
                with SSH() as ssh:
                    result = ssh.execute(f"docker logs nessus-was-scanner |fgrep '{scope_data}'")
                    if result and scope_data in result[0]:
                        break

            # Verify each textarea input was sent correctly
            expected_outputs = [
                '"exclude_file_extensions":["js","css","png","jpeg","gif","pdf","csv","svn-base","svg","jpg","ico","woff","woff2","exe","msi","zip"]',
                '"exclude_path_patterns":["(?-mix:billing)","(?-mix:organization)","(?-mix:logout)"]',
                '"urls":["http://target1.pubtarg.tenablesecurity.com","http://target2.pubtarg.tenablesecurity.com","http://target3.pubtarg.tenablesecurity.com"]'
            ]
            for expected_output in expected_outputs:
                assert expected_output in result[0], f"Expected data to be separated by {separation_type}s"

        # Clean up the scan
        finally:
            try:
                scan_id = get_scan_id(api_object=self.cat.api, scan_name=scan_name)
                scan_status = self.cat.api.scans.get_status(scan_id)
                if scan_status not in [API.Scan.Status.COMPLETED, API.Scan.Status.CANCELED,
                                       API.Scan.Status.ABORTED]:
                    self.cat.api.scans.stop(scan_id)
                    wait_scan_state(api=self.cat.api, scan_id=scan_id, end_state=API.Scan.Status.CANCELED,
                                    timeout=TIME_SIXTY_SECONDS)
                    self.cat.api.scans.delete(scan_id=scan_id)
            except Exception as e:
                log.warning(f"Scan was not cleaned up successfully. Exception: {e}")
                raise Exception("Unable to clean up scan!")
