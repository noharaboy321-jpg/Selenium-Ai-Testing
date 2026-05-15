"""
Nessus agents export/import short cycle related test cases

:copyright: Tenable Network Security, 2017
:created: November 01, 2017
:last_modified: March 27, 2018
:author: @rdutta
"""

import pytest
from collections import ChainMap

from catium.lib.const import WAIT_NORMAL, TIME_FIFTEEN_SECONDS
from catium.lib.util import random_name
from catium.lib.webium.wait import wait
from catium.lib.webium.windows_handler import WindowsHandler
from nessus.lib.const.constants import API, Nessus
from nessus.pageobjects.scans.scan_view_page import ScanViewPage
from nessus.pageobjects.scans.scans_page import ScanList, ScansPage
from nessus.pageobjects.shared.loading import LoadingCircle
from nessus.pageobjects.sidenav.sidenav import SideNav

folder_name = (random_name(prefix='NQA-393-'))[:20]


@pytest.mark.sensor_manager
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'login')
@pytest.mark.parametrize('create_new_folder', [{'folder_name': folder_name}], indirect=True)
class TestAgentsShortCycleExportImport:
    """ Covers short cycle test cases related to export/import of scan files. """
    cat = None
    test_data = {"file_path": 'nessus/tests/ui/agents/test_data/', "encrypted": True,
                 "password": Nessus.DummyCredentials.EXPORT_SECURITY_PASSWORD, "folder_name": folder_name}

    @pytest.mark.parametrize("export_format", API.Scan.UIExportFormats.VALID_FORMATS)
    @pytest.mark.parametrize("import_scan_via_api", [
        ChainMap({"file_name": 'NQA-386_-_Advanced_All_Plugins.db'}, test_data),                      # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-386_-_Advanced_Custom_Pluginset.db'}, test_data),                 # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-386_-_Advanced_All_Plugins_with_compliance.db'}, test_data),      # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-392_-_Advanced_Subnet_Scan_All_Plugins.db'}, test_data),          # NQA-393
        ChainMap({"file_name": 'basic_scan_result.db'}, test_data),                                   # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-386_-_Malware_Scan.db'}, test_data),                              # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-386_-_SCAP.db'}, test_data),                                      # NQA-387, NQA-393
        ChainMap({"file_name": 'Agent_-_Basic.nessus'}, test_data),                                   # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-386_-_Malware_Scan.nessus'}, test_data),                          # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-386_-_Advanced_All_Plugins.nessus'}, test_data),                  # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-386_-_Advanced_Custom_Pluginset.nessus'}, test_data),             # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-386_-_Advanced_All_Plugins_with_compliance.nessus'}, test_data),  # NQA-387, NQA-393
        ChainMap({"file_name": 'NQA-392_-_PCI.db'}, test_data)], indirect=True)                       # NQA-393
    def test_export_scan_file(self, create_new_folder, import_scan_via_api, export_format):
        """ test cover:
        # NQA-387 : Short Cycle-Agent-Stage 3-Export/Import.
        # NQA-393 :Short Cycle-Controller-Stage 4-Export policies and scans.
        1. Import scan files.
        2. Export scan files in different formats. 
        """
        scan_page = ScansPage()
        scan_page.refresh()

        SideNav().get_sidenav_element(element_name=create_new_folder[1]).click()
        LoadingCircle(WAIT_NORMAL)
        ScanList().click_on_scan(scan_name=import_scan_via_api[0])

        # Export the scan from scan details page in specific formats
        scan_view_page = ScanViewPage()
        LoadingCircle(WAIT_NORMAL)

        scan_view_page.export_scan_in_format(format_type=export_format)
        wait(lambda: not WindowsHandler().is_alert_present(), timeout_seconds=TIME_FIFTEEN_SECONDS,
             sleep_seconds=WAIT_NORMAL)
        assert not WindowsHandler().is_alert_present(), 'Export has failed.'

        scan_view_page.back_link.click()
