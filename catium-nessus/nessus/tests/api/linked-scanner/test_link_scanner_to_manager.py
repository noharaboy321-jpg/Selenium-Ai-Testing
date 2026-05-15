import pytest

from catium.lib.log import create_logger
from nessus.apiobjects.nessus_api import NessusAPI

log = create_logger()


@pytest.mark.docker
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login', 'link_scanner_to_manager')
class TestLinkingFixture:
    """This class contains test cases related to link scanner with manager"""

    def test_link_scanner_to_manager(self, link_scanner_to_manager):
        """
        Verify linked scanner should in the listed in manager
        """
        scanner_name = link_scanner_to_manager[2]
        nessus_api = NessusAPI()
        nessus_api.login()
        scanners = [s['name'] for s in nessus_api.scanners.get_list()['scanners']]
        assert scanner_name in scanners, "Scanner does not exist or linked properly"
