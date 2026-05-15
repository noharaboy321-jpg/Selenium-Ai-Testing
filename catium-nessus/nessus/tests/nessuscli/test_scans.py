"""
Nessus CLI "Scans" Tests

Test the nessuscli scans command and subcommands.

:copyright: Tenable Network Security, 2017
:date: September 7th, 2017
:author:
"""

import pytest

from catium.lib.log.log import create_logger
from nessus.helpers.nessuscli import scans

logger = create_logger()


# This may not be a valid test at some point in the future.
# However, since it does still exits in the nessuscli code, we can just mark it as skipped for now.
@pytest.mark.skip
@pytest.mark.usefixtures('nessus_api_login', 'import_scan')
@pytest.mark.parametrize('import_scan',
                         [{"scan": {"filename": 'advance_scan_c7kspv.nessus'}}], indirect=True)
class TestNessusCLIScans:
    """ Test nessuscli scans commands """

    cat = None

    def test_scans_list(self):
        """ Test 'nessuscli scan list' command """
        properties = self.cat.api.server.properties()
        output = scans.list()

        if 'users' in properties['features'] or properties['features']['users']:
            assert output['rc'] == 1
        else:
            assert output['rc'] == 0
            assert not output['stderr']
            # logger.debug('Scan Stdout: {0}'.format(str(output['stdout'])))
            assert output['stdout']
            assert 'imported' in output['stdout']
            assert 'advance_scan' in output['stdout']

    def test_scans_launch(self):
        """ Test 'nessuscli scan launch' command """
        properties = self.cat.api.server.properties()
        output = scans.launch(self.cat.scan_id)

        if 'users' in properties['features'] or properties['features']['users']:
            assert output['rc'] == 1
        else:
            # FIXME: Imported scans are disabled, and cannot be enabled or launched
            logger.debug('Scan Stderr: %s', output['stderr'])
            logger.debug('Scan Stdout: %s', output['stdout'])
            # assert output['rc'] == 0
            assert not output['stderr']

    def test_scans_export(self):
        """ Test 'nessuscli scan export' command """
        properties = self.cat.api.server.properties()
        output = scans.export(self.cat.scan_id)
        if 'users' in properties['features'] or properties['features']['users']:
            assert output['rc'] == 1
        else:
            # FIXME: This leaves the exported report in the current directory
            # FIXME: Need to test both CSV and Nessus formats (make format input to helper)
            logger.debug('Scan Stderr: %s', output['stderr'])
            logger.debug('Scan Stdout: %s', output['stdout'])
            assert output['rc'] == 0
            assert not output['stderr']
