"""
:copyright: Tenable Network Security, 2017
:date: June 6, 2017
:last_modified: July 15, 2020
:author: @cdombrowski, @kpanchal
"""
import re
import time

import pytest

from catium.lib.const import STRING_OFF, STRING_ON
from catium.lib.log import create_logger
from nessus.helpers.system import get_nessus_type
from nessus.lib.const import Nessus

log = create_logger()


@pytest.mark.nessus_smoke
@pytest.mark.nessus_home
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.smoke
@pytest.mark.usefixtures('nessus_api_login', 'get_nessus_server_properties')
class TestNessusLicensing:
    """
    Class will handle testing all licensing related tests.  These tests will include checking that the installed product
    matches the licensed product, the correct number of scanners and agents are in Nessus, and that the licensed IPs
    match what is in the license.
    """

    cat = None

    # API_Tested# GET /server/properties
    def test_nessus_licensing_installed_product(self):
        """
        Tests that the installed product matches the licensed product on the standalone scanner.
        """
        nessus_type = re.sub("Nessus", "", self.cat.server_properties['nessus_type']).lower().lstrip()
        license_type = self.cat.server_properties['license']['type']

        if nessus_type and nessus_type == 'essentials':
            assert license_type == 'home', \
                'The licensed Nessus product does not match the installed product.'
        else:
            assert nessus_type and nessus_type == license_type, \
                'The licensed Nessus product does not match the installed product.'

    # API_Tested# GET /server/properties
    def test_nessus_licensing_expiration_date(self):
        """
        Tests that the license expiration date is in the future on the standalone scanner.
        """
        epoch_time = int(time.time())
        expiration_time = self.cat.server_properties['license']['expiration_date']

        assert expiration_time and epoch_time < expiration_time, \
            'The license expiration date was not retrieved or the license expiration is not in the future.'

    # API_Tested# GET /scanners
    def test_nessus_licensing_licensed_ips(self):
        """
        Tests that the amount of licensed IPs matches the amount of configured licensed IPs in the standalone scanner
        properties.
        """
        scanner_licensed_ips = self.cat.api.scanners.get_list()['scanners'][0]['license']['ips']
        license_licensed_ips = self.cat.server_properties['license']['ips']

        assert scanner_licensed_ips == license_licensed_ips, \
            'The licensed IP amount does not match the configured licensed IP amount.'

    # API_Tested# GET /scanners
    def test_nessus_licensing_agents(self):
        """
        Tests that the amount of licensed agents matches the amount of configured licensed agents in the standalone
        scanner properties.
        """
        scanner_licensed_agents = self.cat.api.scanners.get_list()['scanners'][0]['license']['agents']
        license_licensed_agents = self.cat.server_properties['license']['agents']

        assert scanner_licensed_agents == license_licensed_agents, \
            'The licensed agent amount does not match the configured licensed agent amount.'

    # API_Tested# GET /scanners
    def test_nessus_licensing_scanners(self):
        """
        Tests that the amount of licensed scanners matches the amount of configured licensed scanners in the standalone
        scanner properties.
        """
        scanner_licensed_scanners = self.cat.api.scanners.get_list()['scanners'][0]['license']['scanners']
        license_licensed_scanners = self.cat.server_properties['license']['scanners']

        assert scanner_licensed_scanners == license_licensed_scanners, \
            'The licensed scanner amount does not match the configured licensed scanner amount.'

    # API_Tested# GET /scanners
    def test_nessus_licensing_comment(self):
        """
        Tests that license comment matches the configured licensed comment in the standalone scanner properties.
        """
        scanner_licensed_comment = self.cat.api.scanners.get_list()['scanners'][0]['license']['comment']
        license_licensed_comment = self.cat.server_properties['license']['comment']

        assert scanner_licensed_comment == license_licensed_comment, \
            'The licensed comment amount does not match the configured licensed comment amount.'

    # TODO: Refactor the skip checks using the version marker once it is implemented.
    # API_Tested# GET /scanners
    @pytest.mark.skipif(get_nessus_type() != Nessus.Manager.NESSUS_MANAGER,
                        reason="These tests only run on Nessus Manager.")
    def test_nessus_licensing_linked_scanners(self):
        """
        Tests that the amount of linked scanners does not exceed the licensed amount of scanners.
        """
        scanner_licensed_linked_scanners = self.cat.api.scanners.get_list()['scanners'][0]['license']['scanners_used']
        license_licensed_linked_scanners = self.cat.server_properties['license']['scanners']

        assert license_licensed_linked_scanners >= scanner_licensed_linked_scanners, \
            'The amount of linked scanners exceeds the amount of licensed scanners.'

    # API_Tested# GET /scanners
    def test_nessus_licensing_number_of_scanners(self):
        """
        Tests that the amount of scanners being reported by the Nessus server is the same as the amount showing in the
        scanner list.  We add 1 to server_scanners_used because the local scanner counts as 1 in this test.
        """
        scanner_list = self.cat.api.scanners.get_list()['scanners']

        assert len(scanner_list) >= 1, "Atleast one scanner should be present in Nessus."

        local_scanners = [scanner for scanner in scanner_list if scanner['id'] == 1]

        assert local_scanners, "Local scanner is not present in Nessus."

        server_scanners_used = self.cat.server_properties['license']['scanners_used'] + 1

        # Taking scanners with type local or managed from the list to
        # verify the scanners_used count in server properties.
        scanners = [scanner for scanner in scanner_list if scanner['type'] in ['local', 'managed']]

        assert len(scanners) == server_scanners_used, 'No scanners being reported by Nessus.'

    # API_Tested# GET /scanners
    def test_nessus_licensing_scanner_power_state(self):
        """
        Tests that the scanners reported by Nessus are powered on.
        """
        scanner_status = {}
        amount_of_scanners = self.cat.api.scanners.get_list()['scanners']

        for scanner in amount_of_scanners:
            scanner_status[scanner['id']] = scanner['status']

        assert [scanner_status[key] == STRING_ON for key in scanner_status.keys() if key == 1], \
            "Local Scanner status is not 'on'"

        assert all(status in [STRING_OFF, STRING_ON] for status in scanner_status.values()), \
            "Linked scanner status is not 'on' or 'off'"
