"""
Nessus CLI "Fetch" Tests

Test the nessuscli fetch command and subcommands.

:copyright: Tenable Network Security, 2017
:date: September 7th, 2017
:last_modified: July 15, 2020
:author: @kpanchal, @krpatel
"""

import re
import tempfile

import pytest

from catium.lib.ssh import SSH
from nessus.helpers import license
from nessus.helpers.nessuscli import fetch, fix


@pytest.mark.nessus_mat
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestNessusCLIFetch:
    """ Test nessuscli fetch commands """

    cat = None

    @pytest.mark.usefixtures('nessus_api_login')
    def test_offline_registration(self):
        properties = self.cat.api.server.properties()
        serial = license.get_activation_code(properties=properties)
        challenge_output = fetch.challenge(serial=serial)
        matches = re.search(r'Challenge code:\s*(\S+)', challenge_output['stdout'])
        challenge = matches.group(1)
        nessus_license = license.get_offline_license(code=serial, challenge=challenge)

        # write the file out somewhere.
        lic_file = tempfile.NamedTemporaryFile()
        out = open(lic_file.name, 'w')
        out.write(nessus_license)
        out.close()

        with SSH() as ssh:
            ssh.send_file(lic_file.name, lic_file.name)

        offline_output = fetch.register_offline(license_file=lic_file.name)

        lic_file.close()


        assert 'Nessus is offline' in offline_output['stdout'], 'Error while registering offline'

        # at this point, auto_update should be turned off.
        auto_update = fix.get_value(key='auto_update')
        auto_update_ui = fix.get_value(key='auto_update_ui')

        assert auto_update == 'no', 'Invalid value for auto_update'
        assert auto_update_ui == 'no', 'Invalid value for auto_update_ui'

        output = fetch.code_in_use()
        assert 'Failed to fetch activation code' in output['stdout'], 'activation code is available'

    def test_check(self):
        output = fetch.check()
        assert not output['stderr'], 'Error while executing fetch check command'
        assert 'Checking...' in output['stdout'], 'Invalid response'

    # Registering causes a plugin update, which takes a long time.  We can test with --register-only though
    @pytest.mark.usefixtures('nessus_api_login')
    def test_register(self):
        properties = self.cat.api.server.properties()
        fail_output = fetch.register_only(serial='""')
        assert 'Serial number  is not valid' in fail_output['stdout'], 'Invalid serial number'
        serial = license.get_activation_code(properties=properties)
        register_output = fetch.register_only(serial=serial)
        assert 'registered properly' in register_output['stdout'], 'Error while registering'
