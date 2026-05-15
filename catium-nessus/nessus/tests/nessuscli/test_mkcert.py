"""
Nessus CLI "mkcert-client" Tests

Test the nessuscli mkcert-client command

:copyright: Tenable Network Security, 2017
:date: September 12th, 2017
:last_modified: July 15, 2020
:author: @pellsworth, @kpanchal
"""

import pytest

from nessus.helpers.nessuscli import mkcert, users


@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
class TestNessusMkcertClient:
    """ Test nessuscli mkcert-client commands """

    cat = None

    @pytest.mark.usefixtures('nessus_api_login')
    def test_mkcert_client(self):
        properties = self.cat.api.server.properties()
        users.rmuser(username='admin-mkcert-client-test')
        output = mkcert.mkcert_client(username='admin-mkcert-client-test')
        users.rmuser(username='admin-mkcert-client-test')

        if 'users' not in properties['features'] or not properties['features']['users'] or (
                'npv7' in properties and properties['npv7']):
            assert 'Your license does not allow you to create more than one user' in output['stdout'], \
                'License should not allow to create more than one user'
        else:
            assert not output['stderr'], 'Error while make certificate for user'

    @pytest.mark.nessus_mat
    def test_mkcert(self):
        output = mkcert.mkcert()
        assert 'properly created' in output['stdout'], 'Certificate is not created properly'
        assert not output['stderr'], 'Error while execute make certificate command'
