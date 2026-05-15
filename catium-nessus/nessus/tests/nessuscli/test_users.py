"""
Nessus CLI "Users" Tests

Test the nessuscli user related command and subcommands.

:copyright: Tenable Network Security, 2017
:date: September 7th, 2017
:last_modified: July 15, 2020
:author: @kpanchal
"""

import pytest

from nessus.helpers.nessuscli import users


@pytest.mark.nessus_mat
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.skip_suse
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusCLIUsers:
    """ Test nessuscli users commands """

    cat = None

    def test_users_list(self):
        output = users.lsuser()
        assert not output['stderr'], 'Error on executing list users command'
        assert output['stdout'], 'Invalid output'

    def test_users_list_bogus(self):
        output = users.lsuser(args=['--bogus'])
        assert not output['stderr'], 'Error on executing list user command'

    @pytest.mark.usefixtures('nessus_api_login')
    def test_users_add(self):
        properties = self.cat.api.server.properties()
        output = users.rmuser(username='bogus-add')
        assert 'User removed' in output['stdout'] or 'This user does not exist' in output['stdout'], \
            'Error while removing user'

        if 'users' not in properties['features'] or not properties['features']['users'] or (
                'npv7' in properties and properties['npv7']):
            output = users.adduser(username='bogus-add', fail=True)
            assert 'Only a Nessus Manager license allows you to create more than one user' in output['stdout'], \
                'License should not allow to create more than one user'
        else:
            output = users.adduser(username='bogus-add', password='test', passconfirm='test')
            assert 'User added' in output['stdout'], 'Error while adding new user'

            output = users.adduser(username='bogus-add', fail=True)
            assert "The user 'bogus-add' already exists" in output['stdout'], 'User is not already exists'

    @pytest.mark.usefixtures('nessus_api_login')
    def test_users_delete(self):
        properties = self.cat.api.server.properties()
        output = users.rmuser(username='bogus-delete')
        assert 'User removed' in output['stdout'] or 'This user does not exist' in output['stdout'], \
            'Error while deleting user'
        assert not output['stderr'], 'Error on executing delete user command'

        if 'users' not in properties['features'] or not properties['features']['users'] or (
                'npv7' in properties and properties['npv7']):
            output = users.adduser(username='bogus-delete', fail=True)
            assert 'Only a Nessus Manager license allows you to create more than one user' in output['stdout'], \
                'License should not allow to create more than one user'
        else:
            output = users.adduser(username='bogus-delete', password='test', passconfirm='test')
            assert 'User added' in output['stdout'], 'Error while adding new user'
            assert not output['stderr'], 'Error on executing add user command'

            output = users.rmuser(username='bogus-delete')
            assert 'User removed' in output['stdout'], 'User is not removed'
            assert not output['stderr'], 'Error on executing remove user command'

    @pytest.mark.usefixtures('nessus_api_login')
    def test_users_chpasswd(self):
        properties = self.cat.api.server.properties()
        output = users.rmuser(username='bogus-chpasswd')
        assert 'User removed' in output['stdout'] or 'This user does not exist' in output['stdout'], \
            'Error while deleting user'

        if 'users' not in properties['features'] or not properties['features']['users'] or (
                'npv7' in properties and properties['npv7']):
            output = users.adduser(username='bogus-chpasswd', fail=True)
            assert 'Only a Nessus Manager license allows you to create more than one user' in output['stdout'], \
                'License should not allow to create more than one user'
        else:
            output = users.adduser(username='bogus-chpasswd', password='test', passconfirm='test')
            assert 'User added' in output['stdout'], 'Error while adding new user'

            output = users.chpasswd(username='bogus-chpasswd', password='test1', passconfirm='test1')
            assert 'Password changed for bogus-chpasswd' in output['stdout'], 'Password is not changed'

            output = users.chpasswd(username='bogus-chpasswd-noexist', fail=True, password='test1', passconfirm='test1')
            assert 'This user does not exist' in output['stdout'], 'Error while changing password for non existing user'

            output = users.chpasswd(username='bogus-chpasswd', password='test', passconfirm='nomatch')
            assert 'Passwords do not match!' in output['stdout'], 'Password should not be matched with confirm password'

            output = users.rmuser(username='bogus-chpasswd')
            assert 'User removed' in output['stdout'], 'User is not removed successfully'
