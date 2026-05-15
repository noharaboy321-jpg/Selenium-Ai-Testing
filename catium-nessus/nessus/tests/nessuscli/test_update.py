"""
Nessus CLI "Update" Tests

Test the nessuscli update command and [some] subcommands.

:copyright: Tenable Network Security, 2019
:date: February 27th, 2019
:last_modified: July 15, 2020
:author: @pellsworth, @kpanchal
"""

import pytest

from nessus.helpers.nessuscli import fix, update


@pytest.mark.nessus_mat
@pytest.mark.nessus_manager
@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
class TestNessusCLIFix:
    """ Test nessuscli fix commands """

    # Commands:
    #     update
    #     update --all
    #     update --plugins-only
    #     update <plugin archive>

    @pytest.mark.parametrize('settings',
                             [{'auto_update': 'yes', 'auto_update_ui': 'yes'},
                              {'auto_update': 'no', 'auto_update_ui': 'yes'},
                              {'auto_update': 'yes', 'auto_update_ui': 'no'},
                              {'auto_update': 'no', 'auto_update_ui': 'no'}])
    def test_update(self, settings):
        fix.set(key='auto_update', value=settings['auto_update'])
        fix.set(key='auto_update_ui', value=settings['auto_update_ui'])
        fix.set(secure=True, key='license_md5', value='WRONG MD5 VALUE')

        output = update.update()

        license_md5 = fix.get(secure=True, key='license_md5')

        assert not output['stderr'], 'Error on executing update command'

        if settings['auto_update'] == 'no':
            assert 'Nessus is configured to not obtain updates' in output[
                'stdout'], 'nessuscli did not state that no updates are configured.'
            assert 'Nessus Plugins: Complete' not in output['stdout'], 'nessuscli still attempted to update plugins'
            assert 'Nessus Core Components: Complete' not in output[
                'stdout'], 'nessuscli still attempted to update core components'
        else:
            assert 'Refreshing Nessus license information' in output[
                'stdout'], 'nessuscli did not attempt to refresh license information'
            assert 'WRONG MD5 VALUE' not in license_md5['stdout'], 'License MD5 did not update'
            assert 'complete; continuing with updates' in output[
                'stdout'], 'nessuscli failed to refresh license information'
            assert 'Nessus Plugins: Complete' in output['stdout'], 'nessuscli did not attempt to update plugins'

            if settings['auto_update_ui'] == 'yes':
                assert 'Nessus Core Components: Complete' or 'Internal server error' in output[
                    'stdout'], 'nessuscli did not attempt to update core components'
            else:
                assert 'Nessus Core Components: Complete' not in output[
                    'stdout'], 'nessuscli still attempted to update core components'

    def test_update_all(self):
        fix.set(secure=True, key='license_md5', value='WRONG MD5 VALUE')
        output = update.update(_args=['--all'])

        license_md5 = fix.get(secure=True, key='license_md5')

        assert not output['stderr'], 'Error on executing update command'
        assert 'Refreshing Nessus license information' in output[
            'stdout'], 'nessuscli did not attempt to refresh license information'
        assert 'WRONG MD5 VALUE' not in license_md5['stdout'], 'License MD5 did not update'
        assert 'complete; continuing with updates' in output[
            'stdout'], 'nessuscli failed to refresh license information'
        assert 'Nessus Plugins: Complete' in output['stdout'], 'nessuscli did not attempt to update plugins'
        assert 'Nessus Core Components: Complete' or 'Internal server error' in output[
            'stdout'], 'nessuscli did not attempt to update core components'

    def test_update_plugins_only(self):
        fix.set(secure=True, key='license_md5', value='WRONG MD5 VALUE')
        output = update.update(_args=['--plugins-only'])

        license_md5 = fix.get(secure=True, key='license_md5')

        assert not output['stderr'], 'Error on executing update command'
        assert 'Refreshing Nessus license information' in output[
            'stdout'], 'nessuscli did not attempt to refresh license information'
        assert 'WRONG MD5 VALUE' not in license_md5['stdout'], 'License MD5 did not update'
        assert 'complete; continuing with updates' in output[
            'stdout'], 'nessuscli failed to refresh license information'
        assert 'Nessus Plugins: Complete' in output['stdout'], 'nessuscli did not attempt to plugins'
        assert 'Nessus Core Components' not in output[
            'stdout'], 'nessuscli attempted to update core components on a --plugins-only update'
