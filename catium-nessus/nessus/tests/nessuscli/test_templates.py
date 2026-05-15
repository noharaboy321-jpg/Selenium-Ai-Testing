"""
Nessus CLI template update Tests

Test the various template update scenarios.
"""

import pytest
from waiting import wait

from catium.lib.const import TIME_FIVE_SECONDS
from catium.lib.const.base_constants import TIME_THREE_MINUTES
from catium.lib.log.log import create_logger
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.templates import prep_templates_update, update_templates, \
    get_template_metadata, get_tmp_template_metadata, fill_tmp_templates_dir
from nessus.lib.config.environment_variables import NESSUS_PLATFORM
from nessus.lib.const import OperatingSystems

logger = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_home
@pytest.mark.nessus_manager
@pytest.mark.skip_suse
@pytest.mark.usefixtures('backup_templates')
class TestNessusTemplateUpdates:
    """Test template update scenarios"""

    cat = None

    @staticmethod
    def increment_version(version):
        return str(int(version) + 1)

    @staticmethod
    def decrement_version(version):
        return str(int(version) - 1)

    def test_normal_update(self):
        """ Updating the version should result in templates update """

        # since this is our first test, clear out any test remnants stuck in tmp/
        fill_tmp_templates_dir()

        metadata = get_template_metadata()
        new_version = self.increment_version(metadata['version'])

        metadata['version'] = new_version
        prep_templates_update(metadata)
        update_templates()
        wait(lambda: get_template_metadata()['version'] == new_version, sleep_seconds=TIME_FIVE_SECONDS,
             waiting_for='templates to update', timeout_seconds=TIME_THREE_MINUTES)

        assert get_template_metadata()['version'] == new_version, "Template did not update"

    def test_no_update(self):
        """ A lower version should not update templates """
        metadata = get_template_metadata()
        orig_version = metadata['version']

        metadata['version'] = self.decrement_version(metadata['version'])
        prep_templates_update(metadata)
        update_templates()
        wait(lambda: get_template_metadata()['version'] == orig_version, sleep_seconds=TIME_FIVE_SECONDS,
             waiting_for='templates to update', timeout_seconds=TIME_THREE_MINUTES)

        assert get_template_metadata()['version'] == orig_version, "Template updated and should not have"

    def test_no_tmp_overwrite(self):
        """NES-9284 - do not overwrite var/templates/tmp with lower version from plugins"""
        fill_tmp_templates_dir()
        metadata = get_template_metadata()
        tmp_metadata = get_tmp_template_metadata()

        assert metadata['version'] == tmp_metadata['version'], "Test setup failure, these should match"
        orig_version = metadata['version']

        metadata['version'] = self.decrement_version(metadata['version'])
        prep_templates_update(metadata)
        update_templates()
        wait(lambda: get_template_metadata()['version'] == orig_version, sleep_seconds=TIME_FIVE_SECONDS,
             waiting_for='templates to update', timeout_seconds=TIME_THREE_MINUTES)

        assert get_template_metadata()['version'] == orig_version, "Template updated and should not have"

        assert get_tmp_template_metadata()['version'] == orig_version, "Temp template updated and should not have"

    def test_update_fixes_files(self):
        """Updating the templates should repair a file"""
        credential_json = "/Library/Nessus/run/var/nessus/templates/credentials.json" \
            if NESSUS_PLATFORM == OperatingSystems.MAC_OS else '/opt/nessus/var/nessus/templates/credentials.json'

        execute('rm', ['-f', credential_json])

        metadata = get_template_metadata()
        new_version = self.increment_version(metadata['version'])

        metadata['version'] = new_version
        prep_templates_update(metadata)
        update_templates()
        wait(lambda: get_template_metadata()['version'] == new_version, sleep_seconds=TIME_FIVE_SECONDS,
             waiting_for='templates to update', timeout_seconds=TIME_THREE_MINUTES)

        assert get_template_metadata()['version'] == new_version, "Template did not update"

        data = execute('cat', [credential_json])['stdout']

        assert data[0] == '{', "credentials.json doesn't seem to have been repaired with JSON data"

    def test_partial_update(self):
        """Test that update still occurs even if all files aren't present"""
        metadata = get_template_metadata()
        new_version = self.increment_version(metadata['version'])

        metadata['version'] = new_version
        prep_templates_update(metadata, mask_files=['scap.json', 'compliance.json', 'restrictions.json'])
        update_templates()
        wait(lambda: get_template_metadata()['version'] == new_version, sleep_seconds=TIME_FIVE_SECONDS,
             waiting_for='templates to update', timeout_seconds=TIME_THREE_MINUTES)

        assert get_template_metadata()['version'] == new_version, "Template did not update"

    def test_nessus_version_not_satisfied(self):
        """Test that we won't update to a future nessus version's template"""
        fill_tmp_templates_dir()

        metadata = get_template_metadata()
        orig_version = metadata['version']
        new_version = self.increment_version(metadata['version'])
        metadata['version'] = new_version
        metadata['required_nessus_version'] = '99.0.0'

        prep_templates_update(metadata)
        update_templates()
        wait(lambda: get_tmp_template_metadata()['version'] == new_version, sleep_seconds=TIME_FIVE_SECONDS,
             waiting_for='templates to update', timeout_seconds=TIME_THREE_MINUTES)

        assert get_tmp_template_metadata()['version'] == new_version, "Temp template did not update to new version"

        assert get_template_metadata()['version'] == orig_version, "Template updated to future nessus version"

        # overwrite to prevent remnants from breaking further tests
        fill_tmp_templates_dir()
