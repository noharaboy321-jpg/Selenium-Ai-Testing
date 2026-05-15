"""
Test cases for Discovery Scan Wizard API

(this wizard appears on Home / Pro Trial if there are no scans)
"""
import pytest
from waiting import TimeoutExpired, wait

from catium.helpers.sleep_lib import sleep
from catium.lib.const import TIME_SIXTY_SECONDS
from catium.lib.const.base_constants import TIME_FIFTEEN_SECONDS, TIME_TWO_MINUTES, WAIT_SHORT, TIME_FIFTEEN_MINUTES, \
    TIME_FIVE_SECONDS
from catium.lib.log import create_logger
from requests.exceptions import HTTPError
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.cli_command import execute
from nessus.helpers.nessuscli.helper import get_nessus_cli
from nessus.helpers.waiters import wait_for_scanner_status
from nessus.lib.const import API
from nessus.models.scan import ScanModel

log = create_logger()


@pytest.fixture()
def delete_all_scans(request: 'SubRequest'):
    """ Stop and Delete all scans, including those in Trash. """
    api = request.instance.cat.api
    scans = api.scans.get_scans()
    if 'scans' in scans and scans['scans'] is not None:
        scan_wait = False
        for scan in scans['scans']:
            if scan['status'] == API.Scan.Status.PENDING:
                try:
                    wait(lambda: api.scans.get_status(scan_id=scan['id']) == API.Scan.Status.RUNNING,
                         waiting_for="Scan to get running state.", timeout_seconds=TIME_SIXTY_SECONDS)
                except TimeoutExpired:
                    log.warning("scan with id {} remains in pending state".format(scan['id']))
            if scan['status'] == API.Scan.Status.RUNNING:
                log.info(msg='Stopping scan %d' % scan['id'])
                api.scans.stop(scan['id'])
                scan_wait = True
        if scan_wait:
            sleep(sleep_time=TIME_FIFTEEN_SECONDS * 3, reason='for scans to stop.')

        for scan in scans['scans']:
            log.info(msg='Deleting scan %d' % scan['id'])
            try:
                api.scans.delete(scan['id'])
            except HTTPError:
                log.warning("Unable to delete the scan having ID : {} ".format(scan['id']))


@pytest.fixture()
def enable_disable_wizard(request: 'SubRequest'):
    """ Normally this wizard is completely disabled in automation so as not to disrupt tests. Enable it temporarily. """
    setting_value = request.param.get('enable_wizard')
    nessus_api = NessusAPI()

    execute(get_nessus_cli(), ['fix', '--set', 'show_initial_scan_wizard={}'.format(setting_value)])
    reload_nessus(api=nessus_api)
    yield
    execute(get_nessus_cli(), ['fix', '--set', 'show_initial_scan_wizard=no'])
    reload_nessus(api=nessus_api)


def reload_nessus(api: NessusAPI) -> None:
    """
    Trigger a backend reload and wait for it to complete.
    :param NessusAPI api: Object of NessusAPI class
    :return: None
    """
    log.debug('Reloading nessus backend.')
    execute(get_nessus_cli(), ['reload'])

    # Wait for two minutes to get "loading" state of Nessus and if not found then execution will continue.
    try:
        wait_for_scanner_status(api=api, timeout=TIME_TWO_MINUTES, status=API.Status.LOADING,
                                msg='server to be loading state.', sleep_interval=WAIT_SHORT)
    except TimeoutExpired:
        log.warning("Loading state was not found within two minutes of wait.")

    wait_for_scanner_status(api=api, timeout=TIME_FIFTEEN_MINUTES, status=API.Status.READY,
                            msg='server to finish loading.', sleep_interval=WAIT_SHORT)
    sleep(sleep_time=TIME_FIVE_SECONDS, reason='for reload to take effect.')


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.incompatible
@pytest.mark.usefixtures('nessus_api_login')
class TestWizardOtherLicenseTypes:
    """ Test the scan wizard on non-Essentials """
    cat = None

    def is_wizard_enabled(self):
        properties = self.cat.api.server.properties()
        return 'show_initial_scan_wizard' in properties and properties['show_initial_scan_wizard']

    @pytest.mark.parametrize('enable_disable_wizard', [{'enable_wizard': 'yes'}], indirect=True)
    def test_wizard_not_enabled(self, delete_all_scans, enable_disable_wizard):
        """
        Verify that the wizard is not enabled on Pro / Manager
        Scenarios tested:
        [x] Verify that 'show_initial_scan_wizard' is missing or false
        """
        assert not self.is_wizard_enabled(), "Scan wizard enabled on this license type, it shouldn't be."


@pytest.mark.nessus_home
@pytest.mark.incompatible
@pytest.mark.usefixtures('nessus_api_login')
class TestWizard:
    """ Test the scan wizard on Essentials """
    cat = None

    def is_wizard_enabled(self):
        properties = self.cat.api.server.properties()
        return 'show_initial_scan_wizard' in properties and properties['show_initial_scan_wizard']

    @pytest.mark.parametrize('enable_disable_wizard', [{'enable_wizard': 'no'}], indirect=True)
    def test_wizard_disabled_pref_disabled(self, delete_all_scans, enable_disable_wizard):
        """
        Verify that the wizard is not enabled if the pref is disabled.
        """
        assert not self.is_wizard_enabled(), "Scan wizard enabled when pref is disabled, it shouldn't be."

    @pytest.mark.parametrize('enable_disable_wizard', [{'enable_wizard': 'yes'}], indirect=True)
    def test_wizard_enabled_pref_enabled(self, delete_all_scans, enable_disable_wizard):
        """
        Verify that the wizard is enabled in the API if the pre-conditions are met:
        - pref is enabled
        - license is home or pro trial
        - there are no scans created (including in Trash)
        """
        assert self.is_wizard_enabled(), 'Scan wizard is not enabled, it should be.'

    @pytest.mark.parametrize('enable_disable_wizard', [{'enable_wizard': 'yes'}], indirect=True)
    def test_wizard_enabled_pref_missing(self, delete_all_scans, enable_disable_wizard):
        """
        Verify that the wizard is enabled in the API if the pre-conditions are met:
        - pref is deleted
        - license is home or pro trial
        - there are no scans created (including in Trash)
        """
        execute(get_nessus_cli(), ['fix', '--delete', 'show_initial_scan_wizard'])
        reload_nessus(self.cat.api)
        assert self.is_wizard_enabled(), 'Scan wizard is not enabled after deleting preference.'

    @pytest.mark.parametrize('enable_disable_wizard', [{'enable_wizard': 'yes'}], indirect=True)
    def test_wizard_disabled_scan_exists(self, delete_all_scans, enable_disable_wizard):
        """
        Verify that wizard isn't enabled if a scan exists.
        """
        config = {
            'enabled': True,
            'starttime': '20300101T120000',
            'timezone': 'US/Samoa',
            'launch': 'ONETIME',
            'rrules': 'FREQ=ONETIME',
            'description': 'Created by Automation',
            'text_targets': '127.0.0.1',
        }

        scan_id = self.cat.api.scans.create(ScanModel(name='scan1', **config))['scan']['id']
        assert not self.is_wizard_enabled(), 'Scan wizard is not disabled after creating scan.'

        self.cat.api.scans.delete(scan_id)
        reload_nessus(api=self.cat.api)

        assert self.is_wizard_enabled(), 'Scan wizard is not re-enabled after deleting scan.'
