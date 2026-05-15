"""
Test Audit Warehouse ID Check — GET /audits endpoint

NES-19871: Audit ID Checks API Gives Wrong Response
NES-19814 (Xray Test): Test /audits endpoint

The GET /audits?ids=CSV_AUDIT_IDS endpoint validates audit IDs of the form
PLUGIN_ID_AUDIT_FILENAME. The bug was that a valid plugin_id paired with a valid
filename from a *different* category would return a positive response instead of
being rejected.

Test matrix:
    - No query args                        -> 400
    - Single valid ID                      -> 200, result returned
    - Multiple valid IDs                   -> 200, all results returned
    - Single invalid ID (bogus plugin_id)  -> 400
    - Mismatched ID (valid parts, wrong combo) -> 400
    - Mix of valid + mismatched IDs        -> 200, only valid IDs returned
    - Valid ID with %20 spaces             -> 200, result returned
    - Duplicate valid ID                   -> 200, returned once
"""
from http import HTTPStatus

import pytest

from catium.lib import const
from catium.lib.log import create_logger
from catium.lib.ssh.ssh import SSH
from nessus.helpers.server import expect_http_error
from nessus.lib.const.constants import System

log = create_logger()

AUDITS_ROUTE = 'audits'
WAREHOUSE_QUERY = (
    "SELECT category.plugin_id, filename "
    "FROM audit, category "
    "WHERE audit.category = category.id "
    "AND audit.deprecated = 0 "
    "GROUP BY category.plugin_id "
    "LIMIT 5"
)


@pytest.fixture(scope='class')
def audit_ids(request):
    """Query the audit warehouse via SSH to get valid audit IDs and a mismatched combo.

    Returns a dict with:
        valid_ids: list of valid PLUGIN_ID_FILENAME strings
        mismatched_id: a PLUGIN_ID_FILENAME where both parts are valid but don't go together
    """
    with SSH() as ssh:
        rows = ssh.execute(
            command="echo \"%s\" | sqlite3 -separator '|' %s" % (WAREHOUSE_QUERY, System.LINUX_AUDIT_WAREHOUSE),
            sudo=True)

    if not rows or len(rows) < 2:
        pytest.skip('Need at least 2 audit categories in the warehouse')

    # Each row is "plugin_id|filename"
    combos = [r.strip().split('|') for r in rows if '|' in r]
    if len(combos) < 2:
        pytest.skip('Could not parse audit warehouse query results')

    valid_ids = ['%s_%s' % (pid, fn) for pid, fn in combos]
    # Mismatched: plugin_id from first row + filename from second row
    mismatched_id = '%s_%s' % (combos[0][0], combos[1][1])

    data = {
        'valid_ids': valid_ids,
        'mismatched_id': mismatched_id,
    }
    log.info('audit_ids fixture: valid=%s, mismatched=%s', valid_ids[:2], mismatched_id)
    return data


@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestAuditsIdCheck:
    """
    NES-19871 / NES-19814: Verify the GET /audits endpoint correctly validates
    that the plugin_id and filename in each requested ID actually go together
    in the audit warehouse.
    """

    cat = None

    @pytest.mark.xray(test_key='NES-19814')
    def test_no_query_args_returns_400(self):
        """GET /audits with no ids query arg returns 400."""
        with expect_http_error(code=HTTPStatus.BAD_REQUEST):
            self.cat.api.request(const.HTTPMethods.GET, AUDITS_ROUTE)

    @pytest.mark.xray(test_key='NES-19814')
    def test_single_valid_id(self, audit_ids):
        """GET /audits?ids=VALID_ID returns 200 with the audit info."""
        valid_id = audit_ids['valid_ids'][0]
        response = self.cat.api.request(const.HTTPMethods.GET,
                                        '%s?ids=%s' % (AUDITS_ROUTE, valid_id))

        assert response.status_code == HTTPStatus.OK, \
            'Expected 200, got %s' % response.status_code

        data = response.json()
        assert valid_id in data.get('ids', {}), \
            'Expected %s in response ids, got %s' % (valid_id, list(data.get('ids', {}).keys()))
        assert 'warehouse_info' in data, 'Response should include warehouse_info'

    @pytest.mark.xray(test_key='NES-19814')
    def test_multiple_valid_ids(self, audit_ids):
        """GET /audits?ids=ID1,ID2 returns 200 with all requested audits."""
        ids = audit_ids['valid_ids'][:2]
        ids_param = ','.join(ids)
        response = self.cat.api.request(const.HTTPMethods.GET,
                                        '%s?ids=%s' % (AUDITS_ROUTE, ids_param))

        assert response.status_code == HTTPStatus.OK, \
            'Expected 200, got %s' % response.status_code

        returned_ids = list(response.json().get('ids', {}).keys())
        for expected_id in ids:
            assert expected_id in returned_ids, \
                '%s not in response ids %s' % (expected_id, returned_ids)

    @pytest.mark.xray(test_key='NES-19814')
    def test_single_invalid_id_returns_400(self):
        """GET /audits?ids=BOGUS returns 400."""
        with expect_http_error(code=HTTPStatus.BAD_REQUEST):
            self.cat.api.request(const.HTTPMethods.GET,
                                '%s?ids=99999_nonexistent.audit' % AUDITS_ROUTE)

    @pytest.mark.xray(test_key='NES-19814')
    def test_mismatched_id_returns_400(self, audit_ids):
        """GET /audits with a valid plugin_id + valid filename that don't go together returns 400.

        This is the core bug scenario from NES-19871: both parts are individually valid
        but the filename belongs to a different category than the plugin_id.
        """
        mismatched_id = audit_ids['mismatched_id']
        with expect_http_error(code=HTTPStatus.BAD_REQUEST):
            self.cat.api.request(const.HTTPMethods.GET,
                                '%s?ids=%s' % (AUDITS_ROUTE, mismatched_id))

    @pytest.mark.xray(test_key='NES-19814')
    def test_mix_valid_and_mismatched_returns_only_valid(self, audit_ids):
        """GET /audits with a mix of valid and mismatched IDs returns 200 with only valid results."""
        valid_id = audit_ids['valid_ids'][0]
        mismatched_id = audit_ids['mismatched_id']
        ids_param = '%s,%s' % (valid_id, mismatched_id)

        response = self.cat.api.request(const.HTTPMethods.GET,
                                        '%s?ids=%s' % (AUDITS_ROUTE, ids_param))

        assert response.status_code == HTTPStatus.OK, \
            'Expected 200, got %s' % response.status_code

        returned_ids = list(response.json().get('ids', {}).keys())
        assert valid_id in returned_ids, \
            'Valid ID %s should be in response' % valid_id
        assert mismatched_id not in returned_ids, \
            'Mismatched ID %s should NOT be in response' % mismatched_id

    @pytest.mark.xray(test_key='NES-19814')
    def test_valid_id_with_url_encoded_spaces(self, audit_ids):
        """GET /audits with %20 spaces in the ID still resolves correctly."""
        valid_id = audit_ids['valid_ids'][0]
        # Insert a %20 into the filename portion (after the first underscore)
        parts = valid_id.split('_', 1)
        spaced_id = '%s_%%20%s' % (parts[0], parts[1])

        response = self.cat.api.request(const.HTTPMethods.GET,
                                        '%s?ids=%s' % (AUDITS_ROUTE, spaced_id))

        assert response.status_code == HTTPStatus.OK, \
            'Expected 200 for URL-encoded ID, got %s' % response.status_code

    @pytest.mark.xray(test_key='NES-19814')
    def test_duplicate_valid_id_returned_once(self, audit_ids):
        """GET /audits with the same valid ID twice returns it only once."""
        valid_id = audit_ids['valid_ids'][0]
        ids_param = '%s,%s' % (valid_id, valid_id)

        response = self.cat.api.request(const.HTTPMethods.GET,
                                        '%s?ids=%s' % (AUDITS_ROUTE, ids_param))

        assert response.status_code == HTTPStatus.OK, \
            'Expected 200, got %s' % response.status_code

        returned_ids = list(response.json().get('ids', {}).keys())
        assert returned_ids.count(valid_id) == 1, \
            'Duplicate ID should appear only once in response'
