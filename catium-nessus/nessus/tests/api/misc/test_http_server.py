"""
Test cases for aspects of the HTTP server
"""
import pytest

from catium.lib import const
from nessus.apiobjects.nessus_api import NessusAPI
from nessus.helpers.server import expect_http_error


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
class TestHttpServer:
    """Test cases for Nessus HTTP Server"""
    cat = None

    def test_cache_control(self):
        """
        NES-8696 - Incomplete or No Cache-control and Pragma HTTP Header Set

        Scenarios tested:
        [x] File response sets ETag and allows caching
        [x] 404 response sets no ETag and disables caching
        [x] API response sets no ETag and disables caching
        """
        api = NessusAPI()

        response = api.request(const.HTTPMethods.GET, '/nessus6.js')
        assert response.headers.get('etag'), "No ETag header set for a static asset"
        assert response.headers.get('cache-control') == 'must-revalidate'
        assert response.headers.get('pragma') is None
        assert response.headers.get('expires') is None

        response = api.request(const.HTTPMethods.GET, '/server/status')
        assert response.headers.get('etag') is None, "ETag header is returned for an API call"
        cache_control = response.headers.get('cache-control')
        for item in ['no-cache', 'no-store', 'must-revalidate']:
            assert item in cache_control, "%s missing from Cache-Control header on API call" % item
        assert response.headers.get('pragma') == 'no-cache', "Pragma missing or incorrect on API call"
        assert response.headers.get('expires') == '0', "Expires not set correctly on 404 file"

        with expect_http_error(code=404):
            response = api.request(const.HTTPMethods.GET, '/doesnotexist.html')
            assert response.headers.get('etag') is None, "ETag header is returned for a path that does not exist"
            cache_control = response.headers.get('cache-control')
            for item in ['no-cache', 'no-store', 'must-revalidate']:
                assert item in cache_control, "%s missing from Cache-Control header on 404 file" % item
            assert response.headers.get('pragma') == 'no-cache', "Pragma missing or incorrect on 404 file"
            assert response.headers.get('expires') == '0', "Expires not set correctly on 404 file"

    def test_cache_match(self):
        """
        NES-8696 - Incomplete or No Cache-control and Pragma HTTP Header Set

        Scenarios tested:
        [x] Browser requests for cached content return 304
        """

        api = NessusAPI()

        response = api.request(const.HTTPMethods.GET, '/nessus6.js')
        assert response.headers.get('etag'), "No ETag header set for a static asset"
        etag = response.headers.get('etag')

        response = api.request(const.HTTPMethods.GET, '/nessus6.js', headers={'If-None-Match': etag})
        assert response.status_code == 304, "Did not get a cache hit when requesting same ETag"
