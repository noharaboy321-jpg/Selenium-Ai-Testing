"""
Nessus Scanner Health API Test case

:copyright: Tenable Network Security, 2019
:date: May 28, 2019
:last_modified: Nov 10, 2020
:author: @kpanchal
"""

from datetime import datetime, timedelta
from http import HTTPStatus

import pytest
from requests.exceptions import HTTPError

from catium.lib.config import Config
from catium.lib.log.log import create_logger
from catium.lib.util.util import random_string
from nessus.lib.const.constants import API

log = create_logger()


@pytest.mark.nessus_expert
@pytest.mark.nessus_pro
@pytest.mark.nessus_manager
@pytest.mark.usefixtures('nessus_api_login')
class TestNessusScannerHealthEndpoint:
    """Tests for Nessus Scanner Health Endpoint"""

    cat = None

    start_time = int(datetime.timestamp(datetime.now() - timedelta(hours=1)))
    end_time = int(datetime.timestamp(datetime.now()))
    non_int_value = random_string()

    def convert_time(self, time_var):
        if time_var == 'non_int_value':
            time_var = self.non_int_value
        elif time_var == 'start_time':
            time_var = self.start_time
        elif time_var == 'float_start_time':
            time_var = float(self.start_time)
        elif time_var == 'end_time':
            time_var = self.end_time
        elif time_var == 'float_end_time':
            time_var = float(self.end_time)

        return time_var

    # API_Tested# GET /settings/health/stats
    def test_unauthorized_access_for_scanner_health_stats(self):
        """
        NES-8515: Scanner Health API Tests

        Bad request tests:
            - Non-authenticated access should yield a 401 or 403

        Scenarios tested:
          [x] Verify "401 - Unauthorized" error for Unauthenticated access of scanner health stats.
        """
        self.cat.api.remove_header('X-Cookie')

        try:
            with pytest.raises(HTTPError):
                self.cat.api.scanner_health.get_stats(start_time=self.start_time, end_time=self.end_time, count=24)

            assert self.cat.api.http_status_code == HTTPStatus.UNAUTHORIZED, \
                'Expected 401, got %s instead.' % self.cat.api.http_status_code
        finally:
            self.cat.api.add_header({'X-Cookie': 'token=' + self.cat.api.session_token})

    # API_Tested# GET /settings/health/stats
    @pytest.mark.parametrize('start_time, end_time, count', [('start_time', 'end_time', 25),
                                                             ('start_time', None, 10),
                                                             (None, 'end_time', 20),
                                                             (None, None, None),
                                                             ('end_time', 'start_time', 30),
                                                             ('start_time', 'end_time', 121),
                                                             ('start_time', 'end_time', 180)])
    def test_get_scanner_health_stats(self, start_time, end_time, count):
        """
        NES-8515: Scanner Health API Tests
        NES-12248: [API] [Negative] Scanner health data retrieval with invalid timestamps

        Test providing a count (it will default to 24 if it is not).
            - This is how many data points to provide back, regardless of how the time window chosen by 
              start_time/end_time. If you ask for 24, you should always get 24 entries in the array.

        Scenarios tested:
          [x] Successfully retrieve scanner health stats details.
          [x] Verify Scanner health data retrieval with invalid timestamps
        """
        start_time = self.convert_time(start_time)
        end_time = self.convert_time(end_time)

        time_span = 0
        response = self.cat.api.scanner_health.get_stats(start_time=start_time, end_time=end_time, count=count)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        if start_time and end_time and end_time <= start_time and not response['perf_stats_history']:
            response['perf_stats_history'] = True

        assert all([response['perf_stats_current'], response['perf_stats_history']]), \
            'Scanner health Current stats and history are missing in response.'

        if start_time and end_time:
            time_span = (end_time - start_time) / count

        if start_time and end_time and start_time <= end_time and count < 30:
            if Config.CAT_USE_GRID:
                assert len(response['perf_stats_history']), 'History count should not be 0.'
            else:
                if count:
                    assert len(response['perf_stats_history']) == count, \
                        'History count is different from the expected input count.'
                elif time_span <= 30:
                    assert len(response['perf_stats_history']), \
                        'History count is getting 0 when time span is less than 30.'
                else:
                    assert len(response['perf_stats_history']) == 24, \
                        'History count is different from the expected input count.'

    # API_Tested# GET /settings/health/stats
    @pytest.mark.parametrize('start_time, end_time, count', [('non_int_value', 'non_int_value', 20),
                                                             ('start_time', 'non_int_value', 25),
                                                             ('non_int_value', 'end_time', 30),
                                                             ('non_int_value', 'float_end_time', float(35)),
                                                             ('float_start_time', 'float_end_time', float(40)),
                                                             ('start_time', 'float_end_time', 45),
                                                             ('float_start_time', 'non_int_value', 50),
                                                             ('float_start_time', 'end_time', float(55))])
    def test_scanner_health_stats_with_invalid_start_end_time(self, start_time, end_time, count):
        """
        NES-8515: Scanner Health API Tests

        Bad request tests:
            - start_time, end_time, and count must be either not provided or an int (test that a 400 is returned if
              your provide a non-int)

        Scenarios tested:
          [x] Verify "400 - Bad Request" error while giving non-int value of start_time and end_time.
        """
        start_time = self.convert_time(start_time)
        end_time = self.convert_time(end_time)

        with pytest.raises(HTTPError):
            self.cat.api.scanner_health.get_stats(start_time=start_time, end_time=end_time, count=count)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# GET /settings/health/alerts
    def test_unauthorized_access_for_scanner_health_alerts(self):
        """
        NES-8515: Scanner Health API Tests

        Bad request tests:
            - Unauthenticated access should yield a 401 or 403.

        Scenarios tested:
          [x] Verify "401 - Unauthorized" error for Unauthenticated access for scanner health alerts.
        """
        self.cat.api.remove_header('X-Cookie')

        try:
            with pytest.raises(HTTPError):
                self.cat.api.scanner_health.get_alerts(start_time=self.start_time, end_time=self.end_time)

            assert self.cat.api.http_status_code == HTTPStatus.UNAUTHORIZED, \
                'Expected 401, got %s instead.' % self.cat.api.http_status_code
        finally:
            self.cat.api.add_header({'X-Cookie': 'token=' + self.cat.api.session_token})

    # API_Tested# GET /settings/health/alerts
    @pytest.mark.parametrize('start_time, end_time', [('non_int_value', 'non_int_value'),
                                                      ('start_time', 'non_int_value'),
                                                      ('non_int_value', 'end_time'),
                                                      ('non_int_value', 'float_end_time'),
                                                      ('float_start_time', 'float_end_time'),
                                                      ('start_time', 'float_end_time'),
                                                      ('float_start_time', 'non_int_value'),
                                                      ('float_start_time', 'end_time')])
    def test_scanner_health_alerts_with_invalid_start_end_time(self, start_time, end_time):
        """
        NES-8515: Scanner Health API Tests

        Bad request tests:
            - start_time and end_time must either not be provided or be an integer.

        Scenarios tested:
          [x] Verify "400 - Bad Request" error while giving non-int value of start_time and end_time.
        """
        start_time = self.convert_time(start_time)
        end_time = self.convert_time(end_time)

        with pytest.raises(HTTPError):
            self.cat.api.scanner_health.get_alerts(start_time=start_time, end_time=end_time)

        assert self.cat.api.http_status_code == HTTPStatus.BAD_REQUEST, \
            'Expected 400, got %s instead.' % self.cat.api.http_status_code

    # API_Tested# GET /settings/health/alerts
    def test_get_scanner_health_alerts(self):
        """
        NES-8515: Scanner Health API Tests

        Valid request tests:
            - Test providing start_time and end_time

        Scenarios tested:
          [x] Successfully retrieve scanner health alerts detail.
        """
        response = self.cat.api.scanner_health.get_alerts(start_time=self.start_time, end_time=self.end_time)

        assert self.cat.api.http_status_code == HTTPStatus.OK, \
            'Expected 200, got %s instead.' % self.cat.api.http_status_code

        if len(response) and API.ScannerHealth.SYSTEM_SPEC in response[0]['type']:
            if API.ScannerHealth.SYSTEM_SPEC in response[0]['type']:
                assert response[0]['type'] == API.ScannerHealth.SYSTEM_SPEC, "Alerts type is not 'system-spec'."

                assert response[0]['alert'] in [API.ScannerHealth.ALERT_MESSAGE,
                                                'Minimum disk requirements not met.'], \
                    'Alert message is missing or mismatched.'

                description_msg = response[0]['description'].split('.')

                assert all([description_msg[0] in [API.ScannerHealth.SYS_RAM_WARN_MSG,
                                                   'Your system does not meet the minimum recommended amount of disk '
                                                   'space'],
                            any(msg in description_msg[1] for msg in [API.ScannerHealth.NUMBER_RECOMMEND_MSG,
                                                                      API.ScannerHealth.SYS_RAM_RECOMMEND_MSG]),
                            API.ScannerHealth.CURRENT_SYS_RAM in description_msg[2]]), \
                    'Alerts description messages are missing or mismatched.'
        else:
            pytest.xfail("This test requires at least one alert")
