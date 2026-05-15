"""
Unit test for the Date Picker control

:copyright: Tenable, 2017
:date: Nov 14, 2017
:author: @jyerge
"""
import calendar

import pytest

from catium.lib.log import create_logger
from nessus.pageobjects.agents.agent_blackout_windows_page import AgentBlackoutWindowsPage
from nessus.pageobjects.agents.create_agent_blackout_window_page import CreateBlackoutWindowPage

log = create_logger()


@pytest.mark.unittest
@pytest.mark.usefixtures('login')
class TestUnitDatePickerControl:
    """Tests the Date Picker control from Webium for Nessus"""

    def test_date_picker_control_nessus(self):
        """Verifies the Date Picker control works as expected for Nessus"""
        page = AgentBlackoutWindowsPage()
        page.open()
        page.new_button.click()
        add_page = CreateBlackoutWindowPage()
        add_page.start_date.click()

        assert add_page.date_picker.is_displayed(), 'Expected DatePicker control to be displayed'
        assert add_page.date_picker.month in calendar.month_name,\
            'Expected DatePicker month "{}" to be a valid month'.format(add_page.date_picker.month)
        assert len(add_page.date_picker.year) == 4, 'Expected DatePicker year to be present'

        # Move to the next month
        current_month = add_page.date_picker.month
        add_page.date_picker.next_month()
        assert current_month != add_page.date_picker.month, 'Expected month to change'

        # Move back to the previous month
        add_page.date_picker.previous_month()
        assert add_page.date_picker.month == current_month,\
            'Expected previous month to be "{}" but got "{}" instead'.format(current_month, add_page.date_picker.month)

        # Select the 10th of the month
        add_page.date_picker.next_month()
        expected_startdate = '{:02d}/{:02d}/{}'.format(list(calendar.month_name).index(add_page.date_picker.month),
                                                       10, add_page.date_picker.year)
        add_page.date_picker.select_day(10)
        log.debug('Updated expiration after day selection: %s', add_page.start_date.value)

        # Verify the date has changed to our desired date
        assert expected_startdate == add_page.start_date.value,\
            'Expected Starts field to equal "{}" but got "{}" instead'.format(expected_startdate,
                                                                              add_page.start_date.value)
