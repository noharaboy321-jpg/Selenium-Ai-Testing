"""
Nessus helper to keep UI active

Copyright: Tenable Network Security, 2017
Creation Date: May 2, 2018
:author jamreliya
"""

import threading
from contextlib import contextmanager

from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import visibility_of_element_located

from catium.helpers.sleep_lib import sleep
from catium.lib.const.base_constants import TIME_FIFTEEN_SECONDS
from catium.lib.webium.driver import get_driver_no_init


@contextmanager
def polling_ui():
    """
    keep ui active by locating html tag.
    as soon as context manager goes out of scope thread will be destroyed
    """
    is_poll = True

    def poll():
        """thread worker function"""
        while is_poll:
            visibility_of_element_located((By.CSS_SELECTOR, 'html'))(get_driver_no_init())
            sleep(sleep_time=TIME_FIFTEEN_SECONDS, reason='contextmanager sleep that keeps UI active')
    threading.Thread(target=poll).start()
    yield
    is_poll = False
