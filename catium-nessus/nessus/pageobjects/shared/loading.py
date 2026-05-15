"""
LoadingCircle

Class which waits for our "loading" spinner to appear / disappear.
"""
import inspect
import re

from selenium.webdriver.common.by import By

from catium.lib.const import WAIT_LONG
from catium.lib.log import create_logger
from catium.lib.webium import Find
from catium.lib.webium.wait import webium_wait as wait
from catium.pageobjects.cat_basepage import CATBasePage
from nessus.lib.config import NessusConfig

log = create_logger()


class LoadingCircle(CATBasePage):
    """Page Object which waits for the loading circle icon to disappear if it is present"""
    loading = Find(by=By.CSS_SELECTOR, value='div.loading-spinner-container')

    def __init__(self, timeout: float = 3):
        super().__init__()

        appearance_timeout = timeout
        disappearance_timeout = NessusConfig.CAT_LOADING_CIRCLE_TIMEOUT or WAIT_LONG

        if appearance_timeout:
            log.debug('Waiting for loading circle to appear (timeout %is)...', appearance_timeout)
            # Worst case scenario, this will allow timeout seconds for the circle to appear.
            present = self.is_element_present('loading', timeout=appearance_timeout)

            if not present:
                msg = 'No loading circle was present after %ss (caller %s). ' + \
                      'Consider removing or replacing with a sleep or wait.'
                if NessusConfig.CAT_NESSUS_WARN_SLEEP:
                    log.warning(msg, appearance_timeout, _caller_context())
                else:
                    log.debug(msg, appearance_timeout, _caller_context())

        log.debug('Waiting for loading circle to disappear (timeout %is)...', disappearance_timeout)
        wait(lambda: not self.is_element_present('loading', just_in_dom=True),
             waiting_for='Waiting for LoadingCircle to disappear.', timeout_seconds=disappearance_timeout)


def _caller_context() -> str:
    """ Return the name/location of the first calling function that we find in our stack trace """
    curframe = inspect.currentframe()
    frames = inspect.getouterframes(curframe)
    for frame in frames:
        if not re.search(r'loading\.py', frame.filename):
            shortfile = re.sub(r'.*/nessus/', 'nessus/', frame.filename)
            return "%s() in %s:%d" % (frame.function, shortfile, frame.lineno)
    return "unknown caller"
