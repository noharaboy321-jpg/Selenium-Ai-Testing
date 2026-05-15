"""
Methods related to multiple windows handling 

:copyright: Tenable Network Security, 2019
:date: Feb 28, 2019
:last_modified: Feb 28, 2019
"""
from catium.lib.webium.windows_handler import WindowsHandler
from catium.lib.log import create_logger

log = create_logger()


class MultipleWindows(WindowsHandler):
    def create_new_window(self, url: str)-> str:
        """
        create a new window with provided url.

        :param str url: required url to open
        :return: new window with specified url
        :rtype: str
        """
        log.debug('Creating new tab/window for url %s ', url)
        self.save_window_set()
        self._driver.execute_script('window.open("{}", "_blank");'.format(url))
        log.debug('Created new tab/window for url %s ', url)

        return self.new_window

    def create_and_switch_window(self, url: str)-> str:
        """
        open new window with provided url and switch to the newly created window.

        :param str url: url to create new window
        :return: new_window
        :rtype: str
        """

        new_window = self.create_new_window(url)

        log.debug('Switching new tab/window for url %s ', url)
        self.switch_to_new_window()
        log.debug('Switched new tab/window for url %s ', url)

        return new_window
