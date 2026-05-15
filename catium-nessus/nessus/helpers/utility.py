"""
Nessus helper methods in Utility

:copyright: Tenable Network Security, 2018
:date: Oct 17, 2018
:last_modified: July 21, 2022
:author: @jchavda, @kpanchal, @krpatel
"""
import time

from waiting import wait

from catium.lib.config import Config
from catium.lib.const import TIME_SIXTY_SECONDS
from catium.lib.const.base_constants import WAIT_NORMAL, WAIT_TINY
from catium.lib.log.log import create_logger
from catium.lib.webium.windows_handler import WindowsHandler

log = create_logger()


def get_downloaded_files_chrome(filename: str = None) -> list:
    """
    Get browser downloaded file list for chrome
    :param filename: Name of the file
    :return: List
    """
    url = 'chrome://downloads/'
    windows_handler = WindowsHandler()
    windows_handler.create_window()
    windows_handler.switch_to_new_window()
    try:
        windows_handler._driver.get(url)

        def get_file_list() -> list:

            return windows_handler._driver.execute_script(
                "return document.querySelector('downloads-manager').shadowRoot.querySelector"
                "('#downloadsList downloads-item').shadowRoot.querySelector('div#content #file-link').text;")

        def is_file_found() -> bool:
            file_list = get_file_list()
            if filename:
                return file_list and filename in file_list[0]
            else:
                return True

        wait(lambda: is_file_found(), timeout_seconds=TIME_SIXTY_SECONDS, sleep_seconds=WAIT_NORMAL,
             waiting_for='waiting for file gets downloaded and updated in downloaded list')
        return get_file_list()
    finally:
        windows_handler.close_active_window()


def get_downloaded_file_name(files: list) -> str:
    """
    Return the file name from given file lists which downloads from browser

    :param list files: list of files downloaded from browser
    :return: file name
    :rtype: str
    """
    split_separator = "///" if Config.CAT_USE_SAUCE else "//"

    return files[0].split(split_separator)[1].split('/')[4]
