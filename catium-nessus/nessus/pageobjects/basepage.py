"""
Nessus base class for page objects
"""
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from waiting import wait

from catium.helpers.sleep_lib import sleep
from catium.lib.cat_registry import cat_registry
from catium.lib.const import WAIT_NORMAL
from catium.lib.const.base_constants import WAIT_LONG
from catium.lib.log import create_logger
from catium.lib.url import Url
from catium.lib.webium import Find
from catium.lib.webium.driver import get_driver_no_init
from catium.lib.webium.windows_handler import WindowsHandler
from catium.pageobjects.cat_basepage import CATBasePage
from nessus.lib import const
from nessus.lib.config import NessusConfig
from nessus.pageobjects.shared.loading import LoadingCircle

log = create_logger()


@cat_registry.route(r'')
class NessusBasePage(CATBasePage):
    """Defines properties and methods inherited by all Nessus page objects."""

    progress_bar_div = Find(by=By.CSS_SELECTOR, value='div[class="load-progress"]')
    loading_progress_status = Find(by=By.CLASS_NAME, value='loading-progress-status')
    hide_notifications_flag = True

    def __init__(self):
        url_obj = Url(NessusConfig.CAT_NESSUS_URL)

        # Assign default port, if port's not present
        if url_obj.port is None:
            url_obj.port = const.Nessus.DEFAULT_PORT
        base_url = url_obj.to_string()

        super().__init__()
        self.url = base_url + '/#/'
        self.base_url = self.url
        self.has_loading_circle = False

    def open(self, **kwargs) -> None:
        """
        Set self.url from cat_registry pattern. Allows cat_registry usage in Nessus

        :returns: None
        """
        # We need a way to add the vars from the page object into the url dictionary.
        _url_dictionary = {**locals()['self'].get_dict()}
        # Replaces the vars in the pattern with the corresponding items in dictionary.
        _url = cat_registry.site_map.build(self.__class__.__name__, values=_url_dictionary)
        if _url:
            self.url = self.base_url + _url
        # Calls old open method.
        super().open(**kwargs)

    def loaded(self, **kwargs) -> bool:
        """
        Method to determine if a page is loaded.

        Kwargs:
            timeout (int): Override default timeout of 5 seconds.

        :returns: Bool
        :rtype: Bool
        :raises: CatiumPageLoadError
        """
        if self.has_loading_circle:
            LoadingCircle()

        if NessusBasePage.hide_notifications_flag:
            self.execute_jscript("""var notifications = document.getElementById("notifications");
                                if (notifications) {
                                    notifications.style.zIndex = -1;
                                }
                                """)

        # self.execute_jscript("""if(typeof(_Storage) != undefined) {
        #                             var localStorageSetPrinting = _Storage.set.bind(_Storage);
        #                             _Storage.set = (arg1, arg2)=>{
        #                                 console.error("Storage.set : "+arg1+" "+arg2);
        #                                 let ret_val = localStorageSetPrinting(arg1, arg2);
        #                                 console.error(localStorage);
        #                                 return ret_val;
        #                              }
        #                              var localStorageGetPrinting = _Storage.get.bind(_Storage);
        #                              _Storage.get = (arg1)=>{
        #                                 console.error("Storage.get : "+arg1+" ");
        #                                 let ret_val = localStorageGetPrinting(arg1);
        #                                 console.error(localStorage);
        #                                 return ret_val;
        #                              }
        #                              var localStorageRemovePrinting = _Storage.remove.bind(_Storage);
        #                              _Storage.remove = (arg1)=>{
        #                                 console.error("Storage.remove : "+arg1+" ");
        #                                 let ret_val = localStorageRemovePrinting(arg1);
        #                                 console.error(localStorage);
        #                                 return ret_val;
        #                             }
        #                          }
        #                      """)
        # if BROWSER_FIREFOX not in Config.CAT_BROWSER:  # pylint: disable=unsupported-membership-test
        if get_driver_no_init().capabilities.get('browserName') == 'chrome':
            log_messages = self.log_type('browser')
            # TODO: locate in exception handling or driver closing instead
            for message in log_messages:
                log.debug("Browser logs: %s", message)
        return super().loaded(**kwargs)

    def wait_for_xhr_requests(self, timeout=WAIT_LONG):
        """Waits for server requests to complete."""
        script = """\
        var running = false;
        var urls = Object.keys(_Rest.urls);
        for (var i = urls.length; i--;) {
          if (_Rest.urls[urls[i]]) {
            running = true;
            break;
            }
        }
        return running === false;
        """
        wait(predicate=lambda: (self.execute_jscript(script)),
             timeout_seconds=timeout,
             sleep_seconds=0.5,
             waiting_for='XHR requests to complete')

    def setup(self):  # TODO delete remnants of workflows code.
        """ Hook to config page on open. Needed for the template page-object."""
        pass

    def get_dict(self):
        """Returns the dict of the object"""
        return self.__dict__

    def get_href_from_link(self, element: WebElement) -> str:
        """
        Gets the 'href' attribute from a link element

        :param WebElement element: link element
        :return: link url
        :rtype: str
        """
        return element.get_attribute('href')

    def switch_window_and_get_url(self) -> str:
        """
        Switch to new tab and return url

        :return: url of new tab
        :rtype: str
        """
        windows_handler = WindowsHandler()
        windows_handler.switch_to_window(window_handle=windows_handler.handles[1])
        sleep(sleep_time=WAIT_LONG, reason="waiting for page switch")

        page_url = windows_handler._driver.current_url
        windows_handler._driver.close()

        windows_handler.switch_to_window(window_handle=windows_handler.handles[0])
        sleep(sleep_time=WAIT_NORMAL, reason="waiting for page switch")

        return page_url
