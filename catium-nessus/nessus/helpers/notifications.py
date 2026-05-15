"""
Nessus notification message related Helpers

:copyright: Tenable Network Security, 2017
:date: Jul 01, 2021
:author: @kpanchal.ctr
"""
from selenium.common.exceptions import StaleElementReferenceException, NoSuchElementException
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.common.by import By

from catium.lib.log.log import create_logger
from catium.lib.webium.driver import get_driver_no_init

log = create_logger()


def get_notification_element(element_for: str) -> list:
    """
    Returns list of WebElements of given locator value

    :param WebElement element_for: notification element locator value
    :return: list of WebElements
    """
    log.info("Into get_notification_element function..")
    notification_element = []
    attempts = 0
    driver = get_driver_no_init()
    expected_locator_value = "#notifications > div.success > div.notification-message" if element_for == "success" \
        else "#notifications > div.error"

    while attempts < 30:
        try:
            notification = driver.find_elements(By.CSS_SELECTOR, expected_locator_value)
            log.info("Element found..")

            if notification:
                notification_element.append(notification[-1].text)
                log.info("Element located successfully..")
                break
        except (StaleElementReferenceException, NoSuchElementException, IndexError) as e:
            log.warning('Unable to locate notification message element on UI. Throws exception :: {}'.format(e))

        attempts = attempts + 1

    return notification_element
