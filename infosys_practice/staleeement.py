"""Handling Stale Elements & Memory Race ConditionsThe Scenario:
 You are running your Playwright/Selenium test suite on a Single Page Application (SPA).
   During execution, components or data cards re-render aggressively over WebSockets. 
   Your scripts keep failing with random StaleElementReferenceException (in Selenium)
     or elements disappearing right between evaluation and action (in Playwright).
     How do you design a resilient architecture to completely eliminate 
     this category of flakiness?"""


from selenium.common.exceptions import StaleElementReferenceException
import time

def safe_click(driver, locator_tuple, retries=3):
    for i in range(retries):
        try:
            element = driver.find_element(*locator_tuple)
            element.click()
            return
        except StaleElementReferenceException:
            if i == retries - 1: raise
            time.sleep(0.5) # Wait brief moment for dynamic DOM re-render to settle
