from selenium.webdriver.remote.webdriver import webDriver
from selenium.webdriver.support.ui import WebDriverWait as webDriverWait
from selenium.webdriver.support import expected_conditions as EC


class BasePage:
    def __init__(self, driver: webDriver):
        self.driver = driver
        self.wait = webDriverWait(self.driver,10)

    def navigate_to(self, url_path: str):
        self.driver.get(f'base_url/{url_path}')
    
    def click_on_element(self, locator: tuple):
        self.wait.until(EC.element_to_be_clickable(locator)).click()

    def type_into_element(self, locator: tuple, text:str):
        self.wait.until(EC.visibility_of_element_located(locator)).clear().send_keys(text)
