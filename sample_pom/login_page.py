from selenium.webdriver.common.by import By
from base_page import BasePage

class LoginPage(BasePage):
    def __init__(self, driver):
        super().__init__(driver)        # inherit driver + wait
        self.url_path = "/practice-test-login/"        # page-specific URL

    USERNAME = (By.ID, "username")
    PASSWORD = (By.ID, "password")
    LOGIN_BTN = (By.ID, "submit")

    def load_page(self):
        self.navigate_to(self.url_path)

    def login(self, username, password):
        self.type(self.USERNAME, username)
        self.type(self.PASSWORD, password)
        self.click(self.LOGIN_BTN)
