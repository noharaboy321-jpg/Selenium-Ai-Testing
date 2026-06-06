from selenium.webdriver.common.by import By
from base_page import BasePage

class DashboardPage(BasePage):
    def __init__(self, driver):
        super().__init__(driver)
        self.url_path = "/logged-in-successfully/"

    WELCOME_MSG = (By.XPATH, "//h1[text()='Logged In Successfully']")

    def load_page(self):
        self.navigate_to(self.url_path)

    def get_welcome_message(self):
        return self.get_text(self.WELCOME_MSG)
