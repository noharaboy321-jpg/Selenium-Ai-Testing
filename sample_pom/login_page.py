from base_page import BasePage
from selenium.webdriver.common.by import By


class LoginPage(BasePage):
    # Locators defined at class level for clarity and reuse
    USERNAME_LOCATOR = (By.ID, 'username')
    PASSWORD_LOCATOR = (By.ID, 'password')
    LOGIN_BUTTON_LOCATOR = (By.ID, 'login-button')

    def __init__(self, driver):
        super().__init__(driver)
        self.url_path = '/login'

    def load_page(self):
        self.navigate_to(self.url_path)

    def login(self, username: str, password: str):
        """Perform login using provided credentials.

        Locators are class-level attributes so tests and helpers can reference
        them without instantiating the page, and a single change updates all
        instances.
        """
        self.type_into_element(self.USERNAME_LOCATOR, username)
        self.type_into_element(self.PASSWORD_LOCATOR, password)
        self.click_on_element(self.LOGIN_BUTTON_LOCATOR)    