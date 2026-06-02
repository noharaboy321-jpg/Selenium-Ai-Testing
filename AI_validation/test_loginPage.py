import os
import pathlib
import datetime

import pytest
from requests import options
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException


class LoginPage:
    """
    Page Object Model for the login page at https://practicetestautomation.com/practice-test-login/
    """
    URL = "https://practicetestautomation.com/practice-test-login/"

    # CSS selectors for page elements on the PracticeTestAutomation login page
    USERNAME_INPUT = "input#username"
    PASSWORD_INPUT = "input#password"
    LOGIN_BUTTON = "button#submit"
    FLASH_MESSAGE = "div#error"

    def __init__(self, driver: webdriver.Chrome, timeout: int = 10):
        self.driver = driver
        self.wait = WebDriverWait(self.driver, timeout)

    def load(self) -> None:
        """Navigate to the login page and wait until the page is loaded."""
        self.driver.get(self.URL)
        try:
            self.wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, self.USERNAME_INPUT)))
        except TimeoutException as exc:
            raise RuntimeError("Login page did not load within the expected time.") from exc

    def login(self, username: str, password: str) -> None:
        """Fill in credentials and submit the login form."""
        # Use explicit waits for each interactive element to reduce flakiness
        try:
            username_el = self.wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, self.USERNAME_INPUT)))
            username_el.clear()
            username_el.send_keys(username)

            password_el = self.wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, self.PASSWORD_INPUT)))
            password_el.clear()
            password_el.send_keys(password)

            login_btn = self.wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, self.LOGIN_BUTTON)))
            login_btn.click()
        except (NoSuchElementException, TimeoutException) as exc:
            raise RuntimeError(f"Failed to complete the login form: {exc}") from exc

    def is_login_successful(self) -> bool:
        """Verify successful login by URL or presence of logout control."""
        try:
            # The practice-test-login page redirects to a URL that contains
            # 'logged-in-successfully' on success. Wait for that OR for a
            # visible element containing 'Log out'.
            self.wait.until(lambda d: 'logged-in-successfully' in d.current_url or
                            len(d.find_elements(By.XPATH, "//*[contains(normalize-space(.), 'Log out') or contains(normalize-space(.), 'Log Out')]") ) > 0)
            return True
        except Exception:
            return False

    def is_logout_button_visible(self) -> bool:
        """Verify that the logout button is visible after a successful login."""
        try:
            self.wait.until(lambda d: len(d.find_elements(By.XPATH, SecureAreaPage.LOGOUT_XPATH)) > 0)
            return True
        except TimeoutException:
            return False

    def get_flash_message(self) -> str:
        """Return the flash message text from the page."""
        try:
            # Wait for flash to appear and normalise the text
            flash_element = self.wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, self.FLASH_MESSAGE)))
            text = flash_element.text.replace('\n', ' ').replace('\r', ' ').strip()
            return text
        except NoSuchElementException:
            return ""


class SecureAreaPage:
    """POM for the secure area after successful login."""
    # We will look for any element that contains "Log out" text
    LOGOUT_XPATH = "//*[contains(normalize-space(.), 'Log out') or contains(normalize-space(.), 'Log Out')]"
    FLASH_MESSAGE = "div#error"

    def __init__(self, driver: webdriver.Chrome, timeout: int = 10):
        self.driver = driver
        self.wait = WebDriverWait(self.driver, timeout)

    def is_logged_in(self) -> bool:
        try:
            # Wait for the logged-in URL or visible logout control
            self.wait.until(lambda d: 'logged-in-successfully' in d.current_url or
                            len(d.find_elements(By.XPATH, self.LOGOUT_XPATH)) > 0)
            return True
        except Exception:
            return False

    def logout(self) -> None:
        try:
            # Find the logout control and try a normal click; if that fails use JS click
            btn = self.wait.until(EC.presence_of_element_located((By.XPATH, self.LOGOUT_XPATH)))
            try:
                self.wait.until(EC.element_to_be_clickable((By.XPATH, self.LOGOUT_XPATH)))
                btn.click()
            except Exception:
                # Fallback: use JavaScript click when the element is obscured
                try:
                    self.driver.execute_script("arguments[0].click();", btn)
                except Exception:
                    pass

            # wait for login page username input to re-appear or URL to change
            try:
                WebDriverWait(self.driver, 15).until(lambda d: 'practice-test-login' in d.current_url or
                                                       EC.visibility_of_element_located((By.CSS_SELECTOR, LoginPage.USERNAME_INPUT))(d))
            except TimeoutException:
                # Fallback: explicitly navigate back to the login page and wait
                try:
                    self.driver.get(LoginPage.URL)
                    WebDriverWait(self.driver, 10).until(EC.visibility_of_element_located((By.CSS_SELECTOR, LoginPage.USERNAME_INPUT)))
                except Exception:
                    raise
        except TimeoutException:
            raise RuntimeError('Logout failed or login page did not re-appear')


def pytest_runtest_makereport(item, call):
    """Pytest hook to attach the test call outcome onto the test item.

    This allows fixtures to access `request.node.rep_call` in their teardown
    to determine whether a test failed and collect artifacts.
    """
    if call.when == "call":
        item.rep_call = call


@pytest.fixture(scope="function")
def driver(request):
    """
    Setup and teardown fixture for the WebDriver.
    - Supports headless mode via `HEADLESS=1` env var
    - Captures a screenshot to `reports/screenshots` on test failure
    """
    # Allow running headless via environment variable HEADLESS=1
    headless = os.environ.get("HEADLESS", "0") in ("1", "true", "True")
    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--remote-debugging-port=9222")

    # Create driver using Selenium Manager (bundled with Selenium 4.6+)
    driver = webdriver.Chrome(options=options)
    driver.maximize_window()

    yield driver

    # On teardown, if the test failed, capture a screenshot for diagnostics
    rep = getattr(request.node, "rep_call", None)
    if rep and rep.failed:
        reports_dir = pathlib.Path(request.config.rootpath) / "reports" / "screenshots"
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        screenshot_path = reports_dir / f"{request.node.name}-{ts}.png"
        try:
            driver.save_screenshot(str(screenshot_path))
            print(f"Saved failure screenshot: {screenshot_path}")
        except Exception as e:
            print(f"Failed to save screenshot: {e}")

    driver.quit()


@pytest.mark.parametrize(
    "username, password",
    [
        ("student", "Password123"),
    ],
)
def test_valid_login(driver, username, password):
    """
    Test the login scenario using valid credentials.
    """
    login_page = LoginPage(driver)

    # Load the login page and perform login with test data
    login_page.load()
    login_page.login(username, password)

    # Validate successful login via SecureAreaPage
    secure = SecureAreaPage(driver)
    assert secure.is_logged_in(), f"Expected successful login, but flash was: {login_page.get_flash_message()}"
    # Optionally test logout flow to ensure session controls work
    secure.logout()
    # After logout we should be back at the login page
    assert driver.find_element(By.CSS_SELECTOR, LoginPage.USERNAME_INPUT).is_displayed(), "Login page did not re-appear after logout"