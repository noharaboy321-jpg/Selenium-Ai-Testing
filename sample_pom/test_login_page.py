

class TestLoginPage:
    

    def test_user_login_successfully(login_page, dashboard_page):
        login_page.load_page()
        login_page.login('admin', 'password123')

        welcome_message = dashboard_page.get_welcome_message()
        assert welcome_message == "Welcome, admin!", "Login failed or welcome message is incorrect."



def safe_get_text(self, locator: tuple[str, str]) -> str:
    """Waits for an element to refresh and returns its current text."""
    # EC.refreshed will catch StaleElementReferenceException and re-locate the element
    element = self.wait.until( ##TODO: Consider if we need to wait for visibility or just presence before refreshing
        EC.refreshed(EC.visibility_of_element_located(locator))
    )
    return element.text


driver.switch_to.frame("parent_iframe_id")
driver.switch_to.frame("child_iframe_id")
driver.find_element(By.ID, "target-element").click()
driver.switch_to.default_content() # Resets back to the main document

parent_window = driver.current_window_handle
# Perform click that spawns new window...
all_windows = driver.window_handles
for handle in all_windows:
    if handle != parent_window:
        driver.switch_to.window(handle)
        break

import pytest
from utils.excel_reader import get_excel_data

@pytest.mark.parametrize("username,password", get_excel_data("login_suite.xlsx"))
def test_portal_login(page, username, password):
    page.goto("https://bank.com")
    # Test execution...