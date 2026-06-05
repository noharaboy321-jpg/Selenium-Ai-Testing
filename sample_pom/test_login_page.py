from login_page import LoginPage
from dashboard_page import DashboardPage

def test_valid_login(driver):
    login_page = LoginPage(driver)
    dashboard_page = DashboardPage(driver)

    # Navigate to login page
    login_page.load_page()
    login_page.login("testuser", "securepassword")

    # Validate dashboard
    assert "Welcome" in dashboard_page.get_welcome_message()
