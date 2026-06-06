from login_page import LoginPage
from dashboard_page import DashboardPage

def test_valid_login_for_practice(driver):
    login_page = LoginPage(driver)
    dashboard_page = DashboardPage(driver)

    # Navigate to login page
    login_page.load_page()
    login_page.login("student", "Password123")

    # Validate dashboard
    assert "Logged In Successfully" in dashboard_page.get_welcome_message()
