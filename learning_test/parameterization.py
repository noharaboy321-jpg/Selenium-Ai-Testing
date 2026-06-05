"""
The Scenario: The QA delivery team needs to validate a billing feature 
across 4 different web browsers (Chromium, Firefox, WebKit, Edge) 
combined with 3 different user tier roles (Admin, Manager, Viewer).

"""


import pytest

@pytest.mark.parametrize("browser_type", ["chromium", "firefox", "webkit"])
@pytest.mark.parametrize("user_role", ["admin", "manager", "viewer"])
def test_enterprise_billing_access(authenticated_page, browser_type, user_role):
    # Pytest automatically multiples these configurations (3 x 3 = 9 individual runs)
    print(f"Executing test execution on matrix node: {browser_type} as {user_role}")
    
    authenticated_page.goto(f"https://tradingplatform.com{user_role}")
    assert authenticated_page.is_visible("#billing-matrix-header")
