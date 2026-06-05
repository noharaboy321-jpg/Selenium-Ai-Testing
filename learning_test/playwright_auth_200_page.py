
import os
import pytest
from playwright.sync_api import sync_playwright, BrowserContext, Page

AUTH_FILE = "auth.json"

# ==============================================================================
# FIXTURE 1: THE GLOBAL SESSION AUTHENTICATION GENERATOR
# ==============================================================================
@pytest.fixture(scope="session", autouse=True)
def global_auth():                                                  # Removed the arbitrary 'url' argument as pytest session fixtures need global values.
    
    # --------------------------------------------------------------------------------------------------------------------------------------
    # CHECK FOR CACHED AUTHENTICATION:
    # If the file exists from a previous run, skip the login entirely to save compute time.
    # --------------------------------------------------------------------------------------------------------------------------------------
    if not os.path.exists(AUTH_FILE):                               # Fixed typo: changed 'os.path.exist' to 'os.path.exists'.
        print('\n[AUTH]: No active session found. Initiating fresh login flow...')
        
        with sync_playwright() as p:                                # Fixed syntax: added () to initialize the context manager.
            browser = p.chromium.launch(headless=True)              # Fixed typos: corrected 'chromiun' to 'chromium' and 'true' to 'True'.
            context = browser.new_context()
            page = context.new_page()
            
            page.goto("https://tradingplatform.com")          # Fixed: passed a direct valid endpoint instead of a broken string wrapper.
            
            page.fill("#username", "my_secure_username")            # Simulated locator definitions
            page.fill("#password", "my_secure_password")
            page.click("#submit-btn")
            
            page.wait_for_selector(".welcome-dashboard")            # Wait for dashboard to confirm successful login redirection.
            
            # Save cookies and local storage tokens securely to a local file
            context.storage_state(path=AUTH_FILE)
            browser.close()
    else:
        print('\n[AUTH]: Active session detected. Reusing saved storage state tokens.')
        
    yield                                                           # Hand control over to the executing test layers.

# ==============================================================================
# FIXTURE 2: SYSTEM WORKER ISOLATION (The Test Session Setup)
# ==============================================================================
@pytest.fixture(scope="function")                                   # Runs once per individual test function to ensure clean room isolation.
def authenticated_page():                                           # Match naming convention perfectly.
    
    with sync_playwright() as p:                                    # Initialize execution thread loop.
        browser = p.chromium.launch(headless=True)                  # Launch execution browser.
        
        # ----------------------------------------------------------------------------------------------------------------------------------
        # INJECTING STORAGE STATE:
        # Instead of going to the login page, this context instantly inherits the cookies/tokens from our cached session auth file.
        # ----------------------------------------------------------------------------------------------------------------------------------
        context = browser.new_context(storage_state=AUTH_FILE)
        page = context.new_page()
        
        yield page                                                  # Inject the fully ready, pre-authenticated page object directly into the test function.
        
        # ----------------------------------------------------------------------------------------------------------------------------------
        # CLEANUP TEARDOWN:
        # These lines execute IMMEDIATELY after a test finishes. They must sit inside the 'with' scope to remain valid references.
        # ----------------------------------------------------------------------------------------------------------------------------------
        context.close()                                             
        browser.close()                                             # Prevents zombie driver processes from lingering in your cloud CI agents.

# ==============================================================================
# THE EXECUTING AUTOMATION SUITE
# ==============================================================================
def test_user_can_view_account_balances(authenticated_page: Page):  # Injected the fixture by using its exact match name.
    # We are already logged in automatically because of the fixture's storage state injection!
    authenticated_page.goto("https://tradingplatform.com")
    
    # Run immediate validations
    assert authenticated_page.is_visible(".balance-amount-display")

def test_user_can_download_tax_invoices(authenticated_page: Page):
    authenticated_page.goto("https://tradingplatform.com")
    assert authenticated_page.is_enabled("#download-pdf-btn")

#=============================================================================

import os
import pytest
from playwright.sync_api import sync_playwright

AUTH_FILE = "auth.json"

@pytest.fixture(scope="session", autouse=True)
def global_api_auth():
    if not os.path.exists(AUTH_FILE):
        with sync_playwright() as p:
            request_context = p.request.new_context(base_url="https://tradingplatform.com")
            
            login_payload = {
                "username": "my_secure_username",
                "password": "my_secure_password"
            }
            
            response = request_context.post("/api/v1/login", data=login_payload)
            
            if response.ok:
                request_context.storage_state(path=AUTH_FILE)
            else:
                raise Exception(f"API Authentication Failed: {response.status}")
                
            request_context.dispose()
    yield





















