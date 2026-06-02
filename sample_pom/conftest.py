import pytest
from pages.login_page import LoginPage
from pages.dashboard_page import DashboardPage  
from selenium import webdriver


@pytest.fixture(scope="function")
def driver():
    
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')

    driver = webdriver.Chrome(options=options)
    yield driver

    driver.quit()   

@pytest.fixture(scope="function")
def login_page(driver):
    return LoginPage(driver)

@pytest.fixture(scope="function")
def dashboard_page(driver): 
    return DashboardPage(driver)

