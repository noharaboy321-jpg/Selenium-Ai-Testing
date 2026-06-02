from base_page import BasePage




class DashboardPage(BasePage):
    
    welcome = driver.find_element_by_id('welcome')
    setting_element = driver.find_element_by_id('setting')
    logout_element = driver.find_element_by_id('logout')


    def __init__(self, driver):
        super().__init__(driver)
        self.url_path = '/dashboard'

    def load_page(self):
        self.navigate_to(self.url_path)
    

    def get_welcome_message(self):
        return self.welcome.text
    

    def click_settings(self):
        self.click_on_element(setting_element)
