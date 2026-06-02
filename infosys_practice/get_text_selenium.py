from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC    
from selenium.common.exceptions import TimeoutException, NoSuchElementException

def test_extracting_the_text_from_table_column(url: str, row_selector: str):

    try:
        options=webdriver.ChromeOptions()
        options.add_argument('--headless')
        driver=webdriver.Chrome(options=options)

        wait = WebDriverWait(driver, 10)
        driver.get(url)

        table_row = wait.until(EC.visibility_of_element_located(By.CSS_SELECTOR,row_selector))
        column = table_row.find_element(By.XPATH, "./td[2]")

        text = column.text.strip()
        print(f"Extracted Text: '{text}'")  
        return text
    except TimeoutException:
        print("The page took too long to load or the element was not found within the expected time frame.")
        raise TimeoutException("Page load or element wait timed out.")  
    except NoSuchElementException:
        print("The specified element was not found on the page.")
        raise NoSuchElementException("Element not found.")          
    finally:
        driver.quit()