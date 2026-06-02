from playwright.sync_api import sync_playwright

def test_extract_text_from_element(url: str, row_selector:str):
    
    try:
        with sync_playwright as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            page.goto(url)

            table_row = page.locator(row_selector)
            table_row.wait_for(state="visible", timeout=5000)

            coloumn = table_row.locator("td").nth(1)
            text = coloumn.inner_text().strip()

            print(f"Extracted Text: '{text}'")      
            return text

    
    except Exception as e:
        print(f"An error occurred during Playwright execution: {e}")
        raise e 
    except TimeoutError:
        print("The page took too long to load or the element was not found within the expected time frame.")
        raise TimeoutError("Page load or element wait timed out.")
    finally:
        context.close()
        browser.close() 