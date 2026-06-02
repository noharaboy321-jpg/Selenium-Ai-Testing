import re
from playwright.sync_api import sync_playwright

def test_verify_enrollment_dates():
    with sync_playwright() as p:
        # Launch browser (set headless=False if you want to watch it run)
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        print("Navigating to Interstride Masterclass Overview...")
        page.goto("https://www.interstride.com/masterclass-course-overview/")
        page.wait_for_load_state("networkidle")

        print("Exposing the hidden waitlist form elements...")
        # Inject JavaScript to find the hidden dropdown container and make it visible
        page.evaluate("""
            () => {
                const elements = document.getElementsByTagName('*');
                for (let el of elements) {
                    if (el.textContent && el.textContent.includes("Intended enrollment date")) {
                        // Force parent nodes and the target element to display
                        el.style.display = 'block';
                        el.style.visibility = 'visible';
                        let parent = el.parentElement;
                        while(parent) {
                            parent.style.display = 'block';
                            parent.style.visibility = 'visible';
                            parent = parent.parentElement;
                        }
                    }
                }
            }
        """)

        # Locate the enrollment date dropdown selector
        # Using a relaxed regex lookahead matching 'intended' or 'enrollment' attributes/labels
        dropdown_locator = page.locator("select, select[name*='enrollment'], select[id*='enrollment']").first
        
        # Ensure the element exists in the DOM after modification
        dropdown_locator.wait_for(state="attached", timeout=5000)

        print("Extracting values from the 'Intended enrollment date' dropdown...")
        # Pull all textual options inside that dropdown list
        options = dropdown_locator.locator("option").all_inner_texts()
        print(f"Found options: {options}")

        # Define our defect evaluation constraints (Current year is 2026)
        outdated_year_pattern = re.compile(r"2023|2024|2025")
        found_defects = [opt for opt in options if outdated_year_pattern.search(opt)]

        # Diagnostic Capture: If a bug is caught, take a local screenshot proof
        if found_defects:
            page.screenshot(path="defect_evidence_2024_dates.png", full_page=True)
            print(f"📸 Screenshot evidence saved to defect_evidence_2024_dates.png")

        # Core Test Assertion
        assert not found_defects, f"BUG FOUND: The dropdown contains outdated target periods: {found_defects}"
        
        print("Test passed! No outdated date strings detected.")
        browser.close()

if __name__ == "__main__":
    test_verify_enrollment_dates()
