from playwright.sync_api import sync_playwright

def test_verify_mobile_testimonial_layout():
    with sync_playwright() as p:
        # Emulate an iPhone 12 viewport context
        iphone_12 = p.devices['iPhone 12']
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(**iphone_12)
        page = context.new_page()

        page.goto("https://www.interstride.com/")
        page.wait_for_load_state("networkidle")

        # Select the customer/student testimonial section carousel wrapper
        # Target a text block to pinpoint the testimonial module coordinates
        testimonial_card = page.locator("text=Completely streamlines the job search process").first
        testimonial_card.wait_for(state="visible")

        # Extract structural dimensions of the rendered layout bounding box
        box = testimonial_card.bounding_box()
        
        viewport_width = iphone_12['viewport']['width']
        
        print(f"Mobile Viewport Width: {viewport_width}px")
        print(f"Testimonial Element Render Dimensions: {box}")

        # ASSERTION: Ensure the element's width + its starting offset does not exceed screen boundaries
        element_end_position = box['x'] + box['width']
        
        if element_end_position > viewport_width:
            page.screenshot(path="mobile_clipping_evidence.png")
            print("📸 Captured clipping bug screenshot evidence.")
            raise AssertionError(f"LAYOUT BUG: Testimonial element extends to {element_end_position}px, clipping past the mobile screen width of {viewport_width}px.")
        
        print("Layout test passed successfully on mobile viewports.")
        browser.close()

if __name__ == "__main__":
    test_verify_mobile_testimonial_layout()
