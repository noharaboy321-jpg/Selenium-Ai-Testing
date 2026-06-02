def test_verify_custom_dropdown_values(page: Page):
    page.goto("https://interstride.com")
    
    # 1. Click the custom dropdown box to render the options list in the DOM
    page.get_by_role("button", name="Select Employment Country").click()
    
    # 2. Locate all floating list items or rows that appeared
    options_list = page.locator(".custom-dropdown-menu-list li")
    
    # 3. Use a Web-First Assertion to wait for and verify the visible options
    # This automatically loops and polls the DOM for up to 5 seconds
    expect(options_list).to_have_text(["United States", "Canada", "United Kingdom"])