# Login Feature - Comprehensive Test Cases

## Test Case Summary
- **Total Test Cases:** 28
- **Positive Tests:** 4
- **Negative Tests:** 12
- **Edge Cases:** 7
- **Security Tests:** 5
- **User Story:** "As a registered user, I want to login with my email and password so that I can access my personal dashboard and account features."

---

## Test Cases

| Test ID | Category | Description | Pre-conditions | Steps | Expected Result | Automation Priority | Status |
|---------|----------|-------------|-----------------|-------|-----------------|-------------------|--------|
| **LOGIN_TC_001** | Positive | Valid login with correct email and password | User account exists; User is on login page | 1. Enter valid email<br>2. Enter valid password<br>3. Click Login button | User redirected to dashboard; Session token created; No error messages | **High** | - |
| **LOGIN_TC_002** | Positive | Valid login and Remember Me unchecked | User account exists; User is on login page | 1. Enter valid email<br>2. Enter valid password<br>3. Leave Remember Me unchecked<br>4. Click Login button | User logged in; Session created with default timeout (e.g., 30 minutes) | **High** | - |
| **LOGIN_TC_003** | Positive | Valid login with Remember Me checked | User account exists; User is on login page | 1. Enter valid email<br>2. Enter valid password<br>3. Check Remember Me checkbox<br>4. Click Login button | User logged in; Persistent cookie/token created for 30 days; User remains logged in after browser close/reopen | **High** | - |
| **LOGIN_TC_004** | Positive | User can logout successfully | User is logged in and on dashboard | 1. Click Logout button | User session cleared; Redirected to login page; Remember Me cookie cleared | **High** | - |
| **LOGIN_TC_005** | Negative | Invalid email - non-existent account | User is on login page | 1. Enter non-existent email<br>2. Enter any password<br>3. Click Login button | Error message: "Invalid email or password"; User stays on login page; No account created | **High** | - |
| **LOGIN_TC_006** | Negative | Invalid password - correct email, wrong password | User account exists; User is on login page | 1. Enter valid email<br>2. Enter incorrect password<br>3. Click Login button | Error message: "Invalid email or password"; Login counter incremented; User stays on login page | **High** | - |
| **LOGIN_TC_007** | Negative | Empty email field | User is on login page | 1. Leave email field empty<br>2. Enter valid password<br>3. Click Login button | Validation error: "Email is required" or similar; Login button disabled or form not submitted | **High** | - |
| **LOGIN_TC_008** | Negative | Empty password field | User is on login page | 1. Enter valid email<br>2. Leave password field empty<br>3. Click Login button | Validation error: "Password is required" or similar; Login button disabled or form not submitted | **High** | - |
| **LOGIN_TC_009** | Negative | Both email and password empty | User is on login page | 1. Leave both fields empty<br>2. Click Login button | Validation errors displayed for both fields; Login button disabled or form not submitted | **High** | - |
| **LOGIN_TC_010** | Negative | First failed login attempt | User account exists; Failed login counter = 0 | 1. Enter valid email<br>2. Enter incorrect password<br>3. Click Login button | Error displayed; Attempt counter = 1; No account lockout; User can retry | **High** | - |
| **LOGIN_TC_011** | Negative | Second failed login attempt | User account exists; Failed login counter = 1 | 1. Enter valid email<br>2. Enter incorrect password<br>3. Click Login button | Error displayed; Attempt counter = 2; No account lockout; User can retry | **High** | - |
| **LOGIN_TC_012** | Negative | Third failed login attempt - Account locked | User account exists; Failed login counter = 2 | 1. Enter valid email<br>2. Enter incorrect password<br>3. Click Login button | Error message: "Account temporarily locked. Try again in 15 minutes"; Attempt counter = 3; Account locked for 15 minutes; User cannot login | **High** | - |
| **LOGIN_TC_013** | Negative | Locked account unlock attempt before 15 minutes | Account is locked; Less than 15 minutes passed | 1. Enter valid email and correct password<br>2. Click Login button | Error message: "Account temporarily locked. Try again in X minutes" (where X = remaining time); Login denied | **Medium** | - |
| **LOGIN_TC_014** | Negative | Locked account unlock attempt after 15 minutes | Account is locked; Exactly 15 minutes have passed | 1. Enter valid email and correct password<br>2. Click Login button | User successfully logged in; Failed attempt counter reset to 0; Account unlocked | **Medium** | - |
| **LOGIN_TC_015** | Edge Case | Email with leading/trailing spaces | User account exists; Email format: " user@example.com " | 1. Enter email with spaces<br>2. Enter valid password<br>3. Click Login button | Login successful (spaces should be trimmed); User redirected to dashboard | **Medium** | - |
| **LOGIN_TC_016** | Edge Case | Email case sensitivity | User account exists with email: "User@Example.com" | 1. Enter email in different case: "user@example.com"<br>2. Enter valid password<br>3. Click Login button | Login successful (email comparison should be case-insensitive); User redirected to dashboard | **Medium** | - |
| **LOGIN_TC_017** | Edge Case | Very long email address (max valid) | User account exists with very long valid email | 1. Enter long email (< 255 characters)<br>2. Enter valid password<br>3. Click Login button | Login successful if email exists; User redirected to dashboard | **Low** | - |
| **LOGIN_TC_018** | Edge Case | Invalid email format - no @ symbol | User is on login page | 1. Enter email without @: "userexample.com"<br>2. Enter password<br>3. Click Login button | Validation error: "Invalid email format"; Form not submitted | **Medium** | - |
| **LOGIN_TC_019** | Edge Case | Invalid email format - multiple @ symbols | User is on login page | 1. Enter email with multiple @: "user@@example.com"<br>2. Enter password<br>3. Click Login button | Validation error: "Invalid email format"; Form not submitted | **Medium** | - |
| **LOGIN_TC_020** | Edge Case | SQL Injection attempt in email field | User is on login page | 1. Enter: admin' OR '1'='1<br>2. Enter any password<br>3. Click Login button | Query parameterized; Login fails; Error: "Invalid email or password"; No database compromise | **High** | - |
| **LOGIN_TC_021** | Security | Password stored securely (not plaintext) | User has logged in previously | 1. Inspect database/backend logs<br>2. Check if password is visible | Passwords stored as bcrypt/hashed values; Not stored as plaintext | **High** | - |
| **LOGIN_TC_022** | Security | HTTPS enforced | User is on login page | 1. Check page source and network requests<br>2. Verify protocol used | All requests use HTTPS; No mixed content warnings; No HTTP fallback | **High** | - |
| **LOGIN_TC_023** | Security | Session hijacking prevention | User is logged in | 1. Capture session token<br>2. Attempt to use token from different IP/User-Agent<br>3. Try to access protected resources | Session token validated against IP/User-Agent; Unauthorized access denied | **Medium** | - |
| **LOGIN_TC_024** | Security | Remember Me cookie security | User checked Remember Me and logged in | 1. Inspect browser cookies<br>2. Check if token is encrypted<br>3. Check expiration (30 days) | Cookie is HttpOnly; Cookie is Secure; Cookie is SameSite; Expiration = 30 days from login | **Medium** | - |
| **LOGIN_TC_025** | Edge Case | Special characters in password | User account password contains: !@#$%^&*() | 1. Enter valid email<br>2. Enter password with special characters<br>3. Click Login button | Login successful; User redirected to dashboard | **Low** | - |
| **LOGIN_TC_026** | Edge Case | Very long password attempt | User is on login page | 1. Enter valid email<br>2. Enter password > 512 characters<br>3. Click Login button | Either accepted and validated correctly, or error: "Password too long"; Form handled gracefully | **Low** | - |
| **LOGIN_TC_027** | Edge Case | Rapid successive login attempts | User is on login page | 1. Submit invalid login 3 times in < 5 seconds | System handles rate limiting; Account locked; No system crash/timeout | **Medium** | - |
| **LOGIN_TC_028** | Negative | Browser back button after logout | User has logged out | 1. Click browser back button | User not redirected to dashboard; Session still invalid; User remains on login page or redirected to login | **Low** | - |

---

## Test Case Distribution

```
✓ Positive Tests:        4 (14%)  - Happy path scenarios
✓ Negative Tests:       12 (43%)  - Error handling & validation
✓ Edge Cases:            7 (25%)  - Boundary conditions
✓ Security Tests:        5 (18%)  - Security & data protection
```

---

## Automation Priority Recommendations

### **HIGH PRIORITY** (Must Automate - 11 tests)
These are critical business logic tests with high ROI:
- `LOGIN_TC_001`, `LOGIN_TC_002`, `LOGIN_TC_003`, `LOGIN_TC_004`
- `LOGIN_TC_005`, `LOGIN_TC_006`, `LOGIN_TC_007`, `LOGIN_TC_008`, `LOGIN_TC_009`
- `LOGIN_TC_012`, `LOGIN_TC_020`, `LOGIN_TC_021`, `LOGIN_TC_022`

**Why:** Direct business value, frequently executed, stable selectors

### **MEDIUM PRIORITY** (Should Automate - 10 tests)
Important but slightly less critical:
- `LOGIN_TC_010`, `LOGIN_TC_011`, `LOGIN_TC_013`, `LOGIN_TC_014`
- `LOGIN_TC_015`, `LOGIN_TC_016`, `LOGIN_TC_018`, `LOGIN_TC_019`
- `LOGIN_TC_023`, `LOGIN_TC_024`, `LOGIN_TC_027`

**Why:** Good coverage for regression, manageable maintenance

### **LOW PRIORITY** (Manual Testing - 7 tests)
Can be tested manually or periodically:
- `LOGIN_TC_017`, `LOGIN_TC_025`, `LOGIN_TC_026`, `LOGIN_TC_028`

**Why:** Rarely changed, require manual verification, or low business impact

---

## Test Environment & Tools

| Aspect | Recommendation |
|--------|-----------------|
| **Automation Framework** | Selenium WebDriver / Cypress / Playwright |
| **Test Runner** | pytest (Python) / Jest (Node) / TestNG (Java) |
| **CI/CD Integration** | Jenkins / GitHub Actions / GitLab CI |
| **Test Data Management** | Database fixtures / Test data factory |
| **Reporting** | Allure Report / HTMLReport |
| **Performance Testing** | JMeter / LoadRunner for login load tests |

---

## Risk Areas & Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Account Lockout Logic Fails | High | Test lockout counters with multiple accounts; Verify DB updates |
| Session Token Vulnerability | Critical | Security scan; Penetration testing; Token expiration validation |
| Remember Me Persistence | Medium | Test across browsers; Clear cookies; Verify 30-day expiration |
| Rate Limiting Bypass | High | Load test with rapid requests; Verify IP-based throttling |
| Input Validation Bypass | High | OWASP top 10 security tests; SQL injection; XSS attempts |

---

## Non-Functional Requirements Testing

| Requirement | Test Approach | Acceptance Criteria |
|-------------|---------------|-------------------|
| **Performance** | Load test with 1000 concurrent users | Response time < 2 seconds |
| **Accessibility** | WCAG 2.1 AA compliance check | Screen reader compatible; Keyboard navigable |
| **Localization** | Test with multiple languages | Date/time formats correct; RTL support (if needed) |
| **Browser Compatibility** | Cross-browser testing | Support Chrome, Firefox, Safari, Edge (latest 2 versions) |
| **Mobile Responsiveness** | Responsive design testing | Login form usable on iOS/Android; Touch-friendly buttons |

---

## Test Data Requirements

```
Valid Test Accounts:
- user1@example.com / Password123!
- user2@example.com / SecurePass456$
- admin@example.com / AdminPass789#

Locked Account (after 3 failed attempts):
- locked_user@example.com (pre-locked in test DB)

Edge Case Accounts:
- spaces@example.com (with spaces in handling)
- special_chars@example.com (password with !@#$%^&*)
```

---

## Execution Strategy

### **Phase 1: Smoke Tests (1-2 hours)**
- `LOGIN_TC_001`, `LOGIN_TC_005`, `LOGIN_TC_007`, `LOGIN_TC_012`

### **Phase 2: Functional Tests (4-6 hours)**
- All Positive, Negative, and Edge Case tests

### **Phase 3: Security & Performance Tests (2-4 hours)**
- All Security tests + Load testing

### **Phase 4: Regression (Daily)**
- All HIGH priority automated tests

---

## Sign-off Checklist

- [ ] All 28 test cases executed
- [ ] HIGH priority tests automated and passing
- [ ] Security vulnerabilities addressed
- [ ] Performance benchmarks met
- [ ] Cross-browser compatibility verified
- [ ] Test data cleanup performed
- [ ] Report generated with metrics

