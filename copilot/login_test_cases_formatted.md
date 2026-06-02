# Login Feature - Test Cases (Formatted)

---

## 📋 POSITIVE TEST CASES

| TC ID | Test Name | Pre-Conditions | Steps | Expected Result | Priority |
|-------|-----------|----------------|-------|-----------------|----------|
| **LOGIN_TC_001** | Valid Login with Correct Credentials | • User account exists<br>• User is on login page | 1. Enter valid email<br>2. Enter valid password<br>3. Click Login button | • User redirected to dashboard<br>• Session token created<br>• No error messages | **HIGH** |
| **LOGIN_TC_002** | Valid Login - Remember Me Unchecked | • User account exists<br>• User is on login page | 1. Enter valid email<br>2. Enter valid password<br>3. Leave Remember Me unchecked<br>4. Click Login button | • User logged in successfully<br>• Session created with default timeout (30 min)<br>• User logged out after timeout | **HIGH** |
| **LOGIN_TC_003** | Valid Login - Remember Me Checked | • User account exists<br>• User is on login page | 1. Enter valid email<br>2. Enter valid password<br>3. Check Remember Me checkbox<br>4. Click Login button | • User logged in successfully<br>• Persistent cookie created for 30 days<br>• User remains logged in after browser close/reopen | **HIGH** |
| **LOGIN_TC_004** | Successful Logout | • User is logged in<br>• User is on dashboard | 1. Click Logout button | • User session cleared<br>• Redirected to login page<br>• Remember Me cookie cleared | **HIGH** |

---

## ❌ NEGATIVE TEST CASES

| TC ID | Test Name | Pre-Conditions | Steps | Expected Result | Priority |
|-------|-----------|----------------|-------|-----------------|----------|
| **LOGIN_TC_005** | Invalid Email - Non-Existent Account | • User is on login page | 1. Enter non-existent email<br>2. Enter any password<br>3. Click Login button | • Error message: "Invalid email or password"<br>• User stays on login page<br>• No account created | **HIGH** |
| **LOGIN_TC_006** | Invalid Password | • User account exists<br>• User is on login page | 1. Enter valid email<br>2. Enter incorrect password<br>3. Click Login button | • Error message: "Invalid email or password"<br>• Login counter incremented<br>• User stays on login page | **HIGH** |
| **LOGIN_TC_007** | Empty Email Field | • User is on login page | 1. Leave email field empty<br>2. Enter valid password<br>3. Click Login button | • Validation error: "Email is required"<br>• Login button disabled<br>• Form not submitted | **HIGH** |
| **LOGIN_TC_008** | Empty Password Field | • User is on login page | 1. Enter valid email<br>2. Leave password field empty<br>3. Click Login button | • Validation error: "Password is required"<br>• Login button disabled<br>• Form not submitted | **HIGH** |
| **LOGIN_TC_009** | Both Fields Empty | • User is on login page | 1. Leave both fields empty<br>2. Click Login button | • Validation errors for both fields<br>• Login button disabled<br>• Form not submitted | **HIGH** |
| **LOGIN_TC_010** | First Failed Login Attempt | • User account exists<br>• Failed attempts = 0 | 1. Enter valid email<br>2. Enter incorrect password<br>3. Click Login button | • Error message displayed<br>• Attempt counter = 1<br>• No account lockout<br>• User can retry | **HIGH** |
| **LOGIN_TC_011** | Second Failed Login Attempt | • User account exists<br>• Failed attempts = 1 | 1. Enter valid email<br>2. Enter incorrect password<br>3. Click Login button | • Error message displayed<br>• Attempt counter = 2<br>• No account lockout<br>• User can retry | **HIGH** |
| **LOGIN_TC_012** | Third Failed Login - Account Locked | • User account exists<br>• Failed attempts = 2 | 1. Enter valid email<br>2. Enter incorrect password<br>3. Click Login button | • Error message: "Account temporarily locked. Try again in 15 minutes"<br>• Attempt counter = 3<br>• Account locked for 15 minutes<br>• User cannot login | **HIGH** |
| **LOGIN_TC_013** | Locked Account - Attempt Before 15 Minutes | • Account is locked<br>• Less than 15 minutes passed | 1. Enter valid email and correct password<br>2. Click Login button | • Error message: "Account temporarily locked. Try again in X minutes"<br>• Login denied<br>• Account still locked | **MEDIUM** |
| **LOGIN_TC_014** | Locked Account - Attempt After 15 Minutes | • Account is locked<br>• Exactly 15 minutes have passed | 1. Enter valid email and correct password<br>2. Click Login button | • User successfully logged in<br>• Failed attempt counter reset to 0<br>• Account unlocked | **MEDIUM** |

---

## 🔧 EDGE CASE TEST CASES

| TC ID | Test Name | Pre-Conditions | Steps | Expected Result | Priority |
|-------|-----------|----------------|-------|-----------------|----------|
| **LOGIN_TC_015** | Email with Leading/Trailing Spaces | • User account exists<br>• Email: "user@example.com" | 1. Enter email with spaces: " user@example.com "<br>2. Enter valid password<br>3. Click Login button | • Login successful (spaces trimmed)<br>• User redirected to dashboard | **MEDIUM** |
| **LOGIN_TC_016** | Email Case Insensitivity | • User account with "User@Example.com"<br>• User is on login page | 1. Enter email in different case: "user@example.com"<br>2. Enter valid password<br>3. Click Login button | • Login successful<br>• Email comparison is case-insensitive<br>• User redirected to dashboard | **MEDIUM** |
| **LOGIN_TC_017** | Very Long Email Address | • User account exists with very long valid email (< 255 chars)<br>• User is on login page | 1. Enter long email<br>2. Enter valid password<br>3. Click Login button | • Login successful if email exists<br>• User redirected to dashboard | **LOW** |
| **LOGIN_TC_018** | Invalid Email Format - No @ Symbol | • User is on login page | 1. Enter email without @: "userexample.com"<br>2. Enter password<br>3. Click Login button | • Validation error: "Invalid email format"<br>• Form not submitted | **MEDIUM** |
| **LOGIN_TC_019** | Invalid Email Format - Multiple @ Symbols | • User is on login page | 1. Enter email with multiple @: "user@@example.com"<br>2. Enter password<br>3. Click Login button | • Validation error: "Invalid email format"<br>• Form not submitted | **MEDIUM** |
| **LOGIN_TC_025** | Special Characters in Password | • User password contains: !@#$%^&*()<br>• User is on login page | 1. Enter valid email<br>2. Enter password with special characters<br>3. Click Login button | • Login successful<br>• User redirected to dashboard | **LOW** |
| **LOGIN_TC_026** | Very Long Password (Boundary Test) | • User is on login page | 1. Enter valid email<br>2. Enter password > 512 characters<br>3. Click Login button | • Either accepted and validated correctly<br>• OR error: "Password too long"<br>• Form handled gracefully | **LOW** |

---

## 🔒 SECURITY TEST CASES

| TC ID | Test Name | Pre-Conditions | Steps | Expected Result | Priority |
|-------|-----------|----------------|-------|-----------------|----------|
| **LOGIN_TC_020** | SQL Injection Prevention | • User is on login page | 1. Enter email: admin' OR '1'='1<br>2. Enter any password<br>3. Click Login button | • Query parameterized<br>• Login fails with "Invalid email or password"<br>• No database compromise<br>• No SQL errors exposed | **HIGH** |
| **LOGIN_TC_021** | Password Not Stored as Plaintext | • User has logged in previously<br>• Database access available | 1. Query database for user password<br>2. Check if password is visible in plaintext | • Passwords stored as bcrypt/hashed<br>• Not stored as plaintext<br>• Cannot reverse engineer password | **HIGH** |
| **LOGIN_TC_022** | HTTPS Enforcement | • User is on login page | 1. Check page source<br>2. Inspect network requests<br>3. Verify protocol used | • All requests use HTTPS<br>• No mixed content warnings<br>• No HTTP fallback<br>• Secure connection indicated | **HIGH** |
| **LOGIN_TC_023** | Session Hijacking Prevention | • User is logged in<br>• Session token captured | 1. Capture session token<br>2. Attempt to use token from different IP/User-Agent<br>3. Try to access protected resources | • Session token validated against IP/User-Agent<br>• Unauthorized access denied<br>• User remains authenticated on original session | **MEDIUM** |
| **LOGIN_TC_024** | Remember Me Cookie Security | • User checked Remember Me<br>• User is logged in | 1. Inspect browser cookies<br>2. Check cookie encryption<br>3. Verify 30-day expiration | • Cookie is HttpOnly (not accessible via JS)<br>• Cookie is Secure (HTTPS only)<br>• Cookie is SameSite (CSRF protection)<br>• Expiration = 30 days from login | **MEDIUM** |

---

## ⚡ RATE LIMITING TEST CASE

| TC ID | Test Name | Pre-Conditions | Steps | Expected Result | Priority |
|-------|-----------|----------------|-------|-----------------|----------|
| **LOGIN_TC_027** | Rapid Successive Login Attempts | • User is on login page | 1. Submit invalid login 3 times in < 5 seconds | • System handles rate limiting<br>• Account locked after 3 attempts<br>• No system crash/timeout<br>• Request throttled appropriately | **MEDIUM** |

---

## 🔄 POST-LOGIN TEST CASE

| TC ID | Test Name | Pre-Conditions | Steps | Expected Result | Priority |
|-------|-----------|----------------|-------|-----------------|----------|
| **LOGIN_TC_028** | Browser Back Button After Logout | • User has logged out | 1. Click browser back button | • User NOT redirected to dashboard<br>• Session remains invalid<br>• User stays on login page OR redirected to login | **LOW** |

---

## 📊 TEST CASE SUMMARY TABLE

| Category | Count | Percentage | Details |
|----------|-------|-----------|---------|
| **Positive Tests** | 4 | 14% | Happy path - valid login scenarios |
| **Negative Tests** | 10 | 36% | Error handling & validation |
| **Edge Cases** | 7 | 25% | Boundary conditions & special inputs |
| **Security Tests** | 5 | 18% | Data protection & vulnerabilities |
| **Rate Limiting** | 1 | 4% | Performance & DoS protection |
| **Post-Login** | 1 | 4% | Session management after logout |
| **TOTAL** | **28** | **100%** | Comprehensive coverage |

---

## 🎯 AUTOMATION PRIORITY BREAKDOWN

### ✅ HIGH PRIORITY (Automate First)
**Total: 11 tests** - Must automate for regression suite

- LOGIN_TC_001 - Valid login
- LOGIN_TC_002 - Remember Me unchecked
- LOGIN_TC_003 - Remember Me checked
- LOGIN_TC_004 - Logout
- LOGIN_TC_005 - Invalid email
- LOGIN_TC_006 - Invalid password
- LOGIN_TC_007 - Empty email
- LOGIN_TC_008 - Empty password
- LOGIN_TC_009 - Both empty
- LOGIN_TC_012 - Account locked (3 attempts)
- LOGIN_TC_020 - SQL injection prevention
- LOGIN_TC_021 - Password hashing
- LOGIN_TC_022 - HTTPS enforcement

---

### 🟡 MEDIUM PRIORITY (Should Automate)
**Total: 10 tests** - Good regression coverage

- LOGIN_TC_010 - First failed attempt
- LOGIN_TC_011 - Second failed attempt
- LOGIN_TC_013 - Locked account before 15 min
- LOGIN_TC_014 - Locked account after 15 min
- LOGIN_TC_015 - Email trimming
- LOGIN_TC_016 - Case insensitivity
- LOGIN_TC_018 - No @ symbol validation
- LOGIN_TC_019 - Multiple @ validation
- LOGIN_TC_023 - Session hijacking prevention
- LOGIN_TC_024 - Cookie security
- LOGIN_TC_027 - Rate limiting

---

### 🔵 LOW PRIORITY (Manual Testing)
**Total: 7 tests** - Can be tested manually or periodically

- LOGIN_TC_017 - Very long email
- LOGIN_TC_025 - Special characters in password
- LOGIN_TC_026 - Very long password
- LOGIN_TC_028 - Browser back button

---

## 📋 TEST EXECUTION CHECKLIST

### Phase 1: Smoke Tests (1-2 hours)
- [ ] LOGIN_TC_001 - Valid login
- [ ] LOGIN_TC_005 - Invalid email
- [ ] LOGIN_TC_007 - Empty email
- [ ] LOGIN_TC_012 - Account locked

### Phase 2: Functional Tests (4-6 hours)
- [ ] All Positive tests (TC_001 to TC_004)
- [ ] All Negative tests (TC_005 to TC_014)
- [ ] Edge case tests (TC_015 to TC_026)

### Phase 3: Security & Performance (2-4 hours)
- [ ] All Security tests (TC_020 to TC_024)
- [ ] Rate limiting test (TC_027)

### Phase 4: Regression (Daily)
- [ ] All HIGH priority automated tests

---

## 🛠️ TEST DATA SETUP

```
VALID TEST ACCOUNTS:
├─ user1@example.com / Password123!
├─ user2@example.com / SecurePass456$
└─ admin@example.com / AdminPass789#

LOCKED ACCOUNT (Pre-locked):
├─ locked_user@example.com (already has 3 failed attempts)

EDGE CASE ACCOUNTS:
├─ spaces@example.com (for space trimming test)
├─ special_chars@example.com (password: !@#$%^&*())
└─ long_email_user@example.com (254 character email)
```

---

## ✔️ SIGN-OFF CRITERIA

- [x] All 28 test cases documented
- [ ] HIGH priority tests automated (11/11)
- [ ] MEDIUM priority tests automated (10/10)
- [ ] LOW priority tests executed manually (7/7)
- [ ] All tests passed
- [ ] Security vulnerabilities addressed
- [ ] Performance benchmarks met
- [ ] Cross-browser compatibility verified
- [ ] Test report generated

---

**Generated by:** Senior QA Automation Engineer  
**Date:** June 1, 2026  
**Version:** 1.0  
**Status:** Ready for Implementation
