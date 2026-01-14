# Quick Start Guide - Phoenix IAM Security Tests

## 5-Minute Setup

### Step 1: Prerequisites Check
```bash
# Check Java (need 17+)
java -version

# Check Maven (need 3.6+)
mvn -version
```

### Step 2: Configure Tests
Edit `security-test.properties`:
```properties
iam.base.url=http://localhost:8080
test.client.id=your-client-id
test.username=your-test-user
test.password=your-test-password
```

### Step 3: Run Tests

**Windows:**
```cmd
run-tests.bat
```

**Linux/Mac:**
```bash
chmod +x run-tests.sh
./run-tests.sh
```

**Or use Maven directly:**
```bash
mvn clean compile exec:java
```

---

## What Gets Tested?

✓ **77 Security Tests** covering:
- Authentication (login, OAuth, registration)
- Authorization (JWT, roles, scopes)
- MFA & PKCE (2FA, code challenges)
- Brute force protection (rate limiting, IP blocking)
- Input sanitization (XSS, SQL injection, etc.)
- JIT access control (privilege escalation)

---

## Understanding Results

### Console Output
```
=== Running Authentication Tests ===
[PASS] OAuth authorize endpoint with valid parameters
[FAIL] Login with invalid credentials (should reject)
```

### Report File
Generated as: `security-test-report-YYYYMMDD-HHmmss.txt`

Contains:
- Summary statistics
- Detailed test results
- Pass/fail reasons
- HTTP status codes

---

## Common Issues & Quick Fixes

### Issue: Connection Refused
```
Exception: Connection refused
```
**Fix:** Start the IAM backend first
```bash
cd ../
# Start your backend (adjust command as needed)
java -jar iam-backend.jar
```

### Issue: All Tests Fail with 401
```
Status: 401 Unauthorized
```
**Fix:** Update credentials in `security-test.properties`
```properties
test.username=valid-user
test.password=correct-password
```

### Issue: Tests Pass But Should Fail
```
[PASS] SQL injection attempt
```
**Fix:** This means security IS working (injection was blocked)
- [PASS] = Security measure working correctly
- [FAIL] = Potential vulnerability detected

### Issue: Brute Force Tests Timeout
```
Exception: Read timed out
```
**Fix:** IP might be already blocked. Either:
1. Wait 30 minutes for lockout to expire
2. Restart backend to clear lockouts
3. Adjust `brute.force.test.attempts` in config

---

## Quick Test Categories

### Run Specific Test Category
Modify `IAMSecurityTestRunner.java` to comment out test suites:

```java
// Run only authentication tests
runTestSuite("Authentication Tests", new AuthenticationTests(reporter));
// runTestSuite("Authorization & JWT Tests", new AuthorizationAndJWTTests(reporter));
// ... (comment out others)
```

---

## Reading Test Results

### Good Security (Tests Pass)
```
[PASS] Login with invalid credentials (should reject) - Status: 401
```
✓ System correctly rejected bad credentials

```
[PASS] XSS payload sanitized - XSS found in response: false
```
✓ System removed dangerous scripts

### Potential Issues (Tests Fail)
```
[FAIL] Login with invalid credentials (should reject) - Status: 200
```
✗ System accepted bad credentials (security issue!)

```
[FAIL] XSS payload sanitized - XSS found in response: true
```
✗ System didn't remove dangerous scripts (XSS vulnerability!)

---

## Expected Status Codes

| Code | Meaning | When It's Good |
|------|---------|----------------|
| 200 | Success | Valid operations |
| 201 | Created | Registration succeeded |
| 400 | Bad Request | Invalid input rejected ✓ |
| 401 | Unauthorized | Auth required/failed ✓ |
| 403 | Forbidden | Access denied ✓ |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Duplicate rejected ✓ |
| 429 | Too Many Requests | Rate limited ✓ |

---

## Test Suite Breakdown

1. **Authentication Tests** (17 tests, ~30 seconds)
   - OAuth flow security
   - Login validation
   - Registration checks

2. **Authorization & JWT Tests** (16 tests, ~25 seconds)
   - Token validation
   - Access control
   - Role enforcement

3. **MFA & PKCE Tests** (13 tests, ~20 seconds)
   - Two-factor auth
   - PKCE validation

4. **Brute Force Tests** (6 tests, ~60 seconds)
   - Rate limiting
   - IP blocking
   ⚠️ These tests intentionally slow

5. **Input Sanitization Tests** (12 tests, ~20 seconds)
   - XSS prevention
   - Injection prevention

6. **JIT Access Tests** (13 tests, ~15 seconds)
   - Privilege escalation
   - Admin workflows

**Total Runtime:** ~3-5 minutes

---

## Interpreting the Summary

```
=== TEST SUMMARY ===
Total: 77 | Passed: 75 | Failed: 2 | Pass Rate: 97.4%
```

- **97%+** = Excellent security posture
- **90-97%** = Good, review failures
- **80-90%** = Fair, fix critical issues
- **<80%** = Poor, major security concerns

---

## Next Steps After Testing

### If Tests Pass (Good!)
1. Review the detailed report
2. Save report for compliance documentation
3. Run tests regularly (weekly/monthly)
4. Update tests when adding new features

### If Tests Fail (Needs Attention!)
1. Check backend logs for error details
2. Review failed test details in report
3. Fix identified vulnerabilities
4. Re-run tests to verify fixes
5. Consider security code review

---

## Advanced Usage

### Custom Configuration
```bash
# Use different config file
java -Dconfig.file=custom-test.properties -jar target/iam-security-tests.jar
```

### Integration with CI/CD
```yaml
# .github/workflows/security-tests.yml
- name: Run Security Tests
  run: |
    cd security-tests
    mvn clean compile exec:java

- name: Check Results
  run: |
    if grep -q "Pass Rate: 100" security-tests/security-test-report-*.txt; then
      echo "All security tests passed!"
    else
      echo "Security tests failed!"
      exit 1
    fi
```

### Scheduled Testing
```bash
# Linux cron - run daily at 2 AM
0 2 * * * cd /path/to/security-tests && ./run-tests.sh >> test-$(date +\%Y\%m\%d).log 2>&1
```

---

## Getting Help

### Check These First:
1. ✓ Backend is running?
2. ✓ Credentials correct in properties file?
3. ✓ Network connectivity to backend?
4. ✓ Test users exist in database?

### Still Stuck?
- Review backend logs
- Check `security-test-report-*.txt` for details
- Verify backend version compatibility
- Ensure no firewall blocking

---

## File Structure

```
security-tests/
├── pom.xml                          # Maven configuration
├── security-test.properties         # Configuration file
├── run-tests.bat                    # Windows runner
├── run-tests.sh                     # Linux/Mac runner
├── README.md                        # Full documentation
├── QUICK_START.md                   # This file
├── SECURITY_TEST_MATRIX.md          # Complete test mapping
└── src/main/java/xyz/kaaniche/phoenix/security/
    ├── IAMSecurityTestRunner.java   # Main runner
    ├── config/
    │   └── TestConfig.java          # Configuration loader
    ├── utils/
    │   ├── PKCEUtil.java           # PKCE utilities
    │   └── TestReportGenerator.java # Report generator
    └── tests/
        ├── AuthenticationTests.java
        ├── AuthorizationAndJWTTests.java
        ├── MFAAndPKCETests.java
        ├── BruteForceProtectionTests.java
        ├── InputSanitizationTests.java
        └── JITAccessTests.java
```

---

## Best Practices

✓ **DO:**
- Run tests in isolated test environment
- Use dedicated test accounts
- Review reports after each run
- Keep configuration file secure
- Run tests before deployments

✗ **DON'T:**
- Run against production
- Use production credentials
- Run tests in parallel (sequential only)
- Ignore failed tests
- Commit passwords to git

---

## Success Checklist

- [ ] Java 17+ installed
- [ ] Maven 3.6+ installed
- [ ] Backend running and accessible
- [ ] Configuration file updated
- [ ] Test users exist in backend
- [ ] Tests executed successfully
- [ ] Report generated and reviewed
- [ ] All critical tests passing

---

## Quick Commands Reference

```bash
# Build only
mvn clean compile

# Run tests
mvn exec:java

# Build and run
mvn clean compile exec:java

# Package as JAR
mvn clean package

# Run packaged JAR
java -jar target/iam-security-tests-1.0-SNAPSHOT.jar

# View latest report
cat security-test-report-*.txt | head -50
```

---

**Ready to go!** Run the tests and check your security posture in minutes.

For detailed information, see [README.md](README.md) and [SECURITY_TEST_MATRIX.md](SECURITY_TEST_MATRIX.md).
