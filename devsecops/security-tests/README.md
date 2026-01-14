# Phoenix IAM Security Testing Suite

Comprehensive security testing application for the Phoenix IAM backend system. This test suite covers all major security functions and endpoints in the IAM system.

## Overview

This security testing suite provides automated tests for:

- **Authentication Endpoints** - OAuth 2.0 authorization flow, login, registration
- **Authorization & JWT** - Token validation, role-based access control, scope validation
- **MFA & PKCE** - Multi-factor authentication, PKCE code challenge validation
- **Brute Force Protection** - Failed login tracking, IP blocking, rate limiting
- **Input Sanitization** - XSS prevention, SQL injection prevention, input validation
- **JIT Access** - Just-in-time privilege escalation endpoints

## Test Coverage

### Authentication Tests (17 tests)
- OAuth authorize endpoint validation
- PKCE code challenge requirements
- Login with valid/invalid credentials
- SQL injection prevention
- XSS payload sanitization
- User registration validation
- Duplicate username/email detection

### Authorization & JWT Tests (16 tests)
- Token endpoint with authorization code
- Refresh token flow
- JWT structure validation
- JWK endpoint functionality
- Protected endpoint access control
- Expired/invalid token rejection
- Role-based access control
- Scope-based access control
- Token revocation

### MFA & PKCE Tests (13 tests)
- MFA setup and secret generation
- TOTP code validation
- Invalid/expired code rejection
- Code replay prevention
- PKCE code verifier generation
- Code challenge validation
- Authorization code reuse prevention

### Brute Force Protection Tests (6 tests)
- Multiple failed login attempt tracking
- IP-based blocking
- Lockout duration enforcement
- Successful login counter reset
- Independent IP tracking
- Rate limiting on endpoints

### Input Sanitization Tests (12 tests)
- XSS in query parameters
- XSS in request headers
- Script tag sanitization
- IFrame tag sanitization
- JavaScript protocol sanitization
- Event handler sanitization
- HTML entity encoding
- SQL injection prevention
- Path traversal prevention
- Command injection prevention
- XML injection prevention
- LDAP injection prevention

### JIT Access Tests (13 tests)
- JIT request creation
- Authentication requirement
- Invalid data rejection
- Admin-only endpoints
- Request approval workflow
- Request revocation
- Access expiration handling

## Prerequisites

- Java 17 or higher
- Maven 3.6+
- Running Phoenix IAM backend instance
- Valid test user accounts configured in the backend

## Configuration

Edit `security-test.properties` to configure your test environment:

```properties
# Backend IAM Base URL
iam.base.url=http://localhost:8080

# Test OAuth Client Credentials
test.client.id=test-client
test.client.secret=test-secret
test.redirect.uri=http://localhost:3000/callback

# Test User Credentials
test.username=testuser
test.password=Test@123456
test.email=testuser@example.com

# Test Admin Credentials
test.admin.username=admin
test.admin.password=Admin@123456

# OAuth Scopes
test.scope=openid profile email

# Brute Force Protection Test Configuration
brute.force.test.attempts=6
```

## Building the Project

```bash
cd security-tests
mvn clean compile
```

## Running Tests

### Run all tests:
```bash
mvn exec:java
```

### Run with Maven:
```bash
mvn clean test
```

### Run as JAR:
```bash
mvn clean package
java -jar target/iam-security-tests-1.0-SNAPSHOT.jar
```

## Test Reports

After running the tests, a detailed report will be generated:
- **Console Output** - Real-time test execution status
- **Report File** - `security-test-report-YYYYMMDD-HHmmss.txt`

The report includes:
- Test execution summary
- Pass/fail status for each test
- Detailed information about failures
- HTTP status codes and responses
- Categorized test results

## Understanding Test Results

### Test Status Codes

- **[PASS]** - Test completed successfully, security measure is working
- **[FAIL]** - Test failed, potential security vulnerability detected

### Common Status Codes

- **200 OK** - Request succeeded
- **201 Created** - Resource created successfully
- **400 Bad Request** - Invalid request format or parameters
- **401 Unauthorized** - Authentication required or failed
- **403 Forbidden** - Authenticated but not authorized
- **404 Not Found** - Resource does not exist
- **409 Conflict** - Resource already exists (duplicate)
- **429 Too Many Requests** - Rate limit exceeded

## Test Categories Explained

### 1. Authentication Endpoint Tests
Tests the security of login, registration, and OAuth authorization flows. Validates that:
- Invalid credentials are rejected
- SQL injection attempts are blocked
- XSS payloads are sanitized
- PKCE is properly enforced
- Registration validation works correctly

### 2. Authorization & JWT Tests
Tests token-based authentication and authorization. Validates that:
- Tokens are properly validated
- Expired tokens are rejected
- Invalid tokens are rejected
- Role-based access control is enforced
- Scope-based access control is enforced
- Revoked tokens are blocked

### 3. MFA & PKCE Tests
Tests multi-factor authentication and PKCE implementation. Validates that:
- TOTP codes are properly verified
- Invalid/expired codes are rejected
- Code replay attacks are prevented
- PKCE code challenges are validated
- Authorization codes cannot be reused

### 4. Brute Force Protection Tests
Tests protection against brute force attacks. Validates that:
- Failed login attempts are tracked
- Accounts/IPs are locked after threshold
- Successful logins reset counters
- Different IPs are tracked independently
- Rate limiting is applied

### 5. Input Sanitization Tests
Tests protection against injection attacks. Validates that:
- XSS payloads are sanitized
- SQL injection is prevented
- Path traversal is blocked
- Command injection is prevented
- HTML entities are properly encoded

### 6. JIT Access Tests
Tests just-in-time privilege escalation. Validates that:
- JIT requests require authentication
- Admin approval is required
- Role-based access is enforced
- Access expiration is handled
- Invalid requests are rejected

## Security Functions Tested

### Core Security Functions Covered:

1. **Password Hashing** (Argon2id)
   - Secure password storage
   - Password verification

2. **JWT Management** (EdDSA/Ed25519)
   - Token generation
   - Token validation
   - Token revocation

3. **MFA** (TOTP)
   - Secret generation
   - Code verification
   - QR code generation

4. **PKCE** (S256)
   - Code challenge generation
   - Code verifier validation

5. **Authorization Code** (ChaCha20-Poly1305)
   - Encrypted code generation
   - Code decryption and validation

6. **Brute Force Protection**
   - Failed attempt tracking
   - IP-based blocking
   - Lockout enforcement

7. **Input Sanitization**
   - XSS prevention
   - SQL injection prevention
   - Path traversal prevention

8. **Session Management**
   - Session creation
   - Session validation
   - Session expiration

## Troubleshooting

### Connection Refused
```
Exception: Connection refused
```
**Solution:** Ensure the IAM backend is running at the configured base URL.

### Authentication Failures
```
Status: 401 Unauthorized
```
**Solution:** Verify test credentials in `security-test.properties` match users in the backend database.

### All Tests Failing
**Solution:**
1. Check backend is running
2. Verify base URL is correct
3. Ensure test users exist in database
4. Check OAuth client configuration

### Brute Force Tests Failing
**Solution:** Some brute force tests may fail if:
1. Previous test runs triggered lockouts
2. IP is already blocked
3. Wait for lockout duration to expire or restart backend

## Best Practices

1. **Run in Isolated Environment** - Use a dedicated test environment, not production
2. **Fresh Test Data** - Reset test database between full test runs
3. **Monitor Backend Logs** - Check backend logs for detailed error information
4. **Sequential Execution** - Run tests sequentially, not in parallel
5. **Clean State** - Clear rate limit caches and lockouts between runs

## Extending the Tests

To add new tests:

1. Create a new test class in `src/main/java/xyz/kaaniche/phoenix/security/tests/`
2. Follow the pattern of existing test classes
3. Add test results to the reporter
4. Register the test suite in `IAMSecurityTestRunner.java`

Example:
```java
public class NewSecurityTests {
    private final TestReportGenerator reporter;
    private static final String CATEGORY = "NEW TESTS";

    public NewSecurityTests(TestReportGenerator reporter) {
        this.reporter = reporter;
    }

    public void runAllTests() {
        testNewFeature();
    }

    private void testNewFeature() {
        // Test implementation
        reporter.addResult(CATEGORY, "Test name", passed, "Details");
    }
}
```

## Dependencies

- **REST Assured** - API testing framework
- **JUnit 5** - Testing framework
- **Auth0 JWT** - JWT decoding
- **TOTP Library** - MFA code generation
- **Apache HttpClient** - HTTP operations

## Security Considerations

- **Test Credentials** - Never use production credentials in tests
- **Test Data** - Use isolated test data that can be safely modified
- **Rate Limits** - Tests may trigger rate limits; adjust timing if needed
- **Brute Force** - Some tests intentionally trigger security measures

## License

This test suite is part of the Phoenix IAM project.

## Support

For issues or questions:
1. Check backend logs for detailed error messages
2. Review test configuration in `security-test.properties`
3. Verify backend is running and accessible
4. Check that test users exist in the database

## Continuous Integration

To integrate with CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Security Tests
  run: |
    cd security-tests
    mvn clean test

- name: Upload Test Report
  uses: actions/upload-artifact@v2
  with:
    name: security-test-report
    path: security-tests/security-test-report-*.txt
```

## Metrics

Total Tests: **77 comprehensive security tests**

Coverage:
- Authentication & OAuth: 17 tests
- JWT & Authorization: 16 tests
- MFA & PKCE: 13 tests
- Brute Force Protection: 6 tests
- Input Sanitization: 12 tests
- JIT Access Control: 13 tests

## Version History

- **v1.0** - Initial release with comprehensive security test coverage
  - All major IAM endpoints covered
  - All security functions tested
  - Detailed reporting functionality
