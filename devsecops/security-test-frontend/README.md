# Phoenix IAM Security Testing Frontend

A beautiful, interactive web application for testing the security of the Phoenix IAM backend. This frontend provides a user-friendly interface to execute comprehensive security tests against all IAM endpoints and functions.

![Security Testing Dashboard](https://img.shields.io/badge/Security-Testing-blue)
![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)
![Express](https://img.shields.io/badge/Express-4.18-lightgrey)

## Features

### Comprehensive Test Coverage
- **Authentication Tests** - Login, registration, OAuth, PKCE validation
- **Authorization & JWT Tests** - Token validation, access control, JWK endpoint
- **MFA & Security Tests** - Multi-factor authentication, brute force protection
- **Input Sanitization Tests** - XSS, SQL injection, command injection, path traversal
- **JIT Access Tests** - Just-in-time privilege escalation

### Beautiful User Interface
- Modern, responsive dashboard design
- Real-time test execution and results
- Color-coded pass/fail indicators
- Detailed test reports with timestamps
- Collapsible test categories
- Export test results

### Real-Time Statistics
- Total tests executed
- Pass/fail counts
- Pass rate percentage
- Individual test details

## Screenshots

### Dashboard Overview
```
┌─────────────────────────────────────────────────────────────┐
│  Phoenix IAM Security Testing Dashboard                    │
│  Comprehensive security testing interface for IAM backend  │
├─────────────────────────────────────────────────────────────┤
│  Total Tests: 25  │ Passed: 23  │ Failed: 2  │ Rate: 92%  │
├─────────────────────────────────────────────────────────────┤
│  ▶ Run All Tests   🗑 Clear Results   📥 Export Report    │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Node.js 18+ and npm
- Phoenix IAM backend running (default: `http://localhost:8080`)
- Modern web browser

## Quick Start

### 1. Install Dependencies
```bash
cd security-test-frontend
npm install
```

### 2. Configure Backend URL (Optional)
Set the IAM backend URL as an environment variable:
```bash
# Windows
set IAM_BASE_URL=http://localhost:8080

# Linux/Mac
export IAM_BASE_URL=http://localhost:8080
```

Or it will default to `http://localhost:8080`

### 3. Start the Frontend Server
```bash
npm start
```

### 4. Open in Browser
Navigate to: **http://localhost:3000**

## Usage

### Running Individual Tests

1. **Open a Test Category** - Click on any category header (Authentication, JWT, MFA, etc.)
2. **Click a Test Button** - Each button runs a specific security test
3. **View Results** - Results appear instantly in the "Test Results" section

### Running All Tests

Click the **"▶ Run All Tests"** button to execute the complete test suite automatically.

### Configuring Test Parameters

Scroll to the bottom "Test Configuration" section to set:
- Test username/password
- OAuth client credentials
- Redirect URIs
- Scopes

### Exporting Results

Click **"📥 Export Report"** to download a detailed text report of all test results.

## Test Categories

### 1. Authentication Tests
| Test | Description | Expected Result |
|------|-------------|-----------------|
| Test Valid Login | Login with correct credentials | 200 OK |
| Test Invalid Login | Login with wrong credentials | 401 Unauthorized |
| Test SQL Injection | SQL injection in login | 401/400 |
| Test XSS Attack | XSS payload in login | Sanitized response |
| Test Valid Registration | Register new user | 200/201 |
| Test Duplicate Username | Register existing user | 400/409 |
| Test Invalid Email | Register with bad email | 400 |
| Test OAuth Authorize | OAuth flow with PKCE | 200 OK |
| Test Invalid PKCE | Invalid client ID | 400/401 |

### 2. Authorization & JWT Tests
| Test | Description | Expected Result |
|------|-------------|-----------------|
| Test Token Exchange | Exchange auth code for token | 200 OK |
| Test Invalid Token | Use invalid JWT | 401 |
| Test Expired Token | Use expired JWT | 401 |
| Test JWK Endpoint | Get public key | 200/404 |
| Test Without Auth | Access protected endpoint | 401/403 |
| Test Role-Based Access | Admin endpoint as user | 403 |
| Test Scope Validation | Insufficient scopes | 403 |

### 3. MFA & Security Tests
| Test | Description | Expected Result |
|------|-------------|-----------------|
| Test MFA Setup | Generate MFA secret | 200 OK |
| Test MFA Verification | Verify TOTP code | 200/401 |
| Test Invalid MFA Code | Wrong TOTP code | 401 |
| Test Brute Force | Multiple failed logins | 429 |
| Test Rate Limiting | Excessive requests | 429 |

### 4. Input Sanitization Tests
| Test | Description | Expected Result |
|------|-------------|-----------------|
| Test XSS Injection | Multiple XSS payloads | Sanitized |
| Test SQL Injection | Multiple SQL payloads | Blocked |
| Test Command Injection | Shell command payloads | Blocked |
| Test Path Traversal | Directory traversal | Blocked |
| Test LDAP Injection | LDAP injection payloads | Blocked |

### 5. JIT Access Tests
| Test | Description | Expected Result |
|------|-------------|-----------------|
| Test Create JIT Request | Create privilege request | 200/401 |
| Test Without Auth | JIT without token | 401/403 |
| Test Get Requests | Get pending requests (admin) | 200/403 |

## API Endpoints

The frontend server provides proxy endpoints to test the IAM backend:

### Authentication
- `POST /api/test/auth/login` - Test login
- `POST /api/test/auth/register` - Test registration
- `POST /api/test/auth/oauth-authorize` - Test OAuth flow

### Tokens & JWT
- `POST /api/test/token/exchange` - Exchange authorization code
- `GET /api/test/jwk` - Get public key

### MFA
- `POST /api/test/mfa/setup` - Setup MFA
- `POST /api/test/mfa/verify` - Verify MFA code

### JIT Access
- `POST /api/test/jit/request` - Create JIT request
- `GET /api/test/jit/requests` - Get pending requests

### Utilities
- `GET /api/pkce/generate` - Generate PKCE codes

## Understanding Test Results

### PASS (Green)
- Test executed successfully
- Security measure working correctly
- Expected behavior confirmed

### FAIL (Red)
- Test failed
- Potential security vulnerability
- Unexpected behavior detected

### Status Codes
- **200** - Success
- **201** - Created
- **400** - Bad Request (expected for invalid input)
- **401** - Unauthorized (expected for auth failures)
- **403** - Forbidden (expected for insufficient permissions)
- **404** - Not Found
- **409** - Conflict (expected for duplicates)
- **429** - Too Many Requests (rate limiting)
- **500** - Server Error

## Security Testing Best Practices

### DO:
- Run tests in a dedicated test environment
- Use test credentials only
- Review all test results
- Export and save reports
- Run tests regularly
- Test before deployments

### DON'T:
- Run tests against production
- Use production credentials
- Ignore failed tests
- Run excessive brute force tests
- Test without permission

## Troubleshooting

### Frontend Won't Start
```bash
# Check Node.js version
node --version  # Should be 18+

# Reinstall dependencies
rm -rf node_modules
npm install
```

### Can't Connect to Backend
```bash
# Check backend is running
curl http://localhost:8080/jwk

# Set correct backend URL
export IAM_BASE_URL=http://your-backend:8080
npm start
```

### Tests All Failing
- Verify backend is running
- Check backend URL in configuration
- Ensure test users exist in database
- Check browser console for errors

### CORS Errors
The frontend server acts as a proxy to avoid CORS issues. All requests go through the frontend server to the backend.

## Development

### Project Structure
```
security-test-frontend/
├── server.js              # Express server & API proxy
├── package.json           # Dependencies
├── public/
│   ├── index.html        # Main dashboard
│   ├── styles.css        # Styling
│   └── app.js            # Frontend logic & tests
└── README.md             # This file
```

### Adding New Tests

1. **Add Test Button** in `index.html`:
```html
<button onclick="testNewFeature()" class="btn">Test New Feature</button>
```

2. **Add Test Function** in `app.js`:
```javascript
async function testNewFeature() {
    try {
        const response = await fetch('/api/test/new-feature', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ /* test data */ })
        });

        const data = await response.json();
        addTestResult('New Feature Test', data.success, data.message, data.status);
    } catch (error) {
        addTestResult('New Feature Test', false, error.message, 500);
    }
}
```

3. **Add API Route** in `server.js` (if needed):
```javascript
app.post('/api/test/new-feature', async (req, res) => {
    try {
        const response = await axios.post(`${IAM_BASE_URL}/new-endpoint`, req.body, {
            validateStatus: () => true
        });
        res.json({
            success: response.status === 200,
            status: response.status,
            data: response.data
        });
    } catch (error) {
        res.json({ success: false, status: 500, message: error.message });
    }
});
```

### Running in Development Mode

```bash
npm install nodemon --save-dev
npm run dev
```

This will auto-restart the server on file changes.

## Production Deployment

### Using PM2
```bash
npm install pm2 -g
pm2 start server.js --name iam-security-test
pm2 save
pm2 startup
```

### Using Docker
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

Build and run:
```bash
docker build -t iam-security-test .
docker run -p 3000:3000 -e IAM_BASE_URL=http://backend:8080 iam-security-test
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Security Tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Node
        uses: actions/setup-node@v2
        with:
          node-version: '18'
      - name: Install dependencies
        run: cd security-test-frontend && npm install
      - name: Start frontend
        run: cd security-test-frontend && npm start &
      - name: Run tests via API
        run: curl -X POST http://localhost:3000/api/test/all
```

## Performance

- **Test Execution Time**: ~30-60 seconds for all tests
- **Memory Usage**: < 100MB
- **Concurrent Users**: Supports multiple simultaneous test sessions
- **Browser Compatibility**: Chrome, Firefox, Safari, Edge (modern versions)

## Security Considerations

- Frontend server acts as a proxy to avoid exposing IAM backend directly
- No sensitive data stored in frontend
- All tests are read-only or use test data
- HTTPS recommended for production use

## Contributing

To contribute new tests or features:
1. Follow the existing code structure
2. Add tests to appropriate category
3. Update documentation
4. Test thoroughly before submitting

## License

MIT License - See LICENSE file

## Support

For issues or questions:
- Check browser console for errors
- Verify backend connectivity
- Review test configuration
- Check server.js logs

## Changelog

### Version 1.0.0
- Initial release
- All major IAM security tests
- Interactive dashboard
- Real-time results
- Export functionality
- PKCE support
- MFA testing
- Injection attack testing
- JIT access testing

---

**Happy Testing!**

Keep your IAM backend secure with comprehensive automated testing.
