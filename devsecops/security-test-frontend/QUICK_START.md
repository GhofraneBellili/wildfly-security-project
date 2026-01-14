# Quick Start - Security Testing Frontend

## 3-Minute Setup

### Step 1: Install
```bash
cd security-test-frontend
npm install
```

### Step 2: Start
```bash
npm start
```

### Step 3: Open Browser
Go to: **http://localhost:3000**

### Step 4: Configure
Scroll down to "Test Configuration" and enter:
- Your test username/password
- OAuth client credentials

### 5. Run Tests
Click **"▶ Run All Tests"** or run individual tests by category

---

## Quick Reference

### Start Server
```bash
npm start
```

### Access Dashboard
```
http://localhost:3000
```

### Set Backend URL
```bash
# Windows
set IAM_BASE_URL=http://localhost:8080

# Linux/Mac
export IAM_BASE_URL=http://localhost:8080
```

## Test Categories

1. **Authentication Tests (9 tests)**
   - Login validation
   - Registration security
   - OAuth/PKCE flows

2. **Authorization & JWT (7 tests)**
   - Token validation
   - Access control
   - JWK endpoint

3. **MFA & Security (5 tests)**
   - MFA setup/verification
   - Brute force protection
   - Rate limiting

4. **Input Sanitization (5 tests)**
   - XSS prevention
   - SQL injection
   - Command injection
   - Path traversal
   - LDAP injection

5. **JIT Access Tests (3 tests)**
   - Request creation
   - Authentication checks
   - Admin endpoints

## Quick Start

```bash
# Install
npm install

# Start
npm start

# Open browser
http://localhost:3000
```

## Test Configuration

Update test parameters in the UI:
- Username: `testuser`
- Password: `Test@123456`
- Client ID: `test-client`
- Redirect URI: `http://localhost:3000/callback`
- Scope: `openid profile email`

## Features

✓ Interactive web dashboard
✓ Real-time test execution
✓ Color-coded results
✓ Export test reports
✓ PKCE code generation
✓ Comprehensive security testing
✓ Beautiful UI with animations
✓ Mobile responsive design

## Quick Commands

```bash
# Install
npm install

# Start server
npm start

# Development mode (auto-restart)
npm run dev

# Open browser
# Navigate to http://localhost:3000
```

Enjoy secure testing!
