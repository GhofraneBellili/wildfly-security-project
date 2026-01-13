# Phoenix IAM - Quick Start Guide

This guide will help you run the Phoenix IAM system and integrate it with the frontend App.

---

## Prerequisites Check

Before starting, ensure you have:

- ✅ Java 17+ installed
- ✅ Maven 3.8+ installed
- ✅ Node.js 18+ installed (for frontend)
- ⚠️ **WildFly 27+** (needs to be installed)

---

## Step 1: Install WildFly

### Download WildFly

```bash
# Download WildFly 27
cd ~
wget https://github.com/wildfly/wildfly/releases/download/27.0.1.Final/wildfly-27.0.1.Final.zip

# Or on Windows, download from:
# https://github.com/wildfly/wildfly/releases/download/27.0.1.Final/wildfly-27.0.1.Final.zip
```

### Extract WildFly

```bash
# Linux/Mac
unzip wildfly-27.0.1.Final.zip
export WILDFLY_HOME=~/wildfly-27.0.1.Final

# Windows (PowerShell)
Expand-Archive wildfly-27.0.1.Final.zip
$env:WILDFLY_HOME="C:\wildfly-27.0.1.Final"
```

---

## Step 2: Configure Database

### Option A: Use H2 (Development - No setup needed)

WildFly comes with H2 database pre-configured. Update `persistence.xml`:

```xml
<property name="jakarta.persistence.jdbc.url"
          value="jdbc:h2:mem:phoenix_iam;DB_CLOSE_DELAY=-1"/>
<property name="jakarta.persistence.schema-generation.database.action"
          value="create"/>
```

### Option B: Use PostgreSQL (Production)

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Create database
sudo -u postgres psql
CREATE DATABASE phoenix_iam;
CREATE USER phoenix_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE phoenix_iam TO phoenix_user;
\q
```

---

## Step 3: Set Environment Variables

```bash
# Linux/Mac
export AUTHORIZATION_CODE_KEY=$(openssl rand -base64 32)
export MQTT_USERNAME="mqtt_user"
export MQTT_PASSWORD="mqtt_pass"
export DB_PASSWORD="secure_password"

# Windows (PowerShell)
$env:AUTHORIZATION_CODE_KEY=$(openssl rand -base64 32)
$env:MQTT_USERNAME="mqtt_user"
$env:MQTT_PASSWORD="mqtt_pass"
$env:DB_PASSWORD="secure_password"
```

---

## Step 4: Start WildFly

```bash
# Linux/Mac
cd $WILDFLY_HOME
./bin/standalone.sh

# Windows
cd %WILDFLY_HOME%
bin\standalone.bat
```

**Expected Output:**
```
...
14:30:00,000 INFO  [org.jboss.as] (Controller Boot Thread) WFLYSRV0025: WildFly 27.0.1.Final started in 8234ms
```

---

## Step 5: Deploy IAM Application

### Terminal 2 (while WildFly is running):

```bash
cd /path/to/phoenix-iam/src

# Deploy the WAR file
mvn wildfly:deploy

# Or manual deployment:
cp target/iam-1.0.war $WILDFLY_HOME/standalone/deployments/
```

**Expected Output:**
```
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
```

**Verify Deployment:**
```bash
# Check WildFly logs
tail -f $WILDFLY_HOME/standalone/log/server.log

# Look for:
# "WFLYSRV0010: Deployed "iam-1.0.war""
```

---

## Step 6: Test IAM Endpoints

### Test JWK Endpoint

```bash
curl http://localhost:8080/iam-1.0/jwk
```

**Expected Response:**
```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "...",
      "kid": "..."
    }
  ]
}
```

### Test Authorization Endpoint

```bash
# Open in browser:
http://localhost:8080/iam-1.0/authorize?client_id=test-client&redirect_uri=http://localhost:5173/callback&response_type=code&scope=read&code_challenge=CHALLENGE&code_challenge_method=S256
```

**Expected:** Login page appears

---

## Step 7: Set Up Database (First Time)

You need to manually create initial data:

### Create Test Tenant (Client)

```sql
-- Connect to database
psql -U phoenix_user -d phoenix_iam

-- Create tenant for the App
INSERT INTO tenant (
    id,
    name,
    redirect_uri,
    supported_grant_types,
    allowed_scopes
) VALUES (
    'app-client-001',
    'Phoenix Marketplace App',
    'http://localhost:5173/auth/callback',
    'authorization_code,refresh_token',
    'read write profile'
);
```

### Create Test User

```sql
-- Create identity (password will be hashed on first login)
INSERT INTO identity (
    id,
    username,
    password,  -- This should be Argon2 hashed
    email
) VALUES (
    gen_random_uuid(),
    'testuser@example.com',
    '$argon2id$v=19$m=97579,t=23,p=2$...',  -- Use Argon2 hash
    'testuser@example.com'
);
```

---

## Step 8: Run the Frontend App

### Terminal 3:

```bash
cd /path/to/phoenix-iam/App

# Install dependencies (first time only)
npm install

# Start development server
npm run dev
```

**Expected Output:**
```
  VITE v5.4.2  ready in 500 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
```

---

## Step 9: Configure App to Use Phoenix IAM

### Update App Configuration

Create `App/.env.local`:

```env
# Phoenix IAM Configuration
VITE_IAM_URL=http://localhost:8080/iam-1.0
VITE_CLIENT_ID=app-client-001
VITE_REDIRECT_URI=http://localhost:5173/auth/callback
VITE_SCOPES=read write profile
```

### Create OAuth2 Client for React

Create `App/src/lib/oauth2Client.ts`:

```typescript
// OAuth2 PKCE Client for Phoenix IAM

const IAM_URL = import.meta.env.VITE_IAM_URL || 'http://localhost:8080/iam-1.0';
const CLIENT_ID = import.meta.env.VITE_CLIENT_ID || 'app-client-001';
const REDIRECT_URI = import.meta.env.VITE_REDIRECT_URI || 'http://localhost:5173/auth/callback';
const SCOPES = import.meta.env.VITE_SCOPES || 'read write profile';

// Generate PKCE code verifier
function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

// Generate PKCE code challenge
async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(hash));
}

// Base64 URL encoding
function base64URLEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Start OAuth2 authorization flow
export async function startOAuth2Login() {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  // Store code verifier for later use
  sessionStorage.setItem('code_verifier', codeVerifier);

  // Build authorization URL
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPES,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state: generateState()
  });

  // Redirect to IAM authorization endpoint
  window.location.href = `${IAM_URL}/authorize?${params}`;
}

// Handle OAuth2 callback
export async function handleOAuth2Callback(code: string) {
  const codeVerifier = sessionStorage.getItem('code_verifier');
  if (!codeVerifier) {
    throw new Error('Missing code verifier');
  }

  // Exchange authorization code for tokens
  const response = await fetch(`${IAM_URL}/oauth/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: codeVerifier
    })
  });

  if (!response.ok) {
    throw new Error('Token exchange failed');
  }

  const tokens = await response.json();

  // Store tokens
  localStorage.setItem('access_token', tokens.access_token);
  localStorage.setItem('refresh_token', tokens.refresh_token);

  // Clear code verifier
  sessionStorage.removeItem('code_verifier');

  return tokens;
}

// Generate random state for CSRF protection
function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

// Get current access token
export function getAccessToken(): string | null {
  return localStorage.getItem('access_token');
}

// Refresh access token
export async function refreshAccessToken(): Promise<string> {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  const response = await fetch(`${IAM_URL}/oauth/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: CLIENT_ID
    })
  });

  if (!response.ok) {
    throw new Error('Token refresh failed');
  }

  const tokens = await response.json();
  localStorage.setItem('access_token', tokens.access_token);

  return tokens.access_token;
}

// Logout
export function logout() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  sessionStorage.removeItem('code_verifier');
}
```

---

## Step 10: Access the Application

1. **Open Browser:** http://localhost:5173
2. **Click Login**
3. **Redirected to:** http://localhost:8080/iam-1.0/authorize
4. **Enter Credentials**
5. **Grant Permission**
6. **Redirected Back:** http://localhost:5173/auth/callback?code=...
7. **App exchanges code for tokens**
8. **You're logged in!**

---

## Testing the Integration

### Test OAuth2 Flow Manually

```bash
# 1. Generate PKCE verifier
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '+/=' | cut -c1-43)
echo "Code Verifier: $CODE_VERIFIER"

# 2. Generate challenge
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -binary -sha256 | base64 | tr -d '+/=' | tr -d '\n')
echo "Code Challenge: $CODE_CHALLENGE"

# 3. Open in browser:
http://localhost:8080/iam-1.0/authorize?client_id=app-client-001&redirect_uri=http://localhost:5173/auth/callback&response_type=code&scope=read&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256

# 4. After login, you'll get redirected with a code
# http://localhost:5173/auth/callback?code=urn:phoenix:code:...

# 5. Exchange code for token
curl -X POST http://localhost:8080/iam-1.0/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_CODE_HERE" \
  -d "redirect_uri=http://localhost:5173/auth/callback" \
  -d "client_id=app-client-001" \
  -d "code_verifier=$CODE_VERIFIER"

# 6. You'll receive:
{
  "token_type": "Bearer",
  "access_token": "eyJhbGc...",
  "expires_in": 1020,
  "refresh_token": "eyJhbGc...",
  "scope": "read"
}
```

---

## Troubleshooting

### WildFly Won't Start

```bash
# Check if port 8080 is in use
netstat -ano | findstr :8080  # Windows
lsof -i :8080                  # Linux/Mac

# Kill process using port
# Windows: taskkill /PID <PID> /F
# Linux/Mac: kill -9 <PID>
```

### Deployment Failed

```bash
# Check WildFly logs
tail -f $WILDFLY_HOME/standalone/log/server.log

# Undeploy and redeploy
mvn wildfly:undeploy
mvn clean package wildfly:deploy
```

### Database Connection Failed

```bash
# Test PostgreSQL connection
psql -U phoenix_user -d phoenix_iam -h localhost

# Check connection in persistence.xml
```

### Frontend Can't Connect

```bash
# Check CORS settings in JAX-RS Application
# Add CORS filter if needed

# Check browser console for errors
# Open DevTools > Console
```

---

## Next Steps

1. ✅ WildFly running
2. ✅ IAM deployed
3. ✅ Database configured
4. ✅ Test data inserted
5. ✅ Frontend running
6. ✅ OAuth2 flow tested

**You're all set!** 🎉

---

## Useful Commands

```bash
# Check WildFly status
curl http://localhost:8080

# Check IAM endpoints
curl http://localhost:8080/iam-1.0/jwk

# View WildFly logs
tail -f $WILDFLY_HOME/standalone/log/server.log

# Restart WildFly
# CTRL+C then ./bin/standalone.sh

# Rebuild and redeploy
mvn clean package wildfly:deploy

# Frontend dev server
cd App && npm run dev
```

---

**Last Updated:** January 13, 2026
**Status:** Ready to Run 🚀
