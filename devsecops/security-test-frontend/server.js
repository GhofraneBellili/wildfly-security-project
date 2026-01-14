const express = require('express');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const PORT = 3001;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Configuration
const IAM_BASE_URL = process.env.IAM_BASE_URL || 'http://localhost:8080';

// PKCE utility functions
function generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
    return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// API Routes for testing backend
app.post('/api/test/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const response = await axios.post(`${IAM_BASE_URL}/api/login`, {
            username,
            password
        }, {
            validateStatus: () => true // Accept any status code
        });

        res.json({
            success: response.status === 200,
            status: response.status,
            data: response.data,
            message: response.status === 200 ? 'Login successful' : 'Login failed'
        });
    } catch (error) {
        res.json({
            success: false,
            status: 500,
            message: error.message
        });
    }
});

app.post('/api/test/auth/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        const response = await axios.post(`${IAM_BASE_URL}/api/register`, {
            username,
            email,
            password,
            role
        }, {
            validateStatus: () => true
        });

        res.json({
            success: response.status === 200 || response.status === 201,
            status: response.status,
            data: response.data,
            message: response.status === 201 ? 'Registration successful' : 'Registration failed'
        });
    } catch (error) {
        res.json({
            success: false,
            status: 500,
            message: error.message
        });
    }
});

app.post('/api/test/auth/oauth-authorize', async (req, res) => {
    try {
        const { clientId, redirectUri, scope } = req.body;
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = generateCodeChallenge(codeVerifier);

        const response = await axios.get(`${IAM_BASE_URL}/authorize`, {
            params: {
                client_id: clientId,
                redirect_uri: redirectUri,
                response_type: 'code',
                scope: scope,
                code_challenge: codeChallenge,
                code_challenge_method: 'S256',
                grant_type: 'authorization_code'
            },
            validateStatus: () => true
        });

        res.json({
            success: response.status === 200,
            status: response.status,
            codeVerifier: codeVerifier,
            codeChallenge: codeChallenge,
            message: response.status === 200 ? 'Authorization page loaded' : 'Authorization failed'
        });
    } catch (error) {
        res.json({
            success: false,
            status: 500,
            message: error.message
        });
    }
});

app.post('/api/test/token/exchange', async (req, res) => {
    try {
        const { code, codeVerifier, clientId } = req.body;
        const response = await axios.post(`${IAM_BASE_URL}/oauth/token`,
            new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                code_verifier: codeVerifier,
                client_id: clientId
            }), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            validateStatus: () => true
        });

        res.json({
            success: response.status === 200,
            status: response.status,
            data: response.data,
            message: response.status === 200 ? 'Token obtained' : 'Token exchange failed'
        });
    } catch (error) {
        res.json({
            success: false,
            status: 500,
            message: error.message
        });
    }
});

app.get('/api/test/jwk', async (req, res) => {
    try {
        const { kid } = req.query;
        const response = await axios.get(`${IAM_BASE_URL}/jwk`, {
            params: { kid },
            validateStatus: () => true
        });

        res.json({
            success: response.status === 200,
            status: response.status,
            data: response.data,
            message: response.status === 200 ? 'JWK retrieved' : 'JWK retrieval failed'
        });
    } catch (error) {
        res.json({
            success: false,
            status: 500,
            message: error.message
        });
    }
});

app.post('/api/test/mfa/setup', async (req, res) => {
    try {
        const response = await axios.get(`${IAM_BASE_URL}/api/mfa/setup`, {
            validateStatus: () => true
        });

        res.json({
            success: response.status === 200,
            status: response.status,
            data: response.data,
            message: response.status === 200 ? 'MFA setup initiated' : 'MFA setup failed'
        });
    } catch (error) {
        res.json({
            success: false,
            status: 500,
            message: error.message
        });
    }
});

app.post('/api/test/mfa/verify', async (req, res) => {
    try {
        const { username, code } = req.body;
        const response = await axios.post(`${IAM_BASE_URL}/api/mfa/verify`, {
            username,
            code
        }, {
            validateStatus: () => true
        });

        res.json({
            success: response.status === 200,
            status: response.status,
            data: response.data,
            message: response.status === 200 ? 'MFA verified' : 'MFA verification failed'
        });
    } catch (error) {
        res.json({
            success: false,
            status: 500,
            message: error.message
        });
    }
});

app.post('/api/test/jit/request', async (req, res) => {
    try {
        const { token, requesterId, privilegeType, resourceId, justification } = req.body;
        const response = await axios.post(`${IAM_BASE_URL}/jit/request`, {
            requesterId,
            privilegeType,
            resourceId,
            justification
        }, {
            headers: {
                'Authorization': `Bearer ${token}`
            },
            validateStatus: () => true
        });

        res.json({
            success: response.status === 200 || response.status === 201,
            status: response.status,
            data: response.data,
            message: response.status === 200 ? 'JIT request created' : 'JIT request failed'
        });
    } catch (error) {
        res.json({
            success: false,
            status: 500,
            message: error.message
        });
    }
});

app.get('/api/test/jit/requests', async (req, res) => {
    try {
        const { token } = req.query;
        const response = await axios.get(`${IAM_BASE_URL}/jit/requests`, {
            headers: {
                'Authorization': `Bearer ${token}`
            },
            validateStatus: () => true
        });

        res.json({
            success: response.status === 200,
            status: response.status,
            data: response.data,
            message: response.status === 200 ? 'JIT requests retrieved' : 'Failed to get requests'
        });
    } catch (error) {
        res.json({
            success: false,
            status: 500,
            message: error.message
        });
    }
});

// Generate PKCE codes endpoint
app.get('/api/pkce/generate', (req, res) => {
    const verifier = generateCodeVerifier();
    const challenge = generateCodeChallenge(verifier);
    res.json({ verifier, challenge });
});

// Serve HTML pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`╔════════════════════════════════════════════════════════════╗`);
    console.log(`║  IAM Security Testing Frontend                             ║`);
    console.log(`╠════════════════════════════════════════════════════════════╣`);
    console.log(`║  Server running on: http://localhost:${PORT}              ║`);
    console.log(`║  IAM Backend URL:   ${IAM_BASE_URL.padEnd(36)}║`);
    console.log(`╚════════════════════════════════════════════════════════════╝`);
});
