/**
 * OAuth2 PKCE Client for Phoenix IAM
 *
 * This client implements the OAuth2 Authorization Code Flow with PKCE
 * for secure authentication with the Phoenix IAM backend.
 */

const IAM_URL = import.meta.env.VITE_IAM_URL || 'http://localhost:8080/iam-1.0';
const CLIENT_ID = import.meta.env.VITE_CLIENT_ID || 'app-client-001';
const REDIRECT_URI = import.meta.env.VITE_REDIRECT_URI || 'http://localhost:5173/auth/callback';
const SCOPES = import.meta.env.VITE_SCOPES || 'read write profile';

export interface TokenResponse {
  token_type: string;
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
}

export interface UserProfile {
  sub: string;
  email?: string;
  tenant_id?: string;
  groups?: string[];
  scope?: string;
}

/**
 * Generate PKCE code verifier (random string)
 */
function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

/**
 * Generate PKCE code challenge (SHA-256 hash of verifier)
 */
async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(new Uint8Array(hash));
}

/**
 * Base64 URL encoding (without padding)
 */
function base64URLEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate random state for CSRF protection
 */
function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  const state = base64URLEncode(array);
  sessionStorage.setItem('oauth_state', state);
  return state;
}

/**
 * Validate state parameter (CSRF protection)
 */
function validateState(state: string): boolean {
  const savedState = sessionStorage.getItem('oauth_state');
  sessionStorage.removeItem('oauth_state');
  return savedState === state;
}

/**
 * Start OAuth2 authorization flow
 * Redirects user to Phoenix IAM login page
 */
export async function startOAuth2Login(): Promise<void> {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateState();

  // Store code verifier for later use in token exchange
  sessionStorage.setItem('code_verifier', codeVerifier);

  // Build authorization URL
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPES,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state
  });

  // Redirect to IAM authorization endpoint
  window.location.href = `${IAM_URL}/authorize?${params}`;
}

/**
 * Handle OAuth2 callback after user authorizes
 * Exchanges authorization code for access token
 */
export async function handleOAuth2Callback(code: string, state: string): Promise<TokenResponse> {
  // Validate state (CSRF protection)
  if (!validateState(state)) {
    throw new Error('Invalid state parameter - possible CSRF attack');
  }

  const codeVerifier = sessionStorage.getItem('code_verifier');
  if (!codeVerifier) {
    throw new Error('Missing code verifier - session may have expired');
  }

  try {
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
      const error = await response.text();
      throw new Error(`Token exchange failed: ${error}`);
    }

    const tokens: TokenResponse = await response.json();

    // Store tokens securely
    localStorage.setItem('access_token', tokens.access_token);
    if (tokens.refresh_token) {
      localStorage.setItem('refresh_token', tokens.refresh_token);
    }
    localStorage.setItem('token_expiry', String(Date.now() + tokens.expires_in * 1000));

    // Clear code verifier
    sessionStorage.removeItem('code_verifier');

    return tokens;
  } catch (error) {
    sessionStorage.removeItem('code_verifier');
    throw error;
  }
}

/**
 * Get current access token
 */
export function getAccessToken(): string | null {
  const token = localStorage.getItem('access_token');
  const expiry = localStorage.getItem('token_expiry');

  // Check if token is expired
  if (expiry && Date.now() >= parseInt(expiry)) {
    // Token expired, clear it
    localStorage.removeItem('access_token');
    return null;
  }

  return token;
}

/**
 * Refresh access token using refresh token
 */
export async function refreshAccessToken(): Promise<string> {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  try {
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
      // Refresh token invalid or expired
      logout();
      throw new Error('Token refresh failed - please login again');
    }

    const tokens: TokenResponse = await response.json();

    // Update stored tokens
    localStorage.setItem('access_token', tokens.access_token);
    if (tokens.refresh_token) {
      localStorage.setItem('refresh_token', tokens.refresh_token);
    }
    localStorage.setItem('token_expiry', String(Date.now() + tokens.expires_in * 1000));

    return tokens.access_token;
  } catch (error) {
    logout();
    throw error;
  }
}

/**
 * Decode JWT token to get user profile
 */
export function decodeToken(token: string): UserProfile | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const payload = parts[1];
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));

    return {
      sub: decoded.sub,
      email: decoded.email,
      tenant_id: decoded.tenant_id,
      groups: decoded.groups,
      scope: decoded.scope
    };
  } catch (error) {
    console.error('Failed to decode token:', error);
    return null;
  }
}

/**
 * Get current user profile from access token
 */
export function getCurrentUser(): UserProfile | null {
  const token = getAccessToken();
  if (!token) {
    return null;
  }
  return decodeToken(token);
}

/**
 * Check if user is authenticated
 */
export function isAuthenticated(): boolean {
  return getAccessToken() !== null;
}

/**
 * Logout user (clear tokens)
 */
export function logout(): void {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('token_expiry');
  sessionStorage.removeItem('code_verifier');
  sessionStorage.removeItem('oauth_state');
}

/**
 * Make authenticated API request
 */
export async function authenticatedFetch(url: string, options: RequestInit = {}): Promise<Response> {
  let token = getAccessToken();

  // Try to refresh token if expired
  if (!token) {
    try {
      token = await refreshAccessToken();
    } catch (error) {
      throw new Error('Authentication required');
    }
  }

  // Add Authorization header
  const headers = new Headers(options.headers);
  headers.set('Authorization', `Bearer ${token}`);

  const response = await fetch(url, {
    ...options,
    headers
  });

  // If 401, try refreshing token once
  if (response.status === 401) {
    try {
      token = await refreshAccessToken();
      headers.set('Authorization', `Bearer ${token}`);

      return await fetch(url, {
        ...options,
        headers
      });
    } catch (error) {
      logout();
      throw new Error('Session expired - please login again');
    }
  }

  return response;
}
