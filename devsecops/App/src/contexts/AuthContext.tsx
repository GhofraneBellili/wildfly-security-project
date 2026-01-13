import { createContext, useContext, useEffect, useState } from 'react';
import { UserProfile, isAuthenticated, getCurrentUser, logout, startOAuth2Login, apiLogin, apiVerifyMfa, apiSetupMfa, apiEnableMfa, apiRegister } from '../lib/oauth2Client';

type AuthContextType = {
  user: UserProfile | null;
  profile: UserProfile | null;
  loading: boolean;
  signUp: (email: string, username: string, password: string, role: 'business' | 'buyer', businessName?: string) => Promise<{ error: Error | null }>;
  signIn: () => Promise<{ error: Error | null }>;
  signInWithCredentials: (username: string, password: string) => Promise<{ error: Error | null; mfaRequired?: boolean }>;
  verifyMfa: (username: string, code: string) => Promise<{ error: Error | null }>;
  setupMfa: () => Promise<{ secret?: string; qrCode?: string; error?: string }>;
  enableMfa: (secret: string, code: string) => Promise<{ error: Error | null }>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already authenticated
    if (isAuthenticated()) {
      const currentUser = getCurrentUser();
      setUser(currentUser);
      setProfile(currentUser);
    }
    setLoading(false);
  }, []);

  async function signUp(email: string, username: string, password: string, role: 'business' | 'buyer', businessName?: string) {
    try {
      const { success, error } = await apiRegister(email, username, password, role, businessName);
      if (success) {
        return { error: null };
      } else {
        return { error: new Error(error || 'Registration failed') };
      }
    } catch (error) {
      return { error: error as Error };
    }
  }

  async function signIn() {
    try {
      await startOAuth2Login();
      // This will redirect to IAM, so no return needed
      return { error: null };
    } catch (error) {
      return { error: error as Error };
    }
  }

  async function signInWithCredentials(username: string, password: string) {
    const result = await apiLogin(username, password);
    if (result.success) {
      if (result.mfaRequired) {
        return { error: null, mfaRequired: true };
      } else {
        // Proceed to OAuth2 flow
        await startOAuth2Login();
        return { error: null };
      }
    } else {
      return { error: new Error(result.error || 'Login failed') };
    }
  }

  async function verifyMfa(username: string, code: string) {
    const result = await apiVerifyMfa(username, code);
    if (result.success) {
      // Proceed to OAuth2 flow
      await startOAuth2Login();
      return { error: null };
    } else {
      return { error: new Error(result.error || 'MFA verification failed') };
    }
  }

  async function setupMfa() {
    const result = await apiSetupMfa();
    if ('secret' in result) {
      return { secret: result.secret, qrCode: result.qrCode };
    } else {
      return { error: result.error };
    }
  }

  async function enableMfa(secret: string, code: string) {
    const result = await apiEnableMfa(secret, code);
    if (result.success) {
      return { error: null };
    } else {
      return { error: new Error(result.error || 'MFA enable failed') };
    }
  }

  async function signOut() {
    logout();
    setUser(null);
    setProfile(null);
  }

  return (
    <AuthContext.Provider value={{ user, profile, loading, signUp, signIn, signInWithCredentials, verifyMfa, setupMfa, enableMfa, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
