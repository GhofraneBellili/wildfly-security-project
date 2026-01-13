import { createContext, useContext, useEffect, useState } from 'react';
import { UserProfile, isAuthenticated, getCurrentUser, logout, startOAuth2Login } from '../lib/oauth2Client';

type AuthContextType = {
  user: UserProfile | null;
  profile: UserProfile | null;
  loading: boolean;
  signUp: (email: string, password: string, role: 'business' | 'buyer', businessName?: string) => Promise<{ error: Error | null }>;
  signIn: () => Promise<{ error: Error | null }>;
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

  async function signUp(_email: string, _password: string, _role: 'business' | 'buyer', _businessName?: string) {
    // IAM handles registration separately, not through the app
    // For now, return error indicating to use IAM registration
    return { error: new Error('Please register through the IAM system') };
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

  async function signOut() {
    logout();
    setUser(null);
    setProfile(null);
  }

  return (
    <AuthContext.Provider value={{ user, profile, loading, signUp, signIn, signOut }}>
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
