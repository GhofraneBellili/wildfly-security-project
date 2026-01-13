import { useEffect, useState } from 'react';
import { useAuth } from './contexts/AuthContext';
import Auth from './components/Auth';
import Marketplace from './components/Marketplace';
import { handleOAuth2Callback } from './lib/oauth2Client';

function App() {
  const { user, profile, loading } = useAuth();
  const [callbackLoading, setCallbackLoading] = useState(false);

  useEffect(() => {
    // Handle OAuth2 callback
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');

    if (code && state) {
      setCallbackLoading(true);
      handleOAuth2Callback(code, state)
        .then(() => {
          // Clear URL parameters and redirect to home
          window.history.replaceState({}, document.title, window.location.pathname);
          window.location.reload(); // Reload to update auth state
        })
        .catch((error) => {
          console.error('OAuth callback failed:', error);
          setCallbackLoading(false);
        });
    }
  }, []);

  if (callbackLoading || loading) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">{callbackLoading ? 'Completing sign in...' : 'Loading...'}</p>
        </div>
      </div>
    );
  }

  if (!user || !profile) {
    return <Auth />;
  }

  // For now, assume all users are buyers since IAM doesn't provide role info
  // In a real implementation, you'd decode the JWT to get user roles/groups
  return <Marketplace />;
}

export default App;
