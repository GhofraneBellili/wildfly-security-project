import { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Shield } from 'lucide-react';

export default function Auth() {
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const { signIn } = useAuth();

  async function handleSignIn() {
    setError('');
    setLoading(true);

    const { error } = await signIn();
    if (error) {
      setError(error.message);
      setLoading(false);
    }
    // Note: signIn will redirect to IAM, so loading state may not be relevant
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-green-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-4">
            <Shield className="w-8 h-8 text-blue-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Marketplace</h1>
          <p className="text-gray-600">Secure authentication with Phoenix IAM</p>
        </div>

        <div className="space-y-4">
          <p className="text-center text-sm text-gray-600">
            Click below to sign in through our secure IAM system
          </p>

          {error && (
            <div className="bg-red-50 text-red-600 p-3 rounded-lg text-sm">
              {error}
            </div>
          )}

          <button
            onClick={handleSignIn}
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3 rounded-lg font-medium hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            <Shield className="w-5 h-5" />
            {loading ? 'Redirecting...' : 'Sign In with IAM'}
          </button>

          <div className="text-center text-xs text-gray-500 mt-4">
            <p>Registration is handled through the IAM system</p>
          </div>
        </div>
      </div>
    </div>
  );
}
