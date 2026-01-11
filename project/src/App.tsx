import { useAuth } from './contexts/AuthContext';
import Auth from './components/Auth';
import BusinessDashboard from './components/BusinessDashboard';
import Marketplace from './components/Marketplace';

function App() {
  const { user, profile, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user || !profile) {
    return <Auth />;
  }

  if (profile.role === 'business') {
    return <BusinessDashboard />;
  }

  return <Marketplace />;
}

export default App;
