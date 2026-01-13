import { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { supabase, Product } from '../lib/supabase';
import { ShoppingCart, LogOut, Package, Search, Filter } from 'lucide-react';
import { requestJITAccess, getPendingJITRequests, getMyJITAccess, approveJITRequest, revokeJITRequest, isAdmin, JITRequest } from '../lib/oauth2Client';

type ProductWithBusiness = Product & {
  profiles: {
    business_name: string;
  };
};

export default function Marketplace() {
  const { profile, signOut } = useAuth();
  const [products, setProducts] = useState<ProductWithBusiness[]>([]);
  const [filteredProducts, setFilteredProducts] = useState<ProductWithBusiness[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'product' | 'service'>('all');
  const [cart, setCart] = useState<{ [key: string]: number }>({});

  // JIT Access state
  const [, setJitRequests] = useState<JITRequest[]>([]);
  const [, setMyJITAccess] = useState<JITRequest[]>([]);
  const [, setShowJITForm] = useState(false);
  const [jitForm, setJitForm] = useState({
    privilegeType: '',
    justification: '',
    expirationTime: ''
  });
  const [, setJitLoading] = useState(false);

  useEffect(() => {
    loadProducts();
  }, []);

  useEffect(() => {
    let filtered = products;

    if (searchTerm) {
      filtered = filtered.filter(
        (p) =>
          p.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
          p.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
          p.profiles.business_name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (filterType !== 'all') {
      filtered = filtered.filter((p) => p.type === filterType);
    }

    setFilteredProducts(filtered);
  }, [searchTerm, filterType, products]);

  async function loadProducts() {
    setLoading(true);
    const { data, error } = await supabase
      .from('products')
      .select('*, profiles(business_name)')
      .order('created_at', { ascending: false });

    if (!error && data) {
      setProducts(data as ProductWithBusiness[]);
      setFilteredProducts(data as ProductWithBusiness[]);
    }
    setLoading(false);
  }

  function addToCart(productId: string) {
    setCart((prev) => ({
      ...prev,
      [productId]: (prev[productId] || 0) + 1,
    }));
  }

  function removeFromCart(productId: string) {
    setCart((prev) => {
      const newCart = { ...prev };
      if (newCart[productId] > 1) {
        newCart[productId]--;
      } else {
        delete newCart[productId];
      }
      return newCart;
    });
  }

  async function handleCheckout() {
    const orderPromises = Object.entries(cart).map(([productId, quantity]) => {
      const product = products.find((p) => p.id === productId);
      if (!product) return null;

      return supabase.from('orders').insert({
        buyer_id: profile?.sub,
        product_id: productId,
        quantity,
        total_price: product.price * quantity,
        status: 'pending',
      });
    });

    await Promise.all(orderPromises.filter(Boolean));
    setCart({});
    alert('Order placed successfully!');
  }

  const cartTotal = Object.entries(cart).reduce((sum, [productId, quantity]) => {
    const product = products.find((p) => p.id === productId);
    return sum + (product?.price || 0) * quantity;
  }, 0);

  const cartItemCount = Object.values(cart).reduce((sum, qty) => sum + qty, 0);

  // JIT Access functions
  // @ts-ignore - unused function kept for future implementation
  async function handleJITRequest(e: React.FormEvent) {
    e.preventDefault();
    setJitLoading(true);

    const { success, error } = await requestJITAccess(
      jitForm.privilegeType,
      jitForm.justification,
      jitForm.expirationTime
    );

    if (success) {
      alert('JIT access request submitted successfully!');
      setShowJITForm(false);
      setJitForm({ privilegeType: '', justification: '', expirationTime: '' });
      loadMyJITAccess();
    } else {
      alert(`Failed to submit request: ${error}`);
    }

    setJitLoading(false);
  }

  async function loadPendingJITRequests() {
    if (!isAdmin()) return;
    const requests = await getPendingJITRequests();
    setJitRequests(requests);
  }

  async function loadMyJITAccess() {
    const access = await getMyJITAccess();
    setMyJITAccess(access);
  }

  // @ts-ignore - unused function kept for future implementation
  async function handleApproveJIT(requestId: number) {
    const { success, error } = await approveJITRequest(requestId);
    if (success) {
      alert('JIT request approved!');
      loadPendingJITRequests();
    } else {
      alert(`Failed to approve: ${error}`);
    }
  }

  // @ts-ignore - unused function kept for future implementation
  async function handleRevokeJIT(requestId: number) {
    const { success, error } = await revokeJITRequest(requestId);
    if (success) {
      alert('JIT request revoked!');
      loadPendingJITRequests();
    } else {
      alert(`Failed to revoke: ${error}`);
    }
  }

  useEffect(() => {
    if (isAdmin()) {
      loadPendingJITRequests();
    }
    loadMyJITAccess();
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Marketplace</h1>
              <p className="text-sm text-gray-500">Discover amazing products & services</p>
            </div>
            <div className="flex items-center gap-4">
              <div className="relative">
                <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                  <ShoppingCart className="w-4 h-4" />
                  Cart ({cartItemCount})
                </button>
                {cartItemCount > 0 && (
                  <div className="absolute right-0 mt-2 w-80 bg-white rounded-lg shadow-xl border p-4">
                    <h3 className="font-semibold mb-3">Shopping Cart</h3>
                    <div className="space-y-2 max-h-64 overflow-y-auto mb-3">
                      {Object.entries(cart).map(([productId, quantity]) => {
                        const product = products.find((p) => p.id === productId);
                        if (!product) return null;
                        return (
                          <div key={productId} className="flex justify-between items-center text-sm">
                            <div className="flex-1">
                              <p className="font-medium">{product.title}</p>
                              <p className="text-gray-500">
                                ${product.price} x {quantity}
                              </p>
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => removeFromCart(productId)}
                                className="px-2 py-1 bg-gray-100 rounded hover:bg-gray-200"
                              >
                                -
                              </button>
                              <button
                                onClick={() => addToCart(productId)}
                                className="px-2 py-1 bg-gray-100 rounded hover:bg-gray-200"
                              >
                                +
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div className="border-t pt-3">
                      <div className="flex justify-between font-semibold mb-3">
                        <span>Total:</span>
                        <span>${cartTotal.toFixed(2)}</span>
                      </div>
                      <button
                        onClick={handleCheckout}
                        className="w-full bg-green-600 text-white py-2 rounded-lg hover:bg-green-700 transition-colors"
                      >
                        Checkout
                      </button>
                    </div>
                  </div>
                )}
              </div>
              <button
                onClick={() => signOut()}
                className="flex items-center gap-2 px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <LogOut className="w-4 h-4" />
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6 flex flex-col sm:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Search products, services, or businesses..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="text-gray-400 w-5 h-5" />
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value as 'all' | 'product' | 'service')}
              className="px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Items</option>
              <option value="product">Products Only</option>
              <option value="service">Services Only</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div className="text-center py-12 text-gray-500">Loading marketplace...</div>
        ) : filteredProducts.length === 0 ? (
          <div className="bg-white rounded-xl shadow-sm p-12 text-center">
            <Package className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No products found</h3>
            <p className="text-gray-500">Try adjusting your search or filters</p>
          </div>
        ) : (
          <>
            <p className="text-sm text-gray-600 mb-4">
              Showing {filteredProducts.length} {filteredProducts.length === 1 ? 'item' : 'items'}
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredProducts.map((product) => (
                <div
                  key={product.id}
                  className="bg-white rounded-xl shadow-sm overflow-hidden hover:shadow-lg transition-shadow"
                >
                  {product.image_url ? (
                    <img
                      src={product.image_url}
                      alt={product.title}
                      className="w-full h-48 object-cover"
                    />
                  ) : (
                    <div className="w-full h-48 bg-gradient-to-br from-blue-100 to-green-100 flex items-center justify-center">
                      <Package className="w-16 h-16 text-gray-400" />
                    </div>
                  )}
                  <div className="p-5">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <h3 className="font-semibold text-gray-900 text-lg">{product.title}</h3>
                        <p className="text-sm text-gray-500">{product.profiles.business_name}</p>
                      </div>
                      <span className="inline-block px-2 py-1 text-xs font-medium bg-blue-100 text-blue-700 rounded">
                        {product.type}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mb-4 line-clamp-2">{product.description}</p>
                    <div className="flex items-center justify-between">
                      <p className="text-2xl font-bold text-green-600">${product.price}</p>
                      <button
                        onClick={() => addToCart(product.id)}
                        className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                      >
                        <ShoppingCart className="w-4 h-4" />
                        Add to Cart
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
