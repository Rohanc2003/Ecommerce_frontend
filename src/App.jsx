import React, { useState, useEffect } from 'react';
import './App.css';
import axios from 'axios';
import { useCallback } from 'react';

// API Base URL - change this to your backend URL
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

function App() {
  // View state management
  const [currentView, setCurrentView] = useState('login');
  const [user, setUser] = useState(null);
  const [products, setProducts] = useState([]);
  const [cart, setCart] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [minPrice, setMinPrice] = useState('');
  const [maxPrice, setMaxPrice] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('');

  // Form states
  const [loginForm, setLoginForm] = useState({ email: '', password: '' });
  const [registerForm, setRegisterForm] = useState({ email: '', password: '', confirmPassword: '' });
  const [forgotPasswordForm, setForgotPasswordForm] = useState({ email: '' });
  const [otpForm, setOtpForm] = useState({ email: '', otp: '' });
  const [resetPasswordForm, setResetPasswordForm] = useState({ newPassword: '', confirmPassword: '' });
  const [resetToken, setResetToken] = useState('');

// const fetchCart = useCallback(async () => {
//   if (!user) return;
//   try {
//     const res = await axios.get(`${API_BASE_URL}/api/cart/${user.id}`, {
//       headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
//     });
//     setCart(res.data);
//   } catch (err) {
//     console.error("Error fetching cart:", err);
//   }
// }, [user]);

// useEffect(() => {
//   if (user) {
//     fetchCart();
//   }
// }, [user, fetchCart]);






  // Check for existing token on app load
  useEffect(() => {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
      setCurrentView('products');
      fetchCart(); // Fetch cart for logged-in user
    } else {
      // Show products page even without login
      setCurrentView('products');
    }
    fetchProducts();
  }, []);
  


  // Initialize Google Auth when component mounts
  useEffect(() => {
    const loadGoogleScript = () => {
      if (!window.google && process.env.REACT_APP_GOOGLE_CLIENT_ID) {
        const script = document.createElement('script');
        script.src = 'https://accounts.google.com/gsi/client';
        script.async = true;
        script.defer = true;
        script.onload = () => {
          // Initialize Google Auth after script loads
          setTimeout(() => {
            if (window.google) {
              initializeGoogleAuth();
            }
          }, 100);
        };
        document.head.appendChild(script);
      } else if (window.google) {
        initializeGoogleAuth();
      }
    };

    loadGoogleScript();
  }, []);

  // Re-initialize Google Auth when switching to login/register views
  useEffect(() => {
    if ((currentView === 'login' || currentView === 'register') && window.google) {
      setTimeout(() => {
        initializeGoogleAuth();
      }, 100);
    }
  }, [currentView]);

  // Fetch products from API
 const fetchProducts = async () => {
  try {
    setLoading(true);
    const params = new URLSearchParams();

    if (selectedCategory) {
      params.append('category', selectedCategory);
    }
    if (minPrice !== '') {
      params.append('min_price', minPrice);
    }
    if (maxPrice !== '') {
      params.append('max_price', maxPrice);
    }

    const queryString = params.toString();
    const url = `${API_BASE_URL}/products?${queryString}`;

    const response = await fetch(url);
    const data = await response.json();

    if (response.ok) {
      setProducts(data);
    } else {
      setError(data.error || 'Failed to fetch products');
    }
  } catch (err) {
    setError('Network error: ' + err.message);
  } finally {
    setLoading(false);
  }
};

  // Handle category filter change
  const handleCategoryChange = (category) => {
    setSelectedCategory(category);
    // Fetch products with new category filter
    fetchProductsWithCategory(category);
  };

  // Fetch products with specific category
  const fetchProductsWithCategory = async (category) => {
    try {
      setLoading(true);
      const url = category 
        ? `${API_BASE_URL}/products?category=${category}`
        : `${API_BASE_URL}/products`;
      
      const response = await fetch(url);
      const data = await response.json();
      
      if (response.ok) {
        setProducts(data);
      } else {
        setError(data.error || 'Failed to fetch products');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
  if (user) {
    fetchCart();
  }
}, [user]); // ✅ leave fetchCart out to avoid warnings


  // // Fetch user's cart
  const fetchCart = async () => {
    if (!user) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/cart/${user.id}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setCart(data);
      } else {
        setError(data.error || 'Failed to fetch cart');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    }
  };

  // Handle user registration
  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    // Validate passwords match
    if (registerForm.password !== registerForm.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: registerForm.email,
          password: registerForm.password
        }),
      });

      const data = await response.json();

      if (response.ok) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setUser(data.user);
        setCurrentView('products');
        fetchProducts();
        // Fetch cart after user state is set
        setTimeout(() => {
          fetchCart();
        }, 100);
      } else {
        setError(data.error || 'Registration failed');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle user login
  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(loginForm),
      });

      const data = await response.json();

      if (response.ok) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setUser(data.user);
        setCurrentView('products');
        fetchProducts();
        // Fetch cart after user state is set
        setTimeout(() => {
          fetchCart();
        }, 100);
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };


  // Initialize Google Auth
  const initializeGoogleAuth = () => {
    try {
      window.google.accounts.id.initialize({
        client_id: process.env.REACT_APP_GOOGLE_CLIENT_ID,
        callback: handleGoogleCallback,
        auto_select: false,
        cancel_on_tap_outside: true
      });
      
      // Render Google buttons directly
      const loginButton = document.getElementById('google-signin-button-login');
      const registerButton = document.getElementById('google-signin-button-register');
      
      if (loginButton) {
        window.google.accounts.id.renderButton(loginButton, {
          theme: 'outline',
          size: 'large',
          width: '100%',
          text: 'continue_with',
          shape: 'rectangular'
        });
      }
      
      if (registerButton) {
        window.google.accounts.id.renderButton(registerButton, {
          theme: 'outline',
          size: 'large',
          width: '100%',
          text: 'continue_with',
          shape: 'rectangular'
        });
      }
    } catch (err) {
      setError('Failed to initialize Google authentication: ' + err.message);
      setLoading(false);
    }
  };

  // Handle Google OAuth callback
  const handleGoogleCallback = async (response) => {
    try {
      console.log('Google callback received:', response);
      
      const backendResponse = await fetch(`${API_BASE_URL}/auth/google`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token: response.credential }),
      });

      const data = await backendResponse.json();
      console.log('Backend response:', data);

      if (backendResponse.ok) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setUser(data.user);
        setCurrentView('products');
        fetchProducts();
        // Fetch cart after user state is set
        setTimeout(() => {
          fetchCart();
        }, 100);
        setError(''); // Clear any errors
      } else {
        setError(data.error || 'Google authentication failed');
      }
    } catch (err) {
      console.error('Google auth error:', err);
      setError('Network error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle forgot password
  const handleForgotPassword = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE_URL}/auth/forgot-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: forgotPasswordForm.email }),
      });

      const data = await response.json();

      if (response.ok) {
        setOtpForm({ ...otpForm, email: forgotPasswordForm.email });
        setCurrentView('otp');
        setError('');
      } else {
        setError(data.error || 'Failed to send OTP');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle OTP verification
  const handleOtpVerification = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE_URL}/auth/verify-otp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: otpForm.email, otp: otpForm.otp }),
      });

      const data = await response.json();

      if (response.ok) {
        setResetToken(data.resetToken);
        setCurrentView('reset-password');
        setError('');
      } else {
        setError(data.error || 'Invalid OTP');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle password reset
  const handlePasswordReset = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    // Validate passwords match
    if (resetPasswordForm.newPassword !== resetPasswordForm.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/auth/reset-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          resetToken: resetToken,
          newPassword: resetPasswordForm.newPassword
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setCurrentView('login');
        setError('');
        // Reset forms
        setForgotPasswordForm({ email: '' });
        setOtpForm({ email: '', otp: '' });
        setResetPasswordForm({ newPassword: '', confirmPassword: '' });
        setResetToken('');
      } else {
        setError(data.error || 'Password reset failed');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Handle logout
  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setCart([]);
    setCurrentView('login');
  };

  // Add item to cart
  const addToCart = async (productId) => {
    if (!user) {
      setError('Please login to add items to cart');
      setCurrentView('login');
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/cart`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          productId: productId,
          quantity: 1
        }),
      });

      const data = await response.json();

      if (response.ok) {
        fetchCart(); // Refresh cart
        setError(''); // Clear any previous errors
      } else {
        setError(data.error || 'Failed to add item to cart');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    }
  };

  // Remove item from cart
  const removeFromCart = async (cartItemId) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/cart/${cartItemId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      const data = await response.json();

      if (response.ok) {
        fetchCart(); // Refresh cart
      } else {
        setError(data.error || 'Failed to remove item from cart');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    }
  };

  // Update cart item quantity
  const updateCartQuantity = async (cartItemId, newQuantity) => {
    if (newQuantity <= 0) {
      removeFromCart(cartItemId);
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/cart/${cartItemId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ quantity: newQuantity }),
      });

      const data = await response.json();

      if (response.ok) {
        fetchCart(); // Refresh cart
      } else {
        setError(data.error || 'Failed to update cart item');
      }
    } catch (err) {
      setError('Network error: ' + err.message);
    }
  };

  // Get unique categories for filter
  const categories = [...new Set(products.map(product => product.category))];

  // Calculate total cart value
  const cartTotal = cart.reduce((total, item) => total + (item.price * item.quantity), 0);

  // Login/Register View
  const renderAuthView = () => (
    <div className="auth-container">
      <div className="auth-tabs">
        <button 
          className={currentView === 'login' ? 'active' : ''}
          onClick={() => setCurrentView('login')}
        >
          Login
        </button>
        <button 
          className={currentView === 'register' ? 'active' : ''}
          onClick={() => setCurrentView('register')}
        >
          Register
        </button>
      </div>

      {currentView === 'login' ? (
        <form onSubmit={handleLogin} className="auth-form">
          <h2>Login</h2>
          <input
            type="email"
            placeholder="Email"
            value={loginForm.email}
            onChange={(e) => setLoginForm({...loginForm, email: e.target.value})}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={loginForm.password}
            onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
            required
          />
          <button type="submit" disabled={loading}>
            {loading ? 'Logging in...' : 'Login'}
          </button>
          <div className="forgot-password-link">
            <button type="button" onClick={() => setCurrentView('forgot-password')} className="forgot-password-button">
              Forgot Password?
            </button>
          </div>
          <div className="divider">
            <span>or</span>
          </div>
          <div id="google-signin-button-login" className="google-signin-container"></div>
        </form>
      ) : (
        <form onSubmit={handleRegister} className="auth-form">
          <h2>Register</h2>
          <input
            type="email"
            placeholder="Email"
            value={registerForm.email}
            onChange={(e) => setRegisterForm({...registerForm, email: e.target.value})}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={registerForm.password}
            onChange={(e) => setRegisterForm({...registerForm, password: e.target.value})}
            required
          />
          <input
            type="password"
            placeholder="Confirm Password"
            value={registerForm.confirmPassword}
            onChange={(e) => setRegisterForm({...registerForm, confirmPassword: e.target.value})}
            required
          />
          <button type="submit" disabled={loading}>
            {loading ? 'Registering...' : 'Register'}
          </button>
          <div className="divider">
            <span>or</span>
          </div>
          <div id="google-signin-button-register" className="google-signin-container"></div>
        </form>
      )}
    </div>
  );

  // Forgot Password View
  const renderForgotPasswordView = () => (
    <div className="auth-container">
      <form onSubmit={handleForgotPassword} className="auth-form">
        <h2>Forgot Password</h2>
        <p>Enter your email address and we'll send you an OTP to reset your password.</p>
        <input
          type="email"
          placeholder="Email"
          value={forgotPasswordForm.email}
          onChange={(e) => setForgotPasswordForm({...forgotPasswordForm, email: e.target.value})}
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Sending OTP...' : 'Send OTP'}
        </button>
        <div className="back-to-login">
          <button type="button" onClick={() => setCurrentView('login')} className="back-to-login-button">
            Back to Login
          </button>
        </div>
      </form>
    </div>
  );

  // OTP Verification View
  const renderOtpView = () => (
    <div className="auth-container">
      <form onSubmit={handleOtpVerification} className="auth-form">
        <h2>Verify OTP</h2>
        <p>Enter the 6-digit OTP sent to {otpForm.email}</p>
        <input
          type="text"
          placeholder="Enter OTP"
          value={otpForm.otp}
          onChange={(e) => setOtpForm({...otpForm, otp: e.target.value})}
          maxLength="6"
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Verifying...' : 'Verify OTP'}
        </button>
        <div className="back-to-login">
          <button type="button" onClick={() => setCurrentView('forgot-password')} className="back-to-login-button">
            Back to Forgot Password
          </button>
        </div>
      </form>
    </div>
  );

  // Reset Password View
  const renderResetPasswordView = () => (
    <div className="auth-container">
      <form onSubmit={handlePasswordReset} className="auth-form">
        <h2>Reset Password</h2>
        <p>Enter your new password</p>
        <input
          type="password"
          placeholder="New Password"
          value={resetPasswordForm.newPassword}
          onChange={(e) => setResetPasswordForm({...resetPasswordForm, newPassword: e.target.value})}
          required
        />
        <input
          type="password"
          placeholder="Confirm New Password"
          value={resetPasswordForm.confirmPassword}
          onChange={(e) => setResetPasswordForm({...resetPasswordForm, confirmPassword: e.target.value})}
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Resetting...' : 'Reset Password'}
        </button>
      </form>
    </div>
  );

  // Products View
  const renderProductsView = () => (
    <div className="products-container">
      <div className="header">
        <h1>E-Commerce Store</h1>
        <div className="user-info">
          {user ? (
            <>
              <span>Welcome, {user.email}</span>
              <button onClick={() => setCurrentView('cart')} className="cart-button">
                Cart ({cart.length})
              </button>
              <button onClick={handleLogout} className="logout-button">
                Logout
              </button>
            </>
          ) : (
            <>
              <button onClick={() => setCurrentView('login')} className="login-button">
                Login
              </button>
              <button onClick={() => setCurrentView('register')} className="register-button">
                Register
              </button>
            </>
          )}
        </div>
      </div>

      <div className="filters">
  <select 
    value={selectedCategory} 
    onChange={(e) => {
      setSelectedCategory(e.target.value);
      fetchProducts();
    }}
  >
    <option value="">All Categories</option>
    {categories.map(category => (
      <option key={category} value={category}>{category}</option>
    ))}
  </select>
  <input
    type="number"
    placeholder="Min Price"
    value={minPrice}
    onChange={(e) => setMinPrice(e.target.value)}
    className="price-filter-input"
  />
  <input
    type="number"
    placeholder="Max Price"
    value={maxPrice}
    onChange={(e) => setMaxPrice(e.target.value)}
    className="price-filter-input"
  />
  <button onClick={fetchProducts} className="filter-button">
    Apply Filters
  </button>
  <button onClick={() => {
    setSelectedCategory('');
    setMinPrice('');
    setMaxPrice('');
    fetchProducts();
  }} className="refresh-button">
    Double click to Reset Filters
  </button>
</div>

      <div className="products-grid">
        {products.map(product => (
          <div key={product.id} className="product-card">
            <img src={product.image_url} alt={product.name} />
            <div className="product-info">
              <h3>{product.name}</h3>
              <p className="product-description">{product.description}</p>
              <p className="product-category">{product.category}</p>
              <p className="product-price">${product.price}</p>
              <button 
                onClick={() => addToCart(product.id)}
                className="add-to-cart-button"
              >
                Add to Cart
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  // Cart View
  const renderCartView = () => (
    <div className="cart-container">
      <div className="header">
        <h1>Shopping Cart</h1>
        <div className="user-info">
          <span>Welcome, {user?.email}</span>
          <button onClick={() => setCurrentView('products')} className="back-button">
            Back to Products
          </button>
          <button onClick={handleLogout} className="logout-button">
            Logout
          </button>
        </div>
      </div>

      {cart.length === 0 ? (
        <div className="empty-cart">
          <h2>Your cart is empty</h2>
          <button onClick={() => setCurrentView('products')}>
            Continue Shopping
          </button>
        </div>
      ) : (
        <div className="cart-items">
          {cart.map(item => (
            <div key={item.id} className="cart-item">
              <img src={item.image_url} alt={item.name} />
              <div className="item-details">
                <h3>{item.name}</h3>
                <p className="item-category">{item.category}</p>
                <p className="item-price">${item.price}</p>
              </div>
              <div className="quantity-controls">
                <button onClick={() => updateCartQuantity(item.id, item.quantity - 1)}>
                  -
                </button>
                <span>{item.quantity}</span>
                <button onClick={() => updateCartQuantity(item.id, item.quantity + 1)}>
                  +
                </button>
              </div>
              <div className="item-total">
                ${(item.price * item.quantity).toFixed(2)}
              </div>
              <button 
                onClick={() => removeFromCart(item.id)}
                className="remove-button"
              >
                Remove
              </button>
            </div>
          ))}
          
          <div className="cart-summary">
            <h2>Total: ${cartTotal.toFixed(2)}</h2>
            <button className="checkout-button">
              Proceed to Checkout
            </button>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="app">
      {error && (
        <div className="error-message">
          {error}
          <button onClick={() => setError('')}>×</button>
        </div>
      )}
      
      {currentView === 'login' || currentView === 'register' ? renderAuthView() :
       currentView === 'forgot-password' ? renderForgotPasswordView() :
       currentView === 'otp' ? renderOtpView() :
       currentView === 'reset-password' ? renderResetPasswordView() :
       currentView === 'products' ? renderProductsView() :
       currentView === 'cart' ? renderCartView() : null}
    </div>
  );
}

export default App;
