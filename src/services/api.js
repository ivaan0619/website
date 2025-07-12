import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api';

console.log('🔧 API Configuration:', {
  baseURL: API_BASE_URL,
  environment: import.meta.env.MODE
});

// Create axios instance with better error handling
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 second timeout
  withCredentials: true // Important for CORS
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('authToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  console.log(`🌐 API Request: ${config.method?.toUpperCase()} ${config.url}`);
  return config;
});

// Enhanced response interceptor with better error handling
api.interceptors.response.use(
  (response) => {
    console.log(`✅ API Response: ${response.config.method?.toUpperCase()} ${response.config.url} - ${response.status}`);
    return response;
  },
  (error) => {
    console.error(`❌ API Error: ${error.config?.method?.toUpperCase()} ${error.config?.url}`, error);
    
    if (error.response?.status === 401) {
      localStorage.removeItem('authToken');
      window.location.href = '/login';
    }
    
    // Enhanced error information
    if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
      console.error('❌ Server connection failed. Please check if the Node.js API server is running on port 3001.');
      error.message = 'Unable to connect to server. Please check your connection and try again.';
    }
    
    return Promise.reject(error);
  }
);

// Auth API - Updated for Node.js Express endpoints
export const authAPI = {
  register: (data) => api.post('/auth/register', data),
  login: (data) => api.post('/auth/login', data),
  getProfile: () => api.get('/auth/me'),
  verifyOtp: ({ identifier, otp }) => api.post('/auth/verify-otp', { identifier, otp }),
  resendOtp: ({ identifier }) => api.post('/auth/resend-otp', { identifier }),
  verifyOtpForReset: ({ identifier, otp }) => api.post('/auth/verify-otp-reset', { identifier, otp }),
  forgotPassword: (data) => api.post('/auth/forgot-password', data),
  resetPassword: ({ resetToken, newPassword }) => api.post('/auth/reset-password', { resetToken, newPassword }),
};

// Enhanced Broker API - Updated for Node.js Express endpoints
export const brokerAPI = {
  getConnections: () => api.get('/broker/connections'),
  getConnection: (id) => api.get(`/broker/connections/${id}`),
  connect: async (data) => {
    try {
      console.log('🔗 Attempting broker connection with data:', { 
        brokerName: data.brokerName, 
        connectionName: data.connectionName,
        hasApiKey: !!data.apiKey, 
        hasApiSecret: !!data.apiSecret,
        userId: data.userId 
      });
      
      const response = await api.post('/broker/connect', data);
      console.log('✅ Broker connection response:', response.data);
      return response;
    } catch (error) {
      console.error('❌ Broker connection failed:', error);
      throw error;
    }
  },
  disconnect: (connectionId) => api.post('/broker/disconnect', { connectionId }),
  deleteConnection: (connectionId) => api.delete(`/broker/connections/${connectionId}`),
  
  // Reconnect using stored credentials
  reconnect: async (connectionId) => {
    try {
      console.log('🔄 Attempting to reconnect using stored credentials for connection:', connectionId);
      const response = await api.post(`/broker/reconnect/${connectionId}`);
      console.log('✅ Reconnect response:', response.data);
      return response;
    } catch (error) {
      console.error('❌ Reconnect failed:', error);
      throw error;
    }
  },
  
  syncPositions: (connectionId) => api.post(`/broker/sync/positions/${connectionId}`),
  testConnection: (connectionId) => api.post(`/broker/test/${connectionId}`),
  
  // Real-time positions API
  getPositions: async (connectionId) => {
    try {
      console.log('📊 Fetching real-time positions for connection:', connectionId);
      const response = await api.get(`/broker/positions/${connectionId}`);
      console.log('✅ Positions fetched:', response.data);
      return response;
    } catch (error) {
      console.error('❌ Failed to fetch positions:', error);
      throw error;
    }
  },
  
  getHoldings: async (connectionId) => {
    try {
      console.log('📈 Fetching real-time holdings for connection:', connectionId);
      const response = await api.get(`/broker/holdings/${connectionId}`);
      console.log('✅ Holdings fetched:', response.data);
      return response;
    } catch (error) {
      console.error('❌ Failed to fetch holdings:', error);
      throw error;
    }
  },
  
  // Shoonya specific endpoints
  validateShoonyaCredentials: (data) => api.post('/broker/shoonya/validate', data),
  getShoonyaLoginUrl: (connectionId) => api.get(`/broker/shoonya/${connectionId}/login-url`),
  completeShoonyaAuth: (connectionId, authCode) => api.post(`/broker/shoonya/${connectionId}/complete-auth`, { authCode }),
  refreshShoonyaToken: (connectionId) => api.post(`/broker/shoonya/${connectionId}/refresh-token`),
};

// Enhanced Orders API - Updated for Node.js Express endpoints
export const ordersAPI = {
  getOrders: (params) => api.get('/orders', { params }),
  getOrderDetails: (orderId, params) => api.get(`/orders/${orderId}`, { params }),
  syncOrders: (brokerConnectionId) => api.post(`/orders/sync/${brokerConnectionId}`),
  updateOrderStatus: (orderId, data) => api.patch(`/orders/${orderId}/status`, data),
  getPositions: (params) => api.get('/orders/positions', { params }),
  getPnL: (params) => api.get('/orders/pnl', { params }),
  
  // Real-time order monitoring
  startOrderPolling: async (orderId) => {
    try {
      console.log('🔄 Starting real-time polling for order:', orderId);
      const response = await api.post(`/orders/${orderId}/start-polling`);
      console.log('✅ Order polling started:', response.data);
      return response;
    } catch (error) {
      console.error('❌ Failed to start order polling:', error);
      throw error;
    }
  },
  
  stopOrderPolling: async (orderId) => {
    try {
      console.log('⏹️ Stopping real-time polling for order:', orderId);
      const response = await api.post(`/orders/${orderId}/stop-polling`);
      console.log('✅ Order polling stopped:', response.data);
      return response;
    } catch (error) {
      console.error('❌ Failed to stop order polling:', error);
      throw error;
    }
  },
  
  getPollingStatus: () => api.get('/orders/polling/status'),
};

// Subscription API
export const subscriptionAPI = {
  getPlans: () => api.get('/subscription/plans'),
  getCurrentSubscription: () => api.get('/subscription/current'),
  subscribe: (planId) => api.post('/subscription/subscribe', { planId }),
  cancelSubscription: () => api.post('/subscription/cancel'),
  renewSubscription: (planId) => api.post('/subscription/renew', { planId }),
  getUsage: () => api.get('/subscription/usage'),
};

// Webhook API - Updated for Node.js Express endpoints
export const webhookAPI = {
  getLogs: (userId, params) => api.get(`/webhook/logs/${userId}`, { params }),
  testWebhook: (userId, webhookId) => api.post(`/webhook/test/${userId}/${webhookId}`),
};

export default api;