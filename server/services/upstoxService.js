import axios from 'axios';
import { db } from '../database/init.js';
import { encryptData, decryptData } from '../utils/encryption.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('UpstoxService');

class UpstoxService {
  constructor() {
    this.upstoxInstances = new Map(); // Store Upstox instances per connection
    this.baseURL = 'https://api.upstox.com/v2';
  }

  // Generate access token from authorization code
  async generateAccessToken(apiKey, apiSecret, authorizationCode, redirectUri) {
    try {
      logger.info('Generating Upstox access token');
      
      const tokenUrl = `${this.baseURL}/login/authorization/token`;
      const data = {
        code: authorizationCode,
        client_id: apiKey,
        client_secret: apiSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      };

      const response = await axios.post(tokenUrl, data, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        }
      });

      logger.info('Upstox access token generated successfully');
      return response.data;
    } catch (error) {
      logger.error('Failed to generate Upstox access token:', error);
      throw new Error(`Failed to generate access token: ${error.response?.data?.message || error.message}`);
    }
  }

  // Initialize Upstox instance for a connection
  async initializeUpstox(brokerConnection) {
    try {
      logger.info(`Initializing Upstox instance for connection ${brokerConnection.id}`);

      if (!brokerConnection.api_key) {
        throw new Error('API key is missing from broker connection');
      }

      if (!brokerConnection.access_token) {
        throw new Error('Access token is missing from broker connection');
      }

      // Check if token is expired
      const now = Math.floor(Date.now() / 1000);
      if (brokerConnection.access_token_expires_at && brokerConnection.access_token_expires_at < now) {
        throw new Error('Access token has expired. Please refresh your token.');
      }

      const apiKey = decryptData(brokerConnection.api_key);
      const accessToken = decryptData(brokerConnection.access_token);

      const upstoxInstance = {
        apiKey,
        accessToken,
        baseURL: this.baseURL,
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      };

      // Test the connection
      await this.testConnection(upstoxInstance);

      this.upstoxInstances.set(brokerConnection.id, upstoxInstance);
      logger.info(`Upstox instance initialized for connection ${brokerConnection.id}`);
      
      return upstoxInstance;
    } catch (error) {
      logger.error('Failed to initialize Upstox instance:', error);
      throw new Error(`Failed to initialize Upstox connection: ${error.message}`);
    }
  }

  // Get or create Upstox instance
  async getUpstoxInstance(brokerConnectionId) {
    logger.info(`Getting Upstox instance for connection ${brokerConnectionId}`);
    
    if (this.upstoxInstances.has(brokerConnectionId)) {
      logger.info('Using cached Upstox instance');
      return this.upstoxInstances.get(brokerConnectionId);
    }

    logger.info('Fetching broker connection from database');
    const brokerConnection = await db.getAsync(
      'SELECT * FROM broker_connections WHERE id = ? AND is_active = 1',
      [brokerConnectionId]
    );

    if (!brokerConnection) {
      logger.error('Broker connection not found or inactive');
      throw new Error('Broker connection not found or inactive');
    }

    logger.info('Broker connection found, initializing Upstox');
    return await this.initializeUpstox(brokerConnection);
  }

  // Test connection
  async testConnection(upstoxInstance) {
    try {
      const response = await axios.get(`${upstoxInstance.baseURL}/user/profile`, {
        headers: upstoxInstance.headers
      });
      
      logger.info('Upstox connection test successful');
      return response.data;
    } catch (error) {
      logger.error('Upstox connection test failed:', error);
      throw new Error(`Connection test failed: ${error.response?.data?.message || error.message}`);
    }
  }

  // Place order
  async placeOrder(brokerConnectionId, orderParams) {
    try {
      logger.info(`Placing Upstox order for connection ${brokerConnectionId}`);
      
      const upstoxInstance = await this.getUpstoxInstance(brokerConnectionId);
      
      // Validate required parameters
      if (!orderParams.instrument_token) {
        throw new Error('instrument_token is required for Upstox orders');
      }
      if (!orderParams.transaction_type) {
        throw new Error('transaction_type is required');
      }
      if (!orderParams.quantity) {
        throw new Error('quantity is required');
      }

      // Map order parameters to Upstox format
      const upstoxOrderData = {
        quantity: parseInt(orderParams.quantity),
        product: orderParams.product || 'I', // I = Intraday, D = Delivery, CO = Cover Order, OCO = One Cancels Other
        validity: orderParams.validity || 'DAY',
        price: orderParams.order_type === 'LIMIT' ? parseFloat(orderParams.price || 0) : 0,
        tag: orderParams.tag || 'AutoTraderHub',
        instrument_token: orderParams.instrument_token,
        order_type: orderParams.order_type || 'MARKET',
        transaction_type: orderParams.transaction_type,
        disclosed_quantity: orderParams.disclosed_quantity || 0,
        trigger_price: ['SL', 'SL-M'].includes(orderParams.order_type) ? parseFloat(orderParams.trigger_price || 0) : 0,
        is_amo: orderParams.is_amo || false
      };

      logger.info('Placing order with Upstox API:', upstoxOrderData);
      
      const response = await axios.post(
        `${upstoxInstance.baseURL}/order/place`,
        upstoxOrderData,
        { headers: upstoxInstance.headers }
      );

      logger.info('Upstox order placed successfully:', response.data);
      
      return {
        success: true,
        order_id: response.data.data.order_id,
        data: response.data.data
      };
    } catch (error) {
      logger.error('Failed to place Upstox order:', error);
      throw new Error(`Order placement failed: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get user profile
  async getProfile(brokerConnectionId) {
    try {
      logger.info(`Getting Upstox profile for connection ${brokerConnectionId}`);
      const upstoxInstance = await this.getUpstoxInstance(brokerConnectionId);
      
      const response = await axios.get(`${upstoxInstance.baseURL}/user/profile`, {
        headers: upstoxInstance.headers
      });
      
      logger.info('Upstox profile retrieved successfully');
      return response.data.data;
    } catch (error) {
      logger.error('Failed to get Upstox profile:', error);
      throw new Error(`Failed to get profile: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get positions
  async getPositions(brokerConnectionId) {
    try {
      logger.info(`Getting Upstox positions for connection ${brokerConnectionId}`);
      const upstoxInstance = await this.getUpstoxInstance(brokerConnectionId);
      
      const response = await axios.get(`${upstoxInstance.baseURL}/portfolio/short-term-positions`, {
        headers: upstoxInstance.headers
      });
      
      logger.info('Upstox positions retrieved successfully');
      return response.data.data;
    } catch (error) {
      logger.error('Failed to get Upstox positions:', error);
      throw new Error(`Failed to get positions: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get holdings
  async getHoldings(brokerConnectionId) {
    try {
      logger.info(`Getting Upstox holdings for connection ${brokerConnectionId}`);
      const upstoxInstance = await this.getUpstoxInstance(brokerConnectionId);
      
      const response = await axios.get(`${upstoxInstance.baseURL}/portfolio/long-term-holdings`, {
        headers: upstoxInstance.headers
      });
      
      logger.info('Upstox holdings retrieved successfully');
      return response.data.data;
    } catch (error) {
      logger.error('Failed to get Upstox holdings:', error);
      throw new Error(`Failed to get holdings: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get orders
  async getOrders(brokerConnectionId) {
    try {
      logger.info(`Getting Upstox orders for connection ${brokerConnectionId}`);
      const upstoxInstance = await this.getUpstoxInstance(brokerConnectionId);
      
      const response = await axios.get(`${upstoxInstance.baseURL}/order/retrieve-all`, {
        headers: upstoxInstance.headers
      });
      
      logger.info('Upstox orders retrieved successfully');
      return response.data.data;
    } catch (error) {
      logger.error('Failed to get Upstox orders:', error);
      throw new Error(`Failed to get orders: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get order status
  async getOrderStatus(brokerConnectionId, orderId) {
    try {
      logger.info(`Getting Upstox order status for order ${orderId}`);
      const upstoxInstance = await this.getUpstoxInstance(brokerConnectionId);
      
      const response = await axios.get(`${upstoxInstance.baseURL}/order/details?order_id=${orderId}`, {
        headers: upstoxInstance.headers
      });
      
      logger.info('Upstox order status retrieved successfully');
      return response.data.data;
    } catch (error) {
      logger.error('Failed to get Upstox order status:', error);
      throw new Error(`Failed to get order status: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get instrument details
  async getInstrumentToken(symbol, exchange = 'NSE_EQ') {
    try {
      logger.info(`Getting instrument token for ${symbol} on ${exchange}`);
      
      // This would typically require a master contract file or instrument search API
      // For now, we'll return a placeholder - in production, you'd implement proper instrument lookup
      const response = await axios.get(`${this.baseURL}/market-quote/instruments/${exchange}/${symbol}`, {
        headers: {
          'Accept': 'application/json'
        }
      });
      
      return response.data.data.instrument_token;
    } catch (error) {
      logger.error('Failed to get instrument token:', error);
      throw new Error(`Failed to get instrument token: ${error.response?.data?.message || error.message}`);
    }
  }

  // Clear cached instance
  clearCachedInstance(brokerConnectionId) {
    if (this.upstoxInstances.has(brokerConnectionId)) {
      this.upstoxInstances.delete(brokerConnectionId);
      logger.info(`Cleared cached Upstox instance for connection ${brokerConnectionId}`);
    }
  }
}

export default new UpstoxService();