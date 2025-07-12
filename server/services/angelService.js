import axios from 'axios';
import { db } from '../database/init.js';
import { encryptData, decryptData } from '../utils/encryption.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('AngelService');

class AngelService {
  constructor() {
    this.angelInstances = new Map(); // Store Angel instances per connection
    this.baseURL = 'https://apiconnect.angelbroking.com';
  }

  // Generate access token from authorization code
  async generateAccessToken(apiKey, clientCode, password, totp) {
    try {
      logger.info('Generating Angel Broking access token');
      
      const loginUrl = `${this.baseURL}/rest/auth/angelbroking/user/v1/loginByPassword`;
      const data = {
        clientcode: clientCode,
        password: password,
        totp: totp
      };

      const response = await axios.post(loginUrl, data, {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-UserType': 'USER',
          'X-SourceID': 'WEB',
          'X-ClientLocalIP': '192.168.1.1',
          'X-ClientPublicIP': '106.193.147.98',
          'X-MACAddress': '00:00:00:00:00:00',
          'X-PrivateKey': apiKey
        }
      });

      if (response.data.status && response.data.data) {
        logger.info('Angel Broking access token generated successfully');
        return {
          access_token: response.data.data.jwtToken,
          refresh_token: response.data.data.refreshToken,
          feed_token: response.data.data.feedToken
        };
      } else {
        throw new Error(response.data.message || 'Failed to generate access token');
      }
    } catch (error) {
      logger.error('Failed to generate Angel Broking access token:', error);
      throw new Error(`Failed to generate access token: ${error.response?.data?.message || error.message}`);
    }
  }

  // Initialize Angel instance for a connection
  async initializeAngel(brokerConnection) {
    try {
      logger.info(`Initializing Angel instance for connection ${brokerConnection.id}`);

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

      const angelInstance = {
        apiKey,
        accessToken,
        baseURL: this.baseURL,
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-UserType': 'USER',
          'X-SourceID': 'WEB',
          'X-ClientLocalIP': '192.168.1.1',
          'X-ClientPublicIP': '106.193.147.98',
          'X-MACAddress': '00:00:00:00:00:00',
          'X-PrivateKey': apiKey
        }
      };

      // Test the connection
      await this.testConnection(angelInstance);

      this.angelInstances.set(brokerConnection.id, angelInstance);
      logger.info(`Angel instance initialized for connection ${brokerConnection.id}`);
      
      return angelInstance;
    } catch (error) {
      logger.error('Failed to initialize Angel instance:', error);
      throw new Error(`Failed to initialize Angel connection: ${error.message}`);
    }
  }

  // Get or create Angel instance
  async getAngelInstance(brokerConnectionId) {
    logger.info(`Getting Angel instance for connection ${brokerConnectionId}`);
    
    if (this.angelInstances.has(brokerConnectionId)) {
      logger.info('Using cached Angel instance');
      return this.angelInstances.get(brokerConnectionId);
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

    logger.info('Broker connection found, initializing Angel');
    return await this.initializeAngel(brokerConnection);
  }

  // Test connection
  async testConnection(angelInstance) {
    try {
      const response = await axios.get(`${angelInstance.baseURL}/rest/secure/angelbroking/user/v1/getProfile`, {
        headers: angelInstance.headers
      });
      
      if (response.data.status) {
        logger.info('Angel connection test successful');
        return response.data.data;
      } else {
        throw new Error(response.data.message || 'Connection test failed');
      }
    } catch (error) {
      logger.error('Angel connection test failed:', error);
      throw new Error(`Connection test failed: ${error.response?.data?.message || error.message}`);
    }
  }

  // Place order
  async placeOrder(brokerConnectionId, orderParams) {
    try {
      logger.info(`Placing Angel order for connection ${brokerConnectionId}`);
      
      const angelInstance = await this.getAngelInstance(brokerConnectionId);
      
      // Validate required parameters
      if (!orderParams.symboltoken) {
        throw new Error('symboltoken is required for Angel orders');
      }
      if (!orderParams.transactiontype) {
        throw new Error('transactiontype is required');
      }
      if (!orderParams.quantity) {
        throw new Error('quantity is required');
      }

      // Map order parameters to Angel format
      const angelOrderData = {
        variety: orderParams.variety || 'NORMAL',
        tradingsymbol: orderParams.tradingsymbol,
        symboltoken: orderParams.symboltoken,
        transactiontype: orderParams.transactiontype,
        exchange: orderParams.exchange || 'NSE',
        ordertype: orderParams.ordertype || 'MARKET',
        producttype: orderParams.producttype || 'INTRADAY',
        duration: orderParams.duration || 'DAY',
        price: orderParams.ordertype === 'LIMIT' ? parseFloat(orderParams.price || 0) : '0',
        squareoff: orderParams.squareoff || '0',
        stoploss: orderParams.stoploss || '0',
        quantity: parseInt(orderParams.quantity)
      };

      logger.info('Placing order with Angel API:', angelOrderData);
      
      const response = await axios.post(
        `${angelInstance.baseURL}/rest/secure/angelbroking/order/v1/placeOrder`,
        angelOrderData,
        { headers: angelInstance.headers }
      );

      if (response.data.status) {
        logger.info('Angel order placed successfully:', response.data);
        
        return {
          success: true,
          order_id: response.data.data.orderid,
          data: response.data.data
        };
      } else {
        throw new Error(response.data.message || 'Order placement failed');
      }
    } catch (error) {
      logger.error('Failed to place Angel order:', error);
      throw new Error(`Order placement failed: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get user profile
  async getProfile(brokerConnectionId) {
    try {
      logger.info(`Getting Angel profile for connection ${brokerConnectionId}`);
      const angelInstance = await this.getAngelInstance(brokerConnectionId);
      
      const response = await axios.get(`${angelInstance.baseURL}/rest/secure/angelbroking/user/v1/getProfile`, {
        headers: angelInstance.headers
      });
      
      if (response.data.status) {
        logger.info('Angel profile retrieved successfully');
        return response.data.data;
      } else {
        throw new Error(response.data.message || 'Failed to get profile');
      }
    } catch (error) {
      logger.error('Failed to get Angel profile:', error);
      throw new Error(`Failed to get profile: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get positions
  async getPositions(brokerConnectionId) {
    try {
      logger.info(`Getting Angel positions for connection ${brokerConnectionId}`);
      const angelInstance = await this.getAngelInstance(brokerConnectionId);
      
      const response = await axios.get(`${angelInstance.baseURL}/rest/secure/angelbroking/order/v1/getPosition`, {
        headers: angelInstance.headers
      });
      
      if (response.data.status) {
        logger.info('Angel positions retrieved successfully');
        return response.data.data;
      } else {
        throw new Error(response.data.message || 'Failed to get positions');
      }
    } catch (error) {
      logger.error('Failed to get Angel positions:', error);
      throw new Error(`Failed to get positions: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get holdings
  async getHoldings(brokerConnectionId) {
    try {
      logger.info(`Getting Angel holdings for connection ${brokerConnectionId}`);
      const angelInstance = await this.getAngelInstance(brokerConnectionId);
      
      const response = await axios.get(`${angelInstance.baseURL}/rest/secure/angelbroking/portfolio/v1/getHolding`, {
        headers: angelInstance.headers
      });
      
      if (response.data.status) {
        logger.info('Angel holdings retrieved successfully');
        return response.data.data;
      } else {
        throw new Error(response.data.message || 'Failed to get holdings');
      }
    } catch (error) {
      logger.error('Failed to get Angel holdings:', error);
      throw new Error(`Failed to get holdings: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get orders
  async getOrders(brokerConnectionId) {
    try {
      logger.info(`Getting Angel orders for connection ${brokerConnectionId}`);
      const angelInstance = await this.getAngelInstance(brokerConnectionId);
      
      const response = await axios.get(`${angelInstance.baseURL}/rest/secure/angelbroking/order/v1/getOrderBook`, {
        headers: angelInstance.headers
      });
      
      if (response.data.status) {
        logger.info('Angel orders retrieved successfully');
        return response.data.data;
      } else {
        throw new Error(response.data.message || 'Failed to get orders');
      }
    } catch (error) {
      logger.error('Failed to get Angel orders:', error);
      throw new Error(`Failed to get orders: ${error.response?.data?.message || error.message}`);
    }
  }

  // Get order status
  async getOrderStatus(brokerConnectionId, orderId) {
    try {
      logger.info(`Getting Angel order status for order ${orderId}`);
      const angelInstance = await this.getAngelInstance(brokerConnectionId);
      
      const response = await axios.post(
        `${angelInstance.baseURL}/rest/secure/angelbroking/order/v1/details`,
        { orderid: orderId },
        { headers: angelInstance.headers }
      );
      
      if (response.data.status) {
        logger.info('Angel order status retrieved successfully');
        return response.data.data;
      } else {
        throw new Error(response.data.message || 'Failed to get order status');
      }
    } catch (error) {
      logger.error('Failed to get Angel order status:', error);
      throw new Error(`Failed to get order status: ${error.response?.data?.message || error.message}`);
    }
  }

  // Clear cached instance
  clearCachedInstance(brokerConnectionId) {
    if (this.angelInstances.has(brokerConnectionId)) {
      this.angelInstances.delete(brokerConnectionId);
      logger.info(`Cleared cached Angel instance for connection ${brokerConnectionId}`);
    }
  }
}

export default new AngelService();
