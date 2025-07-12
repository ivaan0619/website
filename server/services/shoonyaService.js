import axios from 'axios';
import crypto from 'crypto';
import { db } from '../database/init.js';
import { encryptData, decryptData } from '../utils/encryption.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('ShoonyaService');

class ShoonyaService {
  constructor() {
    this.shoonyaInstances = new Map(); // Store Shoonya instances per connection
    this.baseURL = 'https://api.shoonya.com/NorenWClientTP';
  }

  // Generate session token using login credentials
  async generateSessionToken(apiKey, apiSecret, userId, password, twoFA, vendor, appKey, imei) {
    try {
      logger.info('Generating Shoonya session token');
      
      // Create password hash
      const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
      
      // Create app key hash
      const appKeyHash = crypto.createHash('sha256').update(`${userId}|${apiKey}`).digest('hex');
      
      const loginData = {
        apkversion: 'js:1.0.0',
        uid: userId,
        pwd: passwordHash,
        factor2: twoFA,
        vc: vendor,
        appkey: appKeyHash,
        imei: imei,
        source: 'API'
      };

      console.log('🔐 Shoonya login request data:', {
        uid: userId,
        vc: vendor,
        source: 'API',
        hasPassword: !!password,
        hasTwoFA: !!twoFA
      });

      const response = await axios.post(`${this.baseURL}/QuickAuth`, loginData, {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'AutoTraderHub/1.0'
        },
        timeout: 30000
      });

      console.log('✅ Shoonya login response status:', response.status);
      console.log('✅ Shoonya login response data:', response.data);

      if (response.data.stat === 'Ok') {
        logger.info('Shoonya session token generated successfully');
        return {
          access_token: response.data.susertoken,
          user_id: response.data.uid || userId,
          user_name: response.data.uname || userId,
          email: response.data.email || '',
          broker: 'shoonya'
        };
      } else {
        throw new Error(response.data.emsg || 'Login failed');
      }
    } catch (error) {
      console.error('❌ Shoonya login failed:', {
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
        message: error.message
      });
      
      logger.error('Failed to generate Shoonya session token:', error);
      
      const errorMessage = error.response?.data?.emsg || 
                          error.response?.data?.error || 
                          error.message;
      
      throw new Error(`Failed to generate session token: ${errorMessage}`);
    }
  }

  // Initialize Shoonya instance for a connection
  async initializeShoonya(brokerConnection) {
    try {
      logger.info(`Initializing Shoonya instance for connection ${brokerConnection.id}`);

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
      const userId = brokerConnection.user_id_broker;

      const shoonyaInstance = {
        apiKey,
        accessToken,
        userId,
        baseURL: this.baseURL,
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'AutoTraderHub/1.0'
        }
      };

      // Test the connection
      await this.testConnection(shoonyaInstance);

      this.shoonyaInstances.set(brokerConnection.id, shoonyaInstance);
      logger.info(`Shoonya instance initialized for connection ${brokerConnection.id}`);
      
      return shoonyaInstance;
    } catch (error) {
      logger.error('Failed to initialize Shoonya instance:', error);
      throw new Error(`Failed to initialize Shoonya connection: ${error.message}`);
    }
  }

  // Get or create Shoonya instance
  async getShoonyaInstance(brokerConnectionId) {
    logger.info(`Getting Shoonya instance for connection ${brokerConnectionId}`);
    
    if (this.shoonyaInstances.has(brokerConnectionId)) {
      logger.info('Using cached Shoonya instance');
      return this.shoonyaInstances.get(brokerConnectionId);
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

    logger.info('Broker connection found, initializing Shoonya');
    return await this.initializeShoonya(brokerConnection);
  }

  // Test connection
  async testConnection(shoonyaInstance) {
    try {
      const response = await this.makeRequest(shoonyaInstance, '/UserDetails', {
        uid: shoonyaInstance.userId,
        actid: shoonyaInstance.userId
      });
      
      logger.info('Shoonya connection test successful');
      return response;
    } catch (error) {
      logger.error('Shoonya connection test failed:', error);
      throw new Error(`Connection test failed: ${error.message}`);
    }
  }

  // Make authenticated request to Shoonya API
  async makeRequest(shoonyaInstance, endpoint, data = {}) {
    try {
      const requestData = {
        ...data,
        uid: shoonyaInstance.userId,
        actid: shoonyaInstance.userId
      };

      // Add session token for authenticated requests
      if (shoonyaInstance.accessToken) {
        requestData.susertoken = shoonyaInstance.accessToken;
      }

      const response = await axios.post(`${shoonyaInstance.baseURL}${endpoint}`, requestData, {
        headers: shoonyaInstance.headers,
        timeout: 30000
      });

      if (response.data.stat === 'Not_Ok') {
        throw new Error(response.data.emsg || 'API request failed');
      }

      return response.data;
    } catch (error) {
      logger.error(`Shoonya API request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // Place order
  async placeOrder(brokerConnectionId, orderParams) {
    try {
      logger.info(`Placing Shoonya order for connection ${brokerConnectionId}`);
      
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      // Validate required parameters
      if (!orderParams.tradingsymbol) {
        throw new Error('tradingsymbol is required for Shoonya orders');
      }
      if (!orderParams.transaction_type) {
        throw new Error('transaction_type is required');
      }
      if (!orderParams.quantity) {
        throw new Error('quantity is required');
      }

      // Map order parameters to Shoonya format
      const shoonyaOrderData = {
        uid: shoonyaInstance.userId,
        actid: shoonyaInstance.userId,
        exch: orderParams.exchange || 'NSE',
        tsym: orderParams.tradingsymbol,
        qty: parseInt(orderParams.quantity).toString(),
        prc: orderParams.order_type === 'LMT' ? parseFloat(orderParams.price || 0).toString() : '0',
        prd: this.mapProduct(orderParams.product || 'I'),
        trantype: orderParams.transaction_type === 'BUY' ? 'B' : 'S',
        prctyp: this.mapOrderType(orderParams.order_type || 'MKT'),
        ret: orderParams.validity || 'DAY',
        ordersource: 'API'
      };

      // Add trigger price for stop loss orders
      if (['SL-LMT', 'SL-MKT'].includes(orderParams.order_type)) {
        shoonyaOrderData.trgprc = parseFloat(orderParams.trigger_price || 0).toString();
      }

      logger.info('Placing order with Shoonya API:', shoonyaOrderData);
      
      const response = await this.makeRequest(shoonyaInstance, '/PlaceOrder', shoonyaOrderData);

      logger.info('Shoonya order placed successfully:', response);
      
      return {
        success: true,
        order_id: response.norenordno,
        data: {
          status: 'OPEN',
          order_id: response.norenordno,
          message: response.result || 'Order placed successfully'
        }
      };
    } catch (error) {
      logger.error('Failed to place Shoonya order:', error);
      throw new Error(`Order placement failed: ${error.message}`);
    }
  }

  // Get user profile
  async getProfile(brokerConnectionId) {
    try {
      logger.info(`Getting Shoonya profile for connection ${brokerConnectionId}`);
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      const response = await this.makeRequest(shoonyaInstance, '/UserDetails', {
        uid: shoonyaInstance.userId,
        actid: shoonyaInstance.userId
      });
      
      logger.info('Shoonya profile retrieved successfully');
      return {
        user_name: response.uname || shoonyaInstance.userId,
        user_id: response.uid || shoonyaInstance.userId,
        email: response.email || '',
        broker: 'shoonya',
        account_id: response.actid || shoonyaInstance.userId
      };
    } catch (error) {
      logger.error('Failed to get Shoonya profile:', error);
      throw new Error(`Failed to get profile: ${error.message}`);
    }
  }

  // Get positions
  async getPositions(brokerConnectionId) {
    try {
      logger.info(`Getting Shoonya positions for connection ${brokerConnectionId}`);
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      const response = await this.makeRequest(shoonyaInstance, '/PositionBook', {
        uid: shoonyaInstance.userId,
        actid: shoonyaInstance.userId
      });
      
      logger.info('Shoonya positions retrieved successfully');
      
      // Format positions data to match our standard format
      const positions = Array.isArray(response) ? response : [];
      return positions
        .filter(pos => Math.abs(parseInt(pos.netqty || 0)) > 0)
        .map(pos => ({
          tradingsymbol: pos.tsym,
          exchange: pos.exch,
          instrument_token: pos.token,
          product: pos.prd,
          quantity: parseInt(pos.netqty || 0),
          average_price: parseFloat(pos.netavgprc || 0),
          last_price: parseFloat(pos.lp || 0),
          pnl: parseFloat(pos.rpnl || 0) + parseFloat(pos.urmtom || 0),
          unrealised: parseFloat(pos.urmtom || 0),
          realised: parseFloat(pos.rpnl || 0),
          value: Math.abs(parseInt(pos.netqty || 0)) * parseFloat(pos.lp || 0)
        }));
    } catch (error) {
      logger.error('Failed to get Shoonya positions:', error);
      throw new Error(`Failed to get positions: ${error.message}`);
    }
  }

  // Get holdings
  async getHoldings(brokerConnectionId) {
    try {
      logger.info(`Getting Shoonya holdings for connection ${brokerConnectionId}`);
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      const response = await this.makeRequest(shoonyaInstance, '/Holdings', {
        uid: shoonyaInstance.userId,
        actid: shoonyaInstance.userId,
        prd: 'C' // CNC product for holdings
      });
      
      logger.info('Shoonya holdings retrieved successfully');
      
      // Format holdings data
      const holdings = Array.isArray(response) ? response : [];
      return holdings
        .filter(holding => parseInt(holding.holdqty || 0) > 0)
        .map(holding => ({
          tradingsymbol: holding.tsym,
          exchange: holding.exch,
          instrument_token: holding.token,
          quantity: parseInt(holding.holdqty || 0),
          average_price: parseFloat(holding.upldprc || 0),
          last_price: parseFloat(holding.lp || 0),
          pnl: parseFloat(holding.pnl || 0),
          day_change: parseFloat(holding.daychange || 0),
          day_change_percentage: parseFloat(holding.daychangeper || 0)
        }));
    } catch (error) {
      logger.error('Failed to get Shoonya holdings:', error);
      throw new Error(`Failed to get holdings: ${error.message}`);
    }
  }

  // Get orders
  async getOrders(brokerConnectionId) {
    try {
      logger.info(`Getting Shoonya orders for connection ${brokerConnectionId}`);
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      const response = await this.makeRequest(shoonyaInstance, '/OrderBook', {
        uid: shoonyaInstance.userId,
        actid: shoonyaInstance.userId
      });
      
      logger.info('Shoonya orders retrieved successfully');
      
      // Format orders data
      const orders = Array.isArray(response) ? response : [];
      return orders.map(order => ({
        order_id: order.norenordno,
        tradingsymbol: order.tsym,
        exchange: order.exch,
        transaction_type: order.trantype === 'B' ? 'BUY' : 'SELL',
        quantity: parseInt(order.qty || 0),
        price: parseFloat(order.prc || 0),
        order_type: this.mapShoonyaOrderType(order.prctyp),
        product: order.prd,
        status: this.mapShoonyaStatus(order.status),
        filled_quantity: parseInt(order.fillshares || 0),
        average_price: parseFloat(order.avgprc || 0),
        order_timestamp: order.norentm,
        exchange_timestamp: order.exch_tm
      }));
    } catch (error) {
      logger.error('Failed to get Shoonya orders:', error);
      throw new Error(`Failed to get orders: ${error.message}`);
    }
  }

  // Get order status
  async getOrderStatus(brokerConnectionId, orderId) {
    try {
      logger.info(`Getting Shoonya order status for order ${orderId}`);
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      // Get order book and find specific order
      const orders = await this.getOrders(brokerConnectionId);
      const order = orders.find(o => o.order_id === orderId);
      
      if (!order) {
        throw new Error(`Order ${orderId} not found`);
      }
      
      logger.info('Shoonya order status retrieved successfully');
      return order;
    } catch (error) {
      logger.error('Failed to get Shoonya order status:', error);
      throw new Error(`Failed to get order status: ${error.message}`);
    }
  }

  // Helper methods for mapping between formats
  mapProduct(product) {
    const productMap = {
      'I': 'I',     // Intraday
      'MIS': 'I',   // Intraday
      'CNC': 'C',   // Cash and Carry
      'D': 'C',     // Delivery
      'NRML': 'M'   // Normal/Margin
    };
    return productMap[product] || 'I';
  }

  mapOrderType(orderType) {
    const orderTypeMap = {
      'MARKET': 'MKT',
      'MKT': 'MKT',
      'LIMIT': 'LMT',
      'LMT': 'LMT',
      'SL': 'SL-LMT',
      'SL-M': 'SL-MKT',
      'SL-LMT': 'SL-LMT',
      'SL-MKT': 'SL-MKT'
    };
    return orderTypeMap[orderType] || 'MKT';
  }

  mapShoonyaOrderType(shoonyaOrderType) {
    const orderTypeMap = {
      'MKT': 'MARKET',
      'LMT': 'LIMIT',
      'SL-LMT': 'SL',
      'SL-MKT': 'SL-M'
    };
    return orderTypeMap[shoonyaOrderType] || 'MARKET';
  }

  mapShoonyaStatus(shoonyaStatus) {
    const statusMap = {
      'COMPLETE': 'COMPLETE',
      'OPEN': 'OPEN',
      'PENDING': 'PENDING',
      'CANCELLED': 'CANCELLED',
      'CANCELED': 'CANCELLED',
      'REJECTED': 'REJECTED'
    };
    return statusMap[shoonyaStatus] || 'PENDING';
  }

  // Clear cached instance
  clearCachedInstance(brokerConnectionId) {
    if (this.shoonyaInstances.has(brokerConnectionId)) {
      this.shoonyaInstances.delete(brokerConnectionId);
      logger.info(`Cleared cached Shoonya instance for connection ${brokerConnectionId}`);
    }
  }
}

export default new ShoonyaService();