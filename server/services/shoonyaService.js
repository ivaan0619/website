import axios from 'axios';
import crypto from 'crypto';
import { db } from '../database/init.js';
import { encryptData, decryptData } from '../utils/encryption.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('ShoonyaService');

class ShoonyaService {
  constructor() {
    this.shoonyaInstances = new Map(); // Store Shoonya instances per connection
    this.baseURL = 'https://api.shoonya.com';
  }

  // Generate session token using login credentials
  async generateSessionToken(apiKey, userId, password, twoFA, vendor_code, api_secret, imei) {
    try {
      logger.info('Generating Shoonya session token');
      
      // Create password hash as per Shoonya documentation
      const pwd = crypto.createHash('sha256').update(password).digest('hex');
      
      // Create app key hash
      const app_key = `${userId}|${api_secret}`;
      const appkey_hash = crypto.createHash('sha256').update(app_key).digest('hex');
      
      const loginUrl = `${this.baseURL}/NorenWClientTP/QuickAuth`;
      const data = {
        uid: userId,
        pwd: pwd,
        factor2: twoFA,
        vc: vendor_code,
        appkey: appkey_hash,
        imei: imei || 'abc1234',
        source: 'API'
      };

      const response = await axios.post(loginUrl, data, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        transformRequest: [(data) => {
          return Object.keys(data).map(key => `${key}=${encodeURIComponent(data[key])}`).join('&');
        }]
      });

      if (response.data.stat === 'Ok') {
        logger.info('Shoonya session token generated successfully');
        return {
          access_token: response.data.susertoken,
          session_token: response.data.susertoken
        };
      } else {
        throw new Error(response.data.emsg || 'Failed to generate session token');
      }
    } catch (error) {
      logger.error('Failed to generate Shoonya session token:', error);
      throw new Error(`Failed to generate session token: ${error.response?.data?.emsg || error.message}`);
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
        throw new Error('Session token has expired. Please refresh your token.');
      }

      const apiKey = decryptData(brokerConnection.api_key);
      const sessionToken = decryptData(brokerConnection.access_token);

      const shoonyaInstance = {
        apiKey,
        sessionToken,
        baseURL: this.baseURL,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
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

  // Helper method to make API calls
  async makeApiCall(shoonyaInstance, endpoint, data = {}) {
    const requestData = {
      ...data,
      uid: shoonyaInstance.userId || data.uid,
      actid: shoonyaInstance.userId || data.actid || data.uid
    };

    // Add session token if available
    if (shoonyaInstance.sessionToken) {
      requestData.token = shoonyaInstance.sessionToken;
    }

    const response = await axios.post(`${shoonyaInstance.baseURL}${endpoint}`, requestData, {
      headers: shoonyaInstance.headers,
      transformRequest: [(data) => {
        return Object.keys(data).map(key => `${key}=${encodeURIComponent(data[key])}`).join('&');
      }]
    });

    if (response.data.stat === 'Ok') {
      return response.data;
    } else {
      throw new Error(response.data.emsg || 'API call failed');
    }
  }

  // Test connection
  async testConnection(shoonyaInstance) {
    try {
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/UserDetails');
      logger.info('Shoonya connection test successful');
      return response;
    } catch (error) {
      logger.error('Shoonya connection test failed:', error);
      throw new Error(`Connection test failed: ${error.message}`);
    }
  }

  // Place order
  async placeOrder(brokerConnectionId, orderParams) {
    try {
      logger.info(`Placing Shoonya order for connection ${brokerConnectionId}`);
      
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      // Validate required parameters
      if (!orderParams.tsym) {
        throw new Error('tsym (trading symbol) is required for Shoonya orders');
      }
      if (!orderParams.trantype) {
        throw new Error('trantype is required');
      }
      if (!orderParams.qty) {
        throw new Error('qty is required');
      }

      // Map order parameters to Shoonya format
      const shoonyaOrderData = {
        uid: shoonyaInstance.userId,
        actid: shoonyaInstance.userId,
        exch: orderParams.exch || 'NSE',
        tsym: orderParams.tsym,
        qty: parseInt(orderParams.qty),
        prc: orderParams.prctyp === 'LMT' ? parseFloat(orderParams.prc || 0).toString() : '0',
        prd: orderParams.prd || 'I', // I=Intraday, C=CNC, M=Margin
        trantype: orderParams.trantype, // B=Buy, S=Sell
        prctyp: orderParams.prctyp || 'MKT', // MKT=Market, LMT=Limit, SL-LMT=Stop Loss Limit, SL-MKT=Stop Loss Market
        ret: orderParams.ret || 'DAY', // DAY, IOC, EOS
        ordersource: 'API'
      };

      // Add trigger price for stop loss orders
      if (['SL-LMT', 'SL-MKT'].includes(orderParams.prctyp) && orderParams.trgprc) {
        shoonyaOrderData.trgprc = parseFloat(orderParams.trgprc).toString();
      }

      logger.info('Placing order with Shoonya API:', shoonyaOrderData);
      
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/PlaceOrder', shoonyaOrderData);
      
      logger.info('Shoonya order placed successfully:', response);
      
      return {
        success: true,
        order_id: response.norenordno,
        data: response
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
      
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/UserDetails');
      
      logger.info('Shoonya profile retrieved successfully');
      return response;
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
      
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/PositionBook');
      
      logger.info('Shoonya positions retrieved successfully');
      return response;
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
      
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/Holdings');
      
      logger.info('Shoonya holdings retrieved successfully');
      return response;
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
      
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/OrderBook');
      
      logger.info('Shoonya orders retrieved successfully');
      return response;
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
      
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/SingleOrdHist', {
        norenordno: orderId
      });
      
      logger.info('Shoonya order status retrieved successfully');
      return response;
    } catch (error) {
      logger.error('Failed to get Shoonya order status:', error);
      throw new Error(`Failed to get order status: ${error.message}`);
    }
  }

  // Get instrument tokens (for symbol lookup)
  async getInstruments(brokerConnectionId, exchange = 'NSE') {
    try {
      logger.info(`Getting Shoonya instruments for exchange ${exchange}`);
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/SearchScrip', {
        exch: exchange,
        stext: '' // Empty to get all instruments
      });
      
      logger.info('Shoonya instruments retrieved successfully');
      return response;
    } catch (error) {
      logger.error('Failed to get Shoonya instruments:', error);
      throw new Error(`Failed to get instruments: ${error.message}`);
    }
  }

  // Search for specific symbol
  async searchSymbol(brokerConnectionId, symbol, exchange = 'NSE') {
    try {
      logger.info(`Searching Shoonya symbol ${symbol} on ${exchange}`);
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/SearchScrip', {
        exch: exchange,
        stext: symbol
      });
      
      logger.info('Shoonya symbol search completed');
      return response;
    } catch (error) {
      logger.error('Failed to search Shoonya symbol:', error);
      throw new Error(`Failed to search symbol: ${error.message}`);
    }
  }

  // Get market data
  async getMarketData(brokerConnectionId, exchange, token) {
    try {
      logger.info(`Getting Shoonya market data for ${exchange}:${token}`);
      const shoonyaInstance = await this.getShoonyaInstance(brokerConnectionId);
      
      const response = await this.makeApiCall(shoonyaInstance, '/NorenWClientTP/GetQuotes', {
        exch: exchange,
        token: token
      });
      
      logger.info('Shoonya market data retrieved successfully');
      return response;
    } catch (error) {
      logger.error('Failed to get Shoonya market data:', error);
      throw new Error(`Failed to get market data: ${error.message}`);
    }
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
