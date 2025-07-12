import { KiteConnect } from 'kiteconnect';
import { db } from '../database/init.js';
import { encryptData, decryptData } from '../utils/encryption.js';
import createLogger from '../utils/logger.js';

const logger = createLogger('KiteService');

class KiteService {
  constructor() {
    this.kiteInstances = new Map(); // Store KiteConnect instances per user
  }

  // Generate access token from request token
  async generateAccessToken(apiKey, apiSecret, requestToken) {
    try {
      console.log('🔑 Generating Zerodha access token with:', {
        apiKey: apiKey.slice(0, 8) + '...',
        requestToken
      });

      const kite = new KiteConnect({
        api_key: apiKey,
        debug: process.env.NODE_ENV === 'development'
      });

      const session = await kite.generateSession(requestToken, apiSecret);

      console.log('✅ Zerodha access token generated successfully:', {
        access_token: session?.access_token?.slice(0, 8) + '...',
        user_id: session?.user_id
      });

      return session;
    } catch (error) {
      console.error('❌ Zerodha token exchange failed:', {
        message: error?.message,
        status: error?.status,
        data: error?.data || null
      });

      throw new Error(`Failed to generate access token: ${error?.message || 'Unknown error'}`);
    }
  }

  // Initialize KiteConnect instance for a user
  async initializeKite(brokerConnection) {
    try {
      console.log('🔍 ===== BROKER CONNECTION DEBUG =====');
      console.log('🔍 Raw broker connection data:', {
        id: brokerConnection.id,
        user_id: brokerConnection.user_id,
        broker_name: brokerConnection.broker_name,
        has_api_key: !!brokerConnection.api_key,
        has_access_token: !!brokerConnection.access_token,
        api_key_encrypted_length: brokerConnection.api_key ? brokerConnection.api_key.length : 0,
        access_token_encrypted_length: brokerConnection.access_token ? brokerConnection.access_token.length : 0,
        is_active: brokerConnection.is_active,
        access_token_expires_at: brokerConnection.access_token_expires_at,
        created_at: brokerConnection.created_at,
        updated_at: brokerConnection.updated_at
      });

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

      console.log('🔍 Encrypted API Key:', brokerConnection.api_key);
      console.log('🔍 Encrypted Access Token:', brokerConnection.access_token);

      let apiKey, accessToken;
      
      try {
        apiKey = decryptData(brokerConnection.api_key);
        console.log('🔍 Decrypted API Key:', apiKey);
        console.log('🔍 API Key Length:', apiKey ? apiKey.length : 0);
        console.log('🔍 API Key Preview:', apiKey ? `${apiKey.substring(0, 8)}...${apiKey.substring(apiKey.length - 4)}` : 'null');
      } catch (decryptError) {
        console.error('❌ Failed to decrypt API key:', decryptError.message);
        throw new Error(`Failed to decrypt API key: ${decryptError.message}`);
      }

      try {
        accessToken = decryptData(brokerConnection.access_token);
        console.log('🔍 Decrypted Access Token:', accessToken);
        console.log('🔍 Access Token Length:', accessToken ? accessToken.length : 0);
        console.log('🔍 Access Token Preview:', accessToken ? `${accessToken.substring(0, 8)}...${accessToken.substring(accessToken.length - 4)}` : 'null');
      } catch (decryptError) {
        console.error('❌ Failed to decrypt access token:', decryptError.message);
        throw new Error(`Failed to decrypt access token: ${decryptError.message}`);
      }

      console.log('🔍 Creating KiteConnect instance with API Key:', apiKey);
      const kc = new KiteConnect({
        api_key: apiKey,
        debug: process.env.NODE_ENV === 'development'
      });

      console.log('🔍 Setting access token:', accessToken);
      kc.setAccessToken(accessToken);

      // Test the connection immediately
      console.log('🔍 Testing connection with Zerodha...');
      try {
        const profile = await kc.getProfile();
        console.log('✅ Connection test successful!');
        console.log('✅ User Name:', profile.user_name);
        console.log('✅ User ID:', profile.user_id);
        console.log('✅ Email:', profile.email);
        console.log('✅ Broker:', profile.broker);
      } catch (testError) {
        console.error('❌ Connection test failed:', testError);
        console.error('❌ Error details:', {
          message: testError.message,
          status: testError.status,
          error_type: testError.error_type,
          data: testError.data
        });
        throw new Error(`Invalid credentials: ${testError.message}`);
      }

      this.kiteInstances.set(brokerConnection.id, kc);
      logger.info(`KiteConnect instance initialized for broker connection ${brokerConnection.id}`);
      console.log('🔍 ===== END BROKER CONNECTION DEBUG =====');
      return kc;
    } catch (error) {
      logger.error('Failed to initialize Kite instance:', error);
      console.error('❌ Failed to initialize Kite instance:', error);
      throw new Error(`Failed to initialize broker connection: ${error.message}`);
    }
  }

  // Get or create KiteConnect instance
  async getKiteInstance(brokerConnectionId) {
    console.log('🔍 Getting KiteConnect instance for broker connection:', brokerConnectionId);
    
    if (this.kiteInstances.has(brokerConnectionId)) {
      console.log('✅ Using cached KiteConnect instance');
      return this.kiteInstances.get(brokerConnectionId);
    }

    console.log('🔍 Fetching broker connection from database...');
    const brokerConnection = await db.getAsync(
      'SELECT * FROM broker_connections WHERE id = ? AND is_active = 1',
      [brokerConnectionId]
    );

    if (!brokerConnection) {
      console.error('❌ Broker connection not found or inactive');
      throw new Error('Broker connection not found or inactive');
    }

    console.log('✅ Broker connection found, initializing KiteConnect...');
    return await this.initializeKite(brokerConnection);
  }

  // Place order with detailed logging
  async placeOrder(brokerConnectionId, orderParams) {
    try {
      console.log('🔍 ===== ORDER PLACEMENT DEBUG =====');
      console.log('🔍 Broker Connection ID:', brokerConnectionId);
      console.log('🔍 Order Parameters:', JSON.stringify(orderParams, null, 2));
      
      const kc = await this.getKiteInstance(brokerConnectionId);
      
      // Validate required parameters
      if (!orderParams.tradingsymbol) {
        throw new Error('tradingsymbol is required');
      }
      if (!orderParams.transaction_type) {
        throw new Error('transaction_type is required');
      }
      if (!orderParams.quantity) {
        throw new Error('quantity is required');
      }
      
      const orderData = {
        exchange: orderParams.exchange || 'NSE',
        tradingsymbol: orderParams.tradingsymbol,
        transaction_type: orderParams.transaction_type,
        quantity: parseInt(orderParams.quantity),
        order_type: orderParams.order_type || 'MARKET',
        product: orderParams.product || 'MIS',
        validity: orderParams.validity || 'DAY',
        disclosed_quantity: orderParams.disclosed_quantity || 0,
        trigger_price: orderParams.trigger_price || 0,
        squareoff: orderParams.squareoff || 0,
        stoploss: orderParams.stoploss || 0,
        trailing_stoploss: orderParams.trailing_stoploss || 0,
        tag: orderParams.tag || 'AutoTraderHub'
      };

      // Add price for limit orders
      if (orderParams.order_type === 'LIMIT' && orderParams.price) {
        orderData.price = parseFloat(orderParams.price);
      }

      console.log('🔍 Final order data for Kite API:', JSON.stringify(orderData, null, 2));
      
      // The KiteConnect placeOrder method expects variety as first parameter
      const variety = orderParams.variety || 'regular';
      console.log('🔍 Order variety:', variety);
      
      console.log('🔍 Calling kc.placeOrder...');
      const response = await kc.placeOrder(variety, orderData);
      
      console.log('✅ Order placed successfully!');
      console.log('✅ Response:', JSON.stringify(response, null, 2));
      console.log('🔍 ===== END ORDER PLACEMENT DEBUG =====');
      
      logger.info(`Order placed successfully: ${response.order_id}`);
      
      return {
        success: true,
        order_id: response.order_id,
        data: response
      };
    } catch (error) {
      console.log('🔍 ===== ORDER PLACEMENT ERROR DEBUG =====');
      console.error('❌ Failed to place order:', error);
      console.error('❌ Error type:', typeof error);
      console.error('❌ Error properties:', Object.keys(error));
      console.error('❌ Error message:', error.message);
      console.error('❌ Error status:', error.status);
      console.error('❌ Error error_type:', error.error_type);
      console.error('❌ Error data:', error.data);
      console.log('🔍 ===== END ORDER PLACEMENT ERROR DEBUG =====');
      
      logger.error('❌ Failed to place order:', error);
      throw new Error(`Order placement failed: ${error.message}`);
    }
  }

  // Get profile with enhanced error handling
  async getProfile(brokerConnectionId) {
    try {
      console.log('🔍 Getting profile for broker connection:', brokerConnectionId);
      const kc = await this.getKiteInstance(brokerConnectionId);
      const profile = await kc.getProfile();
      console.log('✅ Profile retrieved:', profile.user_name);
      return profile;
    } catch (error) {
      console.error('❌ Failed to get profile:', error);
      logger.error('Failed to get profile:', error);
      throw new Error(`Failed to get profile: ${error.message}`);
    }
  }

  // Get positions with enhanced error handling and data formatting
  async getPositions(brokerConnectionId) {
    try {
      console.log('🔍 Getting positions for broker connection:', brokerConnectionId);
      const kc = await this.getKiteInstance(brokerConnectionId);
      const positions = await kc.getPositions();
      logger.info('✅ Positions retrieved from KiteConnect');
      
      // Return both net and day positions for flexibility
      const result = {
        net: positions.net || [],
        day: positions.day || [],
        raw: positions
      };
      
      console.log('✅ Formatted positions:', result.net?.length || 0, 'net positions');
      return result;
    } catch (error) {
      console.error('❌ Failed to get positions:', error);
      logger.error('Failed to get positions:', error);
      throw new Error(`Failed to get positions: ${error.message}`);
    }
  }

  // Get holdings with enhanced error handling
  async getHoldings(brokerConnectionId) {
    try {
      console.log('🔍 Getting holdings for broker connection:', brokerConnectionId);
      const kc = await this.getKiteInstance(brokerConnectionId);
      const holdings = await kc.getHoldings();
      console.log('✅ Holdings retrieved:', holdings?.length || 0, 'holdings');
      return holdings;
    } catch (error) {
      console.error('❌ Failed to get holdings:', error);
      logger.error('Failed to get holdings:', error);
      throw new Error(`Failed to get holdings: ${error.message}`);
    }
  }

  // Get orders with enhanced error handling
  async getOrders(brokerConnectionId) {
    try {
      console.log('🔍 Getting orders for broker connection:', brokerConnectionId);
      const kc = await this.getKiteInstance(brokerConnectionId);
      const orders = await kc.getOrders();
      console.log('✅ Orders retrieved:', orders?.length || 0, 'orders');
      return orders;
    } catch (error) {
      console.error('❌ Failed to get orders:', error);
      logger.error('Failed to get orders:', error);
      throw new Error(`Failed to get orders: ${error.message}`);
    }
  }

  // Get order status with enhanced error handling and retry logic
  async getOrderStatus(brokerConnectionId, orderId) {
    try {
      console.log('🔍 Getting order status for:', { brokerConnectionId, orderId });
      const kc = await this.getKiteInstance(brokerConnectionId);
      
      // First try to get order history
      let orderHistory;
      try {
        orderHistory = await kc.getOrderHistory(orderId);
        console.log('✅ Order history retrieved:', JSON.stringify(orderHistory, null, 2));
      } catch (historyError) {
        console.warn('⚠️ Failed to get order history, trying orders list:', historyError.message);
        
        // Fallback: get all orders and find the specific one
        const allOrders = await kc.getOrders();
        const matchingOrder = allOrders.find(order => order.order_id === orderId);
        
        if (matchingOrder) {
          orderHistory = [matchingOrder];
          console.log('✅ Order found in orders list:', JSON.stringify(matchingOrder, null, 2));
        } else {
          throw new Error(`Order ${orderId} not found in broker account`);
        }
      }
      
      if (!orderHistory || orderHistory.length === 0) {
        throw new Error(`No order history found for order ${orderId}`);
      }
      
      // Return latest status (last item in history)
      const latestStatus = orderHistory[orderHistory.length - 1];
      console.log('✅ Latest order status:', JSON.stringify(latestStatus, null, 2));
      return latestStatus;
    } catch (error) {
      console.error('❌ Failed to get order status:', error);
      logger.error('Failed to get order status:', error);
      throw new Error(`Failed to get order status: ${error.message}`);
    }
  }

  // Test connection with detailed logging
  async testConnection(brokerConnectionId) {
    try {
      console.log('🔍 ===== CONNECTION TEST DEBUG =====');
      console.log('🔍 Testing connection for broker connection:', brokerConnectionId);
      
      const profile = await this.getProfile(brokerConnectionId);
      
      console.log('✅ Connection test successful!');
      console.log('✅ User details:', {
        user_name: profile.user_name,
        user_id: profile.user_id,
        email: profile.email,
        broker: profile.broker
      });
      console.log('🔍 ===== END CONNECTION TEST DEBUG =====');
      
      logger.info(`Connection test successful for broker connection ${brokerConnectionId}`);
      return {
        success: true,
        user_name: profile.user_name,
        user_id: profile.user_id,
        email: profile.email,
        broker: profile.broker
      };
    } catch (error) {
      console.log('🔍 ===== CONNECTION TEST ERROR DEBUG =====');
      console.error('❌ Connection test failed:', error);
      console.log('🔍 ===== END CONNECTION TEST ERROR DEBUG =====');
      
      logger.error(`Connection test failed for broker connection ${brokerConnectionId}:`, error);
      throw error;
    }
  }

  // Sync positions to database
  async syncPositions(brokerConnectionId) {
    try {
      const positions = await this.getPositions(brokerConnectionId);
      
      if (positions && positions.net) {
        for (const position of positions.net) {
          if (position.quantity !== 0) {
            await db.runAsync(`
              INSERT OR REPLACE INTO positions 
              (user_id, broker_connection_id, symbol, exchange, quantity, average_price, current_price, pnl, pnl_percentage, product, updated_at)
              SELECT user_id, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
              FROM broker_connections WHERE id = ?
            `, [
              brokerConnectionId,
              position.tradingsymbol,
              position.exchange,
              position.quantity,
              position.average_price,
              position.last_price,
              position.pnl,
              position.pnl ? (position.pnl / (position.average_price * Math.abs(position.quantity))) * 100 : 0,
              position.product,
              brokerConnectionId
            ]);
          }
        }
      }
      
      return positions;
    } catch (error) {
      console.error('❌ Failed to sync positions:', error);
      throw error;
    }
  }

  // Clear cached instance (useful when token is refreshed)
  clearCachedInstance(brokerConnectionId) {
    if (this.kiteInstances.has(brokerConnectionId)) {
      this.kiteInstances.delete(brokerConnectionId);
      console.log('🗑️ Cleared cached KiteConnect instance for connection:', brokerConnectionId);
    }
  }
}

export default new KiteService();
