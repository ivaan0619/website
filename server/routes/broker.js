import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { db } from '../database/init.js';
import { authenticateToken } from '../middleware/auth.js';
import { encryptData, decryptData, testEncryption } from '../utils/encryption.js';
import kiteService from '../services/kiteService.js';
import upstoxService from '../services/upstoxService.js';
import createLogger from '../utils/logger.js';

const logger = createLogger('BrokerHandler');

const router = express.Router();

// Test encryption on startup
testEncryption();

// Get broker connections with enhanced data
router.get('/connections', authenticateToken, async (req, res) => {
  try {
    const connections = await db.allAsync(`
      SELECT 
        id, broker_name, connection_name, is_active, created_at, last_sync, webhook_url,
        access_token_expires_at,
        CASE WHEN access_token IS NOT NULL AND access_token != '' THEN 1 ELSE 0 END as is_authenticated
      FROM broker_connections 
      WHERE user_id = ?
      ORDER BY created_at DESC
    `, [req.user.id]);

    // Check if access tokens are expired and mark them
    const now = Math.floor(Date.now() / 1000);
    const enhancedConnections = connections.map(conn => ({
      ...conn,
      token_expired: conn.access_token_expires_at && conn.access_token_expires_at < now,
      needs_token_refresh: conn.access_token_expires_at && (conn.access_token_expires_at - now) < 3600 // Less than 1 hour
    }));

    res.json({ connections: enhancedConnections });
  } catch (error) {
    console.error('Get connections error:', error);
    res.status(500).json({ error: 'Failed to fetch connections' });
  }
});

// Get specific broker connection details
router.get('/connections/:id', authenticateToken, async (req, res) => {
  try {
    const connection = await db.getAsync(`
      SELECT 
        id, broker_name, connection_name, is_active, created_at, last_sync, webhook_url,
        user_id_broker, access_token_expires_at,
        CASE WHEN access_token IS NOT NULL AND access_token != '' THEN 1 ELSE 0 END as is_authenticated
      FROM broker_connections 
      WHERE id = ? AND user_id = ?
    `, [req.params.id, req.user.id]);

    if (!connection) {
      return res.status(404).json({ error: 'Broker connection not found' });
    }

    const now = Math.floor(Date.now() / 1000);
    connection.token_expired = connection.access_token_expires_at && connection.access_token_expires_at < now;
    connection.needs_token_refresh = connection.access_token_expires_at && (connection.access_token_expires_at - now) < 3600;

    res.json({ connection });
  } catch (error) {
    console.error('Get connection details error:', error);
    res.status(500).json({ error: 'Failed to fetch connection details' });
  }
});

// NEW: Get real-time positions from broker
router.get('/positions/:connectionId', authenticateToken, async (req, res) => {
  try {
    const { connectionId } = req.params;
    
    logger.info(`Fetching real-time positions for connection ${connectionId}`);

    // Verify connection belongs to user and is active
    const connection = await db.getAsync(
      'SELECT * FROM broker_connections WHERE id = ? AND user_id = ? AND is_active = 1',
      [connectionId, req.user.id]
    );

    if (!connection) {
      return res.status(404).json({ error: 'Broker connection not found or inactive' });
    }

    if (!connection.access_token) {
      return res.status(400).json({ 
        error: 'No access token found. Please authenticate first.',
        needsAuth: true 
      });
    }

    // Check if token is expired
    const now = Math.floor(Date.now() / 1000);
    if (connection.access_token_expires_at && connection.access_token_expires_at < now) {
      return res.status(400).json({ 
        error: 'Access token has expired. Please reconnect your account.',
        tokenExpired: true 
      });
    }

    let positions = [];
    
    try {
      if (connection.broker_name.toLowerCase() === 'zerodha') {
        const positionsData = await kiteService.getPositions(connectionId);
        
        // Format positions data
        if (positionsData && positionsData.net) {
          positions = positionsData.net
            .filter(pos => Math.abs(pos.quantity) > 0) // Only non-zero positions
            .map(pos => ({
              tradingsymbol: pos.tradingsymbol,
              exchange: pos.exchange,
              instrument_token: pos.instrument_token,
              product: pos.product,
              quantity: pos.quantity,
              overnight_quantity: pos.overnight_quantity,
              multiplier: pos.multiplier,
              average_price: pos.average_price,
              close_price: pos.close_price,
              last_price: pos.last_price,
              value: pos.value,
              pnl: pos.pnl,
              m2m: pos.m2m,
              unrealised: pos.unrealised,
              realised: pos.realised,
              buy_quantity: pos.buy_quantity,
              buy_price: pos.buy_price,
              buy_value: pos.buy_value,
              sell_quantity: pos.sell_quantity,
              sell_price: pos.sell_price,
              sell_value: pos.sell_value,
              day_buy_quantity: pos.day_buy_quantity,
              day_buy_price: pos.day_buy_price,
              day_buy_value: pos.day_buy_value,
              day_sell_quantity: pos.day_sell_quantity,
              day_sell_price: pos.day_sell_price,
              day_sell_value: pos.day_sell_value
            }));
        }
      } else if (connection.broker_name.toLowerCase() === 'upstox') {
        const positionsData = await upstoxService.getPositions(connectionId);
        
        // Format Upstox positions data
        if (positionsData && Array.isArray(positionsData)) {
          positions = positionsData
            .filter(pos => Math.abs(pos.quantity || 0) > 0) // Only non-zero positions
            .map(pos => ({
              tradingsymbol: pos.instrument_token, // Upstox uses instrument_token
              exchange: pos.exchange,
              instrument_token: pos.instrument_token,
              product: pos.product,
              quantity: pos.quantity || 0,
              average_price: pos.average_price || 0,
              last_price: pos.last_price || 0,
              pnl: pos.unrealised_pnl || 0,
              unrealised: pos.unrealised_pnl || 0,
              realised: pos.realised_pnl || 0,
              value: (pos.quantity || 0) * (pos.last_price || 0)
            }));
        }
      } else {
        // For other brokers, implement their specific position fetching
        logger.warn(`Real-time positions not implemented for ${connection.broker_name}`);
        return res.status(400).json({ 
          error: `Real-time positions not supported for ${connection.broker_name}` 
        });
      }

      logger.info(`Retrieved ${positions.length} positions for connection ${connectionId}`);
      
      res.json({
        positions,
        broker_name: connection.broker_name,
        last_updated: new Date().toISOString(),
        connection_id: connectionId
      });

    } catch (brokerError) {
      logger.error('Failed to fetch positions from broker:', brokerError);
      
      if (brokerError.message && brokerError.message.includes('api_key') || brokerError.message.includes('access_token')) {
        return res.status(401).json({ 
          error: 'Invalid or expired credentials. Please reconnect your account.',
          tokenExpired: true,
          details: brokerError.message
        });
      }
      
      return res.status(500).json({ 
        error: 'Failed to fetch positions from broker',
        details: brokerError.message
      });
    }

  } catch (error) {
    logger.error('Get positions error:', error);
    res.status(500).json({ error: 'Failed to fetch positions' });
  }
});

// NEW: Get real-time holdings from broker
router.get('/holdings/:connectionId', authenticateToken, async (req, res) => {
  try {
    const { connectionId } = req.params;
    
    logger.info(`Fetching real-time holdings for connection ${connectionId}`);

    // Verify connection belongs to user and is active
    const connection = await db.getAsync(
      'SELECT * FROM broker_connections WHERE id = ? AND user_id = ? AND is_active = 1',
      [connectionId, req.user.id]
    );

    if (!connection) {
      return res.status(404).json({ error: 'Broker connection not found or inactive' });
    }

    if (!connection.access_token) {
      return res.status(400).json({ 
        error: 'No access token found. Please authenticate first.',
        needsAuth: true 
      });
    }

    // Check if token is expired
    const now = Math.floor(Date.now() / 1000);
    if (connection.access_token_expires_at && connection.access_token_expires_at < now) {
      return res.status(400).json({ 
        error: 'Access token has expired. Please reconnect your account.',
        tokenExpired: true 
      });
    }

    let holdings = [];
    
    try {
      if (connection.broker_name.toLowerCase() === 'zerodha') {
        const holdingsData = await kiteService.getHoldings(connectionId);
        
        // Format holdings data
        if (holdingsData && Array.isArray(holdingsData)) {
          holdings = holdingsData
            .filter(holding => holding.quantity > 0) // Only positive holdings
            .map(holding => ({
              tradingsymbol: holding.tradingsymbol,
              exchange: holding.exchange,
              instrument_token: holding.instrument_token,
              isin: holding.isin,
              product: holding.product,
              price: holding.price,
              quantity: holding.quantity,
              used_quantity: holding.used_quantity,
              t1_quantity: holding.t1_quantity,
              realised_quantity: holding.realised_quantity,
              authorised_quantity: holding.authorised_quantity,
              authorised_date: holding.authorised_date,
              opening_quantity: holding.opening_quantity,
              collateral_quantity: holding.collateral_quantity,
              collateral_type: holding.collateral_type,
              discrepancy: holding.discrepancy,
              average_price: holding.average_price,
              last_price: holding.last_price,
              close_price: holding.close_price,
              pnl: holding.pnl,
              day_change: holding.day_change,
              day_change_percentage: holding.day_change_percentage
            }));
        }
      } else if (connection.broker_name.toLowerCase() === 'upstox') {
        const holdingsData = await upstoxService.getHoldings(connectionId);
        
        // Format Upstox holdings data
        if (holdingsData && Array.isArray(holdingsData)) {
          holdings = holdingsData
            .filter(holding => (holding.quantity || 0) > 0) // Only positive holdings
            .map(holding => ({
              tradingsymbol: holding.instrument_token, // Upstox uses instrument_token
              exchange: holding.exchange,
              instrument_token: holding.instrument_token,
              quantity: holding.quantity || 0,
              average_price: holding.average_price || 0,
              last_price: holding.last_price || 0,
              pnl: holding.pnl || 0,
              day_change: holding.day_change || 0,
              day_change_percentage: holding.day_change_percentage || 0,
              used_quantity: holding.used_quantity || 0,
              collateral_quantity: holding.collateral_quantity || 0
            }));
        }
      } else {
        // For other brokers, implement their specific holdings fetching
        logger.warn(`Real-time holdings not implemented for ${connection.broker_name}`);
        return res.status(400).json({ 
          error: `Real-time holdings not supported for ${connection.broker_name}` 
        });
      }

      logger.info(`Retrieved ${holdings.length} holdings for connection ${connectionId}`);
      
      res.json({
        holdings,
        broker_name: connection.broker_name,
        last_updated: new Date().toISOString(),
        connection_id: connectionId
      });

    } catch (brokerError) {
      logger.error('Failed to fetch holdings from broker:', brokerError);
      
      if (brokerError.message && brokerError.message.includes('api_key') || brokerError.message.includes('access_token')) {
        return res.status(401).json({ 
          error: 'Invalid or expired credentials. Please reconnect your account.',
          tokenExpired: true,
          details: brokerError.message
        });
      }
      
      return res.status(500).json({ 
        error: 'Failed to fetch holdings from broker',
        details: brokerError.message
      });
    }

  } catch (error) {
    logger.error('Get holdings error:', error);
    res.status(500).json({ error: 'Failed to fetch holdings' });
  }
});

// Connect broker - Step 1: Store credentials and generate login URL
router.post('/connect', authenticateToken, async (req, res) => {
  try {
    const { brokerName, apiKey, apiSecret, userId, connectionName, password, twoFA, vendor, appKey, imei } = req.body;

    console.log('📡 Broker connection request:', { brokerName, userId, connectionName, hasApiKey: !!apiKey, hasApiSecret: !!apiSecret });

    if (!brokerName || !apiKey || !apiSecret) {
      return res.status(400).json({ error: 'Broker name, API key, and API secret are required' });
    }

    // Additional validation for Shoonya
    if (brokerName.toLowerCase() === 'shoonya') {
      if (!password || !twoFA || !vendor || !appKey || !imei) {
        return res.status(400).json({ 
          error: 'For Shoonya, password, 2FA/PIN, vendor code, app key, and IMEI are required' 
        });
      }
    }
    // Check connection limit (max 5 per user)
    const existingConnections = await db.allAsync(
      'SELECT COUNT(*) as count FROM broker_connections WHERE user_id = ? AND is_active = 1',
      [req.user.id]
    );

    if (existingConnections[0].count >= 5) {
      return res.status(400).json({ error: 'Maximum 5 broker connections allowed per user' });
    }

    // Generate unique webhook URL for this connection
    const webhookId = uuidv4();
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const webhookUrl = `${baseUrl}/api/webhook/${req.user.id}/${webhookId}`;

    console.log('🔗 Generated webhook URL:', webhookUrl);

    // Generate connection name if not provided
    const finalConnectionName = connectionName || `${brokerName} Connection ${Date.now()}`;

    let connectionId;
    
    try {
      // Test encryption before storing
      const testEncrypted = encryptData('test');
      const testDecrypted = decryptData(testEncrypted);
      if (testDecrypted !== 'test') {
        throw new Error('Encryption test failed');
      }

      const encryptedApiKey = encryptData(apiKey);
      const encryptedApiSecret = encryptData(apiSecret);
      
      // Encrypt additional Shoonya fields if provided
      const encryptedPassword = password ? encryptData(password) : null;
      const encryptedTwoFA = twoFA ? encryptData(twoFA) : null;
      const encryptedAppKey = appKey ? encryptData(appKey) : null;

      // Create new connection
      const result = await db.runAsync(`
        INSERT INTO broker_connections 
        (user_id, broker_name, connection_name, api_key, api_secret, user_id_broker, password, two_fa, vendor, app_key, imei, webhook_url) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        req.user.id, 
        brokerName.toLowerCase(), 
        finalConnectionName, 
        encryptedApiKey, 
        encryptedApiSecret, 
        userId, 
        encryptedPassword,
        encryptedTwoFA,
        vendor,
        encryptedAppKey,
        imei,
        webhookUrl
      ]);
      
      connectionId = result.lastID;
      console.log('✅ Created new broker connection:', connectionId);
    } catch (encryptionError) {
      console.error('❌ Encryption error:', encryptionError);
      return res.status(500).json({ error: 'Failed to encrypt credentials. Please try again.' });
    }

    // For Zerodha, generate login URL with proper redirect URL
    if (brokerName.toLowerCase() === 'zerodha') {
      try {
        const redirectUrl = `${baseUrl}/api/broker/auth/zerodha/callback?connection_id=${connectionId}`;
        
        // Generate Zerodha login URL
        const loginUrl = `https://kite.zerodha.com/connect/login?api_key=${apiKey}&v=3&redirect_url=${encodeURIComponent(redirectUrl)}`;
        
        console.log('🔐 Generated Zerodha login URL for connection:', connectionId);
        
        res.json({ 
          message: 'Broker credentials stored. Please complete authentication.',
          connectionId,
          loginUrl,
          webhookUrl,
          requiresAuth: true,
          redirectUrl,
          connectionName: finalConnectionName
        });
      } catch (error) {
        console.error('❌ Failed to generate login URL:', error);
        res.status(400).json({ error: 'Invalid API key or failed to generate login URL' });
      }
    } else if (brokerName.toLowerCase() === 'upstox') {
      try {
        const redirectUrl = `${baseUrl}/api/broker/auth/upstox/callback?connection_id=${connectionId}`;
        
        // Generate Upstox login URL with state parameter (OAuth 2.0 standard)
        const state = Buffer.from(JSON.stringify({ 
          connection_id: connectionId, 
          timestamp: Date.now(),
          nonce: crypto.randomUUID() // prevent replay attacks
        })).toString('base64');
        
        // Clean redirect URL without connection_id parameter
        const cleanRedirectUrl = `${baseUrl}/api/broker/auth/upstox/callback`;
        const loginUrl = `https://api.upstox.com/v2/login/authorization/dialog?response_type=code&client_id=${apiKey}&redirect_uri=${encodeURIComponent(cleanRedirectUrl)}&state=${state}`;
        
        console.log('🔐 Generated Upstox login URL for connection:', connectionId);
        
        res.json({ 
          message: 'Broker credentials stored. Please complete authentication.',
          connectionId,
          loginUrl,
          webhookUrl,
          requiresAuth: true,
          redirectUrl: cleanRedirectUrl,
          connectionName: finalConnectionName
        });
      } catch (error) {
        console.error('❌ Failed to generate Upstox login URL:', error);
        res.status(400).json({ error: 'Invalid API key or failed to generate login URL' });
      }
    } else if (brokerName.toLowerCase() === 'shoonya') {
      try {
        // For Shoonya, we can directly authenticate using the provided credentials
        console.log('🔐 Attempting Shoonya authentication for connection:', connectionId);
        
        const sessionResponse = await shoonyaService.generateSessionToken(
          apiKey, 
          apiSecret, 
          userId, 
          password, 
          twoFA, 
          vendor, 
          appKey, 
          imei
        );
        
        // Store the session token
        const expiresAt = Math.floor(Date.now() / 1000) + (24 * 60 * 60); // 24 hours
        
        await db.runAsync(`
          UPDATE broker_connections 
          SET access_token = ?, access_token_expires_at = ?, is_active = 1, is_authenticated = 1, updated_at = CURRENT_TIMESTAMP 
          WHERE id = ?
        `, [encryptData(sessionResponse.access_token), expiresAt, connectionId]);
        
        console.log('✅ Shoonya authentication completed for connection:', connectionId);
        
        res.json({ 
          message: 'Shoonya broker connected successfully!',
          connectionId,
          webhookUrl,
          requiresAuth: false,
          connectionName: finalConnectionName,
          profile: sessionResponse
        });
      } catch (error) {
        console.error('❌ Shoonya authentication failed:', error);
        res.status(400).json({ error: `Shoonya authentication failed: ${error.message}` });
      }
    } else {
      // For other brokers, mark as connected (mock implementation)
      console.log('✅ Connected to broker:', brokerName);
      res.json({ 
        message: 'Broker connected successfully',
        connectionId,
        webhookUrl,
        requiresAuth: false,
        connectionName: finalConnectionName
      });
    }
  } catch (error) {
    console.error('❌ Connect broker error:', error);
    res.status(500).json({ error: 'Failed to connect broker. Please check your credentials and try again.' });
  }
});

// NEW: Reconnect using stored credentials - generates new access token directly
router.post('/reconnect/:connectionId', authenticateToken, async (req, res) => {
  try {
    const { connectionId } = req.params;
    console.log('--- Step 1: Incoming Request ---');
    console.log('Input - connectionId:', connectionId);
    console.log('Input - req.user.id (from authenticateToken):', req.user ? req.user.id : 'N/A');

    logger.info('🔄 Reconnecting using stored credentials for connection:', connectionId);

    // Get connection details with encrypted credentials
    console.log('--- Step 2: Fetching Connection Details from DB ---');
    console.log('DB Query: SELECT * FROM broker_connections WHERE id = ? AND user_id = ?');
    console.log('DB Parameters:', [connectionId, req.user.id]);
    const connection = await db.getAsync(
      'SELECT * FROM broker_connections WHERE id = ? AND user_id = ? ',
      [connectionId, req.user.id]
    );
    console.log('Output - connection from DB:', connection);

    if (!connection) {
      console.log('--- Step 3: Connection Not Found/Inactive ---');
      console.log('Output - Response: 404 Not Found, error: Broker connection not found or inactive');
      return res.status(404).json({ error: 'Broker connection not found or inactive' });
    }

    // Check if we have the required credentials
    console.log('--- Step 4: Checking for API Credentials ---');
    console.log('Input - connection.api_key:', connection.api_key ? 'Present' : 'Missing');
    console.log('Input - connection.api_secret:', connection.api_secret ? 'Present' : 'Missing');
    if (!connection.api_key || !connection.api_secret) {
      console.log('Output - Response: 400 Bad Request, error: Missing API credentials');
      return res.status(400).json({
        error: 'Missing API credentials. Please update your connection settings.',
        needsCredentials: true
      });
    }

    try {
      // Decrypt stored credentials
      console.log('--- Step 5: Decrypting Credentials ---');
      console.log('Input - connection.api_key (encrypted):', connection.api_key);
      console.log('Input - connection.api_secret (encrypted):', connection.api_secret);
      const apiKey = decryptData(connection.api_key);
      const apiSecret = decryptData(connection.api_secret);
      console.log('Output - apiKey (decrypted):', apiKey ? 'Decrypted Successfully' : 'Decryption Failed');
      console.log('Output - apiSecret (decrypted):', apiSecret ? 'Decrypted Successfully' : 'Decryption Failed');

      logger.info('🔐 Using stored credentials to reconnect');

      console.log('--- Step 6: Checking Broker Type ---');
      console.log('Input - connection.broker_name:', connection.broker_name);
      if (connection.broker_name.toLowerCase() === 'zerodha') {
        // For Zerodha, we need user to login again to get new request token
        // This is because Zerodha's access tokens are session-based
        console.log('--- Step 6a: Handling Zerodha Reconnection ---');
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        console.log('Calculated baseUrl:', baseUrl);
        const redirectUrl = `${baseUrl}/api/broker/auth/zerodha/callback?connection_id=${connectionId}&reconnect=true`;
        console.log('Calculated redirectUrl:', redirectUrl);
        const loginUrl = `https://kite.zerodha.com/connect/login?api_key=${apiKey}&v=3&redirect_url=${encodeURIComponent(redirectUrl)}`;
        console.log('Generated Zerodha loginUrl:', loginUrl);

        logger.info('🔐 Generated reconnection login URL for Zerodha connection:', connectionId);

        console.log('Output - Response: 200 OK, message: Please complete authentication..., loginUrl:', loginUrl);
        res.json({
          message: 'Please complete authentication to reconnect your Zerodha account.',
          loginUrl,
          requiresAuth: true,
          reconnect: true,
          brokerName: 'Zerodha'
        });
      } else if (connection.broker_name.toLowerCase() === 'upstox') {
        // For Upstox, similar OAuth flow
        console.log('--- Step 6b: Handling Upstox Reconnection ---');
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        console.log('Calculated baseUrl:', baseUrl);
        const redirectUrl = `${baseUrl}/api/broker/auth/upstox/callback`;
        // Generate Upstox login URL with state parameter for reconnection
        const state = Buffer.from(JSON.stringify({ 
          connection_id: connectionId, 
          timestamp: Date.now(),
          nonce: crypto.randomUUID(),
          reconnect: true
        })).toString('base64');
        
        // Add connection_id as fallback in case state parsing fails
        const loginUrl = `https://api.upstox.com/v2/login/authorization/dialog?response_type=code&client_id=${apiKey}&redirect_uri=${encodeURIComponent(redirectUrl)}&state=${state}&connection_id=${connectionId}`;
        console.log('Generated Upstox loginUrl:', loginUrl);

        logger.info('🔐 Generated reconnection login URL for Upstox connection:', connectionId);

        res.json({
          message: 'Please complete authentication to reconnect your Upstox account.',
          loginUrl,
          requiresAuth: true,
          reconnect: true,
          brokerName: 'Upstox'
        });
      } else {
        // For other brokers, implement direct token refresh if supported
        // This is where you'd implement direct API calls for other brokers
        console.log('--- Step 6c: Handling Other Brokers (Not Supported Yet) ---');
        console.log('Output - Response: 400 Bad Request, error: Direct reconnection not supported');
        return res.status(400).json({
          error: 'Direct reconnection not supported for this broker. Please update your connection.',
          brokerName: connection.broker_name
        });
      }

    } catch (decryptError) {
      console.log('--- Step 7: Decryption Error ---');
      console.log('Input - decryptError:', decryptError.message);
      logger.error('❌ Failed to decrypt stored credentials:', decryptError);
      console.log('Output - Response: 500 Internal Server Error, error: Failed to decrypt stored credentials');
      return res.status(500).json({
        error: 'Failed to decrypt stored credentials. Please update your connection settings.',
        needsCredentials: true
      });
    }

  } catch (error) {
    console.log('--- Step 8: General Reconnect Error ---');
    console.log('Input - error:', error.message);
    logger.error('❌ Reconnect error:', error);
    console.log('Output - Response: 500 Internal Server Error, error: Failed to reconnect');
    res.status(500).json({ error: 'Failed to reconnect. Please try again.' });
  }
});

// DEPRECATED: Old refresh token method (keeping for backward compatibility)
router.post('/refresh-token/:connectionId', authenticateToken, async (req, res) => {
  try {
    const { connectionId } = req.params;
    
    logger.info('🔄 [DEPRECATED] Refresh token called, redirecting to reconnect');
    
    // Call the reconnect endpoint directly
    const connection = await db.getAsync(
      'SELECT * FROM broker_connections WHERE id = ? AND user_id = ? AND is_active = 1',
      [connectionId, req.user.id]
    );

    if (!connection) {
      return res.status(404).json({ error: 'Broker connection not found or inactive' });
    }

    if (!connection.api_key || !connection.api_secret) {
      return res.status(400).json({ 
        error: 'Missing API credentials. Please update your connection settings.',
        needsCredentials: true 
      });
    }

    try {
      const apiKey = decryptData(connection.api_key);
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const redirectUrl = `${baseUrl}/api/broker/auth/zerodha/callback?connection_id=${connectionId}&reconnect=true`;
      const loginUrl = `https://kite.zerodha.com/connect/login?api_key=${apiKey}&v=3&redirect_url=${encodeURIComponent(redirectUrl)}`;
      
      res.json({ 
        message: 'Please complete authentication to refresh your access token.',
        loginUrl,
        requiresAuth: true,
        reconnect: true
      });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to generate refresh URL' });
    }
    
  } catch (error) {
    logger.error('❌ Refresh token error:', error);
    res.status(500).json({ error: 'Failed to refresh access token' });
  }
});

// Zerodha OAuth callback handler - This is the redirect URL endpoint
router.get('/auth/zerodha/callback', async (req, res) => {
  try {
    const { request_token, action, status, connection_id, reconnect } = req.query;

    console.log('📡 Zerodha callback received:', { request_token, action, status, connection_id, reconnect });

    // Check if authentication was successful
    if (action !== 'login' || status !== 'success' || !request_token) {
      return res.status(400).send(`
        <html>
          <head><title>Authentication Failed</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">❌ Authentication Failed</h1>
            <p>Zerodha authentication was not successful.</p>
            <p>Error: ${status || 'Unknown error'}</p>
            <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
          </body>
        </html>
      `);
    }

    if (!connection_id) {
      return res.status(400).send(`
        <html>
          <head><title>Missing Connection ID</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">❌ Missing Connection ID</h1>
            <p>Connection ID is required for authentication.</p>
            <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
          </body>
        </html>
      `);
    }

    // Get broker connection
    const connection = await db.getAsync(
      'SELECT * FROM broker_connections WHERE id = ?',
      [connection_id]
    );

    if (!connection) {
      return res.status(404).send(`
        <html>
          <head><title>Connection Not Found</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">❌ Connection Not Found</h1>
            <p>Broker connection not found.</p>
            <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
          </body>
        </html>
      `);
    }

    try {
      // Decrypt credentials
      const apiKey = decryptData(connection.api_key);
      const apiSecret = decryptData(connection.api_secret);
      
      console.log('🔐 Generating access token for connection:', connection_id);
      
      // Generate access token using KiteConnect
      const accessTokenResponse = await kiteService.generateAccessToken(apiKey, apiSecret, request_token);
      
      if (!accessTokenResponse || !accessTokenResponse.access_token) {
        throw new Error('Failed to generate access token');
      }

      const accessToken = accessTokenResponse.access_token;
      const publicToken = accessTokenResponse.public_token || '';
      
      // Set token expiry (Zerodha tokens expire at 6 AM IST next day)
      const now = new Date();
      const tomorrow = new Date(now);
      tomorrow.setDate(tomorrow.getDate() + 1);
      tomorrow.setHours(6, 0, 0, 0); // 6 AM IST
      const expiresAt = Math.floor(tomorrow.getTime() / 1000);

      // Store access token and public token
      await db.runAsync(`
        UPDATE broker_connections 
        SET access_token = ?, public_token = ?, access_token_expires_at = ?, is_active = 1, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
      `, [encryptData(accessToken), encryptData(publicToken), expiresAt, connection_id]);

      // Clear any cached KiteConnect instances to force refresh
      kiteService.clearCachedInstance(connection_id);

      console.log('✅ Zerodha authentication completed for connection:', connection_id);

      const actionText = reconnect === 'true' ? 'Reconnection Successful' : 'Authentication Successful';

      // Return success page
      res.send(`
        <html>
          <head>
            <title>${actionText}</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f8f9fa; }
              .success-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 500px; margin: 0 auto; }
              .success-icon { font-size: 48px; margin-bottom: 20px; }
              .success-title { color: #28a745; margin-bottom: 15px; }
              .success-message { color: #6c757d; margin-bottom: 30px; line-height: 1.6; }
              .close-btn { padding: 12px 24px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
              .close-btn:hover { background: #218838; }
            </style>
          </head>
          <body>
            <div class="success-container">
              <div class="success-icon">✅</div>
              <h1 class="success-title">${actionText}!</h1>
              <p class="success-message">
                Your Zerodha account has been successfully ${reconnect === 'true' ? 'reconnected' : 'connected'} to AutoTraderHub.<br>
                New access token expires: ${new Date(expiresAt * 1000).toLocaleString()}<br>
                You can now close this window and return to the dashboard.
              </p>
              <button class="close-btn" onclick="window.close()">Close Window</button>
            </div>
            <script>
              // Auto-close after 5 seconds
              setTimeout(() => {
                window.close();
              }, 5000);
            </script>
          </body>
        </html>
      `);

    } catch (authError) {
      console.error('❌ Authentication error:', authError);
      res.status(500).send(`
        <html>
          <head><title>Authentication Error</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">❌ Authentication Error</h1>
            <p>Failed to complete authentication: ${authError.message}</p>
            <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
          </body>
        </html>
      `);
    }

  } catch (error) {
    console.error('❌ Callback handler error:', error);
    res.status(500).send(`
      <html>
        <head><title>Server Error</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
          <h1 style="color: #dc3545;">❌ Server Error</h1>
          <p>An unexpected error occurred: ${error.message}</p>
          <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
        </body>
        </html>
    `);
  }
});

// Upstox OAuth callback handler
router.get('/auth/upstox/callback', async (req, res) => {
  try {
    const { code, state } = req.query;

    console.log('📡 Upstox callback received:', { code: !!code, state: !!state });

    // Check if authentication was successful
    if (!code) {
      return res.status(400).send(`
        <html>
          <head><title>Authentication Failed</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">❌ Authentication Failed</h1>
            <p>Upstox authentication was not successful.</p>
            <p>Error: No authorization code received</p>
            <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
          </body>
        </html>
      `);
    }

    // Parse state parameter with better error handling
    let connection_id, reconnect = false;
    
    if (state) {
      try {
        const stateData = JSON.parse(Buffer.from(state, 'base64').toString('utf8'));
        connection_id = stateData.connection_id;
        reconnect = stateData.reconnect || false;
        
        console.log('📋 Parsed state data:', { 
          connection_id, 
          reconnect,
          hasTimestamp: !!stateData.timestamp,
          hasNonce: !!stateData.nonce
        });
        
        // Validate timestamp if present (prevent replay attacks - 30 minute window)
        if (stateData.timestamp) {
          const now = Date.now();
          const maxAge = 30 * 60 * 1000; // 30 minutes
          if (now - stateData.timestamp > maxAge) {
            console.warn('⚠️ State parameter expired, but continuing with authentication');
          }
        }
      } catch (error) {
        console.error('❌ Failed to parse state parameter:', error);
        // Continue without state data - we'll try to find the connection another way
        console.log('⚠️ Continuing authentication without state data');
      }
    }
    
    // If we don't have connection_id from state, try to find it from the callback URL
    if (!connection_id) {
      const urlConnectionId = req.query.connection_id;
      if (urlConnectionId) {
        connection_id = urlConnectionId;
        console.log('📋 Using connection_id from URL parameter:', connection_id);
      }
    }
    
    // If we still don't have connection_id, return error
    if (!connection_id) {
      return res.status(400).send(`
        <html>
          <head><title>Missing Connection ID</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">❌ Missing Connection ID</h1>
            <p>Unable to identify the broker connection. Please try connecting again.</p>
            <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
          </body>
        </html>
      `);
    }

    // Get broker connection
    const connection = await db.getAsync(
      'SELECT * FROM broker_connections WHERE id = ?',
      [connection_id]
    );

    if (!connection) {
      return res.status(404).send(`
        <html>
          <head><title>Connection Not Found</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">❌ Connection Not Found</h1>
            <p>Broker connection not found.</p>
            <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
          </body>
        </html>
      `);
    }

    try {
      // Decrypt credentials
      const apiKey = decryptData(connection.api_key);
      const apiSecret = decryptData(connection.api_secret);
      const redirectUrl = `${req.protocol}://${req.get('host')}/api/broker/auth/upstox/callback`;
      
      console.log('🔐 Generating access token for Upstox connection:', connection_id);
      
      // Generate access token using Upstox API
      const accessTokenResponse = await upstoxService.generateAccessToken(apiKey, apiSecret, code, redirectUrl);
      
      if (!accessTokenResponse || !accessTokenResponse.access_token) {
        throw new Error('Failed to generate access token');
      }

      const accessToken = accessTokenResponse.access_token;
      
      // Set token expiry (Upstox tokens typically expire in 24 hours)
      const now = new Date();
      const tomorrow = new Date(now);
      tomorrow.setDate(tomorrow.getDate() + 1);
      const expiresAt = Math.floor(tomorrow.getTime() / 1000);

      // Store access token
      await db.runAsync(`
        UPDATE broker_connections 
        SET access_token = ?, access_token_expires_at = ?, is_active = 1, is_authenticated = 1, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
      `, [encryptData(accessToken), expiresAt, connection_id]);

      // Clear any cached Upstox instances to force refresh
      upstoxService.clearCachedInstance(connection_id);

      console.log('✅ Upstox authentication completed for connection:', connection_id);

      const actionText = reconnect === 'true' ? 'Reconnection Successful' : 'Authentication Successful';

      // Return success page
      res.send(`
        <html>
          <head>
            <title>${actionText}</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f8f9fa; }
              .success-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 500px; margin: 0 auto; }
              .success-icon { font-size: 48px; margin-bottom: 20px; }
              .success-title { color: #28a745; margin-bottom: 15px; }
              .success-message { color: #6c757d; margin-bottom: 30px; line-height: 1.6; }
              .close-btn { padding: 12px 24px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
              .close-btn:hover { background: #218838; }
            </style>
          </head>
          <body>
            <div class="success-container">
              <div class="success-icon">✅</div>
              <h1 class="success-title">${actionText}!</h1>
              <p class="success-message">
                Your Upstox account has been successfully ${reconnect === 'true' ? 'reconnected' : 'connected'} to AutoTraderHub.<br>
                Access token expires: ${new Date(expiresAt * 1000).toLocaleString()}<br>
                You can now close this window and return to the dashboard.
              </p>
              <button class="close-btn" onclick="window.close()">Close Window</button>
            </div>
            <script>
              // Auto-close after 5 seconds
              setTimeout(() => {
                window.close();
              }, 5000);
            </script>
          </body>
        </html>
      `);

    } catch (authError) {
      console.error('❌ Upstox authentication error:', authError);
      res.status(500).send(`
        <html>
          <head><title>Authentication Error</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">❌ Authentication Error</h1>
            <p>Failed to complete authentication: ${authError.message}</p>
            <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
          </body>
        </html>
      `);
    }

  } catch (error) {
    console.error('❌ Upstox callback handler error:', error);
    res.status(500).send(`
      <html>
        <head><title>Server Error</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
          <h1 style="color: #dc3545;">❌ Server Error</h1>
          <p>An unexpected error occurred: ${error.message}</p>
          <button onclick="window.close()" style="padding: 10px 20px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">Close Window</button>
        </body>
        </html>
    `);
  }
});

// Disconnect broker
router.post('/disconnect', authenticateToken, async (req, res) => {
  try {
    const { connectionId } = req.body;

    await db.runAsync(
      'UPDATE broker_connections SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
      [connectionId, req.user.id]
    );

    res.json({ message: 'Broker disconnected successfully' });
  } catch (error) {
    console.error('Disconnect broker error:', error);
    res.status(500).json({ error: 'Failed to disconnect broker' });
  }
});

// Delete broker connection
router.delete('/connections/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await db.runAsync(
      'DELETE FROM broker_connections WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Broker connection not found' });
    }

    res.json({ message: 'Broker connection deleted successfully' });
  } catch (error) {
    console.error('Delete broker connection error:', error);
    res.status(500).json({ error: 'Failed to delete broker connection' });
  }
});

// Mock sync positions
router.post('/sync/positions/:connectionId', authenticateToken, async (req, res) => {
  try {
    const { connectionId } = req.params;

    // Verify connection belongs to user
    const connection = await db.getAsync(
      'SELECT id FROM broker_connections WHERE id = ? AND user_id = ? AND is_active = 1',
      [connectionId, req.user.id]
    );

    if (!connection) {
      return res.status(404).json({ error: 'Broker connection not found' });
    }

    // Try to sync positions using KiteService
    try {
      const positions = await kiteService.getPositions(connectionId);
      res.json({ 
        message: 'Positions synced successfully',
        positions: positions || []
      });
    } catch (syncError) {
      console.error('Failed to sync positions from broker:', syncError);
      // Return mock data if sync fails
      const mockPositions = [
        {
          symbol: 'RELIANCE',
          quantity: 50,
          averagePrice: 2450,
          currentPrice: 2475,
          pnl: 1250,
          pnlPercentage: 1.02
        },
        {
          symbol: 'TCS',
          quantity: -25,
          averagePrice: 3200,
          currentPrice: 3180,
          pnl: 500,
          pnlPercentage: 0.63
        }
      ];

      res.json({ 
        message: 'Positions synced successfully (mock data)',
        positions: mockPositions
      });
    }
  } catch (error) {
    console.error('Sync positions error:', error);
    res.status(500).json({ error: 'Failed to sync positions' });
  }
});

// Enhanced test connection with proper error handling
router.post('/test/:connectionId', authenticateToken, async (req, res) => {
  try {
    const { connectionId } = req.params;

    console.log('🧪 Testing connection for ID:', connectionId);

    // Verify connection belongs to user
    const connection = await db.getAsync(
      'SELECT * FROM broker_connections WHERE id = ? AND user_id = ? AND is_active = 1',
      [connectionId, req.user.id]
    );

    if (!connection) {
      return res.status(404).json({ error: 'Broker connection not found' });
    }

    // Check if access token exists and is not expired
    const now = Math.floor(Date.now() / 1000);
    if (!connection.access_token) {
      return res.status(400).json({ 
        error: 'No access token found. Please authenticate first.',
        needsAuth: true 
      });
    }

    if (connection.access_token_expires_at && connection.access_token_expires_at < now) {
      return res.status(400).json({ 
        error: 'Access token has expired. Please reconnect your account.',
        tokenExpired: true 
      });
    }

    try {
      let testResult;

      if (connection.broker_name.toLowerCase() === 'zerodha') {
        // Test connection using KiteService
        testResult = await kiteService.testConnection(connectionId);
      } else if (connection.broker_name.toLowerCase() === 'upstox') {
        // Test connection using UpstoxService
        testResult = await upstoxService.getProfile(connectionId);
      } else {
        return res.status(400).json({ error: 'Unsupported broker' });
      }

      res.json({ 
        message: `${connection.broker_name} connection is working`,
        profile: testResult,
        tokenExpiresAt: connection.access_token_expires_at,
        tokenExpiresIn: connection.access_token_expires_at - now
      });

    } catch (testError) {
      console.error('❌ Connection test failed:', testError);
      
      // Check if it's a token-related error
      if (testError.message && (testError.message.includes('api_key') || testError.message.includes('access_token'))) {
        return res.status(401).json({ 
          error: 'Invalid or expired credentials. Please reconnect your account.',
          tokenExpired: true,
          details: testError.message
        });
      }

      res.status(500).json({ 
        error: 'Connection test failed',
        details: testError.message
      });
    }

  } catch (error) {
    console.error('Test connection error:', error);
    res.status(500).json({ error: 'Broker connection test failed' });
  }
});


export default router;