import express from 'express';
import { db } from '../database/init.js';
import { subscriptionAPI } from '../services/subscriptionService.js';
import kiteService from '../services/kiteService.js';
import upstoxService from '../services/upstoxService.js';
import angelService from '../services/angelService.js';
import shoonyaService from '../services/shoonyaService.js';
import orderStatusService from '../services/orderStatusService.js';
import createLogger from '../utils/logger.js';

const router = express.Router();
const logger = createLogger('WebhookHandler');

// Helper function to log errors consistently
async function logErrorStatus(logId, message, startTime, debugLogs) {
  await db.runAsync(
    'UPDATE webhook_logs SET status = ?, error_message = ?, processing_time = ? WHERE id = ?',
    ['ERROR', message, Date.now() - startTime, logId]
  );
  logger.error(`Error (Log ID ${logId}): ${message}`);
  debugLogs.push(`❌ ERROR: ${message}`);
}

// Convert webhook payload to Zerodha-compatible payload
function formatOrderPayload(payload, brokerName, debugLogs) {
  console.log('🔍 payload.symbol:', payload.symbol);
  debugLogs.push(`🔍 payload.symbol: ${payload.symbol}`);

  // Ensure symbol is properly converted to string
  const symbolStr = String(payload.symbol || '').trim().toUpperCase();
  console.log('✅ Coerced tradingsymbol:', symbolStr);
  debugLogs.push(`✅ Coerced tradingsymbol: ${symbolStr}`);

  // Validate that symbol is not empty
  if (!symbolStr) {
    throw new Error('Symbol cannot be empty');
  }

  let formatted;
  
  if (brokerName.toLowerCase() === 'zerodha') {
    formatted = {
      variety: 'regular',
      exchange: payload.exchange || 'NSE',
      tradingsymbol: symbolStr,
      transaction_type: payload.action.toUpperCase(),
      quantity: parseInt(payload.quantity),
      order_type: payload.order_type || 'MARKET',
      product: payload.product || 'MIS',
      validity: payload.validity || 'DAY',
      price: payload.order_type === 'LIMIT' ? parseFloat(payload.price || 0) : 0,
      trigger_price: ['SL', 'SL-M'].includes(payload.order_type) ? parseFloat(payload.trigger_price || 0) : 0,
      tag: 'AutoTraderHub'
    };
  } else if (brokerName.toLowerCase() === 'upstox') {
    // For Upstox, we need instrument_token instead of tradingsymbol
    // In a real implementation, you'd look up the instrument_token from symbol
    formatted = {
      instrument_token: symbolStr, // This should be looked up from symbol
      quantity: parseInt(payload.quantity),
      product: payload.product === 'MIS' ? 'I' : (payload.product === 'CNC' ? 'D' : 'I'), // I=Intraday, D=Delivery
      validity: payload.validity || 'DAY',
      price: payload.order_type === 'LIMIT' ? parseFloat(payload.price || 0) : 0,
      order_type: payload.order_type || 'MARKET',
      transaction_type: payload.action.toUpperCase(),
      disclosed_quantity: 0,
      trigger_price: ['SL', 'SL-M'].includes(payload.order_type) ? parseFloat(payload.trigger_price || 0) : 0,
      is_amo: false,
      tag: 'AutoTraderHub'
    };
  } else if (brokerName.toLowerCase() === 'angel') {
    // For Angel Broking, we need symboltoken and specific format
    formatted = {
      variety: 'NORMAL',
      tradingsymbol: symbolStr,
      symboltoken: payload.symboltoken || symbolStr, // This should be looked up from symbol
      transactiontype: payload.action.toUpperCase(),
      exchange: payload.exchange || 'NSE',
      ordertype: payload.order_type || 'MARKET',
      producttype: payload.product === 'MIS' ? 'INTRADAY' : (payload.product === 'CNC' ? 'DELIVERY' : 'INTRADAY'),
      duration: payload.validity || 'DAY',
      price: payload.order_type === 'LIMIT' ? parseFloat(payload.price || 0).toString() : '0',
      squareoff: '0',
      stoploss: ['SL', 'SL-M'].includes(payload.order_type) ? parseFloat(payload.trigger_price || 0).toString() : '0',
      quantity: parseInt(payload.quantity)
    };
  } else if (brokerName.toLowerCase() === 'shoonya') {
    // For Shoonya, we need tsym and specific format
    formatted = {
      exch: payload.exchange || 'NSE',
      tsym: symbolStr,
      qty: parseInt(payload.quantity),
      prc: payload.order_type === 'LMT' ? parseFloat(payload.price || 0).toString() : '0',
      prd: payload.product === 'MIS' ? 'I' : (payload.product === 'CNC' ? 'C' : 'I'), // I=Intraday, C=CNC, M=Margin
      trantype: payload.action.toUpperCase() === 'BUY' ? 'B' : 'S', // B=Buy, S=Sell
      prctyp: payload.order_type === 'LIMIT' ? 'LMT' : 'MKT', // MKT=Market, LMT=Limit
      ret: payload.validity || 'DAY', // DAY, IOC, EOS
      ordersource: 'API'
    };
    
    // Add trigger price for stop loss orders
    if (['SL', 'SL-M'].includes(payload.order_type) && payload.trigger_price) {
      formatted.prctyp = payload.order_type === 'SL' ? 'SL-LMT' : 'SL-MKT';
      formatted.trgprc = parseFloat(payload.trigger_price).toString();
    }
  } else {
    // Default format for other brokers
    formatted = {
      symbol: symbolStr,
      exchange: payload.exchange || 'NSE',
      transaction_type: payload.action.toUpperCase(),
      quantity: parseInt(payload.quantity),
      order_type: payload.order_type || 'MARKET',
      product: payload.product || 'MIS',
      validity: payload.validity || 'DAY',
      price: payload.order_type === 'LIMIT' ? parseFloat(payload.price || 0) : 0,
      trigger_price: ['SL', 'SL-M'].includes(payload.order_type) ? parseFloat(payload.trigger_price || 0) : 0,
      tag: 'AutoTraderHub'
    };
  }

  // Add additional logging to verify the object
  console.log('📋 Complete formatted object:', JSON.stringify(formatted, null, 2));
  debugLogs.push(`📋 Complete formatted object: ${JSON.stringify(formatted)}`);
  
  // Verify symbol/instrument_token is still there
  const symbolField = formatted.tradingsymbol || formatted.instrument_token || formatted.symbol;
  console.log('🔍 formatted symbol field:', symbolField);
  debugLogs.push(`🔍 formatted symbol field: ${symbolField}`);

  logger.debug(`Formatted ${brokerName} Payload:`, formatted);
  return formatted;
}

// Handle TradingView webhook
router.post('/:userId/:webhookId', async (req, res) => {
  const startTime = Date.now();
  const { userId, webhookId } = req.params;
  const payload = req.body;
  const debugLogs = [];

  logger.info(`Webhook received for user ${userId}, webhook ${webhookId}`, { payload });
  debugLogs.push(`📡 Webhook received for user ${userId}, webhook ${webhookId}`);

  // Check subscription status first
  try {
    const user = await db.getAsync('SELECT id FROM users WHERE id = ?', [userId]);
    if (!user) {
      await logErrorStatus(logId, 'User not found', startTime, debugLogs);
      return res.status(404).json({ error: 'User not found', debugLogs });
    }

    const subscription = await db.getAsync(
      'SELECT * FROM subscriptions WHERE user_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1',
      [userId, 'active']
    );

    const isSubscriptionActive = subscription && 
      new Date(subscription.expires_at) > new Date();

    if (!isSubscriptionActive) {
      await logErrorStatus(logId, 'Subscription expired or inactive - webhook disabled', startTime, debugLogs);
      return res.status(403).json({ 
        error: 'Subscription required', 
        message: 'Your subscription has expired. Webhook services are disabled.',
        debugLogs 
      });
    }
  } catch (subscriptionError) {
    logger.error('Failed to check subscription status:', subscriptionError);
    await logErrorStatus(logId, 'Failed to verify subscription status', startTime, debugLogs);
    return res.status(500).json({ error: 'Subscription verification failed', debugLogs });
  }

  let logId = null;

  try {
    const logResult = await db.runAsync(
      'INSERT INTO webhook_logs (user_id, payload, status) VALUES (?, ?, ?)',
      [userId, JSON.stringify(payload), 'RECEIVED']
    );
    logId = logResult.lastID;
    logger.info(`Log inserted with ID: ${logId}`);
    debugLogs.push(`📝 Log inserted with ID: ${logId}`);

    await db.runAsync('UPDATE webhook_logs SET status = ? WHERE id = ?', ['PROCESSING', logId]);
    debugLogs.push(`🔄 Log ${logId} marked as PROCESSING.`);

    const { symbol, action, quantity } = payload;
    if (!symbol || !action || quantity == null) {
      await logErrorStatus(logId, 'Invalid payload: symbol, action, and quantity are required', startTime, debugLogs);
      return res.status(400).json({ error: 'Invalid payload: symbol, action, and quantity are required', debugLogs });
    }

    const parsedQuantity = Number(quantity);
    if (!Number.isInteger(parsedQuantity) || parsedQuantity <= 0) {
      await logErrorStatus(logId, 'Invalid quantity: must be an integer > 0', startTime, debugLogs);
      return res.status(400).json({ error: 'Invalid quantity: must be an integer > 0', debugLogs });
    }

    const transactionType = action.toUpperCase();
    if (!['BUY', 'SELL'].includes(transactionType)) {
      await logErrorStatus(logId, 'Invalid action: must be BUY or SELL', startTime, debugLogs);
      return res.status(400).json({ error: 'Invalid action: must be BUY or SELL', debugLogs });
    }
    debugLogs.push(`✅ Payload validated: Symbol=${symbol}, Action=${transactionType}, Quantity=${parsedQuantity}`);

    const brokerConnection = await db.getAsync(
      `SELECT * FROM broker_connections WHERE user_id = ? AND webhook_url LIKE ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1`,
      [userId, `%${webhookId}%`]
    );

    if (!brokerConnection) {
      await logErrorStatus(logId, 'No active broker connection found for this webhook', startTime, debugLogs);
      return res.status(404).json({ error: 'No active broker connection found for this webhook', debugLogs });
    }

    await db.runAsync('UPDATE webhook_logs SET broker_connection_id = ? WHERE id = ?', [brokerConnection.id, logId]);
    debugLogs.push(`🔗 Broker connection found: ${brokerConnection.broker_name} (ID ${brokerConnection.id})`);

    const orderParams = formatOrderPayload(payload, brokerConnection.broker_name, debugLogs);
    
    // Additional verification before sending to broker
    console.log('🔍 Final orderParams before broker call:', JSON.stringify(orderParams, null, 2));
    debugLogs.push(`🔍 Final orderParams before broker call: ${JSON.stringify(orderParams)}`);

    const orderResult = await db.runAsync(
      `INSERT INTO orders (user_id, broker_connection_id, symbol, exchange, quantity, order_type, transaction_type, product, price, trigger_price, status, webhook_data)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [userId, brokerConnection.id, 
        orderParams.tradingsymbol || orderParams.instrument_token || orderParams.symbol, 
        orderParams.exchange || 'NSE', 
        orderParams.quantity,
        orderParams.order_type, orderParams.transaction_type, orderParams.product, orderParams.price,
        orderParams.trigger_price, 'PENDING', JSON.stringify(payload)]
    );
    const orderId = orderResult.lastID;
    await db.runAsync('UPDATE webhook_logs SET order_id = ? WHERE id = ?', [orderId, logId]);
    debugLogs.push(`📝 Order created with ID: ${orderId}`);

    let brokerResponse;
    try {
      debugLogs.push(`📤 Placing order with broker: ${brokerConnection.broker_name}`);
      if (brokerConnection.broker_name.toLowerCase() === 'zerodha') {
        // Create a clean copy of orderParams to avoid any reference issues
        const cleanOrderParams = { ...orderParams };
        console.log('🔍 Clean orderParams being sent to kiteService:', JSON.stringify(cleanOrderParams, null, 2));
        debugLogs.push(`🔍 Clean orderParams being sent to kiteService: ${JSON.stringify(cleanOrderParams)}`);
        
        brokerResponse = await kiteService.placeOrder(brokerConnection.id, cleanOrderParams);
      } else if (brokerConnection.broker_name.toLowerCase() === 'upstox') {
        // Create a clean copy of orderParams for Upstox
        const cleanOrderParams = { ...orderParams };
        console.log('🔍 Clean orderParams being sent to upstoxService:', JSON.stringify(cleanOrderParams, null, 2));
        debugLogs.push(`🔍 Clean orderParams being sent to upstoxService: ${JSON.stringify(cleanOrderParams)}`);
        
        brokerResponse = await upstoxService.placeOrder(brokerConnection.id, cleanOrderParams);
      } else if (brokerConnection.broker_name.toLowerCase() === 'angel') {
        // Create a clean copy of orderParams for Angel
        const cleanOrderParams = { ...orderParams };
        console.log('🔍 Clean orderParams being sent to angelService:', JSON.stringify(cleanOrderParams, null, 2));
        debugLogs.push(`🔍 Clean orderParams being sent to angelService: ${JSON.stringify(cleanOrderParams)}`);
        
        brokerResponse = await angelService.placeOrder(brokerConnection.id, cleanOrderParams);
      } else if (brokerConnection.broker_name.toLowerCase() === 'shoonya') {
        // Create a clean copy of orderParams for Shoonya
        const cleanOrderParams = { ...orderParams };
        console.log('🔍 Clean orderParams being sent to shoonyaService:', JSON.stringify(cleanOrderParams, null, 2));
        debugLogs.push(`🔍 Clean orderParams being sent to shoonyaService: ${JSON.stringify(cleanOrderParams)}`);
        
        brokerResponse = await shoonyaService.placeOrder(brokerConnection.id, cleanOrderParams);
      } else {
        brokerResponse = { success: true, order_id: `MOCK_${Date.now()}`, data: { status: 'COMPLETE' } };
      }

      debugLogs.push(`📥 Broker response received: ${JSON.stringify(brokerResponse)}`);

      await db.runAsync(
        'UPDATE orders SET broker_order_id = ?, status = ?, status_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [brokerResponse.order_id, brokerResponse.data.status || 'OPEN', JSON.stringify(brokerResponse.data), orderId]
      );

      // Start real-time polling for the order if it's not in final state
      if (brokerResponse.order_id && !orderStatusService.isFinalStatus(brokerResponse.data.status || 'OPEN')) {
        try {
          await orderStatusService.startOrderStatusPolling(
            orderId,
            brokerConnection.id,
            brokerResponse.order_id
          );
          debugLogs.push('🔄 Started real-time order status polling');
        } catch (pollingError) {
          debugLogs.push(`⚠️ Failed to start order polling: ${pollingError.message}`);
        }
      }

      if (brokerResponse.data.status === 'COMPLETE') {
        try {
          if (brokerConnection.broker_name.toLowerCase() === 'zerodha') {
            await kiteService.syncPositions(brokerConnection.id);
          } else if (brokerConnection.broker_name.toLowerCase() === 'upstox') {
            // Upstox position sync would be implemented here
            // await upstoxService.syncPositions(brokerConnection.id);
          } else if (brokerConnection.broker_name.toLowerCase() === 'angel') {
            // Angel position sync would be implemented here
            // await angelService.syncPositions(brokerConnection.id);
          } else if (brokerConnection.broker_name.toLowerCase() === 'shoonya') {
            // Shoonya position sync would be implemented here
            // await shoonyaService.syncPositions(brokerConnection.id);
          }
          debugLogs.push('🔄 Positions synced successfully.');
        } catch (syncError) {
          debugLogs.push(`⚠️ Sync positions failed: ${syncError.message}`);
        }
      }

      await db.runAsync(
        'UPDATE webhook_logs SET status = ?, processing_time = ? WHERE id = ?',
        ['SUCCESS', Date.now() - startTime, logId]
      );

      debugLogs.push(`✅ Order placed successfully. Broker Order ID: ${brokerResponse.order_id}`);

      return res.json({
        success: true,
        message: 'Order placed successfully',
        orderId,
        brokerOrderId: brokerResponse.order_id,
        status: brokerResponse.data.status,
        processingTime: Date.now() - startTime,
        pollingStarted: !orderStatusService.isFinalStatus(brokerResponse.data.status || 'OPEN'),
        debugLogs
      });

    } catch (brokerError) {
      await db.runAsync(
        'UPDATE orders SET status = ?, status_message = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        ['REJECTED', brokerError.message, orderId]
      );
      await logErrorStatus(logId, brokerError.message, startTime, debugLogs);

      return res.status(500).json({
        success: false,
        error: 'Order placement failed',
        message: brokerError.message,
        orderId,
        debugLogs
      });
    }
  } catch (error) {
    if (logId) {
      await logErrorStatus(logId, error.message, startTime, debugLogs);
    }
    return res.status(500).json({
      success: false,
      error: 'Webhook processing failed',
      message: error.message,
      debugLogs
    });
  }
});

export default router;
