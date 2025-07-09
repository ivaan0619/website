import { db } from '../database/init.js';
import kiteService from './kiteService.js';
import upstoxService from './upstoxService.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('ORDER_STATUS_SERVICE');

class OrderStatusService {
  constructor() {
    this.activePolling = new Map(); // Track active polling sessions
    this.pollingIntervals = new Map(); // Store interval references
  }

  // Start polling for order status updates
  async startOrderStatusPolling(orderId, brokerConnectionId, brokerOrderId) {
    const pollingKey = `${orderId}-${brokerOrderId}`;
    
    // Don't start if already polling this order
    if (this.activePolling.has(pollingKey)) {
      logger.debug(`Already polling order ${orderId}`);
      return;
    }

    logger.info(`Starting status polling for order ${orderId} (broker order: ${brokerOrderId})`);
    this.activePolling.set(pollingKey, true);

    const pollInterval = setInterval(async () => {
      try {
        await this.checkAndUpdateOrderStatus(orderId, brokerConnectionId, brokerOrderId, pollingKey);
      } catch (error) {
        logger.error(`Error polling order ${orderId}:`, error);
        this.stopPolling(pollingKey);
      }
    }, 5000); // Poll every 5 seconds

    this.pollingIntervals.set(pollingKey, pollInterval);

    // Auto-stop polling after 30 minutes to prevent infinite polling
    setTimeout(() => {
      if (this.activePolling.has(pollingKey)) {
        logger.info(`Auto-stopping polling for order ${orderId} after 30 minutes`);
        this.stopPolling(pollingKey);
      }
    }, 30 * 60 * 1000);
  }

  // Check and update order status from broker
  async checkAndUpdateOrderStatus(orderId, brokerConnectionId, brokerOrderId, pollingKey) {
    try {
      // Get current order from database
      const currentOrder = await db.getAsync(
        'SELECT * FROM orders WHERE id = ?',
        [orderId]
      );

      if (!currentOrder) {
        logger.warn(`Order ${orderId} not found in database`);
        this.stopPolling(pollingKey);
        return;
      }

      // Check if order is already in final state
      if (this.isFinalStatus(currentOrder.status)) {
        logger.info(`Order ${orderId} already in final state: ${currentOrder.status}`);
        this.stopPolling(pollingKey);
        return;
      }

      // Get broker connection details
      const brokerConnection = await db.getAsync(
        'SELECT * FROM broker_connections WHERE id = ? AND is_active = 1',
        [brokerConnectionId]
      );

      if (!brokerConnection) {
        logger.warn(`Broker connection ${brokerConnectionId} not found or inactive`);
        this.stopPolling(pollingKey);
        return;
      }

      // Fetch order status from broker
      let brokerOrderData;
      if (brokerConnection.broker_name.toLowerCase() === 'zerodha') {
        brokerOrderData = await kiteService.getOrderStatus(brokerConnectionId, brokerOrderId);
      } else if (brokerConnection.broker_name.toLowerCase() === 'upstox') {
        brokerOrderData = await upstoxService.getOrderStatus(brokerConnectionId, brokerOrderId);
      } else {
        // For other brokers, implement their specific API calls
        logger.warn(`Order status polling not implemented for ${brokerConnection.broker_name}`);
        this.stopPolling(pollingKey);
        return;
      }

      if (!brokerOrderData) {
        logger.warn(`No order data received from broker for order ${brokerOrderId}`);
        return;
      }

      // Check if status has changed
      const newStatus = this.mapBrokerStatus(brokerOrderData.status);
      if (newStatus !== currentOrder.status) {
        logger.info(`Order ${orderId} status changed: ${currentOrder.status} -> ${newStatus}`);
        
        // Update order in database
        await this.updateOrderInDatabase(orderId, brokerOrderData, newStatus);
        
        // If order reached final state, stop polling
        if (this.isFinalStatus(newStatus)) {
          logger.info(`Order ${orderId} reached final state: ${newStatus}`);
          this.stopPolling(pollingKey);
          
          // If order is completed, sync positions
          if (newStatus === 'COMPLETE') {
            try {
              if (brokerConnection.broker_name.toLowerCase() === 'zerodha') {
                await kiteService.syncPositions(brokerConnectionId);
              } else if (brokerConnection.broker_name.toLowerCase() === 'upstox') {
                // Upstox position sync would be implemented here
                // await upstoxService.syncPositions(brokerConnectionId);
              }
              logger.info(`Positions synced after order ${orderId} completion`);
            } catch (syncError) {
              logger.error(`Failed to sync positions after order completion:`, syncError);
            }
          }
        }
      } else {
        logger.debug(`Order ${orderId} status unchanged: ${currentOrder.status}`);
      }

    } catch (error) {
      logger.error(`Error checking order status for ${orderId}:`, error);
      
      // If it's an authentication error, stop polling
      if (error.message && (error.message.includes('Invalid') || error.message.includes('expired'))) {
        logger.warn(`Authentication error for order ${orderId}, stopping polling`);
        this.stopPolling(pollingKey);
      }
    }
  }

  // Update order details in database
  async updateOrderInDatabase(orderId, brokerOrderData, newStatus) {
    try {
      const updateData = {
        status: newStatus,
        executed_price: brokerOrderData.average_price || brokerOrderData.price || null,
        executed_quantity: brokerOrderData.filled_quantity || brokerOrderData.quantity || 0,
        status_message: JSON.stringify(brokerOrderData),
        updated_at: new Date().toISOString()
      };

      // Calculate P&L if order is completed
      if (newStatus === 'COMPLETE' && updateData.executed_price && updateData.executed_quantity) {
        const order = await db.getAsync('SELECT * FROM orders WHERE id = ?', [orderId]);
        if (order) {
          const pnl = this.calculatePnL(order, updateData);
          updateData.pnl = pnl;
        }
      }

      await db.runAsync(`
        UPDATE orders 
        SET status = ?, executed_price = ?, executed_quantity = ?, status_message = ?, pnl = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `, [
        updateData.status,
        updateData.executed_price,
        updateData.executed_quantity,
        updateData.status_message,
        updateData.pnl || 0,
        orderId
      ]);

      logger.info(`Order ${orderId} updated in database with status: ${newStatus}`);
    } catch (error) {
      logger.error(`Failed to update order ${orderId} in database:`, error);
      throw error;
    }
  }

  // Calculate P&L for completed orders
  calculatePnL(order, updateData) {
    try {
      const originalPrice = parseFloat(order.price) || 0;
      const executedPrice = parseFloat(updateData.executed_price) || 0;
      const quantity = parseInt(updateData.executed_quantity) || 0;

      if (originalPrice === 0 || executedPrice === 0 || quantity === 0) {
        return 0;
      }

      let pnl = 0;
      if (order.transaction_type === 'BUY') {
        // For buy orders, P&L is negative (cost)
        pnl = -(executedPrice * quantity);
      } else {
        // For sell orders, P&L is positive (revenue)
        pnl = executedPrice * quantity;
      }

      return parseFloat(pnl.toFixed(2));
    } catch (error) {
      logger.error(`Error calculating P&L for order ${order.id}:`, error);
      return 0;
    }
  }

  // Map broker-specific status to our standard status
  mapBrokerStatus(brokerStatus) {
    const statusMap = {
      'COMPLETE': 'COMPLETE',
      'EXECUTED': 'COMPLETE',
      'OPEN': 'OPEN',
      'PENDING': 'PENDING',
      'CANCELLED': 'CANCELLED',
      'CANCELED': 'CANCELLED',
      'REJECTED': 'REJECTED',
      'FAILED': 'REJECTED'
    };

    return statusMap[brokerStatus?.toUpperCase()] || 'PENDING';
  }

  // Check if status is final (no more updates expected)
  isFinalStatus(status) {
    const finalStatuses = ['COMPLETE', 'CANCELLED', 'REJECTED'];
    return finalStatuses.includes(status?.toUpperCase());
  }

  // Stop polling for a specific order
  stopPolling(pollingKey) {
    if (this.pollingIntervals.has(pollingKey)) {
      clearInterval(this.pollingIntervals.get(pollingKey));
      this.pollingIntervals.delete(pollingKey);
    }
    this.activePolling.delete(pollingKey);
    logger.info(`Stopped polling for order: ${pollingKey}`);
  }

  // Start polling for all open orders on service startup
  async startPollingForOpenOrders() {
    try {
      logger.info('Starting polling for all open orders');
      
      const openOrders = await db.allAsync(`
        SELECT o.*, bc.broker_name 
        FROM orders o
        LEFT JOIN broker_connections bc ON o.broker_connection_id = bc.id
        WHERE o.status IN ('OPEN', 'PENDING') 
        AND o.broker_order_id IS NOT NULL 
        AND bc.is_active = 1
        AND bc.is_authenticated = 1
      `);

      logger.info(`Found ${openOrders.length} open orders to monitor`);

      for (const order of openOrders) {
        if (order.broker_order_id && order.broker_connection_id) {
          // Start polling with a small delay to avoid overwhelming the broker API
          setTimeout(() => {
            this.startOrderStatusPolling(
              order.id,
              order.broker_connection_id,
              order.broker_order_id
            );
          }, Math.random() * 5000); // Random delay up to 5 seconds
        }
      }
    } catch (error) {
      logger.error('Error starting polling for open orders:', error);
    }
  }

  // Get polling status for debugging
  getPollingStatus() {
    return {
      activePolling: Array.from(this.activePolling.keys()),
      pollingCount: this.activePolling.size
    };
  }

  // Stop all polling (for graceful shutdown)
  stopAllPolling() {
    logger.info('Stopping all order status polling');
    
    for (const [pollingKey, interval] of this.pollingIntervals) {
      clearInterval(interval);
    }
    
    this.pollingIntervals.clear();
    this.activePolling.clear();
  }
}

// Create singleton instance
const orderStatusService = new OrderStatusService();

export default orderStatusService;