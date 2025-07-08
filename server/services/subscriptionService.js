import { db } from '../database/init.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('SUBSCRIPTION_SERVICE');

class SubscriptionService {
  // Check if user has active subscription
  async isSubscriptionActive(userId) {
    try {
      const subscription = await db.getAsync(
        'SELECT * FROM subscriptions WHERE user_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1',
        [userId, 'active']
      );

      if (!subscription) {
        return false;
      }

      const now = new Date();
      const expiresAt = new Date(subscription.expires_at);
      
      return expiresAt > now;
    } catch (error) {
      logger.error('Failed to check subscription status:', error);
      return false;
    }
  }

  // Get current subscription for user
  async getCurrentSubscription(userId) {
    try {
      const subscription = await db.getAsync(
        'SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
        [userId]
      );

      if (!subscription) {
        return null;
      }

      const now = new Date();
      const expiresAt = new Date(subscription.expires_at);
      
      return {
        ...subscription,
        isActive: subscription.status === 'active' && expiresAt > now,
        expiresAt: subscription.expires_at
      };
    } catch (error) {
      logger.error('Failed to get current subscription:', error);
      return null;
    }
  }

  // Deactivate services for expired subscriptions
  async deactivateExpiredSubscriptions() {
    try {
      const now = new Date().toISOString();
      
      // Find expired subscriptions
      const expiredSubscriptions = await db.allAsync(
        'SELECT * FROM subscriptions WHERE status = ? AND expires_at < ?',
        ['active', now]
      );

      for (const subscription of expiredSubscriptions) {
        // Update subscription status
        await db.runAsync(
          'UPDATE subscriptions SET status = ? WHERE id = ?',
          ['expired', subscription.id]
        );

        // Deactivate broker connections
        await db.runAsync(
          'UPDATE broker_connections SET is_active = 0 WHERE user_id = ?',
          [subscription.user_id]
        );

        logger.info(`Deactivated services for expired subscription: ${subscription.id}`);
      }

      return expiredSubscriptions.length;
    } catch (error) {
      logger.error('Failed to deactivate expired subscriptions:', error);
      return 0;
    }
  }

  // Reactivate services for renewed subscriptions
  async reactivateServices(userId) {
    try {
      // Reactivate broker connections
      await db.runAsync(
        'UPDATE broker_connections SET is_active = 1 WHERE user_id = ?',
        [userId]
      );

      logger.info(`Reactivated services for user: ${userId}`);
      return true;
    } catch (error) {
      logger.error('Failed to reactivate services:', error);
      return false;
    }
  }
}

export default new SubscriptionService();