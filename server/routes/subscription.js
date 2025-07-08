import express from 'express';
import { db } from '../database/init.js';
import { authenticateToken } from '../middleware/auth.js';
import { createLogger } from '../utils/logger.js';

const router = express.Router();
const logger = createLogger('SUBSCRIPTION');

// Subscription plans
const PLANS = {
  'free-trial': {
    id: 'free-trial',
    name: 'Free Trial',
    price: 0,
    duration: 1, // days
    features: ['1 Day Access', '1 Broker Account', 'Basic Analytics', 'Up to 10 Trades']
  },
  'weekly': {
    id: 'weekly',
    name: 'Weekly Plan',
    price: 100,
    duration: 7, // days
    features: ['7 Days Access', '3 Broker Accounts', 'Advanced Analytics', 'Unlimited Trades']
  },
  'monthly': {
    id: 'monthly',
    name: 'Monthly Plan',
    price: 300,
    duration: 30, // days
    features: ['30 Days Access', '5 Broker Accounts', 'Premium Analytics', 'Unlimited Trades', 'API Access']
  }
};

// Get available plans
router.get('/plans', (req, res) => {
  try {
    logger.info('Fetching subscription plans');
    res.json({
      plans: Object.values(PLANS)
    });
  } catch (error) {
    logger.error('Failed to fetch plans:', error);
    res.status(500).json({ error: 'Failed to fetch plans' });
  }
});

// Get current subscription
router.get('/current', authenticateToken, async (req, res) => {
  try {
    logger.info(`Fetching current subscription for user ${req.user.id}`);
    
    const subscription = await db.getAsync(
      'SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
      [req.user.id]
    );

    if (!subscription) {
      return res.json({ subscription: null });
    }

    // Check if subscription is still active
    const now = new Date();
    const expiresAt = new Date(subscription.expires_at);
    const isActive = expiresAt > now && subscription.status === 'active';

    res.json({
      subscription: {
        ...subscription,
        isActive,
        expiresAt: subscription.expires_at
      }
    });
  } catch (error) {
    logger.error('Failed to fetch current subscription:', error);
    res.status(500).json({ error: 'Failed to fetch subscription' });
  }
});

// Subscribe to a plan
router.post('/subscribe', authenticateToken, async (req, res) => {
  try {
    const { planId } = req.body;
    
    logger.info(`User ${req.user.id} attempting to subscribe to plan: ${planId}`);

    if (!PLANS[planId]) {
      return res.status(400).json({ error: 'Invalid plan ID' });
    }

    const plan = PLANS[planId];
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (plan.duration * 24 * 60 * 60 * 1000));

    // Check if user already has an active subscription
    const existingSubscription = await db.getAsync(
      'SELECT * FROM subscriptions WHERE user_id = ? AND status = ? AND expires_at > ?',
      [req.user.id, 'active', now.toISOString()]
    );

    if (existingSubscription) {
      return res.status(400).json({ error: 'You already have an active subscription' });
    }

    // Create new subscription
    const result = await db.runAsync(
      `INSERT INTO subscriptions (user_id, plan_id, plan_name, price, status, expires_at, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        planId,
        plan.name,
        plan.price,
        'active',
        expiresAt.toISOString(),
        now.toISOString()
      ]
    );

    logger.info(`Subscription created successfully for user ${req.user.id}, plan: ${planId}`);

    res.json({
      success: true,
      message: 'Subscription activated successfully',
      subscription: {
        id: result.lastID,
        planId,
        planName: plan.name,
        price: plan.price,
        status: 'active',
        expiresAt: expiresAt.toISOString(),
        isActive: true
      },
      requiresPayment: plan.price > 0
    });
  } catch (error) {
    logger.error('Failed to create subscription:', error);
    res.status(500).json({ error: 'Failed to create subscription' });
  }
});

// Cancel subscription
router.post('/cancel', authenticateToken, async (req, res) => {
  try {
    logger.info(`User ${req.user.id} attempting to cancel subscription`);

    const result = await db.runAsync(
      'UPDATE subscriptions SET status = ? WHERE user_id = ? AND status = ?',
      ['cancelled', req.user.id, 'active']
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'No active subscription found' });
    }

    logger.info(`Subscription cancelled for user ${req.user.id}`);
    res.json({ message: 'Subscription cancelled successfully' });
  } catch (error) {
    logger.error('Failed to cancel subscription:', error);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

// Renew subscription
router.post('/renew', authenticateToken, async (req, res) => {
  try {
    const { planId } = req.body;
    
    logger.info(`User ${req.user.id} attempting to renew subscription with plan: ${planId}`);

    if (!PLANS[planId]) {
      return res.status(400).json({ error: 'Invalid plan ID' });
    }

    const plan = PLANS[planId];
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (plan.duration * 24 * 60 * 60 * 1000));

    // Update existing subscription or create new one
    const result = await db.runAsync(
      `INSERT INTO subscriptions (user_id, plan_id, plan_name, price, status, expires_at, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        planId,
        plan.name,
        plan.price,
        'active',
        expiresAt.toISOString(),
        now.toISOString()
      ]
    );

    logger.info(`Subscription renewed for user ${req.user.id}, plan: ${planId}`);

    res.json({
      success: true,
      message: 'Subscription renewed successfully',
      subscription: {
        id: result.lastID,
        planId,
        planName: plan.name,
        price: plan.price,
        status: 'active',
        expiresAt: expiresAt.toISOString(),
        isActive: true
      }
    });
  } catch (error) {
    logger.error('Failed to renew subscription:', error);
    res.status(500).json({ error: 'Failed to renew subscription' });
  }
});

// Get usage statistics
router.get('/usage', authenticateToken, async (req, res) => {
  try {
    logger.info(`Fetching usage statistics for user ${req.user.id}`);

    const [brokerCount, orderCount, currentSubscription] = await Promise.all([
      db.getAsync(
        'SELECT COUNT(*) as count FROM broker_connections WHERE user_id = ? AND is_active = 1',
        [req.user.id]
      ),
      db.getAsync(
        'SELECT COUNT(*) as count FROM orders WHERE user_id = ? AND created_at >= date("now", "-30 days")',
        [req.user.id]
      ),
      db.getAsync(
        'SELECT * FROM subscriptions WHERE user_id = ? AND status = ? ORDER BY created_at DESC LIMIT 1',
        [req.user.id, 'active']
      )
    ]);

    const plan = currentSubscription ? PLANS[currentSubscription.plan_id] : null;
    const maxBrokers = plan ? (plan.id === 'free-trial' ? 1 : plan.id === 'weekly' ? 3 : 5) : 0;
    const maxTrades = plan ? (plan.id === 'free-trial' ? 10 : -1) : 0; // -1 means unlimited

    res.json({
      usage: {
        brokerConnections: {
          current: brokerCount.count,
          limit: maxBrokers
        },
        trades: {
          current: orderCount.count,
          limit: maxTrades
        },
        subscription: currentSubscription ? {
          planName: currentSubscription.plan_name,
          expiresAt: currentSubscription.expires_at,
          isActive: new Date(currentSubscription.expires_at) > new Date()
        } : null
      }
    });
  } catch (error) {
    logger.error('Failed to fetch usage statistics:', error);
    res.status(500).json({ error: 'Failed to fetch usage statistics' });
  }
});

export default router;