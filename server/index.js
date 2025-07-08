import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.js';
import brokerRoutes from './routes/broker.js';
import orderRoutes from './routes/orders.js';
import webhookRoutes from './routes/webhook.js';
import subscriptionRoutes from './routes/subscription.js';
import { initDatabase } from './database/init.js';
import { createLogger, requestLoggingMiddleware } from './utils/logger.js';
import orderStatusService from './services/orderStatusService.js';
import subscriptionService from './services/subscriptionService.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize logger
const logger = createLogger('SERVER');

// Enhanced CORS configuration
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200
}));

// Handle preflight requests
app.options('*', cors());

// Security headers with relaxed CSP for development
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "http://localhost:*", "ws://localhost:*"],
    },
  }
}));

// Rate limiting with more lenient settings for development
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 100 : 1000, // More requests in development
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Enhanced request logging middleware with logger
app.use(requestLoggingMiddleware);

// Additional middleware to log request bodies (excluding sensitive data)
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
    const logBody = { ...req.body };
    // Hide sensitive fields
    if (logBody.password) logBody.password = '[HIDDEN]';
    if (logBody.apiSecret) logBody.apiSecret = '[HIDDEN]';
    if (logBody.apiKey) logBody.apiKey = `${logBody.apiKey.substring(0, 4)}...`;
    
    logger.debug('Request body received', {
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      body: logBody
    });
  }
  
  next();
});

// Initialize database with proper error logging
try {
  await initDatabase();
  logger.info('Database initialized successfully');
} catch (error) {
  logger.error('Database initialization failed', error, {
    fatal: true,
    component: 'database'
  });
  process.exit(1);
}

// Initialize order status service
try {
  logger.info('Starting order status service...');
  await orderStatusService.startPollingForOpenOrders();
  logger.info('Order status service initialized successfully');
} catch (error) {
  logger.error('Order status service initialization failed', error, {
    component: 'order_status_service'
  });
  // Don't exit, service can still function without real-time updates
}

// Initialize subscription monitoring
try {
  logger.info('Starting subscription monitoring service...');
  
  // Check for expired subscriptions every hour
  setInterval(async () => {
    try {
      const deactivatedCount = await subscriptionService.deactivateExpiredSubscriptions();
      if (deactivatedCount > 0) {
        logger.info(`Deactivated ${deactivatedCount} expired subscriptions`);
      }
    } catch (error) {
      logger.error('Subscription monitoring error:', error);
    }
  }, 60 * 60 * 1000); // Every hour
  
  logger.info('Subscription monitoring service initialized successfully');
} catch (error) {
  logger.error('Subscription monitoring service initialization failed:', error);
}

// Routes with enhanced logging
app.use('/api/auth', (req, res, next) => {
  logger.debug('Auth route accessed', {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    route: 'auth'
  });
  next();
}, authRoutes);

app.use('/api/broker', (req, res, next) => {
  logger.debug('Broker route accessed', {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    route: 'broker'
  });
  next();
}, brokerRoutes);

app.use('/api/orders', (req, res, next) => {
  logger.debug('Orders route accessed', {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    route: 'orders'
  });
  next();
}, orderRoutes);

app.use('/api/webhook', (req, res, next) => {
  logger.debug('Webhook route accessed', {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    route: 'webhook'
  });
  next();
}, webhookRoutes);

app.use('/api/subscription', (req, res, next) => {
  logger.debug('Subscription route accessed', {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    route: 'subscription'
  });
  next();
}, subscriptionRoutes);

// Health check with detailed information
app.get('/api/health', (req, res) => {
  const pollingStatus = orderStatusService.getPollingStatus();
  const healthInfo = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    port: PORT,
    env: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.version,
    orderPolling: {
      active: pollingStatus.pollingCount,
      orders: pollingStatus.activePolling
    }
  };
  
  logger.info('Health check requested', {
    requestId: req.requestId,
    healthInfo
  });
  res.json(healthInfo);
});

// Enhanced error handling middleware with comprehensive logging
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || err.status || 500;
  
  // Log error with full context
  logger.error('Unhandled error occurred', err, {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    statusCode,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    body: req.body,
    query: req.query,
    params: req.params
  });
  
  const errorResponse = {
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method,
    requestId: req.requestId
  };
  
  res.status(statusCode).json(errorResponse);
});

// Enhanced 404 route with logging
app.use('*', (req, res) => {
  logger.warn('Route not found', {
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.status(404).json({ 
    error: 'Route not found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
    timestamp: new Date().toISOString(),
    requestId: req.requestId,
    availableRoutes: [
      'GET /api/health',
      'POST /api/auth/register',
      'POST /api/auth/login',
      'GET /api/broker/connections',
      'POST /api/broker/connect',
      'GET /api/orders',
      'GET /api/orders/:orderId',
      'POST /api/orders/:orderId/start-polling',
      'GET /api/subscription/plans',
      'POST /api/subscription/subscribe'
    ]
  });
});

// Graceful shutdown handling with logging and cleanup
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully', { signal: 'SIGTERM' });
  orderStatusService.stopAllPolling();
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully', { signal: 'SIGINT' });
  orderStatusService.stopAllPolling();
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', error, { fatal: true });
  orderStatusService.stopAllPolling();
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', reason, { 
    fatal: true,
    promise: promise.toString()
  });
  orderStatusService.stopAllPolling();
  process.exit(1);
});

// Start server with enhanced logging
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info('Server started successfully', {
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    availableRoutes: [
      '/api/auth/*',
      '/api/broker/*', 
      '/api/orders/*',
      '/api/webhook/*',
      '/api/subscription/*',
      '/api/health'
    ]
  });
  
  // Also log to console for immediate visibility
  console.log('🚀 ================================');
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log(`📊 AutoTraderHub API is ready`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🕒 Started at: ${new Date().toISOString()}`);
  console.log(`🔄 Order Status Service: Active`);
  console.log('🚀 ================================');
});

// Handle server errors with logging
server.on('error', (error) => {
  logger.error('Server error occurred', error, {
    port: PORT,
    fatal: true
  });
  
  if (error.code === 'EADDRINUSE') {
    logger.error('Port already in use', null, {
      port: PORT,
      suggestion: 'Use a different port or stop the existing server'
    });
  }
  orderStatusService.stopAllPolling();
  process.exit(1);
});

export default app;