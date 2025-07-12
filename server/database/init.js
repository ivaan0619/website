import sqlite3 from 'sqlite3';
import { promisify } from 'util';
import { createLogger } from '../utils/logger.js';

const db = new sqlite3.Database('./autotrader.db');
const logger = createLogger('DATABASE');

// Custom Promise-based db.runAsync to return lastID and changes with logging
db.runAsync = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    db.run(sql, params, function (err) {
      const duration = Date.now() - startTime;
      
      if (err) {
        logger.error('Database query failed', err, {
          sql: sql.substring(0, 100) + '...',
          params,
          duration: `${duration}ms`
        });
        return reject(err);
      }
      
      logger.debug('Database query executed', {
        sql: sql.substring(0, 100) + '...',
        params,
        duration: `${duration}ms`,
        lastID: this.lastID,
        changes: this.changes
      });
      
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

// Enhanced promisified methods with logging
db.getAsync = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    db.get(sql, params, (err, row) => {
      const duration = Date.now() - startTime;
      
      if (err) {
        logger.error('Database get query failed', err, {
          sql: sql.substring(0, 100) + '...',
          params,
          duration: `${duration}ms`
        });
        return reject(err);
      }
      
      logger.debug('Database get query executed', {
        sql: sql.substring(0, 100) + '...',
        params,
        duration: `${duration}ms`,
        hasResult: !!row
      });
      
      resolve(row);
    });
  });
};

db.allAsync = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    db.all(sql, params, (err, rows) => {
      const duration = Date.now() - startTime;
      
      if (err) {
        logger.error('Database all query failed', err, {
          sql: sql.substring(0, 100) + '...',
          params,
          duration: `${duration}ms`
        });
        return reject(err);
      }
      
      logger.debug('Database all query executed', {
        sql: sql.substring(0, 100) + '...',
        params,
        duration: `${duration}ms`,
        rowCount: rows ? rows.length : 0
      });
      
      resolve(rows);
    });
  });
};

// Initialize all database tables
export const initDatabase = async () => {
  logger.info('Starting database initialization');
  
  try {
    // Users table
    logger.debug('Creating users table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        mobileNumber TEXT,
        name TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Pending registrations table - stores user data before OTP verification
    logger.debug('Creating pending_registrations table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS pending_registrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        password TEXT NOT NULL,
        mobileNumber TEXT,
        name TEXT NOT NULL,
        identifier TEXT NOT NULL, -- email or mobile number used for OTP
        created_at INTEGER NOT NULL, -- Unix timestamp
        expires_at INTEGER NOT NULL -- Unix timestamp
      )
    `);

    // OTPs table to store verification codes
    logger.debug('Creating otps table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL, -- Can be email or mobile number
        type TEXT NOT NULL, -- 'email' or 'mobile'
        otp TEXT NOT NULL,
        purpose TEXT NOT NULL DEFAULT 'registration', -- 'registration' or 'password_reset'
        expires_at INTEGER NOT NULL, -- Unix timestamp
        created_at INTEGER NOT NULL
      )
    `);

    // Password reset tokens table
    logger.debug('Creating password_reset_tokens table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL,
        token TEXT NOT NULL,
        expires_at INTEGER NOT NULL, -- Unix timestamp
        created_at INTEGER NOT NULL
      )
    `);

    // Subscriptions table
    logger.debug('Creating subscriptions table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        plan_id TEXT NOT NULL,
        plan_name TEXT NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        status TEXT NOT NULL DEFAULT 'active', -- active, cancelled, expired
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Enhanced Broker connections table with connection_name for multiple connections
    logger.debug('Dropping existing broker_connections table if it exists');
    await db.runAsync(`DROP TABLE IF EXISTS broker_connections`);
    logger.debug('Creating broker_connections table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS broker_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        broker_name TEXT NOT NULL,
        connection_name TEXT, -- User-defined name for this connection
        api_key TEXT NOT NULL,
        api_secret TEXT NOT NULL,
        user_id_broker TEXT,
        password TEXT, -- For Shoonya login password (encrypted)
        two_fa TEXT, -- For Shoonya 2FA/PIN (encrypted)
        vendor TEXT, -- For Shoonya vendor code
        app_key TEXT, -- For Shoonya app key (encrypted)
        imei TEXT, -- For Shoonya IMEI
        access_token TEXT,
        public_token TEXT,
        access_token_expires_at INTEGER, -- Unix timestamp for token expiry
        webhook_url TEXT,
        is_active BOOLEAN DEFAULT 1,
        is_authenticated BOOLEAN DEFAULT 0,
        last_sync DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Add index for better performance on user queries
    await db.runAsync(`
      CREATE INDEX IF NOT EXISTS idx_broker_connections_user_id 
      ON broker_connections (user_id)
    `);

    // Orders table
    logger.debug('Creating orders table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        broker_connection_id INTEGER NOT NULL,
        broker_order_id TEXT,
        symbol TEXT NOT NULL,
        exchange TEXT NOT NULL DEFAULT 'NSE',
        quantity INTEGER NOT NULL,
        order_type TEXT NOT NULL, -- MARKET, LIMIT, SL, SL-M
        transaction_type TEXT NOT NULL, -- BUY, SELL
        product TEXT NOT NULL DEFAULT 'MIS', -- CNC, MIS, NRML
        price DECIMAL(10,2),
        trigger_price DECIMAL(10,2),
        executed_price DECIMAL(10,2),
        executed_quantity INTEGER DEFAULT 0,
        status TEXT DEFAULT 'PENDING', -- PENDING, OPEN, COMPLETE, CANCELLED, REJECTED
        status_message TEXT,
        pnl DECIMAL(10,2) DEFAULT 0,
        webhook_data TEXT, -- JSON data from TradingView
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (broker_connection_id) REFERENCES broker_connections (id)
      )
    `);

    // Positions table
    logger.debug('Creating positions table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS positions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        broker_connection_id INTEGER NOT NULL,
        symbol TEXT NOT NULL,
        exchange TEXT NOT NULL DEFAULT 'NSE',
        quantity INTEGER NOT NULL,
        average_price DECIMAL(10,2) NOT NULL,
        current_price DECIMAL(10,2),
        pnl DECIMAL(10,2) DEFAULT 0,
        pnl_percentage DECIMAL(5,2) DEFAULT 0,
        product TEXT NOT NULL DEFAULT 'MIS',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (broker_connection_id) REFERENCES broker_connections (id),
        UNIQUE(user_id, broker_connection_id, symbol, product)
      )
    `);

    // Holdings table (for long-term investments)
    logger.debug('Creating holdings table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS holdings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        broker_connection_id INTEGER NOT NULL,
        symbol TEXT NOT NULL,
        exchange TEXT NOT NULL DEFAULT 'NSE',
        quantity INTEGER NOT NULL,
        average_price DECIMAL(10,2) NOT NULL,
        current_price DECIMAL(10,2),
        pnl DECIMAL(10,2) DEFAULT 0,
        pnl_percentage DECIMAL(5,2) DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (broker_connection_id) REFERENCES broker_connections (id),
        UNIQUE(user_id, broker_connection_id, symbol)
      )
    `);

    // Webhook logs table
    logger.debug('Creating webhook_logs table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS webhook_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        broker_connection_id INTEGER,
        payload TEXT NOT NULL,
        status TEXT NOT NULL, -- RECEIVED, PROCESSING, SUCCESS, ERROR
        error_message TEXT,
        order_id INTEGER,
        processing_time INTEGER, -- milliseconds
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (broker_connection_id) REFERENCES broker_connections (id),
        FOREIGN KEY (order_id) REFERENCES orders (id)
      )
    `);

    // Market data table (for caching live prices)
    logger.debug('Creating market_data table');
    await db.runAsync(`
      CREATE TABLE IF NOT EXISTS market_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        symbol TEXT NOT NULL,
        exchange TEXT NOT NULL DEFAULT 'NSE',
        last_price DECIMAL(10,2),
        change DECIMAL(10,2),
        change_percent DECIMAL(5,2),
        volume INTEGER,
        high DECIMAL(10,2),
        low DECIMAL(10,2),
        open DECIMAL(10,2),
        close DECIMAL(10,2),
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(symbol, exchange)
      )
    `);

    logger.info('Database initialization completed successfully', {
      tablesCreated: [
        'users', 'pending_registrations', 'otps', 'password_reset_tokens',
        'subscriptions', 'broker_connections', 'orders', 'positions', 'holdings', 
        'webhook_logs', 'market_data'
      ]
    });
  } catch (error) {
    logger.error('Database initialization failed', error, {
      fatal: true,
      component: 'database_init'
    });
    throw error;
  }
};

export { db };