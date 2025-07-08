import winston from 'winston';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create logs directory in project root
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { 
    recursive: true,
    mode: 0o755 // Read & execute for everyone, write for owner
  });
}

// Ensure we can write to the logs directory
try {
  const testFile = path.join(logsDir, '.test-write');
  fs.writeFileSync(testFile, 'test');
  fs.unlinkSync(testFile);
} catch (error) {
  console.error('Cannot write to logs directory:', error);
  process.exit(1);
}

// Function to clean old log files (older than 1 day)
const cleanOldLogs = () => {
  try {
    const files = fs.readdirSync(logsDir);
    const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000); // 24 hours in milliseconds
    
    files.forEach(file => {
      const filePath = path.join(logsDir, file);
      const stats = fs.statSync(filePath);
      
      if (stats.mtime.getTime() < oneDayAgo) {
        fs.unlinkSync(filePath);
        console.log(`🗑️ Cleaned old log file: ${file}`);
      }
    });
  } catch (error) {
    console.error('Error cleaning old logs:', error);
  }
};

// Clean old logs on startup
cleanOldLogs();

// Set up log file rotation - create new file each day
const getLogFileName = () => {
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
  return `app-${today}.log`;
};

// Custom format for better readability
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
    let logMessage = `[${timestamp}] ${level.toUpperCase()}: ${message}`;
    
    // Add stack trace for errors
    if (stack) {
      logMessage += `\nStack Trace:\n${stack}`;
    }
    
    // Add metadata if present
    if (Object.keys(meta).length > 0) {
      logMessage += `\nMetadata: ${JSON.stringify(meta, null, 2)}`;
    }
    
    return logMessage;
  })
);

// Create Winston logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  transports: [
    // File transport for persistent logging
    new winston.transports.File({
      filename: path.join(logsDir, getLogFileName()),
      maxsize: 10 * 1024 * 1024, // 10MB max file size
      maxFiles: 1, // Keep only current day's file
      tailable: true
    }),
    // Console transport for development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        logFormat
      )
    })
  ],
  // Handle uncaught exceptions and rejections
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, `exceptions-${new Date().toISOString().split('T')[0]}.log`)
    })
  ],
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, `rejections-${new Date().toISOString().split('T')[0]}.log`)
    })
  ]
});

// Generate unique request ID for correlation
const generateRequestId = () => {
  return Math.random().toString(36).substr(2, 9);
};

// Enhanced logging methods with request correlation
const createLogger = (module = 'APP') => {
  return {
    error: (message, error = null, meta = {}) => {
      const logData = {
        module,
        ...meta
      };
      
      if (error instanceof Error) {
        logger.error(message, { ...logData, stack: error.stack, errorMessage: error.message });
      } else if (error) {
        logger.error(message, { ...logData, error });
      } else {
        logger.error(message, logData);
      }
    },
    
    warn: (message, meta = {}) => {
      logger.warn(message, { module, ...meta });
    },
    
    info: (message, meta = {}) => {
      logger.info(message, { module, ...meta });
    },
    
    debug: (message, meta = {}) => {
      logger.debug(message, { module, ...meta });
    },
    
    // Special method for HTTP requests
    logRequest: (req, res, duration = null) => {
      const requestData = {
        module,
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.requestId,
        statusCode: res.statusCode,
        duration: duration ? `${duration}ms` : undefined
      };
      
      if (res.statusCode >= 400) {
        logger.error(`HTTP ${res.statusCode} - ${req.method} ${req.originalUrl}`, requestData);
      } else {
        logger.info(`HTTP ${res.statusCode} - ${req.method} ${req.originalUrl}`, requestData);
      }
    },
    
    // Method for database operations
    logDatabase: (operation, table, success, error = null, meta = {}) => {
      const dbData = {
        module: 'DATABASE',
        operation,
        table,
        success,
        ...meta
      };
      
      if (success) {
        logger.info(`Database ${operation} on ${table} successful`, dbData);
      } else {
        logger.error(`Database ${operation} on ${table} failed`, { ...dbData, error: error?.message || error });
      }
    },
    
    // Method for external API calls
    logExternalAPI: (service, endpoint, success, responseTime = null, error = null) => {
      const apiData = {
        module: 'EXTERNAL_API',
        service,
        endpoint,
        success,
        responseTime: responseTime ? `${responseTime}ms` : undefined
      };
      
      if (success) {
        logger.info(`External API call to ${service} successful`, apiData);
      } else {
        logger.error(`External API call to ${service} failed`, { ...apiData, error: error?.message || error });
      }
    }
  };
};

// Middleware to add request ID and timing
const requestLoggingMiddleware = (req, res, next) => {
  req.requestId = generateRequestId();
  req.startTime = Date.now();
  
  // Log request start
  const appLogger = createLogger('HTTP');
  appLogger.info(`Incoming request: ${req.method} ${req.originalUrl}`, {
    requestId: req.requestId,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(...args) {
    const duration = Date.now() - req.startTime;
    appLogger.logRequest(req, res, duration);
    originalEnd.apply(this, args);
  };
  
  next();
};

// Schedule daily cleanup
setInterval(cleanOldLogs, 24 * 60 * 60 * 1000); // Run every 24 hours

export { createLogger, requestLoggingMiddleware, generateRequestId };
export default createLogger;
