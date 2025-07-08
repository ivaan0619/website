import jwt from 'jsonwebtoken';
import { db } from '../database/init.js';
import { createLogger } from '../utils/logger.js';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const logger = createLogger('AUTH_MIDDLEWARE');

export const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    logger.warn('Authentication failed - No token provided', {
      requestId: req.requestId,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method
    });
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await db.getAsync('SELECT id, email, name FROM users WHERE id = ?', [decoded.userId]);
    
    if (!user) {
      logger.warn('Authentication failed - Invalid token (user not found)', {
        requestId: req.requestId,
        userId: decoded.userId,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method
      });
      return res.status(401).json({ error: 'Invalid token' });
    }

    logger.debug('User authenticated successfully', {
      requestId: req.requestId,
      userId: user.id,
      email: user.email,
      path: req.path,
      method: req.method
    });

    req.user = user;
    next();
  } catch (error) {
    logger.error('Authentication failed - Token verification error', error, {
      requestId: req.requestId,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      tokenProvided: !!token,
      errorType: error.name
    });
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};
