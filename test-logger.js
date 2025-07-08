import { createLogger } from './server/utils/logger.js';

const logger = createLogger('TEST');

// Test different log levels
logger.info('This is an info message');
logger.warn('This is a warning message');
logger.error('This is an error message', new Error('Test error'));

// Test with metadata
logger.info('Message with metadata', {
    user: 'test-user',
    action: 'test-logging'
});

console.log('Log files are saved in:', process.cwd() + '/logs/');
