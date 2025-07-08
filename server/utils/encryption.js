import crypto from 'crypto';

// Use environment variable or fallback for development
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'autotrader-hub-secret-key-32-chars';
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16; // 128 bits

// Ensure the key is exactly 32 bytes
const getKey = () => {
  let key = ENCRYPTION_KEY;

  if (process.env.NODE_ENV === 'production' && !process.env.ENCRYPTION_KEY) {
    throw new Error('❌ ENCRYPTION_KEY is required in production.');
  }

  if (key.length < 32) {
    key = key.padEnd(32, '0');
  } else if (key.length > 32) {
    key = key.substring(0, 32);
  }

  return Buffer.from(key, 'utf8');
};

// Encrypt plaintext using AES-256-CBC
export const encryptData = (text) => {
  try {
    if (!text) throw new Error('Text to encrypt cannot be empty');

    const key = getKey();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Format: iv:encryptedData
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('🔒 Encryption error:', error.message);
    throw new Error('Encryption failed');
  }
};

// Decrypt the encrypted string
export const decryptData = (encryptedData) => {
  try {
    if (!encryptedData || typeof encryptedData !== 'string') {
      throw new Error('Invalid encrypted data');
    }

    const parts = encryptedData.split(':');
    if (parts.length !== 2) throw new Error('Invalid encrypted data format');

    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = parts[1];

    if (iv.length !== IV_LENGTH) {
      throw new Error('Invalid IV length');
    }

    const key = getKey();
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);

    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    console.error('🔓 Decryption error:', error.message);
    throw new Error('Decryption failed');
  }
};

// Utility to test encryption/decryption
export const testEncryption = () => {
  try {
    const testData = 'test-api-key-12345';
    const encrypted = encryptData(testData);
    const decrypted = decryptData(encrypted);

    const match = testData === decrypted;
    if (match) {
      console.log('✅ Encryption/Decryption test passed');
    } else {
      console.error('❌ Test failed: Decrypted value mismatch');
    }
    return match;
  } catch (error) {
    console.error('❌ Encryption test error:', error.message);
    return false;
  }
};