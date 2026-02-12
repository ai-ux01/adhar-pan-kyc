const crypto = require('crypto');

/**
 * Encryption utility for sensitive data
 * Uses AES-256-CBC encryption with random IV for each encryption
 */

/**
 * Encrypt a string using AES-256-CBC
 * @param {string} text - The text to encrypt
 * @returns {string} - Encrypted text in format "iv:encryptedData"
 */
function encrypt(text) {
  if (!text || typeof text !== 'string') {
    throw new Error('Invalid input for encryption');
  }

  const encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey) {
    throw new Error('Encryption key not configured');
  }

  try {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(encryptionKey, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Return in format "iv:encryptedData"
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt data');
  }
}

/**
 * Decrypt a string using AES-256-CBC
 * @param {string} encryptedText - The encrypted text in format "iv:encryptedData"
 * @returns {string} - Decrypted text
 */
function decrypt(encryptedText) {
  if (!encryptedText || typeof encryptedText !== 'string') {
    throw new Error('Invalid input for decryption');
  }

  const encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey) {
    throw new Error('Encryption key not configured');
  }

  try {
    // Check if it's in the new format with IV
    if (encryptedText.includes(':')) {
      const algorithm = 'aes-256-cbc';
      const key = crypto.scryptSync(encryptionKey, 'salt', 32);
      const [ivHex, encrypted] = encryptedText.split(':');
      const iv = Buffer.from(ivHex, 'hex');
      const decipher = crypto.createDecipheriv(algorithm, key, iv);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } else {
      // Handle old format (without IV) - deprecated but kept for backward compatibility
      const algorithm = 'aes-256-cbc';
      const decipher = crypto.createDecipher(algorithm, encryptionKey);
      
      let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    }
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt data');
  }
}

/**
 * Check if a string appears to be encrypted
 * @param {string} text - The text to check
 * @returns {boolean} - True if the text appears to be encrypted
 */
function isEncrypted(text) {
  if (!text || typeof text !== 'string') {
    return false;
  }

  // Check for new format with IV
  if (text.includes(':')) {
    const parts = text.split(':');
    if (parts.length === 2) {
      const [ivHex, encrypted] = parts;
      // Check if both parts are valid hex
      return /^[0-9a-fA-F]+$/.test(ivHex) && /^[0-9a-fA-F]+$/.test(encrypted);
    }
  }

  // Check for old format (hex string)
  if (text.length > 20 && /^[0-9a-fA-F]+$/.test(text)) {
    return true;
  }

  return false;
}

/**
 * Encrypt an object by encrypting all string values
 * @param {Object} obj - The object to encrypt
 * @param {Array} fieldsToEncrypt - Array of field names to encrypt
 * @returns {Object} - Object with encrypted values
 */
function encryptObject(obj, fieldsToEncrypt = []) {
  if (!obj || typeof obj !== 'object') {
    throw new Error('Invalid input for object encryption');
  }

  const encrypted = { ...obj };

  fieldsToEncrypt.forEach(field => {
    if (encrypted[field] && typeof encrypted[field] === 'string' && encrypted[field].trim() !== '') {
      // Skip if already encrypted
      if (!isEncrypted(encrypted[field])) {
        try {
          encrypted[field] = encrypt(encrypted[field]);
        } catch (error) {
          console.error(`Error encrypting field ${field}:`, error);
          // Keep original value if encryption fails
        }
      }
    }
  });

  return encrypted;
}

/**
 * Decrypt an object by decrypting all encrypted string values
 * @param {Object} obj - The object to decrypt
 * @param {Array} fieldsToDecrypt - Array of field names to decrypt
 * @returns {Object} - Object with decrypted values
 */
function decryptObject(obj, fieldsToDecrypt = []) {
  if (!obj || typeof obj !== 'object') {
    throw new Error('Invalid input for object decryption');
  }

  const decrypted = { ...obj };

  fieldsToDecrypt.forEach(field => {
    if (decrypted[field] && typeof decrypted[field] === 'string') {
      if (isEncrypted(decrypted[field])) {
        try {
          decrypted[field] = decrypt(decrypted[field]);
        } catch (error) {
          console.error(`Error decrypting field ${field}:`, error);
          decrypted[field] = '[ENCRYPTED]';
        }
      }
    }
  });

  return decrypted;
}

/**
 * Generate a secure random string
 * @param {number} length - Length of the random string
 * @returns {string} - Random string
 */
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Hash a string using SHA-256
 * @param {string} text - The text to hash
 * @returns {string} - SHA-256 hash
 */
function hash(text) {
  if (!text || typeof text !== 'string') {
    throw new Error('Invalid input for hashing');
  }

  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Compare a plain text with a hash
 * @param {string} text - Plain text
 * @param {string} hash - Hash to compare against
 * @returns {boolean} - True if they match
 */
function compareHash(text, hash) {
  if (!text || !hash || typeof text !== 'string' || typeof hash !== 'string') {
    return false;
  }

  const textHash = crypto.createHash('sha256').update(text).digest('hex');
  return textHash === hash;
}

module.exports = {
  encrypt,
  decrypt,
  isEncrypted,
  encryptObject,
  decryptObject,
  generateRandomString,
  hash,
  compareHash
};

