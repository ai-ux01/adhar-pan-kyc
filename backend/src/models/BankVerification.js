const mongoose = require('mongoose');
const crypto = require('crypto');

const BankVerificationSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    batchId: {
      type: String,
      required: true,
      index: true,
    },
    verificationId: {
      type: String,
      required: true,
    },
    ifsc: {
      type: String,
      required: true,
      index: true,
    },
    accountNumber: {
      type: String,
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ['pending', 'verified', 'rejected', 'error'],
      default: 'pending',
    },
    nameAtBank: String,
    accountExists: Boolean,
    verificationDetails: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    processingTime: Number,
    isProcessed: {
      type: Boolean,
      default: false,
    },
    processedAt: Date,
    errorMessage: String,
  },
  { timestamps: true }
);

// Helper function to check if a string is encrypted in "iv:ciphertext" format
function isEncryptedFormat(str) {
  if (!str || typeof str !== 'string') return false;
  // Match 32 hex chars (IV) followed by colon, followed by hex chars (ciphertext)
  return /^[0-9a-fA-F]{32}:[0-9a-fA-F]+$/.test(str);
}

// Pre-save middleware to encrypt sensitive data
BankVerificationSchema.pre('save', function(next) {
  const encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey) {
    return next(new Error('Encryption key not configured'));
  }

  // Only encrypt if this is a new document or if fields have been modified
  if (this.isNew || this.isModified()) {
    // Encrypt sensitive fields
    const fieldsToEncrypt = ['accountNumber', 'nameAtBank'];
    
    fieldsToEncrypt.forEach(field => {
      if (this[field] && typeof this[field] === 'string' && this[field].trim() !== '') {
        // Skip encryption if already encrypted in new format or deprecated old hex format
        const isAlreadyEncrypted = isEncryptedFormat(this[field]) || 
                                   (this[field].length > 24 && /^[0-9a-fA-F]+$/.test(this[field]));
        
        if (!isAlreadyEncrypted) {
          try {
            const algorithm = 'aes-256-cbc';
            const key = crypto.scryptSync(encryptionKey, 'salt', 32);
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            let encrypted = cipher.update(this[field], 'utf8', 'hex');
            encrypted += cipher.final('hex');
            this[field] = iv.toString('hex') + ':' + encrypted;
          } catch (error) {
            console.error(`Error encrypting field ${field}:`, error);
          }
        }
      } else if (this[field] === '') {
        this[field] = null;
      }
    });

    // Handle nested objects like verificationDetails
    if (this.verificationDetails && typeof this.verificationDetails === 'object') {
      const isAlreadyEncrypted = typeof this.verificationDetails === 'string' && 
                                 (isEncryptedFormat(this.verificationDetails) || 
                                  (this.verificationDetails.length > 24 && /^[0-9a-fA-F]+$/.test(this.verificationDetails)));
      
      if (!isAlreadyEncrypted) {
        try {
          const algorithm = 'aes-256-cbc';
          const key = crypto.scryptSync(encryptionKey, 'salt', 32);
          const iv = crypto.randomBytes(16);
          const cipher = crypto.createCipheriv(algorithm, key, iv);
          let encrypted = cipher.update(JSON.stringify(this.verificationDetails), 'utf8', 'hex');
          encrypted += cipher.final('hex');
          this.verificationDetails = iv.toString('hex') + ':' + encrypted;
        } catch (error) {
          console.error('Error encrypting verificationDetails:', error);
        }
      }
    }
  }

  next();
});

// Method to decrypt sensitive data
BankVerificationSchema.methods.decryptData = function() {
  const encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey) {
    throw new Error('Encryption key not configured');
  }

  const decrypted = this.toObject();
  const fieldsToDecrypt = ['accountNumber', 'nameAtBank', 'verificationDetails'];

  fieldsToDecrypt.forEach(field => {
    if (decrypted[field] && typeof decrypted[field] === 'string') {
      const isEncrypted = isEncryptedFormat(decrypted[field]) || 
                         (decrypted[field].length > 24 && /^[0-9a-fA-F]+$/.test(decrypted[field]));
      
      if (isEncrypted) {
        try {
          let currentValue = decrypted[field];
          let attempts = 0;
          const maxAttempts = 3;
          
          while (attempts < maxAttempts && isEncryptedFormat(currentValue)) {
            const algorithm = 'aes-256-cbc';
            const key = crypto.scryptSync(encryptionKey, 'salt', 32);
            const [ivHex, encrypted] = currentValue.split(':');
            const iv = Buffer.from(ivHex, 'hex');
            const decipher = crypto.createDecipheriv(algorithm, key, iv);
            let decryptedField = decipher.update(encrypted, 'hex', 'utf8');
            decryptedField += decipher.final('utf8');
            currentValue = decryptedField;
            attempts++;
          }
          
          if (attempts < maxAttempts && currentValue.length > 24 && /^[0-9a-fA-F]+$/.test(currentValue)) {
            try {
              const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
              let decryptedField = decipher.update(currentValue, 'hex', 'utf8');
              decryptedField += decipher.final('utf8');
              currentValue = decryptedField;
            } catch (oldError) {
              currentValue = '[ENCRYPTED]';
            }
          }

          // Try parsing verificationDetails back to JSON object
          if (field === 'verificationDetails') {
            try {
              decrypted[field] = JSON.parse(currentValue);
            } catch (e) {
              decrypted[field] = currentValue;
            }
          } else {
            decrypted[field] = currentValue;
          }
        } catch (error) {
          decrypted[field] = '[ENCRYPTED]';
        }
      }
    }
  });

  return decrypted;
};

BankVerificationSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('BankVerification', BankVerificationSchema);
