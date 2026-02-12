const mongoose = require('mongoose');
const crypto = require('crypto');

const AadhaarVerificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  batchId: {
    type: String,
    required: true,
    index: true,
  },
  aadhaarNumber: {
    type: String,
    required: true,
    encrypted: true,
  },
  name: {
    type: String,
    required: true,
    encrypted: true,
  },
  dateOfBirth: {
    type: String,
    encrypted: true,
  },
  gender: {
    type: String,
    enum: ['M', 'F', 'O'],
    encrypted: true,
  },
  address: {
    type: String,
    encrypted: true,
  },
  pinCode: {
    type: String,
    encrypted: true,
  },
  state: {
    type: String,
    encrypted: true,
  },
  district: {
    type: String,
    encrypted: true,
  },
  careOf: {
    type: String,
    encrypted: true,
  },
  photo: {
    type: String,
    encrypted: true,
  },
  dynamicFields: [{
    label: {
      type: String,
      required: true,
    },
    value: {
      type: String,
      required: true,
    }
  }],
  selfie: {
    filename: String,
    originalName: String,
    path: String,
    mimetype: String,
    size: Number,
    uploadedAt: {
      type: Date,
      default: Date.now,
    },
  },
  status: {
    type: String,
    enum: ['pending', 'verified', 'rejected', 'invalid', 'error'],
    default: 'pending',
  },
  verificationDetails: {
    apiResponse: {
      type: mongoose.Schema.Types.Mixed,
      encrypted: true,
    },
    verifiedName: {
      type: String,
      encrypted: true,
    },
    verifiedDob: {
      type: String,
      encrypted: true,
    },
    verifiedGender: {
      type: String,
      encrypted: true,
    },
    verifiedAddress: {
      type: String,
      encrypted: true,
    },
    verificationDate: Date,
    remarks: String,
    confidence: Number,
    dataMatch: Boolean,
    nameMatch: Boolean,
    dobMatch: Boolean,
    genderMatch: Boolean,
    addressMatch: Boolean,
    source: String,
    transactionId: String,
  },
  apiAttempts: [{
    timestamp: {
      type: Date,
      default: Date.now,
    },
    status: {
      type: String,
      enum: ['success', 'failed', 'timeout'],
    },
    response: mongoose.Schema.Types.Mixed,
    error: String,
  }],
  fileUpload: {
    originalName: String,
    fileName: String,
    fileSize: Number,
    uploadDate: {
      type: Date,
      default: Date.now,
    },
  },
  processingTime: {
    type: Number, // in milliseconds
  },
  retryCount: {
    type: Number,
    default: 0,
  },
  lastRetryAt: Date,
  isProcessed: {
    type: Boolean,
    default: false,
  },
  processedAt: Date,
  errorMessage: String,
}, {
  timestamps: true,
});

// Indexes for better query performance
AadhaarVerificationSchema.index({ userId: 1, createdAt: -1 });
AadhaarVerificationSchema.index({ batchId: 1 });
AadhaarVerificationSchema.index({ status: 1 });
AadhaarVerificationSchema.index({ isProcessed: 1 });
AadhaarVerificationSchema.index({ createdAt: -1 });

// Virtual for processing duration
AadhaarVerificationSchema.virtual('processingDuration').get(function() {
  if (this.createdAt && this.processedAt) {
    return this.processedAt - this.createdAt;
  }
  return null;
});

// Pre-validate middleware to ensure required fields are present
AadhaarVerificationSchema.pre('validate', function(next) {
  // Ensure required fields are present before validation
  if (!this.name || this.name.trim() === '') {
    return next(new Error('name: Path `name` is required.'));
  }
  if (!this.aadhaarNumber || this.aadhaarNumber.trim() === '') {
    return next(new Error('aadhaarNumber: Path `aadhaarNumber` is required.'));
  }
  next();
});

// Pre-save middleware to encrypt sensitive data
AadhaarVerificationSchema.pre('save', function(next) {
  const encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey) {
    return next(new Error('Encryption key not configured'));
  }

  // Only encrypt if this is a new document or if fields have been modified
  if (this.isNew || this.isModified()) {
    // Encrypt sensitive fields
    const fieldsToEncrypt = ['aadhaarNumber', 'name', 'dateOfBirth', 'gender', 'address', 'pinCode', 'state', 'district', 'careOf', 'photo', 'dynamicFields', 'verificationDetails'];
    
    fieldsToEncrypt.forEach(field => {
      if (field === 'dynamicFields') {
        // Handle dynamicFields array specially
        if (this[field] && Array.isArray(this[field]) && this[field].length > 0) {
          try {
            const algorithm = 'aes-256-cbc';
            const key = crypto.scryptSync(encryptionKey, 'salt', 32);
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            let encrypted = cipher.update(JSON.stringify(this[field]), 'utf8', 'hex');
            encrypted += cipher.final('hex');
            this[field] = iv.toString('hex') + ':' + encrypted;
          } catch (error) {
            console.error(`Error encrypting field ${field}:`, error);
            // Don't fail the save if encryption fails
          }
        }
      } else if (this[field] && typeof this[field] === 'string' && this[field].trim() !== '') {
        // Skip encryption if already encrypted (new format with IV or old hex format)
        const isAlreadyEncrypted = this[field].includes(':') || /^[0-9a-fA-F]+$/.test(this[field]);
        
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
            // Don't fail the save if encryption fails
          }
        }
      } else if (this[field] === '') {
        // Set empty strings to null to avoid encryption issues
        this[field] = null;
      }
    });

    // Handle nested objects like verificationDetails
    if (this.verificationDetails && typeof this.verificationDetails === 'object') {
      // Skip encryption if already encrypted
      const isAlreadyEncrypted = typeof this.verificationDetails === 'string' && 
                                 (this.verificationDetails.includes(':') || /^[0-9a-fA-F]+$/.test(this.verificationDetails));
      
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
          // Don't fail the save if encryption fails
        }
      }
    }
  }

  next();
});

// Method to decrypt sensitive data
AadhaarVerificationSchema.methods.decryptData = function() {
  const encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey) {
    throw new Error('Encryption key not configured');
  }

  const decrypted = this.toObject();
  const fieldsToDecrypt = ['aadhaarNumber', 'name', 'dateOfBirth', 'gender', 'address', 'pinCode', 'state', 'district', 'careOf', 'photo', 'dynamicFields', 'verificationDetails'];

  fieldsToDecrypt.forEach(field => {
    if (field === 'dynamicFields') {
      // Handle dynamicFields array specially
      if (decrypted[field] && typeof decrypted[field] === 'string') {
        // Check if the field looks like encrypted data
        const isEncrypted = decrypted[field].includes(':') || 
                           (decrypted[field].length > 20 && /^[0-9a-fA-F]+$/.test(decrypted[field]));
        
        if (isEncrypted) {
          try {
            let currentValue = decrypted[field];
            
            // Keep decrypting until we get plain text (handle double encryption)
            let attempts = 0;
            const maxAttempts = 3; // Prevent infinite loops
            
            while (attempts < maxAttempts && currentValue.includes(':')) {
              // New format with IV
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
            
            // If still encrypted (old format), try deprecated method
            if (attempts < maxAttempts && /^[0-9a-fA-F]+$/.test(currentValue)) {
              try {
                const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
                let decryptedField = decipher.update(currentValue, 'hex', 'utf8');
                decryptedField += decipher.final('utf8');
                currentValue = decryptedField;
              } catch (oldError) {
                // If old method fails, mark as encrypted
                currentValue = '[ENCRYPTED]';
              }
            }
            
            // Try to parse as JSON array
            if (currentValue !== '[ENCRYPTED]' && currentValue.startsWith('[')) {
              decrypted[field] = JSON.parse(currentValue);
            } else {
              decrypted[field] = currentValue;
            }
          } catch (error) {
            decrypted[field] = '[ENCRYPTED]';
          }
        }
      } else if (decrypted[field] === null || decrypted[field] === undefined) {
        // Handle null/undefined values (empty fields)
        decrypted[field] = [];
      }
    } else if (decrypted[field] && typeof decrypted[field] === 'string') {
      // Check if the field looks like encrypted data
      const isEncrypted = decrypted[field].includes(':') || 
                         (decrypted[field].length > 20 && /^[0-9a-fA-F]+$/.test(decrypted[field]));
      
      if (isEncrypted) {
        try {
          let currentValue = decrypted[field];
          
          // Keep decrypting until we get plain text (handle double encryption)
          let attempts = 0;
          const maxAttempts = 3; // Prevent infinite loops
          
          while (attempts < maxAttempts && currentValue.includes(':')) {
            // New format with IV
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
          
          // If still encrypted (old format), try deprecated method
          if (attempts < maxAttempts && /^[0-9a-fA-F]+$/.test(currentValue)) {
            try {
              const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
              let decryptedField = decipher.update(currentValue, 'hex', 'utf8');
              decryptedField += decipher.final('utf8');
              currentValue = decryptedField;
            } catch (oldError) {
              // If old method fails, mark as encrypted
              currentValue = '[ENCRYPTED]';
            }
          }
          
          decrypted[field] = currentValue;
        } catch (error) {
          decrypted[field] = '[ENCRYPTED]';
        }
      }
      // If it doesn't look encrypted, leave it as is (it's already decrypted/plain text)
    } else if (decrypted[field] === null) {
      // Handle null values (empty fields)
      decrypted[field] = '';
    }
  });

  // Handle nested objects
  if (decrypted.verificationDetails && typeof decrypted.verificationDetails === 'string') {
    // Check if verificationDetails looks like encrypted data
    const isEncrypted = decrypted.verificationDetails.includes(':') || 
                       (decrypted.verificationDetails.length > 20 && /^[0-9a-fA-F]+$/.test(decrypted.verificationDetails));
    
    if (isEncrypted) {
      try {
        let currentValue = decrypted.verificationDetails;
        
        // Keep decrypting until we get plain text (handle double encryption)
        let attempts = 0;
        const maxAttempts = 3; // Prevent infinite loops
        
        while (attempts < maxAttempts && currentValue.includes(':')) {
          // New format with IV
          const algorithm = 'aes-256-cbc';
          const key = crypto.scryptSync(encryptionKey, 'salt', 32);
          const [ivHex, encrypted] = currentValue.split(':');
          const iv = Buffer.from(ivHex, 'hex');
          const decipher = crypto.createDecipheriv(algorithm, key, iv);
          let decryptedDetails = decipher.update(encrypted, 'hex', 'utf8');
          decryptedDetails += decipher.final('utf8');
          currentValue = decryptedDetails;
          attempts++;
        }
        
        // If still encrypted (old format), try deprecated method
        if (attempts < maxAttempts && /^[0-9a-fA-F]+$/.test(currentValue)) {
          try {
            const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
            let decryptedDetails = decipher.update(currentValue, 'hex', 'utf8');
            decryptedDetails += decipher.final('utf8');
            currentValue = decryptedDetails;
          } catch (oldError) {
            // If old method fails, mark as encrypted
            currentValue = '[ENCRYPTED]';
          }
        }
        
        // Try to parse as JSON if it looks like JSON
        if (currentValue !== '[ENCRYPTED]' && (currentValue.startsWith('{') || currentValue.startsWith('['))) {
          decrypted.verificationDetails = JSON.parse(currentValue);
        } else {
          decrypted.verificationDetails = currentValue;
        }
      } catch (error) {
        decrypted.verificationDetails = '[ENCRYPTED]';
      }
    }
    // If it doesn't look encrypted, leave it as is (it's already decrypted/plain text)
  }

  return decrypted;
};

// Static method to get batch statistics
AadhaarVerificationSchema.statics.getBatchStats = async function(batchId) {
  const stats = await this.aggregate([
    { $match: { batchId } },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
      },
    },
  ]);

  const result = {
    total: 0,
    pending: 0,
    verified: 0,
    rejected: 0,
    invalid: 0,
    error: 0,
  };

  stats.forEach(stat => {
    result[stat._id] = stat.count;
    result.total += stat.count;
  });

  return result;
};

// Static method to get user statistics
AadhaarVerificationSchema.statics.getUserStats = async function(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  const stats = await this.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startDate },
      },
    },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
      },
    },
  ]);

  const result = {
    total: 0,
    pending: 0,
    verified: 0,
    rejected: 0,
    invalid: 0,
    error: 0,
  };

  stats.forEach(stat => {
    result[stat._id] = stat.count;
    result.total += stat.count;
  });

  return result;
};

module.exports = mongoose.model('AadhaarVerification', AadhaarVerificationSchema);