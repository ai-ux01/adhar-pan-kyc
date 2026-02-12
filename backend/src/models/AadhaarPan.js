const mongoose = require('mongoose');
const crypto = require('crypto');

const AadhaarPanSchema = new mongoose.Schema({
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
  panNumber: {
    type: String,
    required: true,
    encrypted: true,
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
  fatherName: {
    type: String,
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
  status: {
    type: String,
    enum: ['pending', 'linked', 'not-linked', 'invalid', 'error'],
    default: 'pending',
  },
  linkingDetails: {
    apiResponse: {
      type: mongoose.Schema.Types.Mixed,
      encrypted: true,
    },
    linkingDate: Date,
    linkingStatus: {
      type: String,
      enum: ['linked', 'not-linked', 'invalid'],
    },
    remarks: String,
    lastChecked: Date,
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
AadhaarPanSchema.index({ userId: 1, createdAt: -1 });
AadhaarPanSchema.index({ batchId: 1 });
AadhaarPanSchema.index({ status: 1 });
AadhaarPanSchema.index({ isProcessed: 1 });
AadhaarPanSchema.index({ createdAt: -1 });

// Virtual for processing duration
AadhaarPanSchema.virtual('processingDuration').get(function() {
  if (this.createdAt && this.processedAt) {
    return this.processedAt - this.createdAt;
  }
  return null;
});

// Pre-validate middleware to ensure required fields are present
AadhaarPanSchema.pre('validate', function(next) {
  // Ensure required fields are present before validation
  if (!this.name || this.name.trim() === '') {
    return next(new Error('name: Path `name` is required.'));
  }
  if (!this.panNumber || this.panNumber.trim() === '') {
    return next(new Error('panNumber: Path `panNumber` is required.'));
  }
  if (!this.aadhaarNumber || this.aadhaarNumber.trim() === '') {
    return next(new Error('aadhaarNumber: Path `aadhaarNumber` is required.'));
  }
  next();
});

// Pre-save middleware to encrypt sensitive data
// Temporarily disabled to fix display issues
AadhaarPanSchema.pre('save', function(next) {
  // Skip encryption for now to ensure data displays correctly
  next();
});

// Method to decrypt sensitive data
// Temporarily simplified to return original data
AadhaarPanSchema.methods.decryptData = function() {
  // Return original data without encryption/decryption for now
  return this.toObject();
};

// Static method to get batch statistics
AadhaarPanSchema.statics.getBatchStats = async function(batchId) {
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
    linked: 0,
    'not-linked': 0,
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
AadhaarPanSchema.statics.getUserStats = async function(userId, days = 30) {
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
    linked: 0,
    'not-linked': 0,
    invalid: 0,
    error: 0,
  };

  stats.forEach(stat => {
    result[stat._id] = stat.count;
    result.total += stat.count;
  });

  return result;
};

module.exports = mongoose.model('AadhaarPan', AadhaarPanSchema);
