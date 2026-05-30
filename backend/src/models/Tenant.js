const mongoose = require('mongoose');

const TenantSchema = new mongoose.Schema(
  {
    tenantId: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^[a-z0-9_-]{3,64}$/, 'tenantId must be 3-64 chars: lowercase letters, numbers, _ or -']
    },
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120
    },
    apiKeyPrefix: {
      type: String,
      required: true,
      index: true
    },
    apiKeyHash: {
      type: String,
      required: true,
      select: false
    },
    isActive: {
      type: Boolean,
      default: true
    },
    rateLimitPerMinute: {
      type: Number,
      default: 60,
      min: 1,
      max: 1000
    },
    contactEmail: {
      type: String,
      trim: true
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  },
  { timestamps: true }
);

TenantSchema.index({ isActive: 1 });

module.exports = mongoose.model('Tenant', TenantSchema);
