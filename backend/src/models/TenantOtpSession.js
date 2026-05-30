const mongoose = require('mongoose');

const TenantOtpSessionSchema = new mongoose.Schema(
  {
    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Tenant',
      required: true,
      index: true
    },
    aadhaarNumberHash: {
      type: String,
      required: true,
      index: true
    },
    transactionId: {
      type: String,
      required: true
    },
    externalReferenceId: {
      type: String,
      trim: true,
      default: ''
    },
    expiresAt: {
      type: Date,
      required: true
    },
    status: {
      type: String,
      enum: ['otp_sent', 'verified', 'expired', 'failed'],
      default: 'otp_sent'
    }
  },
  { timestamps: true }
);

TenantOtpSessionSchema.index({ tenantId: 1, transactionId: 1 });
TenantOtpSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('TenantOtpSession', TenantOtpSessionSchema);
