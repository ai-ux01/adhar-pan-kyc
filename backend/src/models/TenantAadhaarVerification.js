const mongoose = require('mongoose');

const TenantAadhaarVerificationSchema = new mongoose.Schema(
  {
    tenantId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Tenant',
      required: true,
      index: true
    },
    tenantSlug: {
      type: String,
      required: true,
      index: true
    },
    aadhaarNumberHash: {
      type: String,
      required: true,
      index: true
    },
    aadhaarNumber: {
      type: String,
      required: true
    },
    externalReferenceId: {
      type: String,
      trim: true,
      default: ''
    },
    name: { type: String, default: '' },
    dateOfBirth: { type: String, default: '' },
    gender: { type: String, enum: ['M', 'F', 'O', ''], default: '' },
    address: { type: String, default: '' },
    pinCode: { type: String, default: '' },
    state: { type: String, default: '' },
    district: { type: String, default: '' },
    careOf: { type: String, default: '' },
    photo: { type: String, default: '' },
    status: {
      type: String,
      enum: ['pending', 'verified', 'rejected', 'invalid', 'error'],
      default: 'pending',
      index: true
    },
    source: {
      type: String,
      enum: ['sandbox_api', 'tenant_cache', 'partner_api'],
      default: 'sandbox_api'
    },
    verificationDetails: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },
    verifiedAt: { type: Date },
    processingTime: { type: Number, default: 0 }
  },
  { timestamps: true }
);

TenantAadhaarVerificationSchema.index(
  { tenantId: 1, aadhaarNumberHash: 1, status: 1, verifiedAt: -1 }
);

module.exports = mongoose.model('TenantAadhaarVerification', TenantAadhaarVerificationSchema);
