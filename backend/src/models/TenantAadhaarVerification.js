const mongoose = require('mongoose');
const { encrypt, decrypt, isEncrypted } = require('../utils/encryption');

const SENSITIVE_STRING_FIELDS = [
  'aadhaarNumber',
  'name',
  'dateOfBirth',
  'gender',
  'address',
  'pinCode',
  'state',
  'district',
  'careOf',
  'photo'
];

function decryptTenantVerificationRecord(record) {
  if (!record) return record;

  const decrypted = { ...record };

  SENSITIVE_STRING_FIELDS.forEach((field) => {
    const value = decrypted[field];
    if (value && typeof value === 'string' && isEncrypted(value)) {
      try {
        decrypted[field] = decrypt(value);
      } catch {
        decrypted[field] = '';
      }
    }
  });

  if (decrypted.verificationDetails && typeof decrypted.verificationDetails === 'string') {
    if (isEncrypted(decrypted.verificationDetails)) {
      try {
        decrypted.verificationDetails = JSON.parse(decrypt(decrypted.verificationDetails));
      } catch {
        decrypted.verificationDetails = {};
      }
    }
  }

  return decrypted;
}

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

TenantAadhaarVerificationSchema.pre('save', function encryptSensitiveFields(next) {
  if (!process.env.ENCRYPTION_KEY) {
    return next(new Error('Encryption key not configured'));
  }

  if (this.isNew || this.isModified()) {
    SENSITIVE_STRING_FIELDS.forEach((field) => {
      const value = this[field];
      if (value && typeof value === 'string' && value.trim() !== '' && !isEncrypted(value)) {
        try {
          this[field] = encrypt(value);
        } catch (error) {
          return next(error);
        }
      }
    });

    if (this.verificationDetails && typeof this.verificationDetails === 'object') {
      const serialized = JSON.stringify(this.verificationDetails);
      if (serialized !== '{}' && !isEncrypted(serialized)) {
        try {
          this.verificationDetails = encrypt(serialized);
        } catch (error) {
          return next(error);
        }
      }
    }
  }

  next();
});

TenantAadhaarVerificationSchema.statics.decryptRecord = decryptTenantVerificationRecord;

module.exports = mongoose.model('TenantAadhaarVerification', TenantAadhaarVerificationSchema);
module.exports.decryptTenantVerificationRecord = decryptTenantVerificationRecord;
module.exports.SENSITIVE_STRING_FIELDS = SENSITIVE_STRING_FIELDS;
