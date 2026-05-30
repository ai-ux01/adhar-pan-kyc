const mongoose = require('mongoose');

const UdyamVerificationSchema = new mongoose.Schema(
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
    udyamNumber: {
      type: String,
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ['pending', 'verified', 'rejected', 'error'],
      default: 'pending',
    },
    enterpriseName: String,
    ownerName: String,
    organizationType: String,
    enterpriseType: String,
    majorActivity: String,
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

UdyamVerificationSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('UdyamVerification', UdyamVerificationSchema);
