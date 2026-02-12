const mongoose = require('mongoose');

const AuditSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false, // Some events might not have a user (system events)
  },
  action: {
    type: String,
    required: true,
    enum: [
      // Authentication events
      'login', 'logout', 'login_failed', 'password_reset', 'password_change',
      'email_verification', 'two_factor_enabled', 'two_factor_disabled',
      
      // User management events
      'user_created', 'user_updated', 'user_deleted', 'user_suspended', 'user_activated',
      'role_changed', 'module_access_changed',
      
      // File upload events
      'file_uploaded', 'file_processed', 'file_deleted', 'file_downloaded',
      
      // PAN KYC events
      'pan_kyc_upload', 'pan_kyc_verification', 'pan_kyc_batch_complete',
      'pan_kyc_api_call', 'pan_kyc_api_error', 'record_verified', 'batch_deleted', 'single_kyc_verified',
      
      // Aadhaar-PAN events
      'aadhaar_pan_upload', 'aadhaar_pan_verification', 'aadhaar_pan_batch_complete',
      'aadhaar_pan_api_call', 'aadhaar_pan_api_error', 'single_linking_verified',
      
      // Aadhaar Verification events
      'aadhaar_verification_verification', 'aadhaar_verification_batch_complete',
      'aadhaar_verification_api_call', 'aadhaar_verification_api_error', 'single_aadhaar_verified',
      'otp_sent', 'otp_verification_completed', 'otp_verification_failed',
      
      // Report events
      'report_generated', 'report_downloaded', 'report_deleted',
      
      // System events
      'system_startup', 'system_shutdown', 'backup_created', 'maintenance_mode',
      'api_rate_limit_exceeded', 'security_alert',
      
      // Admin events
      'admin_action', 'settings_changed', 'api_credentials_updated',
      
      // Archival events
      'archival_process_completed', 'archival_process_failed', 'record_marked_for_deletion',
      'record_deleted', 'record_manually_deleted', 'archival_config_updated',
    ],
  },
  module: {
    type: String,
    enum: ['auth', 'user_management', 'pan_kyc', 'aadhaar_pan', 'aadhaar_verification', 'admin', 'system', 'reports', 'archival'],
    required: true,
  },
  resource: {
    type: String, // e.g., 'user', 'batch', 'file', 'report'
    required: false,
  },
  resourceId: {
    type: mongoose.Schema.Types.ObjectId,
    required: false,
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    required: false,
  },
  ipAddress: {
    type: String,
    required: false,
  },
  userAgent: {
    type: String,
    required: false,
  },
  status: {
    type: String,
    enum: ['success', 'failed', 'pending'],
    default: 'success',
  },
  errorMessage: {
    type: String,
    required: false,
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    required: false,
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low',
  },
  sessionId: {
    type: String,
    required: false,
  },
  requestId: {
    type: String,
    required: false,
  },
}, {
  timestamps: true,
});

// Indexes for better query performance
AuditSchema.index({ userId: 1, createdAt: -1 });
AuditSchema.index({ action: 1, createdAt: -1 });
AuditSchema.index({ module: 1, createdAt: -1 });
AuditSchema.index({ status: 1, createdAt: -1 });
AuditSchema.index({ severity: 1, createdAt: -1 });
AuditSchema.index({ createdAt: -1 });

// Static method to log audit events
AuditSchema.statics.logEvent = async function(data) {
  try {
    const auditEntry = new this({
      userId: data.userId,
      action: data.action,
      module: data.module,
      resource: data.resource,
      resourceId: data.resourceId,
      details: data.details,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      status: data.status || 'success',
      errorMessage: data.errorMessage,
      metadata: data.metadata,
      severity: data.severity || 'low',
      sessionId: data.sessionId,
      requestId: data.requestId,
    });

    await auditEntry.save();
    return auditEntry;
  } catch (error) {
    console.error('Failed to log audit event:', error);
    // Don't throw error as audit logging should not break main functionality
  }
};

// Static method to get user activity
AuditSchema.statics.getUserActivity = async function(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return await this.find({
    userId,
    createdAt: { $gte: startDate },
  })
  .sort({ createdAt: -1 })
  .populate('userId', 'name email role');
};

// Static method to get system activity
AuditSchema.statics.getSystemActivity = async function(days = 7) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return await this.find({
    createdAt: { $gte: startDate },
    $or: [
      { module: 'system' },
      { severity: { $in: ['high', 'critical'] } },
    ],
  })
  .sort({ createdAt: -1 })
  .populate('userId', 'name email role');
};

// Static method to get security events
AuditSchema.statics.getSecurityEvents = async function(days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return await this.find({
    createdAt: { $gte: startDate },
    $or: [
      { action: { $in: ['login_failed', 'security_alert', 'api_rate_limit_exceeded'] } },
      { severity: { $in: ['high', 'critical'] } },
    ],
  })
  .sort({ createdAt: -1 })
  .populate('userId', 'name email role');
};

// Static method to get module activity
AuditSchema.statics.getModuleActivity = async function(module, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return await this.find({
    module,
    createdAt: { $gte: startDate },
  })
  .sort({ createdAt: -1 })
  .populate('userId', 'name email role');
};

// Static method to get activity statistics
AuditSchema.statics.getActivityStats = async function(days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  const stats = await this.aggregate([
    {
      $match: {
        createdAt: { $gte: startDate },
      },
    },
    {
      $group: {
        _id: {
          module: '$module',
          action: '$action',
        },
        count: { $sum: 1 },
      },
    },
    {
      $group: {
        _id: '$_id.module',
        actions: {
          $push: {
            action: '$_id.action',
            count: '$count',
          },
        },
        totalCount: { $sum: '$count' },
      },
    },
  ]);

  return stats;
};

module.exports = mongoose.model('Audit', AuditSchema);
