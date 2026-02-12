const Audit = require('../models/Audit');
const logger = require('../utils/logger');

// Log audit event
const logEvent = async (data) => {
  try {
    const auditEntry = await Audit.logEvent({
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

    logger.info(`Audit event logged: ${data.action} in ${data.module}`, {
      userId: data.userId,
      action: data.action,
      module: data.module,
      resource: data.resource,
      resourceId: data.resourceId,
    });

    return auditEntry;
  } catch (error) {
    logger.error('Failed to log audit event:', error);
    // Don't throw error as audit logging should not break main functionality
  }
};

// Log authentication events
const logAuthEvent = async (action, userId, details, req) => {
  return await logEvent({
    userId,
    action,
    module: 'auth',
    resource: 'user',
    resourceId: userId,
    details,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID,
    requestId: req.headers['x-request-id'],
  });
};

// Log file upload events
const logFileUpload = async (action, userId, fileData, req) => {
  return await logEvent({
    userId,
    action,
    module: 'file_management',
    resource: 'file',
    resourceId: fileData.fileId,
    details: {
      fileName: fileData.fileName,
      fileSize: fileData.fileSize,
      fileType: fileData.fileType,
      batchId: fileData.batchId,
    },
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID,
    requestId: req.headers['x-request-id'],
  });
};

// Log PAN KYC events
const logPanKycEvent = async (action, userId, kycData, req) => {
  return await logEvent({
    userId,
    action,
    module: 'pan_kyc',
    resource: 'kyc_record',
    resourceId: kycData.recordId,
    details: {
      batchId: kycData.batchId,
      panNumber: kycData.panNumber ? '***' + kycData.panNumber.slice(-4) : undefined,
      status: kycData.status,
      processingTime: kycData.processingTime,
    },
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID,
    requestId: req.headers['x-request-id'],
  });
};

// Log Aadhaar-PAN events
const logAadhaarPanEvent = async (action, userId, linkData, req) => {
  return await logEvent({
    userId,
    action,
    module: 'aadhaar_pan',
    resource: 'link_record',
    resourceId: linkData.recordId,
    details: {
      batchId: linkData.batchId,
      panNumber: linkData.panNumber ? '***' + linkData.panNumber.slice(-4) : undefined,
      aadhaarNumber: linkData.aadhaarNumber ? '***' + linkData.aadhaarNumber.slice(-4) : undefined,
      status: linkData.status,
      processingTime: linkData.processingTime,
    },
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID,
    requestId: req.headers['x-request-id'],
  });
};

// Log Aadhaar verification events
const logAadhaarVerificationEvent = async (action, userId, verificationData, req) => {
  return await logEvent({
    userId,
    action,
    module: 'aadhaar_verification',
    resource: 'verification_record',
    resourceId: verificationData.recordId,
    details: {
      batchId: verificationData.batchId,
      aadhaarNumber: verificationData.aadhaarNumber ? '***' + verificationData.aadhaarNumber.slice(-4) : undefined,
      status: verificationData.status,
      processingTime: verificationData.processingTime,
    },
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID,
    requestId: req.headers['x-request-id'],
  });
};

// Log API call events
const logApiCall = async (service, action, userId, apiData, req) => {
  return await logEvent({
    userId,
    action,
    module: 'api',
    resource: 'api_call',
    details: {
      service,
      endpoint: apiData.endpoint,
      method: apiData.method,
      statusCode: apiData.statusCode,
      responseTime: apiData.responseTime,
      success: apiData.success,
    },
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID,
    requestId: req.headers['x-request-id'],
    status: apiData.success ? 'success' : 'failed',
    errorMessage: apiData.error,
    severity: apiData.success ? 'low' : 'medium',
  });
};

// Log admin events
const logAdminEvent = async (action, adminId, targetData, req) => {
  return await logEvent({
    userId: adminId,
    action,
    module: 'admin',
    resource: targetData.resource,
    resourceId: targetData.resourceId,
    details: {
      targetType: targetData.targetType,
      targetId: targetData.targetId,
      changes: targetData.changes,
      reason: targetData.reason,
    },
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID,
    requestId: req.headers['x-request-id'],
    severity: 'medium',
  });
};

// Log system events
const logSystemEvent = async (action, details, severity = 'low') => {
  return await logEvent({
    action,
    module: 'system',
    resource: 'system',
    details,
    severity,
    timestamp: new Date(),
  });
};

// Log security events
const logSecurityEvent = async (action, details, req, severity = 'medium') => {
  return await logEvent({
    action,
    module: 'security',
    resource: 'security',
    details,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID,
    requestId: req.headers['x-request-id'],
    severity,
    status: 'failed',
  });
};

// Get audit logs with filters
const getAuditLogs = async (filters = {}, page = 1, limit = 50) => {
  try {
    const query = {};

    // Apply filters
    if (filters.userId) query.userId = filters.userId;
    if (filters.action) query.action = filters.action;
    if (filters.module) query.module = filters.module;
    if (filters.status) query.status = filters.status;
    if (filters.severity) query.severity = filters.severity;
    if (filters.startDate) query.createdAt = { $gte: new Date(filters.startDate) };
    if (filters.endDate) {
      if (query.createdAt) {
        query.createdAt.$lte = new Date(filters.endDate);
      } else {
        query.createdAt = { $lte: new Date(filters.endDate) };
      }
    }

    const skip = (page - 1) * limit;
    
    const [logs, total] = await Promise.all([
      Audit.find(query)
        .populate('userId', 'name email role')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Audit.countDocuments(query),
    ]);

    return {
      logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  } catch (error) {
    logger.error('Failed to get audit logs:', error);
    throw error;
  }
};

// Get user activity summary
const getUserActivitySummary = async (userId, days = 30) => {
  try {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const summary = await Audit.aggregate([
      {
        $match: {
          userId: userId,
          createdAt: { $gte: startDate },
        },
      },
      {
        $group: {
          _id: {
            action: '$action',
            module: '$module',
          },
          count: { $sum: 1 },
          lastActivity: { $max: '$createdAt' },
        },
      },
      {
        $group: {
          _id: '$_id.module',
          actions: {
            $push: {
              action: '$_id.action',
              count: '$count',
              lastActivity: '$lastActivity',
            },
          },
          totalActions: { $sum: '$count' },
        },
      },
    ]);

    return summary;
  } catch (error) {
    logger.error('Failed to get user activity summary:', error);
    throw error;
  }
};

// Get system activity summary
const getSystemActivitySummary = async (days = 7) => {
  try {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const summary = await Audit.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
        },
      },
      {
        $group: {
          _id: {
            module: '$module',
            severity: '$severity',
          },
          count: { $sum: 1 },
        },
      },
      {
        $group: {
          _id: '$_id.module',
          severities: {
            $push: {
              severity: '$_id.severity',
              count: '$count',
            },
          },
          totalEvents: { $sum: '$count' },
        },
      },
    ]);

    return summary;
  } catch (error) {
    logger.error('Failed to get system activity summary:', error);
    throw error;
  }
};

// Clean old audit logs
const cleanOldAuditLogs = async (daysToKeep = 365) => {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

    const result = await Audit.deleteMany({
      createdAt: { $lt: cutoffDate },
      severity: { $ne: 'critical' }, // Keep critical logs longer
    });

    logger.info(`Cleaned ${result.deletedCount} old audit logs`);
    return result.deletedCount;
  } catch (error) {
    logger.error('Failed to clean old audit logs:', error);
    throw error;
  }
};

module.exports = {
  logEvent,
  logAuthEvent,
  logFileUpload,
  logPanKycEvent,
  logAadhaarPanEvent,
  logAadhaarVerificationEvent,
  logApiCall,
  logAdminEvent,
  logSystemEvent,
  logSecurityEvent,
  getAuditLogs,
  getUserActivitySummary,
  getSystemActivitySummary,
  cleanOldAuditLogs,
};
