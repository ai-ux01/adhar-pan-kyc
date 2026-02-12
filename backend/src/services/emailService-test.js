const logger = require('../utils/logger');

// Mock email service for testing (logs emails to console)
const mockEmailService = {
  // Send verification email
  sendVerificationEmail: async (email, token) => {
    const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email/${token}`;
    
    console.log('\n📧 ===== VERIFICATION EMAIL =====');
    console.log(`To: ${email}`);
    console.log(`Subject: Verify Your Email Address`);
    console.log(`Verification URL: ${verificationUrl}`);
    console.log('================================\n');
    
    logger.info(`Mock verification email sent to ${email}`);
    return { messageId: 'mock-verification-' + Date.now() };
  },

  // Send password reset email
  sendPasswordResetEmail: async (email, token) => {
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password/${token}`;
    
    console.log('\n📧 ===== PASSWORD RESET EMAIL =====');
    console.log(`To: ${email}`);
    console.log(`Subject: Reset Your Password`);
    console.log(`Reset URL: ${resetUrl}`);
    console.log('===================================\n');
    
    logger.info(`Mock password reset email sent to ${email}`);
    return { messageId: 'mock-reset-' + Date.now() };
  },

  // Send notification email
  sendNotificationEmail: async (email, subject, message, data = {}) => {
    console.log('\n📧 ===== NOTIFICATION EMAIL =====');
    console.log(`To: ${email}`);
    console.log(`Subject: ${subject}`);
    console.log(`Message: ${message}`);
    if (data.details) {
      console.log(`Details:`, JSON.stringify(data.details, null, 2));
    }
    console.log('=================================\n');
    
    logger.info(`Mock notification email sent to ${email}`);
    return { messageId: 'mock-notification-' + Date.now() };
  },

  // Send batch completion notification
  sendBatchCompletionEmail: async (email, batchData) => {
    const subject = `Batch Processing Complete - ${batchData.batchId}`;
    const message = `
      Your batch processing has been completed successfully.
      Batch ID: ${batchData.batchId}
      Module: ${batchData.module}
      Total Records: ${batchData.totalRecords}
      Processing Time: ${batchData.processingTime}ms
    `;

    return await mockEmailService.sendNotificationEmail(email, subject, message, {
      details: batchData,
    });
  },

  // Send error notification
  sendErrorNotificationEmail: async (email, errorData) => {
    const subject = `System Error Alert - ${errorData.type}`;
    const message = `
      A system error has occurred that requires your attention.
      Error Type: ${errorData.type}
      Severity: ${errorData.severity}
      Timestamp: ${new Date(errorData.timestamp).toLocaleString()}
    `;

    return await mockEmailService.sendNotificationEmail(email, subject, message, {
      details: errorData,
    });
  },

  // Send API failure notification
  sendApiFailureEmail: async (email, apiData) => {
    const subject = `API Failure Alert - ${apiData.service}`;
    const message = `
      An API service failure has been detected.
      Service: ${apiData.service}
      Error: ${apiData.error}
      Timestamp: ${new Date(apiData.timestamp).toLocaleString()}
    `;

    return await mockEmailService.sendNotificationEmail(email, subject, message, {
      details: apiData,
    });
  },
};

module.exports = mockEmailService;
