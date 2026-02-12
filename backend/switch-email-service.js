const fs = require('fs');
const path = require('path');

// Switch between real and mock email service
const switchEmailService = (useMock = true) => {
  const emailServicePath = path.join(__dirname, 'src', 'services', 'emailService.js');
  const mockEmailServicePath = path.join(__dirname, 'src', 'services', 'emailService-test.js');
  
  if (useMock) {
    // Copy mock service to main service
    const mockContent = fs.readFileSync(mockEmailServicePath, 'utf8');
    fs.writeFileSync(emailServicePath, mockContent);
    console.log('✅ Switched to MOCK email service (emails will be logged to console)');
  } else {
    // Restore original service
    const originalContent = `const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

// Create transporter
const createTransporter = () => {
  return nodemailer.createTransporter({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_PORT === '465', // true for 465, false for other ports
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
};

// Send verification email
const sendVerificationEmail = async (email, token) => {
  try {
    const transporter = createTransporter();
    const verificationUrl = \`\${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email/\${token}\`;

    const mailOptions = {
      from: \`"KYC Aadhaar System" <\${process.env.SMTP_USER}>\`,
      to: email,
      subject: 'Verify Your Email Address',
      html: \`
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">KYC Aadhaar System</h1>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa;">
            <h2 style="color: #333; margin-bottom: 20px;">Verify Your Email Address</h2>
            
            <p style="color: #666; line-height: 1.6; margin-bottom: 25px;">
              Thank you for registering with our KYC Aadhaar System. To complete your registration, 
              please verify your email address by clicking the button below:
            </p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="\${verificationUrl}" 
                 style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; 
                        border-radius: 5px; display: inline-block; font-weight: bold;">
                Verify Email Address
              </a>
            </div>
            
            <p style="color: #666; line-height: 1.6; margin-bottom: 15px;">
              If the button doesn't work, you can copy and paste this link into your browser:
            </p>
            
            <p style="color: #667eea; word-break: break-all; margin-bottom: 25px;">
              \${verificationUrl}
            </p>
            
            <p style="color: #666; line-height: 1.6; margin-bottom: 15px;">
              This verification link will expire in 24 hours. If you didn't create an account, 
              you can safely ignore this email.
            </p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
            
            <p style="color: #999; font-size: 12px; text-align: center;">
              This is an automated email. Please do not reply to this message.
            </p>
          </div>
        </div>
      \`,
    };

    const info = await transporter.sendMail(mailOptions);
    logger.info(\`Verification email sent to \${email}: \${info.messageId}\`);
    return info;
  } catch (error) {
    logger.error('Failed to send verification email:', error);
    throw error;
  }
};

// Send password reset email
const sendPasswordResetEmail = async (email, token) => {
  try {
    const transporter = createTransporter();
    const resetUrl = \`\${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password/\${token}\`;

    const mailOptions = {
      from: \`"KYC Aadhaar System" <\${process.env.SMTP_USER}>\`,
      to: email,
      subject: 'Reset Your Password',
      html: \`
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">KYC Aadhaar System</h1>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa;">
            <h2 style="color: #333; margin-bottom: 20px;">Reset Your Password</h2>
            
            <p style="color: #666; line-height: 1.6; margin-bottom: 25px;">
              You requested to reset your password. Click the button below to create a new password:
            </p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="\${resetUrl}" 
                 style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; 
                        border-radius: 5px; display: inline-block; font-weight: bold;">
                Reset Password
              </a>
            </div>
            
            <p style="color: #666; line-height: 1.6; margin-bottom: 15px;">
              If the button doesn't work, you can copy and paste this link into your browser:
            </p>
            
            <p style="color: #667eea; word-break: break-all; margin-bottom: 25px;">
              \${resetUrl}
            </p>
            
            <p style="color: #666; line-height: 1.6; margin-bottom: 15px;">
              This reset link will expire in 10 minutes. If you didn't request a password reset, 
              you can safely ignore this email.
            </p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
            
            <p style="color: #999; font-size: 12px; text-align: center;">
              This is an automated email. Please do not reply to this message.
            </p>
          </div>
        </div>
      \`,
    };

    const info = await transporter.sendMail(mailOptions);
    logger.info(\`Password reset email sent to \${email}: \${info.messageId}\`);
    return info;
  } catch (error) {
    logger.error('Failed to send password reset email:', error);
    throw error;
  }
};

// Send notification email
const sendNotificationEmail = async (email, subject, message, data = {}) => {
  try {
    const transporter = createTransporter();

    const mailOptions = {
      from: \`"KYC Aadhaar System" <\${process.env.SMTP_USER}>\`,
      to: email,
      subject: subject,
      html: \`
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">KYC Aadhaar System</h1>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa;">
            <h2 style="color: #333; margin-bottom: 20px;">\${subject}</h2>
            
            <div style="color: #666; line-height: 1.6; margin-bottom: 25px;">
              \${message}
            </div>
            
            \${data.actionUrl ? \`
              <div style="text-align: center; margin: 30px 0;">
                <a href="\${data.actionUrl}" 
                   style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; 
                          border-radius: 5px; display: inline-block; font-weight: bold;">
                  \${data.actionText || 'View Details'}
                </a>
              </div>
            \` : ''}
            
            \${data.details ? \`
              <div style="background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h4 style="margin-top: 0; color: #333;">Details:</h4>
                <pre style="color: #666; margin: 0; white-space: pre-wrap;">\${JSON.stringify(data.details, null, 2)}</pre>
              </div>
            \` : ''}
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
            
            <p style="color: #999; font-size: 12px; text-align: center;">
              This is an automated email. Please do not reply to this message.
            </p>
          </div>
        </div>
      \`,
    };

    const info = await transporter.sendMail(mailOptions);
    logger.info(\`Notification email sent to \${email}: \${info.messageId}\`);
    return info;
  } catch (error) {
    logger.error('Failed to send notification email:', error);
    throw error;
  }
};

// Send batch completion notification
const sendBatchCompletionEmail = async (email, batchData) => {
  const subject = \`Batch Processing Complete - \${batchData.batchId}\`;
  const message = \`
    <p>Your batch processing has been completed successfully.</p>
    <p><strong>Batch ID:</strong> \${batchData.batchId}</p>
    <p><strong>Module:</strong> \${batchData.module}</p>
    <p><strong>Total Records:</strong> \${batchData.totalRecords}</p>
    <p><strong>Processing Time:</strong> \${batchData.processingTime}ms</p>
  \`;

  const details = {
    batchId: batchData.batchId,
    module: batchData.module,
    totalRecords: batchData.totalRecords,
    processedRecords: batchData.processedRecords,
    failedRecords: batchData.failedRecords,
    processingTime: batchData.processingTime,
    status: batchData.status,
  };

  return await sendNotificationEmail(email, subject, message, {
    actionUrl: \`\${process.env.FRONTEND_URL || 'http://localhost:3000'}/dashboard/\${batchData.module}/\${batchData.batchId}\`,
    actionText: 'View Batch Results',
    details,
  });
};

// Send error notification
const sendErrorNotificationEmail = async (email, errorData) => {
  const subject = \`System Error Alert - \${errorData.type}\`;
  const message = \`
    <p>A system error has occurred that requires your attention.</p>
    <p><strong>Error Type:</strong> \${errorData.type}</p>
    <p><strong>Severity:</strong> \${errorData.severity}</p>
    <p><strong>Timestamp:</strong> \${new Date(errorData.timestamp).toLocaleString()}</p>
  \`;

  return await sendNotificationEmail(email, subject, message, {
    details: errorData,
  });
};

// Send API failure notification
const sendApiFailureEmail = async (email, apiData) => {
  const subject = \`API Failure Alert - \${apiData.service}\`;
  const message = \`
    <p>An API service failure has been detected.</p>
    <p><strong>Service:</strong> \${apiData.service}</p>
    <p><strong>Error:</strong> \${apiData.error}</p>
    <p><strong>Timestamp:</strong> \${new Date(apiData.timestamp).toLocaleString()}</p>
  \`;

  return await sendNotificationEmail(email, subject, message, {
    details: apiData,
  });
};

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendNotificationEmail,
  sendBatchCompletionEmail,
  sendErrorNotificationEmail,
  sendApiFailureEmail,
};`;
    
    fs.writeFileSync(emailServicePath, originalContent);
    console.log('✅ Switched to REAL email service (requires SMTP configuration)');
  }
};

// Get command line argument
const useMock = process.argv[2] !== 'real';

console.log('🔄 Switching email service...');
switchEmailService(useMock);

if (useMock) {
  console.log('\n📝 To use real email service:');
  console.log('   1. Configure SMTP settings in .env file');
  console.log('   2. Run: node switch-email-service.js real');
  console.log('\n🧪 To test forgot password:');
  console.log('   1. Start your server: npm start');
  console.log('   2. Go to: http://localhost:3000/forgot-password');
  console.log('   3. Check console logs for email content');
} else {
  console.log('\n📧 To test real email service:');
  console.log('   1. Run: node test-email.js');
  console.log('   2. Check your email inbox');
}
