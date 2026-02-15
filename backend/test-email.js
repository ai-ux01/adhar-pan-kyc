const nodemailer = require('nodemailer');
require('dotenv').config();

// Test email configuration
const testEmailService = async () => {
  console.log('🔍 Testing Email Service Configuration...\n');
  
  // Check environment variables
  console.log('📧 SMTP Configuration:');
  console.log(`   Host: ${process.env.SMTP_HOST || 'NOT SET'}`);
  console.log(`   Port: ${process.env.SMTP_PORT || 'NOT SET'}`);
  console.log(`   User: ${process.env.SMTP_USER || 'NOT SET'}`);
  console.log(`   Pass: ${process.env.SMTP_PASS ? '***SET***' : 'NOT SET'}`);
  console.log(`   Frontend URL: ${process.env.FRONTEND_URL || 'NOT SET'}\n`);

  // Check if all required variables are set
  const requiredVars = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS'];
  const missingVars = requiredVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    console.log('❌ Missing required environment variables:');
    missingVars.forEach(varName => console.log(`   - ${varName}`));
    console.log('\n📝 Please set these variables in your .env file\n');
    return;
  }

  try {
    // Create transporter
    const transporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: process.env.SMTP_PORT === '465',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    console.log('🔧 Testing SMTP connection...');
    
    // Verify connection
    await transporter.verify();
    console.log('✅ SMTP connection successful!\n');

    // Test email
    const testEmail = process.env.SMTP_USER; // Send to yourself
    console.log(`📤 Sending test email to: ${testEmail}`);
    
    const mailOptions = {
      from: `"KYC Aadhaar System" <${process.env.SMTP_USER}>`,
      to: testEmail,
      subject: 'Test Email - KYC Aadhaar System',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">KYC Aadhaar System</h1>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa;">
            <h2 style="color: #333; margin-bottom: 20px;">Email Service Test</h2>
            
            <p style="color: #666; line-height: 1.6; margin-bottom: 25px;">
              This is a test email to verify that the email service is working correctly.
            </p>
            
            <div style="background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0;">
              <h4 style="margin-top: 0; color: #333;">Test Details:</h4>
              <p style="color: #666; margin: 0;">
                <strong>Timestamp:</strong> ${new Date().toLocaleString()}<br>
                <strong>SMTP Host:</strong> ${process.env.SMTP_HOST}<br>
                <strong>SMTP Port:</strong> ${process.env.SMTP_PORT}<br>
                <strong>From:</strong> ${process.env.SMTP_USER}
              </p>
            </div>
            
            <p style="color: #666; line-height: 1.6; margin-bottom: 15px;">
              If you received this email, your email service is configured correctly!
            </p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
            
            <p style="color: #999; font-size: 12px; text-align: center;">
              This is a test email from the KYC Aadhaar System.
            </p>
          </div>
        </div>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Test email sent successfully!');
    console.log(`   Message ID: ${info.messageId}`);
    console.log(`   Response: ${info.response}\n`);
    
    console.log('🎉 Email service is working correctly!');
    console.log('   You should receive the test email shortly.\n');

  } catch (error) {
    console.log('❌ Email service test failed:');
    console.log(`   Error: ${error.message}\n`);
    
    if (error.code === 'EAUTH') {
      console.log('🔐 Authentication failed. Please check:');
      console.log('   1. Your email address is correct');
      console.log('   2. You are using an App Password (not your regular password)');
      console.log('   3. 2-Factor Authentication is enabled on your email account\n');
    } else if (error.code === 'ECONNECTION') {
      console.log('🌐 Connection failed. Please check:');
      console.log('   1. SMTP_HOST is correct');
      console.log('   2. SMTP_PORT is correct');
      console.log('   3. Your internet connection is working\n');
    }
    
    console.log('📚 Common solutions:');
    console.log('   For Gmail:');
    console.log('   1. Enable 2-Factor Authentication');
    console.log('   2. Generate an App Password');
    console.log('   3. Use the App Password in SMTP_PASS\n');
  }
};

// Run the test
testEmailService().catch(console.error);
