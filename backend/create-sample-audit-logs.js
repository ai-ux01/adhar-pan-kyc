const mongoose = require('mongoose');
const Audit = require('./src/models/Audit');

async function createSampleAuditLogs() {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/kyc-aadhaar-app');
    console.log('Connected to MongoDB');
    
    // Clear existing audit logs (optional)
    if (process.argv.includes('--clear')) {
      await Audit.deleteMany({});
      console.log('Cleared existing audit logs');
    }
    
    // Create sample audit logs with realistic timestamps
    const now = new Date();
    const sampleLogs = [
      {
        action: 'login',
        module: 'auth',
        resource: 'user',
        details: { email: 'admin@example.com' },
        ipAddress: '192.168.1.100',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 5) // 5 minutes ago
      },
      {
        action: 'user_created',
        module: 'admin',
        resource: 'user',
        details: { email: 'newuser@example.com', name: 'New User' },
        ipAddress: '192.168.1.100',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 15) // 15 minutes ago
      },
      {
        action: 'pan_kyc_upload',
        module: 'pan_kyc',
        resource: 'batch',
        details: { fileName: 'pan_data.xlsx', recordCount: 100 },
        ipAddress: '192.168.1.101',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 30) // 30 minutes ago
      },
      {
        action: 'aadhaar_pan_verification',
        module: 'aadhaar_pan',
        resource: 'record',
        details: { aadhaarNumber: '123456789012', panNumber: 'ABCDE1234F' },
        ipAddress: '192.168.1.102',
        userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 45) // 45 minutes ago
      },
      {
        action: 'login_failed',
        module: 'auth',
        resource: 'user',
        details: { email: 'invalid@example.com', error: 'Invalid credentials' },
        ipAddress: '192.168.1.103',
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0) AppleWebKit/605.1.15',
        status: 'failed',
        severity: 'medium',
        createdAt: new Date(now.getTime() - 1000 * 60 * 60) // 1 hour ago
      },
      {
        action: 'file_uploaded',
        module: 'pan_kyc',
        resource: 'file',
        details: { fileName: 'kyc_batch_2.xlsx', size: '2.5MB' },
        ipAddress: '192.168.1.100',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 90) // 1.5 hours ago
      },
      {
        action: 'user_updated',
        module: 'admin',
        resource: 'user',
        details: { email: 'user@example.com', changes: ['role', 'moduleAccess'] },
        ipAddress: '192.168.1.100',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 120) // 2 hours ago
      },
      {
        action: 'pan_kyc_api_call',
        module: 'pan_kyc',
        resource: 'api',
        details: { endpoint: '/api/pan-verification', responseTime: 1250 },
        ipAddress: '192.168.1.101',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 150) // 2.5 hours ago
      },
      {
        action: 'logout',
        module: 'auth',
        resource: 'user',
        details: { email: 'user@example.com' },
        ipAddress: '192.168.1.104',
        userAgent: 'Mozilla/5.0 (Android 10; Mobile; rv:68.0) Gecko/68.0',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 180) // 3 hours ago
      },
      {
        action: 'aadhaar_pan_batch_complete',
        module: 'aadhaar_pan',
        resource: 'batch',
        details: { batchId: 'batch_123', processedCount: 50, successCount: 48 },
        ipAddress: '192.168.1.102',
        userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 200) // 3.3 hours ago
      },
      {
        action: 'pan_kyc_verification',
        module: 'pan_kyc',
        resource: 'record',
        details: { panNumber: 'ABCDE1234F', status: 'verified' },
        ipAddress: '192.168.1.101',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 240) // 4 hours ago
      },
      {
        action: 'admin_action',
        module: 'admin',
        resource: 'system',
        details: { action: 'system_backup', status: 'completed' },
        ipAddress: '192.168.1.100',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        status: 'success',
        createdAt: new Date(now.getTime() - 1000 * 60 * 300) // 5 hours ago
      }
    ];
    
    await Audit.insertMany(sampleLogs);
    console.log('Created', sampleLogs.length, 'sample audit logs');
    
    const count = await Audit.countDocuments();
    console.log('Total audit logs now:', count);
    
    // Show recent logs
    const recentLogs = await Audit.find().sort({ createdAt: -1 }).limit(5);
    console.log('\nRecent audit logs:');
    recentLogs.forEach(log => {
      console.log(`- ${log.action} in ${log.module} at ${log.createdAt.toLocaleString()}`);
    });
    
    await mongoose.disconnect();
    console.log('\nDisconnected from MongoDB');
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

// Run the script
createSampleAuditLogs();

