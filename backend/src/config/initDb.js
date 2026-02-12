const mongoose = require('mongoose');
const User = require('../models/User');
const PanKyc = require('../models/PanKyc');
const AadhaarPan = require('../models/AadhaarPan');
const Audit = require('../models/Audit');
require('dotenv').config();

const initializeDatabase = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB for initialization');

    // Clear existing data (optional - comment out if you want to keep existing data)
    await User.deleteMany({});
    await PanKyc.deleteMany({});
    await AadhaarPan.deleteMany({});
    await Audit.deleteMany({});
    console.log('🧹 Cleared existing data');

    // Create admin user
    const adminUser = new User({
      name: 'Admin User',
      email: 'admin@kyc.com',
      password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
      role: 'admin',
      isEmailVerified: true,
      moduleAccess: ['pan-kyc', 'aadhaar-pan'],
      preferences: {
        notifications: {
          email: true,
          sms: false,
          push: true
        },
        theme: 'light',
        language: 'en'
      }
    });

    await adminUser.save();
    console.log('👤 Created admin user: admin@kyc.com (password: password)');

    // Create regular user
    const regularUser = new User({
      name: 'Test User',
      email: 'user@kyc.com',
      password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
      role: 'user',
      isEmailVerified: true,
      moduleAccess: ['pan-kyc'],
      preferences: {
        notifications: {
          email: true,
          sms: false,
          push: true
        },
        theme: 'light',
        language: 'en'
      }
    });

    await regularUser.save();
    console.log('👤 Created regular user: user@kyc.com (password: password)');

    // Create sample PAN KYC records
    const samplePanKyc = [
      {
        userId: adminUser._id,
        batchId: 'BATCH001',
        panNumber: 'ABCDE1234F',
        name: 'John Doe',
        dateOfBirth: '1990-01-15',
        fatherName: 'Robert Doe',
        status: 'verified',
        verificationDetails: {
          verifiedName: 'John Doe',
          verifiedDob: '1990-01-15',
          verifiedFatherName: 'Robert Doe',
          verificationDate: new Date(),
          remarks: 'Successfully verified'
        },
        isProcessed: true,
        processedAt: new Date()
      },
      {
        userId: regularUser._id,
        batchId: 'BATCH002',
        panNumber: 'FGHIJ5678K',
        name: 'Jane Smith',
        dateOfBirth: '1985-05-20',
        fatherName: 'Michael Smith',
        status: 'pending',
        verificationDetails: {
          remarks: 'Under review'
        }
      }
    ];

    await PanKyc.insertMany(samplePanKyc);
    console.log('📄 Created sample PAN KYC records');

    // Create sample Aadhaar-PAN linking records
    const sampleAadhaarPan = [
      {
        userId: adminUser._id,
        batchId: 'AADHAAR001',
        aadhaarNumber: '123456789012',
        panNumber: 'ABCDE1234F',
        name: 'John Doe',
        dateOfBirth: '1990-01-15',
        gender: 'M',
        status: 'linked',
        linkingDetails: {
          linkingDate: new Date(),
          linkingStatus: 'linked',
          remarks: 'Successfully linked',
          lastChecked: new Date()
        },
        isProcessed: true,
        processedAt: new Date()
      },
      {
        userId: regularUser._id,
        batchId: 'AADHAAR002',
        aadhaarNumber: '987654321098',
        panNumber: 'FGHIJ5678K',
        name: 'Jane Smith',
        dateOfBirth: '1985-05-20',
        gender: 'F',
        status: 'not-linked',
        linkingDetails: {
          linkingStatus: 'not-linked',
          remarks: 'No match found',
          lastChecked: new Date()
        },
        isProcessed: true,
        processedAt: new Date()
      }
    ];

    await AadhaarPan.insertMany(sampleAadhaarPan);
    console.log('🔗 Created sample Aadhaar-PAN linking records');

    // Create sample audit logs
    const sampleAuditLogs = [
      {
        userId: adminUser._id,
        action: 'user_created',
        module: 'auth',
        resource: 'user',
        resourceId: adminUser._id,
        details: { email: adminUser.email, role: adminUser.role },
        ipAddress: '127.0.0.1',
        userAgent: 'Database Initialization'
      },
      {
        userId: regularUser._id,
        action: 'user_created',
        module: 'auth',
        resource: 'user',
        resourceId: regularUser._id,
        details: { email: regularUser.email, role: regularUser.role },
        ipAddress: '127.0.0.1',
        userAgent: 'Database Initialization'
      }
    ];

    await Audit.insertMany(sampleAuditLogs);
    console.log('📝 Created sample audit logs');

    console.log('✅ Database initialization completed successfully!');
    console.log('\n📋 Login Credentials:');
    console.log('Admin: admin@kyc.com / password');
    console.log('User: user@kyc.com / password');

  } catch (error) {
    console.error('❌ Database initialization failed:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
};

// Run initialization if this file is executed directly
if (require.main === module) {
  initializeDatabase();
}

module.exports = initializeDatabase;
