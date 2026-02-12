const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./src/models/User');
require('dotenv').config();

const fixPasswordDirect = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB');

    // Create fresh password hash
    const freshPassword = await bcrypt.hash('password', 10);
    console.log('🔐 Fresh password hash created');

    // Update admin user directly in database (bypassing pre-save hook)
    const result = await User.updateOne(
      { email: 'admin@kyc.com' },
      { 
        $set: { 
          password: freshPassword,
          isActive: true,
          isEmailVerified: true
        }
      }
    );
    console.log('✅ Updated admin user directly:', result.modifiedCount, 'documents');

    // Update regular user
    const result2 = await User.updateOne(
      { email: 'user@kyc.com' },
      { 
        $set: { 
          password: freshPassword,
          isActive: true,
          isEmailVerified: true
        }
      }
    );
    console.log('✅ Updated regular user directly:', result2.modifiedCount, 'documents');

    // Test the password
    const testUser = await User.findOne({ email: 'admin@kyc.com' }).select('+password');
    const isValid = await bcrypt.compare('password', testUser.password);
    console.log('🔍 Password verification test:', isValid ? 'PASSED' : 'FAILED');

    console.log('\n📋 Login Credentials:');
    console.log('Admin: admin@kyc.com / password');
    console.log('User: user@kyc.com / password');

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
};

fixPasswordDirect();
