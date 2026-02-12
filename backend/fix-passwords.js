const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./src/models/User');
require('dotenv').config();

const fixPasswords = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB');

    // Update admin user
    const adminUser = await User.findOne({ email: 'admin@kyc.com' });
    if (adminUser) {
      // Force update without triggering pre-save middleware
      await User.updateOne(
        { _id: adminUser._id },
        { password: await bcrypt.hash('password', 10) }
      );
      console.log('✅ Updated admin@kyc.com password');
    }

    // Update regular user
    const regularUser = await User.findOne({ email: 'user@kyc.com' });
    if (regularUser) {
      // Force update without triggering pre-save middleware
      await User.updateOne(
        { _id: regularUser._id },
        { password: await bcrypt.hash('password', 10) }
      );
      console.log('✅ Updated user@kyc.com password');
    }

    // Test login
    const testUser = await User.findOne({ email: 'admin@kyc.com' });
    if (testUser && testUser.password) {
      const isValid = await bcrypt.compare('password', testUser.password);
      console.log('🔍 Password verification test:', isValid ? 'PASSED' : 'FAILED');
    } else {
      console.log('🔍 Password verification test: SKIPPED (user not found)');
    }

    console.log('\n📋 Updated Login Credentials:');
    console.log('Admin: admin@kyc.com / password');
    console.log('User: user@kyc.com / password');

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
};

fixPasswords();
