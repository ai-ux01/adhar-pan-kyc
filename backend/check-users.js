const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./src/models/User');
require('dotenv').config();

const checkUsers = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB');

    // Get all users
    const users = await User.find({}).select('+password');
    console.log('👥 Found users:', users.length);

    users.forEach(user => {
      console.log(`\n📋 User: ${user.email}`);
      console.log(`- Role: ${user.role}`);
      console.log(`- Active: ${user.isActive}`);
      console.log(`- Email Verified: ${user.isEmailVerified}`);
      console.log(`- Password length: ${user.password ? user.password.length : 0}`);
    });

    // Create a fresh user with proper password
    const freshPassword = await bcrypt.hash('password', 10);
    console.log('\n🔐 Fresh password hash length:', freshPassword.length);

    // Update admin user with fresh password and ensure isActive is true
    const adminUser = await User.findOne({ email: 'admin@kyc.com' });
    if (adminUser) {
      adminUser.password = freshPassword;
      adminUser.isActive = true;
      adminUser.isEmailVerified = true;
      await adminUser.save();
      console.log('✅ Updated admin user');
    }

    // Test the password
    const testUser = await User.findOne({ email: 'admin@kyc.com' }).select('+password');
    const isValid = await bcrypt.compare('password', testUser.password);
    console.log('🔍 Password verification test:', isValid ? 'PASSED' : 'FAILED');

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
};

checkUsers();
