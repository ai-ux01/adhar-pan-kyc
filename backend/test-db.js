const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./src/models/User');
require('dotenv').config();

const testDatabase = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB');

    // Check existing users
    const users = await User.find({});
    console.log('👥 Existing users:', users.length);
    users.forEach(user => {
      console.log(`- ${user.email} (${user.role})`);
    });

    // Create a test user with proper password hash
    const hashedPassword = await bcrypt.hash('password', 10);
    console.log('🔐 Password hash created');

    const testUser = new User({
      name: 'Test Admin',
      email: 'test@kyc.com',
      password: hashedPassword,
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

    await testUser.save();
    console.log('✅ Test user created: test@kyc.com / password');

    // Test password verification
    const user = await User.findOne({ email: 'test@kyc.com' });
    const isValid = await bcrypt.compare('password', user.password);
    console.log('🔍 Password verification test:', isValid ? 'PASSED' : 'FAILED');

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
};

testDatabase();
