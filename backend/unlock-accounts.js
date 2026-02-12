const mongoose = require('mongoose');
const User = require('./src/models/User');
require('dotenv').config();

const unlockAccounts = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB');

    // Unlock all accounts by resetting login attempts and lockUntil
    const result = await User.updateMany(
      { lockUntil: { $exists: true } },
      { 
        $unset: { loginAttempts: 1, lockUntil: 1 },
        $set: { lastLogin: null }
      }
    );

    console.log(`✅ Unlocked ${result.modifiedCount} accounts`);

    // Show current user status
    const users = await User.find({}, 'email role isActive loginAttempts lockUntil');
    console.log('\n📋 Current User Status:');
    users.forEach(user => {
      console.log(`${user.email} (${user.role}): ${user.isActive ? 'Active' : 'Inactive'}`);
    });

    console.log('\n🔑 You can now login with:');
    console.log('Admin: admin@kyc.com / password');
    console.log('User: user@kyc.com / password');

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
};

unlockAccounts();
