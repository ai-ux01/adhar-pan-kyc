#!/usr/bin/env node

/**
 * Script to reset rate limiting and user lockouts
 * This helps when testing login functionality
 */

const mongoose = require('mongoose');
const User = require('./src/models/User');

async function resetAllLimits() {
  try {
    console.log('🔄 Connecting to database...');
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/kyc-aadhaar-app');
    
    console.log('🔓 Resetting user login attempts and locks...');
    const result = await User.updateMany(
      {},
      {
        $unset: { loginAttempts: 1, lockUntil: 1 }
      }
    );
    
    console.log(`✅ Reset login attempts for ${result.modifiedCount} users`);
    
    // Check all users status
    console.log('\n📊 Current user status:');
    const users = await User.find({}, 'email loginAttempts lockUntil isActive').limit(10);
    users.forEach(user => {
      console.log(`- ${user.email}: attempts=${user.loginAttempts || 0}, locked=${user.isLocked}, active=${user.isActive}`);
    });
    
    console.log('\n💡 Note: Rate limiting is IP-based and resets automatically after 15 minutes');
    console.log('   If you still get rate limit errors, try:');
    console.log('   1. Wait 15 minutes');
    console.log('   2. Restart the server');
    console.log('   3. Use a different IP/network');
    
    await mongoose.disconnect();
    console.log('\n✅ Database disconnected');
    
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

// Run the script
resetAllLimits();
