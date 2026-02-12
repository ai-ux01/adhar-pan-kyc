const mongoose = require('mongoose');
const User = require('./backend/src/models/User');
require('dotenv').config();

async function testLogin() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');
    
    const user = await User.findOne({ email: 'admin@kyc.com' }).select('+password');
    console.log('User found:', !!user);
    
    if (user) {
      console.log('User isActive:', user.isActive);
      console.log('User isLocked:', user.isLocked);
      console.log('User status:', user.status);
      console.log('User loginAttempts:', user.loginAttempts);
      
      const isMatch = await user.matchPassword('password');
      console.log('Password match:', isMatch);
    }
    
    await mongoose.disconnect();
    console.log('Disconnected from MongoDB');
  } catch (error) {
    console.error('Error:', error);
  }
}

testLogin();
