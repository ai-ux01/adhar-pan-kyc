const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./src/models/User');
require('dotenv').config();

const testPassword = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB');

    // Find the admin user
    const user = await User.findOne({ email: 'admin@kyc.com' }).select('+password');
    
    if (!user) {
      console.log('❌ User not found');
      return;
    }

    console.log('👤 Found user:', user.email);
    console.log('🔐 Password field exists:', !!user.password);
    console.log('🔐 Password length:', user.password ? user.password.length : 0);
    console.log('🔐 Password starts with $2b$:', user.password ? user.password.startsWith('$2b$') : false);

    // Test password comparison
    const testPassword = 'password';
    const isMatch = await bcrypt.compare(testPassword, user.password);
    console.log('🔍 Password match test:', isMatch);

    // Test using the model method
    const modelMatch = await user.matchPassword(testPassword);
    console.log('🔍 Model method test:', modelMatch);

    // Create a new hash for comparison
    const newHash = await bcrypt.hash(testPassword, 10);
    console.log('🆕 New hash created:', newHash.startsWith('$2b$'));

    // Test with new hash
    const newHashMatch = await bcrypt.compare(testPassword, newHash);
    console.log('🔍 New hash test:', newHashMatch);

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
};

testPassword();
