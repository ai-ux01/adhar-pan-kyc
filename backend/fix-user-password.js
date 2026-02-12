const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Import User model
const User = require('./src/models/User');
const bcrypt = require('bcryptjs');

async function fixUserPassword() {
  try {
    const userEmail = 'user@kyc.com';
    const newPassword = 'password12';
    
    // Find the user
    const user = await User.findOne({ email: userEmail });
    
    if (!user) {
      console.log('User not found');
      return;
    }
    
    console.log('=== BEFORE PASSWORD UPDATE ===');
    console.log('User details:', {
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      hasPassword: !!user.password,
      passwordLength: user.password ? user.password.length : 0,
      loginAttempts: user.loginAttempts,
      lockUntil: user.lockUntil,
      isLocked: user.isLocked
    });
    
    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update the user with new password and unlock account
    user.password = hashedPassword;
    user.loginAttempts = 0;
    user.lockUntil = null;
    
    // Save the changes
    await user.save();
    
    console.log('\n=== AFTER PASSWORD UPDATE ===');
    console.log('Updated user details:', {
      hasPassword: !!user.password,
      passwordLength: user.password ? user.password.length : 0,
      loginAttempts: user.loginAttempts,
      lockUntil: user.lockUntil,
      isLocked: user.isLocked
    });
    
    // Verify the password works
    const testUser = await User.findOne({ email: userEmail }).select('+password');
    const isPasswordValid = await bcrypt.compare(newPassword, testUser.password);
    
    console.log('\n=== PASSWORD VERIFICATION ===');
    console.log('Password verification result:', isPasswordValid);
    
    if (isPasswordValid) {
      console.log('\n✅ Password set successfully!');
      console.log('User can now login with:');
      console.log(`Email: ${userEmail}`);
      console.log(`Password: ${newPassword}`);
    } else {
      console.log('\n❌ Password verification failed!');
    }
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

fixUserPassword();
