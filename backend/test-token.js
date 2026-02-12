const mongoose = require('mongoose');
const User = require('./src/models/User');
const jwt = require('jsonwebtoken');

async function getTestToken() {
  try {
    await mongoose.connect('mongodb://localhost:27017/kyc-aadhaar-app');
    console.log('Connected to MongoDB');
    
    const adminUser = await User.findOne({ role: 'admin' });
    if (!adminUser) {
      console.log('No admin user found');
      return;
    }
    
    console.log('Admin user found:', adminUser.email);
    
    const token = jwt.sign(
      { id: adminUser._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '1h' }
    );
    
    console.log('Test token:', token);
    
    await mongoose.disconnect();
  } catch (error) {
    console.error('Error:', error);
  }
}

getTestToken();
