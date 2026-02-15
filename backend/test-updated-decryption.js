const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function testUpdatedDecryption() {
  try {
    console.log('🔍 Testing updated decryption logic...');
    
    // Test the specific record that was showing encrypted data
    const recordId = '68bf271f9291804651b02352';
    const record = await PanKyc.findById(recordId);
    
    if (!record) {
      console.log('❌ Record not found');
      return;
    }
    
    console.log('Record ID:', record._id);
    console.log('Original PAN:', record.panNumber);
    console.log('Original Name:', record.name);
    console.log('Original DOB:', record.dateOfBirth);
    
    // Test decryption with updated logic
    console.log('\n--- Testing Updated Decryption ---');
    try {
      const decryptedRecord = record.decryptData();
      console.log('Decrypted PAN:', decryptedRecord.panNumber);
      console.log('Decrypted Name:', decryptedRecord.name);
      console.log('Decrypted DOB:', decryptedRecord.dateOfBirth);
      
      // Check if still encrypted
      if (decryptedRecord.panNumber.includes(':') || decryptedRecord.panNumber === '[ENCRYPTED]') {
        console.log('❌ PAN is still encrypted after updated decryption!');
      } else {
        console.log('✅ PAN is properly decrypted with updated logic');
      }
    } catch (error) {
      console.log('❌ Updated decryption failed:', error.message);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

testUpdatedDecryption();
