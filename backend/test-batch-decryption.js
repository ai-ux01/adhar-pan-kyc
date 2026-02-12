const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const PanKyc = require('./src/models/PanKyc');

async function testBatchDecryption() {
  try {
    console.log('🔍 Testing batch decryption...');
    
    // Find the specific batch
    const batchId = 'PAN aadhar KYC_1757357847231_kwb5r9';
    const records = await PanKyc.find({
      batchId: batchId
    }).sort({ createdAt: -1 });
    
    console.log('Found records:', records.length);
    
    if (records.length > 0) {
      const record = records[0];
      console.log('\n--- Original Record ---');
      console.log('ID:', record._id);
      console.log('PAN:', record.panNumber);
      console.log('Name:', record.name);
      console.log('DOB:', record.dateOfBirth);
      
      // Test the current method used in the route
      console.log('\n--- Testing Route Method ---');
      try {
        const tempDoc = new PanKyc(record);
        const decryptedRecord = tempDoc.decryptData();
        console.log('Decrypted PAN:', decryptedRecord.panNumber);
        console.log('Decrypted Name:', decryptedRecord.name);
        console.log('Decrypted DOB:', decryptedRecord.dateOfBirth);
      } catch (error) {
        console.log('❌ Route method failed:', error.message);
      }
      
      // Test direct method call
      console.log('\n--- Testing Direct Method ---');
      try {
        const decryptedRecord = record.decryptData();
        console.log('Decrypted PAN:', decryptedRecord.panNumber);
        console.log('Decrypted Name:', decryptedRecord.name);
        console.log('Decrypted DOB:', decryptedRecord.dateOfBirth);
      } catch (error) {
        console.log('❌ Direct method failed:', error.message);
      }
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

testBatchDecryption();
