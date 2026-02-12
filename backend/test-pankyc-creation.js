const mongoose = require('mongoose');
const PanKyc = require('./src/models/PanKyc');
require('dotenv').config();

const testPanKycCreation = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('🗄️  Connected to MongoDB');

    // Test data
    const testData = {
      userId: new mongoose.Types.ObjectId(), // Create a dummy ObjectId
      batchId: 'TEST_BATCH_123',
      panNumber: 'ABCDE1234F',
      name: 'John Doe',
      dateOfBirth: '1990-01-01',
      fatherName: 'James Doe'
    };

    console.log('🔍 Test data before creation:');
    console.log(JSON.stringify(testData, null, 2));
    console.log('');

    // Try to create the document
    console.log('🔍 Creating PanKyc document...');
    const record = new PanKyc(testData);
    
    console.log('🔍 Document created, checking fields:');
    console.log('panNumber:', record.panNumber);
    console.log('name:', record.name);
    console.log('dateOfBirth:', record.dateOfBirth);
    console.log('fatherName:', record.fatherName);
    console.log('');

    console.log('🔍 Field types:');
    console.log('panNumber type:', typeof record.panNumber);
    console.log('name type:', typeof record.name);
    console.log('dateOfBirth type:', typeof record.dateOfBirth);
    console.log('fatherName type:', typeof record.fatherName);
    console.log('');

    console.log('🔍 Field lengths:');
    console.log('panNumber length:', record.panNumber ? record.panNumber.length : 0);
    console.log('name length:', record.name ? record.name.length : 0);
    console.log('dateOfBirth length:', record.dateOfBirth ? record.dateOfBirth.length : 0);
    console.log('fatherName length:', record.fatherName ? record.fatherName.length : 0);
    console.log('');

    console.log('🔍 Truthy check:');
    console.log('panNumber truthy:', !!record.panNumber);
    console.log('name truthy:', !!record.name);
    console.log('dateOfBirth truthy:', !!record.dateOfBirth);
    console.log('fatherName truthy:', !!record.fatherName);
    console.log('');

    // Try to validate
    console.log('🔍 Running validation...');
    try {
      await record.validate();
      console.log('✅ Validation passed');
    } catch (validationError) {
      console.log('❌ Validation failed:');
      console.log(validationError.message);
      console.log('Validation errors:', validationError.errors);
    }

    // Try to save
    console.log('🔍 Trying to save...');
    try {
      await record.save();
      console.log('✅ Save successful');
    } catch (saveError) {
      console.log('❌ Save failed:');
      console.log(saveError.message);
    }

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
  }
};

testPanKycCreation();
