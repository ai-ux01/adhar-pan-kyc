const { verifyPAN } = require('./src/services/panVerificationService');

// Test data
const testData = {
  panNumber: "CHIPK8864R",
  name: "Ashul Kumar",
  dateOfBirth: "1990-03-01",
  reason: "KYC Verification"
};

async function testUpdatedService() {
  console.log('🧪 Testing Updated Backend Service...\n');
  console.log('Test Data:', testData);
  console.log('');

  try {
    console.log('🔍 Calling our updated backend service...');
    
    const result = await verifyPAN(
      testData.panNumber,
      testData.name,
      testData.dateOfBirth,
      testData.reason
    );

    console.log('✅ SUCCESS! Backend service working!');
    console.log('Result:', JSON.stringify(result, null, 2));

    // Show key verification details
    console.log('\n📊 Verification Summary:');
    console.log('  Valid:', result.valid);
    console.log('  Message:', result.message);
    console.log('  Source:', result.details.source);
    console.log('  Name Match:', result.details.nameMatch);
    console.log('  DOB Match:', result.details.dobMatch);
    console.log('  Category:', result.details.category);
    console.log('  Aadhaar Seeding:', result.details.aadhaarSeedingStatus);

  } catch (error) {
    console.error("❌ Test failed!");
    console.error('Error:', error.message);
  }
}

// Run the test
console.log('🚀 Starting Updated Service Test...\n');
testUpdatedService();
