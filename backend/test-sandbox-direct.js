const { verifyPAN, authenticateWithSandbox } = require('./src/services/panVerificationService');

// Test data
const testData = {
  panNumber: "CHIPK8864R",
  name: "Ashul Kumar",
  dateOfBirth: "1990-03-01",
  reason: "KYC Verification"
};

async function testSandboxDirect() {
  console.log('🚀 Testing Direct Sandbox API Integration...\n');
  console.log('Test Data:', testData);
  console.log('');

  try {
    console.log('🔍 Testing Sandbox Authentication...');
    const accessToken = await authenticateWithSandbox();
    console.log('✅ Authentication successful!');
    console.log('Access Token:', accessToken.substring(0, 20) + '...');
    console.log('');

    console.log('🔍 Testing PAN Verification...');
    const result = await verifyPAN(
      testData.panNumber,
      testData.name,
      testData.dateOfBirth,
      testData.reason
    );

    console.log('✅ PAN Verification successful!');
    console.log('Result:', JSON.stringify(result, null, 2));

  } catch (error) {
    console.error('❌ Test failed!');
    console.error('Error:', error.message);
    
    if (error.stack) {
      console.error('Stack:', error.stack);
    }
  }
}

async function testWithDifferentData() {
  console.log('\n🧪 Testing with different PAN data...\n');
  
  const testCases = [
    {
      panNumber: "ABCDE1234F",
      name: "Test User",
      dateOfBirth: "1985-06-15",
      reason: "Test Verification"
    },
    {
      panNumber: "XYZAB5678G",
      name: "Sample Name",
      dateOfBirth: "1992-12-25",
      reason: "Sample Verification"
    }
  ];

  for (const testCase of testCases) {
    try {
      console.log(`🔍 Testing: ${testCase.panNumber}`);
      const result = await verifyPAN(
        testCase.panNumber,
        testCase.name,
        testCase.dateOfBirth,
        testCase.reason
      );
      
      console.log(`✅ Success: ${result.valid ? 'Valid' : 'Invalid'} PAN`);
      console.log(`   Message: ${result.message}`);
      console.log(`   Source: ${result.details.source}`);
      console.log('');
      
    } catch (error) {
      console.error(`❌ Failed: ${error.message}`);
      console.log('');
    }
  }
}

async function runTests() {
  console.log('🧪 Starting Direct Sandbox API Tests...\n');
  
  await testSandboxDirect();
  await testWithDifferentData();
  
  console.log('✨ All tests completed!');
}

runTests();
