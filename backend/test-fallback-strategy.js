const { verifyPAN } = require('./src/services/panVerificationService');

// Test data
const testData = {
  panNumber: "CHIPK8864R",
  name: "Ashul Kumar",
  dateOfBirth: "1990-03-01",
  reason: "KYC Verification"
};

async function testFallbackStrategy() {
  console.log('🚀 Testing Fallback Strategy...\n');
  console.log('Strategy: Try Sandbox API first, fallback to Next.js API if needed');
  console.log('Test Data:', testData);
  console.log('');

  try {
    console.log('🔍 Testing PAN Verification with Fallback...');
    const result = await verifyPAN(
      testData.panNumber,
      testData.name,
      testData.dateOfBirth,
      testData.reason
    );

    console.log('✅ PAN Verification successful!');
    console.log('Source:', result.details.source);
    console.log('Valid:', result.valid);
    console.log('Message:', result.message);
    console.log('Confidence:', result.details.confidence);
    console.log('Transaction ID:', result.details.transactionId);
    console.log('');
    console.log('Full Result:', JSON.stringify(result, null, 2));

  } catch (error) {
    console.error('❌ Test failed!');
    console.error('Error:', error.message);
    
    if (error.stack) {
      console.error('Stack:', error.stack);
    }
  }
}

async function testMultiplePANs() {
  console.log('\n🧪 Testing Multiple PANs with Fallback...\n');
  
  const testCases = [
    {
      panNumber: "CHIPK8864R",
      name: "Ashul Kumar",
      dateOfBirth: "1990-03-01",
      reason: "KYC Verification"
    },
    {
      panNumber: "ABCDE1234F",
      name: "Test User",
      dateOfBirth: "1985-06-15",
      reason: "Test Verification"
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
      console.log(`   Source: ${result.details.source}`);
      console.log(`   Confidence: ${result.details.confidence}`);
      console.log(`   Transaction ID: ${result.details.transactionId}`);
      console.log('');
      
    } catch (error) {
      console.error(`❌ Failed: ${error.message}`);
      console.log('');
    }
  }
}

async function runTests() {
  console.log('🧪 Starting Fallback Strategy Tests...\n');
  
  await testFallbackStrategy();
  await testMultiplePANs();
  
  console.log('✨ All tests completed!');
}

runTests();
