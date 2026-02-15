const { verifyPAN } = require('./src/services/panVerificationService');

async function testPANVerification() {
  console.log('🧪 Testing PAN Verification Service...\n');

  try {
    // Test case 1: Valid PAN verification
    console.log('📋 Test Case 1: Valid PAN Verification');
    console.log('PAN: ABCDE1234F, Name: John Doe, DOB: 1990-05-15');
    
    const result1 = await verifyPAN('ABCDE1234F', 'John Doe', '1990-05-15', 'KYC Verification');
    console.log('Result:', JSON.stringify(result1, null, 2));
    console.log('✅ Test 1 completed\n');

    // Test case 2: Invalid PAN format
    console.log('📋 Test Case 2: Invalid PAN Format');
    console.log('PAN: INVALID123, Name: Jane Smith, DOB: 1985-12-20');
    
    const result2 = await verifyPAN('INVALID123', 'Jane Smith', '1985-12-20', 'KYC Verification');
    console.log('Result:', JSON.stringify(result2, null, 2));
    console.log('✅ Test 2 completed\n');

    // Test case 3: Missing name
    console.log('📋 Test Case 3: Missing Name');
    console.log('PAN: FGHIJ5678K, Name: "", DOB: 1995-08-10');
    
    const result3 = await verifyPAN('FGHIJ5678K', '', '1995-08-10', 'KYC Verification');
    console.log('Result:', JSON.stringify(result3, null, 2));
    console.log('✅ Test 3 completed\n');

  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

// Run the test
testPANVerification();
