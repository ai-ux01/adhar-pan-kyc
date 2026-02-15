const axios = require('axios');

// Test configuration
const BASE_URL = 'http://localhost:3002';
const TEST_TOKEN = 'your-test-jwt-token-here'; // You'll need to get this from login

// Test data
const testPANData = {
  panNumber: 'ABCDE1234F',
  name: 'John Doe',
  dateOfBirth: '1990-05-15',
  reason: 'KYC Verification'
};

async function testSingleVerificationNoFallback() {
  console.log('🧪 Testing Single PAN Verification (No Fallback Mode)...\n');
  
  try {
    const response = await axios.post(`${BASE_URL}/api/pan-kyc/verify-single`, testPANData, {
      headers: {
        'Authorization': `Bearer ${TEST_TOKEN}`,
        'Content-Type': 'application/json'
      }
    });

    console.log('✅ Single Verification Response:');
    console.log('Status:', response.status);
    console.log('Success:', response.data.success);
    console.log('Message:', response.data.message);
    console.log('Data:', JSON.stringify(response.data.data, null, 2));
    
    // Check if Sandbox API response is included
    if (response.data.data.sandboxApiResponse) {
      console.log('\n🔍 Sandbox API Response Found:');
      console.log(JSON.stringify(response.data.data.sandboxApiResponse, null, 2));
    } else {
      console.log('\n⚠️  No Sandbox API Response');
    }
    
  } catch (error) {
    console.error('❌ Single Verification Test Failed:');
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
      console.error('Error source:', error.response.data.source);
    } else {
      console.error('Error:', error.message);
    }
  }
}

async function testBatchVerificationNoFallback() {
  console.log('\n🧪 Testing Batch PAN Verification (No Fallback Mode)...\n');
  
  try {
    const response = await axios.post(`${BASE_URL}/api/pan-kyc/verify`, {
      batchId: 'TEST_BATCH_' + Date.now()
    }, {
      headers: {
        'Authorization': `Bearer ${TEST_TOKEN}`,
        'Content-Type': 'application/json'
      }
    });

    console.log('✅ Batch Verification Response:');
    console.log('Status:', response.status);
    console.log('Success:', response.data.success);
    console.log('Message:', response.data.message);
    console.log('Data:', JSON.stringify(response.data.data, null, 2));
    
    // Check source breakdown
    if (response.data.data.sourceBreakdown) {
      console.log('\n📊 Source Breakdown:');
      console.log(JSON.stringify(response.data.data.sourceBreakdown, null, 2));
    }
    
    // Check individual results
    if (response.data.data.results && response.data.data.results.length > 0) {
      console.log('\n🔍 Individual Results:');
      response.data.data.results.forEach((result, index) => {
        console.log(`\nRecord ${index + 1}:`);
        console.log('  Status:', result.status);
        console.log('  Source:', result.source);
        if (result.sandboxApiResponse) {
          console.log('  Sandbox API Response:', JSON.stringify(result.sandboxApiResponse, null, 2));
        } else {
          console.log('  No Sandbox API Response');
        }
        if (result.error) {
          console.log('  Error:', result.error);
        }
      });
    }
    
  } catch (error) {
    console.error('❌ Batch Verification Test Failed:');
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    } else {
      console.error('Error:', error.message);
    }
  }
}

async function runTests() {
  console.log('🚀 Starting PAN Verification Tests (No Fallback Mode)...\n');
  
  if (TEST_TOKEN === 'your-test-jwt-token-here') {
    console.log('⚠️  Please update TEST_TOKEN with a valid JWT token from login');
    console.log('   You can get this by logging in through your frontend application\n');
    return;
  }
  
  await testSingleVerificationNoFallback();
  await testBatchVerificationNoFallback();
  
  console.log('\n✨ All tests completed!');
  console.log('\n📝 Expected Behavior:');
  console.log('  - If Sandbox API works: You\'ll get real verification results');
  console.log('  - If Sandbox API fails: You\'ll get error responses (no simulation)');
  console.log('  - Source will always be "sandbox_api" or "sandbox_api_failure"');
}

// Run tests
runTests();
