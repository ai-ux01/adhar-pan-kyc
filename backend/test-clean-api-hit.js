const axios = require('axios');

console.log('🚀 Testing Sandbox API...\n');

// API Configuration
const API_KEY = 'key_live_6edea225e1354559b2422d3921c795cf';
const API_SECRET = 'secret_live_03078556231c41879cd6ab46e1d6d6a07f';

console.log('📋 Using API Key:', API_KEY);
console.log('📋 Using API Secret:', API_SECRET.substring(0, 20) + '...');
console.log('');

// Test Authentication
async function testAuth() {
  try {
    console.log('🔐 Testing Authentication...');
    
    const response = await axios.post('https://api.sandbox.co.in/authenticate', {}, {
      headers: {
        'x-api-key': API_KEY,
        'x-api-secret': API_SECRET,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    
    console.log('✅ SUCCESS!');
    console.log('Status:', response.status);
    console.log('Access Token:', response.data.access_token ? 'YES' : 'NO');
    console.log('Response:', JSON.stringify(response.data, null, 2));
    
  } catch (error) {
    console.log('❌ FAILED!');
    console.log('Status:', error.response?.status || 'No Response');
    console.log('Message:', error.response?.data?.message || error.message);
    console.log('Code:', error.response?.data?.code || 'N/A');
    console.log('Transaction ID:', error.response?.data?.transaction_id || 'N/A');
  }
}

// Test PAN Verification
async function testPANVerification() {
  try {
    console.log('\n🔍 Testing PAN Verification...');
    
    // First authenticate
    const authResponse = await axios.post('https://api.sandbox.co.in/authenticate', {}, {
      headers: {
        'x-api-key': API_KEY,
        'x-api-secret': API_SECRET,
        'Content-Type': 'application/json'
      }
    });
    
    const accessToken = authResponse.data.access_token;
    console.log('✅ Authentication successful, got token');
    
    // Now verify PAN
    const panData = {
      "@entity": "in.co.sandbox.kyc.pan_verification.request",
      pan: "CHIPK8864R",
      name_as_per_pan: "Ashul Kumar",
      date_of_birth: "01/03/1990",
      consent: "Y",
      reason: "KYC Verification"
    };
    
    const verifyResponse = await axios.post('https://api.sandbox.co.in/kyc/pan/verify', panData, {
      headers: {
        'authorization': accessToken,
        'x-api-key': API_KEY,
        'Content-Type': 'application/json'
      }
    });
    
    console.log('✅ PAN Verification successful!');
    console.log('Status:', verifyResponse.status);
    console.log('Response:', JSON.stringify(verifyResponse.data, null, 2));
    
  } catch (error) {
    console.log('❌ PAN Verification failed!');
    console.log('Status:', error.response?.status || 'No Response');
    console.log('Message:', error.response?.data?.message || error.message);
  }
}

// Run tests
async function runTests() {
  await testAuth();
  await testPANVerification();
  console.log('\n✨ Test completed!');
}

runTests();
