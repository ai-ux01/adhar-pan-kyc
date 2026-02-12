const axios = require('axios');

console.log('🚀 Starting Simple API Hit Test...\n');

// API Configuration
const API_KEY = 'key_live_6edea225e1354559b2422d3921c795cf';
const API_SECRET = 'secret_live_03078556231c41879cd6ab46e1d6d6a07f';
const BASE_URL = 'https://api.sandbox.co.in';

console.log('📋 API Configuration:');
console.log('API Key:', API_KEY);
console.log('API Secret:', API_SECRET);
console.log('Base URL:', BASE_URL);
console.log('');

// Test 1: Simple Authentication
async function testAuthentication() {
  console.log('🔐 Test 1: Testing Authentication...');
  
  try {
    const options = {
      method: 'POST',
      url: `${BASE_URL}/authenticate`,
      headers: {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
        'x-api-secret': API_SECRET,
      },
      timeout: 10000,
    };

    console.log('📤 Sending authentication request...');
    console.log('URL:', options.url);
    console.log('Headers:', options.headers);
    console.log('');

    const response = await axios.request(options);
    
    console.log('✅ Authentication SUCCESS!');
    console.log('Status:', response.status);
    console.log('Status Text:', response.statusText);
    console.log('Headers:', response.headers);
    console.log('Data:', JSON.stringify(response.data, null, 2));
    console.log('');
    
    return response.data;
    
  } catch (error) {
    console.log('❌ Authentication FAILED!');
    
    if (error.response) {
      console.log('Response Status:', error.response.status);
      console.log('Response Headers:', error.response.headers);
      console.log('Response Data:', JSON.stringify(error.response.data, null, 2));
    } else if (error.request) {
      console.log('Request Error:', error.request);
    } else {
      console.log('Error:', error.message);
    }
    
    console.log('Full Error:', error);
    console.log('');
    return null;
  }
}

// Test 2: PAN Verification (if auth succeeds)
async function testPANVerification(accessToken) {
  if (!accessToken) {
    console.log('⏭️  Skipping PAN verification - no access token');
    return;
  }
  
  console.log('🔍 Test 2: Testing PAN Verification...');
  
  try {
    const testData = {
      "@entity": "in.co.sandbox.kyc.pan_verification.request",
      pan: "CHIPK8864R",
      name_as_per_pan: "Ashul Kumar",
      date_of_birth: "01/03/1990",
      consent: "Y",
      reason: "KYC Verification",
    };

    const options = {
      method: 'POST',
      url: `${BASE_URL}/kyc/pan/verify`,
      headers: {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'authorization': accessToken,
        'x-api-key': API_KEY,
        'x-accept-cache': 'true',
      },
      data: testData,
      timeout: 15000,
    };

    console.log('📤 Sending PAN verification request...');
    console.log('URL:', options.url);
    console.log('Headers:', options.headers);
    console.log('Data:', JSON.stringify(testData, null, 2));
    console.log('');

    const response = await axios.request(options);
    
    console.log('✅ PAN Verification SUCCESS!');
    console.log('Status:', response.status);
    console.log('Status Text:', response.statusText);
    console.log('Headers:', response.headers);
    console.log('Data:', JSON.stringify(response.data, null, 2));
    console.log('');
    
  } catch (error) {
    console.log('❌ PAN Verification FAILED!');
    
    if (error.response) {
      console.log('Response Status:', error.response.status);
      console.log('Response Headers:', error.response.headers);
      console.log('Response Data:', JSON.stringify(error.response.data, null, 2));
    } else if (error.request) {
      console.log('Request Error:', error.request);
    } else {
      console.log('Error:', error.message);
    }
    
    console.log('Full Error:', error);
    console.log('');
  }
}

// Test 3: Test different authentication methods
async function testDifferentAuthMethods() {
  console.log('🧪 Test 3: Testing Different Authentication Methods...\n');
  
  const authMethods = [
    {
      name: 'Method 1: Standard Headers',
      headers: {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
        'x-api-secret': API_SECRET,
      }
    },
    {
      name: 'Method 2: Authorization Header',
      headers: {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`,
        'x-api-secret': API_SECRET,
      }
    },
    {
      name: 'Method 3: Query Parameters',
      url: `${BASE_URL}/authenticate?api_key=${API_KEY}&api_secret=${API_SECRET}`,
      headers: {
        'accept': 'application/json',
        'Content-Type': 'application/json',
      }
    }
  ];

  for (const method of authMethods) {
    console.log(`🔍 Testing: ${method.name}`);
    
    try {
      const options = {
        method: 'POST',
        url: method.url || `${BASE_URL}/authenticate`,
        headers: method.headers,
        timeout: 10000,
      };

      console.log('Request:', options);
      
      const response = await axios.request(options);
      console.log('✅ SUCCESS:', response.status, response.statusText);
      console.log('Data:', JSON.stringify(response.data, null, 2));
      
    } catch (error) {
      console.log('❌ FAILED:', error.response?.status || error.message);
      if (error.response?.data) {
        console.log('Error Data:', JSON.stringify(error.response.data, null, 2));
      }
    }
    
    console.log('');
  }
}

// Main execution
async function runTests() {
  console.log('🧪 Running All Tests...\n');
  
  // Test 1: Authentication
  const authResult = await testAuthentication();
  
  // Test 2: PAN Verification (if auth succeeds)
  if (authResult && authResult.access_token) {
    await testPANVerification(authResult.access_token);
  } else if (authResult && authResult.data && authResult.data.access_token) {
    await testPANVerification(authResult.data.access_token);
  }
  
  // Test 3: Different auth methods
  await testDifferentAuthMethods();
  
  console.log('✨ All tests completed!');
}

// Run the tests
runTests().catch(console.error);
