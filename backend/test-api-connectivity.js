const axios = require('axios');

// Test your Next.js API endpoint
const API_URL = 'http://192.168.31.82:3000/api/verify-pan';

// Test data
const testData = {
  pan: "CHIPK8864R",
  dob: "1990-03-01",
  name_as_per_pan: "Ashul Kumar",
  reason: "test"
};

async function testAPIConnectivity() {
  console.log('🧪 Testing API Connectivity and Response...\n');
  console.log('API URL:', API_URL);
  console.log('Test Data:', testData);
  console.log('');

  try {
    console.log('🔍 Testing API connectivity...');
    
    // First, test if the endpoint is reachable
    const response = await axios.post(API_URL, testData, {
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 10000, // 10 second timeout
      validateStatus: function (status) {
        return status < 500; // Accept all status codes less than 500
      }
    });

    console.log('✅ API Response Received!');
    console.log('Status:', response.status);
    console.log('Headers:', response.headers);
    console.log('Content-Type:', response.headers['content-type']);
    
    // Check if response is JSON or HTML
    const contentType = response.headers['content-type'] || '';
    if (contentType.includes('application/json')) {
      console.log('✅ Response is JSON');
      console.log('Response data:', JSON.stringify(response.data, null, 2));
    } else if (contentType.includes('text/html')) {
      console.log('⚠️  Response is HTML (not JSON)');
      console.log('Response preview:', response.data.substring(0, 500));
    } else {
      console.log('⚠️  Unknown content type:', contentType);
      console.log('Response preview:', response.data.substring(0, 500));
    }

  } catch (error) {
    console.error("❌ API test failed!");
    
    if (error.code === 'ECONNREFUSED') {
      console.error('Connection refused - API server might be down');
    } else if (error.code === 'ENOTFOUND') {
      console.error('Host not found - check the IP address');
    } else if (error.code === 'ETIMEDOUT') {
      console.error('Request timed out');
    } else if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response headers:', error.response.headers);
      console.error('Response data:', error.response.data);
    } else {
      console.error('Error:', error.message);
    }
  }
}

// Also test localhost version
async function testLocalhostAPI() {
  console.log('\n🔍 Testing localhost API endpoint...');
  
  const localhostURL = 'http://localhost:3000/api/verify-pan';
  
  try {
    const response = await axios.post(localhostURL, testData, {
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 10000,
      validateStatus: function (status) {
        return status < 500;
      }
    });

    console.log('✅ Localhost API Response:');
    console.log('Status:', response.status);
    console.log('Content-Type:', response.headers['content-type']);
    
    if (response.headers['content-type']?.includes('application/json')) {
      console.log('Response data:', JSON.stringify(response.data, null, 2));
    } else {
      console.log('Response preview:', response.data.substring(0, 500));
    }

  } catch (error) {
    console.error('❌ Localhost API failed:', error.message);
  }
}

async function runTests() {
  console.log('🚀 Starting API Connectivity Tests...\n');
  
  await testAPIConnectivity();
  await testLocalhostAPI();
  
  console.log('\n✨ All tests completed!');
}

runTests();
