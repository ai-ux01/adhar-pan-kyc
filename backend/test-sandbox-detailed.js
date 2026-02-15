const axios = require('axios');

// Sandbox API credentials
const SANDBOX_API_KEY = 'key_live_6edea225e1354559b2422d3921c795cf';
const SANDBOX_API_SECRET = 'secret_live_03078556231c41879cd6ab46e1d6d6a07f';

// Test different authentication approaches
async function testAuthenticationMethods() {
  console.log('🧪 Testing Different Sandbox API Authentication Methods...\n');
  console.log('API Key:', SANDBOX_API_KEY);
  console.log('API Secret:', SANDBOX_API_SECRET);
  console.log('');

  // Method 1: Standard authentication (empty body)
  console.log('🔐 Method 1: Standard Authentication (Empty Body)');
  try {
    const response = await axios.post('https://api.sandbox.co.in/authenticate', {}, {
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': SANDBOX_API_KEY,
        'x-api-secret': SANDBOX_API_SECRET,
      }
    });
    console.log('✅ Success! Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
  } catch (error) {
    console.log('❌ Failed:', error.response?.status, error.response?.data?.message);
  }

  console.log('');

  // Method 2: Authentication with credentials in body
  console.log('🔐 Method 2: Authentication with Credentials in Body');
  try {
    const response = await axios.post('https://api.sandbox.co.in/authenticate', {
      api_key: SANDBOX_API_KEY,
      api_secret: SANDBOX_API_SECRET
    }, {
      headers: {
        'Content-Type': 'application/json',
      }
    });
    console.log('✅ Success! Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
  } catch (error) {
    console.log('❌ Failed:', error.response?.status, error.response?.data?.message);
  }

  console.log('');

  // Method 3: Different header format
  console.log('🔐 Method 3: Different Header Format');
  try {
    const response = await axios.post('https://api.sandbox.co.in/authenticate', {}, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': SANDBOX_API_KEY,
        'X-API-Secret': SANDBOX_API_SECRET,
      }
    });
    console.log('✅ Success! Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
  } catch (error) {
    console.log('❌ Failed:', error.response?.status, error.response?.data?.message);
  }

  console.log('');

  // Method 4: Query parameters
  console.log('🔐 Method 4: Query Parameters');
  try {
    const response = await axios.post(`https://api.sandbox.co.in/authenticate?api_key=${SANDBOX_API_KEY}&api_secret=${SANDBOX_API_SECRET}`, {}, {
      headers: {
        'Content-Type': 'application/json',
      }
    });
    console.log('✅ Success! Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
  } catch (error) {
    console.log('❌ Failed:', error.response?.status, error.response?.data?.message);
  }

  console.log('');

  // Method 5: Basic auth
  console.log('🔐 Method 5: Basic Authentication');
  try {
    const response = await axios.post('https://api.sandbox.co.in/authenticate', {}, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${Buffer.from(`${SANDBOX_API_KEY}:${SANDBOX_API_SECRET}`).toString('base64')}`
      }
    });
    console.log('✅ Success! Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
  } catch (error) {
    console.log('❌ Failed:', error.response?.status, error.response?.data?.message);
  }
}

// Test API endpoint availability
async function testAPIEndpoints() {
  console.log('\n🌐 Testing API Endpoint Availability...\n');

  const endpoints = [
    'https://api.sandbox.co.in/authenticate',
    'https://api.sandbox.co.in/health',
    'https://api.sandbox.co.in/status',
    'https://api.sandbox.co.in/'
  ];

  for (const endpoint of endpoints) {
    try {
      console.log(`🔍 Testing: ${endpoint}`);
      const response = await axios.get(endpoint, { timeout: 5000 });
      console.log(`✅ Available - Status: ${response.status}`);
    } catch (error) {
      if (error.code === 'ECONNREFUSED') {
        console.log(`❌ Connection refused`);
      } else if (error.response) {
        console.log(`⚠️  Responds but with status: ${error.response.status}`);
      } else {
        console.log(`❌ Error: ${error.message}`);
      }
    }
    console.log('');
  }
}

// Test with different user agents
async function testUserAgents() {
  console.log('🤖 Testing Different User Agents...\n');

  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'PostmanRuntime/7.32.3',
    'curl/7.68.0',
    'axios/1.11.0'
  ];

  for (const userAgent of userAgents) {
    try {
      console.log(`🔍 Testing with User-Agent: ${userAgent.substring(0, 30)}...`);
      const response = await axios.post('https://api.sandbox.co.in/authenticate', {}, {
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': SANDBOX_API_KEY,
          'x-api-secret': SANDBOX_API_SECRET,
          'User-Agent': userAgent
        }
      });
      console.log(`✅ Success with User-Agent: ${userAgent.substring(0, 30)}...`);
      break;
    } catch (error) {
      console.log(`❌ Failed with User-Agent: ${userAgent.substring(0, 30)}...`);
    }
  }
}

async function runTests() {
  console.log('🚀 Starting Comprehensive Sandbox API Tests...\n');
  
  await testAuthenticationMethods();
  await testAPIEndpoints();
  await testUserAgents();
  
  console.log('\n✨ All tests completed!');
  console.log('\n📝 Summary:');
  console.log('  - If all methods fail, the credentials may be invalid or inactive');
  console.log('  - If some methods work, we found the correct format');
  console.log('  - Check with Sandbox API support for correct usage');
}

runTests();
