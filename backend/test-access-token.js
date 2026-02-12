const axios = require('axios');

console.log('🔑 Testing Access Token Display...\n');

// Test 1: Show what happens when auth succeeds
async function testSuccessfulAuth() {
  console.log('1️⃣  Testing Successful Authentication (Simulated)...');
  
  // Simulate a successful access token
  const mockAccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  
  console.log('✅ Mock Access Token Received!');
  console.log('🔑 accessToken>>>>>', mockAccessToken);
  console.log('🔑 Token length:', mockAccessToken.length);
  console.log('🔑 Token preview:', mockAccessToken.substring(0, 20) + '...');
  console.log('');
  
  return mockAccessToken;
}

// Test 2: Test actual Sandbox API
async function testActualSandboxAPI() {
  console.log('2️⃣  Testing Actual Sandbox API...');
  
  const API_KEY = 'key_live_6edea225e1354559b2422d3921c795cf';
  const API_SECRET = 'secret_live_03078556231c41879cd6ab46e1d6d6a07f';
  
  try {
    console.log('🔐 Attempting to authenticate with Sandbox API...');
    
    const response = await axios.post('https://api.sandbox.co.in/authenticate', {}, {
      headers: {
        'x-api-key': API_KEY,
        'x-api-secret': API_SECRET,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    
    const accessToken = response.data.access_token || response.data.data?.access_token;
    
    if (accessToken) {
      console.log('✅ SUCCESS! Access Token Received!');
      console.log('🔑 accessToken>>>>>', accessToken);
      console.log('🔑 Token length:', accessToken.length);
      console.log('🔑 Token preview:', accessToken.substring(0, 20) + '...');
      console.log('🔑 Full Response:', JSON.stringify(response.data, null, 2));
    } else {
      console.log('⚠️  Authentication succeeded but no access token found');
      console.log('🔍 Response:', JSON.stringify(response.data, null, 2));
    }
    
  } catch (error) {
    console.log('❌ Authentication FAILED!');
    console.log('Status:', error.response?.status || 'No Response');
    console.log('Message:', error.response?.data?.message || error.message);
    console.log('Code:', error.response?.data?.code || 'N/A');
    console.log('Transaction ID:', error.response?.data?.transaction_id || 'N/A');
  }
  
  console.log('');
}

// Test 3: Test different credential formats
async function testDifferentCredentialFormats() {
  console.log('3️⃣  Testing Different Credential Formats...\n');
  
  const testCases = [
    {
      name: 'Test Case 1: Standard Format',
      headers: {
        'x-api-key': 'key_live_6edea225e1354559b2422d3921c795cf',
        'x-api-secret': 'secret_live_03078556231c41879cd6ab46e1d6d6a07f'
      }
    },
    {
      name: 'Test Case 2: Different Header Names',
      headers: {
        'api-key': 'key_live_6edea225e1354559b2422d3921c795cf',
        'api-secret': 'secret_live_03078556231c41879cd6ab46e1d6d6a07f'
      }
    },
    {
      name: 'Test Case 3: Authorization Header',
      headers: {
        'Authorization': 'Bearer key_live_6edea225e1354559b2422d3921c795cf',
        'x-api-secret': 'secret_live_03078556231c41879cd6ab46e1d6d6a07f'
      }
    }
  ];
  
  for (const testCase of testCases) {
    console.log(`🔍 Testing: ${testCase.name}`);
    
    try {
      const response = await axios.post('https://api.sandbox.co.in/authenticate', {}, {
        headers: {
          ...testCase.headers,
          'Content-Type': 'application/json'
        },
        timeout: 5000
      });
      
      const accessToken = response.data.access_token || response.data.data?.access_token;
      
      if (accessToken) {
        console.log('✅ SUCCESS! Access Token Received!');
        console.log('🔑 accessToken>>>>>', accessToken);
        console.log('🔑 Token length:', accessToken.length);
        console.log('🔑 Token preview:', accessToken.substring(0, 20) + '...');
        break; // Stop testing if we get a successful response
      } else {
        console.log('⚠️  Success but no token');
      }
      
    } catch (error) {
      console.log('❌ Failed:', error.response?.status || error.message);
      if (error.response?.data?.message) {
        console.log('   Message:', error.response.data.message);
      }
    }
    
    console.log('');
  }
}

// Test 4: Show what the access token would look like
function showAccessTokenFormat() {
  console.log('4️⃣  Access Token Format Examples...\n');
  
  const exampleTokens = [
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    'access_token_12345_abcdef_67890'
  ];
  
  exampleTokens.forEach((token, index) => {
    console.log(`Example ${index + 1}:`);
    console.log('🔑 accessToken>>>>>', token);
    console.log('🔑 Token length:', token.length);
    console.log('🔑 Token preview:', token.substring(0, 20) + '...');
    console.log('');
  });
}

// Run all tests
async function runAllTests() {
  console.log('🚀 Starting Access Token Tests...\n');
  
  // Test 1: Show successful case
  await testSuccessfulAuth();
  
  // Test 2: Test actual API
  await testActualSandboxAPI();
  
  // Test 3: Test different formats
  await testDifferentCredentialFormats();
  
  // Test 4: Show token format examples
  showAccessTokenFormat();
  
  console.log('✨ All tests completed!');
  console.log('\n💡 To see the actual access token:');
  console.log('   1. Get valid API credentials');
  console.log('   2. Or use your working Next.js API endpoint');
  console.log('   3. The console.log will show the token immediately!');
}

runAllTests();
