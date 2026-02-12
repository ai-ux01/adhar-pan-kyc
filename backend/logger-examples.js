const logger = require('./src/utils/logger');

console.log('🚀 Logger Usage Examples\n');

// 1. Basic Logging Levels
console.log('1️⃣  Basic Logging Levels:');
logger.info('This is an INFO message');
logger.warn('This is a WARNING message');
logger.error('This is an ERROR message');
logger.debug('This is a DEBUG message (if enabled)');

console.log('');

// 2. Logging with Context/Service
console.log('2️⃣  Logging with Context:');
logger.info('User authentication successful', {
  service: 'auth-service',
  userId: '12345',
  timestamp: new Date().toISOString()
});

console.log('');

// 3. Logging Objects and Data
console.log('3️⃣  Logging Objects and Data:');
const userData = {
  name: 'John Doe',
  email: 'john@example.com',
  role: 'admin'
};

logger.info('User data received', {
  service: 'user-service',
  data: userData,
  count: Object.keys(userData).length
});

console.log('');

// 4. Error Logging with Stack Traces
console.log('4️⃣  Error Logging:');
try {
  // Simulate an error
  throw new Error('Something went wrong!');
} catch (error) {
  logger.error('An error occurred', {
    service: 'example-service',
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
}

console.log('');

// 5. Logging API Requests/Responses
console.log('5️⃣  API Request/Response Logging:');
logger.info('API request sent', {
  service: 'api-service',
  method: 'POST',
  url: '/api/users',
  requestId: 'req-12345',
  timestamp: new Date().toISOString()
});

logger.info('API response received', {
  service: 'api-service',
  status: 200,
  responseTime: '150ms',
  requestId: 'req-12345',
  timestamp: new Date().toISOString()
});

console.log('');

// 6. Performance Logging
console.log('6️⃣  Performance Logging:');
const startTime = Date.now();
setTimeout(() => {
  const duration = Date.now() - startTime;
  logger.info('Operation completed', {
    service: 'performance-service',
    operation: 'database-query',
    duration: `${duration}ms`,
    success: true
  });
}, 100);

console.log('');

// 7. Structured Logging for Business Logic
console.log('7️⃣  Business Logic Logging:');
logger.info('PAN verification started', {
  service: 'pan-verification',
  panNumber: 'ABCDE1234F',
  verificationType: 'individual',
  timestamp: new Date().toISOString()
});

logger.info('PAN verification completed', {
  service: 'pan-verification',
  panNumber: 'ABCDE1234F',
  status: 'verified',
  confidence: 95,
  processingTime: '2.5s',
  timestamp: new Date().toISOString()
});

console.log('');

// 8. Conditional Logging
console.log('8️⃣  Conditional Logging:');
const isDebugMode = process.env.NODE_ENV === 'development';

if (isDebugMode) {
  logger.debug('Debug information', {
    service: 'debug-service',
    environment: process.env.NODE_ENV,
    memoryUsage: process.memoryUsage()
  });
}

console.log('');

// 9. Logging with Metadata
console.log('9️⃣  Logging with Metadata:');
logger.info('Database operation', {
  service: 'database-service',
  operation: 'insert',
  collection: 'users',
  documentId: 'user-67890',
  metadata: {
    source: 'api',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  }
});

console.log('');

// 10. Error Context Logging
console.log('🔟  Error Context Logging:');
logger.error('Database connection failed', {
  service: 'database-service',
  error: 'Connection timeout',
  context: {
    host: 'localhost',
    port: 27017,
    database: 'kyc-app',
    retryCount: 3
  },
  timestamp: new Date().toISOString()
});

console.log('\n✨ Logger examples completed!');
console.log('\n📋 Logger Levels Available:');
console.log('   - logger.info()  : General information');
console.log('   - logger.warn()  : Warnings');
console.log('   - logger.error() : Errors');
console.log('   - logger.debug() : Debug information (if enabled)');
console.log('\n💡 Tips:');
console.log('   - Always include service name for easy filtering');
console.log('   - Use structured data objects for better searchability');
console.log('   - Include timestamps for tracking');
console.log('   - Add context for better debugging');
