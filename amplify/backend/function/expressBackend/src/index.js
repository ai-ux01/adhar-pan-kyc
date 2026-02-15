/**
 * AWS Lambda handler for Express.js backend
 * This wraps the Express app to work with API Gateway
 * 
 * For separate Amplify deployment, the backend code should be
 * bundled with this Lambda function.
 */

const serverless = require('serverless-http');

// Try to load the Express app from bundled backend
let app;
try {
  // Option 1: Backend bundled in Lambda function
  app = require('./backend/src/server');
} catch (error) {
  console.error('Error loading Express app:', error);
  
  // Option 2: Fallback - create simple Express app for testing
  const express = require('express');
  app = express();
  app.use(express.json());
  
  app.get('/health', (req, res) => {
    res.json({
      status: 'OK',
      message: 'Lambda function is working. Backend integration needed.',
      timestamp: new Date().toISOString(),
      note: 'Please bundle backend code with Lambda function or configure path correctly'
    });
  });
  
  app.all('*', (req, res) => {
    res.status(501).json({
      error: 'Backend not fully integrated. Please bundle backend code with Lambda function.',
      path: req.path,
      instructions: 'See SEPARATE_AMPLIFY_DEPLOYMENT.md for setup instructions'
    });
  });
}

// Wrap Express app with serverless-http
// This converts API Gateway events to Express requests
const handler = serverless(app, {
  binary: [
    'image/*',
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-excel'
  ],
  request: (request, event, context) => {
    // Add API Gateway context to request
    request.context = event.requestContext;
    request.apiGateway = {
      event,
      context
    };
  }
});

module.exports = { handler };
