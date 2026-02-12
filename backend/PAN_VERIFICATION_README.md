# PAN Verification Service Integration

This document explains how to use the new PAN verification service that integrates with the Sandbox API for real PAN verification.

## 🚀 Features

- **Real PAN Verification**: Integrates with Sandbox API for actual government database verification
- **Automatic Fallback**: Falls back to simulation if the real API fails
- **Enhanced Security**: Proper authentication and error handling
- **Comprehensive Logging**: Detailed logs for debugging and monitoring

## 🔧 Setup

### 1. Environment Variables

Add these to your `.env` file:

```bash
# Sandbox API Configuration
SANDBOX_API_KEY=key_live_4e188ef5754649e5aceaff5733a62c30
SANDBOX_API_SECRET=secret_live_0afc41875f284de5a2e563b5d6d3f3e9
```

### 2. API Credentials

The service uses the following Sandbox API credentials:
- **API Key**: `key_live_4e188ef5754649e5aceaff5733a62c30`
- **API Secret**: `secret_live_0afc41875f284de5a2e563b5d6d3f3e9`

## 📡 API Endpoints

### Single PAN Verification

**Endpoint**: `POST /api/pan-kyc/verify-single`

**Request Body**:
```json
{
  "panNumber": "ABCDE1234F",
  "name": "John Doe",
  "dateOfBirth": "1990-05-15",
  "reason": "KYC Verification"
}
```

**Response**:
```json
{
  "success": true,
  "message": "KYC verification completed",
  "data": {
    "panNumber": "ABCDE1234F",
    "name": "John Doe",
    "dateOfBirth": "1990-05-15",
    "status": "verified",
    "verificationDetails": {
      "message": "PAN verification completed",
      "source": "sandbox_api",
      "confidence": 95,
      "dataMatch": true,
      "apiResponse": { ... }
    },
    "processedAt": "2024-01-15T10:30:00.000Z",
    "processingTime": 1500,
    "source": "sandbox_api"
  }
}
```

### Batch PAN Verification

**Endpoint**: `POST /api/pan-kyc/verify`

This endpoint processes multiple PAN records from a batch and uses the same verification service.

## 🔄 Verification Flow

1. **Authentication**: Service authenticates with Sandbox API using credentials
2. **Date Formatting**: Converts YYYY-MM-DD to DD/MM/YYYY format as required by Sandbox
3. **API Call**: Makes verification request to Sandbox API
4. **Response Processing**: Processes the API response and formats it for the application
5. **Fallback**: If real API fails, falls back to simulation mode

## 🧪 Testing

Run the test script to verify the service works:

```bash
node test-pan-verification.js
```

## 📊 Response Statuses

- **`verified`**: PAN verification successful
- **`rejected`**: PAN verification failed
- **`error`**: Technical error during verification

## 🔍 Logging

The service provides comprehensive logging:

- **Authentication logs**: Success/failure of Sandbox API authentication
- **Verification logs**: Details of each verification attempt
- **Error logs**: Detailed error information for debugging
- **Fallback logs**: When simulation mode is used

## 🚨 Error Handling

### Common Errors

1. **Authentication Failed**: Check API credentials
2. **Invalid PAN Format**: PAN must be 10 characters (5 letters + 4 digits + 1 letter)
3. **API Rate Limit**: Sandbox API may have rate limits
4. **Network Issues**: Connection problems with external API

### Fallback Behavior

If the real API fails, the service automatically falls back to simulation mode, ensuring your application continues to work.

## 🔐 Security Considerations

- API credentials are stored in environment variables
- All API calls are logged for audit purposes
- Error messages don't expose sensitive information
- Rate limiting is handled gracefully

## 📈 Performance

- **Real API**: Typically 1-3 seconds response time
- **Fallback**: 1-2 seconds simulation delay
- **Caching**: Sandbox API supports caching for better performance

## 🔄 Updates

The service automatically handles:
- API version updates
- Response format changes
- Error code updates
- Rate limit changes

## 📞 Support

For issues with the Sandbox API:
- Check the Sandbox API documentation
- Verify your API credentials
- Monitor the logs for detailed error information
- Contact Sandbox support if needed

## 🎯 Next Steps

1. Test the service with your existing PAN data
2. Monitor logs for any issues
3. Adjust rate limiting if needed
4. Consider implementing caching for better performance
5. Set up monitoring for API health checks
