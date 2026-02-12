# Email Service Setup Guide

## Quick Setup for Gmail

### 1. Enable 2-Factor Authentication
1. Go to your Google Account settings
2. Navigate to Security
3. Enable 2-Step Verification

### 2. Generate App Password
1. In Google Account settings, go to Security
2. Under "2-Step Verification", click "App passwords"
3. Select "Mail" and your device
4. Copy the generated 16-character password

### 3. Configure Environment Variables
Create or update your `.env` file in the backend directory:

```env
# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-16-character-app-password
FRONTEND_URL=http://localhost:3000
```

### 4. Test Email Service
Run the test script to verify your configuration:

```bash
cd backend
node test-email.js
```

## Alternative Email Providers

### Outlook/Hotmail
```env
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USER=your-email@outlook.com
SMTP_PASS=your-password
```

### Yahoo Mail
```env
SMTP_HOST=smtp.mail.yahoo.com
SMTP_PORT=587
SMTP_USER=your-email@yahoo.com
SMTP_PASS=your-app-password
```

### Custom SMTP Server
```env
SMTP_HOST=your-smtp-server.com
SMTP_PORT=587
SMTP_USER=your-email@domain.com
SMTP_PASS=your-password
```

## Troubleshooting

### Common Issues

1. **Authentication Failed (EAUTH)**
   - Use App Password instead of regular password
   - Ensure 2FA is enabled
   - Check email address is correct

2. **Connection Failed (ECONNECTION)**
   - Verify SMTP_HOST and SMTP_PORT
   - Check internet connection
   - Ensure firewall allows SMTP connections

3. **Emails Not Received**
   - Check spam/junk folder
   - Verify recipient email address
   - Check email provider's sending limits

### Testing Steps

1. Run the test script: `node test-email.js`
2. Check your email inbox (and spam folder)
3. If successful, test forgot password functionality
4. Check server logs for any errors

## Security Notes

- Never commit your `.env` file to version control
- Use App Passwords instead of regular passwords
- Consider using environment-specific email services for production
- Monitor email sending limits and quotas

## Production Recommendations

For production environments, consider using:
- SendGrid
- Mailgun
- Amazon SES
- Postmark

These services provide better deliverability and monitoring features.
