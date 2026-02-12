# KYC Aadhaar System

A comprehensive web application for PAN KYC verification and Aadhaar-PAN linking status check with role-based access control, audit logging, and modern UI.

## 🚀 Features

### Module 1: PAN KYC Verification
- Bulk upload of PAN details via Excel (.xls/.xlsx)
- Real-time PAN KYC verification using official APIs
- Status tracking (Verified, Rejected, Pending, Error)
- Download verification reports (CSV and PDF)
- Comprehensive audit logging

### Module 2: Aadhaar-PAN Linking Status Check
- Bulk upload of PAN and Aadhaar details via Excel
- Aadhaar-PAN linking status verification
- Status tracking (Linked, Not Linked, Pending, Invalid)
- Download status reports and logs

### Admin Module
- Secure login with role-based access management
- User account management (create, edit, suspend, delete)
- Module access control for users
- Full audit log access
- System settings and API configuration

### Security Features
- JWT-based authentication
- Role-based access control (Admin, User)
- Two-factor authentication for admin accounts
- Data encryption at rest and in transit
- Rate limiting and security headers
- Comprehensive audit logging

### Modern UI/UX
- Responsive design with Tailwind CSS
- Dark/Light theme support
- Real-time notifications
- Interactive dashboards with charts
- Modern component library

## 🛠️ Technology Stack

### Backend
- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **MongoDB** - Database
- **Mongoose** - ODM for MongoDB
- **JWT** - Authentication
- **bcryptjs** - Password hashing
- **Multer** - File upload handling
- **XLSX** - Excel file processing
- **Nodemailer** - Email notifications
- **Winston** - Logging
- **Helmet** - Security headers

### Frontend
- **React** - UI library
- **TypeScript** - Type safety
- **Tailwind CSS** - Styling
- **React Router** - Navigation
- **React Hook Form** - Form handling
- **Yup** - Form validation
- **Axios** - HTTP client
- **Recharts** - Data visualization
- **React Hot Toast** - Notifications
- **Heroicons** - Icons

## 📋 Prerequisites

- Node.js (v16 or higher)
- MongoDB (v4.4 or higher)
- npm or yarn

## 🚀 Installation

### 1. Clone the repository
```bash
git clone <repository-url>
cd kyc-aadhaar-app
```

### 2. Backend Setup
```bash
cd backend

# Install dependencies
npm install

# Create environment file
cp env.example .env

# Edit .env file with your configuration
# Update MongoDB URI, JWT secret, email settings, etc.

# Start the server
npm run dev
```

### 3. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Start the development server
npm start
```

## ⚙️ Configuration

### Backend Environment Variables (.env)
```env
# Server Configuration
PORT=5000
NODE_ENV=development

# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/kyc-aadhaar-app

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=24h

# Encryption
ENCRYPTION_KEY=your-32-character-encryption-key

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# API Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# External APIs
PAN_KYC_API_URL=https://api.example.com/pan-kyc
AADHAAR_PAN_API_URL=https://api.example.com/aadhaar-pan
API_KEY=your-api-key
```

### Frontend Environment Variables
Create a `.env` file in the frontend directory:
```env
REACT_APP_API_URL=http://localhost:5000/api
```

## 📁 Project Structure

```
kyc-aadhaar-app/
├── backend/
│   ├── src/
│   │   ├── config/          # Database and app configuration
│   │   ├── controllers/     # Route controllers
│   │   ├── middleware/      # Custom middleware
│   │   ├── models/          # MongoDB models
│   │   ├── routes/          # API routes
│   │   ├── services/        # Business logic services
│   │   ├── utils/           # Utility functions
│   │   └── server.js        # Main server file
│   ├── uploads/             # File upload directory
│   ├── logs/                # Application logs
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── components/      # Reusable components
│   │   ├── contexts/        # React contexts
│   │   ├── pages/           # Page components
│   │   ├── services/        # API services
│   │   └── App.tsx          # Main app component
│   └── package.json
└── README.md
```

## 🔧 Development

### Backend Development
```bash
cd backend
npm run dev          # Start development server with nodemon
npm start           # Start production server
npm test            # Run tests
```

### Frontend Development
```bash
cd frontend
npm start           # Start development server
npm run build       # Build for production
npm test            # Run tests
```

## 📊 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user
- `POST /api/auth/forgot-password` - Forgot password
- `POST /api/auth/reset-password/:token` - Reset password

### Users
- `GET /api/users/profile` - Get user profile
- `PUT /api/users/profile` - Update user profile
- `PUT /api/users/preferences` - Update user preferences
- `GET /api/users/activity` - Get user activity
- `GET /api/users/stats` - Get user statistics

### PAN KYC (To be implemented)
- `POST /api/pan-kyc/upload` - Upload PAN KYC file
- `GET /api/pan-kyc/batches` - Get PAN KYC batches
- `GET /api/pan-kyc/batch/:id` - Get batch details
- `GET /api/pan-kyc/reports` - Download reports

### Aadhaar-PAN (To be implemented)
- `POST /api/aadhaar-pan/upload` - Upload Aadhaar-PAN file
- `GET /api/aadhaar-pan/batches` - Get Aadhaar-PAN batches
- `GET /api/aadhaar-pan/batch/:id` - Get batch details
- `GET /api/aadhaar-pan/reports` - Download reports

### Admin (To be implemented)
- `GET /api/admin/users` - Get all users
- `POST /api/admin/users` - Create user
- `PUT /api/admin/users/:id` - Update user
- `DELETE /api/admin/users/:id` - Delete user
- `GET /api/admin/audit-logs` - Get audit logs

## 🔒 Security Features

- **Authentication**: JWT-based authentication with refresh tokens
- **Authorization**: Role-based access control (RBAC)
- **Data Protection**: Encryption of sensitive data at rest
- **Input Validation**: Comprehensive input validation and sanitization
- **Rate Limiting**: API rate limiting to prevent abuse
- **Security Headers**: Helmet.js for security headers
- **Audit Logging**: Complete audit trail of all actions
- **2FA**: Two-factor authentication for admin accounts

## 📈 Monitoring and Logging

- **Winston Logger**: Structured logging with different levels
- **Audit Trail**: Complete audit logging of user actions
- **Error Tracking**: Comprehensive error handling and logging
- **Performance Monitoring**: Request/response logging

## 🚀 Deployment

### Backend Deployment
1. Set up MongoDB database
2. Configure environment variables
3. Install dependencies: `npm install --production`
4. Start the server: `npm start`

### Frontend Deployment
1. Build the application: `npm run build`
2. Serve the build folder using a web server (nginx, Apache, etc.)
3. Configure reverse proxy to backend API

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions, please contact the development team or create an issue in the repository.

## 🔄 Roadmap

- [ ] Complete PAN KYC module implementation
- [ ] Complete Aadhaar-PAN module implementation
- [ ] Complete Admin module implementation
- [ ] Add comprehensive test coverage
- [ ] Implement real-time notifications
- [ ] Add mobile app support
- [ ] Implement advanced analytics
- [ ] Add multi-language support
- [ ] Implement advanced security features
# adhar-pan-kyc
