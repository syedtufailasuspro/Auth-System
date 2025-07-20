const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'if your dad, than iam your dad';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'life is a journey, not a destination';
const OTP_EXPIRY_TIME = 5 * 60 * 1000; // 5 minutes in milliseconds
const TOKEN_EXPIRY = '15m'; // 15 minutes
const REFRESH_TOKEN_EXPIRY = '7d'; // 7 days

// Gmail configuration
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: '220191601058@crescent.education', // your gmail address
    pass: 'ryrjgljlnkkaezhu' // Gmail app-specific password
  }
});

// Verify email transporter on startup
emailTransporter.verify((error, success) => {
  if (error) {
    console.log('❌ Email transporter verification failed:', error);
  } else {
    console.log('✅ Email server is ready to send messages');
  }
});

// Middleware
app.use(express.json());
app.use(cookieParser());


// CORS middleware for local development
// CORS middleware for production
app.use((req, res, next) => {
  // Allow multiple origins in production
  const allowedOrigins = [
  'https://auth-system-vzmh.vercel.app'
];

  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});


// In-memory storage (replace with database in production)
const users = new Map();
const otps = new Map();
const refreshTokens = new Set();

// Utility functions
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
  const refreshToken = jwt.sign({ userId }, JWT_REFRESH_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
  return { accessToken, refreshToken };
};

const findUserByEmailOrMobile = (identifier) => {
  for (let [key, user] of users) {
    if (user.email === identifier || user.mobile === identifier) {
      return { key, user };
    }
  }
  return null;
};

// Email OTP sending function
const sendEmailOTP = async (email, otp, userName = 'User') => {
  try {
    const mailOptions = {
      from: {
        name: 'Your App Name',
        address: process.env.GMAIL_USER
      },
      to: email,
      subject: 'Your OTP Verification Code',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>OTP Verification</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f4;">
          <div style="max-width: 600px; margin: 40px auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
            
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
              <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 600;">OTP Verification</h1>
            </div>
            
            <!-- Content -->
            <div style="padding: 40px 30px;">
              <p style="font-size: 16px; color: #333; margin: 0 0 20px 0; line-height: 1.5;">
                Hello <strong>${userName}</strong>,
              </p>
              
              <p style="font-size: 16px; color: #666; margin: 0 0 30px 0; line-height: 1.5;">
                You requested an OTP for account verification. Please use the code below to complete your verification:
              </p>
              
              <!-- OTP Box -->
              <div style="background-color: #f8f9ff; border: 2px dashed #667eea; border-radius: 12px; padding: 30px; text-align: center; margin: 30px 0;">
                <p style="margin: 0 0 10px 0; font-size: 14px; color: #666; text-transform: uppercase; letter-spacing: 1px; font-weight: 500;">
                  Your OTP Code
                </p>
                <div style="font-size: 36px; font-weight: bold; color: #667eea; letter-spacing: 8px; margin: 10px 0; font-family: 'Courier New', monospace;">
                  ${otp}
                </div>
              </div>
              
              <!-- Warning Box -->
              <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 15px; margin: 25px 0;">
                <p style="margin: 0; font-size: 14px; color: #856404;">
                  <strong>⚠️ Important:</strong> This code will expire in <strong>5 minutes</strong>. Do not share this code with anyone.
                </p>
              </div>
              
              <p style="font-size: 14px; color: #999; margin: 25px 0 0 0; line-height: 1.5;">
                If you didn't request this verification code, please ignore this email or contact support if you have concerns.
              </p>
            </div>
            
            <!-- Footer -->
            <div style="background-color: #f8f9fa; padding: 20px 30px; border-top: 1px solid #e9ecef; text-align: center;">
              <p style="margin: 0; font-size: 12px; color: #6c757d;">
                This is an automated message, please do not reply to this email.
              </p>
              <p style="margin: 8px 0 0 0; font-size: 12px; color: #adb5bd;">
                © ${new Date().getFullYear()} Your App Name. All rights reserved.
              </p>
            </div>
            
          </div>
        </body>
        </html>
      `
    };

    const info = await emailTransporter.sendMail(mailOptions);
    console.log(`✅ Email OTP sent to ${email}: ${otp}`);
    console.log(`📧 Message ID: ${info.messageId}`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('❌ Email sending failed:', error);
    return { success: false, error: error.message };
  }
};

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const token = req.cookies.sessionToken;
  
  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Access token required' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
    }
    req.userId = decoded.userId;
    next();
  });
};

// Routes

// 1. POST /signup
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;

    // Validation
    if (!name || !email || !mobile || !password) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Mobile validation (10 digits)
    const mobileRegex = /^\d{10}$/;
    if (!mobileRegex.test(mobile)) {
      return res.status(400).json({
        success: false,
        message: 'Mobile number must be 10 digits'
      });
    }

    // Password strength validation
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    // Check if user already exists
    const existingUser = findUserByEmailOrMobile(email) || findUserByEmailOrMobile(mobile);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'User already exists with this email or mobile'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    const userId = crypto.randomUUID();

    // Store user
    users.set(userId, {
      id: userId,
      name,
      email,
      mobile,
      password: hashedPassword,
      isVerified: false,
      createdAt: new Date()
    });

    // Generate and send OTP to email
    const otp = generateOTP();
    const otpExpiry = Date.now() + OTP_EXPIRY_TIME;
    
    otps.set(email, {
      otp,
      expiresAt: otpExpiry,
      attempts: 0,
      userId
    });

    // Send OTP via email
    const otpResult = await sendEmailOTP(email, otp, name);
    
    if (!otpResult.success) {
      // Remove user from storage if OTP sending fails
      users.delete(userId);
      return res.status(500).json({
        success: false,
        message: `Failed to send OTP: ${otpResult.error}`
      });
    }

    res.status(201).json({
      success: true,
      message: 'User registered successfully. Please check your email for the OTP verification code.',
      data: {
        userId,
        email,
        mobile,
        message: 'OTP sent to your email address'
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// 2. POST /login
app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body; // identifier can be email or mobile

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email/Mobile and password are required'
      });
    }

    // Find user
    const userResult = findUserByEmailOrMobile(identifier);
    if (!userResult) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const { user } = userResult;

    // Check if user is verified
    if (!user.isVerified) {
      return res.status(401).json({
        success: false,
        message: 'Please verify your account first. Check your email for the OTP.',
        data: {
          requiresVerification: true,
          email: user.email
        }
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user.id);
    
    // Store refresh token
    refreshTokens.add(refreshToken);

    // Set HTTP-only cookies
    res.cookie('sessionToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        userId: user.id,
        name: user.name,
        email: user.email,
        mobile: user.mobile
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// 3. POST /verify-otp
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body; // Only email since we're using Gmail only

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Email and OTP are required'
      });
    }
    
  // Check OTP
    const otpData = otps.get(email);
    
    // Check expiry
    if (Date.now() > otpData.expiresAt) {
      otps.delete(email);
      return res.status(400).json({
        success: false,
        message: 'OTP has expired. Please request a new OTP.'
      });
    }

    // Check attempts (max 3 attempts)
    if (otpData.attempts >= 3) {
      otps.delete(email);
      return res.status(400).json({
        success: false,
        message: 'Too many failed attempts. Please request a new OTP.'
      });
    }

    // Verify OTP
    if (otpData.otp !== otp) {
      otpData.attempts++;
      return res.status(400).json({
        success: false,
        message: `Invalid OTP. ${3 - otpData.attempts} attempts remaining.`
      });
    }

    // OTP is valid - mark user as verified
    const user = users.get(otpData.userId);
    if (user) {
      user.isVerified = true;
      user.verifiedAt = new Date();
    }

    // Clean up OTP
    otps.delete(email);

    res.json({
      success: true,
      message: 'Email verified successfully! You can now login to your account.',
      data: {
        userId: otpData.userId,
        isVerified: true,
        verifiedAt: new Date()
      }
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// 4. POST /refresh-token
app.post('/api/refresh-token', (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token required'
      });
    }

    // Check if refresh token exists in our store
    if (!refreshTokens.has(refreshToken)) {
      return res.status(403).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    // Verify refresh token
    jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, decoded) => {
      if (err) {
        // Remove invalid token from store
        refreshTokens.delete(refreshToken);
        return res.status(403).json({
          success: false,
          message: 'Invalid refresh token'
        });
      }

      // Generate new tokens
      const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded.userId);
      
      // Remove old refresh token and add new one
      refreshTokens.delete(refreshToken);
      refreshTokens.add(newRefreshToken);

      // Set new cookies
      res.cookie('sessionToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      res.json({
        success: true,
        message: 'Tokens refreshed successfully'
      });
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Protected route example
app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    const user = users.get(req.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
        mobile: user.mobile,
        isVerified: user.isVerified,
        createdAt: user.createdAt,
        verifiedAt: user.verifiedAt || null
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  
  // Remove refresh token from store
  if (refreshToken) {
    refreshTokens.delete(refreshToken);
  }
  
  // Clear cookies
  res.clearCookie('sessionToken');
  res.clearCookie('refreshToken');
  
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// Resend OTP endpoint
app.post('/api/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // Find user by email
    const userResult = findUserByEmailOrMobile(email);
    if (!userResult) {
      return res.status(404).json({
        success: false,
        message: 'User not found with this email'
      });
    }

    const { user } = userResult;

    // Don't resend if already verified
    if (user.isVerified) {
      return res.status(400).json({
        success: false,
        message: 'User is already verified'
      });
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpExpiry = Date.now() + OTP_EXPIRY_TIME;
    
    otps.set(email, {
      otp,
      expiresAt: otpExpiry,
      attempts: 0,
      userId: user.id
    });

    // Send OTP via email
    const otpResult = await sendEmailOTP(email, otp, user.name);
    
    if (!otpResult.success) {
      return res.status(500).json({
        success: false,
        message: `Failed to send OTP: ${otpResult.error}`
      });
    }

    res.json({
      success: true,
      message: 'OTP sent successfully. Please check your email.',
      data: {
        email,
        expiresIn: '5 minutes'
      }
    });

  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    emailService: process.env.GMAIL_USER ? 'Gmail configured' : 'Gmail not configured',
    stats: {
      users: users.size,
      pendingOTPs: otps.size,
      activeTokens: refreshTokens.size
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📧 Email service: ${process.env.GMAIL_USER ? `Gmail (${process.env.GMAIL_USER})` : 'Not configured - Please set GMAIL_USER and GMAIL_APP_PASSWORD'}`);
  console.log(`📋 Available endpoints:`);
  console.log(`   POST /signup - Register with email OTP verification`);
  console.log(`   POST /login - Login with email/mobile`);
  console.log(`   POST /verify-otp - Verify email with OTP`);
  console.log(`   POST /resend-otp - Resend OTP to email`);
  console.log(`   POST /refresh-token - Refresh access tokens`);
  console.log(`   GET  /profile - Get user profile (protected)`);
  console.log(`   POST /logout - Logout user`);
  console.log(`   GET  /health - Server health check`);
});

module.exports = app;
