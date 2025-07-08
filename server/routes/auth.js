import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { db } from '../database/init.js';
import { authenticateToken } from '../middleware/auth.js';
import { sendOTP, sendPasswordResetOTP } from '../services/emailService.js';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// REGISTER - Step 1: Store pending registration and send OTP
router.post('/register', async (req, res) => {
  try {
    const { email, password, name, mobileNumber } = req.body;

    const normalizedEmail = email ? email.trim().toLowerCase() : null;

    // Check if user already exists
    if (normalizedEmail) {
      const existingUser = await db.getAsync(
        'SELECT id FROM users WHERE email = ?',
        [normalizedEmail]
      );
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }
    }

    let identifier;
    if (email) {
      identifier = normalizedEmail;
    } else if (mobileNumber) {
      identifier = mobileNumber;
    } else {
      return res.status(400).json({ error: 'Email or mobile number is required' });
    }

    if (!password || !name) {
      return res.status(400).json({ error: 'Password and name are required' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Clean up any existing pending registrations for this identifier
    await db.runAsync(
      'DELETE FROM pending_registrations WHERE identifier = ?',
      [identifier]
    );

    // Clean up any existing OTPs for this identifier
    await db.runAsync(
      'DELETE FROM otps WHERE identifier = ? AND purpose = ?',
      [identifier, 'registration']
    );

    // Store pending registration
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + (30 * 60); // 30 minutes from now

    await db.runAsync(
      'INSERT INTO pending_registrations (email, password, name, mobileNumber, identifier, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [normalizedEmail, hashedPassword, name, mobileNumber || null, identifier, now, expiresAt]
    );

    // Generate a 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiresAt = Math.floor(Date.now() / 1000) + (10 * 60); // 10 minutes from now

    const otpType = email ? 'email' : 'mobile';

    // Send OTP
    try {
      await sendOTP(identifier, otp, otpType);
    } catch (emailError) {
      console.error('Failed to send OTP:', emailError);
      // Continue with registration even if email fails
    }

    // Store OTP in the database
    await db.runAsync(
      'INSERT INTO otps (identifier, type, otp, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [identifier, otpType, otp, 'registration', otpExpiresAt, now]
    );

    res.status(200).json({
      message: 'Registration initiated. Please verify OTP to complete account creation.',
      identifier: identifier,
      requiresOTP: true
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// VERIFY OTP - Step 2: Complete registration after OTP verification
router.post('/verify-otp', async (req, res) => {
  try {
    const { identifier, otp } = req.body;

    if (!identifier || !otp) {
      return res.status(400).json({ error: 'Identifier and OTP are required' });
    }

    const now = Math.floor(Date.now() / 1000);

    // Find a matching and unexpired OTP for registration
    const otpRecord = await db.getAsync(
      'SELECT id FROM otps WHERE identifier = ? AND otp = ? AND purpose = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1',
      [identifier, otp, 'registration', now]
    );

    if (!otpRecord) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Get pending registration data
    const pendingRegistration = await db.getAsync(
      'SELECT * FROM pending_registrations WHERE identifier = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1',
      [identifier, now]
    );

    if (!pendingRegistration) {
      return res.status(400).json({ error: 'Registration session expired. Please register again.' });
    }

    // Create the user account
    const result = await db.runAsync(
      'INSERT INTO users (email, password, name, mobileNumber) VALUES (?, ?, ?, ?)',
      [
        pendingRegistration.email,
        pendingRegistration.password,
        pendingRegistration.name,
        pendingRegistration.mobileNumber
      ]
    );

    // Clean up pending registration and OTP
    await db.runAsync('DELETE FROM otps WHERE id = ?', [otpRecord.id]);
    await db.runAsync('DELETE FROM pending_registrations WHERE identifier = ?', [identifier]);

    // Return success message without auto-login
    res.status(201).json({
      message: 'Account created successfully! You can now login with your credentials.',
      accountCreated: true,
      user: {
        id: result.lastID,
        email: pendingRegistration.email,
        name: pendingRegistration.name,
        mobileNumber: pendingRegistration.mobileNumber
      },
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

// RESEND OTP
router.post('/resend-otp', async (req, res) => {
  try {
    const { identifier } = req.body;

    if (!identifier) {
      return res.status(400).json({ error: 'Identifier is required' });
    }

    const now = Math.floor(Date.now() / 1000);

    // Check if there's a pending registration
    const pendingRegistration = await db.getAsync(
      'SELECT * FROM pending_registrations WHERE identifier = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1',
      [identifier, now]
    );

    if (!pendingRegistration) {
      return res.status(400).json({ error: 'No pending registration found. Please register again.' });
    }

    // Clean up existing OTPs for this identifier
    await db.runAsync(
      'DELETE FROM otps WHERE identifier = ? AND purpose = ?',
      [identifier, 'registration']
    );

    // Generate a new 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiresAt = Math.floor(Date.now() / 1000) + (10 * 60); // 10 minutes from now

    const otpType = pendingRegistration.email ? 'email' : 'mobile';

    // Send OTP
    try {
      await sendOTP(identifier, otp, otpType);
    } catch (emailError) {
      console.error('Failed to resend OTP:', emailError);
      return res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
    }

    // Store new OTP in the database
    await db.runAsync(
      'INSERT INTO otps (identifier, type, otp, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [identifier, otpType, otp, 'registration', otpExpiresAt, now]
    );

    res.json({ message: 'OTP resent successfully' });
  } catch (error) {
    console.error('Resend OTP error:', error);
    res.status(500).json({ error: 'Failed to resend OTP' });
  }
});

// VERIFY OTP FOR PASSWORD RESET
router.post('/verify-otp-reset', async (req, res) => {
  try {
    const { identifier, otp } = req.body;

    if (!identifier || !otp) {
      return res.status(400).json({ error: 'Identifier and OTP are required' });
    }

    const now = Math.floor(Date.now() / 1000);

    // Find a matching and unexpired OTP for password reset
    const otpRecord = await db.getAsync(
      'SELECT id FROM otps WHERE identifier = ? AND otp = ? AND purpose = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1',
      [identifier, otp, 'password_reset', now]
    );

    if (!otpRecord) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Generate a reset token
    const resetToken = crypto.randomUUID();
    const tokenExpiresAt = Math.floor(Date.now() / 1000) + (15 * 60); // 15 minutes from now

    // Store the reset token
    await db.runAsync(
      'INSERT INTO password_reset_tokens (identifier, token, expires_at, created_at) VALUES (?, ?, ?, ?)',
      [identifier, resetToken, tokenExpiresAt, Math.floor(Date.now() / 1000)]
    );

    // Delete the OTP record to prevent reuse
    await db.runAsync('DELETE FROM otps WHERE id = ?', [otpRecord.id]);

    res.json({ 
      message: 'OTP verified successfully',
      resetToken: resetToken
    });
  } catch (error) {
    console.error('Verify OTP for reset error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

// LOGIN - Enhanced with better error messages
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Find user
    const user = await db.getAsync(
      'SELECT * FROM users WHERE email = ?',
      [normalizedEmail]
    );
    
    // Check if account exists
    if (!user) {
      return res.status(404).json({ 
        error: 'Account not available',
        message: 'No account found with this email address. Please check your email or create a new account.'
      });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        error: 'Invalid password',
        message: 'The password you entered is incorrect. Please try again.'
      });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      message: 'Login successful',
      access_token: token,
      user: { 
        id: user.id,
        email: user.email,
        name: user.name
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// RESET PASSWORD - Verify Reset Token and Set New Password
router.post('/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    if (!resetToken || !newPassword) {
      return res.status(400).json({ error: 'Reset token and new password are required' });
    }

    const now = Math.floor(Date.now() / 1000);

    // Find a matching and unexpired reset token
    const tokenRecord = await db.getAsync(
      'SELECT id, identifier FROM password_reset_tokens WHERE token = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1',
      [resetToken, now]
    );

    if (!tokenRecord) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password
    await db.runAsync(
      'UPDATE users SET password = ? WHERE email = ? OR mobileNumber = ?',
      [hashedPassword, tokenRecord.identifier, tokenRecord.identifier]
    );

    // Delete the reset token to prevent reuse
    await db.runAsync('DELETE FROM password_reset_tokens WHERE id = ?', [tokenRecord.id]);

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// GET CURRENT USER
router.get('/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// FORGOT PASSWORD - Initiate
router.post('/forgot-password', async (req, res) => {
  try {
    const { identifier } = req.body;

    if (!identifier) {
      return res.status(400).json({ error: 'Email or mobile number is required' });
    }

    // Find user by email or mobile number
    const user = await db.getAsync(
      'SELECT id, email, mobileNumber FROM users WHERE email = ? OR mobileNumber = ?',
      [identifier, identifier]
    );

    // Always return success for security reasons, but only send OTP if user exists
    if (user) {
      // Clean up existing password reset OTPs for this identifier
      await db.runAsync(
        'DELETE FROM otps WHERE identifier = ? AND purpose = ?',
        [identifier, 'password_reset']
      );

      // Generate a 6-digit OTP
      const otp = crypto.randomInt(100000, 999999).toString();
      const expiresAt = Math.floor(Date.now() / 1000) + (10 * 60); // 10 minutes from now

      const otpType = user.email === identifier ? 'email' : 'mobile';

      // Send OTP
      try {
        await sendPasswordResetOTP(identifier, otp);
        console.log(`✅ Password reset OTP sent to ${identifier}: ${otp}`);
      } catch (emailError) {
        console.error('Failed to send password reset OTP:', emailError);
        return res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
      }

      // Store OTP in the database
      await db.runAsync(
        'INSERT INTO otps (identifier, type, otp, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        [identifier, otpType, otp, 'password_reset', expiresAt, Math.floor(Date.now() / 1000)]
      );
    } else {
      console.log(`❌ Password reset attempt for unknown identifier: ${identifier}`);
    }

    res.json({ message: 'If a matching account is found, an OTP has been sent.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Forgot password request failed' });
  }
});

export default router;