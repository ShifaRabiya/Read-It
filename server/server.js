require('dotenv').config();
console.log('Your secret is:', process.env.JWT_SECRET);

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const resetTokens = {};

const User = require('./models/User'); // Your User model

//middlewares
const app = express();
app.use(cors());
app.use(express.json());

const path = require('path');
app.use(express.static(path.join(__dirname, '../client')));

const PORT = process.env.PORT || 5000;

// Middleware to authenticate and extract user info from JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) return res.status(401).json({ message: 'Missing token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user; // user.userId will contain the logged-in user's ID
    next();
  });
}

// Connect to MongoDB
mongoose.connect('mongodb+srv://shifarabiya4216:4FQY802jzaUwoOfO@cluster0.cnfaduy.mongodb.net/readit-db?retryWrites=true&w=majority&appName=Cluster0')
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Create Nodemailer transporter once here
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL,       
    pass: process.env.PASS
  }
});

// SIGNUP route
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { name }] });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword });

    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Signup failed', error: err.message });
  }
});

// LOGIN route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid password' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({
      message: 'Login successful',
      token,
      userId: user._id,
      name: user.name,
      email: user.email
    });
    console.log('Logging in user:', user.name, user.email);

  } catch (err) {
    res.status(500).json({ message: 'Login failed', error: err.message });
  }
});

// FORGOT PASSWORD route
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const token = crypto.randomBytes(32).toString('hex');
    resetTokens[token] = {
      userId: user._id,
      expires: Date.now() + 3600000 // 1 hour
    };

    const resetLink = `http://localhost:5000/reset-password.html?token=${token}`;

    await transporter.sendMail({
      from: '"Read-It" <no-reply@readit.com>',
      to: email,
      subject: 'Password Reset',
      text: `Click this link to reset your password: ${resetLink}`
    });

    res.json({ message: 'Reset link sent to your email.' });
  } catch (err) {
    console.error('Error sending reset email:', err);
    res.status(500).json({ message: 'Failed to send reset link' });
  }
});

// RESET PASSWORD route
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  const data = resetTokens[token];

  if (!data || Date.now() > data.expires) {
    return res.status(400).json({ message: 'Invalid or expired token' });
  }

  try {
    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(data.userId, { password: hashed });
    delete resetTokens[token];

    res.json({ message: 'Password successfully reset!' });
  } catch (err) {
    console.error('Error resetting password:', err);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// UPDATE USER PROFILE route
app.put('/api/update-profile', async (req, res) => {
  const { userId, name, email, password } = req.body;

  if (!userId) return res.status(400).json({ message: 'User ID not found' });

  try {
    const updateData = {};

    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateData.password = hashedPassword;
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updateData, { new: true });

    if (!updatedUser) return res.status(404).json({ message: 'User not found' });

    res.json({
      message: 'Profile updated successfully',
      name: updatedUser.name,
      email: updatedUser.email
    });
  } catch (error) {
      if (error.code === 11000) {
        return res.status(400).json({ message: 'Name or email already in use' });
      }
    res.status(500).json({ message: 'Failed to update profile', error: error.message });
  }
});

// Get current user profile (protected)
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

