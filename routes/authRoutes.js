// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const { users, auditLogs } = require('../config/db');

const SALT_ROUNDS = 12;

// ── REGISTER ──────────────────────────────────────────
router.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('register', { errors: [], old: {} });
});

router.post('/register', [
  body('username')
    .trim()
    .isAlphanumeric().withMessage('Username must contain letters and numbers only')
    .isLength({ min: 3, max: 20 }).withMessage('Username must be 3–20 characters'),
  body('email')
    .normalizeEmail()
    .isEmail().withMessage('Enter a valid email address'),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain a number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must contain a special character'),
  body('confirm_password').custom((val, { req }) => {
    if (val !== req.body.password) throw new Error('Passwords do not match');
    return true;
  })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('register', {
      errors: errors.array(),
      old: { username: req.body.username, email: req.body.email }
    });
  }

  const { username, email, password } = req.body;

  try {
    // Check duplicates
    if (users.findByEmail(email) || users.findByUsername(username)) {
      return res.status(400).render('register', {
        errors: [{ msg: 'Username or email already taken' }],
        old: { username, email }
      });
    }

    // Hash password - never store plaintext
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const user = users.create({ username, email, password: hashed });
    auditLogs.create(user.id, 'USER_REGISTERED', req.ip);

    res.redirect('/auth/login?registered=1');
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).render('error', { code: 500, message: 'Registration failed. Please try again.' });
  }
});

// ── LOGIN ─────────────────────────────────────────────
router.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('login', {
    errors: [],
    success: req.query.registered ? 'Account created! Please log in.' : null
  });
});

router.post('/login', [
  body('email').normalizeEmail().isEmail().withMessage('Enter a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('login', { errors: errors.array(), success: null });
  }

  const { email, password } = req.body;

  try {
    const user = users.findByEmail(email);

    // Always run bcrypt (prevents timing attacks even if user not found)
    const dummyHash = '$2b$12$invalidhashfortimingatk';
    const match = user
      ? await bcrypt.compare(password, user.password)
      : await bcrypt.compare(password, dummyHash).then(() => false);

    if (!match) {
      auditLogs.create(user?.id || null, 'LOGIN_FAILED', req.ip);
      // Same message whether email or password is wrong (no user enumeration)
      return res.status(401).render('login', {
        errors: [{ msg: 'Invalid email or password' }],
        success: null
      });
    }

    // Regenerate session to prevent session fixation attack
    req.session.regenerate((err) => {
      if (err) return res.status(500).render('error', { code: 500, message: 'Login error' });

      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.username = user.username;

      auditLogs.create(user.id, 'LOGIN_SUCCESS', req.ip);
      res.redirect('/dashboard');
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).render('error', { code: 500, message: 'Login error. Please try again.' });
  }
});

// ── LOGOUT ────────────────────────────────────────────
router.post('/logout', (req, res) => {
  const userId = req.session.userId;
  req.session.destroy(() => {
    auditLogs.create(userId, 'LOGOUT', req.ip);
    res.clearCookie('connect.sid');
    res.redirect('/auth/login');
  });
});

module.exports = router;
