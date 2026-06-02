const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const { users, auditLogs, products } = require('../config/db');
const { isAuthenticated, isAdmin } = require('../middleware/auth');

router.get('/profile', isAuthenticated, (req, res) => {
  const user = users.findById(req.session.userId);
  if (!user) return res.redirect('/auth/login');
  const { password, ...safeUser } = user;
  res.render('profile', { user: safeUser, errors: [], success: null });
});

router.post('/profile', isAuthenticated, [
  body('username').trim().isAlphanumeric().withMessage('Username must be letters and numbers only').isLength({ min: 3, max: 20 }),
  body('email').normalizeEmail().isEmail().withMessage('Enter a valid email'),
  body('new_password').optional({ checkFalsy: true })
    .isLength({ min: 8 }).withMessage('Min 8 characters')
    .matches(/[A-Z]/).withMessage('Must contain uppercase')
    .matches(/[0-9]/).withMessage('Must contain number')
    .matches(/[^A-Za-z0-9]/).withMessage('Must contain special character'),
], async (req, res) => {
  const user = users.findById(req.session.userId);
  if (!user) return res.redirect('/auth/login');
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const { password, ...safeUser } = user;
    return res.status(400).render('profile', { user: safeUser, errors: errors.array(), success: null });
  }
  const { username, email, new_password, current_password } = req.body;
  const updates = { username, email };
  if (new_password) {
    const match = await bcrypt.compare(current_password, user.password);
    if (!match) {
      const { password, ...safeUser } = user;
      return res.status(400).render('profile', { user: safeUser, errors: [{ msg: 'Current password is incorrect' }], success: null });
    }
    updates.password = await bcrypt.hash(new_password, 12);
  }
  users.update(req.session.userId, updates);
  req.session.username = username;
  auditLogs.create(req.session.userId, 'PROFILE_UPDATED', req.ip);
  const updated = users.findById(req.session.userId);
  const { password, ...safeUpdated } = updated;
  res.render('profile', { user: safeUpdated, errors: [], success: 'Profile updated successfully!' });
});

router.get('/audit-logs', isAuthenticated, isAdmin, (req, res) => {
  const logs = auditLogs.all();
  const allUsers = users.all();
  const enriched = logs.map(log => {
    const u = allUsers.find(u => u.id === log.user_id);
    return { ...log, username: u ? u.username : 'Guest' };
  });
  res.render('audit', { logs: enriched, user: req.session });
});

router.get('/dashboard', isAuthenticated, (req, res) => {
  const allProducts = products.all();
  const allUsers = users.all();
  res.render('dashboard', { user: req.session, products: allProducts, totalUsers: allUsers.length });
});

module.exports = router;
