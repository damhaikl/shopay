// middleware/auth.js

// Checks if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.redirect('/auth/login');
}

// Checks if user is admin
function isAdmin(req, res, next) {
  if (req.session && req.session.role === 'admin') {
    return next();
  }
  res.status(403).render('error', { code: 403, message: 'Access denied. Admins only.' });
}

module.exports = { isAuthenticated, isAdmin };
