require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const path = require('path');
const fs = require('fs');

const authRoutes = require('./routes/authRoutes');
const productRoutes = require('./routes/productRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();

// FIX #7: Disable X-Powered-By header (hide framework info)
app.disable('x-powered-by');

// FIX #7: Configuration Security — debug mode disabled in production
if (process.env.NODE_ENV === 'production') {
  app.set('env', 'production');
}

// FIX #10 + #7: Helmet sets secure HTTP headers including CSP to prevent XSS
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  // FIX #5: HSTS — force HTTPS connections
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// FIX #2: Secure session — HttpOnly, SameSite, 30 min timeout, Secure in production
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,                                          // Prevent JS access to cookie
    secure: process.env.NODE_ENV === 'production',           // HTTPS only in production
    sameSite: 'strict',                                      // CSRF protection layer 2
    maxAge: 1000 * 60 * 30                                   // 30 minute session timeout
  }
}));

// FIX #2: CSRF protection — all POST forms require valid token
app.use(csrf());
app.use((req, res, next) => { res.locals.csrfToken = req.csrfToken(); next(); });

// FIX #2: Rate limiting — brute force protection on auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                   // max 10 attempts
  message: 'Too many attempts, please try again later.'
});
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);

app.get('/', (req, res) => req.session.userId ? res.redirect('/dashboard') : res.redirect('/auth/login'));
app.use('/auth', authRoutes);
app.use('/products', productRoutes);
app.use('/', userRoutes);

// FIX #4: Custom error pages — no stack traces exposed to users
app.use((req, res) => res.status(404).render('error', { code: 404, message: 'Page not found.' }));
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).render('error', { code: 403, message: 'Invalid form token. Please go back and try again.' });
  }
  // FIX #8: Log error server-side but NEVER expose stack trace to user
  console.error('[ERROR]', err.message); // No stack trace in log either
  res.status(500).render('error', { code: 500, message: 'Something went wrong.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Shopay running at http://localhost:${PORT}`));

// Auto-create admin on first run
const bcrypt = require('bcrypt');
const { users } = require('./config/db');
(async () => {
  if (!users.findByEmail('admin@shopay.com')) {
    const hashed = await bcrypt.hash('Admin@1234', 12);
    const admin = users.create({ username: 'admin', email: 'admin@shopay.com', password: hashed });
    users.update(admin.id, { role: 'admin' });
    console.log('Admin created: admin@shopay.com / Admin@1234');
  }
})();
