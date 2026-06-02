// routes/productRoutes.js
const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const { products, auditLogs, orders } = require('../config/db');
const { isAuthenticated, isAdmin } = require('../middleware/auth');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// ── SECURE UPLOAD FOLDER (outside web root) ──────────
// FIX #6: Store uploaded files OUTSIDE public folder to prevent direct URL access
const UPLOAD_DIR = path.join(__dirname, '../uploads_secure');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ── ALLOWED MIME TYPES (MIME + extension whitelist) ───
// FIX #6: Validate MIME type AND extension (double check)
const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp'];
const ALLOWED_EXT  = ['.jpg', '.jpeg', '.png', '.webp'];

// ── MULTER SETUP ──────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    // FIX #6: Rename to random UUID — prevents path traversal & enumeration
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uuidv4()}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  // FIX #6: Check BOTH MIME type and file extension
  if (ALLOWED_MIME.includes(file.mimetype) && ALLOWED_EXT.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Only JPG, PNG, or WEBP images are allowed.'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 2 * 1024 * 1024 } // FIX #6: Restrict to 2MB max
});

// ── SECURE FILE SERVE ROUTE ───────────────────────────
// FIX #6: Serve uploaded images through Express (not static) so access is controlled
router.get('/image/:filename', isAuthenticated, (req, res) => {
  const filename = path.basename(req.params.filename); // prevent path traversal
  const filePath = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).render('error', { code: 404, message: 'Image not found.' });
  }
  res.sendFile(filePath);
});

// ── SHOP (all logged in users) ────────────────────────
router.get('/', isAuthenticated, (req, res) => {
  const allProducts = products.all();
  // FIX #1: Trim and sanitize search input before use
  const search = req.query.search ? req.query.search.trim().substring(0, 100) : '';
  const filtered = search
    ? allProducts.filter(p =>
        p.name.toLowerCase().includes(search.toLowerCase()) ||
        p.category.toLowerCase().includes(search.toLowerCase()))
    : allProducts;
  res.render('products/shop', { products: filtered, user: req.session, search });
});

// ── PRODUCT DETAIL ────────────────────────────────────
router.get('/view/:id', isAuthenticated, (req, res) => {
  const product = products.findById(req.params.id);
  if (!product) return res.status(404).render('error', { code: 404, message: 'Product not found.' });
  res.render('products/detail', { product, user: req.session });
});

// ── ADMIN: MANAGE PRODUCTS ────────────────────────────
// FIX #3: isAdmin middleware enforces RBAC — only admin can access
router.get('/manage', isAuthenticated, isAdmin, (req, res) => {
  res.render('products/manage', { products: products.all(), user: req.session });
});

// ── ADMIN: CREATE ─────────────────────────────────────
router.get('/create', isAuthenticated, isAdmin, (req, res) => {
  res.render('products/form', { product: null, errors: [], user: req.session });
});

router.post('/create', isAuthenticated, isAdmin, (req, res, next) => {
  upload.single('image')(req, res, (err) => {
    if (err) {
      return res.status(400).render('products/form', {
        product: req.body,
        errors: [{ msg: err.message }],
        user: req.session
      });
    }
    next();
  });
}, [
  // FIX #1: Whitelist validation + escape on all inputs
  body('name').trim().notEmpty().withMessage('Product name is required')
    .isLength({ max: 100 }).withMessage('Name too long').escape(),
  body('description').trim().isLength({ max: 1000 }).withMessage('Description too long').escape(),
  body('price').isFloat({ min: 0.01 }).withMessage('Price must be a positive number'),
  body('stock').isInt({ min: 0 }).withMessage('Stock must be a whole number'),
  body('category').trim().notEmpty().withMessage('Category is required').escape(),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).render('products/form', { product: req.body, errors: errors.array(), user: req.session });
  }
  const { name, description, price, stock, category } = req.body;
  // Store only the UUID filename, served via /products/image/:filename
  const image = req.file ? req.file.filename : null;
  products.create({ name, description, price: parseFloat(price), stock: parseInt(stock), category, image });
  auditLogs.create(req.session.userId, `PRODUCT_CREATED: ${name}`, req.ip);
  res.redirect('/products/manage');
});

// ── ADMIN: EDIT ───────────────────────────────────────
router.get('/edit/:id', isAuthenticated, isAdmin, (req, res) => {
  const product = products.findById(req.params.id);
  if (!product) return res.status(404).render('error', { code: 404, message: 'Product not found.' });
  res.render('products/form', { product, errors: [], user: req.session });
});

router.post('/edit/:id', isAuthenticated, isAdmin, (req, res, next) => {
  upload.single('image')(req, res, (err) => {
    if (err) {
      const product = products.findById(req.params.id);
      return res.status(400).render('products/form', {
        product: { ...product, ...req.body },
        errors: [{ msg: err.message }],
        user: req.session
      });
    }
    next();
  });
}, [
  body('name').trim().notEmpty().withMessage('Product name is required').isLength({ max: 100 }).escape(),
  body('description').trim().isLength({ max: 1000 }).escape(),
  body('price').isFloat({ min: 0.01 }).withMessage('Price must be a positive number'),
  body('stock').isInt({ min: 0 }).withMessage('Stock must be a whole number'),
  body('category').trim().notEmpty().withMessage('Category is required').escape(),
], (req, res) => {
  const product = products.findById(req.params.id);
  if (!product) return res.status(404).render('error', { code: 404, message: 'Product not found.' });

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).render('products/form', { product: { ...product, ...req.body }, errors: errors.array(), user: req.session });
  }

  const { name, description, price, stock, category } = req.body;
  let image = product.image;

  if (req.file) {
    // Delete old file securely
    if (product.image) {
      const oldPath = path.join(UPLOAD_DIR, path.basename(product.image));
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }
    image = req.file.filename;
  }

  products.update(req.params.id, { name, description, price: parseFloat(price), stock: parseInt(stock), category, image });
  auditLogs.create(req.session.userId, `PRODUCT_UPDATED: ${name}`, req.ip);
  res.redirect('/products/manage');
});

// ── ADMIN: DELETE ─────────────────────────────────────
router.post('/delete/:id', isAuthenticated, isAdmin, (req, res) => {
  const product = products.findById(req.params.id);
  if (!product) return res.status(404).render('error', { code: 404, message: 'Product not found.' });

  if (product.image) {
    const imgPath = path.join(UPLOAD_DIR, path.basename(product.image));
    if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
  }

  products.delete(req.params.id);
  auditLogs.create(req.session.userId, `PRODUCT_DELETED: ${product.name}`, req.ip);
  res.redirect('/products/manage');
});

// ── BUY: CHECKOUT FORM ────────────────────────────────
router.get('/buy/:id', isAuthenticated, (req, res) => {
  const product = products.findById(req.params.id);
  if (!product) return res.status(404).render('error', { code: 404, message: 'Product not found.' });
  if (product.stock === 0) return res.redirect('/products/view/' + req.params.id);
  res.render('products/checkout', { product, errors: [], user: req.session });
});

router.post('/buy/:id', isAuthenticated, [
  // FIX #1: Validate and sanitize all checkout inputs
  body('full_name').trim().notEmpty().withMessage('Full name is required').escape(),
  body('phone').trim().notEmpty().withMessage('Phone number is required')
    .matches(/^\+?[\d\s\-]{7,15}$/).withMessage('Enter a valid phone number').escape(),
  body('address').trim().notEmpty().withMessage('Delivery address is required').escape(),
  body('card_number').trim().notEmpty().withMessage('Card number is required')
    .matches(/^\d{16}$/).withMessage('Card number must be 16 digits'),
  body('expiry').trim().notEmpty().withMessage('Expiry date is required')
    .matches(/^(0[1-9]|1[0-2])\/\d{2}$/).withMessage('Expiry must be MM/YY'),
  body('cvv').trim().matches(/^\d{3,4}$/).withMessage('CVV must be 3 or 4 digits'),
], (req, res) => {
  const product = products.findById(req.params.id);
  if (!product) return res.status(404).render('error', { code: 404, message: 'Product not found.' });

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).render('products/checkout', { product, errors: errors.array(), user: req.session });
  }

  const { full_name, phone, address } = req.body;
  // FIX #5: Card details are NOT saved to any log or database — sensitive data protection
  products.update(product.id, { stock: product.stock - 1 });

  orders.create({
    userId: req.session.userId,
    productId: product.id,
    productName: product.name,
    price: product.price,
    full_name,
    phone,
    address
    // card_number, cvv, expiry intentionally NOT stored
  });

  auditLogs.create(req.session.userId, `PRODUCT_PURCHASED: ${product.name}`, req.ip);
  res.render('products/order_success', { product, full_name, address, user: req.session });
});

module.exports = router;
