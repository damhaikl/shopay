const fs = require('fs');
const path = require('path');
const DB_PATH = path.join(__dirname, 'data.json');

function initDB() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], products: [], audit_logs: [], orders: [] }, null, 2));
  }
}
function readDB() { initDB(); return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
function writeDB(data) { fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2)); }

const users = {
  findByEmail: (email) => readDB().users.find(u => u.email === email) || null,
  findByUsername: (username) => readDB().users.find(u => u.username === username) || null,
  findById: (id) => readDB().users.find(u => u.id === id) || null,
  create: (user) => {
    const db = readDB();
    const newUser = { id: Date.now().toString(), ...user, role: 'user', created_at: new Date().toISOString() };
    db.users.push(newUser); writeDB(db); return newUser;
  },
  update: (id, fields) => {
    const db = readDB();
    const idx = db.users.findIndex(u => u.id === id);
    if (idx === -1) return null;
    db.users[idx] = { ...db.users[idx], ...fields }; writeDB(db); return db.users[idx];
  },
  all: () => readDB().users
};

const products = {
  findById: (id) => readDB().products.find(p => p.id === id) || null,
  all: () => readDB().products,
  create: (product) => {
    const db = readDB();
    const newProduct = { id: Date.now().toString(), ...product, created_at: new Date().toISOString() };
    db.products.push(newProduct); writeDB(db); return newProduct;
  },
  update: (id, fields) => {
    const db = readDB();
    const idx = db.products.findIndex(p => p.id === id);
    if (idx === -1) return null;
    db.products[idx] = { ...db.products[idx], ...fields }; writeDB(db); return db.products[idx];
  },
  delete: (id) => {
    const db = readDB();
    db.products = db.products.filter(p => p.id !== id); writeDB(db);
  }
};

const auditLogs = {
  create: (userId, action, ip) => {
    const db = readDB();
    db.audit_logs.push({ id: Date.now().toString(), user_id: userId, action, ip, timestamp: new Date().toISOString() });
    writeDB(db);
  },
  all: () => readDB().audit_logs.slice().reverse()
};

const orders = {
  create: (order) => {
    const db = readDB();
    if (!db.orders) db.orders = [];
    const newOrder = { id: Date.now().toString(), ...order, status: 'paid', created_at: new Date().toISOString() };
    db.orders.push(newOrder);
    writeDB(db);
    return newOrder;
  },
  findByUser: (userId) => {
    const db = readDB();
    return (db.orders || []).filter(o => o.userId === userId);
  },
  all: () => {
    const db = readDB();
    return db.orders || [];
  }
};

module.exports = { users, products, auditLogs, orders };