// server.js (final version)
// Place this file in your backend/ folder and run: node server.js

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

const app = express();

/* ================= CONFIG ================= */
const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend'); // if you serve frontend from backend

/* ================= EMAIL (nodemailer) ================= */
/*
.env should contain:
EMAIL_USER=youremail@gmail.com
EMAIL_PASS=<16-char app password from Google (NOT your normal gmail password)>
*/
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASS || ''
  }
});

transporter.verify()
  .then(() => console.log('✅ Email transporter verified'))
  .catch(err => console.warn('⚠️ Email transporter verify failed: ', err && err.message ? err.message : err));

async function sendMail({ to, subject, html, text }) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('⚠️ Email config missing, skipping sendMail to:', to);
    return;
  }
  try {
    await transporter.sendMail({
      from: `"Found-Hub" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
      text
    });
    console.log(`📧 Email sent to ${to} — subject: ${subject}`);
  } catch (err) {
    console.warn('❌ sendMail error:', err && err.message ? err.message : err);
  }
}

/* ================= MIDDLEWARE ================= */
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

/* ================= DATABASE ================= */
const dbFile = path.join(__dirname, 'foundhub.sqlite');
const db = new Database(dbFile);

// Initialize schema if db.sql present (safe: CREATE TABLE IF NOT EXISTS)
const sqlPath = path.join(__dirname, 'db.sql');
if (fs.existsSync(sqlPath)) {
  try {
    const initSQL = fs.readFileSync(sqlPath, 'utf8');
    db.exec(initSQL);
    console.log('✅ Database initialized (db.sql applied).');
  } catch (err) {
    console.error('❌ Error applying db.sql:', err && err.message ? err.message : err);
  }
} else {
  console.log('ℹ️ db.sql not found — assuming DB already exists.');
}

/* ================= HELPERS ================= */
const signToken = (u) => jwt.sign({ id: u.id, email: u.email, role: u.role, name: u.name }, JWT_SECRET, { expiresIn: '7d' });

const auth = (req, res, next) => {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const ownerOrAdmin = (userId, ownerId, role) => role === 'admin' || userId === ownerId;

/* ================= FILE UPLOAD (multer) ================= */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const d = path.join(__dirname, 'uploads');
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    cb(null, d);
  },
  filename: (req, file, cb) => {
    cb(null, `item_${Date.now()}${path.extname(file.originalname || '.jpg')}`);
  }
});
const upload = multer({ storage });

/* ================= ROUTES ================= */

/* health */
app.get('/api/status', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

/* ---------- AUTH ---------- */
app.post('/api/auth/signup', (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users(name,email,password_hash) VALUES (?,?,?)').run(name, email, hash);
    const user = db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(info.lastInsertRowid);
    return res.json({ user, token: signToken(user) });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Email already registered' });
    console.error('Signup error:', e && e.message ? e.message : e);
    return res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!u || !bcrypt.compareSync(password, u.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });

    const user = { id: u.id, name: u.name, email: u.email, role: u.role };
    return res.json({ user, token: signToken(user) });
  } catch (e) {
    console.error('Login error:', e && e.message ? e.message : e);
    return res.status(500).json({ error: 'Login failed' });
  }
});

/* ---------- ITEMS ---------- */
app.post('/api/items', auth, upload.single('photo'), (req, res) => {
  try {
    const { type, title, description = '', category = '', location = '' } = req.body;
    if (!type || !title) return res.status(400).json({ error: 'type and title required' });

    const photo_url = req.file ? `/uploads/${req.file.filename}` : null;
    const info = db.prepare('INSERT INTO items(type,title,description,category,location,photo_url,owner_id) VALUES (?,?,?,?,?,?,?)')
      .run(type, title, description, category, location, photo_url, req.user.id);

    const item = db.prepare('SELECT * FROM items WHERE id=?').get(info.lastInsertRowid);
    res.json(item);
  } catch (e) {
    console.error('Create item error:', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Failed to create item' });
  }
});

app.get('/api/items', (req, res) => {
  try {
    const { type, q } = req.query;
    const status = req.query.status || null;

    let sql = 'SELECT items.*, users.name AS owner_name FROM items JOIN users ON users.id=items.owner_id WHERE 1=1';
    const params = [];
    if (type) { sql += ' AND type=?'; params.push(type); }
    if (status) { sql += ' AND status=?'; params.push(status); }
    if (q) {
      sql += ' AND (title LIKE ? OR description LIKE ? OR location LIKE ? OR category LIKE ?)';
      params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
    }
    sql += ' ORDER BY date_reported DESC';
    const rows = db.prepare(sql).all(...params);
    res.json(rows);
  } catch (e) {
    console.error('Get items error:', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Failed to fetch items' });
  }
});

app.get('/api/items/:id', (req, res) => {
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if (!it) return res.status(404).json({ error: 'Not found' });
  res.json(it);
});

app.patch('/api/items/:id', auth, (req, res) => {
  try {
    const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
    if (!it) return res.status(404).json({ error: 'Not found' });
    if (!ownerOrAdmin(req.user.id, it.owner_id, req.user.role)) return res.status(403).json({ error: 'Forbidden' });

    const { title, description, category, location, status } = req.body;
    db.prepare(`UPDATE items SET title=COALESCE(?,title), description=COALESCE(?,description), category=COALESCE(?,category), location=COALESCE(?,location), status=COALESCE(?,status) WHERE id=?`)
      .run(title, description, category, location, status, req.params.id);

    const updated = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
    res.json(updated);
  } catch (e) {
    console.error('Patch item error:', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Failed to update item' });
  }
});

app.delete('/api/items/:id', auth, (req, res) => {
  try {
    const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
    if (!it) return res.status(404).json({ error: 'Not found' });
    if (!ownerOrAdmin(req.user.id, it.owner_id, req.user.role)) return res.status(403).json({ error: 'Forbidden' });

    db.prepare('DELETE FROM items WHERE id=?').run(req.params.id);
    res.json({ ok: true });
  } catch (e) {
    console.error('Delete item error:', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Failed to delete item' });
  }
});

/* ---------- CLAIMS ---------- */
app.post('/api/items/:id/claims', auth, async (req, res) => {
  try {
    const message = req.body.message || '';
    const item = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
    if (!item) return res.status(404).json({ error: 'Item not found' });
    if (item.owner_id === req.user.id) return res.status(403).json({ error: 'Cannot claim your own post' });

    const info = db.prepare('INSERT INTO claims(item_id,claimer_id,message) VALUES (?,?,?)').run(item.id, req.user.id, message);
    const claim = db.prepare('SELECT * FROM claims WHERE id=?').get(info.lastInsertRowid);

    // notify item owner by email (best-effort)
    const owner = db.prepare('SELECT id,name,email FROM users WHERE id=?').get(item.owner_id);
    if (owner && owner.email) {
      const html = `<h3>Hi ${owner.name || 'User'},</h3>
        <p>Your item <strong>${item.title}</strong> received a new claim.</p>
        <p><b>Claim message:</b><br/>${message ? message : '(no message)'}</p>
        <p>Login to your dashboard to review the claim.</p>`;
      sendMail({ to: owner.email, subject: `New claim for ${item.title}`, html });
    } else {
      console.warn('Owner has no email, skipping notification.');
    }

    res.json(claim);
  } catch (e) {
    console.error('Create claim error:', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Failed to submit claim' });
  }
});

// client's "my claims" (claims submitted by me)
app.get('/api/my/claims', auth, (req, res) => {
  try {
    const sql = `
      SELECT c.*, i.title, i.type
      FROM claims c
      JOIN items i ON i.id = c.item_id
      WHERE c.claimer_id = ?
      ORDER BY c.created_at DESC
    `;
    const rows = db.prepare(sql).all(req.user.id);
    res.json(rows);
  } catch (e) {
    console.error('Get my claims error:', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Failed to fetch claims' });
  }
});

// incoming claims for items I own
app.get('/api/incoming/claims', auth, (req, res) => {
  try {
    const sql = `
      SELECT 
        c.id, c.message, c.status, c.created_at, i.title, i.type, i.location,
        u.name AS claimer_name, u.email AS claimer_email
      FROM claims c
      JOIN items i ON i.id = c.item_id
      JOIN users u ON u.id = c.claimer_id
      WHERE i.owner_id = ?
      ORDER BY c.created_at DESC
    `;
    const rows = db.prepare(sql).all(req.user.id);
    res.json(rows);
  } catch (e) {
    console.error('Get incoming claims error:', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Failed to fetch incoming claims' });
  }
});

/* ---------- APPROVE / REJECT ---------- */
app.post('/api/claims/:id/decision', auth, async (req, res) => {
  try {
    const { decision } = req.body;
    if (!['approved', 'rejected'].includes(decision)) return res.status(400).json({ error: 'Invalid decision' });

    const claim = db.prepare('SELECT * FROM claims WHERE id=?').get(req.params.id);
    if (!claim) return res.status(404).json({ error: 'Claim not found' });

    const item = db.prepare('SELECT * FROM items WHERE id=?').get(claim.item_id);
    if (!item) return res.status(404).json({ error: 'Item not found' });

    if (!ownerOrAdmin(req.user.id, item.owner_id, req.user.role)) return res.status(403).json({ error: 'Forbidden' });

    db.prepare('UPDATE claims SET status=? WHERE id=?').run(decision, claim.id);

    if (decision === 'approved') {
      db.prepare('UPDATE items SET status=? WHERE id=?').run('claimed', item.id);
    }

    const updated = db.prepare('SELECT * FROM claims WHERE id=?').get(claim.id);

    // notify claimer by email
    const claimer = db.prepare('SELECT name,email FROM users WHERE id=?').get(claim.claimer_id);
    if (claimer && claimer.email) {
      const html = `<h3>Hi ${claimer.name || 'User'},</h3>
        <p>Your claim for <strong>${item.title}</strong> was <b>${decision}</b>.</p>
        <p>Login to Found-Hub for details.</p>`;
      sendMail({ to: claimer.email, subject: `Your claim for ${item.title} — ${decision}`, html });
    }

    res.json(updated);
  } catch (e) {
    console.error('Decision error:', e && e.message ? e.message : e);
    res.status(500).json({ error: 'Failed to update claim decision' });
  }
});





/* ================= START ================= */
app.listen(PORT, () => {
  console.log(`🚀 Found-Hub API running on http://localhost:${PORT}`);
  console.log('Make sure frontend uses same API base (e.g. http://localhost:4000)');
});

