const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const SECRET = 'supersecretkey'; // obviously change this in production
const ADMIN_USER = 'HallowByThyName';
const ADMIN_PASS = 'cr1msonr3fused';

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database(path.join(__dirname, 'db.sqlite'));

// Ensure posts table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    content TEXT,
    ip TEXT,
    created_at INTEGER
  )`);
});

// Json file for user secrets
const usersFile = path.join(__dirname, 'users.json');
if (!fs.existsSync(usersFile)) {
  fs.writeFileSync(usersFile, JSON.stringify({}));
}
function loadUsers() {
  return JSON.parse(fs.readFileSync(usersFile, 'utf8'));
}
function saveUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

// Bans
let bannedUsers = new Set();
let bannedIps = new Set();

// Utils
function generateId() {
  return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}
function nowTs() {
  return Math.floor(Date.now() / 1000);
}

// Middleware auth
function auth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'no token' });
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    if (bannedUsers.has(decoded.username)) return res.status(403).json({ error: 'user banned' });
    if (bannedIps.has(req.ip)) return res.status(403).json({ error: 'ip banned' });
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// Register
app.post('/api/register', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });
  if (bannedUsers.has(username)) return res.status(403).json({ error: 'banned username' });

  const users = loadUsers();
  if (users[username]) return res.status(400).json({ error: 'username exists' });

  const secret = Math.random().toString(36).slice(2);
  const token = jwt.sign({ username }, SECRET);
  const id = generateId();

  users[username] = { id, secret, created: new Date().toISOString(), ip: req.ip };
  saveUsers(users);

  return res.json({ username, secret, token, id });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, secret } = req.body;
  if (!username || !secret) return res.status(400).json({ error: 'missing' });
  if (bannedUsers.has(username)) return res.status(403).json({ error: 'banned' });

  const users = loadUsers();
  if (!users[username]) return res.status(404).json({ error: 'not registered' });
  if (users[username].secret !== secret) return res.status(401).json({ error: 'invalid secret' });

  const token = jwt.sign({ username }, SECRET);
  return res.json({ token });
});

// Create post
app.post('/api/pastes', auth, (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'empty' });
  if (bannedIps.has(req.ip)) return res.status(403).json({ error: 'ip banned' });

  db.run(
    'INSERT INTO posts (username, content, ip, created_at) VALUES (?,?,?,?)',
    [req.user.username, content, req.ip, nowTs()],
    function (err) {
      if (err) return res.status(500).json({ error: 'db error' });
      res.json({ id: this.lastID });
    }
  );
});

// List posts
app.get('/api/pastes', (req, res) => {
  db.all('SELECT * FROM posts ORDER BY id DESC LIMIT 100', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json(rows);
  });
});

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ admin: true }, SECRET);
    return res.json({ token });
  }
  return res.status(401).json({ error: 'bad creds' });
});

function adminAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'no token' });
  const token = auth.split(' ')[1];
  try {
    const dec = jwt.verify(token, SECRET);
    if (!dec.admin) throw Error('not admin');
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid admin token' });
  }
}

// Admin endpoints
app.get('/api/admin/pastes', adminAuth, (req, res) => {
  db.all('SELECT * FROM posts ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json(rows);
  });
});
app.delete('/api/admin/pastes/:id', adminAuth, (req, res) => {
  db.run('DELETE FROM posts WHERE id=?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json({ success: true });
  });
});
app.get('/api/admin/users', adminAuth, (req, res) => {
  try {
    const users = loadUsers();
    res.json(users);
  } catch (e) {
    res.json({});
  }
});
app.post('/api/admin/ban/user/:username', adminAuth, (req, res) => {
  bannedUsers.add(req.params.username);
  res.json({ success: true });
});
app.post('/api/admin/ban/ip/:ip', adminAuth, (req, res) => {
  bannedIps.add(req.params.ip);
  res.json({ success: true });
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running at http://localhost:' + PORT));