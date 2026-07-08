const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const SESSION_COOKIE = 'acnh_session';
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;
const PASSWORD_ITERATIONS = 210000;
const PASSWORD_KEY_LENGTH = 64;
const PASSWORD_DIGEST = 'sha512';

const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'database.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

fs.mkdirSync(DATA_DIR, { recursive: true });

function emptyDb() {
  return {
    nextUserId: 1,
    users: [],
    progress: {},
    sessions: {}
  };
}

function loadDb() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const db = emptyDb();
      saveDb(db);
      return db;
    }

    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    db.nextUserId = db.nextUserId || 1;
    db.users = Array.isArray(db.users) ? db.users : [];
    db.progress = db.progress && typeof db.progress === 'object' ? db.progress : {};
    db.sessions = db.sessions && typeof db.sessions === 'object' ? db.sessions : {};
    return db;
  } catch (error) {
    console.error('Datenbank konnte nicht gelesen werden:', error);
    return emptyDb();
  }
}

function saveDb(db) {
  const tempFile = DB_FILE + '.tmp';
  fs.writeFileSync(tempFile, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tempFile, DB_FILE);
}

function parseCookies(cookieHeader = '') {
  const cookies = {};

  cookieHeader.split(';').forEach(part => {
    const trimmed = part.trim();
    if (!trimmed) return;

    const index = trimmed.indexOf('=');
    if (index === -1) return;

    const key = trimmed.slice(0, index);
    const value = trimmed.slice(index + 1);

    try {
      cookies[key] = decodeURIComponent(value);
    } catch (error) {
      cookies[key] = value;
    }
  });

  return cookies;
}

function setSessionCookie(req, res, token) {
  const attributes = [
    `Max-Age=${SESSION_MAX_AGE_SECONDS}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/'
  ];

  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    attributes.push('Secure');
  }

  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(token)}; ${attributes.join('; ')}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/`);
}

function cleanExpiredSessions(db) {
  const now = Date.now();
  let changed = false;

  for (const [token, session] of Object.entries(db.sessions)) {
    if (!session || session.expiresAt <= now) {
      delete db.sessions[token];
      changed = true;
    }
  }

  if (changed) {
    saveDb(db);
  }
}

function getSession(db, req) {
  cleanExpiredSessions(db);

  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies[SESSION_COOKIE];

  if (!token || !db.sessions[token]) {
    return null;
  }

  const session = db.sessions[token];
  const user = db.users.find(item => item.id === session.userId);

  if (!user) {
    delete db.sessions[token];
    saveDb(db);
    return null;
  }

  return { token, session, user };
}

function createSession(db, userId) {
  const token = crypto.randomBytes(32).toString('hex');

  db.sessions[token] = {
    userId,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_MAX_AGE_SECONDS * 1000
  };

  return token;
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username
  };
}

function normalizeUsername(value) {
  return String(value || '').trim();
}

function validateUsername(username) {
  if (username.length < 3 || username.length > 24) {
    return 'Der Name muss zwischen 3 und 24 Zeichen haben.';
  }

  if (!/^[a-zA-Z0-9_\-äöüÄÖÜß]+$/.test(username)) {
    return 'Der Name darf nur Buchstaben, Zahlen, Unterstrich und Bindestrich enthalten.';
  }

  return '';
}

function validatePassword(password) {
  if (String(password || '').length < 4) {
    return 'Das Passwort muss mindestens 4 Zeichen haben.';
  }

  if (String(password || '').length > 80) {
    return 'Das Passwort ist zu lang.';
  }

  return '';
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .pbkdf2Sync(String(password), salt, PASSWORD_ITERATIONS, PASSWORD_KEY_LENGTH, PASSWORD_DIGEST)
    .toString('hex');

  return {
    salt,
    hash,
    iterations: PASSWORD_ITERATIONS,
    keyLength: PASSWORD_KEY_LENGTH,
    digest: PASSWORD_DIGEST
  };
}

function verifyPassword(password, passwordData) {
  if (!passwordData || !passwordData.salt || !passwordData.hash) {
    return false;
  }

  const expected = Buffer.from(passwordData.hash, 'hex');
  const actual = crypto.pbkdf2Sync(
    String(password),
    passwordData.salt,
    passwordData.iterations || PASSWORD_ITERATIONS,
    passwordData.keyLength || PASSWORD_KEY_LENGTH,
    passwordData.digest || PASSWORD_DIGEST
  );

  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

function requireLogin(req, res, next) {
  const db = loadDb();
  const current = getSession(db, req);

  if (!current) {
    return res.status(401).json({ error: 'Bitte zuerst anmelden.' });
  }

  req.db = db;
  req.currentUser = current.user;
  req.currentSession = current;
  next();
}

function progressForUser(db, userId) {
  const progress = db.progress[String(userId)] || {};

  return Object.entries(progress).map(([key, value]) => ({
    critter_key: key,
    type: value.type || '',
    caught: value.caught === true,
    donated: value.donated === true,
    updatedAt: value.updatedAt || null
  }));
}

function buildRanking(db) {
  const rows = db.users.map(user => {
    const progress = db.progress[String(user.id)] || {};
    const values = Object.values(progress);

    return {
      username: user.username,
      caught: values.filter(item => item.caught === true).length,
      donated: values.filter(item => item.donated === true).length,
      updatedAt: values.reduce((latest, item) => Math.max(latest, item.updatedAt || 0), 0)
    };
  });

  rows.sort((a, b) => {
    if (b.caught !== a.caught) return b.caught - a.caught;
    if (b.donated !== a.donated) return b.donated - a.donated;
    if (b.updatedAt !== a.updatedAt) return b.updatedAt - a.updatedAt;
    return a.username.localeCompare(b.username, 'de');
  });

  return rows.map((row, index) => ({
    rank: index + 1,
    username: row.username,
    caught: row.caught,
    donated: row.donated
  }));
}

app.use(express.json({ limit: '100kb' }));
app.use(express.static(PUBLIC_DIR));

app.get('/api/me', (req, res) => {
  const db = loadDb();
  const current = getSession(db, req);

  if (!current) {
    return res.json({ user: null, progress: [] });
  }

  res.json({
    user: publicUser(current.user),
    progress: progressForUser(db, current.user.id)
  });
});

app.post('/api/register', (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || '');
  const usernameError = validateUsername(username);
  const passwordError = validatePassword(password);

  if (usernameError) return res.status(400).json({ error: usernameError });
  if (passwordError) return res.status(400).json({ error: passwordError });

  const db = loadDb();
  const usernameKey = username.toLowerCase();

  if (db.users.some(user => user.usernameKey === usernameKey)) {
    return res.status(409).json({ error: 'Dieser Name ist bereits vergeben.' });
  }

  const user = {
    id: db.nextUserId++,
    username,
    usernameKey,
    password: hashPassword(password),
    createdAt: Date.now()
  };

  db.users.push(user);
  const token = createSession(db, user.id);
  saveDb(db);
  setSessionCookie(req, res, token);

  res.status(201).json({ user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || '');
  const db = loadDb();
  const usernameKey = username.toLowerCase();
  const user = db.users.find(item => item.usernameKey === usernameKey);

  if (!user || !verifyPassword(password, user.password)) {
    return res.status(401).json({ error: 'Name oder Passwort ist falsch.' });
  }

  user.lastLoginAt = Date.now();
  const token = createSession(db, user.id);
  saveDb(db);
  setSessionCookie(req, res, token);

  res.json({ user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  const db = loadDb();
  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies[SESSION_COOKIE];

  if (token && db.sessions[token]) {
    delete db.sessions[token];
    saveDb(db);
  }

  clearSessionCookie(res);
  res.json({ ok: true });
});

app.post('/api/progress', requireLogin, (req, res) => {
  const key = String(req.body.key || '').trim();
  const type = String(req.body.type || '').trim();

  if (key.length < 2 || key.length > 120) {
    return res.status(400).json({ error: 'Ungültiger Tier-Schlüssel.' });
  }

  const userId = String(req.currentUser.id);

  if (!req.db.progress[userId]) {
    req.db.progress[userId] = {};
  }

  req.db.progress[userId][key] = {
    type: type.slice(0, 40),
    caught: req.body.caught === true,
    donated: req.body.donated === true,
    updatedAt: Date.now()
  };

  saveDb(req.db);
  res.json({ ok: true, item: req.db.progress[userId][key] });
});

app.get('/api/ranking', (req, res) => {
  const db = loadDb();
  res.json({ ranking: buildRanking(db) });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`ACNH Tracker läuft auf http://localhost:${PORT}`);
});
