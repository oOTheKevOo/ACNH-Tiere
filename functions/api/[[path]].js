const SESSION_COOKIE = 'acnh_session';
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;
const PASSWORD_ITERATIONS = 150000;
const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...headers
    }
  });
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

function setCookieHeader(token) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Max-Age=${SESSION_MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Lax; Path=/`;
}

function clearCookieHeader() {
  return `${SESSION_COOKIE}=; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Path=/`;
}

function randomHex(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach(byte => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function passwordHash(password, saltBase64, iterations = PASSWORD_ITERATIONS) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(String(password)),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: base64ToBytes(saltBase64),
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  return bytesToBase64(new Uint8Array(derivedBits));
}

async function createPassword(password) {
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const salt = bytesToBase64(saltBytes);
  const hash = await passwordHash(password, salt, PASSWORD_ITERATIONS);

  return { salt, hash, iterations: PASSWORD_ITERATIONS };
}

function constantTimeEqual(a, b) {
  const textA = String(a || '');
  const textB = String(b || '');
  if (textA.length !== textB.length) return false;

  let result = 0;
  for (let i = 0; i < textA.length; i++) {
    result |= textA.charCodeAt(i) ^ textB.charCodeAt(i);
  }
  return result === 0;
}

async function verifyPassword(password, user) {
  if (!user || !user.password_salt || !user.password_hash) return false;

  const hash = await passwordHash(
    password,
    user.password_salt,
    user.password_iterations || PASSWORD_ITERATIONS
  );

  return constantTimeEqual(hash, user.password_hash);
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

async function readJson(request) {
  try {
    return await request.json();
  } catch (error) {
    return {};
  }
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username
  };
}

async function cleanExpiredSessions(db) {
  await db.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(Date.now()).run();
}

async function getCurrentUser(request, db) {
  await cleanExpiredSessions(db);

  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const token = cookies[SESSION_COOKIE];

  if (!token) return null;

  const row = await db.prepare(`
    SELECT
      users.id,
      users.username,
      users.username_key,
      sessions.token
    FROM sessions
    INNER JOIN users ON users.id = sessions.user_id
    WHERE sessions.token = ? AND sessions.expires_at > ?
    LIMIT 1
  `).bind(token, Date.now()).first();

  return row || null;
}

async function createSession(db, userId) {
  const token = randomHex(32);
  const now = Date.now();

  await db.prepare(`
    INSERT INTO sessions (token, user_id, created_at, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(token, userId, now, now + SESSION_MAX_AGE_SECONDS * 1000).run();

  return token;
}

async function getProgressForUser(db, userId) {
  const result = await db.prepare(`
    SELECT
      critter_key,
      type,
      caught,
      donated,
      updated_at AS updatedAt
    FROM progress
    WHERE user_id = ?
    ORDER BY critter_key ASC
  `).bind(userId).all();

  return result.results || [];
}

async function handleMe(request, env) {
  const current = await getCurrentUser(request, env.DB);

  if (!current) {
    return json({ user: null, progress: [] });
  }

  return json({
    user: publicUser(current),
    progress: await getProgressForUser(env.DB, current.id)
  });
}

async function handleRegister(request, env) {
  const body = await readJson(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password || '');
  const usernameError = validateUsername(username);
  const passwordError = validatePassword(password);

  if (usernameError) return json({ error: usernameError }, 400);
  if (passwordError) return json({ error: passwordError }, 400);

  const usernameKey = username.toLowerCase();
  const existing = await env.DB.prepare('SELECT id FROM users WHERE username_key = ? LIMIT 1')
    .bind(usernameKey)
    .first();

  if (existing) {
    return json({ error: 'Dieser Name ist bereits vergeben.' }, 409);
  }

  const passwordData = await createPassword(password);
  const now = Date.now();

  await env.DB.prepare(`
    INSERT INTO users (username, username_key, password_salt, password_hash, password_iterations, created_at, last_login_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    username,
    usernameKey,
    passwordData.salt,
    passwordData.hash,
    passwordData.iterations,
    now,
    now
  ).run();

  const user = await env.DB.prepare('SELECT id, username, username_key FROM users WHERE username_key = ? LIMIT 1')
    .bind(usernameKey)
    .first();

  const token = await createSession(env.DB, user.id);

  return json({ user: publicUser(user) }, 201, {
    'Set-Cookie': setCookieHeader(token)
  });
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password || '');
  const usernameKey = username.toLowerCase();

  const user = await env.DB.prepare(`
    SELECT id, username, username_key, password_salt, password_hash, password_iterations
    FROM users
    WHERE username_key = ?
    LIMIT 1
  `).bind(usernameKey).first();

  if (!user || !(await verifyPassword(password, user))) {
    return json({ error: 'Name oder Passwort ist falsch.' }, 401);
  }

  await env.DB.prepare('UPDATE users SET last_login_at = ? WHERE id = ?')
    .bind(Date.now(), user.id)
    .run();

  const token = await createSession(env.DB, user.id);

  return json({ user: publicUser(user) }, 200, {
    'Set-Cookie': setCookieHeader(token)
  });
}

async function handleLogout(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const token = cookies[SESSION_COOKIE];

  if (token) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }

  return json({ ok: true }, 200, {
    'Set-Cookie': clearCookieHeader()
  });
}

async function handleProgress(request, env) {
  const current = await getCurrentUser(request, env.DB);

  if (!current) {
    return json({ error: 'Bitte zuerst anmelden.' }, 401);
  }

  const body = await readJson(request);
  const key = String(body.key || '').trim();
  const type = String(body.type || '').trim().slice(0, 40);

  if (key.length < 2 || key.length > 120) {
    return json({ error: 'Ungültiger Tier-Schlüssel.' }, 400);
  }

  const caught = body.caught === true ? 1 : 0;
  const donated = body.donated === true ? 1 : 0;
  const updatedAt = Date.now();

  await env.DB.prepare(`
    INSERT INTO progress (user_id, critter_key, type, caught, donated, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, critter_key)
    DO UPDATE SET
      type = excluded.type,
      caught = excluded.caught,
      donated = excluded.donated,
      updated_at = excluded.updated_at
  `).bind(current.id, key, type, caught, donated, updatedAt).run();

  return json({
    ok: true,
    item: {
      type,
      caught: caught === 1,
      donated: donated === 1,
      updatedAt
    }
  });
}

async function handleRanking(env) {
  const result = await env.DB.prepare(`
    SELECT
      users.username AS username,
      COALESCE(SUM(CASE WHEN progress.caught = 1 THEN 1 ELSE 0 END), 0) AS caught,
      COALESCE(SUM(CASE WHEN progress.donated = 1 THEN 1 ELSE 0 END), 0) AS donated,
      COALESCE(MAX(progress.updated_at), 0) AS updatedAt
    FROM users
    LEFT JOIN progress ON progress.user_id = users.id
    GROUP BY users.id, users.username
    ORDER BY caught DESC, donated DESC, updatedAt DESC, users.username ASC
    LIMIT 100
  `).all();

  const ranking = (result.results || []).map((row, index) => ({
    rank: index + 1,
    username: row.username,
    caught: Number(row.caught || 0),
    donated: Number(row.donated || 0)
  }));

  return json({ ranking });
}

function missingDatabaseResponse() {
  return json({ error: 'Cloudflare D1 ist noch nicht verbunden. Bitte eine D1-Bindung mit dem Namen DB anlegen.' }, 500);
}

export async function onRequest(context) {
  const { request, env } = context;

  if (!env.DB) {
    return missingDatabaseResponse();
  }

  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');
  const method = request.method.toUpperCase();

  try {
    if (path === 'me' && method === 'GET') return handleMe(request, env);
    if (path === 'register' && method === 'POST') return handleRegister(request, env);
    if (path === 'login' && method === 'POST') return handleLogin(request, env);
    if (path === 'logout' && method === 'POST') return handleLogout(request, env);
    if (path === 'progress' && method === 'POST') return handleProgress(request, env);
    if ((path === 'ranking' || path === 'leaderboard') && method === 'GET') return handleRanking(env);

    return json({ error: 'API-Endpunkt nicht gefunden.' }, 404);
  } catch (error) {
    return json({ error: 'Serverfehler: ' + (error && error.message ? error.message : 'Unbekannter Fehler') }, 500);
  }
}

