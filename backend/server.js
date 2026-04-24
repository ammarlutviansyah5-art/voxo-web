const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const { z } = require('zod');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 4000;
const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'dev-access-secret-change-me';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-change-me';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'voxo.db');
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, '..', 'uploads');
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const OTP_TTL_MIN = Number(process.env.OTP_TTL_MIN || 15);
const RESET_TTL_MIN = Number(process.env.RESET_TTL_MIN || 30);
const ACCESS_TTL_MIN = Number(process.env.ACCESS_TTL_MIN || 15);
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS || 30);

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(DB_FILE);
db.pragma('foreign_keys = ON');

const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
db.exec(schema);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST', 'PATCH', 'DELETE'] },
});

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_DIR));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOAD_DIR),
    filename: (_, file, cb) => {
      const ext = path.extname(file.originalname || '');
      cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`);
    },
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
});

const q = {
  get: (sql, params = []) => db.prepare(sql).get(...params),
  all: (sql, params = []) => db.prepare(sql).all(...params),
  run: (sql, params = []) => db.prepare(sql).run(...params),
};

function nowIso() { return new Date().toISOString(); }
function addMinutes(date, mins) { return new Date(date.getTime() + mins * 60 * 1000); }
function addDays(date, days) { return new Date(date.getTime() + days * 24 * 60 * 60 * 1000); }
function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function randomOtp() { return String(Math.floor(100000 + Math.random() * 900000)); }
function normalizeEmail(v) { return String(v || '').trim().toLowerCase(); }
function normalizeName(v) { return String(v || '').trim().replace(/\s+/g, ' '); }
function generateVoxoId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let token = '';
  for (let i = 0; i < 10; i++) token += chars[Math.floor(Math.random() * chars.length)];
  return `VX-${token}`;
}
function safeId() { return uuidv4(); }
function signAccessToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, voxoId: user.voxo_id }, JWT_ACCESS_SECRET, { expiresIn: `${ACCESS_TTL_MIN}m` });
}
function signRefreshToken(user, sessionId) {
  return jwt.sign({ sub: user.id, sid: sessionId }, JWT_REFRESH_SECRET, { expiresIn: `${REFRESH_TTL_DAYS}d` });
}
function sendOtpEmail({ email, otp, purpose }) {
  console.log(`[VOXO OTP] ${purpose} -> ${email}: ${otp}`);
}
function sendResetEmail({ email, token }) {
  console.log(`[VOXO RESET] ${email}: ${token}`);
}
function createUserSettings(userId) {
  q.run('INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)', [userId]);
}
function getUserById(id) {
  return q.get('SELECT id, voxo_id, name, email, email_verified_at, avatar_url, status_message, created_at, updated_at, last_login_at FROM users WHERE id = ?', [id]);
}
function getUserByEmail(email) {
  return q.get('SELECT * FROM users WHERE email = ?', [normalizeEmail(email)]);
}
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    const user = getUserById(payload.sub);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}
function otpMatches({ email, purpose, otp }) {
  const row = q.get(
    `SELECT * FROM auth_otp
     WHERE email = ? AND purpose = ? AND consumed_at IS NULL
     ORDER BY created_at DESC LIMIT 1`,
    [normalizeEmail(email), purpose]
  );
  if (!row) return { ok: false, reason: 'OTP tidak ditemukan' };
  if (new Date(row.expires_at).getTime() < Date.now()) return { ok: false, reason: 'OTP sudah kedaluwarsa' };
  if (row.attempts >= 5) return { ok: false, reason: 'Terlalu banyak percobaan' };
  const matches = bcrypt.compareSync(String(otp), row.otp_hash);
  q.run('UPDATE auth_otp SET attempts = attempts + 1 WHERE id = ?', [row.id]);
  if (!matches) return { ok: false, reason: 'OTP salah' };
  q.run('UPDATE auth_otp SET consumed_at = ? WHERE id = ?', [nowIso(), row.id]);
  return { ok: true, row };
}
function createSession(user, req) {
  const sessionId = safeId();
  const refreshToken = signRefreshToken(user, sessionId);
  const refreshHash = sha256(refreshToken);
  const expiresAt = addDays(new Date(), REFRESH_TTL_DAYS).toISOString();
  q.run(
    `INSERT INTO sessions (id, user_id, refresh_token_hash, user_agent, ip_address, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [sessionId, user.id, refreshHash, req.headers['user-agent'] || '', req.ip || '', expiresAt]
  );
  const accessToken = signAccessToken(user);
  return { accessToken, refreshToken, sessionId };
}
function serializeSettings(row) {
  return {
    user_id: row.user_id,
    notifications_enabled: !!row.notifications_enabled,
    read_receipts_enabled: !!row.read_receipts_enabled,
    privacy_last_seen: row.privacy_last_seen,
    privacy_status: row.privacy_status,
    theme: row.theme,
    language: row.language,
    updated_at: row.updated_at,
  };
}

const signupSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(8),
});
const otpSchema = z.object({ email: z.string().email(), otp: z.string().min(4).max(8) });
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });
const forgotSchema = z.object({ email: z.string().email() });
const resetSchema = z.object({ email: z.string().email(), token: z.string().min(6), newPassword: z.string().min(8) });
const updateProfileSchema = z.object({
  name: z.string().min(2).optional(),
  avatar_url: z.string().url().nullable().optional(),
  status_message: z.string().max(140).optional(),
});
const settingsSchema = z.object({
  notifications_enabled: z.boolean().optional(),
  read_receipts_enabled: z.boolean().optional(),
  privacy_last_seen: z.enum(['everyone', 'my_contacts', 'nobody']).optional(),
  privacy_status: z.enum(['my_contacts', 'selected', 'only_share_with', 'hide_from']).optional(),
  theme: z.enum(['dark', 'light']).optional(),
  language: z.string().min(2).max(10).optional(),
});

app.get('/health', (_, res) => res.json({ ok: true, service: 'voxo-backend' }));

app.post('/api/auth/signup', (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { name, email, password } = parsed.data;
  const normalizedEmail = normalizeEmail(email);
  if (getUserByEmail(normalizedEmail)) return res.status(409).json({ error: 'Email sudah terdaftar' });

  let voxoId = generateVoxoId();
  while (q.get('SELECT 1 FROM users WHERE voxo_id = ?', [voxoId])) voxoId = generateVoxoId();

  const id = safeId();
  const passwordHash = bcrypt.hashSync(password, 12);
  q.run(
    `INSERT INTO users (id, voxo_id, name, email, password_hash) VALUES (?, ?, ?, ?, ?)`,
    [id, voxoId, normalizeName(name), normalizedEmail, passwordHash]
  );
  createUserSettings(id);
  const otp = randomOtp();
  q.run(
    `INSERT INTO auth_otp (id, user_id, email, purpose, otp_hash, expires_at)
     VALUES (?, ?, ?, 'verify_email', ?, ?)`,
    [safeId(), id, normalizedEmail, bcrypt.hashSync(otp, 10), addMinutes(new Date(), OTP_TTL_MIN).toISOString()]
  );
  sendOtpEmail({ email: normalizedEmail, otp, purpose: 'verify_email' });
  res.status(201).json({
    message: 'Akun dibuat. Verifikasi OTP telah dikirim.',
    user: { id, voxo_id: voxoId, email: normalizedEmail, name: normalizeName(name), email_verified_at: null },
  });
});

app.post('/api/auth/verify-email-otp', (req, res) => {
  const parsed = otpSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { email, otp } = parsed.data;
  const result = otpMatches({ email, purpose: 'verify_email', otp });
  if (!result.ok) return res.status(400).json({ error: result.reason });
  const user = getUserByEmail(email);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  q.run('UPDATE users SET email_verified_at = ?, updated_at = ? WHERE id = ?', [nowIso(), nowIso(), user.id]);
  const session = createSession(user, req);
  q.run('UPDATE users SET last_login_at = ? WHERE id = ?', [nowIso(), user.id]);
  res.json({ message: 'Email terverifikasi', user: getUserById(user.id), ...session });
});

app.post('/api/auth/login', (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { email, password } = parsed.data;
  const user = getUserByEmail(email);
  if (!user) return res.status(401).json({ error: 'Email atau password salah' });
  if (!user.email_verified_at) return res.status(403).json({ error: 'Email belum diverifikasi' });
  if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Email atau password salah' });
  const session = createSession(user, req);
  q.run('UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?', [nowIso(), nowIso(), user.id]);
  res.json({ message: 'Login berhasil', user: getUserById(user.id), ...session, settings: q.get('SELECT * FROM user_settings WHERE user_id = ?', [user.id]) });
});

app.post('/api/auth/forgot-password', (req, res) => {
  const parsed = forgotSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { email } = parsed.data;
  const user = getUserByEmail(email);
  if (!user) return res.json({ message: 'Jika email terdaftar, instruksi reset sudah dikirim.' });
  const token = randomOtp() + randomOtp();
  q.run(
    `INSERT INTO password_resets (id, user_id, token_hash, expires_at)
     VALUES (?, ?, ?, ?)`,
    [safeId(), user.id, sha256(token), addMinutes(new Date(), RESET_TTL_MIN).toISOString()]
  );
  sendResetEmail({ email: user.email, token });
  res.json({ message: 'Jika email terdaftar, instruksi reset sudah dikirim.' });
});

app.post('/api/auth/reset-password', (req, res) => {
  const parsed = resetSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { email, token, newPassword } = parsed.data;
  const user = getUserByEmail(email);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  const row = q.get(
    `SELECT * FROM password_resets WHERE user_id = ? AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1`,
    [user.id]
  );
  if (!row || row.expires_at < nowIso() || row.token_hash !== sha256(token)) {
    return res.status(400).json({ error: 'Token reset tidak valid' });
  }
  q.run('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', [bcrypt.hashSync(newPassword, 12), nowIso(), user.id]);
  q.run('UPDATE password_resets SET consumed_at = ? WHERE id = ?', [nowIso(), row.id]);
  res.json({ message: 'Password berhasil direset' });
});

app.post('/api/auth/refresh', (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: 'refreshToken diperlukan' });
  try {
    const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const session = q.get('SELECT * FROM sessions WHERE id = ? AND revoked_at IS NULL', [payload.sid]);
    if (!session) return res.status(401).json({ error: 'Session invalid' });
    if (session.refresh_token_hash !== sha256(refreshToken)) return res.status(401).json({ error: 'Session invalid' });
    const user = getUserById(payload.sub);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    return res.json({ accessToken: signAccessToken(user) });
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const { sessionId } = req.body || {};
  if (sessionId) q.run('UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ?', [nowIso(), sessionId, req.user.id]);
  res.json({ message: 'Logout berhasil' });
});

app.get('/api/me', requireAuth, (req, res) => {
  const settings = q.get('SELECT * FROM user_settings WHERE user_id = ?', [req.user.id]);
  res.json({ user: req.user, settings: serializeSettings(settings) });
});

app.patch('/api/me', requireAuth, (req, res) => {
  const parsed = updateProfileSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const changes = [];
  const params = [];
  if (parsed.data.name !== undefined) { changes.push('name = ?'); params.push(normalizeName(parsed.data.name)); }
  if (parsed.data.avatar_url !== undefined) { changes.push('avatar_url = ?'); params.push(parsed.data.avatar_url); }
  if (parsed.data.status_message !== undefined) { changes.push('status_message = ?'); params.push(parsed.data.status_message); }
  if (changes.length) {
    changes.push('updated_at = ?');
    params.push(nowIso(), req.user.id);
    q.run(`UPDATE users SET ${changes.join(', ')} WHERE id = ?`, params);
  }
  res.json({ message: 'Profil diperbarui', user: getUserById(req.user.id) });
});

app.get('/api/users/search', requireAuth, (req, res) => {
  const term = String(req.query.q || '').trim();
  if (!term) return res.json({ results: [] });
  const like = `%${term.toLowerCase()}%`;
  const results = q.all(
    `SELECT id, voxo_id, name, email, avatar_url, status_message
     FROM users
     WHERE id != ? AND (lower(name) LIKE ? OR lower(email) LIKE ? OR lower(voxo_id) LIKE ?)
     ORDER BY name ASC LIMIT 20`,
    [req.user.id, like, like, like]
  );
  res.json({ results });
});

app.get('/api/contacts', requireAuth, (req, res) => {
  const rows = q.all(
    `SELECT c.*, u.voxo_id AS resolved_voxo_id, u.avatar_url AS resolved_avatar, u.status_message AS resolved_status
     FROM contacts c
     LEFT JOIN users u ON u.id = c.contact_user_id
     WHERE c.owner_user_id = ?
     ORDER BY c.created_at DESC`,
    [req.user.id]
  );
  const pinned = q.all('SELECT conversation_id FROM pinned_chats WHERE user_id = ?', [req.user.id]).map(r => r.conversation_id);
  const archived = q.all('SELECT conversation_id FROM archived_chats WHERE user_id = ?', [req.user.id]).map(r => r.conversation_id);
  const blocked = q.all('SELECT blocked_user_id FROM blocked_users WHERE blocker_user_id = ?', [req.user.id]).map(r => r.blocked_user_id);
  res.json({
    contacts: rows.map(r => ({
      id: r.id,
      display_name: r.display_name,
      contact_email: r.contact_email,
      contact_voxo_id: r.contact_voxo_id || r.resolved_voxo_id,
      contact_phone: r.contact_phone,
      notes: r.notes,
      contact_user_id: r.contact_user_id,
      avatar_url: r.resolved_avatar,
      status_message: r.resolved_status,
    })),
    pinned,
    archived,
    blocked,
  });
});

app.post('/api/contacts', requireAuth, (req, res) => {
  const schema = z.object({
    name: z.string().min(2),
    email: z.string().email().optional(),
    voxo_id: z.string().optional(),
    phone: z.string().optional(),
    notes: z.string().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const { name, email, voxo_id, phone, notes } = parsed.data;
  let contactUser = null;
  if (email) contactUser = getUserByEmail(email);
  if (!contactUser && voxo_id) contactUser = q.get('SELECT * FROM users WHERE voxo_id = ?', [voxo_id]);
  q.run(
    `INSERT INTO contacts (id, owner_user_id, contact_user_id, display_name, contact_email, contact_voxo_id, contact_phone, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [safeId(), req.user.id, contactUser?.id || null, name, email || contactUser?.email || null, voxo_id || contactUser?.voxo_id || null, phone || null, notes || '']
  );
  res.status(201).json({ message: 'Kontak tersimpan' });
});

app.post('/api/contacts/:id/action', requireAuth, (req, res) => {
  const schema = z.object({ action: z.enum(['pin', 'unpin', 'mute', 'unmute', 'archive', 'unarchive', 'block', 'unblock', 'report']) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const contact = q.get('SELECT * FROM contacts WHERE id = ? AND owner_user_id = ?', [req.params.id, req.user.id]);
  if (!contact) return res.status(404).json({ error: 'Kontak tidak ditemukan' });
  const otherUserId = contact.contact_user_id;
  const conv = contact.contact_user_id ? ensureDirectConversation(req.user.id, contact.contact_user_id) : null;
  switch (parsed.data.action) {
    case 'pin':
      if (conv) q.run('INSERT OR IGNORE INTO pinned_chats (id, user_id, conversation_id) VALUES (?, ?, ?)', [safeId(), req.user.id, conv.id]);
      break;
    case 'unpin':
      if (conv) q.run('DELETE FROM pinned_chats WHERE user_id = ? AND conversation_id = ?', [req.user.id, conv.id]);
      break;
    case 'archive':
      if (conv) q.run('INSERT OR IGNORE INTO archived_chats (id, user_id, conversation_id) VALUES (?, ?, ?)', [safeId(), req.user.id, conv.id]);
      break;
    case 'unarchive':
      if (conv) q.run('DELETE FROM archived_chats WHERE user_id = ? AND conversation_id = ?', [req.user.id, conv.id]);
      break;
    case 'mute':
      if (conv) q.run('UPDATE conversation_participants SET muted = 1 WHERE user_id = ? AND conversation_id = ?', [req.user.id, conv.id]);
      break;
    case 'unmute':
      if (conv) q.run('UPDATE conversation_participants SET muted = 0 WHERE user_id = ? AND conversation_id = ?', [req.user.id, conv.id]);
      break;
    case 'block':
      if (otherUserId) q.run('INSERT OR IGNORE INTO blocked_users (id, blocker_user_id, blocked_user_id) VALUES (?, ?, ?)', [safeId(), req.user.id, otherUserId]);
      break;
    case 'unblock':
      if (otherUserId) q.run('DELETE FROM blocked_users WHERE blocker_user_id = ? AND blocked_user_id = ?', [req.user.id, otherUserId]);
      break;
    case 'report':
      break;
  }
  res.json({ message: `Action ${parsed.data.action} berhasil` });
});

function ensureDirectConversation(userA, userB) {
  let existing = q.get(
    `SELECT c.* FROM conversations c
     JOIN conversation_participants p1 ON p1.conversation_id = c.id AND p1.user_id = ?
     JOIN conversation_participants p2 ON p2.conversation_id = c.id AND p2.user_id = ?
     WHERE c.is_group = 0 LIMIT 1`,
    [userA, userB]
  );
  if (existing) return existing;
  const id = safeId();
  q.run('INSERT INTO conversations (id, is_group, title, created_at, updated_at) VALUES (?, 0, NULL, ?, ?)', [id, nowIso(), nowIso()]);
  q.run('INSERT INTO conversation_participants (id, conversation_id, user_id) VALUES (?, ?, ?)', [safeId(), id, userA]);
  q.run('INSERT INTO conversation_participants (id, conversation_id, user_id) VALUES (?, ?, ?)', [safeId(), id, userB]);
  existing = q.get('SELECT * FROM conversations WHERE id = ?', [id]);
  return existing;
}

app.get('/api/conversations', requireAuth, (req, res) => {
  const rows = q.all(
    `SELECT c.*,
      (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS message_count
     FROM conversations c
     JOIN conversation_participants p ON p.conversation_id = c.id AND p.user_id = ?
     ORDER BY COALESCE(c.last_message_at, c.created_at) DESC`,
    [req.user.id]
  );
  res.json({ conversations: rows });
});

app.post('/api/conversations/direct', requireAuth, (req, res) => {
  const schema = z.object({ email: z.string().email().optional(), voxo_id: z.string().optional(), user_id: z.string().optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  let target = null;
  if (parsed.data.user_id) target = getUserById(parsed.data.user_id);
  if (!target && parsed.data.email) target = getUserByEmail(parsed.data.email);
  if (!target && parsed.data.voxo_id) target = q.get('SELECT * FROM users WHERE voxo_id = ?', [parsed.data.voxo_id]);
  if (!target) return res.status(404).json({ error: 'User tujuan tidak ditemukan' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'Tidak bisa chat dengan diri sendiri' });
  const convo = ensureDirectConversation(req.user.id, target.id);
  res.json({ conversation: convo, target: { id: target.id, name: target.name, voxo_id: target.voxo_id } });
});

app.get('/api/conversations/:id/messages', requireAuth, (req, res) => {
  const participant = q.get('SELECT 1 FROM conversation_participants WHERE conversation_id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!participant) return res.status(403).json({ error: 'Forbidden' });
  const rows = q.all(
    `SELECT m.*, mf.public_url AS media_url, mf.mime_type AS media_mime, mf.file_name AS media_name
     FROM messages m
     LEFT JOIN media_files mf ON mf.id = m.media_id
     WHERE m.conversation_id = ?
     ORDER BY m.created_at ASC`,
    [req.params.id]
  );
  res.json({ messages: rows });
});

app.post('/api/messages', requireAuth, (req, res) => {
  const schema = z.object({
    conversation_id: z.string(),
    body: z.string().optional().default(''),
    type: z.enum(['text', 'image', 'video', 'document', 'voice', 'system']).optional().default('text'),
    media_id: z.string().optional().nullable(),
    reply_to_message_id: z.string().optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const convoMember = q.get('SELECT 1 FROM conversation_participants WHERE conversation_id = ? AND user_id = ?', [parsed.data.conversation_id, req.user.id]);
  if (!convoMember) return res.status(403).json({ error: 'Forbidden' });
  const id = safeId();
  q.run(
    `INSERT INTO messages (id, conversation_id, sender_id, type, body, media_id, reply_to_message_id, delivered_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, parsed.data.conversation_id, req.user.id, parsed.data.type, parsed.data.body || '', parsed.data.media_id || null, parsed.data.reply_to_message_id || null, nowIso()]
  );
  q.run('UPDATE conversations SET last_message_at = ?, updated_at = ? WHERE id = ?', [nowIso(), nowIso(), parsed.data.conversation_id]);
  const msg = q.get('SELECT * FROM messages WHERE id = ?', [id]);
  io.to(parsed.data.conversation_id).emit('message:new', msg);
  res.status(201).json({ message: msg });
});

app.patch('/api/messages/:id', requireAuth, (req, res) => {
  const schema = z.object({ body: z.string().min(1) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const msg = q.get('SELECT * FROM messages WHERE id = ? AND sender_id = ?', [req.params.id, req.user.id]);
  if (!msg) return res.status(404).json({ error: 'Pesan tidak ditemukan' });
  q.run('UPDATE messages SET body = ?, edited_at = ? WHERE id = ?', [parsed.data.body, nowIso(), req.params.id]);
  const updated = q.get('SELECT * FROM messages WHERE id = ?', [req.params.id]);
  io.to(updated.conversation_id).emit('message:edited', updated);
  res.json({ message: updated });
});

app.delete('/api/messages/:id', requireAuth, (req, res) => {
  const msg = q.get('SELECT * FROM messages WHERE id = ? AND sender_id = ?', [req.params.id, req.user.id]);
  if (!msg) return res.status(404).json({ error: 'Pesan tidak ditemukan' });
  q.run('UPDATE messages SET deleted_at = ? WHERE id = ?', [nowIso(), req.params.id]);
  io.to(msg.conversation_id).emit('message:deleted', { id: req.params.id, conversation_id: msg.conversation_id });
  res.json({ message: 'Pesan dihapus' });
});

app.post('/api/messages/:id/read', requireAuth, (req, res) => {
  const msg = q.get('SELECT * FROM messages WHERE id = ?', [req.params.id]);
  if (!msg) return res.status(404).json({ error: 'Pesan tidak ditemukan' });
  q.run('UPDATE messages SET read_at = COALESCE(read_at, ?) WHERE id = ?', [nowIso(), req.params.id]);
  io.to(msg.conversation_id).emit('message:read', { id: msg.id, conversation_id: msg.conversation_id, read_at: nowIso() });
  res.json({ message: 'Read status tersimpan' });
});

app.post('/api/attachments', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File wajib diunggah' });
  const kind = String(req.body.kind || 'document');
  const publicUrl = `${PUBLIC_BASE_URL}/uploads/${path.basename(req.file.path)}`;
  const id = safeId();
  q.run(
    `INSERT INTO media_files (id, owner_user_id, kind, file_name, mime_type, size_bytes, storage_path, public_url)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, req.user.id, kind, req.file.originalname, req.file.mimetype, req.file.size, req.file.path, publicUrl]
  );
  res.status(201).json({ media: q.get('SELECT * FROM media_files WHERE id = ?', [id]) });
});

app.get('/api/statuses', requireAuth, (req, res) => {
  const rows = q.all(
    `SELECT s.*, mf.public_url AS media_url, mf.mime_type AS media_mime, mf.file_name AS media_name
     FROM statuses s
     JOIN media_files mf ON mf.id = s.media_id
     WHERE s.deleted_at IS NULL AND datetime(s.expires_at) > datetime('now')
     ORDER BY s.created_at DESC`);
  res.json({ statuses: rows });
});

app.post('/api/statuses', requireAuth, (req, res) => {
  const schema = z.object({ media_id: z.string(), caption: z.string().optional().default(''), visibility: z.enum(['my_contacts', 'selected', 'only_share_with', 'hide_from']).optional().default('my_contacts'), expires_hours: z.number().int().min(1).max(24).optional().default(24) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const media = q.get('SELECT * FROM media_files WHERE id = ? AND owner_user_id = ?', [parsed.data.media_id, req.user.id]);
  if (!media) return res.status(404).json({ error: 'Media tidak ditemukan' });
  const id = safeId();
  q.run(
    `INSERT INTO statuses (id, user_id, media_id, caption, visibility, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [id, req.user.id, media.id, parsed.data.caption, parsed.data.visibility, addHours(new Date(), parsed.data.expires_hours).toISOString()]
  );
  res.status(201).json({ status: q.get('SELECT * FROM statuses WHERE id = ?', [id]) });
});

function addHours(date, hours) { return new Date(date.getTime() + hours * 60 * 60 * 1000); }

app.patch('/api/settings', requireAuth, (req, res) => {
  const parsed = settingsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const current = q.get('SELECT * FROM user_settings WHERE user_id = ?', [req.user.id]);
  const next = {
    notifications_enabled: parsed.data.notifications_enabled ?? !!current.notifications_enabled,
    read_receipts_enabled: parsed.data.read_receipts_enabled ?? !!current.read_receipts_enabled,
    privacy_last_seen: parsed.data.privacy_last_seen ?? current.privacy_last_seen,
    privacy_status: parsed.data.privacy_status ?? current.privacy_status,
    theme: parsed.data.theme ?? current.theme,
    language: parsed.data.language ?? current.language,
  };
  q.run(
    `UPDATE user_settings SET notifications_enabled = ?, read_receipts_enabled = ?, privacy_last_seen = ?, privacy_status = ?, theme = ?, language = ?, updated_at = ?
     WHERE user_id = ?`,
    [next.notifications_enabled ? 1 : 0, next.read_receipts_enabled ? 1 : 0, next.privacy_last_seen, next.privacy_status, next.theme, next.language, nowIso(), req.user.id]
  );
  res.json({ message: 'Setting tersimpan', settings: q.get('SELECT * FROM user_settings WHERE user_id = ?', [req.user.id]) });
});

app.get('/api/settings', requireAuth, (req, res) => {
  const settings = q.get('SELECT * FROM user_settings WHERE user_id = ?', [req.user.id]);
  res.json({ settings: serializeSettings(settings) });
});

app.post('/api/call-logs', requireAuth, (req, res) => {
  const schema = z.object({
    callee_id: z.string(),
    conversation_id: z.string().optional().nullable(),
    call_type: z.enum(['audio', 'video']),
    status: z.enum(['calling', 'ringing', 'accepted', 'ended', 'missed', 'declined']),
    signal_id: z.string().optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const id = safeId();
  q.run(
    `INSERT INTO call_logs (id, conversation_id, caller_id, callee_id, call_type, status, signal_id)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [id, parsed.data.conversation_id || null, req.user.id, parsed.data.callee_id, parsed.data.call_type, parsed.data.status, parsed.data.signal_id || null]
  );
  io.emit('call:log', q.get('SELECT * FROM call_logs WHERE id = ?', [id]));
  res.status(201).json({ call: q.get('SELECT * FROM call_logs WHERE id = ?', [id]) });
});

app.patch('/api/call-logs/:id', requireAuth, (req, res) => {
  const schema = z.object({ status: z.enum(['calling', 'ringing', 'accepted', 'ended', 'missed', 'declined']), duration_sec: z.number().int().min(0).optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const call = q.get('SELECT * FROM call_logs WHERE id = ? AND caller_id = ?', [req.params.id, req.user.id]);
  if (!call) return res.status(404).json({ error: 'Call log tidak ditemukan' });
  q.run('UPDATE call_logs SET status = ?, ended_at = CASE WHEN ? IN ("ended","missed","declined") THEN COALESCE(ended_at, ?) ELSE ended_at END, duration_sec = COALESCE(?, duration_sec) WHERE id = ?', [parsed.data.status, parsed.data.status, nowIso(), parsed.data.duration_sec ?? null, req.params.id]);
  res.json({ call: q.get('SELECT * FROM call_logs WHERE id = ?', [req.params.id]) });
});

app.get('/api/call-logs', requireAuth, (req, res) => {
  const rows = q.all(
    `SELECT * FROM call_logs WHERE caller_id = ? OR callee_id = ? ORDER BY created_at DESC LIMIT 100`,
    [req.user.id, req.user.id]
  );
  res.json({ call_logs: rows });
});

app.get('/api/chat/bootstrap', requireAuth, (req, res) => {
  const contacts = q.all('SELECT * FROM contacts WHERE owner_user_id = ? ORDER BY created_at DESC', [req.user.id]);
  const convs = q.all(
    `SELECT c.* FROM conversations c
     JOIN conversation_participants p ON p.conversation_id = c.id AND p.user_id = ?
     ORDER BY COALESCE(c.last_message_at, c.created_at) DESC`,
    [req.user.id]
  );
  const settings = q.get('SELECT * FROM user_settings WHERE user_id = ?', [req.user.id]);
  res.json({
    me: getUserById(req.user.id),
    settings: serializeSettings(settings),
    contacts,
    conversations: convs,
  });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

io.on('connection', (socket) => {
  socket.on('conversation:join', ({ conversationId }) => {
    if (conversationId) socket.join(conversationId);
  });
  socket.on('conversation:leave', ({ conversationId }) => {
    if (conversationId) socket.leave(conversationId);
  });
  socket.on('call:join', ({ signalId }) => {
    if (signalId) socket.join(`call:${signalId}`);
  });
  socket.on('call:offer', (payload) => {
    if (payload?.signalId) io.to(`call:${payload.signalId}`).emit('call:offer', payload);
  });
  socket.on('call:answer', (payload) => {
    if (payload?.signalId) io.to(`call:${payload.signalId}`).emit('call:answer', payload);
  });
  socket.on('call:ice', (payload) => {
    if (payload?.signalId) io.to(`call:${payload.signalId}`).emit('call:ice', payload);
  });
  socket.on('call:hangup', (payload) => {
    if (payload?.signalId) io.to(`call:${payload.signalId}`).emit('call:hangup', payload);
  });
});

server.listen(PORT, () => {
  console.log(`VOXO backend running on http://localhost:${PORT}`);
});
