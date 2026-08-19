const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
 
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12시간
 
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
 
let col; // mongodb collection handle
const sessions = new Map(); // token -> { username, role, expires }
 
/* ---------- 비밀번호 해싱 ---------- */
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(plain, stored) {
  if (!stored || typeof stored !== 'string' || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  try {
    const check = crypto.scryptSync(plain, salt, 64);
    const original = Buffer.from(hash, 'hex');
    if (check.length !== original.length) return false;
    return crypto.timingSafeEqual(check, original);
  } catch (e) {
    return false;
  }
}
function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}
 
/* ---------- 세션 인증 미들웨어 ---------- */
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const sess = token && sessions.get(token);
  if (!sess || sess.expires < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: '로그인이 필요합니다' });
  }
  sess.expires = Date.now() + SESSION_TTL_MS; // 사용할 때마다 만료 연장
  req.user = { username: sess.username, role: sess.role };
  next();
}
 
/* ---------- DB 연결 ---------- */
async function initDb() {
  if (!MONGODB_URI) {
    console.error('MONGODB_URI 환경변수가 설정되지 않았습니다.');
    return;
  }
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db('msi');
  col = db.collection('appdata');
  console.log('MongoDB 연결 성공');
  await ensureBootstrapAccount();
}
 
// 최초 실행 시 관리자 계정이 없으면 하나 만들어 둠 (비밀번호는 해시로 저장)
async function ensureBootstrapAccount() {
  const doc = await col.findOne({ _id: 'main' });
  const d = (doc && doc.data) || {};
  if (!d.accounts) d.accounts = [];
  if (!d.accounts.find(a => a.role === 'root')) {
    d.accounts.push({
      username: '김민준',
      password: hashPassword('1234'),
      role: 'root',
      mustChangePassword: true
    });
    await col.updateOne({ _id: 'main' }, { $set: { data: d, updatedAt: new Date() } }, { upsert: true });
    console.log('기본 관리자 계정을 생성했습니다 (최초 로그인 시 비밀번호 변경 필요)');
  }
}
 
/* ---------- 로그인 (인증 불필요, 자격 확인용) ---------- */
app.post('/api/login', async (req, res) => {
  try {
    if (!col) return res.status(500).json({ error: 'DB 연결 안 됨' });
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: '아이디/비밀번호를 입력하세요' });
    const doc = await col.findOne({ _id: 'main' });
    const d = (doc && doc.data) || {};
    const accounts = d.accounts || [];
    const acct = accounts.find(a => a.username === username);
    if (!acct) {
      return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다' });
    }
 
    const isLegacyPlaintext = typeof acct.password === 'string' && !acct.password.includes(':');
    let passwordOk = false;
 
    if (isLegacyPlaintext) {
      // 보안 강화 이전에 평문으로 저장된 예전 계정 - 일치하면 이번 기회에 해시로 자동 전환
      passwordOk = acct.password === password;
      if (passwordOk) {
        acct.password = hashPassword(password);
        acct.mustChangePassword = true;
        await col.updateOne({ _id: 'main' }, { $set: { data: d, updatedAt: new Date() } }, { upsert: true });
      }
    } else {
      passwordOk = verifyPassword(password, acct.password);
    }
 
    if (!passwordOk) {
      return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다' });
    }
    const token = makeToken();
    sessions.set(token, { username: acct.username, role: acct.role, expires: Date.now() + SESSION_TTL_MS });
    res.json({ ok: true, token, role: acct.role, mustChangePassword: !!acct.mustChangePassword });
  } catch (e) {
    console.error('로그인 실패:', e.message);
    res.status(500).json({ error: e.message });
  }
});
 
/* ---------- 회원가입 신청 (인증 불필요) ---------- */
app.post('/api/signup', async (req, res) => {
  try {
    if (!col) return res.status(500).json({ error: 'DB 연결 안 됨' });
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: '아이디/비밀번호를 입력하세요' });
    const doc = await col.findOne({ _id: 'main' });
    const d = (doc && doc.data) || {};
    if (!d.accounts) d.accounts = [];
    if (!d.signupRequests) d.signupRequests = [];
    if (d.accounts.find(a => a.username === username) || d.signupRequests.find(r => r.username === username)) {
      return res.status(409).json({ error: '이미 사용중이거나 대기중인 아이디입니다' });
    }
    d.signupRequests.push({ username, password: hashPassword(password), requestedAt: Date.now() });
    if (!d.notifications) d.notifications = [];
    d.accounts.filter(a => a.role === 'root' || a.role === 'mid').forEach(a => {
      d.notifications.unshift({
        id: crypto.randomBytes(8).toString('hex'),
        toUsername: a.username,
        message: username + '님이 가입 신청을 하였습니다',
        ts: new Date().toISOString(),
        read: false
      });
    });
    if (d.notifications.length > 500) d.notifications = d.notifications.slice(0, 500);
    if (!d.activityLog) d.activityLog = [];
    d.activityLog.unshift({ ts: new Date().toISOString(), username, action: '가입 신청', detail: '(담당자)' });
    if (d.activityLog.length > 500) d.activityLog = d.activityLog.slice(0, 500);
    await col.updateOne({ _id: 'main' }, { $set: { data: d, updatedAt: new Date() } }, { upsert: true });
    res.json({ ok: true });
  } catch (e) {
    console.error('가입 신청 실패:', e.message);
    res.status(500).json({ error: e.message });
  }
});
 
/* ---------- 로그아웃 ---------- */
app.post('/api/logout', requireAuth, (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (token) sessions.delete(token);
  res.json({ ok: true });
});
 
/* ---------- 비밀번호 해시 발급 (로그인 상태에서만) ---------- */
// 계정 생성/초기화/비밀번호 변경 시, 평문 비밀번호를 서버에서 해시로 바꿔서 돌려줌.
// 클라이언트는 이 해시값만 저장하므로 평문 비밀번호가 데이터에 남지 않음.
app.post('/api/hash-password', requireAuth, (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'password required' });
  res.json({ hash: hashPassword(password) });
});
 
/* ---------- 데이터 조회/저장 (로그인 필요) ---------- */
app.get('/api/data', requireAuth, async (req, res) => {
  try {
    if (!col) return res.json({});
    const doc = await col.findOne({ _id: 'main' });
    res.json((doc && doc.data) || {});
  } catch (e) {
    console.error('조회 실패:', e.message);
    res.status(500).json({ error: e.message });
  }
});
 
app.post('/api/data', requireAuth, async (req, res) => {
  try {
    if (!col) return res.status(500).json({ ok: false, error: 'DB 연결 안 됨' });
    await col.updateOne(
      { _id: 'main' },
      { $set: { data: req.body || {}, updatedAt: new Date() } },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('저장 실패:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});
 
app.get('/healthz', (req, res) => res.send('ok'));
 
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`서버가 켜졌습니다: http://localhost:${PORT}`);
  });
}).catch((e) => {
  console.error('DB 연결 실패:', e.message);
  app.listen(PORT, () => {
    console.log(`서버가 켜졌습니다 (DB 없이): http://localhost:${PORT}`);
  });
});
 
