const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
const geoip = require('geoip-lite');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24시간
const MAX_LOGIN_FAILS = 5;
const LOCKOUT_MS = 24 * 60 * 60 * 1000; // 24시간
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('[경고] SESSION_SECRET 환경변수가 설정되지 않았습니다. 서버가 재시작되면 모든 로그인이 풀립니다. Render 환경변수에 SESSION_SECRET을 추가해주세요.');
}

const app = express();
app.set('trust proxy', true); // Render 등 프록시 뒤에서도 실제 접속 IP를 인식하기 위함
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function getClientIp(req) {
  let ip = req.ip || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}
function isPrivateOrLocalIp(ip) {
  return !ip || ip === '127.0.0.1' || ip === '::1' ||
    ip.startsWith('10.') || ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip);
}
function describeLocation(ip) {
  if (isPrivateOrLocalIp(ip)) return '로컬/내부망';
  const geo = geoip.lookup(ip);
  if (!geo) return '위치 확인 불가';
  const parts = [geo.country];
  if (geo.city) parts.push(geo.city);
  return parts.filter(Boolean).join(' ');
}

/* ---------- 해외 접속 차단 (한국 IP만 허용) ---------- */
app.use((req, res, next) => {
  const ip = getClientIp(req);
  if (isPrivateOrLocalIp(ip)) return next();
  const geo = geoip.lookup(ip);
  if (geo && geo.country && geo.country !== 'KR') {
    return res.status(403).send('이 사이트는 한국 내에서만 접속할 수 있습니다.');
  }
  next();
});

let col; // mongodb collection handle (앱 데이터)
let secCol; // mongodb collection handle (로그인 보안 상태)

/* ---------- 서명된 로그인 토큰 (서버 재시작에도 유지됨) ---------- */
function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}
function makeToken(username, role) {
  const payload = { username, role, exp: Date.now() + SESSION_TTL_MS };
  const body = base64url(Buffer.from(JSON.stringify(payload)));
  const sig = base64url(crypto.createHmac('sha256', SESSION_SECRET).update(body).digest());
  return body + '.' + sig;
}
function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expectedSig = base64url(crypto.createHmac('sha256', SESSION_SECRET).update(body).digest());
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(base64urlDecode(body).toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

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
/* ---------- 세션 인증 미들웨어 ---------- */
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: '로그인이 필요합니다' });
  }
  req.user = { username: payload.username, role: payload.role };
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
  secCol = db.collection('loginSecurity');
  console.log('MongoDB 연결 성공');
  await ensureBootstrapAccount();
}

/* ---------- 로그인 실패 잠금 처리 ---------- */
async function getLockState(username) {
  const doc = secCol ? await secCol.findOne({ username }) : null;
  return doc || { username, failCount: 0, lockedUntil: 0 };
}
async function recordLoginFailure(username) {
  if (!secCol) return { failCount: 0, lockedUntil: 0 };
  const state = await getLockState(username);
  const failCount = (state.failCount || 0) + 1;
  const update = { username, failCount, lastAttempt: new Date() };
  update.lockedUntil = failCount >= MAX_LOGIN_FAILS ? (Date.now() + LOCKOUT_MS) : (state.lockedUntil || 0);
  await secCol.updateOne({ username }, { $set: update }, { upsert: true });
  return update;
}
async function resetLoginFailures(username) {
  if (!secCol) return;
  await secCol.updateOne({ username }, { $set: { failCount: 0, lockedUntil: 0 } }, { upsert: true });
}
function loginFailMessage(state) {
  if (state.failCount >= MAX_LOGIN_FAILS) {
    return '비밀번호를 ' + MAX_LOGIN_FAILS + '회 잘못 입력하여 24시간 동안 로그인이 제한됩니다.';
  }
  const remaining = MAX_LOGIN_FAILS - state.failCount;
  return '아이디 또는 비밀번호가 올바르지 않습니다. (' + remaining + '회 더 틀리면 24시간 동안 잠깁니다)';
}

/* ---------- 로그인 기록을 활동 로그에 남김 ---------- */
async function logLoginEvent(username, success, ip) {
  if (!col) return;
  const entry = {
    ts: new Date().toISOString(),
    username: username || '(알 수 없음)',
    action: success ? '로그인 성공' : '로그인 실패',
    detail: describeLocation(ip) + ' · ' + (ip || '알 수 없음')
  };
  try {
    await col.updateOne(
      { _id: 'main' },
      { $push: { 'data.activityLog': { $each: [entry], $position: 0, $slice: 500 } }, $set: { updatedAt: new Date() } },
      { upsert: true }
    );
  } catch (e) {
    console.error('로그인 기록 실패:', e.message);
  }
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
    const ip = getClientIp(req);

    const lockState = await getLockState(username);
    if (lockState.lockedUntil && lockState.lockedUntil > Date.now()) {
      const remainMin = Math.ceil((lockState.lockedUntil - Date.now()) / 60000);
      return res.status(423).json({ error: '로그인 5회 실패로 잠겼습니다. 약 ' + remainMin + '분 후 다시 시도해주세요.' });
    }

    const doc = await col.findOne({ _id: 'main' });
    const d = (doc && doc.data) || {};
    const accounts = d.accounts || [];
    const acct = accounts.find(a => a.username === username);
    if (!acct) {
      const st = await recordLoginFailure(username);
      await logLoginEvent(username, false, ip);
      return res.status(401).json({ error: loginFailMessage(st) });
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
      const st = await recordLoginFailure(username);
      await logLoginEvent(username, false, ip);
      return res.status(401).json({ error: loginFailMessage(st) });
    }

    await resetLoginFailures(username);
    await logLoginEvent(username, true, ip);

    const token = makeToken(acct.username, acct.role);
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
  // 토큰이 서명 방식(무상태)이라 서버에 따로 지울 목록이 없습니다.
  // 실제 로그아웃 처리는 클라이언트가 저장해둔 토큰을 지우는 것으로 이뤄집니다.
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

/* ---------- 로그인 잠금 해제 (관리자 전용) ---------- */
app.post('/api/unlock-login', requireAuth, async (req, res) => {
  if (req.user.role !== 'root' && req.user.role !== 'mid') {
    return res.status(403).json({ error: '권한이 없습니다' });
  }
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username required' });
  await resetLoginFailures(username);
  res.json({ ok: true });
});

/* ---------- 비밀번호 변경 (본인, 현재 비밀번호 확인 필요) ---------- */
app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    if (!col) return res.status(500).json({ error: 'DB 연결 안 됨' });
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) return res.status(400).json({ error: '비밀번호를 입력하세요' });

    const doc = await col.findOne({ _id: 'main' });
    const d = (doc && doc.data) || {};
    const acct = (d.accounts || []).find(a => a.username === req.user.username);
    if (!acct) return res.status(404).json({ error: '계정을 찾을 수 없습니다' });

    const isLegacyPlaintext = typeof acct.password === 'string' && !acct.password.includes(':');
    const ok = isLegacyPlaintext ? acct.password === currentPassword : verifyPassword(currentPassword, acct.password);
    if (!ok) return res.status(401).json({ error: '현재 비밀번호가 올바르지 않습니다' });

    acct.password = hashPassword(newPassword);
    acct.mustChangePassword = false;
    await col.updateOne({ _id: 'main' }, { $set: { data: d, updatedAt: new Date() } }, { upsert: true });
    res.json({ ok: true });
  } catch (e) {
    console.error('비밀번호 변경 실패:', e.message);
    res.status(500).json({ error: e.message });
  }
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
