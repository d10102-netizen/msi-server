const express = require('express');
const path = require('path');
const { MongoClient } = require('mongodb');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let col; // mongodb collection handle

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
}

app.get('/api/data', async (req, res) => {
  try {
    if (!col) return res.json({});
    const doc = await col.findOne({ _id: 'main' });
    res.json((doc && doc.data) || {});
  } catch (e) {
    console.error('조회 실패:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/data', async (req, res) => {
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
