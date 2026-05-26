const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'geowfm2024';
const DB_FILE = path.join(process.cwd(), 'geowfm.db');

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(process.cwd(), 'public')));

// Healthcheck — Railway uchun
app.get('/health', (req, res) => res.json({ status: 'ok', time: nowUZ() }));
app.get('/', (req, res) => {
  const indexPath = path.join(process.cwd(), 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.send('<h1>GeoWFM</h1><p>index.html topilmadi: ' + indexPath + '</p>');
  }
});

let db;

function save() {
  try {
    fs.writeFileSync(DB_FILE, Buffer.from(db.export()));
  } catch (e) {
    console.error('Save error:', e.message);
  }
}

function run(sql, p = []) {
  try {
    db.run(sql, p);
    save();
  } catch (e) {
    console.error('Run error:', e.message, sql.slice(0, 60));
  }
}

function all(sql, p = []) {
  try {
    const s = db.prepare(sql);
    s.bind(p);
    const rows = [];
    while (s.step()) rows.push(s.getAsObject());
    s.free();
    return rows;
  } catch (e) {
    console.error('All error:', e.message);
    return [];
  }
}

function get(sql, p = []) {
  return all(sql, p)[0] || null;
}

function nowUZ() {
  const uz = new Date(Date.now() + 5 * 60 * 60 * 1000);
  return uz.toISOString().slice(0, 19).replace('T', ' ');
}
function todayUZ() { return nowUZ().slice(0, 10); }
function uzHour()  { return parseInt(nowUZ().slice(11, 13)); }
function uzMin()   { return parseInt(nowUZ().slice(14, 16)); }

async function start() {
  console.log('GeoWFM starting...');

  // ═══════════════════════════════════════════════════════════
  // BUG FIX #1: sql.js wasm faylini aniq ko'rsatish
  // Railway'da initSqlJs() parametrsiz chaqirilsa, wasm fayli
  // topilmaydi va server crash bo'ladi.
  // ═══════════════════════════════════════════════════════════
  try {
    const SQL = await initSqlJs({
      locateFile: file => path.join(__dirname, 'node_modules', 'sql.js', 'dist', file)
    });
    db = fs.existsSync(DB_FILE)
      ? new SQL.Database(fs.readFileSync(DB_FILE))
      : new SQL.Database();
    console.log('DB initialized. File:', DB_FILE);
  } catch (e) {
    console.error('DB init error:', e.message);
    process.exit(1);
  }

  // Jadvallar
  run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, email TEXT UNIQUE, password TEXT,
    role TEXT DEFAULT 'worker', position TEXT,
    group_name TEXT, phone TEXT, status TEXT DEFAULT 'active',
    created_at TEXT
  )`);
  run(`CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    check_in TEXT, check_out TEXT, check_in_lat REAL, check_in_lng REAL,
    location_name TEXT, date TEXT, work_hours REAL DEFAULT 0,
    status TEXT DEFAULT 'present'
  )`);
  run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT,
    description TEXT, assigned_to INTEGER, created_by INTEGER,
    priority TEXT DEFAULT 'medium', status TEXT DEFAULT 'pending',
    location TEXT, location_lat REAL, location_lng REAL,
    deadline TEXT, completed_at TEXT, created_at TEXT
  )`);
  run(`CREATE TABLE IF NOT EXISTS task_proofs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER, user_id INTEGER,
    image_url TEXT, comment TEXT, latitude REAL, longitude REAL,
    distance_to_task REAL, submitted_at TEXT
  )`);
  run(`CREATE TABLE IF NOT EXISTS daily_work (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    date TEXT, works TEXT, notes TEXT, image_url TEXT,
    summary TEXT, created_at TEXT
  )`);
  run(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    title TEXT, message TEXT, type TEXT DEFAULT 'info',
    is_read INTEGER DEFAULT 0, created_at TEXT
  )`);

  // Demo foydalanuvchilar
  const adminExists = get('SELECT id FROM users WHERE email=?', ['sh.xaytbayev@geo.uz']);
  if (!adminExists) {
    const h = p => bcrypt.hashSync(p, 10);
    run('DELETE FROM users');
    [
      ['Shoniyor Xaytbayev', 'sh.xaytbayev@geo.uz', h('1234'), 'admin',      'Bosh Admin',     'Rahbariyat'],
      ['Shukur Teshaboyev',  'sh.teshaboyev@geo.uz', h('1234'), 'supervisor', 'Rahbar',         'Rahbariyat'],
      ['Aydar Muratov',      'a.muratov@geo.uz',     h('1234'), 'worker',     'Elektromontyor', 'Xodimlar'],
    ].forEach(u => run(
      'INSERT OR IGNORE INTO users (name,email,password,role,position,group_name,created_at) VALUES (?,?,?,?,?,?,?)',
      [...u, nowUZ()]
    ));
    console.log('Demo users created');
  }

  // ═══ MIDDLEWARE ═══
  function auth(req, res, next) {
    const t = req.headers.authorization?.split(' ')[1];
    if (!t) return res.status(401).json({ error: 'Token kerak' });
    try {
      req.user = jwt.verify(t, SECRET);
      next();
    } catch {
      res.status(401).json({ error: "Noto'g'ri token" });
    }
  }

  function adminOnly(req, res, next) {
    if (req.user.role !== 'admin')
      return res.status(403).json({ error: 'Faqat Bosh Admin' });
    next();
  }

  function adminOrSup(req, res, next) {
    if (!['admin', 'supervisor'].includes(req.user.role))
      return res.status(403).json({ error: "Ruxsat yo'q" });
    next();
  }

  // ═══ AUTH ═══
  app.post('/api/auth/login', (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password)
        return res.status(400).json({ error: 'Email va parol kerak' });
      const u = get('SELECT * FROM users WHERE email=?', [email]);
      if (!u || !bcrypt.compareSync(password, u.password))
        return res.status(401).json({ error: "Email yoki parol noto'g'ri" });
      if (u.status === 'blocked')
        return res.status(403).json({ error: 'Akkaunt bloklangan' });
      const token = jwt.sign(
        { id: u.id, email: u.email, role: u.role, name: u.name, group: u.group_name },
        SECRET, { expiresIn: '24h' }
      );
      res.json({
        token,
        user: { id: u.id, name: u.name, email: u.email, role: u.role, position: u.position, group: u.group_name }
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ═══ USERS ═══
  app.get('/api/users', auth, adminOrSup, (req, res) => {
    if (req.user.role === 'admin')
      return res.json(all('SELECT id,name,email,role,position,group_name,phone,status FROM users ORDER BY role,name'));
    res.json(all(
      'SELECT id,name,email,role,position,group_name,phone,status FROM users WHERE group_name=? ORDER BY name',
      [req.user.group]
    ));
  });

  app.post('/api/users', auth, adminOnly, (req, res) => {
    const { name, email, password, role, position, group_name, phone } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Ism, email, parol kerak' });
    try {
      run(
        'INSERT INTO users (name,email,password,role,position,group_name,phone,created_at) VALUES (?,?,?,?,?,?,?,?)',
        [name, email, bcrypt.hashSync(password, 10), role || 'worker', position || '', group_name || '', phone || '', nowUZ()]
      );
      res.json({ message: 'Created' });
    } catch (e) {
      res.status(400).json({ error: 'Bu email allaqachon mavjud' });
    }
  });

  app.put('/api/users/:id', auth, adminOnly, (req, res) => {
    const { name, position, group_name, phone, role, status, password } = req.body;
    const t = get('SELECT * FROM users WHERE id=?', [req.params.id]);
    if (!t) return res.status(404).json({ error: 'Topilmadi' });
    const newPass = password ? bcrypt.hashSync(password, 10) : t.password;
    run(
      'UPDATE users SET name=?,position=?,group_name=?,phone=?,role=?,status=?,password=? WHERE id=?',
      [name || t.name, position || t.position, group_name || t.group_name, phone || t.phone,
       role || t.role, status || t.status, newPass, req.params.id]
    );
    res.json({ message: 'Updated' });
  });

  app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
    const t = get('SELECT role FROM users WHERE id=?', [req.params.id]);
    if (t && t.role === 'admin')
      return res.status(403).json({ error: "Bosh Adminni o'chirib bo'lmaydi" });
    run('DELETE FROM users WHERE id=?', [req.params.id]);
    res.json({ message: 'Deleted' });
  });

  // ═══ ATTENDANCE ═══
  app.post('/api/attendance/checkin', auth, (req, res) => {
    const { latitude, longitude, location_name } = req.body;
    const today = todayUZ();
    if (get('SELECT id FROM attendance WHERE user_id=? AND date=?', [req.user.id, today]))
      return res.status(400).json({ error: 'Bugun allaqachon kirdingiz' });
    const now = nowUZ();
    const h = uzHour(), m = uzMin();
    const status = (h > 9 || (h === 9 && m > 0)) ? 'late' : 'present';
    run(
      'INSERT INTO attendance (user_id,check_in,check_in_lat,check_in_lng,location_name,date,status) VALUES (?,?,?,?,?,?,?)',
      [req.user.id, now, latitude || 0, longitude || 0, location_name || "Noma'lum", today, status]
    );
    res.json({ check_in: now, status });
  });

  app.post('/api/attendance/checkout', auth, (req, res) => {
    const today = todayUZ();
    const rec = get(
      'SELECT * FROM attendance WHERE user_id=? AND date=? AND check_out IS NULL',
      [req.user.id, today]
    );
    if (!rec) return res.status(400).json({ error: 'Avval kirish qiling' });
    const now = nowUZ();
    const diffMs = new Date(now.replace(' ', 'T')) - new Date(rec.check_in.replace(' ', 'T'));
    const hours = Math.max(0, diffMs / 3600000).toFixed(2);
    run('UPDATE attendance SET check_out=?,work_hours=? WHERE id=?', [now, hours, rec.id]);
    res.json({ work_hours: hours, check_out: now });
  });

  app.get('/api/attendance', auth, (req, res) => {
    const { date } = req.query;
    let q = 'SELECT a.*,u.name,u.id as user_id,u.group_name FROM attendance a JOIN users u ON a.user_id=u.id WHERE 1=1';
    const p = [];
    if (req.user.role === 'worker') { q += ' AND a.user_id=?'; p.push(req.user.id); }
    else if (req.user.role === 'supervisor') { q += ' AND u.group_name=?'; p.push(req.user.group); }
    if (date) { q += ' AND a.date=?'; p.push(date); }
    res.json(all(q + ' ORDER BY a.check_in DESC LIMIT 200', p));
  });

  // ═══ TASKS ═══
  app.get('/api/tasks', auth, (req, res) => {
    const { status } = req.query;
    let q = 'SELECT t.*,u.name as assigned_name FROM tasks t LEFT JOIN users u ON t.assigned_to=u.id WHERE 1=1';
    const p = [];
    if (req.user.role === 'worker') { q += ' AND t.assigned_to=?'; p.push(req.user.id); }
    else if (req.user.role === 'supervisor') { q += ' AND u.group_name=?'; p.push(req.user.group); }
    if (status && status !== 'all') { q += ' AND t.status=?'; p.push(status); }
    res.json(all(q + ' ORDER BY t.created_at DESC', p));
  });

  app.post('/api/tasks', auth, adminOrSup, (req, res) => {
    const { title, description, assigned_to, priority, location, location_lat, location_lng, deadline } = req.body;
    if (!title) return res.status(400).json({ error: 'Vazifa nomi kerak' });
    const now = nowUZ();
    if (assigned_to === 'all') {
      const workers = all('SELECT id FROM users WHERE role=?', ['worker']);
      workers.forEach(w => {
        run(
          'INSERT INTO tasks (title,description,assigned_to,created_by,priority,location,location_lat,location_lng,deadline,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
          [title, description || '', w.id, req.user.id, priority || 'medium', location || '', location_lat || null, location_lng || null, deadline || null, now]
        );
      });
      return res.json({ message: 'Barcha xodimlarga yuborildi', count: workers.length });
    }
    run(
      'INSERT INTO tasks (title,description,assigned_to,created_by,priority,location,location_lat,location_lng,deadline,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
      [title, description || '', assigned_to || null, req.user.id, priority || 'medium', location || '', location_lat || null, location_lng || null, deadline || null, now]
    );
    res.json({ message: 'Created' });
  });

  app.put('/api/tasks/:id', auth, adminOrSup, (req, res) => {
    const { status } = req.body;
    const task = get('SELECT * FROM tasks WHERE id=?', [req.params.id]);
    if (!task) return res.status(404).json({ error: 'Topilmadi' });
    const done = status === 'done' ? nowUZ() : task.completed_at;
    run('UPDATE tasks SET status=?,completed_at=? WHERE id=?', [status || task.status, done, req.params.id]);
    res.json({ message: 'Updated' });
  });

  app.delete('/api/tasks/:id', auth, adminOrSup, (req, res) => {
    run('DELETE FROM tasks WHERE id=?', [req.params.id]);
    res.json({ message: 'Deleted' });
  });

  // ═══ TASK PROOFS ═══
  app.post('/api/tasks/:id/proof', auth, (req, res) => {
    const { image_url, comment, latitude, longitude, distance_to_task } = req.body;
    const task = get('SELECT * FROM tasks WHERE id=?', [req.params.id]);
    if (!task) return res.status(404).json({ error: 'Vazifa topilmadi' });
    const now = nowUZ();
    run(
      'INSERT INTO task_proofs (task_id,user_id,image_url,comment,latitude,longitude,distance_to_task,submitted_at) VALUES (?,?,?,?,?,?,?,?)',
      [req.params.id, req.user.id, image_url || '', comment || '', latitude || 0, longitude || 0, distance_to_task || 0, now]
    );
    run('UPDATE tasks SET status=?,completed_at=? WHERE id=?', ['done', now, req.params.id]);
    res.json({ message: 'Proof submitted' });
  });

  app.get('/api/tasks/:id/proof', auth, adminOrSup, (req, res) => {
    res.json(all(
      'SELECT p.*,u.name FROM task_proofs p JOIN users u ON p.user_id=u.id WHERE p.task_id=?',
      [req.params.id]
    ));
  });

  app.get('/api/proofs', auth, adminOrSup, (req, res) => {
    let q = `SELECT p.*,u.name as worker_name,t.title as task_title,t.location
      FROM task_proofs p JOIN users u ON p.user_id=u.id JOIN tasks t ON p.task_id=t.id`;
    const params = [];
    if (req.user.role === 'supervisor') { q += ' WHERE u.group_name=?'; params.push(req.user.group); }
    res.json(all(q + ' ORDER BY p.submitted_at DESC LIMIT 100', params));
  });

  // ═══ DAILY WORK ═══
  app.post('/api/daily-work', auth, adminOrSup, (req, res) => {
    const { date, works, notes, image_url, summary } = req.body;
    if (!date || !works?.length)
      return res.status(400).json({ error: 'Sana va ishlar kerak' });
    run(
      'INSERT INTO daily_work (user_id,date,works,notes,image_url,summary,created_at) VALUES (?,?,?,?,?,?,?)',
      [req.user.id, date, JSON.stringify(works), notes || '', image_url || '', summary || '', nowUZ()]
    );
    res.json({ message: 'Saved' });
  });

  app.get('/api/daily-work', auth, adminOrSup, (req, res) => {
    let q = `SELECT dw.*,u.name as worker_name FROM daily_work dw JOIN users u ON dw.user_id=u.id WHERE 1=1`;
    const p = [];
    if (req.user.role === 'supervisor') { q += ' AND u.group_name=?'; p.push(req.user.group); }
    res.json(all(q + ' ORDER BY dw.created_at DESC LIMIT 100', p));
  });

  // ═══ NOTIFICATIONS ═══
  app.get('/api/notifications', auth, (req, res) => {
    res.json(all(
      'SELECT * FROM notifications WHERE user_id=? OR user_id IS NULL ORDER BY created_at DESC LIMIT 50',
      [req.user.id]
    ));
  });

  // ═══ DASHBOARD ═══
  app.get('/api/dashboard', auth, (req, res) => {
    const today = todayUZ();
    const isSup = req.user.role === 'supervisor';
    const g = isSup ? [req.user.group] : [];

    const wQ = 'SELECT COUNT(*) as c FROM users WHERE role="worker"' + (isSup ? ' AND group_name=?' : '');
    const pQ = 'SELECT COUNT(*) as c FROM attendance WHERE date=? AND check_in IS NOT NULL' + (isSup ? ' AND user_id IN (SELECT id FROM users WHERE group_name=?)' : '');
    const aQ = 'SELECT COUNT(*) as c FROM tasks WHERE status IN ("pending","active")' + (isSup ? ' AND assigned_to IN (SELECT id FROM users WHERE group_name=?)' : '');
    const dQ = 'SELECT COUNT(*) as c FROM tasks WHERE status="done"' + (isSup ? ' AND assigned_to IN (SELECT id FROM users WHERE group_name=?)' : '');

    res.json({
      totalWorkers:  get(wQ, g)?.c || 0,
      presentToday:  get(pQ, isSup ? [today, ...g] : [today])?.c || 0,
      activeTasks:   get(aQ, g)?.c || 0,
      doneTasks:     get(dQ, g)?.c || 0,
    });
  });

  // Barcha noma'lum routelar uchun index.html
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api/'))
      return res.status(404).json({ error: 'Not found' });
    const indexPath = path.join(process.cwd(), 'public', 'index.html');
    if (fs.existsSync(indexPath)) res.sendFile(indexPath);
    else res.status(404).send('index.html topilmadi');
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ GeoWFM port ${PORT} da ishlayapti`);
    console.log("⏰ UTC+5 (O'zbekiston) vaqti:", nowUZ());
    console.log('🔑 sh.xaytbayev@geo.uz / 1234');
  });
}

start().catch(e => {
  console.error('FATAL ERROR:', e.message);
  process.exit(1);
});
