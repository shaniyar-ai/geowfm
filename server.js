const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET = 'geowfm2024';
const DB_FILE = path.join(process.cwd(), 'geowfm.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(process.cwd(), 'public')));
app.get('/', (req, res) => res.sendFile(path.join(process.cwd(), 'public', 'index.html')));

let db;

function save() {
  fs.writeFileSync(DB_FILE, Buffer.from(db.export()));
}

function run(sql, p=[]) { db.run(sql, p); save(); }

function all(sql, p=[]) {
  const s = db.prepare(sql);
  s.bind(p);
  const rows = [];
  while (s.step()) rows.push(s.getAsObject());
  s.free();
  return rows;
}

function get(sql, p=[]) { return all(sql, p)[0] || null; }

async function start() {
  const SQL = await initSqlJs();
  db = fs.existsSync(DB_FILE)
    ? new SQL.Database(fs.readFileSync(DB_FILE))
    : new SQL.Database();

  run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, email TEXT UNIQUE, password TEXT,
    role TEXT DEFAULT 'worker', position TEXT,
    group_name TEXT, phone TEXT, status TEXT DEFAULT 'active'
  )`);
  run(`CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    check_in TEXT, check_out TEXT, check_in_lat REAL, check_in_lng REAL,
    location_name TEXT, date TEXT, work_hours REAL DEFAULT 0, status TEXT DEFAULT 'present'
  )`);
  run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT,
    description TEXT, assigned_to INTEGER, created_by INTEGER,
    priority TEXT DEFAULT 'medium', status TEXT DEFAULT 'pending',
    location TEXT, location_lat REAL, location_lng REAL,
    deadline TEXT, completed_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  run(`CREATE TABLE IF NOT EXISTS gps_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    latitude REAL, longitude REAL, battery INTEGER,
    logged_at TEXT DEFAULT (datetime('now'))
  )`);
  run(`CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    title TEXT, message TEXT, type TEXT DEFAULT 'info',
    is_read INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now'))
  )`);
  run(`CREATE TABLE IF NOT EXISTS task_proofs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER, user_id INTEGER,
    image_url TEXT, comment TEXT, latitude REAL, longitude REAL,
    distance_to_task REAL, submitted_at TEXT DEFAULT (datetime('now'))
  )`);
  run(`CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT, permission TEXT, allowed INTEGER DEFAULT 1,
    UNIQUE(role, permission)
  )`);

  if (!get('SELECT id FROM users WHERE email=?', ['sh.xaytbayev@geo.uz'])) {
    run('DELETE FROM users');
    const h = p => bcrypt.hashSync(p, 10);
    [
      ['Shoniyor Xaytbayev','sh.xaytbayev@geo.uz',h('1234'),'admin','Bosh admin','MTT guruhi'],
      ['Shukur Teshaboyev','sh.teshaboyev@geo.uz',h('1234'),'supervisor','Rahbar','MTT guruhi'],
      ['Aydar Muratov','a.muratov@geo.uz',h('1234'),'worker','Nazoratchi','MTT guruhi'],
      ['Ergali Murzafarov','e.murzafarov@geo.uz',h('1234'),'worker','Nazoratchi','MTT guruhi'],
      ['Aziz Umurbayev','a.umurbayev@geo.uz',h('1234'),'worker','Nazoratchi','MTT guruhi'],
    ].forEach(u => run('INSERT OR IGNORE INTO users (name,email,password,role,position,group_name) VALUES (?,?,?,?,?,?)', u));

    [
      ['supervisor','view_users',1],['supervisor','edit_users',1],
      ['supervisor','view_tasks',1],['supervisor','add_tasks',1],
      ['supervisor','view_attendance',1],['supervisor','view_map',1],
      ['worker','view_tasks',1],['worker','do_tasks',1],
      ['worker','view_attendance',1],['worker','checkin',1],
    ].forEach(r => run('INSERT OR IGNORE INTO permissions (role,permission,allowed) VALUES (?,?,?)', r));

    save();
    console.log('Demo data created');
  }

  // --- Middleware ---
  function auth(req, res, next) {
    const t = req.headers.authorization?.split(' ')[1];
    if (!t) return res.status(401).json({ error: 'Token required' });
    try { req.user = jwt.verify(t, SECRET); next(); }
    catch { res.status(401).json({ error: 'Invalid token' }); }
  }
  function adminOnly(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  }
  function adminOrSup(req, res, next) {
    if (!['admin','supervisor'].includes(req.user.role)) return res.status(403).json({ error: 'No access' });
    next();
  }

  // --- AUTH ---
  app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    const u = get('SELECT * FROM users WHERE email=?', [email]);
    if (!u || !bcrypt.compareSync(password, u.password))
      return res.status(401).json({ error: 'Wrong email or password' });
    if (u.status === 'blocked')
      return res.status(403).json({ error: 'Account blocked' });
    const token = jwt.sign({ id:u.id, email:u.email, role:u.role, name:u.name, group:u.group_name }, SECRET, { expiresIn:'24h' });
    const perms = all('SELECT permission,allowed FROM permissions WHERE role=?', [u.role]);
    res.json({ token, user:{ id:u.id, name:u.name, email:u.email, role:u.role, position:u.position, group:u.group_name }, permissions:Object.fromEntries(perms.map(p=>[p.permission,!!p.allowed])) });
  });

  app.get('/api/auth/me', auth, (req, res) => {
    res.json(get('SELECT id,name,email,role,position,group_name,phone,status FROM users WHERE id=?', [req.user.id]));
  });

  // --- USERS ---
  app.get('/api/users', auth, adminOrSup, (req, res) => {
    if (req.user.role === 'admin')
      return res.json(all('SELECT id,name,email,role,position,group_name,phone,status FROM users'));
    res.json(all('SELECT id,name,email,role,position,group_name,phone,status FROM users WHERE group_name=? AND role="worker"', [req.user.group]));
  });

  app.post('/api/users', auth, adminOnly, (req, res) => {
    const { name, email, password, role, position, group_name, phone } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email, password required' });
    try {
      run('INSERT INTO users (name,email,password,role,position,group_name,phone) VALUES (?,?,?,?,?,?,?)',
        [name, email, bcrypt.hashSync(password,10), role||'worker', position||'', group_name||'', phone||'']);
      res.json({ message: 'Created' });
    } catch { res.status(400).json({ error: 'Email already exists' }); }
  });

  app.put('/api/users/:id', auth, adminOrSup, (req, res) => {
    const { name, position, group_name, phone, role, status, password } = req.body;
    const t = get('SELECT * FROM users WHERE id=?', [req.params.id]);
    if (!t) return res.status(404).json({ error: 'Not found' });
    const newRole   = req.user.role==='admin' ? (role||t.role) : t.role;
    const newStatus = req.user.role==='admin' ? (status||t.status) : t.status;
    const newPass   = password ? bcrypt.hashSync(password,10) : t.password;
    run('UPDATE users SET name=?,position=?,group_name=?,phone=?,role=?,status=?,password=? WHERE id=?',
      [name||t.name, position||t.position, group_name||t.group_name, phone||t.phone, newRole, newStatus, newPass, req.params.id]);
    res.json({ message: 'Updated' });
  });

  app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
    const t = get('SELECT role FROM users WHERE id=?', [req.params.id]);
    if (t && t.role === 'admin') return res.status(403).json({ error: 'Cannot delete admin' });
    run('DELETE FROM users WHERE id=?', [req.params.id]);
    res.json({ message: 'Deleted' });
  });

  // --- PERMISSIONS ---
  app.get('/api/permissions', auth, adminOnly, (req, res) => {
    res.json(all('SELECT * FROM permissions ORDER BY role, permission'));
  });
  app.put('/api/permissions', auth, adminOnly, (req, res) => {
    const { role, permission, allowed } = req.body;
    if (role === 'admin') return res.status(403).json({ error: 'Cannot change admin permissions' });
    run('INSERT OR REPLACE INTO permissions (role,permission,allowed) VALUES (?,?,?)', [role, permission, allowed?1:0]);
    res.json({ message: 'Updated' });
  });

  // --- ATTENDANCE ---
  app.post('/api/attendance/checkin', auth, (req, res) => {
    const { latitude, longitude, location_name } = req.body;
    const today = new Date().toISOString().split('T')[0];
    if (get('SELECT id FROM attendance WHERE user_id=? AND date=?', [req.user.id, today]))
      return res.status(400).json({ error: 'Already checked in today' });
    const now = new Date().toISOString();
    const ws = new Date(); ws.setHours(9,0,0,0);
    const status = new Date() > ws ? 'late' : 'present';
    run('INSERT INTO attendance (user_id,check_in,check_in_lat,check_in_lng,location_name,date,status) VALUES (?,?,?,?,?,?,?)',
      [req.user.id, now, latitude||0, longitude||0, location_name||'Unknown', today, status]);
    res.json({ check_in:now, status });
  });

  app.post('/api/attendance/checkout', auth, (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    const rec = get('SELECT * FROM attendance WHERE user_id=? AND date=? AND check_out IS NULL', [req.user.id, today]);
    if (!rec) return res.status(400).json({ error: 'Not checked in' });
    const now = new Date();
    const hours = ((now - new Date(rec.check_in))/3600000).toFixed(2);
    run('UPDATE attendance SET check_out=?,work_hours=? WHERE id=?', [now.toISOString(), hours, rec.id]);
    res.json({ work_hours:hours });
  });

  app.get('/api/attendance', auth, (req, res) => {
    const { date } = req.query;
    let q = 'SELECT a.*,u.name,u.group_name FROM attendance a JOIN users u ON a.user_id=u.id WHERE 1=1';
    const p = [];
    if (req.user.role==='worker') { q+=' AND a.user_id=?'; p.push(req.user.id); }
    else if (req.user.role==='supervisor') { q+=' AND u.group_name=?'; p.push(req.user.group); }
    if (date) { q+=' AND a.date=?'; p.push(date); }
    res.json(all(q+' ORDER BY a.check_in DESC LIMIT 100', p));
  });

  // --- TASKS ---
  app.get('/api/tasks', auth, (req, res) => {
    const { status } = req.query;
    let q = 'SELECT t.*,u.name as assigned_name FROM tasks t LEFT JOIN users u ON t.assigned_to=u.id WHERE 1=1';
    const p = [];
    if (req.user.role==='worker') { q+=' AND t.assigned_to=?'; p.push(req.user.id); }
    else if (req.user.role==='supervisor') { q+=' AND u.group_name=?'; p.push(req.user.group); }
    if (status && status!=='all') { q+=' AND t.status=?'; p.push(status); }
    res.json(all(q+' ORDER BY t.created_at DESC', p));
  });

  app.post('/api/tasks', auth, adminOrSup, (req, res) => {
    const { title, description, assigned_to, priority, location, location_lat, location_lng, deadline } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    run('INSERT INTO tasks (title,description,assigned_to,created_by,priority,location,location_lat,location_lng,deadline) VALUES (?,?,?,?,?,?,?,?,?)',
      [title, description||'', assigned_to||null, req.user.id, priority||'medium', location||'', location_lat||null, location_lng||null, deadline||null]);
    res.json({ message: 'Created' });
  });

  app.put('/api/tasks/:id', auth, (req, res) => {
    const { status, title, priority } = req.body;
    const task = get('SELECT * FROM tasks WHERE id=?', [req.params.id]);
    if (!task) return res.status(404).json({ error: 'Not found' });
    const done = status==='done' ? new Date().toISOString() : task.completed_at;
    run('UPDATE tasks SET status=?,title=?,priority=?,completed_at=? WHERE id=?',
      [status||task.status, title||task.title, priority||task.priority, done, req.params.id]);
    res.json({ message: 'Updated' });
  });

  app.delete('/api/tasks/:id', auth, adminOrSup, (req, res) => {
    run('DELETE FROM tasks WHERE id=?', [req.params.id]);
    res.json({ message: 'Deleted' });
  });

  // --- TASK PROOFS ---
  app.post('/api/tasks/:id/proof', auth, (req, res) => {
    const { image_url, comment, latitude, longitude, distance_to_task } = req.body;
    const task = get('SELECT * FROM tasks WHERE id=?', [req.params.id]);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    run('INSERT INTO task_proofs (task_id,user_id,image_url,comment,latitude,longitude,distance_to_task) VALUES (?,?,?,?,?,?,?)',
      [req.params.id, req.user.id, image_url||'', comment||'', latitude||0, longitude||0, distance_to_task||0]);
    run('UPDATE tasks SET status=?,completed_at=? WHERE id=?',
      ['done', new Date().toISOString(), req.params.id]);
    res.json({ message: 'Proof submitted' });
  });

  app.get('/api/tasks/:id/proof', auth, adminOrSup, (req, res) => {
    res.json(all('SELECT p.*,u.name FROM task_proofs p JOIN users u ON p.user_id=u.id WHERE p.task_id=?', [req.params.id]));
  });

  app.get('/api/proofs', auth, adminOrSup, (req, res) => {
    let q = `SELECT p.*,u.name as worker_name,t.title as task_title,t.location
      FROM task_proofs p 
      JOIN users u ON p.user_id=u.id 
      JOIN tasks t ON p.task_id=t.id`;
    const params = [];
    if (req.user.role === 'supervisor') {
      q += ' WHERE u.group_name=?';
      params.push(req.user.group);
    }
    q += ' ORDER BY p.submitted_at DESC LIMIT 50';
    res.json(all(q, params));
  });

  // --- GPS ---
  app.post('/api/gps', auth, (req, res) => {
    const { latitude, longitude, battery } = req.body;
    run('INSERT INTO gps_logs (user_id,latitude,longitude,battery) VALUES (?,?,?,?)', [req.user.id,latitude,longitude,battery||0]);
    res.json({ message: 'Saved' });
  });

  app.get('/api/gps/live', auth, adminOrSup, (req, res) => {
    let q = `SELECT g.user_id,g.latitude,g.longitude,g.battery,g.logged_at,u.name,u.group_name
      FROM gps_logs g JOIN users u ON g.user_id=u.id
      WHERE g.id IN (SELECT MAX(id) FROM gps_logs GROUP BY user_id)`;
    const p = [];
    if (req.user.role==='supervisor') { q+=' AND u.group_name=?'; p.push(req.user.group); }
    res.json(all(q, p));
  });

  // --- NOTIFICATIONS ---
  app.get('/api/notifications', auth, (req, res) => {
    res.json(all('SELECT * FROM notifications WHERE user_id=? OR user_id IS NULL ORDER BY created_at DESC LIMIT 50', [req.user.id]));
  });

  // --- DASHBOARD ---
  app.get('/api/dashboard', auth, (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    res.json({
      totalWorkers:  get('SELECT COUNT(*) as c FROM users WHERE role="worker"').c,
      presentToday:  get('SELECT COUNT(*) as c FROM attendance WHERE date=? AND check_in IS NOT NULL', [today]).c,
      activeTasks:   get('SELECT COUNT(*) as c FROM tasks WHERE status IN ("pending","active")').c,
    });
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log('GeoWFM running at http://localhost:' + PORT);
    console.log('sh.xaytbayev@geo.uz / 1234');
  });
}

start().catch(console.error);
