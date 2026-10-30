const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

const DATA_DIR      = path.join(__dirname, 'data');
const DATA_FILE     = path.join(DATA_DIR, 'items.json');
const CONFIG_FILE   = path.join(DATA_DIR, 'config.json');
const USAGE_FILE    = path.join(DATA_DIR, 'usage.json');
const REQUESTS_FILE = path.join(DATA_DIR, 'requests.json');
const AUDIT_FILE    = path.join(DATA_DIR, 'audit.json');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const MAX_USAGE_ROWS = 20000;
const MAX_AUDIT_ROWS = 5000;

if (!ADMIN_PASSWORD) {
  console.error('ERROR: ADMIN_PASSWORD environment variable is not set. Set it to a strong password and restart.');
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.warn('NOTE: SESSION_SECRET not set — a random one was generated. Everyone will be logged out on restart.');
}

// ---------- generic json helpers ----------
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return fallback; }
}
function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

// ---------- items ----------
function loadItems()      { return readJson(DATA_FILE, []); }
function saveItems(items) { writeJson(DATA_FILE, items); }
function nextId(items)    { return items.length ? Math.max(...items.map(i => i.id)) + 1 : 1; }

// ---------- config (stores) ----------
// Each store carries two codes: staffCode (lookup only) and managerCode (can edit).
function loadConfig() {
  const cfg = readJson(CONFIG_FILE, null);
  if (!cfg) {
    const seeded = {
      stores: [],
      updatedAt: new Date().toISOString()
    };
    writeJson(CONFIG_FILE, seeded);
    return seeded;
  }
  if (!Array.isArray(cfg.stores)) cfg.stores = [];

  // Migrate older single-code stores forward.
  let changed = false;
  cfg.stores.forEach(s => {
    if (s.code && !s.staffCode) { s.staffCode = s.code; delete s.code; changed = true; }
    if (!s.managerCode) { s.managerCode = ''; changed = true; }
  });
  if (changed) writeJson(CONFIG_FILE, cfg);

  return cfg;
}
function saveConfig(cfg) {
  cfg.updatedAt = new Date().toISOString();
  writeJson(CONFIG_FILE, cfg);
}

// ---------- usage log ----------
function loadUsage()  { return readJson(USAGE_FILE, []); }
function logLookup(storeId, storeName, query, found) {
  const rows = loadUsage();
  rows.push({
    ts: new Date().toISOString(),
    storeId: storeId || 'admin',
    storeName: storeName || 'Admin',
    query: String(query).slice(0, 60),
    found: !!found
  });
  if (rows.length > MAX_USAGE_ROWS) rows.splice(0, rows.length - MAX_USAGE_ROWS);
  writeJson(USAGE_FILE, rows);
}

// ---------- missing-item requests ----------
function loadRequests()  { return readJson(REQUESTS_FILE, []); }
function saveRequests(r) { writeJson(REQUESTS_FILE, r); }

// ---------- audit log ----------
// Every change to the item list is recorded: who, what, when.
function loadAudit() { return readJson(AUDIT_FILE, []); }
function logAudit(req, action, detail) {
  const rows = loadAudit();
  rows.unshift({
    ts: new Date().toISOString(),
    actor: req.session.storeName || 'Unknown',
    role: req.session.role || 'staff',
    action: action,
    detail: String(detail).slice(0, 200)
  });
  writeJson(AUDIT_FILE, rows.slice(0, MAX_AUDIT_ROWS));
}

// seed data files if missing
if (!fs.existsSync(DATA_FILE)) saveItems([]);
loadConfig();

// ---------- middleware ----------
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(session({
  name: 'produce.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 60, // 60 days
    sameSite: 'lax',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.authed) return next();
  return res.status(401).json({ error: 'not authenticated' });
}
// Managers and admins can change the item list.
function requireEditor(req, res, next) {
  if (req.session && req.session.authed &&
     (req.session.role === 'admin' || req.session.role === 'manager')) return next();
  return res.status(403).json({ error: 'manager or admin only' });
}
// Admin-only: deletes, bulk import, store codes, full activity log.
function requireAdmin(req, res, next) {
  if (req.session && req.session.authed && req.session.role === 'admin') return next();
  return res.status(403).json({ error: 'admin only' });
}

// ---------- auth ----------
function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

app.post('/api/login', (req, res) => {
  const password = String((req.body && req.body.password) || '');

  if (safeEqual(password, ADMIN_PASSWORD)) {
    req.session.authed = true;
    req.session.role = 'admin';
    req.session.storeId = 'admin';
    req.session.storeName = 'Admin';
    return res.json({ ok: true, role: 'admin', storeName: 'Admin' });
  }

  const stores = loadConfig().stores;

  // Manager codes are checked first — a manager's code should never fall through to staff.
  const mgr = stores.find(s => s.managerCode && safeEqual(password, s.managerCode));
  if (mgr) {
    req.session.authed = true;
    req.session.role = 'manager';
    req.session.storeId = mgr.id;
    req.session.storeName = mgr.name;
    return res.json({ ok: true, role: 'manager', storeName: mgr.name });
  }

  const store = stores.find(s => s.staffCode && safeEqual(password, s.staffCode));
  if (store) {
    req.session.authed = true;
    req.session.role = 'staff';
    req.session.storeId = store.id;
    req.session.storeName = store.name;
    return res.json({ ok: true, role: 'staff', storeName: store.name });
  }

  return res.status(401).json({ error: 'wrong password' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/session', (req, res) => {
  if (req.session && req.session.authed) {
    return res.json({
      authed: true,
      role: req.session.role,
      storeName: req.session.storeName,
      storeId: req.session.storeId
    });
  }
  res.json({ authed: false });
});

// ---------- items ----------
app.get('/api/items', requireAuth, (req, res) => res.json(loadItems()));

app.post('/api/items', requireEditor, (req, res) => {
  const { name, code } = req.body || {};
  if (!name || !code) return res.status(400).json({ error: 'name and code required' });
  const items = loadItems();
  const item = { id: nextId(items), name: String(name).trim(), code: String(code).trim(), discontinued: false };
  items.push(item);
  saveItems(items);
  logAudit(req, 'added', item.name + ' (' + item.code + ')');
  res.json(item);
});

app.put('/api/items/:id', requireEditor, (req, res) => {
  const id = Number(req.params.id);
  const items = loadItems();
  const idx = items.findIndex(i => i.id === id);
  if (idx === -1) return res.status(404).json({ error: 'not found' });

  const before = Object.assign({}, items[idx]);
  const { name, code, discontinued } = req.body || {};
  if (name !== undefined) items[idx].name = String(name).trim();
  if (code !== undefined) items[idx].code = String(code).trim();
  if (discontinued !== undefined) items[idx].discontinued = !!discontinued;
  saveItems(items);

  const after = items[idx];
  if (discontinued !== undefined && before.discontinued !== after.discontinued) {
    logAudit(req, after.discontinued ? 'discontinued' : 'reactivated', after.name);
  } else {
    const changes = [];
    if (before.name !== after.name) changes.push('name "' + before.name + '" -> "' + after.name + '"');
    if (before.code !== after.code) changes.push('code ' + before.code + ' -> ' + after.code);
    if (changes.length) logAudit(req, 'edited', after.name + ': ' + changes.join(', '));
  }
  res.json(after);
});

// Delete stays admin-only: it is irreversible and hits every store at once.
app.delete('/api/items/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const items = loadItems();
  const gone = items.find(i => i.id === id);
  saveItems(items.filter(i => i.id !== id));
  if (gone) logAudit(req, 'deleted', gone.name + ' (' + gone.code + ')');
  res.json({ ok: true });
});

app.post('/api/bulk-import', requireAdmin, (req, res) => {
  const text = req.body && req.body.text;
  if (!text) return res.status(400).json({ error: 'no text provided' });

  const items = loadItems();
  const existingByName = new Map(items.map(i => [i.name.toLowerCase(), i]));
  let added = 0, updated = 0, skipped = 0;

  const lines = String(text).split('\n').map(l => l.trim()).filter(Boolean);
  for (const line of lines) {
    let name, code;
    let match = line.match(/^(.*?)\s*[-,]\s*(D?-?\d{5,6})\s*$/i);
    if (match) { name = match[1].trim(); code = match[2].trim(); }
    else {
      match = line.match(/^(.*?)\s+(D?-?\d{5,6})\s*$/i);
      if (match) { name = match[1].trim(); code = match[2].trim(); }
    }
    if (!name || !code) { skipped++; continue; }

    let discontinued = false;
    if (/^D-?/i.test(code)) { discontinued = true; code = code.replace(/^D-?/i, ''); }

    const existing = existingByName.get(name.toLowerCase());
    if (existing) {
      existing.code = code;
      existing.discontinued = discontinued;
      updated++;
    } else {
      const item = { id: nextId(items), name, code, discontinued };
      items.push(item);
      existingByName.set(name.toLowerCase(), item);
      added++;
    }
  }

  saveItems(items);
  logAudit(req, 'bulk import', added + ' added, ' + updated + ' updated, ' + skipped + ' skipped');
  res.json({ added, updated, skipped, total: items.length });
});

// CSV backup of the whole item list
app.get('/api/items.csv', requireEditor, (req, res) => {
  const cell = v => '"' + String(v === undefined || v === null ? '' : v).replace(/"/g, '""') + '"';
  const rows = [['Name', 'Code', 'Discontinued'].map(cell).join(',')];
  loadItems()
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name))
    .forEach(i => rows.push([i.name, i.code, i.discontinued ? 'yes' : 'no'].map(cell).join(',')));
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="produce-codes.csv"');
  res.send(rows.join('\n'));
});

// ---------- usage ----------
app.post('/api/usage', requireAuth, (req, res) => {
  const { query, found } = req.body || {};
  if (query && String(query).trim().length >= 2) {
    logLookup(req.session.storeId, req.session.storeName, String(query).trim(), found);
  }
  res.json({ ok: true });
});

app.get('/api/usage/summary', requireEditor, (req, res) => {
  const days = Math.min(365, Math.max(1, Number(req.query.days) || 30));
  const cutoff = Date.now() - days * 86400000;
  let rows = loadUsage().filter(r => new Date(r.ts).getTime() >= cutoff);

  // A manager sees only their own store. Admin sees everything.
  const scoped = req.session.role !== 'admin';
  if (scoped) rows = rows.filter(r => r.storeId === req.session.storeId);

  const byStore = {};
  const byQuery = {};
  const failed = {};

  rows.forEach(r => {
    const sKey = r.storeName || r.storeId;
    byStore[sKey] = (byStore[sKey] || 0) + 1;
    const q = r.query.toLowerCase();
    byQuery[q] = (byQuery[q] || 0) + 1;
    if (!r.found) failed[q] = (failed[q] || 0) + 1;
  });

  const top = obj => Object.entries(obj).sort((a, b) => b[1] - a[1]);

  res.json({
    days,
    scoped,
    scopeName: scoped ? req.session.storeName : 'All stores',
    total: rows.length,
    byStore: top(byStore),
    topQueries: top(byQuery).slice(0, 20),
    failedQueries: top(failed).slice(0, 25)
  });
});

// ---------- activity / audit log (admin only) ----------
app.get('/api/audit', requireAdmin, (req, res) => {
  res.json(loadAudit().slice(0, 150));
});

// ---------- missing-item requests ----------
// Admin sees every store's requests; a manager sees only their own store's.
app.get('/api/requests', requireEditor, (req, res) => {
  const all = loadRequests();
  if (req.session.role === 'admin') return res.json(all);
  res.json(all.filter(r => r.storeId === req.session.storeId));
});

app.post('/api/requests', requireAuth, (req, res) => {
  const { name, note } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'item name required' });
  const requests = loadRequests();
  const entry = {
    id: Date.now().toString(),
    ts: new Date().toISOString(),
    storeId: req.session.storeId,
    storeName: req.session.storeName,
    name: String(name).trim().slice(0, 120),
    note: String(note || '').trim().slice(0, 300),
    status: 'open'
  };
  requests.unshift(entry);
  saveRequests(requests.slice(0, 500));
  res.json({ ok: true });
});

app.delete('/api/requests/:id', requireEditor, (req, res) => {
  const all = loadRequests();
  const target = all.find(r => r.id === req.params.id);
  if (!target) return res.json({ ok: true });
  // A manager can only clear requests from their own store.
  if (req.session.role !== 'admin' && target.storeId !== req.session.storeId) {
    return res.status(403).json({ error: 'not your store' });
  }
  saveRequests(all.filter(r => r.id !== req.params.id));
  res.json({ ok: true });
});

// ---------- store management ----------
app.get('/api/stores', requireAdmin, (req, res) => res.json(loadConfig().stores));

function codeInUse(cfg, code, exceptStoreId) {
  return cfg.stores.some(s =>
    s.id !== exceptStoreId && (s.staffCode === code || s.managerCode === code));
}

app.post('/api/stores', requireAdmin, (req, res) => {
  const name        = String((req.body && req.body.name) || '').trim();
  const staffCode   = String((req.body && req.body.staffCode) || '').trim();
  const managerCode = String((req.body && req.body.managerCode) || '').trim();

  if (!name || !staffCode || !managerCode) {
    return res.status(400).json({ error: 'store name and both codes are required' });
  }
  if (staffCode === managerCode) {
    return res.status(400).json({ error: 'staff and manager codes must be different' });
  }
  const cfg = loadConfig();
  if (codeInUse(cfg, staffCode) || codeInUse(cfg, managerCode)) {
    return res.status(400).json({ error: 'one of those codes is already in use' });
  }
  if (staffCode === ADMIN_PASSWORD || managerCode === ADMIN_PASSWORD) {
    return res.status(400).json({ error: 'cannot reuse the admin password' });
  }

  cfg.stores.push({ id: 'store-' + Date.now(), name, staffCode, managerCode });
  saveConfig(cfg);
  logAudit(req, 'store added', name);
  res.json(cfg.stores);
});

// Change one store's codes without touching the others.
app.put('/api/stores/:id', requireAdmin, (req, res) => {
  const cfg = loadConfig();
  const store = cfg.stores.find(s => s.id === req.params.id);
  if (!store) return res.status(404).json({ error: 'store not found' });

  const name        = req.body && req.body.name        !== undefined ? String(req.body.name).trim() : undefined;
  const staffCode   = req.body && req.body.staffCode   !== undefined ? String(req.body.staffCode).trim() : undefined;
  const managerCode = req.body && req.body.managerCode !== undefined ? String(req.body.managerCode).trim() : undefined;

  const newStaff = staffCode !== undefined ? staffCode : store.staffCode;
  const newMgr   = managerCode !== undefined ? managerCode : store.managerCode;

  if (!newStaff || !newMgr) return res.status(400).json({ error: 'both codes are required' });
  if (newStaff === newMgr)  return res.status(400).json({ error: 'staff and manager codes must be different' });
  if (codeInUse(cfg, newStaff, store.id) || codeInUse(cfg, newMgr, store.id)) {
    return res.status(400).json({ error: 'one of those codes is already in use' });
  }
  if (newStaff === ADMIN_PASSWORD || newMgr === ADMIN_PASSWORD) {
    return res.status(400).json({ error: 'cannot reuse the admin password' });
  }

  if (name) store.name = name;
  store.staffCode = newStaff;
  store.managerCode = newMgr;
  saveConfig(cfg);
  logAudit(req, 'store updated', store.name);
  res.json(cfg.stores);
});

app.delete('/api/stores/:id', requireAdmin, (req, res) => {
  const cfg = loadConfig();
  const gone = cfg.stores.find(s => s.id === req.params.id);
  cfg.stores = cfg.stores.filter(s => s.id !== req.params.id);
  saveConfig(cfg);
  if (gone) logAudit(req, 'store removed', gone.name);
  res.json(cfg.stores);
});

// ---------- PWA assets ----------
const ICON_192 = Buffer.from('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', 'base64');
const ICON_512 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAgAAAAIABAMAAAAGVsnJAAAAMFBMVEX8/fv2+PT1+PT1+PP1+PLk+ePD38NBmks9lkc8lkk8lkY8lkUnuC82kUH/AP8AAADE+eCkAAAfCklEQVR42u2de3QUVZ7Hv7c6wTinH9W8ZIFAiQ4ykkcTNbBBBCQ6mgUWx4XdCYgYRpizrmdnFAOjshthVR7qzO7s2Z0QQYfXmcFxyRIOuypIYiCLyKOTJixmSGjSwCIjdnU6ShOoqv2j00k/qqobtCqpun3/0dCdx+/T39/j3vure4mElMehoWOAUG1goPv2Mxz63WBFS60grQHa3lmd+neRlAFcOTsOobpP8hy1ACnof/ZDcAMWV5tr/xpsOrP6uwYgvLQGv8i3tPJk4O0sJL4fAoAT8LfycA4a+Qj+Ycyi7xTAsV0VK5zwk3vg6Je299rj4Fv5jPzLP0XL2O8OgPDSmtArDn6QC/3b+ohJ9v0W27BFxxjXdwQgtKbiJfayZYIEowxW3D/hbHloTcV3AuBQ1rj/lBofNMSn3xsPvvTYr1S8+Np3AGBT2dVf+QfnG8p8AEQ6OuHMihVrvjWAFWtOVQdm+GG8wR4N4PVDk74lgJWr10rBaTyMOIi13r48lPWtALz42lopI9+Y9gPEsc95ZYU6AUb11d+8ttZ/x2ij2g+JL/bfevHQzQM49NNKfzGMPPzF/vcmHb5ZAKFJH5wp9sPgBC6vLVx5czEglPXB8TslGH049w5e5uVuQgHCmpb9JrAf/uLLb2S/exMKqHj5jYzRMMNgP544m7lhAMdcL2bkwxzDXvvD7xXeoAuECtZbpprEfnTkf1TovUEAF0/5XbxZACDD9sZt7hsCcOjPqu+FeYZ0x5cfjLsRAKFJO4MSzDSmf3rRfQNB0LsjMI03FQAI55753JWqAg6NtLtMZj8slyvHpeoCXZPe6ITpxoNfXKxIEcBrn3fmmw8An/+HFanFAPHaTgvMOI79kHWlooCm/R5T2o9pH41LRQGi+MY9vCkBkNNZrb9OroCmP2SY035Id36x3p0UgDDekw+TDin/N+8ndQH3KQvMO4794ymXugKE8R4T249ECcQrwNwCkJEAQ5UAZCQQp4CKceYWQKIEYgEIYoXL5ACEYbHlYKwL+PaZ3X5Y9uYqx4DQqDrW7ACQU+NWBHDqjxbe9AAsR3KVAAg7jk81vf0gVl+FAgDyisf8AoDk2iEoZAGzF0ERk92vWGQVEDJ7ERSRQE69WxbAqU0sFQBgiV4YiQJQPdpFBwDYf+eWASC8XM9TAiCfq5YJghWTLLQAQOMqJkEBQpcb1IyczRUJAMiqTmoEAHaYkOACNHlAtA8wNHoAkLP5Z3EArtHkAQA73BbnAhXjBtEEAI0vZ8UoQLjMgqqRe+hnMQCu/fIAVQKAA92feEb4P81HHHQpoPPAyzEKqKFmHtAzJ6xwRwG48hcenjL7pzxSHQWATAhQJgDwXUJUGqSrDAwbfnxlVq8CaLMegOR81d0DILT+AH0IRs6o7nGB0D8hnzoAouUxS0QBa0ZOpc8HmONRWYADhYP8q7sbgPCih6cQwP1SdUQBDI32A67IXMDz+4E02t9ZvzIyGcofRKMEJBIJgr9jqfQAOH7jBhggtOoAnTEgm+tWACPRqQBkhQGcqqXUBTLqx4UV8KWLTgASCSvgXdA62DVuEEkQdjKUArCF3BUMwHhoVQAPgEEXtR4AkrUSDD7f76AVgKX+GhhUX3bRCkAimWAAlqfXCXwgUqg2SK394i0ccyXjAL0CkFgwAySJXgAsqjOuZRB6AQTISuZUhYNeABZPlyXrnttD9BI4+xCziGIBAJLEsDzFZQAhn1ns3/8exS4w7BZybV8HxS5gCzFSE80xgAdDAjQDAMtAotr+y4xEaAYQcDJe0D0YQnUhxHzMSLQroJWj2XwChnIBSEyka5paFwDSAGj2AJZ2BYyitEGs1wMYlvYYQGiXQBPtCuBoB5CuA9IA0gDSANIA0gDSANIA0gDSANIA0gDSANIA+scQ6QYgtvl0/G0Z/c78MwPmdvl4agG0Bcu6Kv1ZNhelAFoLh1f6q3CL20MlALFp8Yavqkgxjm4XXBQCED1PVbZUF8MP1+F/bqIPgHh+wfoNg4v9AIJNNRJHG4DWwvy3qoolPwBIRe3ZOv1asqO/hP+5hz98t+eSd9LU6KFLAW1zK1tqoi65t2+36eMD/aQSbJxbeXj3ND+AcMeKlNOSR1EpLLoXVK47MZUHALHOCQCdO2/X53db5vYD+5uf3Li++LZw+dtevGd8Vgi4M3CFpQSA2Fz65q+L/eGnFkj7H6591DIuhFuuPnKVDhcQm0vfrOq95J4MeGHJwjqgc6c+QbDPs4DoWfDWxl77hWldv13aJfl4qWibLnkgox/Y/3ZU+nOMrSnYMQAA8JWNBheIsx8Aj9tLanig8+1ZFABoi7f/BMtCkgIAYN/qNT2Atrlx9pOO+RzCj3BI4zt4swNonVtZFat/QALOb3IAQPDwQpMDEAor1xXH2i9MJwAfPtiIHDd5ISQOqDt8Z9znb7/7IouuSx0hALjzrMSaWAHi+VtbTvgT/pmHWHI27PykZbaZXaC5ZMeBhLNsAywLSaoPfxHcL5kYQFvp2q358WGeNPckAQCSfbv2ibCvKsHWea9vnSqT5iTgfM9R/zm8zawKEAorN8rZ7yQAf93V/VXnhtkmBSBe+GDDDBn7rfN2Ifqkc7PGALH50ZZ7/bIv8RBLAxECUtE2rykB+ErXHZC1n7AsJNT0fq39ymBfABBmrd8qe5g7OTCZi9F9cOdoE2YB8cKx306Tn+eQ0R6cOxZV/jm2OjjTKaD50fcU7AchQMe1XnXoMCPUH0Bb6TqlW72sf9WE2OsuSMtCswEQ7tu4VfE2h4FuoCj6TA/tq2FG9wDwwZtTFWXNshC5muiXNa+G9QbgK2mZoWQ/OWjnEHu4nZSj9TlPOgMQZq3d7Vd8lcwEMt6JnR5qHQQydHaA41uVHQCEAO3XYt5g0ToI6KsAb8lhFfutc9qBOMlrPiXWFYB439oTai49tBa4P+4NWgcBXQE0f7pV9T4jloU4anecwZemmQaAUNqi4gAgB8X4JACgc2e2aQCc3LRVVc5kAWBJWAuXtpoFQFvpR+oXWhEG8H0W9x5pcofbHGlQvG/tOYvaG2xzziYkgXBoMIcCmj9Qj4CQhtYCeQkANF4Y1A1AkgjY/UmLObsT3iSZIwZc2LRb3X7SLLKQOeZa44VBvWKAWPLnyQQQWOCB7OGGvGACAM3/nZGsoiMAzn+aiCnQomXruE4AxB/nJROAMI0AvMxUUdv5kE7b4yf+i0l2enHMzniMMi7ahhk9CAo/3pLCwZU8xJKaRJ1Ikxm30QGc3DAh6Zwuqj0qgQxrcABC6b8kFUBUe5SupZAuQfDkpwNTmNRLwPnP8hVeMTQAofTuB5MCCLdHXZa98saxRbv9IUaXCJDClZ6OsbuUpj3S+A5DxwCh1C0jbMLKJYGzPHQeOgC4sKlexixrnVwSqJePgjtmGxiAWPJHmXUQ9uCT3hSTAAC/ZGAAvuNy08C6sucDiUlgk0K2dGi3Nq49AOZDOQEsXrZrZnQUkJy9PbIyUZA3rgKER2VWQskn5Ru/jslstnm70CdnPGsO4OQGmU9VmvwrZvySupSTQEC7plmtAYhFXjm/Ji0LQaay0VmRhYR6pTmrdjNirQFIo2VXwoL7wWyP2vEgB+dzqiWvZvdgaF0KX/hAdiFEKtomOIdELxNLwLljSlMmya7ZI2QaK0As+U+FV/7oGlkW9aWTAB3XXEo/R7stUo0BnN8UlP/LO/8j17JnQU8QsBbH9sgmDM0uRtU6BvxJaTfMvt2LwY09Xw7kIRYpX3nUuS/PkADEEqXtUCmH54eX9b7IspC4GmUJ+I2ZBXyblD/TDU9Y/jdSDJKDU9STAKRdXiMCYP6kvB8s+rzenjMCSHZCe1Rc5RQ0ogKUPQCQJtfww5+OFIPd7VEqP8uQWcCySeVF8uFCQqaEfcD6WLv8zngUTCPWAU0qHoDgGTDbI93wQ2qBIjUAgdN5xgOgltcAqWibO/fhup4kIHJq28eWWgO6gDS6RlXVLQ+IE7qTgFx7VMJ6ieEAXNikOsHv3Dma6S4GyQIgY2dsiIj7Xq1uxtQ0Bnyp3hOTt90rhotBQoD2mIBBrB/H2u/weI0GQCxR7wmRrDxGlvGQ65F1Xj/4k1iDc4wYA5Lk7s7KWZb/WsAi3CM7JerdziMXnvt5QJdCQMP1gPOHkvVEOLY6LIM9ANhsiNm7exzGuffhifPjo55oOAUkncJL4zswvKwxvj2KsHvnTZxfHTVZBgByerbBAIilSfe5OjfMJmdnsQgsACxnIpbaape+Pn/XmLimgGCt0RSgtM8V8552pmF0eMHP191HS6wHflJ+eBfXtiizUY9CQLsYcOEYm9T+ohpbXl7elKgeWeeRb8rK3xsz6tjTlW2xT41KW/INFgP+lPwPJpcWgtikoZ9ENkWcRwqXL6saI/qerjxcHWt/rjY3BGsGQCw5m/xNwZ0Ss/0vwUaKBufehyfO31ggnp+5dt2JabHvtfMGiwGoT/4XS5O3e+1zD4KFJPEg9r1L7irdVdA6pOStDcWjeegxNAyCKb3Ji5FjSHhnnFjrly4vquHa5h1+8+3ixEXAS5pMiDULgr6jbArv6vz9S03bF0nA+U+nXT+4uHyHZVT88ao98YLnmowEgLmWn4qG7dtsbBcBeP/1hueWVBWInkWVLd3Hq8bFC23O2dUuDabkwlIOn22fvZMD6xu6fGFVgXh+QdWGDPkSWjJUDBDvDqT0vs4NU5j3OYgl39w1/52C1sySt9bdqyQdyUgAwNWkFsXFLd4xALx3le5ytc5rWVdV7Ff6RmIoF1D/uIiDjyTCIAAwJ4tquLZ5Gz6vKVbeAzJUIeR7R9V+W093SPcZESM8oxrnVn4qG/4ik+d6r4EUwFxTe0rcemBmZNc4GM5tzKjmBZXrBqt8kzSKMZILqC4GXG94rqupZ0K0zcYBrQNK36oqVl1D0uZcMY0AiEWVKq8OeOHJ63k9UyVeAITC4bLVXyxUwUAK4ALKDc6kcfPGRT1fBVgbcMH9xW+LNdsC75M0WK+aIe450bMz3jyfg1jy+dYZye1njaMA1W0eyb7NFuQ8UQnz/Ke7p/bJ56+ZAtRrlhyezxsSWfByEoCXki0gAxptEGsEgDmj9mqgZeH1x7otjj9CUAXql3bjAPDtV/NXy36ppzUA4JNsI/dmVgMpANdVFwSlrb2tAcnao3qx1RopC6gaJE3ucLNhASRvj9J49M2psuTSrK8eDZdCJJuPPULQHFlglPrLwepRkQYAQoCB11Ja8jfSeoCNT2YLs2cmC8D6eBPgTW3pQBMC2gAQJfVCQCra5u3e+xvkjmmPcprEBbhknymP3IfqupNAVHsUOcqaAwCa1AkED88WxiDhCEFivbdRJXQSAwFIUtmQ45LFN5ONO0KQWBsK+JucYPSvNJj0T5Xs221BNhh3hKDtwIpFX+h446ym0+EkI4fn2SGNse1R9vqfzn+X5W92imUsAOTStOFP8eH2qMlhm531i5/dPH5JoxnSYPIR3JlNyBQWLAsx/GCZc+/i8nddZ5hZrAlcIAWtOra27xkd1SNLjiwtr3IJ8zapnCVtJheQxnfwcIZ7ZI8DIKcLy98rEAZUbtDX/r68bI0d/mieBUC7bypPrIUTd9whDrh1x506zwy1UUAK7TydG2YTInS3RxFrw8SiO8Tm723o1HtmrNFcIIW1GwnMiSeHfgLk8bA1LC/1iM2lv9+dD1MASCUIFG3zNrEsIObsxoGfzK/hPKXr1E5dhjbXTvXhXWM8n/swWEgSPi772Wau7Yn1W1TXhu3TzAUg8OFCkdg4EFxfsmyTq3Xum79VXxuXSLupsoDlDJiTHHD+0NLyqoLWeZVVM5LMAoa4OVO5gGMLRgDAN/OqCoTCynXFfF/8FX2nAGl8h9sFYAS6CsQLxw/3zd5oXyqAXHoAAJjxHvH8oy3nTLU3mFI1E7lEqGNUc8m6AylcKGS2NNhT3Hvkbt6TqR2NNBtMZd4iFW1zA0Dbgje3prA5TBpF0ygg8lAk7wLQNvetjalsjoM8wRkIwBRlhyVOa2TVxwuIcyvfnsF/d5Gln6RBL6vcImTbmzmze9WDB84fW5diAiSGWg9Q/rSIZ8ltvg4A8EyxQSz5cYr2C5pMBfogBlgfX74oTCI4nwOkEykWAA7WaxwFMCdZ5TM/BmwYMLiG65ZJ7w2rScfQJs4UCiCXZowvCyDJEYKy82cDuYDK3xqsHhUOEDd4hGCANVIlqPbHSlIknt/IObKkeTJnIACqS9gEmIJkRwgmDm2uH9UKgEV5h8u+rX3PaDb5EYJxw6nNkYIa1QGjQrzSByblREKEhBtojwpfx2kYBQiPqUVInmURc8OqPQUMGl0yoBEAVWWLLjGzLvqGVVLf+O3iav8DoFa3B4/kjXwKUTesEuvimcmsIwdzOSMBAJQLPHJcAgl/pAJXwwNsw7zBSSVAcmEkAIxXZT4MQjCFHMzrTgLkyNKuxf5vo6n+qICTKvY7tjB7RrMkp7s9yjrxGc/2J5L4gPWxdmMBUAuQ4xkv33uEIDlYuJnDC3VJvmuI22AAnEny4PXuIwSJ9elSl1D6RpKrCJvtMBYAMUMtrLFiJt99hKCt4ec1OLlpS5IpQWABZywA2U8pWxRomZ39lDvcIxuoX/4+11b62dQkhdV0YjAFqFVCllpIyAy3R1kfLx2T7DZedF/BYigAqllLkgjpPkKwoXBL0tt4AQ2vHtDqsjUp1EmUrlcjF2deuRqa/gV8//fNj4oGCg9t/rMkAiBH/v2qwRTAnFQuBaWc+vZmlgF4/rZnPWLSuyih5WMEmqVBNZscPD/K6QZcXxdu4nyPVk1NOheet9lwANQnb6z0ICDePbC0QJiz7s5kAiAnWNZwAJChXLqRS3lwA8DQLThZtTX5wnhHKWc4ACPKlJ+ZCFZz4ABmz2RXW/LbeAHrY2eNFwPUc0S4TBjRJH5/XfIICIxtMiAA1dLNF/7lXPMPNk9N/pMacjXzAO0uXSWXrirfsxoaeoUFAOGhdSncxEcuVXxhPADwdHUoAsh2SMMAoPmzDSlsDdpKTg0zoAuwyYuXttKPpqagpYOpLBr3PwDZD6mscVx2ARDuW3uOT+VvXMAZEYCg8leHL405mcIkCIB1SQ2MCIAQZfcWXADE0sOpNEeRZg0dQMsgSD5zdilFQfvdF1mc+2RzKqYR379dNaQC0KE+VxJLNk5FSh6wGcYEwDoVBR6+YTWYSgQkDc+4DAogW3G7R/2G1fh5gBcGBaC2Q6x2w2r8POATowIgRCnGiRNSbo8iDfM19QANswDIpYDCbMBecJFF1yXlUjm6DL7IGlUB8LGqSSCV9ijSMErjmbmm6wGD3fL/Hki5Pcr62CzOuACUFoVI83wOJJX2KHJQsw2RyND0oSmilgRS6ZG1PVjqMbALMF6FzhcnAfjryaM7kQq3wMgxoEHe/tSPEGwodRkaQN6QOsUkkMoRgtalNTA0AOEphVlCakcIkoZnYGwAIFNkQ3uKRwhal1ZzxgbA7BktFwXCN6yyKQiAMboC5Lf1o3pk+1wAGgOQXRi1Pt6eyhGCTl0EoPXN07fL/eug2iQ3rAIA+XKpmzM8ABC5htGkN6wCgO3kM+0wPABmz2iZJGDnkh83R+qX7+KMD0A2CsYcIagYAR8v1cV+rQGMeLhONgmoX7MNkIaxW3SxX/MjNBKjYOINqzL2W8s0nwbqowDGkzghjDpCUDECNjxfA1MAkFsW6z1CUFEAx5e+z5kEgDikMT4JJL9m2zrxb3Vr3dH6F41MaJom0TesygvgYOEWvQSgeRAkZErcHiEB4POp3kKkWwTUQQEJE0Jb1A2rShFwXg1MAwAYHGusNPQT9ftDnQeW/4kzEYDhZY0JtaE484AiAXKkbH47TASAnI2tBMLXbCsrwFpYvpkzEwAmdmmYBBao7ow7Gya+54KZACD3+3XxSeC8YoM8ObK0dAzMBUD4UcxX0wjA+xUz4A+frdHVfi23xyOIY3pm7Xer7YzbG/7y6A9gMgXAExvTeIglCnsCzrqlpQUwHYDc6DWBcHuUwq7xkaef0dkBdAEQvTKq1h5F9M6AegFgdi+IyoSK7VHEqncG1AsAmF77hemK7VG2huU6Z0DdAIxY0hMEHGOVTo9yHlg6vwbmBBDj9ArtUc69Zc/s4kwKgNnTEwSCLAtJqperAJdt7gv7dXpqLNIuRjzySYBYC8e+74JpAQzvbReTTQLE2jBxxBiYFwAh3VfHSLLtUcTWsLy0rw441uX39tyvGT5CMD4E2ur7JgHoGAPG91TDMknAWb/42b4JgPoBwO1ht5c7QtC5d3F5tQvmBsDsmcUCIAefSOiRZfcuLa/qs89fNwWI3b0yAuCLaY9i65aWv1cA0wPILuhOB3HtUc6PF5e/N6YP7ddhRShs+T6uKwTbJCdwKWo5yLlvSR/br9v5AfYhjYg6QjAS//rcft0AjCzjEdcjS5x7l/a5/boBsOxZwJKDdg6i1FP/9Qf7dTxCY0gjyExvT3sUsdX3B/v1AzC8jAcZkNvW3R5FrPWL+4P9emUBgNnHXeW/+urHn17qCAHOE639w34dXcA+pG5E5edvL+IB4txb+Fx5VX+wX8ebprJn/jKj+MOv/QdGE9veJbctrCroD/aD7NDtV/k8Pt4p7J9Bvmwue3h8db/4/HUFgJy8fBAWewsnlB/2cf3Dfj0vWxPJzGCAvV47766F743pL/brqgDfxXeyj2eWzRvxbgFAIwDB9YMhjzmX9B/56w0Anqtkifj+GPSnoeuFi+PvE3eQ/mW/vgCYHeQOgGIA6Hfm9/GFi2kAaQBpAGkAaQBpAGkAaQBpAGkAaQBpAGkAaQBpAGkAaQBpAGkAaQBpAGkAaQBpAGkAaQBpAGkAaQB6AWBpB3CZTbtAGgDFQ6Q9BvgoVwDxMzz1MYBuAiRdBwS8lAMIUm2+RHsMEF3Mk4RqCQxkUrryyrTDQX0pzDAi1S7Ag2FyaQbA8ozVQTOAgJc5RHUI8ExnWJrrACLkMu+C4tmAxICZc8JNsQLQxYyrCNALQJiWyWSC4lLQ8fVq5hooroR4dk5GJqG4EmL5WsayykFvGjjBz2Ewh+JCgP8bVwYQsNCbBTPBYJylkdosmAswyFxEbR503PY8GECkuBZeBAaWilxaCTR6gQxg3ilKoyAJ/n0WGABnvbROBgEwwLjnKZ0OCVMyww0StGYBKcsDMECW/35KYwAfdgF8Q6n9nkdcYQD8WUpdILNbAeMWu2m0//r0Qd0AIFG5JsJ2uhE+SCmr4n4LhXPixiscIidJee+gUAHBVywRF/j5uVoKAdiBCIBbKigMArbC1T0AMl+msBQKhO/+ZQDAksVTNyMmnkd+1QMAKzx11M2E7M29MQCooK8MLBwUBSDr1ftp8wHff4dLn+4TJfkAZd1SJFCRFf6f8GJAKKMin64kyNT8OjoGZB6jbYfwm3AIiACw7KGsV6r+kYoYAFhxjqr9IdHxKmIBYKGNriQY2QroaRWumERR4zxxr2LiAVCVB0RfYHW8C0CkKAxK9/ZshvV2y9PkA409HhAFQJCo8QHbSX/EA6KfF7BbaZkPBAp6xd4LwFI+wU0JAM+UXyHRBSBI/+iiYylgGOuSUQAsJ+iYD5DGU1FfRV+wEAr4aAiDQuaiLMgpAPlPCzSEQaksWgHRAG5d9SRPQwgcFR3qYh4bFEUKwqAwjOMUFACGgjBITkyKkXnsg6MUZEKhPbgaSgoAlpl+VaBx6ONQBmD5m5+bvBoUnH/tUgGA+163mV0Av4iLCXE9cocmrHKZOgI8eyvUFGB2CSQIIEEB5paArSleAInnB9z3us289XBdggASFYBD91RM42mJAHKHqU16NdekeyTOxvLPkVwBEKQ37jGjBMjprMurUwEAb2irGdcFbPUv35r4r3JtAdljrWbsGqt9+nOkBsCyatlR02UCIgzNdqUIACuXTa81G4DrZ59bLQtG9nER4fo7g831HAk5+sN9sgDkW4Msry8+bS4BnB4yRdZ+pZOkVr7qcpspDNg65B1AyQUAEes7zDMnEN0KDqB8rC6z6nnBNE/SOI/f9cBq3JgCAO/Vnff6zREAjwz+u1NKclbujxx2l3Ov0xwBcOCyNYrurHKcoMis9c8w/qSAnCZ/LSg/EaPSIcv8zwvOj41v/3UycZjKE0FqLcJ/vuoF9pjRZwXXz06clIWbA4CKVS+wRwwdB9jWsxMfOIWbBYCKVc879xpYA8595JZJTar1TJIzVQXfqHX8IJdRQ+FR58RJv1uEm1cALNntK5xCrSGrYmI/5rzyQBL7kfxU3ZWrf+EIPGg8DTiPBB3loVPJ6vkUjhVeseZFh38wZ7DpsX3/hDMrDk1KrpMU7DpW0PVLib/HQIdvEqk1yH5d0TI2+VtTeVSoIPTa8oBF+NgoB+85yemjRHhhxcqxKbFK5UcKL60JvcJK/ODR/V4GxIF9mNGategffuTCdwYAODSMC/0z63CTgRMg9VcIhMXlM7zFmffNnND5O1L1llR/+qb2CqyY7hnpBinopwBaeWTYLF9mVXS1jUs9XKT844UKSwXE9fmBgW6uX9ovDnJLgXvnIOTOcqX8Tf8Pm8LvWtdS880AAAAASUVORK5CYII=', 'base64');

function sendIcon(res, buf) {
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'public, max-age=604800');
  res.send(buf);
}
app.get('/icon-192.png', (req, res) => sendIcon(res, ICON_192));
app.get('/icon-512.png', (req, res) => sendIcon(res, ICON_512));

app.get('/manifest.json', (req, res) => {
  res.json({
    name: 'Produce Lookup',
    short_name: 'Produce',
    description: 'Fast produce item code lookup for inventory counts',
    start_url: '/',
    scope: '/',
    display: 'standalone',
    orientation: 'portrait',
    background_color: '#121212',
    theme_color: '#3c9646',
    icons: [
      { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' }
    ]
  });
});

const SW_VERSION = 'v2';
app.get('/sw.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'no-cache');
  res.send(`
const CACHE = 'produce-${SW_VERSION}';
const SHELL = ['/', '/manifest.json', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET') return;
  // Never cache API calls — the app handles its own offline data.
  if (url.pathname.startsWith('/api/')) return;

  e.respondWith(
    fetch(e.request)
      .then(res => {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return res;
      })
      .catch(() => caches.match(e.request).then(r => r || caches.match('/')))
  );
});
`.trim());
});

// ---------- frontend ----------
app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.send(HTML);
});

app.listen(PORT, () => console.log('Produce lookup running on port ' + PORT));

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="theme-color" content="#3c9646">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Produce">
<link rel="manifest" href="/manifest.json">
<link rel="apple-touch-icon" href="/icon-192.png">
<link rel="icon" href="/icon-192.png">
<title>Produce Lookup</title>
<style>
  :root {
    --bg: #121212;
    --card: #1e1e1e;
    --card2: #262626;
    --border: #333;
    --text: #eee;
    --muted: #999;
    --accent: #4caf50;
    --accent-dim: #3c9646;
    --danger: #e05252;
    --warn: #d9a441;
    --safe-b: env(safe-area-inset-bottom, 0px);
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    overscroll-behavior-y: contain;
  }

  /* ---------- login ---------- */
  #login-screen { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
  .login-box { background: var(--card); padding: 30px; border-radius: 14px; width: 100%; max-width: 340px; border: 1px solid var(--border); }
  .login-box h1 { font-size: 21px; margin: 0 0 6px; text-align: center; }
  .login-sub { text-align: center; color: var(--muted); font-size: 13px; margin-bottom: 20px; }

  input, textarea, select {
    width: 100%; padding: 14px; border-radius: 10px; border: 1px solid var(--border);
    background: var(--card2); color: var(--text); font-size: 16px; margin-bottom: 10px;
  }
  button {
    width: 100%; padding: 14px; border-radius: 10px; border: none;
    background: var(--accent); color: #fff; font-size: 16px; font-weight: 600; cursor: pointer;
    min-height: 48px;
  }
  button:active { transform: scale(.985); }
  button.secondary { background: var(--card2); color: var(--text); border: 1px solid var(--border); }
  button.danger { background: var(--danger); }
  .error { color: var(--danger); font-size: 14px; margin-bottom: 10px; text-align: center; }

  /* ---------- app shell ---------- */
  #app { display: none; max-width: 700px; margin: 0 auto; padding: 14px 14px calc(20px + var(--safe-b)); }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; gap: 10px; }
  header h1 { font-size: 20px; margin: 0; }
  header button { width: auto; padding: 9px 14px; font-size: 13px; min-height: 0; }
  .whoami { color: var(--muted); font-size: 12px; margin-bottom: 14px; }
  .whoami .role-pill {
    display: inline-block; background: var(--card2); border: 1px solid var(--border);
    border-radius: 20px; padding: 2px 9px; font-size: 11px; margin-left: 6px;
  }

  #offline-banner {
    display: none; background: #3a2e1e; color: var(--warn); border: 1px solid #5a4620;
    border-radius: 10px; padding: 10px 12px; font-size: 13px; margin-bottom: 12px;
  }
  #offline-banner.on { display: block; }

  .tabs { display: flex; gap: 8px; margin-bottom: 14px; overflow-x: auto; scrollbar-width: none; }
  .tabs::-webkit-scrollbar { display: none; }
  .tab {
    padding: 10px 15px; border-radius: 10px; background: var(--card2); color: var(--muted);
    cursor: pointer; white-space: nowrap; font-size: 14px; border: 1px solid var(--border);
    user-select: none;
  }
  .tab.active { background: var(--accent); color: #fff; border-color: var(--accent); font-weight: 600; }
  .tab .badge {
    display: inline-block; background: var(--danger); color: #fff; border-radius: 10px;
    font-size: 11px; padding: 0 6px; margin-left: 6px; font-weight: 700;
  }
  .panel { display: none; }
  .panel.active { display: block; }

  /* ---------- search ---------- */
  #search-box { font-size: 19px; padding: 17px; margin-bottom: 10px; }
  .result-count { color: var(--muted); font-size: 13px; margin-bottom: 10px; }

  .item-card {
    background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 15px 16px; margin-bottom: 9px;
  }
  .item-card.discontinued { opacity: .55; }
  .item-card.exact { border-color: var(--accent-dim); }
  .list-row-top { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
  .item-name { font-size: 17px; font-weight: 600; line-height: 1.3; }
  .item-name mark { background: rgba(76,175,80,.25); color: inherit; border-radius: 3px; padding: 0 1px; }
  .item-tag { font-size: 11px; color: var(--warn); font-weight: 700; margin-left: 8px; letter-spacing: .4px; }
  .item-code {
    font-size: 27px; font-weight: 800; color: var(--accent);
    letter-spacing: 1.5px; white-space: nowrap;
    font-variant-numeric: tabular-nums;
    cursor: pointer;
  }
  .item-code:active { color: #fff; }
  .item-actions { display: flex; gap: 7px; margin-top: 11px; flex-wrap: wrap; }
  .item-actions button { width: auto; padding: 9px 13px; font-size: 13px; min-height: 0; }

  .chips { display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 4px; }
  .chip {
    background: var(--card2); border: 1px solid var(--border); border-radius: 20px;
    padding: 9px 14px; font-size: 14px; cursor: pointer; color: var(--text);
  }
  .chip:active { border-color: var(--accent); }

  .empty-state { text-align: center; padding: 30px 14px; color: var(--muted); }
  .empty-state .big { font-size: 15px; color: var(--text); margin-bottom: 6px; }
  .empty-state button { width: auto; padding: 11px 18px; font-size: 14px; margin-top: 14px; }

  /* ---------- forms / cards ---------- */
  .form-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 12px; }
  .form-card h3 { margin: 0 0 12px; font-size: 15px; }
  .form-card label { font-size: 13px; color: var(--muted); display: block; margin-bottom: 4px; }
  .msg { padding: 11px; border-radius: 9px; margin-bottom: 12px; font-size: 14px; }
  .msg.success { background: #1e3a24; color: #7fd992; }
  .msg.error-msg { background: #3a1e1e; color: #e08a8a; }
  textarea { min-height: 160px; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 14px; }
  .hint { color: var(--muted); font-size: 12px; margin-bottom: 12px; line-height: 1.55; }
  .hint code { background: var(--card2); padding: 1px 5px; border-radius: 4px; }

  /* ---------- stats ---------- */
  .stat-row { display: flex; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
  .stat-box { flex: 1; min-width: 110px; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 13px 15px; }
  .stat-label { font-size: 10px; letter-spacing: .6px; color: var(--muted); text-transform: uppercase; }
  .stat-val { font-size: 23px; font-weight: 700; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .bar-row { margin-bottom: 11px; }
  .bar-top { display: flex; justify-content: space-between; font-size: 14px; margin-bottom: 5px; gap: 10px; }
  .bar-top span:last-child { color: var(--muted); font-variant-numeric: tabular-nums; }
  .bar-track { height: 8px; background: var(--card2); border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; background: var(--accent); border-radius: 4px; }
  .bar-fill.warn { background: var(--warn); }

  .req-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px 15px; margin-bottom: 9px; }
  .code-row { display: flex; align-items: center; gap: 10px; margin-top: 9px; }
  .code-label {
    font-size: 10px; letter-spacing: .6px; text-transform: uppercase; color: var(--muted);
    background: var(--card2); border: 1px solid var(--border); border-radius: 5px;
    padding: 3px 8px; min-width: 68px; text-align: center;
  }
  .code-val {
    font-size: 17px; font-weight: 700; color: var(--accent); letter-spacing: .5px;
    cursor: pointer; font-family: ui-monospace, Menlo, Consolas, monospace;
  }
  .code-val.mgr { color: var(--warn); }
  .code-val:active { color: #fff; }
  .req-meta { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .req-note { font-size: 13px; color: var(--text); margin-top: 7px; font-style: italic; }

  .toast {
    position: fixed; left: 50%; transform: translateX(-50%);
    bottom: calc(22px + var(--safe-b));
    background: var(--accent); color: #fff; padding: 12px 20px; border-radius: 24px;
    font-size: 14px; font-weight: 600; z-index: 99; box-shadow: 0 6px 20px rgba(0,0,0,.4);
    animation: pop .18s ease-out;
  }
  @keyframes pop { from { opacity: 0; transform: translateX(-50%) translateY(8px); } }

  #install-prompt {
    display: none; background: var(--card); border: 1px solid var(--accent-dim);
    border-radius: 12px; padding: 13px 15px; margin-bottom: 13px;
    align-items: center; justify-content: space-between; gap: 12px;
  }
  #install-prompt.on { display: flex; }
  #install-prompt button { width: auto; padding: 10px 15px; font-size: 13px; min-height: 0; }
</style>
</head>
<body>

<div id="login-screen">
  <div class="login-box">
    <h1>Produce Lookup</h1>
    <div class="login-sub">Enter your store code</div>
    <div id="login-error" class="error" style="display:none"></div>
    <input type="password" id="password-input" placeholder="Code" autocomplete="current-password">
    <button onclick="login()">Log In</button>
  </div>
</div>

<div id="app">
  <header>
    <h1>Produce Lookup</h1>
    <button class="secondary" onclick="logout()">Log Out</button>
  </header>
  <div class="whoami" id="whoami"></div>

  <div id="install-prompt">
    <div style="font-size:13px">Add to your home screen for one-tap access.</div>
    <button onclick="doInstall()">Install</button>
  </div>

  <div id="offline-banner">
    Offline — showing saved codes from <span id="cache-age">earlier</span>. Lookups still work.
  </div>

  <div class="tabs" id="tabs"></div>

  <!-- SEARCH -->
  <div id="panel-search" class="panel active">
    <input type="text" id="search-box" placeholder="Type item name or code..."
           autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"
           oninput="onSearchInput()">
    <div class="result-count" id="search-count"></div>
    <div id="recent-wrap" style="display:none">
      <div class="result-count">Recent</div>
      <div class="chips" id="recent-chips"></div>
    </div>
    <div id="search-results"></div>
  </div>

  <!-- FULL LIST -->
  <div id="panel-list" class="panel">
    <div class="result-count" id="list-count"></div>
    <div id="list-results"></div>
  </div>

  <!-- REPORT MISSING (staff) -->
  <div id="panel-report" class="panel">
    <div class="form-card">
      <h3>Report a missing item</h3>
      <div class="hint">Can't find something? Send it over and it'll get added to the list.</div>
      <div id="report-msg"></div>
      <label>Item name</label>
      <input type="text" id="report-name" placeholder="e.g. Honeycrisp Apples">
      <label>Note (optional)</label>
      <input type="text" id="report-note" placeholder="e.g. new item, code on the box is 4xxxxx">
      <button onclick="submitRequest()">Send</button>
    </div>
  </div>

  <!-- ADD (admin) -->
  <div id="panel-add" class="panel">
    <div class="form-card">
      <div id="add-msg"></div>
      <label>Item name</label>
      <input type="text" id="add-name" placeholder="e.g. Broccoli Crowns">
      <label>6-digit code</label>
      <input type="text" id="add-code" inputmode="numeric" placeholder="e.g. 123456">
      <button onclick="addItem()">Add item</button>
    </div>
  </div>

  <!-- BULK (admin) -->
  <div id="panel-bulk" class="panel">
    <div class="form-card">
      <div id="bulk-msg"></div>
      <div class="hint">
        One item per line. Accepted formats:<br>
        <code>Broccoli - 123456</code> &nbsp; <code>Broccoli, 123456</code> &nbsp; <code>Broccoli 123456</code><br>
        Prefix the code with <code>D-</code> to mark discontinued. An existing name gets updated, not duplicated.
      </div>
      <textarea id="bulk-text" placeholder="Broccoli - 123456&#10;Vidalia Onions - D-356677"></textarea>
      <button onclick="bulkImport()">Import</button>
    </div>
    <div class="form-card">
      <h3>Backup</h3>
      <div class="hint">Download the full list as a CSV. Worth doing before any big import.</div>
      <a href="/api/items.csv" style="text-decoration:none">
        <button class="secondary">Download CSV backup</button>
      </a>
    </div>
  </div>

  <!-- REQUESTS (admin) -->
  <div id="panel-requests" class="panel">
    <div class="result-count" id="requests-count"></div>
    <div id="requests-list"></div>
  </div>

  <!-- USAGE (manager + admin) -->
  <div id="panel-usage" class="panel">
    <div class="result-count" id="u-scope"></div>
    <div class="stat-row">
      <div class="stat-box"><div class="stat-label">Lookups (30d)</div><div class="stat-val" id="u-total">0</div></div>
      <div class="stat-box"><div class="stat-label">Stores active</div><div class="stat-val" id="u-stores">0</div></div>
      <div class="stat-box"><div class="stat-label">Items</div><div class="stat-val" id="u-items">0</div></div>
    </div>
    <div class="form-card" id="u-store-card">
      <h3>Lookups by store</h3>
      <div id="u-by-store"></div>
    </div>
    <div class="form-card">
      <h3>Searches that found nothing</h3>
      <div class="hint">These are the gaps in your list. Each one is someone who couldn't find what they needed.</div>
      <div id="u-failed"></div>
    </div>
    <div class="form-card">
      <h3>Most searched</h3>
      <div id="u-top"></div>
    </div>
  </div>

  <!-- ACTIVITY (admin) -->
  <div id="panel-activity" class="panel">
    <div class="form-card">
      <h3>Recent changes</h3>
      <div class="hint">Every add, edit, and delete — who did it and when. Useful when a code looks wrong and you need to know what changed.</div>
      <div id="activity-list"></div>
    </div>
  </div>

  <!-- STORES (admin) -->
  <div id="panel-stores" class="panel">
    <div class="form-card">
      <h3>Store codes</h3>
      <div class="hint">
        Each store gets two codes. The <strong>staff code</strong> is lookup only. The <strong>manager code</strong> can add
        and edit items, but can't delete anything or change these codes. Tap a code to copy it.
      </div>
      <div id="stores-msg"></div>
      <div id="stores-list"></div>
    </div>
    <div class="form-card">
      <h3>Add a store</h3>
      <label>Store name</label>
      <input type="text" id="store-name" placeholder="e.g. Store 2">
      <label>Staff code</label>
      <input type="text" id="store-code" placeholder="given to everyone at that store">
      <label>Manager code</label>
      <input type="text" id="store-mgr-code" placeholder="given to that store's manager only">
      <button onclick="addStore()">Add store</button>
    </div>
  </div>
</div>

<script>
var ITEMS = [];
var ROLE = 'staff';
var STORE_NAME = '';
var editingId = null;
var isOffline = false;
var deferredPrompt = null;
var usageTimer = null;
var lastLogged = '';

var CACHE_KEY = 'produce_items_v2';
var CACHE_TS_KEY = 'produce_items_ts_v2';
var RECENT_KEY = 'produce_recent_v2';

/* ============ helpers ============ */
function esc(s) {
  return String(s === undefined || s === null ? '' : s)
    .replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
}

/* Build a JS string literal that is safe inside an HTML onclick="..." attribute.
   JSON.stringify alone emits real double quotes, which close the attribute early. */
function jsArg(v) {
  return JSON.stringify(String(v === undefined || v === null ? '' : v)).replace(/"/g, '&quot;');
}

function toast(msg) {
  var el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(function () { el.remove(); }, 1600);
}

function normalize(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9 ]/g, ' ').replace(/\\s+/g, ' ').trim();
}

function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  var prev = [], i, j;
  for (j = 0; j <= b.length; j++) prev[j] = j;
  for (i = 1; i <= a.length; i++) {
    var cur = [i];
    for (j = 1; j <= b.length; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1)
      );
    }
    prev = cur;
  }
  return prev[b.length];
}

function isSubsequence(needle, hay) {
  var i = 0;
  for (var j = 0; j < hay.length && i < needle.length; j++) {
    if (hay.charAt(j) === needle.charAt(i)) i++;
  }
  return i === needle.length;
}

/* Ranked fuzzy match. Higher score = better. 0 = no match. */
function scoreItem(item, rawQuery) {
  var q = normalize(rawQuery);
  if (!q) return 0;

  // Numeric query: match against the code
  if (/^[0-9]+$/.test(q)) {
    var code = String(item.code);
    if (code === q) return 2000;
    if (code.indexOf(q) === 0) return 1500;
    if (code.indexOf(q) !== -1) return 1200;
    return 0;
  }

  var n = normalize(item.name);
  if (n === q) return 1000;
  if (n.indexOf(q) === 0) return 900 - n.length;

  var words = n.split(' ');
  var i;
  for (i = 0; i < words.length; i++) {
    if (words[i].indexOf(q) === 0) return 800 - n.length;
  }
  if (n.indexOf(q) !== -1) return 700 - n.length;

  // All query tokens appear somewhere ("gold apple" -> "Golden Apples")
  var qt = q.split(' ');
  var allIn = true;
  for (i = 0; i < qt.length; i++) {
    if (n.indexOf(qt[i]) === -1) { allIn = false; break; }
  }
  if (allIn) return 600 - n.length;

  // Every token is a near-prefix of some word (handles plurals/truncation)
  var tokenHits = 0;
  for (i = 0; i < qt.length; i++) {
    for (var w = 0; w < words.length; w++) {
      if (words[w].indexOf(qt[i]) === 0 || qt[i].indexOf(words[w]) === 0) { tokenHits++; break; }
    }
  }
  if (tokenHits === qt.length) return 550 - n.length;

  // Typo tolerance on whole words
  if (q.length >= 4) {
    var best = 99;
    for (i = 0; i < words.length; i++) {
      var d = levenshtein(words[i], q);
      if (d < best) best = d;
    }
    var tol = q.length >= 7 ? 2 : 1;
    if (best <= tol) return 400 - best * 20 - n.length * 0.1;
  }

  // Loose: letters appear in order ("brccl" -> "broccoli")
  if (q.length >= 4 && isSubsequence(q.replace(/ /g, ''), n.replace(/ /g, ''))) {
    return 250 - n.length * 0.1;
  }

  return 0;
}

function searchItems(query) {
  var scored = [];
  for (var i = 0; i < ITEMS.length; i++) {
    var s = scoreItem(ITEMS[i], query);
    if (s > 0) {
      if (ITEMS[i].discontinued) s -= 250; // push discontinued down, don't hide
      scored.push({ item: ITEMS[i], score: s });
    }
  }
  scored.sort(function (a, b) {
    if (b.score !== a.score) return b.score - a.score;
    return a.item.name.localeCompare(b.item.name);
  });
  return scored.slice(0, 40);
}

function highlight(name, query) {
  var q = normalize(query);
  if (!q || /^[0-9]+$/.test(q)) return esc(name);
  var nl = name.toLowerCase();
  var idx = nl.indexOf(q);
  if (idx === -1) return esc(name);
  return esc(name.slice(0, idx)) + '<mark>' + esc(name.slice(idx, idx + q.length)) + '</mark>' + esc(name.slice(idx + q.length));
}

/* ============ recent lookups ============ */
function getRecent() {
  try { return JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); }
  catch (e) { return []; }
}
function pushRecent(name) {
  try {
    var r = getRecent().filter(function (x) { return x !== name; });
    r.unshift(name);
    localStorage.setItem(RECENT_KEY, JSON.stringify(r.slice(0, 8)));
  } catch (e) {}
}
function renderRecent() {
  var r = getRecent();
  var wrap = document.getElementById('recent-wrap');
  if (!r.length) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'block';
  document.getElementById('recent-chips').innerHTML = r.map(function (n) {
    return '<div class="chip" onclick="useRecent(' + jsArg(n) + ')">' + esc(n) + '</div>';
  }).join('');
}
function useRecent(name) {
  document.getElementById('search-box').value = name;
  onSearchInput();
}

/* ============ offline cache ============ */
function cacheItems(items) {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify(items));
    localStorage.setItem(CACHE_TS_KEY, String(Date.now()));
  } catch (e) {}
}
function readCachedItems() {
  try {
    var raw = localStorage.getItem(CACHE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) { return null; }
}
function cacheAgeText() {
  var ts = Number(localStorage.getItem(CACHE_TS_KEY) || 0);
  if (!ts) return 'earlier';
  var mins = Math.round((Date.now() - ts) / 60000);
  if (mins < 2) return 'just now';
  if (mins < 60) return mins + ' min ago';
  var hrs = Math.round(mins / 60);
  if (hrs < 24) return hrs + (hrs === 1 ? ' hour ago' : ' hours ago');
  var days = Math.round(hrs / 24);
  return days + (days === 1 ? ' day ago' : ' days ago');
}
function setOffline(flag) {
  isOffline = flag;
  document.getElementById('offline-banner').classList.toggle('on', flag);
  if (flag) document.getElementById('cache-age').textContent = cacheAgeText();
}

/* ============ auth ============ */
async function checkSession() {
  try {
    var res = await fetch('/api/session');
    var data = await res.json();
    if (data.authed) {
      ROLE = data.role;
      STORE_NAME = data.storeName;
      showApp();
    }
  } catch (e) {
    // Offline with a cached list: let them in read-only.
    var cached = readCachedItems();
    if (cached && cached.length) {
      ITEMS = cached;
      ROLE = 'staff';
      STORE_NAME = 'Offline';
      showApp(true);
      setOffline(true);
    }
  }
}

async function login() {
  var password = document.getElementById('password-input').value;
  var errBox = document.getElementById('login-error');
  try {
    var res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: password })
    });
    if (res.ok) {
      var data = await res.json();
      ROLE = data.role;
      STORE_NAME = data.storeName;
      errBox.style.display = 'none';
      showApp();
    } else {
      errBox.textContent = 'Wrong code';
      errBox.style.display = 'block';
    }
  } catch (e) {
    errBox.textContent = 'No connection';
    errBox.style.display = 'block';
  }
}

async function logout() {
  try { await fetch('/api/logout', { method: 'POST' }); } catch (e) {}
  document.getElementById('app').style.display = 'none';
  document.getElementById('login-screen').style.display = 'flex';
  document.getElementById('password-input').value = '';
}

/* ============ tabs ============ */
var TABS_STAFF = [
  { id: 'search', label: 'Search' },
  { id: 'list',   label: 'Full List' },
  { id: 'report', label: 'Report Missing' }
];
var TABS_MANAGER = [
  { id: 'search',   label: 'Search' },
  { id: 'list',     label: 'Full List' },
  { id: 'add',      label: 'Add' },
  { id: 'requests', label: 'Requests' },
  { id: 'usage',    label: 'Usage' }
];
var TABS_ADMIN = [
  { id: 'search',   label: 'Search' },
  { id: 'list',     label: 'Full List' },
  { id: 'add',      label: 'Add' },
  { id: 'bulk',     label: 'Bulk / Backup' },
  { id: 'requests', label: 'Requests' },
  { id: 'usage',    label: 'Usage' },
  { id: 'activity', label: 'Activity' },
  { id: 'stores',   label: 'Stores' }
];

function isEditor() { return ROLE === 'admin' || ROLE === 'manager'; }
function roleLabel() {
  if (ROLE === 'admin') return 'Admin';
  if (ROLE === 'manager') return 'Manager';
  return 'Staff';
}

function renderTabs(openRequests) {
  var tabs = ROLE === 'admin' ? TABS_ADMIN : (ROLE === 'manager' ? TABS_MANAGER : TABS_STAFF);
  document.getElementById('tabs').innerHTML = tabs.map(function (t, idx) {
    var badge = (t.id === 'requests' && openRequests) ? '<span class="badge">' + openRequests + '</span>' : '';
    return '<div class="tab' + (idx === 0 ? ' active' : '') + '" data-tab="' + t.id +
           '" onclick="switchTab(\\'' + t.id + '\\')">' + t.label + badge + '</div>';
  }).join('');
}

function switchTab(tab) {
  var all = document.querySelectorAll('.tab');
  for (var i = 0; i < all.length; i++) all[i].classList.toggle('active', all[i].dataset.tab === tab);
  var panels = document.querySelectorAll('.panel');
  for (var j = 0; j < panels.length; j++) panels[j].classList.remove('active');
  var p = document.getElementById('panel-' + tab);
  if (p) p.classList.add('active');
  if (tab === 'search') document.getElementById('search-box').focus();
  if (tab === 'usage') loadUsageStats();
  if (tab === 'requests') loadRequests();
  if (tab === 'stores') loadStores();
  if (tab === 'activity') loadActivity();
}

/* ============ app boot ============ */
async function showApp(skipFetch) {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display = 'block';

  document.getElementById('whoami').innerHTML =
    esc(STORE_NAME) + '<span class="role-pill">' + roleLabel() + '</span>';

  renderTabs(0);

  // Render instantly from cache, then refresh from the network.
  var cached = readCachedItems();
  if (cached && cached.length && !ITEMS.length) {
    ITEMS = cached;
    renderSearch();
    renderList();
  }

  if (!skipFetch) await loadItems();
  renderSearch();
  renderList();
  renderRecent();

  if (isEditor()) loadRequests(true);
}

async function loadItems() {
  try {
    var res = await fetch('/api/items');
    if (!res.ok) throw new Error('bad status');
    ITEMS = await res.json();
    cacheItems(ITEMS);
    setOffline(false);
  } catch (e) {
    var cached = readCachedItems();
    if (cached) { ITEMS = cached; setOffline(true); }
  }
}

/* ============ search ============ */
function onSearchInput() {
  renderSearch();
  var q = document.getElementById('search-box').value.trim();
  clearTimeout(usageTimer);
  if (q.length >= 2 && !isOffline) {
    usageTimer = setTimeout(function () {
      if (q === lastLogged) return;
      lastLogged = q;
      var found = searchItems(q).length > 0;
      fetch('/api/usage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q, found: found })
      }).catch(function () {});
    }, 1200);
  }
}

function renderSearch() {
  var q = document.getElementById('search-box').value.trim();
  var countEl = document.getElementById('search-count');
  var resEl = document.getElementById('search-results');

  if (!q) {
    countEl.textContent = ITEMS.length + ' items available';
    resEl.innerHTML = '';
    renderRecent();
    return;
  }

  document.getElementById('recent-wrap').style.display = 'none';
  var results = searchItems(q);

  if (!results.length) {
    countEl.textContent = '';
    resEl.innerHTML =
      '<div class="empty-state">' +
        '<div class="big">No match for "' + esc(q) + '"</div>' +
        '<div>Check the spelling, or try a shorter word.</div>' +
        (isEditor()
          ? '<button class="secondary" onclick="prefillAdd()">Add this item</button>'
          : '<button class="secondary" onclick="prefillReport()">Report this item</button>') +
      '</div>';
    return;
  }

  countEl.textContent = results.length + (results.length === 1 ? ' match' : ' matches');
  resEl.innerHTML = results.map(function (r, idx) {
    return itemCard(r.item, q, idx === 0 && r.score >= 700);
  }).join('');
}

function renderList() {
  var sorted = ITEMS.slice().sort(function (a, b) { return a.name.localeCompare(b.name); });
  document.getElementById('list-count').textContent = sorted.length + ' items';
  document.getElementById('list-results').innerHTML = sorted.map(function (i) {
    return itemCard(i, '', false);
  }).join('');
}

function itemCard(i, query, isTop) {
  var cls = 'item-card' + (i.discontinued ? ' discontinued' : '') + (isTop ? ' exact' : '');
  var tag = i.discontinued ? '<span class="item-tag">DISCONTINUED</span>' : '';
  var nameHtml = query ? highlight(i.name, query) : esc(i.name);

  var actions = '';
  if (isEditor()) {
    var toggleLabel = i.discontinued ? 'Mark Active' : 'Mark Discontinued';
    // Delete is admin-only — managers get Mark Discontinued instead.
    var delBtn = ROLE === 'admin'
      ? '<button class="danger" onclick="deleteItem(' + i.id + ')">Delete</button>'
      : '';
    actions =
      '<div class="item-actions">' +
        '<button class="secondary" onclick="startEdit(' + i.id + ')">Edit</button>' +
        '<button class="secondary" onclick="toggleDiscontinued(' + i.id + ',' + (!i.discontinued) + ')">' + toggleLabel + '</button>' +
        delBtn +
      '</div>';
  }

  return '<div class="' + cls + '">' +
    '<div class="list-row-top">' +
      '<div><span class="item-name">' + nameHtml + '</span>' + tag + '</div>' +
      '<div class="item-code" onclick="copyCode(' + jsArg(i.code) + ',' + jsArg(i.name) + ')">' +
        esc(i.code) +
      '</div>' +
    '</div>' + actions +
  '</div>';
}

function copyCode(code, name) {
  pushRecent(name);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(code).then(
      function () { toast('Copied ' + code); },
      function () { toast(code); }
    );
  } else {
    toast(code);
  }
}

function prefillReport() {
  document.getElementById('report-name').value = document.getElementById('search-box').value.trim();
  switchTab('report');
}
function prefillAdd() {
  document.getElementById('add-name').value = document.getElementById('search-box').value.trim();
  editingId = null;
  switchTab('add');
}

/* ============ admin: items ============ */
function startEdit(id) {
  var item = null;
  for (var i = 0; i < ITEMS.length; i++) if (ITEMS[i].id === id) item = ITEMS[i];
  if (!item) return;
  editingId = id;
  document.getElementById('add-name').value = item.name;
  document.getElementById('add-code').value = item.code;
  switchTab('add');
  document.getElementById('add-msg').innerHTML =
    '<div class="msg success">Editing "' + esc(item.name) + '" — submit to save.</div>';
}

async function addItem() {
  var name = document.getElementById('add-name').value.trim();
  var code = document.getElementById('add-code').value.trim();
  var msgBox = document.getElementById('add-msg');
  if (!name || !code) {
    msgBox.innerHTML = '<div class="msg error-msg">Name and code are both required.</div>';
    return;
  }
  var res;
  if (editingId) {
    res = await fetch('/api/items/' + editingId, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name, code: code })
    });
  } else {
    res = await fetch('/api/items', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name, code: code })
    });
  }
  if (res.ok) {
    msgBox.innerHTML = '<div class="msg success">Saved.</div>';
    document.getElementById('add-name').value = '';
    document.getElementById('add-code').value = '';
    editingId = null;
    await loadItems(); renderSearch(); renderList();
  } else {
    var err = await res.json().catch(function () { return {}; });
    msgBox.innerHTML = '<div class="msg error-msg">' + esc(err.error || 'Error saving item') + '</div>';
  }
}

async function toggleDiscontinued(id, value) {
  await fetch('/api/items/' + id, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ discontinued: value })
  });
  await loadItems(); renderSearch(); renderList();
}

async function deleteItem(id) {
  var item = null;
  for (var i = 0; i < ITEMS.length; i++) if (ITEMS[i].id === id) item = ITEMS[i];
  var label = item ? '"' + item.name + '"' : 'this item';
  if (!confirm('Delete ' + label + ' permanently?\\n\\nThis removes it for every store. "Mark Discontinued" is usually the better choice.')) return;
  await fetch('/api/items/' + id, { method: 'DELETE' });
  await loadItems(); renderSearch(); renderList();
  toast('Deleted');
}

async function bulkImport() {
  var text = document.getElementById('bulk-text').value;
  var msgBox = document.getElementById('bulk-msg');
  if (!text.trim()) return;
  var res = await fetch('/api/bulk-import', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: text })
  });
  var data = await res.json().catch(function () { return {}; });
  if (res.ok) {
    msgBox.innerHTML = '<div class="msg success">Added ' + data.added + ', updated ' + data.updated +
      ', skipped ' + data.skipped + '. Total: ' + data.total + '.</div>';
    document.getElementById('bulk-text').value = '';
    await loadItems(); renderSearch(); renderList();
  } else {
    msgBox.innerHTML = '<div class="msg error-msg">' + esc(data.error || 'Import failed') + '</div>';
  }
}

/* ============ requests ============ */
async function submitRequest() {
  var name = document.getElementById('report-name').value.trim();
  var note = document.getElementById('report-note').value.trim();
  var msgBox = document.getElementById('report-msg');
  if (!name) {
    msgBox.innerHTML = '<div class="msg error-msg">Enter the item name.</div>';
    return;
  }
  try {
    var res = await fetch('/api/requests', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name, note: note })
    });
    if (res.ok) {
      msgBox.innerHTML = '<div class="msg success">Sent. Thanks — it\\'ll get added soon.</div>';
      document.getElementById('report-name').value = '';
      document.getElementById('report-note').value = '';
    } else {
      msgBox.innerHTML = '<div class="msg error-msg">Could not send.</div>';
    }
  } catch (e) {
    msgBox.innerHTML = '<div class="msg error-msg">No connection — try again when you have signal.</div>';
  }
}

async function loadRequests(badgeOnly) {
  if (!isEditor()) return;
  try {
    var res = await fetch('/api/requests');
    var list = await res.json();
    renderTabs(list.length);
    if (badgeOnly) return;

    document.getElementById('requests-count').textContent =
      list.length ? list.length + ' open' : '';
    document.getElementById('requests-list').innerHTML = list.length
      ? list.map(function (r) {
          return '<div class="req-card">' +
            '<div class="list-row-top">' +
              '<div><span class="item-name">' + esc(r.name) + '</span></div>' +
            '</div>' +
            (r.note ? '<div class="req-note">"' + esc(r.note) + '"</div>' : '') +
            '<div class="req-meta">' + esc(r.storeName) + ' &middot; ' + new Date(r.ts).toLocaleDateString() + '</div>' +
            '<div class="item-actions">' +
              '<button class="secondary" onclick="requestToAdd(' + jsArg(r.id) + ',' + jsArg(r.name) + ')">Add item</button>' +
              '<button class="secondary" onclick="dismissRequest(' + jsArg(r.id) + ')">Dismiss</button>' +
            '</div>' +
          '</div>';
        }).join('')
      : '<div class="empty-state">No open requests.</div>';
  } catch (e) {}
}

function requestToAdd(id, name) {
  document.getElementById('add-name').value = name;
  document.getElementById('add-code').value = '';
  editingId = null;
  document.getElementById('add-msg').innerHTML =
    '<div class="msg success">From a store request — add the code and save, then dismiss the request.</div>';
  switchTab('add');
}

async function dismissRequest(id) {
  await fetch('/api/requests/' + id, { method: 'DELETE' });
  loadRequests();
}

/* ============ usage stats ============ */
async function loadUsageStats() {
  if (!isEditor()) return;
  try {
    var res = await fetch('/api/usage/summary?days=30');
    var d = await res.json();

    document.getElementById('u-scope').textContent = d.scopeName + ' — last 30 days';
    document.getElementById('u-total').textContent = d.total;
    document.getElementById('u-stores').textContent = d.byStore.length;
    document.getElementById('u-items').textContent = ITEMS.length;

    // A manager only ever sees their own store, so the breakdown is noise for them.
    document.getElementById('u-store-card').style.display = d.scoped ? 'none' : 'block';
    document.getElementById('u-by-store').innerHTML = bars(d.byStore, false) ||
      '<div class="hint" style="margin:0">No lookups recorded yet.</div>';
    document.getElementById('u-failed').innerHTML = bars(d.failedQueries, true) ||
      '<div class="hint" style="margin:0">Nothing came up empty. Your list is covering what people search for.</div>';
    document.getElementById('u-top').innerHTML = bars(d.topQueries, false) ||
      '<div class="hint" style="margin:0">No searches recorded yet.</div>';
  } catch (e) {}
}

function bars(entries, warn) {
  if (!entries || !entries.length) return '';
  var max = entries[0][1] || 1;
  return entries.map(function (e) {
    return '<div class="bar-row">' +
      '<div class="bar-top"><span>' + esc(e[0]) + '</span><span>' + e[1] + '</span></div>' +
      '<div class="bar-track"><div class="bar-fill' + (warn ? ' warn' : '') +
        '" style="width:' + (e[1] / max * 100) + '%"></div></div>' +
    '</div>';
  }).join('');
}

/* ============ activity log ============ */
async function loadActivity() {
  if (ROLE !== 'admin') return;
  try {
    var res = await fetch('/api/audit');
    var rows = await res.json();
    document.getElementById('activity-list').innerHTML = rows.length
      ? rows.map(function (r) {
          var when = new Date(r.ts);
          var stamp = when.toLocaleDateString() + ' ' +
            when.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
          return '<div class="req-card">' +
            '<div><span class="item-name" style="font-size:15px">' +
              esc(r.actor) + ' ' + esc(r.action) + '</span></div>' +
            '<div class="req-note" style="font-style:normal">' + esc(r.detail) + '</div>' +
            '<div class="req-meta">' + esc(stamp) + ' &middot; ' + esc(r.role) + '</div>' +
          '</div>';
        }).join('')
      : '<div class="hint" style="margin:0">No changes recorded yet.</div>';
  } catch (e) {}
}

/* ============ stores ============ */
async function loadStores() {
  if (ROLE !== 'admin') return;
  try {
    var res = await fetch('/api/stores');
    var stores = await res.json();
    document.getElementById('stores-list').innerHTML = stores.length
      ? stores.map(function (s) {
          return '<div class="req-card">' +
            '<div><span class="item-name">' + esc(s.name) + '</span></div>' +
            '<div class="code-row">' +
              '<span class="code-label">Staff</span>' +
              '<span class="code-val" onclick="copyCode(' + jsArg(s.staffCode || '') + ',' +
                jsArg(s.name) + ')">' + esc(s.staffCode || '—') + '</span>' +
            '</div>' +
            '<div class="code-row">' +
              '<span class="code-label">Manager</span>' +
              '<span class="code-val mgr" onclick="copyCode(' + jsArg(s.managerCode || '') + ',' +
                jsArg(s.name) + ')">' + esc(s.managerCode || 'not set') + '</span>' +
            '</div>' +
            '<div class="item-actions">' +
              '<button class="secondary" onclick="editStore(' + jsArg(s.id) + ')">Change codes</button>' +
              '<button class="danger" onclick="deleteStore(' + jsArg(s.id) + ',' + jsArg(s.name) + ')">Remove</button>' +
            '</div>' +
          '</div>';
        }).join('')
      : '<div class="hint" style="margin:0">No stores yet.</div>';
  } catch (e) {}
}

async function editStore(id) {
  var res = await fetch('/api/stores');
  var stores = await res.json();
  var s = null;
  for (var i = 0; i < stores.length; i++) if (stores[i].id === id) s = stores[i];
  if (!s) return;

  var newStaff = prompt('Staff code for "' + s.name + '"\\n(lookup only)', s.staffCode || '');
  if (newStaff === null) return;
  var newMgr = prompt('Manager code for "' + s.name + '"\\n(can add and edit items)', s.managerCode || '');
  if (newMgr === null) return;

  var put = await fetch('/api/stores/' + id, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ staffCode: newStaff.trim(), managerCode: newMgr.trim() })
  });
  var data = await put.json().catch(function () { return {}; });
  var msgBox = document.getElementById('stores-msg');
  if (put.ok) {
    msgBox.innerHTML = '<div class="msg success">Codes updated. Anyone on the old codes is now locked out.</div>';
    loadStores();
  } else {
    msgBox.innerHTML = '<div class="msg error-msg">' + esc(data.error || 'Could not update') + '</div>';
  }
}

async function addStore() {
  var name = document.getElementById('store-name').value.trim();
  var code = document.getElementById('store-code').value.trim();
  var mgrCode = document.getElementById('store-mgr-code').value.trim();
  var msgBox = document.getElementById('stores-msg');
  if (!name || !code || !mgrCode) {
    msgBox.innerHTML = '<div class="msg error-msg">Store name and both codes are required.</div>';
    return;
  }
  var res = await fetch('/api/stores', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: name, staffCode: code, managerCode: mgrCode })
  });
  var data = await res.json().catch(function () { return {}; });
  if (res.ok) {
    msgBox.innerHTML = '<div class="msg success">Added.</div>';
    document.getElementById('store-name').value = '';
    document.getElementById('store-code').value = '';
    document.getElementById('store-mgr-code').value = '';
    loadStores();
  } else {
    msgBox.innerHTML = '<div class="msg error-msg">' + esc(data.error || 'Could not add store') + '</div>';
  }
}

async function deleteStore(id, name) {
  if (!confirm('Remove "' + name + '"?\\n\\nAnyone using that code will be locked out.')) return;
  await fetch('/api/stores/' + id, { method: 'DELETE' });
  loadStores();
}

/* ============ PWA install ============ */
window.addEventListener('beforeinstallprompt', function (e) {
  e.preventDefault();
  deferredPrompt = e;
  document.getElementById('install-prompt').classList.add('on');
});

function doInstall() {
  if (!deferredPrompt) return;
  deferredPrompt.prompt();
  deferredPrompt.userChoice.then(function () {
    deferredPrompt = null;
    document.getElementById('install-prompt').classList.remove('on');
  });
}

window.addEventListener('appinstalled', function () {
  document.getElementById('install-prompt').classList.remove('on');
});

if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('/sw.js').catch(function () {});
  });
}

window.addEventListener('online', function () { setOffline(false); loadItems().then(renderSearch); });
window.addEventListener('offline', function () { setOffline(true); });

document.getElementById('password-input').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') login();
});

checkSession();
</script>
</body>
</html>`;
