// Dexter's Namespace Server
// Railway-ready Express server — namespace storage, CORS, admin panel

'use strict';

const express      = require('express');
const fs           = require('fs');
const path         = require('path');
const cookieParser = require('cookie-parser');

const app = express();

const DATA_DIR       = process.env.DATA_DIR       || '/data';
const API_KEY        = process.env.API_KEY        || 'changeme';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const PORT           = process.env.PORT           || 3000;

// In-memory session tokens (single user, so this is fine)
const sessions = new Set();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ── CORS ─────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Data dir ──────────────────────────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function safeName(name) {
  // Prevent path traversal — only allow safe chars
  return String(name).replace(/[^a-zA-Z0-9_\-]/g, '_');
}

function nsFilePath(name) {
  return path.join(DATA_DIR, safeName(name) + '.json');
}

function readNS(name) {
  try   { return JSON.parse(fs.readFileSync(nsFilePath(name), 'utf8')); }
  catch { return {}; }
}

function writeNS(name, data) {
  fs.writeFileSync(nsFilePath(name), JSON.stringify(data, null, 2));
}

function listNS() {
  try {
    return fs.readdirSync(DATA_DIR)
      .filter(f => f.endsWith('.json'))
      .map(f => f.slice(0, -5));
  } catch { return []; }
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireApiKey(req, res, next) {
  if (req.headers['x-api-key'] !== API_KEY)
    return res.status(401).json({ error: 'Invalid API key' });
  next();
}

function requireAdmin(req, res, next) {
  if (!sessions.has(req.cookies.admin_token))
    return res.redirect('/admin/login');
  next();
}

// ── Public namespace API (read = open, write = API key) ───────────────────────

// GET /ns/:name  →  full namespace JSON
app.get('/ns/:name', (req, res) => {
  res.json(readNS(req.params.name));
});

// POST /ns/:name  body: { key, value }  →  set a key
app.post('/ns/:name', requireApiKey, (req, res) => {
  const { key, value } = req.body;
  if (!key) return res.status(400).json({ error: 'key is required' });
  const data = readNS(req.params.name);
  data[String(key)] = String(value ?? '');
  writeNS(req.params.name, data);
  res.json({ ok: true });
});

// DELETE /ns/:name  body: { key }  →  delete a key
app.delete('/ns/:name', requireApiKey, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key is required' });
  const data = readNS(req.params.name);
  delete data[String(key)];
  writeNS(req.params.name, data);
  res.json({ ok: true });
});

// ── Admin login ───────────────────────────────────────────────────────────────
app.get('/admin/login', (req, res) => {
  res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Admin Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI",system-ui,sans-serif;background:#0f0f13;color:#e0e0e0;
  height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1a1a24;border:1px solid #2a2a3a;border-radius:14px;padding:36px 40px;
  width:340px;display:flex;flex-direction:column;gap:20px}
h1{font-size:18px;font-weight:700;color:#fff}
.sub{font-size:12px;color:#555;margin-top:-14px}
input{width:100%;background:#0f0f18;border:1px solid #2a2a3a;color:#ddd;
  padding:10px 12px;border-radius:8px;font-size:14px;outline:none}
input:focus{border-color:#FF1493}
button{background:#FF1493;color:#fff;border:none;padding:11px;border-radius:8px;
  cursor:pointer;font-size:14px;font-weight:600;transition:background .15s}
button:hover{background:#e0127e}
.err{color:#ff4466;font-size:12px;display:none}
.err.show{display:block}
</style></head><body>
<div class="card">
  <h1>🗄 Namespace Admin</h1>
  <p class="sub">Dexter's Cloud Storage</p>
  ${req.query.err ? '<p class="err show">Wrong password, try again.</p>' : ''}
  <form method="POST" action="/admin/login">
    <div style="display:flex;flex-direction:column;gap:12px">
      <input type="password" name="password" placeholder="Admin password..." autofocus>
      <button type="submit">Sign in</button>
    </div>
  </form>
</div></body></html>`);
});

app.post('/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    const token = Math.random().toString(36).slice(2) + Date.now().toString(36);
    sessions.add(token);
    res.cookie('admin_token', token, { httpOnly: true, sameSite: 'lax' });
    return res.redirect('/admin');
  }
  res.redirect('/admin/login?err=1');
});

app.post('/admin/logout', requireAdmin, (req, res) => {
  sessions.delete(req.cookies.admin_token);
  res.clearCookie('admin_token');
  res.redirect('/admin/login');
});

// ── Admin API (cookie auth) ───────────────────────────────────────────────────

app.get('/admin/api/namespaces', requireAdmin, (req, res) => {
  res.json(listNS());
});

app.post('/admin/api/namespaces', requireAdmin, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const p = nsFilePath(name);
  if (!fs.existsSync(p)) writeNS(name, {});
  res.json({ ok: true, name: safeName(name) });
});

app.delete('/admin/api/namespaces/:name', requireAdmin, (req, res) => {
  try { fs.unlinkSync(nsFilePath(req.params.name)); } catch {}
  res.json({ ok: true });
});

app.get('/admin/api/ns/:name', requireAdmin, (req, res) => {
  res.json(readNS(req.params.name));
});

app.post('/admin/api/ns/:name', requireAdmin, (req, res) => {
  const { key, value } = req.body;
  if (!key) return res.status(400).json({ error: 'key required' });
  const data = readNS(req.params.name);
  data[String(key)] = String(value ?? '');
  writeNS(req.params.name, data);
  res.json({ ok: true });
});

app.delete('/admin/api/ns/:name/key', requireAdmin, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key required' });
  const data = readNS(req.params.name);
  delete data[String(key)];
  writeNS(req.params.name, data);
  res.json({ ok: true });
});

// Delete all keys in a folder (prefix/)
app.delete('/admin/api/ns/:name/folder', requireAdmin, (req, res) => {
  const { folder } = req.body;
  if (!folder) return res.status(400).json({ error: 'folder required' });
  const data    = readNS(req.params.name);
  const prefix  = folder + '/';
  Object.keys(data).forEach(k => { if (k.startsWith(prefix)) delete data[k]; });
  writeNS(req.params.name, data);
  res.json({ ok: true });
});

// ── Admin panel ───────────────────────────────────────────────────────────────
app.get('/admin', requireAdmin, (req, res) => {
  res.send(buildAdminHTML());
});

function buildAdminHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Namespace Admin</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI",system-ui,sans-serif;background:#0f0f13;color:#e0e0e0;
  height:100vh;display:flex;flex-direction:column;overflow:hidden;font-size:13px}
#titlebar{background:#1a1a24;border-bottom:1px solid #2a2a3a;padding:10px 16px;
  display:flex;align-items:center;gap:10px;flex-shrink:0}
#titlebar h1{font-size:14px;font-weight:600;color:#fff}
.pill{background:#FF1493;color:#fff;font-size:10px;font-weight:700;padding:2px 8px;
  border-radius:99px}
.spacer{flex:1}
.hbtn{background:none;border:1px solid #333;color:#aaa;padding:4px 10px;border-radius:6px;
  cursor:pointer;font-size:12px;transition:all .15s}
.hbtn:hover{border-color:#FF1493;color:#FF1493}
#main{display:flex;flex:1;overflow:hidden}

/* Sidebar */
#sidebar{width:210px;background:#111118;border-right:1px solid #1e1e2e;
  display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
#sb-hdr{padding:10px 12px 6px;font-size:10px;font-weight:700;letter-spacing:.08em;
  color:#666;text-transform:uppercase;display:flex;align-items:center;gap:6px}
#sb-hdr button{margin-left:auto;background:#FF14931a;border:1px solid #FF149344;
  color:#FF1493;padding:2px 8px;border-radius:6px;cursor:pointer;font-size:11px}
#sb-hdr button:hover{background:#FF14932a}
#ns-list{flex:1;overflow-y:auto;padding:4px}
.ns-item{padding:7px 10px;border-radius:6px;cursor:pointer;color:#bbb;font-size:12px;
  transition:background .1s;display:flex;align-items:center;gap:6px;user-select:none}
.ns-item:hover{background:#1a1a2a;color:#fff}
.ns-item.active{background:#FF14931a;color:#FF1493;font-weight:600}
.ns-item .ns-del{margin-left:auto;opacity:0;font-size:10px;color:#ff4466;padding:1px 5px;
  border-radius:4px;border:none;background:none;cursor:pointer}
.ns-item:hover .ns-del{opacity:1}

/* Middle — folder/key list */
#middle{width:220px;border-right:1px solid #1e1e2e;display:flex;flex-direction:column;
  background:#0f0f15;overflow:hidden}
#mid-hdr{padding:10px 12px 6px;font-size:10px;font-weight:700;letter-spacing:.08em;
  color:#666;text-transform:uppercase;display:flex;align-items:center;gap:6px;flex-shrink:0}
#mid-hdr button{margin-left:auto;background:#1e1e2e;border:1px solid #2e2e42;
  color:#ccc;padding:2px 8px;border-radius:6px;cursor:pointer;font-size:11px}
#mid-hdr button:hover{border-color:#FF1493;color:#FF1493}
#folder-list{flex:1;overflow-y:auto;padding:4px}
.folder-item{padding:6px 10px;border-radius:6px;cursor:pointer;color:#bbb;font-size:12px;
  transition:background .1s;display:flex;align-items:center;gap:6px;user-select:none}
.folder-item:hover{background:#1a1a2a;color:#fff}
.folder-item.active{background:#f0a0301a;color:#f0a030;font-weight:600}
.folder-item .f-del{margin-left:auto;opacity:0;font-size:10px;color:#ff4466;padding:1px 5px;
  border-radius:4px;border:none;background:none;cursor:pointer}
.folder-item:hover .f-del{opacity:1}
.key-item{padding:5px 10px 5px 24px;border-radius:6px;cursor:pointer;color:#888;font-size:11px;
  transition:background .1s;display:flex;align-items:center;gap:6px}
.key-item:hover{background:#1a1a2a;color:#ccc}
.key-item.active{background:#1e1e2e;color:#ddd}
.key-item .k-del{margin-left:auto;opacity:0;font-size:10px;color:#ff4466;padding:1px 5px;
  border-radius:4px;border:none;background:none;cursor:pointer}
.key-item:hover .k-del{opacity:1}

/* Editor */
#editor{flex:1;display:flex;flex-direction:column;overflow:hidden;background:#0f0f13}
#ed-hdr{padding:12px 16px;border-bottom:1px solid #1a1a28;display:flex;align-items:center;
  gap:8px;flex-shrink:0}
#ed-hdr h2{font-size:13px;color:#fff;font-weight:600;flex:1}
#ed-body{flex:1;overflow-y:auto;padding:20px;display:flex;flex-direction:column;gap:16px}
.ed-empty{color:#333;font-size:13px;text-align:center;margin:auto}
.field label{display:block;font-size:10px;font-weight:700;letter-spacing:.06em;
  color:#555;text-transform:uppercase;margin-bottom:6px}
.field input,.field textarea{width:100%;background:#16161f;border:1px solid #2a2a3a;
  color:#ddd;padding:9px 11px;border-radius:8px;font-size:13px;outline:none;
  transition:border-color .15s}
.field input:focus,.field textarea:focus{border-color:#FF1493}
.field textarea{min-height:100px;resize:vertical;font-family:inherit;line-height:1.5}
.field .hint{font-size:10px;color:#444;margin-top:4px}
.field .hint b{color:#f0a030}.field .hint code{background:#1e1e2e;padding:1px 4px;border-radius:3px;color:#f0a030}
.img-preview{max-width:100%;max-height:140px;border-radius:6px;margin-top:8px;
  display:none;border:1px solid #2a2a3a}
.actions{display:flex;gap:8px;margin-top:4px}
.btn-save{background:#FF1493;color:#fff;border:none;padding:9px 20px;border-radius:8px;
  cursor:pointer;font-size:13px;font-weight:600;transition:background .15s}
.btn-save:hover{background:#e0127e}
.btn-del{background:none;color:#ff4466;border:1px solid #ff446633;padding:8px 16px;
  border-radius:8px;cursor:pointer;font-size:13px;transition:all .15s}
.btn-del:hover{background:#ff44661a;border-color:#ff4466}
.toast{position:fixed;bottom:20px;right:20px;background:#222232;border:1px solid #333;
  color:#ddd;padding:10px 16px;border-radius:8px;font-size:12px;opacity:0;
  transition:opacity .3s;pointer-events:none;z-index:999}
.toast.show{opacity:1}

/* Modal */
#modal-overlay{display:none;position:fixed;inset:0;background:#00000088;z-index:100;
  align-items:center;justify-content:center}
#modal-overlay.open{display:flex}
#modal{background:#1a1a26;border:1px solid #2e2e44;border-radius:12px;padding:24px;
  width:320px;display:flex;flex-direction:column;gap:14px;box-shadow:0 20px 60px #00000099}
#modal h2{font-size:14px;color:#fff}
#modal input{width:100%;background:#0f0f18;border:1px solid #2a2a3a;color:#ddd;
  padding:9px 11px;border-radius:8px;font-size:13px;outline:none}
#modal input:focus{border-color:#FF1493}
.m-sub{color:#555;font-size:11px;margin-top:-8px}
.m-actions{display:flex;gap:8px;justify-content:flex-end}
.m-cancel{background:none;border:1px solid #333;color:#888;padding:7px 16px;
  border-radius:8px;cursor:pointer;font-size:12px}
.m-cancel:hover{border-color:#555;color:#ccc}
.m-ok{background:#FF1493;border:none;color:#fff;padding:7px 16px;border-radius:8px;
  cursor:pointer;font-size:12px;font-weight:600}
.m-ok:hover{background:#e0127e}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#2a2a3a;border-radius:99px}
</style>
</head>
<body>

<div id="titlebar">
  <h1>🗄 Namespace Admin</h1>
  <span class="pill">Dexter's Cloud</span>
  <div class="spacer"></div>
  <form method="POST" action="/admin/logout" style="margin:0">
    <button class="hbtn" type="submit">Sign out</button>
  </form>
</div>

<div id="main">
  <div id="sidebar">
    <div id="sb-hdr">
      Namespaces
      <button onclick="openModal('ns')">+ New</button>
    </div>
    <div id="ns-list"></div>
  </div>

  <div id="middle">
    <div id="mid-hdr">
      <span id="mid-label">Folders &amp; Keys</span>
      <button id="new-folder-btn" onclick="openModal('folder')" style="display:none">+ Folder</button>
    </div>
    <div id="folder-list"></div>
  </div>

  <div id="editor">
    <div id="ed-hdr">
      <h2 id="ed-title">No key selected</h2>
    </div>
    <div id="ed-body">
      <p class="ed-empty">Select a namespace, then a key to edit it.</p>
    </div>
  </div>
</div>

<div id="modal-overlay">
  <div id="modal">
    <h2 id="modal-title">New Namespace</h2>
    <p class="m-sub" id="modal-sub"></p>
    <input id="modal-input" type="text" placeholder="">
    <div class="m-actions">
      <button class="m-cancel" onclick="closeModal()">Cancel</button>
      <button class="m-ok" onclick="confirmModal()">Create</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let currentNS     = null;
let currentFolder = null;
let currentKey    = null;
let nsData        = {};
let modalMode     = null;

// ── Toast ──────────────────────────────────────────────────────────────────
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}

// ── API helpers ────────────────────────────────────────────────────────────
async function api(method, url, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  return res.json();
}

// ── Namespace list ──────────────────────────────────────────────────────────
async function loadNSList() {
  const list = await api('GET', '/admin/api/namespaces');
  const el = document.getElementById('ns-list');
  el.innerHTML = '';
  list.sort().forEach(name => {
    const div = document.createElement('div');
    div.className = 'ns-item' + (name === currentNS ? ' active' : '');
    div.innerHTML = \`<span>📦</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${name}</span>
      <button class="ns-del" onclick="deleteNS('\${name}',event)">✕</button>\`;
    div.onclick = () => selectNS(name);
    el.appendChild(div);
  });
}

async function selectNS(name) {
  currentNS     = name;
  currentFolder = null;
  currentKey    = null;
  nsData        = await api('GET', '/admin/api/ns/' + encodeURIComponent(name));
  loadNSList();
  renderFolders();
  renderEditor();
  document.getElementById('new-folder-btn').style.display = '';
}

async function deleteNS(name, e) {
  e.stopPropagation();
  if (!confirm('Delete namespace "' + name + '" and ALL its data?')) return;
  await api('DELETE', '/admin/api/namespaces/' + encodeURIComponent(name));
  if (currentNS === name) { currentNS = null; currentFolder = null; currentKey = null; nsData = {}; }
  loadNSList();
  renderFolders();
  renderEditor();
  document.getElementById('new-folder-btn').style.display = 'none';
  showToast('Namespace deleted');
}

// ── Folders & keys ──────────────────────────────────────────────────────────
function getFolders() {
  const folders = {};
  Object.keys(nsData).forEach(k => {
    const slash = k.indexOf('/');
    if (slash !== -1) {
      const folder = k.slice(0, slash);
      const subkey = k.slice(slash + 1);
      if (!folders[folder]) folders[folder] = [];
      folders[folder].push(subkey);
    } else {
      if (!folders['']) folders[''] = [];
      folders[''].push(k);
    }
  });
  return folders;
}

function renderFolders() {
  const el   = document.getElementById('folder-list');
  const midL = document.getElementById('mid-label');
  el.innerHTML = '';
  if (!currentNS) { midL.textContent = 'Folders & Keys'; return; }
  midL.textContent = currentNS;

  const folders = getFolders();

  // Flat keys (no folder)
  if (folders['']) {
    folders[''].forEach(k => renderKeyItem(el, '', k));
  }

  // Folders
  Object.keys(folders).filter(f => f !== '').sort().forEach(folder => {
    const fd = document.createElement('div');
    fd.className = 'folder-item' + (folder === currentFolder ? ' active' : '');
    fd.innerHTML = \`<span>📁</span><span style="flex:1">\${folder}</span>
      <button class="f-del" onclick="deleteFolder('\${folder}',event)">✕</button>\`;
    fd.onclick = () => { currentFolder = folder; currentKey = null; renderFolders(); };
    el.appendChild(fd);

    if (folder === currentFolder) {
      folders[folder].forEach(k => renderKeyItem(el, folder, k));
      // + New key in folder
      const addBtn = document.createElement('div');
      addBtn.style.cssText = 'padding:4px 10px 4px 24px;cursor:pointer;color:#555;font-size:11px';
      addBtn.textContent = '+ New key';
      addBtn.onmouseenter = () => addBtn.style.color = '#FF1493';
      addBtn.onmouseleave = () => addBtn.style.color = '#555';
      addBtn.onclick = () => openModal('key');
      el.appendChild(addBtn);
    }
  });
}

function renderKeyItem(container, folder, k) {
  const fullKey = folder ? folder + '/' + k : k;
  const div = document.createElement('div');
  div.className = 'key-item' + (fullKey === currentKey ? ' active' : '');
  div.innerHTML = \`<span>🔑</span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${k}</span>
    <button class="k-del" onclick="deleteKey('\${fullKey}',event)">✕</button>\`;
  div.onclick = () => { currentKey = fullKey; currentFolder = folder || currentFolder; renderFolders(); renderEditor(); };
  container.appendChild(div);
}

async function deleteFolder(folder, e) {
  e.stopPropagation();
  if (!confirm('Delete folder "' + folder + '" and all its keys?')) return;
  await api('DELETE', '/admin/api/ns/' + encodeURIComponent(currentNS) + '/folder', { folder });
  const prefix = folder + '/';
  Object.keys(nsData).filter(k => k.startsWith(prefix)).forEach(k => delete nsData[k]);
  if (currentFolder === folder) { currentFolder = null; currentKey = null; }
  renderFolders();
  renderEditor();
  showToast('Folder deleted');
}

async function deleteKey(fullKey, e) {
  e.stopPropagation();
  if (!confirm('Delete key "' + fullKey + '"?')) return;
  await api('DELETE', '/admin/api/ns/' + encodeURIComponent(currentNS) + '/key', { key: fullKey });
  delete nsData[fullKey];
  if (currentKey === fullKey) { currentKey = null; }
  renderFolders();
  renderEditor();
  showToast('Key deleted');
}

// ── Editor ──────────────────────────────────────────────────────────────────
function renderEditor() {
  const title = document.getElementById('ed-title');
  const body  = document.getElementById('ed-body');

  if (!currentKey) {
    title.textContent = 'No key selected';
    body.innerHTML = '<p class="ed-empty">Select a namespace, then a key to edit it.</p>';
    return;
  }

  const val = nsData[currentKey] ?? '';
  const looksLikeURL = /^https?:\/\//.test(val);
  // Detect ImgBB share pages vs direct links — ibb.co/xxx is a page, i.ibb.co/xxx is direct
  const isImgbbPage  = /^https?:\/\/ibb\.co\//i.test(val);
  const isDirectImage = /\.(png|jpe?g|gif|webp|svg|bmp)(\?.*)?$/i.test(val) ||
                        /^https?:\/\/i\.ibb\.co\//i.test(val) ||
                        /^https?:\/\/i\.imgur\.com\//i.test(val);
  const urlWarning = looksLikeURL && !isDirectImage
    ? (isImgbbPage
        ? '⚠️ This looks like an ImgBB <b>share page</b>, not a direct image. Use the <b>Direct link</b> (starts with <code>i.ibb.co</code>) from ImgBB.'
        : '⚠️ URL may not be a direct image link. Make sure it ends in .png / .jpg / .gif / .webp or is a known direct image host.')
    : '';

  title.textContent = currentKey;
  body.innerHTML = \`
    <div class="field">
      <label>Key</label>
      <input type="text" id="ed-key" value="\${escHtml(currentKey)}" readonly style="color:#666;cursor:default">
    </div>
    <div class="field">
      <label>Value</label>
      <textarea id="ed-val">\${escHtml(val)}</textarea>
      <p class="hint" id="url-hint">\${urlWarning || 'For image keys: paste a <strong>direct</strong> image URL (.png/.jpg/.gif/etc). ImgBB: use the <strong>Direct link</strong>, not the share page.'}</p>
      <img id="img-preview" class="img-preview" \${looksLikeURL && isDirectImage ? 'src="'+escHtml(val)+'" style="display:block"' : ''}>
    </div>
    <div class="actions">
      <button class="btn-save" onclick="saveKey()">Save</button>
      <button class="btn-del" onclick="deleteKey('\${currentKey}', {stopPropagation:()=>{}})">Delete key</button>
    </div>
  \`;

  document.getElementById('ed-val').addEventListener('input', function() {
    const v    = this.value;
    const img  = document.getElementById('img-preview');
    const hint = document.getElementById('url-hint');
    const isURL    = /^https?:\/\//.test(v);
    const isDirect = /\.(png|jpe?g|gif|webp|svg|bmp)(\?.*)?$/i.test(v) ||
                     /^https?:\/\/i\.ibb\.co\//i.test(v) ||
                     /^https?:\/\/i\.imgur\.com\//i.test(v);
    const isPage   = /^https?:\/\/ibb\.co\//i.test(v);
    if (isURL && isDirect) {
      img.src = v; img.style.display = 'block';
      hint.innerHTML = '';
    } else if (isURL && isPage) {
      img.style.display = 'none';
      hint.innerHTML = '⚠️ ImgBB <b>share page</b> detected. Copy the <b>Direct link</b> from ImgBB instead (starts with <code>i.ibb.co</code>).';
    } else if (isURL) {
      img.src = v; img.style.display = 'block';
      hint.innerHTML = '⚠️ URL may not be a direct image — preview may be broken.';
    } else {
      img.style.display = 'none';
      hint.innerHTML = 'For image keys: paste a <strong>direct</strong> image URL.';
    }
  });
}

async function saveKey() {
  if (!currentNS || !currentKey) return;
  const value = document.getElementById('ed-val').value;
  await api('POST', '/admin/api/ns/' + encodeURIComponent(currentNS), { key: currentKey, value });
  nsData[currentKey] = value;
  showToast('Saved ✓');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Modal ───────────────────────────────────────────────────────────────────
function openModal(mode) {
  modalMode = mode;
  const titles = { ns: 'New Namespace', folder: 'New Folder', key: 'New Key' };
  const subs   = {
    ns:     'Creates a new empty namespace on the server.',
    folder: currentNS ? 'In namespace: ' + currentNS : '',
    key:    (currentFolder ? 'In folder: ' + currentFolder : 'At root of: ' + currentNS)
  };
  document.getElementById('modal-title').textContent = titles[mode];
  document.getElementById('modal-sub').textContent   = subs[mode] || '';
  document.getElementById('modal-input').value = '';
  document.getElementById('modal-overlay').classList.add('open');
  setTimeout(() => document.getElementById('modal-input').focus(), 50);
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  modalMode = null;
}

async function confirmModal() {
  const name = document.getElementById('modal-input').value.trim();
  if (!name) return;
  if (modalMode === 'ns') {
    const r = await api('POST', '/admin/api/namespaces', { name });
    closeModal();
    await loadNSList();
    selectNS(r.name || name);
    showToast('Namespace created');
  } else if (modalMode === 'folder') {
    // Create a placeholder key so the folder exists
    const key = name + '/title';
    await api('POST', '/admin/api/ns/' + encodeURIComponent(currentNS), { key, value: '' });
    nsData[key] = '';
    currentFolder = name;
    currentKey    = key;
    closeModal();
    renderFolders();
    renderEditor();
    showToast('Folder created');
  } else if (modalMode === 'key') {
    const fullKey = currentFolder ? currentFolder + '/' + name : name;
    await api('POST', '/admin/api/ns/' + encodeURIComponent(currentNS), { key: fullKey, value: '' });
    nsData[fullKey] = '';
    currentKey = fullKey;
    closeModal();
    renderFolders();
    renderEditor();
    showToast('Key created');
  }
}

document.getElementById('modal-overlay').addEventListener('click', e => {
  if (e.target === document.getElementById('modal-overlay')) closeModal();
});
document.getElementById('modal-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') confirmModal();
  if (e.key === 'Escape') closeModal();
});

// ── Init ────────────────────────────────────────────────────────────────────
loadNSList();
</script>
</body>
</html>`;
}

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Namespace server running on port ${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin`);
});
