/* ============================================================
   EMS Vulnerability Lab — app.js
   ============================================================ */

'use strict';

// ── Global state ──────────────────────────────────────────
let teacherMode  = false;
let currentUser  = null;
let compareMode  = 'login';

// ═══════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════

function qs(sel, root = document) { return root.querySelector(sel); }
function qsa(sel, root = document) { return [...root.querySelectorAll(sel)]; }

function showToast(msg, type = 'info') {
  const t = qs('#toast');
  t.textContent = msg;
  t.className   = `toast ${type}`;
  t.style.display = 'block';
  setTimeout(() => { t.style.display = 'none'; }, 2800);
}

async function apiPost(url, body) {
  const r = await fetch(url, {
    method : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body   : JSON.stringify(body),
  });
  return r.json();
}

async function apiGet(url) {
  const r = await fetch(url);
  return r.json();
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Highlight SQL keywords inside a plain text query
function highlightSQL(rawQuery) {
  const kws = ['SELECT','FROM','WHERE','AND','OR','LIKE','UNION','INSERT','UPDATE','DELETE','INTO','VALUES','ORDER','BY','LIMIT','NULL','NOT','IN','JOIN','ON','AS','GROUP','HAVING'];
  let s = escHtml(rawQuery);
  kws.forEach(k => {
    s = s.replace(new RegExp(`\\b${k}\\b`, 'g'), `<span class="kw">${k}</span>`);
  });
  return s;
}

// Build a dynamic table from an array of row objects
function buildTable(rows, theadRow, tbodyEl) {
  if (!rows || rows.length === 0) {
    theadRow.innerHTML = '';
    tbodyEl.innerHTML  = '<tr><td class="tbl-empty">No records returned</td></tr>';
    return;
  }
  const cols = Object.keys(rows[0]);
  theadRow.innerHTML = cols.map(c => `<th>${escHtml(c)}</th>`).join('');
  tbodyEl.innerHTML  = rows.map(row =>
    `<tr>${cols.map(c => `<td>${escHtml(String(row[c] ?? ''))}</td>`).join('')}</tr>`
  ).join('');
}

// ═══════════════════════════════════════════════════════════
//  LOGIN
// ═══════════════════════════════════════════════════════════

// Live SQL preview on the login form
function updateLoginPreview() {
  const u = qs('#l-username').value;
  const p = qs('#l-password').value;
  qs('#lq-user').textContent = u || '...';
  qs('#lq-pass').textContent = p || '...';
}

qs('#l-username').addEventListener('input', updateLoginPreview);
qs('#l-password').addEventListener('input', updateLoginPreview);

// Fill payload into login form
function fillLogin(username, password) {
  qs('#l-username').value = username;
  qs('#l-password').value = password;
  updateLoginPreview();
}

// Toggle teacher payload panel (login page)
function toggleTeacherPanel(id) {
  const payloads = qs(`#teacher-${id}-payloads`);
  const arrow    = qs(`#teacher-${id}-arrow`);
  const hidden   = payloads.classList.contains('hidden');
  payloads.classList.toggle('hidden', !hidden);
  if (arrow) arrow.textContent = hidden ? '▲' : '▼';
}

// Submit login
qs('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = qs('#l-username').value;
  const password = qs('#l-password').value;

  const btn = qs('#login-btn');
  btn.disabled   = true;
  btn.innerHTML  = '<span>Sending…</span>';

  try {
    const data = await apiPost('/api/login', { username, password });
    showLoginResult(data);

    if (data.success && data.user) {
      currentUser = data.user;
      setTimeout(() => enterApp(data.user), 900);
    }
  } catch (err) {
    showLoginResult({ success: false, message: 'Network error: ' + err.message });
  }

  btn.disabled  = false;
  btn.innerHTML = '<span>Sign In</span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
});

function showLoginResult(data) {
  const result = qs('#login-result');
  const status = qs('#lr-status');
  const query  = qs('#lr-query');
  const dataW  = qs('#lr-data-wrap');
  const dataEl = qs('#lr-data');

  result.classList.remove('hidden');

  if (data.success) {
    status.innerHTML = '✅ <span style="color:#86efac">Login successful! Authentication bypassed.</span>';
    status.style.background = 'rgba(34,197,94,.1)';
    status.style.borderBottom = '1px solid rgba(34,197,94,.2)';
  } else {
    status.innerHTML = data.error
      ? `❌ <span style="color:#fca5a5">SQL Error: ${escHtml(data.error)}</span>`
      : '❌ <span style="color:#fca5a5">Invalid credentials — login failed.</span>';
    status.style.background = 'rgba(239,68,68,.1)';
    status.style.borderBottom = '1px solid rgba(239,68,68,.2)';
  }

  query.innerHTML = highlightSQL(data.query || '');

  if (data.user) {
    dataW.classList.remove('hidden');
    dataEl.textContent = JSON.stringify(data.user, null, 2);
  } else {
    dataW.classList.add('hidden');
  }
}

// ═══════════════════════════════════════════════════════════
//  APP NAV
// ═══════════════════════════════════════════════════════════

function enterApp(user) {
  qs('#login-view').style.display  = 'none';
  qs('#app-view').classList.remove('hidden');
  qs('#app-view').style.display    = 'flex';

  // Set user info in sidebar
  const name = user.username;
  qs('#sb-ava').textContent  = name[0].toUpperCase();
  qs('#sb-name').textContent = name;
  qs('#sb-role').textContent = user.role;

  navigate('dashboard');
  loadDashboardEmployees();
}

function navigate(section) {
  qsa('.section').forEach(s => s.classList.remove('active'));
  qsa('.nav-link').forEach(l => l.classList.remove('active'));

  const sec = qs(`#section-${section}`);
  if (sec) sec.classList.add('active');

  const link = qs(`.nav-link[data-section="${section}"]`);
  if (link) link.classList.add('active');

  const titles = { dashboard:'Dashboard', search:'Employee Search', lookup:'Employee ID Lookup', compare:'Fix Comparison' };
  qs('#page-title').textContent = titles[section] || section;
}

function logout() {
  currentUser = null;
  qs('#app-view').style.display   = 'none';
  qs('#login-view').style.display = 'flex';
  qs('#login-result').classList.add('hidden');
  qs('#l-username').value = '';
  qs('#l-password').value = '';
  updateLoginPreview();
  showToast('Logged out');
}

// ═══════════════════════════════════════════════════════════
//  TEACHER MODE
// ═══════════════════════════════════════════════════════════

function setTeacherMode(on) {
  teacherMode = on;

  // Toggle attack columns visible + grid layout
  const panels = ['search-attack-col', 'lookup-attack-col'];
  const grids  = ['search-two-col', 'lookup-two-col'];

  panels.forEach(id => {
    const el = qs(`#${id}`);
    if (el) el.classList.toggle('hidden', !on);
  });
  grids.forEach(id => {
    const el = qs(`#${id}`);
    if (el) el.classList.toggle('teacher-on', on);
  });

  showToast(on ? '🎓 Teacher Mode ON — Attack panels revealed' : 'Teacher Mode OFF');
}

// ═══════════════════════════════════════════════════════════
//  DASHBOARD
// ═══════════════════════════════════════════════════════════

async function loadDashboardEmployees() {
  try {
    const data = await apiGet('/api/employees/search?name=');
    const tbody = qs('#dash-emp-body');
    if (data.results && data.results.length) {
      tbody.innerHTML = data.results.map(r => `
        <tr>
          <td>${escHtml(String(r.id))}</td>
          <td>${escHtml(r.name)}</td>
          <td>${escHtml(r.department || '')}</td>
          <td>${escHtml(r.position || '')}</td>
          <td>${escHtml(r.email || '')}</td>
          <td>${escHtml(r.hire_date || '')}</td>
        </tr>
      `).join('');
      qs('#stat-emp-count').textContent = data.results.length;
    }
  } catch (e) {
    qs('#dash-emp-body').innerHTML = `<tr><td colspan="6" class="tbl-empty">Error loading employees</td></tr>`;
  }
}

// ═══════════════════════════════════════════════════════════
//  EMPLOYEE SEARCH  (VULN-2)
// ═══════════════════════════════════════════════════════════

function updateSearchPreview() {
  const val = qs('#search-input').value;
  qs('#sq-val').textContent = val;
}

async function doSearch() {
  const name = qs('#search-input').value;
  updateSearchPreview();

  const countBadge = qs('#search-count');
  countBadge.textContent = '…';

  try {
    const data = await apiGet(`/api/employees/search?name=${encodeURIComponent(name)}`);

    // Update query display
    const sqlBox = qs('#search-sql');
    sqlBox.innerHTML = highlightSQL(data.query || '');

    // Render results with dynamic columns (UNION may return different cols)
    const thead = qs('#search-thead-row');
    const tbody = qs('#search-tbody');
    buildTable(data.results, thead, tbody);

    const count = data.count ?? (data.results ? data.results.length : 0);
    countBadge.textContent = `${count} record${count !== 1 ? 's' : ''}`;

    if (data.error) {
      tbody.innerHTML = `<tr><td colspan="99" class="tbl-empty" style="color:#fca5a5">SQL Error: ${escHtml(data.error)}</td></tr>`;
    }

    // Flash if UNION injection detected (more columns or unexpected keys)
    if (data.results && data.results.length > 0) {
      const cols = Object.keys(data.results[0]);
      if (name.toUpperCase().includes('UNION') || cols.some(c => ['username','password','key_name','value'].includes(c))) {
        showToast('🔓 Data leaked via UNION injection!', 'warning');
      }
    }
  } catch (err) {
    showToast('Request failed: ' + err.message, 'error');
  }
}

function injectSearch(payload) {
  qs('#search-input').value = payload;
  updateSearchPreview();
  doSearch();
}

// ═══════════════════════════════════════════════════════════
//  EMPLOYEE ID LOOKUP  (VULN-3)
// ═══════════════════════════════════════════════════════════

function updateLookupPreview() {
  const val = qs('#lookup-input').value;
  qs('#lkq-val').textContent = val || '1';
}

async function doLookup() {
  const id = qs('#lookup-input').value || '1';
  updateLookupPreview();

  const countBadge = qs('#lookup-count');
  countBadge.textContent = '…';

  try {
    const data = await apiGet(`/api/employees/${encodeURIComponent(id)}`);

    // Update query
    const sqlBox = qs('#lookup-sql');
    sqlBox.innerHTML = highlightSQL(data.query || '');

    const thead = qs('#lookup-thead-row');
    const tbody = qs('#lookup-tbody');
    buildTable(data.results, thead, tbody);

    const count = data.count ?? (data.results ? data.results.length : 0);
    countBadge.textContent = `${count} record${count !== 1 ? 's' : ''}`;

    if (data.error) {
      tbody.innerHTML = `<tr><td colspan="99" class="tbl-empty" style="color:#fca5a5">SQL Error: ${escHtml(data.error)}</td></tr>`;
    }

    if (data.results && data.results.length > 0) {
      const keys = Object.keys(data.results[0]);
      if (String(id).toUpperCase().includes('UNION') || keys.includes('password') || keys.includes('key_name')) {
        showToast('🔓 UNION injection successful — data exfiltrated!', 'warning');
      }
    }
  } catch (err) {
    showToast('Request failed: ' + err.message, 'error');
  }
}

function injectLookup(payload) {
  qs('#lookup-input').value = payload;
  updateLookupPreview();
  doLookup();
}

// ═══════════════════════════════════════════════════════════
//  COMPARE SECTION
// ═══════════════════════════════════════════════════════════

function setCompareMode(mode) {
  compareMode = mode;
  qsa('.ctab').forEach(b => b.classList.toggle('active', b.dataset.cmode === mode));
  qsa('.compare-panel').forEach(p => p.classList.add('hidden'));
  const panel = qs(`#cpanel-${mode}`);
  if (panel) panel.classList.remove('hidden');
}

// Login compare
async function runCompareLogin() {
  const username = qs('#c-login-user').value;
  const password = qs('#c-login-pass').value;

  const [vuln, safe] = await Promise.all([
    apiPost('/api/login',        { username, password }),
    apiPost('/api/secure/login', { username, password }),
  ]);

  qs('#cc-login-vuln-q').innerHTML = highlightSQL(vuln.query || '');
  qs('#cc-login-safe-q').innerHTML = highlightSQL(safe.query || '');

  const vr = qs('#cc-login-vuln-r');
  const sr = qs('#cc-login-safe-r');

  vr.innerHTML = vuln.success
    ? `<span style="color:#86efac">✅ LOGGED IN as <strong>${escHtml(vuln.user?.username || '?')}</strong> (${escHtml(vuln.user?.role || '?')})</span>`
    : `<span style="color:#fca5a5">❌ Login failed</span>`;

  sr.innerHTML = safe.success
    ? `<span style="color:#86efac">✅ LOGGED IN as <strong>${escHtml(safe.user?.username || '?')}</strong></span>`
    : `<span style="color:#86efac">✅ Correctly rejected — <strong>Invalid credentials</strong></span>`;

  // Highlight discrepancy
  if (vuln.success && !safe.success) {
    showToast('⚠️ Injection worked on VULNERABLE but blocked on SECURE endpoint', 'warning');
  }
}

// Search compare
async function runCompareSearch() {
  const name = qs('#c-search-val').value;

  const [vuln, safe] = await Promise.all([
    apiGet(`/api/employees/search?name=${encodeURIComponent(name)}`),
    apiGet(`/api/secure/employees/search?name=${encodeURIComponent(name)}`),
  ]);

  qs('#cc-search-vuln-q').innerHTML = highlightSQL(vuln.query || '');
  qs('#cc-search-safe-q').innerHTML = highlightSQL(safe.query || '');

  const vc = vuln.count ?? (vuln.results?.length ?? 0);
  const sc = safe.count ?? (safe.results?.length ?? 0);
  qs('#cc-search-vuln-count').textContent = vc;
  qs('#cc-search-safe-count').textContent = sc;

  if (vuln.results?.length) {
    const vd = qs('#cc-search-vuln-data');
    vd.style.display = 'block';
    vd.textContent = JSON.stringify(vuln.results, null, 2);
  }
  if (safe.results?.length) {
    const sd = qs('#cc-search-safe-data');
    sd.style.display = 'block';
    sd.textContent = JSON.stringify(safe.results, null, 2);
  }

  if (vc !== sc) {
    showToast(`⚠️ Vulnerable returned ${vc} records vs Secure's ${sc}`, 'warning');
  }
}

// Lookup compare
async function runCompareLookup() {
  const id = qs('#c-lookup-val').value;

  const [vuln, safe] = await Promise.all([
    apiGet(`/api/employees/${encodeURIComponent(id)}`),
    apiGet(`/api/secure/employees/${encodeURIComponent(id)}`),
  ]);

  qs('#cc-lookup-vuln-q').innerHTML = highlightSQL(vuln.query || '');
  qs('#cc-lookup-safe-q').innerHTML = highlightSQL(safe.query || '');

  const vc = vuln.count ?? (vuln.results?.length ?? 0);
  const sc = safe.count ?? (safe.results?.length ?? 0);
  qs('#cc-lookup-vuln-count').textContent = vc;
  qs('#cc-lookup-safe-count').textContent = sc;

  if (vuln.results?.length) {
    const vd = qs('#cc-lookup-vuln-data');
    vd.style.display = 'block';
    vd.textContent = JSON.stringify(vuln.results, null, 2);
  }
  if (safe.results?.length) {
    const sd = qs('#cc-lookup-safe-data');
    sd.style.display = 'block';
    sd.textContent = JSON.stringify(safe.results, null, 2);
  }

  if (vc !== sc) {
    showToast(`⚠️ Vulnerable returned ${vc} records vs Secure's ${sc}`, 'warning');
  }
}

// ═══════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════

// Init login preview
updateLoginPreview();
// Init lookup preview  
updateLookupPreview();
// Init compare mode
setCompareMode('login');
