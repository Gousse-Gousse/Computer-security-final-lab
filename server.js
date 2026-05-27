/**
 * ============================================================
 *  EMS VULNERABILITY LAB — server.js
 *  ⚠️  FOR EDUCATIONAL / CLASSROOM USE ONLY
 *  Contains INTENTIONAL SQL injection vulnerabilities.
 *  DO NOT deploy in any production or live environment.
 *
 *  Uses sql.js (SQLite compiled to WebAssembly) — no native
 *  build tools required; works on any Node.js version.
 *
 *  CVE-2026-21643 simulation endpoints:
 *    GET  /api/v1/init_consts   ← Error-based SQLi via Site header
 *    POST /api/v1/auth/signin   ← Time-based SQLi via Site header
 * ============================================================
 */

const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');
const initSqlJs  = require('sql.js');

// ── Lockout state (simulates FortiClient EMS 3-attempt lockout) ──
// Map of  ip -> { count, lockedUntil }
const signinAttempts = new Map();

const app  = express();
const PORT = 3000;

// ── Middleware ────────────────────────────────────────────────
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── SQL.js helpers ────────────────────────────────────────────
// Convert sql.js exec() result (columns + values) → array of objects
function toObjects(result) {
  if (!result || result.length === 0) return [];
  const { columns, values } = result[0];
  return values.map(row => {
    const obj = {};
    columns.forEach((col, i) => { obj[col] = row[i]; });
    return obj;
  });
}

// Execute a raw SQL string (VULNERABLE — used for injection demos)
function runRaw(db, sql) {
  const result = db.exec(sql);
  return toObjects(result);
}

// Execute a parameterized query (SECURE — used for fix demos)
function runParam(db, sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

// ── Bootstrap ─────────────────────────────────────────────────
async function bootstrap() {
  const SQL = await initSqlJs();
  const db  = new SQL.Database();   // in-memory SQLite (perfect for lab use)

  // ── Schema & seed data ──────────────────────────────────────
  db.run(`
    CREATE TABLE users (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      role     TEXT DEFAULT 'employee'
    );

    CREATE TABLE employees (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      name       TEXT NOT NULL,
      department TEXT,
      email      TEXT,
      salary     INTEGER,
      ssn        TEXT,
      phone      TEXT,
      hire_date  TEXT,
      position   TEXT
    );

    CREATE TABLE secrets (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      key_name TEXT,
      value    TEXT
    );

    CREATE TABLE app_config (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id      TEXT NOT NULL,
      config_value TEXT
    );

    CREATE TABLE sessions (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      site_key TEXT NOT NULL,
      user_id  INTEGER
    );
  `);

  db.run(`
    INSERT INTO users (username, password, role) VALUES
      ('admin',      'SuperSecret123!', 'admin'),
      ('john.doe',   'password123',     'employee'),
      ('jane.smith', 'qwerty456',       'manager'),
      ('hr.admin',   'hr@2024',         'hr');

    INSERT INTO employees (name, department, email, salary, ssn, phone, hire_date, position) VALUES
      ('John Doe',      'Engineering', 'john.doe@ems.corp',    85000,  '123-45-6789', '555-0101', '2021-03-15', 'Software Engineer'),
      ('Jane Smith',    'Management',  'jane.smith@ems.corp',  120000, '987-65-4321', '555-0102', '2019-07-22', 'Department Manager'),
      ('Bob Johnson',   'HR',          'bob.j@ems.corp',       72000,  '456-78-9012', '555-0103', '2020-11-01', 'HR Specialist'),
      ('Alice Chen',    'Finance',     'alice.c@ems.corp',     95000,  '321-54-9876', '555-0104', '2018-05-10', 'Financial Analyst'),
      ('Charlie Brown', 'Engineering', 'charlie.b@ems.corp',   88000,  '654-32-1098', '555-0105', '2022-01-30', 'DevOps Engineer'),
      ('Diana Prince',  'Legal',       'diana.p@ems.corp',     110000, '789-01-2345', '555-0106', '2017-08-20', 'Legal Counsel'),
      ('Ethan Hunt',    'Operations',  'ethan.h@ems.corp',     78000,  '234-56-7890', '555-0107', '2023-02-14', 'Operations Analyst');

    INSERT INTO secrets (key_name, value) VALUES
      ('db_root_password',     'P@ssw0rd!DB2024'),
      ('api_secret_key',       'sk-prod-xK92mNpQ7rTvLzWo'),
      ('backup_encryption_key','AES256-PROD-KEY-9182736450'),
      ('aws_access_key',       'AKIA4EXAMPLE12345678'),
      ('jwt_secret',           'hs256-jwt-secret-do-not-share-2024');
  `);

  // =================================================================
  //  🔓 VULNERABLE ENDPOINTS  (intentionally insecure — DO NOT COPY)
  // =================================================================

  /**
   * [VULN-1] Authentication Bypass via SQL Injection
   * POST /api/login
   * Payload: username = admin'--   (comments out password check)
   */
  app.post('/api/login', (req, res) => {
    const { username = '', password = '' } = req.body;

    // ❌ VULNERABLE: direct string interpolation — never do this
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    try {
      const rows = runRaw(db, query);
      const user = rows[0] || null;
      res.json({
        success : !!user,
        message : user
          ? `Welcome, ${user.username}!  (Role: ${user.role})`
          : 'Invalid username or password.',
        query,
        user    : user ? { id: user.id, username: user.username, role: user.role } : null,
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message, query });
    }
  });

  /**
   * [VULN-2] UNION-based Data Exfiltration via Employee Search
   * GET /api/employees/search?name=<input>
   * Payload: ' UNION SELECT 1,username,password,role,'5','6' FROM users--
   */
  app.get('/api/employees/search', (req, res) => {
    const name = req.query.name || '';

    // ❌ VULNERABLE: direct string interpolation in LIKE clause
    const query = `SELECT id, name, department, email, position, hire_date FROM employees WHERE name LIKE '%${name}%'`;

    try {
      const results = runRaw(db, query);
      res.json({ success: true, query, results, count: results.length });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message, query });
    }
  });

  /**
   * [VULN-3] SQL Injection via Numeric Route Parameter
   * GET /api/employees/:id
   * Payload: 0 UNION SELECT 1,username,department,email,0,password,phone,hire_date,role FROM users
   */
  app.get('/api/employees/:id', (req, res) => {
    const id = req.params.id;

    // ❌ VULNERABLE: numeric param embedded directly, no casting
    const query = `SELECT * FROM employees WHERE id = ${id}`;

    try {
      const results = runRaw(db, query);
      res.json({ success: true, query, results, count: results.length });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message, query });
    }
  });

  // =================================================================
  //  💀 CVE-2026-21643 SIMULATION ENDPOINTS
  //     Mirrors real FortiClient EMS 7.4.4 attack surface:
  //     - SQL injection via the HTTP "Site" request header
  //     - No authentication required (pre-auth)
  // =================================================================

  /**
   * [CVE-1] Error-based SQLi — GET /api/v1/init_consts
   *
   * The real EMS endpoint reads the Site header and embeds it
   * directly into a PostgreSQL query.  Injecting a CAST of a
   * non-numeric string forces a type-error that PostgreSQL
   * reflects verbatim in the HTTP 500 response body.
   *
   * Exploit script detection heuristic:
   *   status == 500  &&  injected string appears in response body
   *
   * SQLite simulation:
   *   sql.js throws "no such function: CAST" or a parse error
   *   when the payload breaks the query; we reflect that error
   *   text in the response body exactly as the script expects.
   *
   * Test payload (from exploit script):
   *   Site: x'; SELECT CAST('alireza_cve_2026_21643_test' AS int)--
   */
  app.get('/api/v1/init_consts', (req, res) => {
    const site = req.headers['site'] || 'default';

    // ❌ VULNERABLE: Site header embedded directly into SQL string
    const query = `SELECT config_value FROM app_config WHERE site_id = '${site}'`;

    // ── PostgreSQL CAST error simulation ────────────────────────────
    // SQLite accepts CAST() silently; real PostgreSQL raises a type error
    // that reflects the payload in the response body.  We detect any SQL
    // breakout in the Site header and emit the same error format so the
    // exploit script's probe-string-in-body detection works correctly.
    const castMatch = site.match(/CAST\s*\(\s*'([^']+)'\s+AS\s+\w+\s*\)/i);
    const hasBreakout = /[';]/.test(site) || /--/.test(site);

    if (hasBreakout) {
      let errorBody;
      if (castMatch) {
        // Reflect the cast value exactly as PostgreSQL would in its error
        errorBody = `ERROR: invalid input syntax for type integer: "${castMatch[1]}" at character 1\nDETAIL: ${castMatch[1]}`;
      } else {
        errorBody = `ERROR: syntax error at or near "'" at character 1 — query: ${query}`;
      }
      return res.status(500).send(errorBody);
    }

    try {
      runRaw(db, query);
      // Normal response for a clean Site value
      res.json({
        version        : '7.4.4',
        build          : '1728',
        auth_methods   : ['local', 'ldap'],
        session_timeout: 3600,
      });
    } catch (err) {
      const reflected = `ERROR: invalid input syntax for type integer: "${site}" — ${err.message}`;
      res.status(500).send(reflected);
    }
  });

  /**
   * [CVE-2] Time-based SQLi — POST /api/v1/auth/signin
   *
   * The real EMS endpoint also reads the Site header without
   * sanitisation.  Injecting pg_sleep(N) causes the database
   * to pause before responding.  pgbouncer executes the
   * statement twice, producing ~2× the requested delay.
   *
   * Exploit script detection heuristic:
   *   injected_time  >  baseline_time + 8 seconds
   *   OR the request times out entirely (ReadTimeout).
   *
   * This endpoint enforces a lockout per IP to mirror the real
   * FortiClient EMS account-lockout behaviour.
   *
   * Lab note: the threshold is set to 20 *injection* attempts
   * (clean/baseline requests are free and do NOT count) so that
   * repeated exploit runs during a classroom session do not
   * constantly hit the lockout wall.  Use GET /api/v1/admin/reset-lockout
   * to clear the counter without restarting the server.
   *
   * SQLite simulation:
   *   sql.js has no pg_sleep(), so we parse the sleep value
   *   from the payload manually and use setTimeout to simulate
   *   the delay before responding.
   *
   * Test payload (from exploit script):
   *   Site: x'; SELECT pg_sleep(5)--
   *   (pgbouncer doubles it → ~10 s real delay)
   */
  app.post('/api/v1/auth/signin', async (req, res) => {
    const ip   = req.ip || req.connection.remoteAddress || 'unknown';
    const site = req.headers['site'] || 'default';
    const now  = Date.now();

    // Only injection payloads (containing breakout chars) count toward lockout.
    // Clean baseline requests are free so repeated exploit runs don't self-lock.
    const isInjectionAttempt = /[';]/.test(site) || /--/.test(site);

    // ── Lockout check ─────────────────────────────────────────────
    if (!signinAttempts.has(ip)) {
      signinAttempts.set(ip, { count: 0, lockedUntil: 0 });
    }
    const attempt = signinAttempts.get(ip);

    if (attempt.lockedUntil > now) {
      const remaining = Math.ceil((attempt.lockedUntil - now) / 1000);
      return res.status(429).json({
        error   : 'Account locked',
        message : `Too many injection attempts. Try again in ${remaining}s. Or call GET /api/v1/admin/reset-lockout`,
        locked  : true,
      });
    }

    if (isInjectionAttempt) {
      attempt.count += 1;
      if (attempt.count >= 20) {           // 20 injection attempts before lockout
        attempt.lockedUntil = now + 5 * 60 * 1000; // 5-minute lockout
        attempt.count       = 0;
      }
    }

    // ── Time-based injection simulation ──────────────────────────
    // Parse pg_sleep(N) from the Site header payload.
    // The exploit doubles the delay (pgbouncer executes twice),
    // so we apply the same 2× multiplier here.
    let sleepMs = 0;
    const sleepMatch = site.match(/pg_sleep\s*\(\s*([\d.]+)\s*\)/i);
    if (sleepMatch) {
      const sleepSec = parseFloat(sleepMatch[1]);
      sleepMs = sleepSec * 2 * 1000; // 2× for pgbouncer simulation
    }

    // ❌ VULNERABLE: Site header concatenated into query string
    const query = `SELECT user_id FROM sessions WHERE site_key = '${site}'`;

    // Simulate the blocking delay before responding
    await new Promise(resolve => setTimeout(resolve, sleepMs));

    try {
      runRaw(db, query);
      res.json({
        success : false,
        message : 'Invalid credentials.',
        locked  : false,
      });
    } catch (err) {
      // Reflect error (SQLi confirmed path)
      res.status(500).json({
        success : false,
        error   : err.message,
        query,
      });
    }
  });

  // =================================================================
  //  🛡️  SECURE ENDPOINTS  (parameterized queries — the correct way)
  // =================================================================

  /** [SECURE-1] Parameterized Login */
  app.post('/api/secure/login', (req, res) => {
    const { username = '', password = '' } = req.body;

    // ✅ SECURE: parameterized query — user input never touches SQL string
    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
    const rows  = runParam(db, query, [username, password]);
    const user  = rows[0] || null;

    res.json({
      success : !!user,
      message : user
        ? `Welcome, ${user.username}!  (Role: ${user.role})`
        : 'Invalid username or password.',
      query   : `${query}  -- params: ['${username}', '***']`,
      user    : user ? { id: user.id, username: user.username, role: user.role } : null,
    });
  });

  /** [SECURE-2] Parameterized Employee Search */
  app.get('/api/secure/employees/search', (req, res) => {
    const name = req.query.name || '';

    // ✅ SECURE: LIKE pattern passed as parameter, not concatenated
    const query   = `SELECT id, name, department, email, position, hire_date FROM employees WHERE name LIKE ?`;
    const results = runParam(db, query, [`%${name}%`]);

    res.json({
      success : true,
      query   : `${query}  -- param: '%${name}%'`,
      results,
      count   : results.length,
    });
  });

  /** [SECURE-3] Parameterized Employee Lookup by ID */
  app.get('/api/secure/employees/:id', (req, res) => {
    const id = req.params.id;

    // ✅ SECURE: parameterized — injection payload treated as literal value
    const query   = `SELECT * FROM employees WHERE id = ?`;
    const results = runParam(db, query, [id]);

    res.json({
      success : true,
      query   : `${query}  -- param: '${id}'`,
      results,
      count   : results.length,
    });
  });

  // ── Health check ──────────────────────────────────────────────
  app.get('/api/health', (_req, res) => {
    res.json({
      status  : 'running',
      engine  : 'sql.js (SQLite WASM — no native build required)',
      warning : '⚠️  FOR EDUCATIONAL USE ONLY — DO NOT DEPLOY IN PRODUCTION',
    });
  });

  // ── Lab management: reset lockout counter ────────────────────
  // Allows instructors / students to clear the signin lockout
  // state without restarting the server process.
  app.get('/api/v1/admin/reset-lockout', (req, res) => {
    const ip      = req.query.ip || null;
    const before  = signinAttempts.size;

    if (ip) {
      signinAttempts.delete(ip);
      res.json({ cleared: ip, entries_before: before, entries_after: signinAttempts.size });
    } else {
      signinAttempts.clear();
      res.json({ cleared: 'all', entries_before: before, entries_after: 0 });
    }
  });

  // ── Start server ──────────────────────────────────────────────
  app.listen(PORT, () => {
    const line = '═'.repeat(60);
    console.log(`\n${line}`);
    console.log('  🚨  EMS VULNERABILITY LAB  —  EDUCATIONAL USE ONLY');
    console.log(line);
    console.log(`  🌐  URL     : http://localhost:${PORT}`);
    console.log(`  ⚙️   Engine  : sql.js (SQLite WebAssembly — no C++ required)`);
    console.log(`  ⚠️   WARNING : Contains intentional SQL injection flaws`);
    console.log(`  📚  Purpose : Security education & classroom demos`);
    console.log(`${line}\n`);
    console.log('  CVE-2026-21643 simulation (Site-header injection):');
    console.log(`    GET  /api/v1/init_consts           ← Error-based SQLi`);
    console.log(`    POST /api/v1/auth/signin            ← Time-based SQLi (20-injection lockout)`);
    console.log(`    GET  /api/v1/admin/reset-lockout   ← Reset lockout counter (lab utility)`);
    console.log('  Legacy vulnerable endpoints:');
    console.log(`    POST /api/login                   ← Auth bypass`);
    console.log(`    GET  /api/employees/search?name=  ← UNION injection`);
    console.log(`    GET  /api/employees/:id           ← Numeric param injection`);
    console.log('  Secure endpoints (for comparison):');
    console.log(`    POST /api/secure/login`);
    console.log(`    GET  /api/secure/employees/search?name=`);
    console.log(`    GET  /api/secure/employees/:id`);
    console.log(`\n${line}\n`);
  });
}

bootstrap().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
