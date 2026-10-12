// SecureGate Console - Frontend Application Logic
(() => {
  'use strict';

  // App session state
  const state = { access: null, refresh: null, email: null, user: null };
  let refreshPromise = null, auditTimer = null, countTimer = null;
  let authMode = 'login', currentTab = 'playground';

  // DOM element helpers
  const el = (id) => document.getElementById(id);
  const mk = (tag, cls, txt) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (txt !== undefined) node.textContent = txt;
    return node;
  };

  // Show a date + time that is easy to read, e.g. "12 Oct, 14:03:21"
  const fmtTime = (iso) => new Date(iso).toLocaleString([], {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });

  // Safe client-side base64url decode of JWT payload
  function decodeJwt(token) {
    try {
      const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      const json = decodeURIComponent(
        atob(b64).split('').map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
      );
      return JSON.parse(json);
    } catch { return null; }
  }

  // Session persistence in sessionStorage
  function saveSession(access, refresh, email) {
    state.access = access; state.refresh = refresh; state.email = email; state.user = decodeJwt(access);
    sessionStorage.setItem('sg_acc', access);
    sessionStorage.setItem('sg_ref', refresh);
    sessionStorage.setItem('sg_em', email);
  }

  function clearSession() {
    state.access = state.refresh = state.email = state.user = null;
    sessionStorage.clear();
    clearInterval(auditTimer);
    clearInterval(countTimer);
  }

  function loadSession() {
    const acc = sessionStorage.getItem('sg_acc'), ref = sessionStorage.getItem('sg_ref'), em = sessionStorage.getItem('sg_em');
    if (acc && ref && em) {
      state.access = acc; state.refresh = ref; state.email = em; state.user = decodeJwt(acc);
      return !!state.user;
    }
    return false;
  }

  // Core API caller with automatic token refresh
  async function api(path, opts = {}) {
    const headers = {};
    if (opts.auth !== false && state.access) headers['Authorization'] = opts.fakeToken || `Bearer ${state.access}`;
    let body = opts.body;
    if (body && typeof body === 'object') { headers['Content-Type'] = 'application/json'; body = JSON.stringify(body); }

    const t0 = performance.now();
    let res, data;
    try {
      res = await fetch(path, { method: opts.method || 'GET', headers, body });
    } catch {
      return { status: 0, data: { error: 'Cannot reach the gateway' }, ms: Math.round(performance.now() - t0) };
    }
    const ms = Math.round(performance.now() - t0);
    const retryAfter = res.headers.get('Retry-After');
    try { data = await res.json(); } catch { data = { error: res.statusText || 'Parse error' }; }

    // Single in-flight token refresh on 401
    if (res.status === 401 && state.refresh && !opts._retried && !opts.fakeToken && !path.startsWith('/auth/')) {
      if (!refreshPromise) {
        refreshPromise = (async () => {
          const r = await fetch('/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken: state.refresh }),
          });
          if (!r.ok) throw new Error('Refresh failed');
          return r.json();
        })().finally(() => { refreshPromise = null; });
      }

      try {
        const pair = await refreshPromise;
        saveSession(pair.access, pair.refresh, state.email);
        return api(path, { ...opts, _retried: true });
      } catch {
        clearSession();
        render('Session expired. Please log in again.');
        return { status: 401, data: { error: 'Session expired' }, ms, retryAfter: null };
      }
    }
    return { status: res.status, data, ms, retryAfter };
  }

  // Health check poller (runs every 15s)
  async function checkHealth() {
    const { data } = await api('/health', { auth: false });
    ['db', 'redis'].forEach((k) => {
      const ok = data && data[k] === 'up', pill = el(`${k}-health`);
      pill.textContent = `${k.toUpperCase()} ${ok ? 'up' : 'down'}`;
      pill.className = `health-pill ${ok ? 'up' : 'down'}`;
    });
  }

  // Highlight decision in the 6-step pipeline
  function updatePipeline(status) {
    for (let i = 1; i <= 6; i++) el(`pipe-live-${i}`).className = 'pipe-step';
    const pass = (n) => { for (let i = 1; i <= n; i++) el(`pipe-live-${i}`).classList.add('step-pass'); };
    if (status >= 200 && status < 300) pass(6);
    else if (status === 429) { pass(1); el('pipe-live-2').classList.add('step-fail'); }
    else if (status === 401) { pass(2); el('pipe-live-3').classList.add('step-fail'); }
    else if (status === 403) { pass(3); el('pipe-live-4').classList.add('step-fail'); }
    else if (status === 502 || status === 504) { pass(4); el('pipe-live-5').classList.add('step-fail'); }
  }

  // Display playground response details
  function showResult(status, data, ms, retry) {
    el('res-time').textContent = `${ms} ms`;
    el('res-json').textContent = JSON.stringify(data, null, 2);
    const b = el('res-badge');
    const badgeCls = status >= 200 && status < 300 ? 'badge-2xx' : (status === 401 || status === 403 ? 'badge-401' : (status === 429 ? 'badge-429' : 'badge-5xx'));
    b.className = `status-badge ${badgeCls}`;
    b.textContent = `${status || 'ERR'} ${status === 200 ? 'OK' : status === 201 ? 'Created' : ''}`.trim();

    const msgMap = {
      401: "I don't know who you are",
      403: 'I know you, but your role is not allowed',
      429: retry ? `too many requests (retry in ${retry}s)` : 'too many requests',
      502: 'the service behind me is down',
      504: 'the service took too long',
    };
    el('res-explanation').textContent = msgMap[status] || (status >= 200 && status < 300 ? 'Request authorized and succeeded' : 'Request completed');
    updatePipeline(status);
  }

  // Highlight active role column in permissions matrix
  function updateMatrix() {
    ['viewer', 'analyst', 'admin'].forEach((r) => el(`col-${r}`).classList.toggle('active-role', state.user && state.user.role === r));
  }

  // Safe text alert box helpers
  function showMsg(box, text, cls = 'alert-error') { box.textContent = text; box.className = `alert-box ${cls}`; }
  function hideMsg(box) { box.textContent = ''; box.className = 'alert-box hidden'; }

  // Render main screen state
  function render(flash) {
    const loggedIn = !!(state.access && state.user);
    el('logged-out-view').classList.toggle('hidden', loggedIn);
    el('logged-in-view').classList.toggle('hidden', !loggedIn);
    el('user-chip').classList.toggle('hidden', !loggedIn);

    if (loggedIn) {
      el('user-email-badge').textContent = state.email;
      el('user-role-badge').textContent = state.user.role;
      el('user-role-badge').className = `badge badge-${state.user.role}`;
      updateMatrix();
      setTab(currentTab);
      startCountdown();
    } else {
      if (flash) showMsg(el('auth-msg'), flash, 'alert-warning');
      else hideMsg(el('auth-msg'));
    }
  }

  // Switch navigation tabs
  function setTab(tab) {
    currentTab = tab;
    ['playground', 'admin', 'session'].forEach((t) => {
      el(`nav-${t}`).classList.toggle('active', t === tab);
      el(`panel-${t}`).classList.toggle('hidden', t !== tab);
    });
    if (tab === 'admin') loadAdmin();
    else { clearInterval(auditTimer); auditTimer = null; }
    if (tab === 'session') updateSession();
  }

  // Admin tab rendering & stats computation
  async function loadAdmin() {
    const role = state.user?.role;
    const isViewer = role === 'viewer', isAdmin = role === 'admin';
    el('admin-locked-notice').classList.toggle('hidden', !isViewer);
    el('admin-content').classList.toggle('hidden', isViewer);
    if (isViewer) return;
    el('admin-management-grid').classList.toggle('hidden', !isAdmin);
    if (isAdmin) loadBlockedIps();
    if (el('auto-refresh-audit').checked && !auditTimer) auditTimer = setInterval(loadAuditTrail, 5000);
    await loadAuditTrail();
  }

  async function loadAuditTrail() {
    const act = el('filter-action').value, st = el('filter-status').value, lim = el('filter-limit').value;
    const q = new URLSearchParams();
    if (act) q.set('action', act);
    if (st) q.set('status', st);
    if (lim) q.set('limit', lim);

    el('audit-table-status').textContent = 'Loading audit events...';
    const { status, data } = await api(`/admin/audit?${q}`);
    if (status !== 200 || !Array.isArray(data)) {
      el('audit-table-status').textContent = data.error || 'Failed to load audit logs';
      return;
    }
    el('audit-table-status').textContent = `Displaying ${data.length} event(s).`;

    loadStats(); // the 4 cards always use the latest 200 events, whatever the filters are

    // Build audit table safely
    const tbody = el('audit-table-body');
    tbody.replaceChildren();
    if (!data.length) {
      const tr = mk('tr'), td = mk('td', null, 'No audit records found.');
      td.colSpan = 6; tr.appendChild(td); tbody.appendChild(tr);
      return;
    }

    data.forEach((r) => {
      const tr = mk('tr'), tdSt = mk('td');
      tdSt.appendChild(mk('span', `badge-status badge-${r.status}`, r.status));
      [mk('td', null, fmtTime(r.created_at)), mk('td', null, r.user_id ? String(r.user_id) : '—'), mk('td', null, r.ip || '—'), mk('td', null, r.action), tdSt, mk('td', null, r.meta ? JSON.stringify(r.meta) : '')].forEach((c) => tr.appendChild(c));
      tbody.appendChild(tr);
    });
  }

  // The 4 stat cards: always the latest 200 events, never filtered
  async function loadStats() {
    const { status, data } = await api('/admin/audit?limit=200');
    if (status !== 200 || !Array.isArray(data)) return;
    const count = (fn) => String(data.filter(fn).length);
    el('stat-failed-logins').textContent = count((r) => r.action === 'login' && r.status === 'failed');
    el('stat-blocked-requests').textContent = count((r) => r.action === 'blocked_request');
    el('stat-access-denied').textContent = count((r) => r.action === 'access_denied');
    el('stat-auto-blocks').textContent = count((r) => r.action === 'auto_block');
  }

  // Load and manage Blocked IPs
  async function loadBlockedIps() {
    const { status, data } = await api('/admin/ips');
    const tbody = el('blocked-ips-tbody');
    tbody.replaceChildren();
    if (status !== 200 || !Array.isArray(data) || !data.length) {
      const tr = mk('tr'), td = mk('td', null, 'No blocked IPs.');
      td.colSpan = 4; tr.appendChild(td); tbody.appendChild(tr);
      return;
    }

    data.forEach((item) => {
      const tr = mk('tr'), tdAct = mk('td');
      const btn = mk('button', 'btn btn-outline btn-sm', 'Unblock');
      btn.type = 'button';
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        const res = await api(`/admin/ips/${encodeURIComponent(item.ip)}`, { method: 'DELETE' });
        if (res.status === 200) { loadBlockedIps(); loadAuditTrail(); }
        else { showMsg(el('block-ip-msg'), res.data.error || 'Failed to unblock IP.'); btn.disabled = false; }
      });
      tdAct.appendChild(btn);
      [mk('td', null, item.ip), mk('td', null, item.reason || 'manual'), mk('td', null, item.created_at ? fmtTime(item.created_at) : '—'), tdAct].forEach((c) => tr.appendChild(c));
      tbody.appendChild(tr);
    });
  }

  // Session view and live countdown
  function updateSession() {
    if (!state.user) return;
    el('claim-sub').textContent = state.user.sub || '—';
    el('claim-role').textContent = state.user.role || '—';
    el('claim-type').textContent = state.user.type || 'access';
    el('claim-email').textContent = state.email || '—';
    el('claim-exp').textContent = state.user.exp ? new Date(state.user.exp * 1000).toLocaleTimeString() : '—';
    tickCountdown();
  }

  function tickCountdown() {
    if (!state.user?.exp) { el('claim-countdown').textContent = '—'; return; }
    const sec = state.user.exp - Math.floor(Date.now() / 1000), tag = el('claim-countdown');
    if (sec <= 0) { tag.textContent = 'Expired'; tag.style.color = 'var(--danger)'; }
    else {
      const m = Math.floor(sec / 60), s = sec % 60;
      tag.textContent = `${m}m ${s < 10 ? '0' : ''}${s}s left`;
      tag.style.color = 'var(--accent)';
    }
  }

  function startCountdown() {
    clearInterval(countTimer);
    tickCountdown();
    countTimer = setInterval(tickCountdown, 1000);
  }

  // Event handlers registration
  function setupEvents() {
    // Auth mode toggle
    const setAuthMode = (m) => {
      authMode = m;
      el('auth-tab-login').classList.toggle('active', m === 'login');
      el('auth-tab-register').classList.toggle('active', m === 'register');
      el('auth-submit-btn').textContent = m === 'login' ? 'Log In' : 'Register';
      hideMsg(el('auth-msg'));
    };
    el('auth-tab-login').addEventListener('click', () => setAuthMode('login'));
    el('auth-tab-register').addEventListener('click', () => setAuthMode('register'));

    // Password visibility toggle
    el('show-pw-toggle').addEventListener('change', (e) => { el('auth-password').type = e.target.checked ? 'text' : 'password'; });

    // Auth form submit
    el('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = el('auth-email').value.trim(), password = el('auth-password').value, btn = el('auth-submit-btn');
      if (!email || !password) return showMsg(el('auth-msg'), 'Please provide email and password.');
      if (password.length < 8) return showMsg(el('auth-msg'), 'Password must be at least 8 characters.');

      btn.disabled = true; btn.textContent = 'Please wait...'; hideMsg(el('auth-msg'));
      try {
        if (authMode === 'register') {
          const reg = await api('/auth/register', { method: 'POST', body: { email, password }, auth: false });
          if (reg.status === 409) return showMsg(el('auth-msg'), 'An account with this email already exists.');
          if (reg.status !== 201) return showMsg(el('auth-msg'), reg.data.error || 'Registration failed.');
        }

        const log = await api('/auth/login', { method: 'POST', body: { email, password }, auth: false });
        if (log.status === 401) showMsg(el('auth-msg'), 'Invalid email or password.');
        else if (log.status === 429) showMsg(el('auth-msg'), log.data.error || 'Account temporarily locked. Try again in 15 minutes.');
        else if (log.status === 200 && log.data.access) {
          saveSession(log.data.access, log.data.refresh, email);
          el('auth-password').value = ''; render();
        } else showMsg(el('auth-msg'), log.data.error || 'Login failed.');
      } finally {
        btn.disabled = false; btn.textContent = authMode === 'login' ? 'Log In' : 'Register';
      }
    });

    // Logout actions
    const doLogout = async () => {
      if (state.access && state.refresh) await api('/auth/logout', { method: 'POST', body: { refreshToken: state.refresh } });
      clearSession(); currentTab = 'playground'; render('You have logged out.');
    };
    [el('header-logout-btn'), el('btn-logout')].forEach((b) => b.addEventListener('click', doLogout));

    // Tab switcher
    ['playground', 'admin', 'session'].forEach((t) => el(`nav-${t}`).addEventListener('click', () => setTab(t)));

    // Playground request runners
    const runBtn = async (btn, fn) => { btn.disabled = true; try { await fn(); } finally { btn.disabled = false; } };

    [
      ['btn-get-inventory', '/api/inventory', 'GET', null],
      ['btn-post-inventory', '/api/inventory', 'POST', { item: 'Widget-A', quantity: 10 }],
      ['btn-get-logs', '/api/logs', 'GET', null],
      ['btn-get-audit', '/admin/audit?limit=10', 'GET', null],
    ].forEach(([id, path, method, body]) => {
      el(id).addEventListener('click', (e) => runBtn(e.target, async () => {
        const { status, data, ms, retryAfter } = await api(path, { method, body });
        showResult(status, data, ms, retryAfter);
      }));
    });

    // Rate-limit demo: keep sending requests until the gateway answers 429 (max 130).
    // The default limit is 100 requests per minute per IP, so 15 requests could never trigger it.
    el('btn-spam-test').addEventListener('click', async (e) => {
      const btn = e.target; btn.disabled = true;
      const MAX = 130;
      let sent = 0, allowed = 0, retry = null;
      const t0 = performance.now();
      el('res-explanation').textContent = 'Sending requests until the gateway says 429...';
      try {
        while (sent < MAX) {
          const r = await api('/api/inventory');
          sent++;
          if (r.status === 429) { retry = r.retryAfter; break; }
          if (r.status === 200) allowed++;
          else { showResult(r.status, r.data, r.ms, r.retryAfter); return; } // some other problem
        }
        const ms = Math.round(performance.now() - t0);
        const hit = retry !== null;
        showResult(hit ? 429 : 200, { sent, allowed_200: allowed, rate_limited_429: hit ? 1 : 0, retry_after_seconds: retry }, ms, retry);
        el('res-explanation').textContent = hit
          ? `Rate limit reached after ${allowed} allowed requests. Your IP is blocked for about ${retry || 60}s, so other buttons will show 429 until then.`
          : `${sent} requests were all allowed: the gateway limit is higher than ${MAX} per minute.`;
      } finally { btn.disabled = false; }
    });

    // Broken token demo
    el('btn-bad-token').addEventListener('click', (e) => runBtn(e.target, async () => {
      const { status, data, ms, retryAfter } = await api('/api/inventory', { fakeToken: 'Bearer invalid.token.payload' });
      showResult(status, data, ms, retryAfter);
    }));

    // Admin filter events
    ['filter-action', 'filter-status', 'filter-limit'].forEach((id) => el(id).addEventListener('change', loadAuditTrail));
    el('btn-refresh-audit').addEventListener('click', loadAuditTrail);
    el('auto-refresh-audit').addEventListener('change', (e) => {
      clearInterval(auditTimer); auditTimer = null;
      if (e.target.checked) auditTimer = setInterval(loadAuditTrail, 5000);
    });

    // Block IP Form
    el('block-ip-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const ip = el('block-ip-input').value.trim(), reason = el('block-reason-input').value.trim() || 'Manual console block';
      if (!ip) return;
      const btn = el('btn-block-ip'); btn.disabled = true; hideMsg(el('block-ip-msg'));
      try {
        const res = await api('/admin/ips/block', { method: 'POST', body: { ip, reason } });
        if (res.status === 201) {
          showMsg(el('block-ip-msg'), `IP ${ip} blocked successfully.`, 'alert-success');
          el('block-ip-input').value = ''; el('block-reason-input').value = '';
          loadBlockedIps(); loadAuditTrail();
        } else showMsg(el('block-ip-msg'), res.data.error || 'Failed to block IP.');
      } finally { btn.disabled = false; }
    });

    // Change Role Form
    el('change-role-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const userId = el('role-user-id').value.trim(), role = el('role-select').value;
      if (!userId) return;
      const btn = el('btn-apply-role'); btn.disabled = true; hideMsg(el('change-role-msg'));
      try {
        const res = await api(`/admin/users/${encodeURIComponent(userId)}/role`, { method: 'PATCH', body: { role } });
        if (res.status === 200) {
          showMsg(el('change-role-msg'), `User ${userId} role changed to ${role}.`, 'alert-success');
          loadAuditTrail();
        } else showMsg(el('change-role-msg'), res.data.error || 'Failed to update role.');
      } finally { btn.disabled = false; }
    });

    // Manual Refresh Token button on Session tab
    el('btn-refresh-token').addEventListener('click', async () => {
      const btn = el('btn-refresh-token'); btn.disabled = true; hideMsg(el('session-msg'));
      try {
        const res = await api('/auth/refresh', { method: 'POST', body: { refreshToken: state.refresh }, auth: false });
        if (res.status === 200 && res.data.access) {
          saveSession(res.data.access, res.data.refresh, state.email);
          updateSession(); render();
          showMsg(el('session-msg'), 'Tokens refreshed and rotated successfully.', 'alert-success');
        } else showMsg(el('session-msg'), res.data.error || 'Failed to refresh token.');
      } finally { btn.disabled = false; }
    });
  }

  // App bootstrap
  function init() {
    setupEvents();
    loadSession();
    render();
    checkHealth();
    setInterval(checkHealth, 15000);
  }

  init();
})();