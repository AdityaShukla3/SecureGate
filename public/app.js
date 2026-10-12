// SecureGate Console — 3D Cyber Control Room Frontend Logic
(() => {
  'use strict';

  // App Session State
  const state = { access: null, refresh: null, email: null, user: null };
  let refreshPromise = null, auditTimer = null, countTimer = null;
  let authMode = 'login', currentTab = 'playground';
  let activeAnimId = 0;
  let lastResponseData = null;

  // DOM Helpers
  const el = (id) => document.getElementById(id);
  const mk = (tag, cls, txt) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (txt !== undefined) node.textContent = txt;
    return node;
  };

  // Human-readable date time formatting
  const fmtTime = (iso) => new Date(iso).toLocaleString([], {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });

  // Client-side JWT Payload Decoder
  function decodeJwt(token) {
    try {
      const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      const json = decodeURIComponent(
        atob(b64).split('').map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
      );
      return JSON.parse(json);
    } catch { return null; }
  }

  // Session Storage Management
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

  // Core API Caller with Automatic 401 Token Refresh
  async function api(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (opts.body && typeof opts.body === 'object') headers['Content-Type'] = 'application/json';
    if (opts.auth !== false && state.access) headers.Authorization = `Bearer ${state.access}`;
    if (opts.fakeToken) headers.Authorization = opts.fakeToken;

    const t0 = performance.now();
    let res, data;
    try {
      res = await fetch(path, {
        method: opts.method || 'GET',
        headers,
        body: opts.body ? JSON.stringify(opts.body) : undefined,
      });
      const txt = await res.text();
      try { data = JSON.parse(txt); } catch { data = { raw: txt }; }
    } catch (err) {
      const ms = Math.round(performance.now() - t0);
      return { status: 0, data: { error: err.message || 'Network unreachable' }, ms, retryAfter: null };
    }

    const ms = Math.round(performance.now() - t0);
    const retryHeader = res.headers.get('Retry-After');
    const retryAfter = retryHeader ? Number(retryHeader) : null;

    // Handle 401 token refresh queue
    if (res.status === 401 && !opts._retried && state.refresh && opts.auth !== false && !opts.fakeToken) {
      if (!refreshPromise) {
        refreshPromise = (async () => {
          try {
            const r = await fetch('/auth/refresh', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ refreshToken: state.refresh }),
            });
            if (!r.ok) throw new Error('Refresh failed');
            return await r.json();
          } finally { refreshPromise = null; }
        })();
      }

      try {
        const pair = await refreshPromise;
        saveSession(pair.access, pair.refresh, state.email);
        return api(path, { ...opts, _retried: true });
      } catch {
        clearSession();
        render('Session expired. Please re-authenticate.');
        return { status: 401, data: { error: 'Session expired' }, ms, retryAfter: null };
      }
    }
    return { status: res.status, data, ms, retryAfter };
  }

  // Health Check Poller
  async function checkHealth() {
    const { data } = await api('/health', { auth: false });
    ['db', 'redis'].forEach((k) => {
      const ok = data && data[k] === 'up', pill = el(`${k}-health`);
      if (!pill) return;
      pill.textContent = '';
      pill.appendChild(mk('span', 'pulse-dot'));
      pill.appendChild(document.createTextNode(` ${k.toUpperCase()} ${ok ? 'UP' : 'DOWN'}`));
      pill.className = `health-pill ${ok ? 'up' : 'down'}`;
    });
  }

  // Safe DOM-based JSON Syntax Highlighting (No innerHTML, strictly CSP safe)
  function renderJsonSyntax(container, obj) {
    container.textContent = '';
    if (obj === undefined) { container.textContent = '// No payload'; return; }
    const str = JSON.stringify(obj, null, 2);
    if (!str) { container.textContent = String(obj); return; }

    const tokenRegex = /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\btrue\b|\bfalse\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}[\],:])/g;
    let match, lastIndex = 0;

    while ((match = tokenRegex.exec(str)) !== null) {
      if (match.index > lastIndex) {
        container.appendChild(document.createTextNode(str.slice(lastIndex, match.index)));
      }
      const tok = match[0];
      const span = document.createElement('span');

      if (tok.endsWith(':')) {
        span.className = 'json-tok-key';
        span.textContent = tok.slice(0, -1);
        container.appendChild(span);
        container.appendChild(document.createTextNode(':'));
      } else if (tok.startsWith('"')) {
        span.className = 'json-tok-string';
        span.textContent = tok;
        container.appendChild(span);
      } else if (tok === 'true' || tok === 'false') {
        span.className = 'json-tok-bool';
        span.textContent = tok;
        container.appendChild(span);
      } else if (tok === 'null') {
        span.className = 'json-tok-null';
        span.textContent = tok;
        container.appendChild(span);
      } else if (/^-?\d/.test(tok)) {
        span.className = 'json-tok-num';
        span.textContent = tok;
        container.appendChild(span);
      } else {
        span.className = 'json-tok-punct';
        span.textContent = tok;
        container.appendChild(span);
      }
      lastIndex = tokenRegex.lastIndex;
    }
    if (lastIndex < str.length) {
      container.appendChild(document.createTextNode(str.slice(lastIndex)));
    }
  }

  // ========================================================================
  // Interactive 3D Decision Pipeline Controller
  // ========================================================================

  const STAGE_CONFIG = [
    { num: 1, name: 'IP Block', sub: 'Edge blip filter', icon: '🛡️' },
    { num: 2, name: 'Rate Limit', sub: 'Sliding window Lua', icon: '⏱️' },
    { num: 3, name: 'JWT Auth', sub: 'Signature & blacklist', icon: '🔑' },
    { num: 4, name: 'RBAC Check', sub: 'Role permission match', icon: '⚖️' },
    { num: 5, name: 'Proxying', sub: 'Forward secret header', icon: '🚀' },
    { num: 6, name: 'Audit Log', sub: 'PostgreSQL async write', icon: '📋' },
  ];

  function resetPipelineView() {
    for (let i = 1; i <= 6; i++) {
      const node = el(`pipe-live-${i}`);
      if (!node) continue;
      node.className = 'pipe-step node-3d';
      const chip = node.querySelector('.node-status-chip');
      if (chip) { chip.className = 'node-status-chip chip-idle'; chip.textContent = 'Ready'; }
      const reason = node.querySelector('.node-reason');
      if (reason) reason.textContent = '';
    }
    const pulse = el('pipeline-light-pulse');
    if (pulse) {
      pulse.classList.remove('active');
      pulse.style.transform = 'translate(-50%, -50%)';
    }
  }

  // Position pulse over a target stage node (1 to 6)
  function movePulseToStage(stageNum) {
    const pulse = el('pipeline-light-pulse');
    const container = el('live-pipeline');
    const targetNode = el(`pipe-live-${stageNum}`);
    if (!pulse || !container || !targetNode) return;

    const contRect = container.getBoundingClientRect();
    const nodeRect = targetNode.getBoundingClientRect();
    const xPos = (nodeRect.left + nodeRect.width / 2) - contRect.left;

    pulse.style.transform = `translate(${Math.round(xPos)}px, -50%)`;
    pulse.classList.add('active');
  }

  // Determine which pipeline stage rejected or processed the request
  function resolveTargetStage(status, data) {
    if (status === 403 && data && data.error && data.error.toLowerCase().includes('ip')) {
      return { stage: 1, reason: 'IP blocked at edge (403)' };
    }
    if (status === 429) {
      return { stage: 2, reason: 'Quota exceeded (429)' };
    }
    if (status === 401) {
      return { stage: 3, reason: 'Missing / invalid JWT (401)' };
    }
    if (status === 403) {
      return { stage: 4, reason: 'Role permission denied (403)' };
    }
    if (status === 502 || status === 504) {
      return { stage: 5, reason: 'Upstream service down (502)' };
    }
    if (status >= 200 && status < 300) {
      return { stage: 6, reason: 'Verified & logged (200)' };
    }
    return { stage: 1, reason: `Error ${status || 'Network'}` };
  }

  // Animated pipeline execution synchronized with response
  async function animatePipelineExecution(status, data, animId) {
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const { stage: targetStage, reason } = resolveTargetStage(status, data);
    const isSuccess = status >= 200 && status < 300;

    resetPipelineView();

    if (reducedMotion) {
      // Instant state without animation
      for (let i = 1; i <= 6; i++) {
        const node = el(`pipe-live-${i}`);
        if (!node) continue;
        const chip = node.querySelector('.node-status-chip');
        const reasonEl = node.querySelector('.node-reason');

        if (i < targetStage || (isSuccess && i <= targetStage)) {
          node.classList.add('step-pass');
          if (chip) { chip.className = 'node-status-chip'; chip.textContent = '✔ Passed'; }
        } else if (i === targetStage && !isSuccess) {
          node.classList.add('step-fail');
          if (chip) { chip.className = 'node-status-chip'; chip.textContent = '✖ Blocked'; }
          if (reasonEl) reasonEl.textContent = reason;
        } else {
          node.classList.add('step-bypassed');
          if (chip) { chip.className = 'node-status-chip chip-idle'; chip.textContent = 'Bypassed'; }
        }
      }
      return;
    }

    // Step-by-step pulse traversal with smooth pacing
    for (let i = 1; i <= targetStage; i++) {
      if (activeAnimId !== animId) return; // Cancel if superseded by new request

      movePulseToStage(i);
      const node = el(`pipe-live-${i}`);
      if (node) {
        node.classList.remove('step-pass', 'step-fail', 'step-bypassed');
        node.classList.add('step-evaluating');
        const chip = node.querySelector('.node-status-chip');
        if (chip) { chip.className = 'node-status-chip'; chip.textContent = 'Scanning...'; }
      }

      await new Promise((r) => setTimeout(r, 110));
      if (activeAnimId !== animId) return;

      if (i < targetStage) {
        if (node) {
          node.classList.remove('step-evaluating');
          node.classList.add('step-pass');
          const chip = node.querySelector('.node-status-chip');
          if (chip) { chip.className = 'node-status-chip'; chip.textContent = '✔ Passed'; }
        }
      } else {
        // Target stage reached
        if (node) {
          node.classList.remove('step-evaluating');
          const chip = node.querySelector('.node-status-chip');
          const reasonEl = node.querySelector('.node-reason');

          if (isSuccess) {
            node.classList.add('step-pass');
            if (chip) { chip.className = 'node-status-chip'; chip.textContent = '✔ Logged'; }
            if (reasonEl) reasonEl.textContent = 'Audit recorded';
          } else {
            node.classList.add('step-fail');
            if (chip) { chip.className = 'node-status-chip'; chip.textContent = '✖ Blocked'; }
            if (reasonEl) reasonEl.textContent = reason;
          }
        }
      }
    }

    // Mark downstream nodes as bypassed
    if (!isSuccess) {
      for (let j = targetStage + 1; j <= 6; j++) {
        const nextNode = el(`pipe-live-${j}`);
        if (!nextNode) continue;
        nextNode.classList.add('step-bypassed');
        const chip = nextNode.querySelector('.node-status-chip');
        if (chip) { chip.className = 'node-status-chip chip-idle'; chip.textContent = 'Bypassed'; }
      }
    }
  }

  // ========================================================================
  // Enhanced Response Inspector Console
  // ========================================================================

  function showResult(method, endpoint, status, data, ms, retry) {
    lastResponseData = data;

    // Method and endpoint tag
    const epBadge = el('res-endpoint');
    if (epBadge) epBadge.textContent = `${method} ${endpoint}`;

    // Request latency tag
    const timeTag = el('res-time');
    if (timeTag) timeTag.textContent = `${ms} ms`;

    // Outcome Tag & Status Badge
    const outcomeTag = el('res-outcome');
    const badge = el('res-badge');
    const isSuccess = status >= 200 && status < 300;

    let outcomeText = 'COMPLETED', outcomeCls = 'outcome-ready';
    let badgeCls = 'badge-idle';

    if (isSuccess) {
      outcomeText = 'PASSED (VERIFIED)';
      outcomeCls = 'outcome-success';
      badgeCls = 'badge-2xx';
    } else if (status === 401) {
      outcomeText = 'UNAUTHORIZED';
      outcomeCls = 'outcome-blocked';
      badgeCls = 'badge-401';
    } else if (status === 403) {
      outcomeText = 'FORBIDDEN';
      outcomeCls = 'outcome-blocked';
      badgeCls = 'badge-403';
    } else if (status === 429) {
      outcomeText = 'RATE LIMITED';
      outcomeCls = 'outcome-throttle';
      badgeCls = 'badge-429';
    } else if (status >= 500) {
      outcomeText = 'GATEWAY ERROR';
      outcomeCls = 'outcome-blocked';
      badgeCls = 'badge-5xx';
    }

    if (outcomeTag) {
      outcomeTag.className = `outcome-tag ${outcomeCls}`;
      outcomeTag.textContent = outcomeText;
    }

    if (badge) {
      const statusTitle = status === 200 ? 'OK' : status === 201 ? 'Created' : status === 401 ? 'Unauthorized' : status === 403 ? 'Forbidden' : status === 429 ? 'Too Many Requests' : status === 502 ? 'Bad Gateway' : 'Result';
      badge.className = `status-badge ${badgeCls}`;
      badge.textContent = `${status || 'ERR'} ${statusTitle}`;
    }

    // Concise Security Explanation Callout
    const msgMap = {
      200: 'Request authorized and forwarded. Response proxied back from backend microservice and audited.',
      201: 'Authorized write operation completed on target service. Record created and audited.',
      401: 'Authentication rejected at Stage 3 (JWT Auth): missing, expired, or revoked bearer token.',
      403: 'Access denied at Stage 4 (RBAC Check): operator role lacks required permission for this route.',
      429: retry ? `Throttled at Stage 2 (Rate Limit): sliding window quota exceeded. Retry after ${retry} seconds.` : 'Throttled at Stage 2 (Rate Limit): request rate exceeded.',
      502: 'Proxy error at Stage 5: target backend service is unreachable or offline.',
      504: 'Gateway timeout at Stage 5: downstream service did not respond in time.',
    };
    const expEl = el('res-explanation');
    if (expEl) expEl.textContent = msgMap[status] || (isSuccess ? 'Security checks cleared and request completed successfully.' : 'Request halted by gateway security perimeter.');

    // Retry banner for HTTP 429
    const retryBanner = el('res-retry-banner');
    const retryText = el('res-retry-text');
    if (retryBanner) {
      if (status === 429 && retry) {
        retryBanner.classList.remove('hidden');
        if (retryText) retryText.textContent = `Rate limit in effect. Cooldown window active: ${retry}s remaining before reset.`;
      } else {
        retryBanner.classList.add('hidden');
      }
    }

    // Syntax Highlighted JSON
    const jsonPre = el('res-json');
    if (jsonPre) renderJsonSyntax(jsonPre, data);

    // Trigger Pipeline 3D visualization
    activeAnimId++;
    animatePipelineExecution(status, data, activeAnimId);

    // Highlight Role Matrix
    highlightMatrix(method, endpoint);
  }

  // ========================================================================
  // Enhanced Role & Permissions Matrix
  // ========================================================================

  function updateMatrixColumns() {
    const userRole = state.user ? state.user.role : 'viewer';
    ['viewer', 'analyst', 'admin'].forEach((r) => {
      const col = el(`col-${r}`);
      if (col) col.classList.toggle('active-role', r === userRole);
    });
    const roleLbl = el('matrix-active-role-label');
    if (roleLbl) roleLbl.textContent = userRole;
  }

  function highlightMatrix(method, endpoint) {
    updateMatrixColumns();
    const routeKey = `${method} ${endpoint}`.trim();

    // Clear active row highlights
    document.querySelectorAll('#matrix-table tbody tr').forEach((tr) => {
      tr.classList.remove('active-matrix-row');
    });

    // Map executed endpoint to matrix row
    let targetRow = null;
    if (routeKey.includes('/api/inventory') && method === 'GET') targetRow = el('row-get-inventory');
    else if (routeKey.includes('/api/inventory') && method === 'POST') targetRow = el('row-post-inventory');
    else if (routeKey.includes('/api/logs')) targetRow = el('row-get-logs');
    else if (routeKey.includes('/admin/audit')) targetRow = el('row-get-audit');

    if (targetRow) {
      targetRow.classList.add('active-matrix-row');
    }
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
      updateMatrixColumns();
      setTab(currentTab);
      startCountdown();
    } else {
      if (flash) showMsg(el('auth-msg'), flash, 'alert-warning');
      else hideMsg(el('auth-msg'));
    }
  }

  // Switch Navigation Tabs
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

  // Countdown timer for access token expiry
  function startCountdown() {
    clearInterval(countTimer);
    const update = () => {
      if (!state.user || !state.user.exp) { el('claim-countdown').textContent = '-'; return; }
      const diff = Math.max(0, state.user.exp - Math.floor(Date.now() / 1000));
      const m = Math.floor(diff / 60), s = diff % 60;
      el('claim-countdown').textContent = diff > 0 ? `Expires in ${m}m ${s < 10 ? '0' : ''}${s}s` : 'Token expired';
    };
    update();
    countTimer = setInterval(update, 1000);
  }

  // Update session tab claims list
  function updateSession() {
    if (!state.user) return;
    el('claim-sub').textContent = state.user.sub || state.user.id || '-';
    el('claim-role').textContent = state.user.role || '-';
    el('claim-type').textContent = state.user.type || 'access';
    el('claim-email').textContent = state.email || '-';
    el('claim-exp').textContent = state.user.exp ? new Date(state.user.exp * 1000).toLocaleTimeString() : '-';
  }

  // Admin Tab Controller
  async function loadAdmin() {
    const isViewer = state.user && state.user.role === 'viewer';
    const isAdmin = state.user && state.user.role === 'admin';
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
    const params = new URLSearchParams();
    if (act) params.set('action', act);
    if (st) params.set('status', st);
    if (lim) params.set('limit', lim);

    const { status, data } = await api(`/admin/audit?${params.toString()}`);
    if (status !== 200 || !Array.isArray(data)) {
      el('audit-table-status').textContent = 'Could not load audit log records.';
      return;
    }
    el('audit-table-status').textContent = `Displaying ${data.length} audit record(s).`;
    loadStats();

    const tbody = el('audit-table-body');
    tbody.textContent = '';
    if (data.length === 0) {
      const tr = mk('tr'), td = mk('td', 'text-muted', 'No matching audit records found.');
      td.colSpan = 6; tr.appendChild(td); tbody.appendChild(tr);
      return;
    }

    data.forEach((r) => {
      const tr = mk('tr'), tdSt = mk('td');
      tdSt.appendChild(mk('span', `badge-status badge-${r.status}`, r.status));
      [
        mk('td', 'font-mono text-cyan', fmtTime(r.created_at)),
        mk('td', null, r.user_id ? String(r.user_id) : '—'),
        mk('td', 'font-mono', r.ip || '—'),
        mk('td', 'font-mono', r.action),
        tdSt,
        mk('td', 'text-muted font-mono text-sm', r.meta ? JSON.stringify(r.meta) : '')
      ].forEach((c) => tr.appendChild(c));
      tbody.appendChild(tr);
    });
  }

  async function loadStats() {
    const { status, data } = await api('/admin/audit?limit=200');
    if (status !== 200 || !Array.isArray(data)) return;
    const count = (fn) => String(data.filter(fn).length);
    el('stat-failed-logins').textContent = count((r) => r.action === 'login' && r.status === 'failed');
    el('stat-blocked-requests').textContent = count((r) => r.action === 'blocked_request');
    el('stat-access-denied').textContent = count((r) => r.action === 'access_denied');
    el('stat-auto-blocks').textContent = count((r) => r.action === 'auto_block');
  }

  async function loadBlockedIps() {
    const { status, data } = await api('/admin/ips');
    const tbody = el('blocked-ips-tbody');
    tbody.textContent = '';
    if (status !== 200 || !Array.isArray(data) || data.length === 0) {
      const tr = mk('tr'), td = mk('td', 'text-muted', 'No active IP blocks.');
      td.colSpan = 4; tr.appendChild(td); tbody.appendChild(tr);
      return;
    }

    data.forEach((item) => {
      const tr = mk('tr'), tdAct = mk('td');
      const btn = mk('button', 'btn btn-outline btn-sm cyber-btn-red', 'Unblock');
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        const res = await api(`/admin/ips/${encodeURIComponent(item.ip)}`, { method: 'DELETE' });
        if (res.status === 200) { loadBlockedIps(); loadAuditTrail(); }
        else { showMsg(el('block-ip-msg'), res.data.error || 'Failed to unblock IP.'); btn.disabled = false; }
      });
      tdAct.appendChild(btn);
      [
        mk('td', 'font-mono text-cyan', item.ip),
        mk('td', null, item.reason || 'manual block'),
        mk('td', 'font-mono', item.created_at ? fmtTime(item.created_at) : '—'),
        tdAct
      ].forEach((c) => tr.appendChild(c));
      tbody.appendChild(tr);
    });
  }

  // Google Identity Services (OAuth) State & Handlers
  let googleClientId = null;
  let gisInitialized = false;

  async function initGoogleAuth() {
    try {
      const res = await api('/auth/config', { auth: false });
      if (res.data && res.data.googleClientId) {
        googleClientId = res.data.googleClientId;
      }
    } catch (err) {
      console.warn('Could not fetch auth config:', err);
    }
    setupGisIfReady();
  }

  function setupGisIfReady() {
    if (!googleClientId || gisInitialized || !window.google?.accounts?.id) return;
    try {
      window.google.accounts.id.initialize({
        client_id: googleClientId,
        callback: handleGoogleCredentialResponse,
        auto_select: false,
        cancel_on_tap_outside: true,
      });

      const hiddenDiv = el('gis-hidden-btn');
      if (hiddenDiv) {
        window.google.accounts.id.renderButton(hiddenDiv, {
          theme: 'outline',
          size: 'large',
          type: 'standard',
        });
      }
      gisInitialized = true;
    } catch (e) {
      console.warn('Google Identity Services init error:', e);
    }
  }

  async function handleGoogleCredentialResponse(response) {
    if (!response || !response.credential) {
      showMsg(el('auth-msg'), 'No credential received from Google.');
      return;
    }

    hideMsg(el('auth-msg'));
    const googleBtn = el('btn-google-auth');
    if (googleBtn) googleBtn.disabled = true;

    try {
      const res = await api('/auth/google', {
        method: 'POST',
        body: { credential: response.credential },
        auth: false,
      });

      if (res.status === 200 && res.data.access && res.data.refresh) {
        saveSession(res.data.access, res.data.refresh, res.data.email);
        el('auth-password').value = '';
        render();
      } else {
        showMsg(el('auth-msg'), res.data.error || 'Google authentication failed.');
      }
    } catch (err) {
      showMsg(el('auth-msg'), err.message || 'Network error during Google sign-in.');
    } finally {
      if (googleBtn) googleBtn.disabled = false;
    }
  }

  // Setup Event Listeners
  function setupEvents() {
    // Auth Tabs
    el('auth-tab-login').addEventListener('click', () => {
      authMode = 'login';
      el('auth-tab-login').classList.add('active');
      el('auth-tab-register').classList.remove('active');
      const submitText = el('auth-submit-btn')?.querySelector('.btn-text');
      if (submitText) submitText.textContent = 'Log In';
      const gText = el('google-btn-text');
      if (gText) gText.textContent = 'Sign In with Google';
      hideMsg(el('auth-msg'));
    });
    el('auth-tab-register').addEventListener('click', () => {
      authMode = 'register';
      el('auth-tab-register').classList.add('active');
      el('auth-tab-login').classList.remove('active');
      const submitText = el('auth-submit-btn')?.querySelector('.btn-text');
      if (submitText) submitText.textContent = 'Create Account';
      const gText = el('google-btn-text');
      if (gText) gText.textContent = 'Sign Up with Google';
      hideMsg(el('auth-msg'));
    });

    // Password Visibility Toggle
    el('show-pw-toggle').addEventListener('change', (e) => {
      el('auth-password').type = e.target.checked ? 'text' : 'password';
    });

    // Google OAuth Button Click Trigger
    const googleBtn = el('btn-google-auth');
    if (googleBtn) {
      googleBtn.addEventListener('click', () => {
        hideMsg(el('auth-msg'));
        if (!googleClientId) {
          showMsg(
            el('auth-msg'),
            'Google Client ID is not configured. Please add GOOGLE_CLIENT_ID to your .env file and restart the server.'
          );
          return;
        }

        if (!window.google?.accounts?.id) {
          showMsg(
            el('auth-msg'),
            'Google Identity Services is initializing. Please verify your connection or try again.'
          );
          return;
        }

        setupGisIfReady();

        const hiddenIframeBtn = el('gis-hidden-btn')?.querySelector('div[role="button"]');
        if (hiddenIframeBtn) {
          hiddenIframeBtn.click();
        } else {
          window.google.accounts.id.prompt((notification) => {
            if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
              const btn = el('gis-hidden-btn')?.querySelector('div[role="button"]');
              if (btn) btn.click();
            }
          });
        }
      });
    }

    // Auth Form Submission
    el('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = el('auth-email').value.trim(), password = el('auth-password').value;
      if (!email || !password) { showMsg(el('auth-msg'), 'Please enter both email and password.'); return; }

      const submitBtn = el('auth-submit-btn');
      submitBtn.disabled = true;
      hideMsg(el('auth-msg'));

      try {
        if (authMode === 'register') {
          const res = await api('/auth/register', { method: 'POST', body: { email, password }, auth: false });
          if (res.status === 201) {
            authMode = 'login';
            el('auth-tab-login').click();
            showMsg(el('auth-msg'), 'Registration successful. You can now log in.', 'alert-success');
          } else {
            showMsg(el('auth-msg'), res.data.error || 'Registration failed.');
          }
        } else {
          const res = await api('/auth/login', { method: 'POST', body: { email, password }, auth: false });
          if (res.status === 200 && res.data.access && res.data.refresh) {
            saveSession(res.data.access, res.data.refresh, email);
            el('auth-password').value = '';
            render();
          } else {
            showMsg(el('auth-msg'), res.data.error || 'Invalid credentials or account locked.');
          }
        }
      } finally { submitBtn.disabled = false; }
    });

    // Logout
    const doLogout = async () => {
      if (state.access && state.refresh) await api('/auth/logout', { method: 'POST', body: { refreshToken: state.refresh } });
      clearSession(); currentTab = 'playground'; render('Session terminated.');
    };
    [el('header-logout-btn'), el('btn-logout')].forEach((b) => b.addEventListener('click', doLogout));

    // Nav Switcher
    ['playground', 'admin', 'session'].forEach((t) => el(`nav-${t}`).addEventListener('click', () => setTab(t)));

    // Playground Route Dispatcher
    const runBtn = async (btn, fn) => { btn.disabled = true; try { await fn(); } finally { btn.disabled = false; } };

    [
      ['btn-get-inventory', '/api/inventory', 'GET', null],
      ['btn-post-inventory', '/api/inventory', 'POST', { item: 'Cyber-Sensor-X1', quantity: 15 }],
      ['btn-get-logs', '/api/logs', 'GET', null],
      ['btn-get-audit', '/admin/audit?limit=10', 'GET', null],
    ].forEach(([id, path, method, body]) => {
      el(id).addEventListener('click', (e) => runBtn(e.target.closest('button'), async () => {
        const { status, data, ms, retryAfter } = await api(path, { method, body });
        showResult(method, path, status, data, ms, retryAfter);
      }));
    });

    // Rate-limit burst demo (spams until 429)
    el('btn-spam-test').addEventListener('click', async (e) => {
      const btn = e.target.closest('button'); btn.disabled = true;
      const MAX = 130;
      let sent = 0, allowed = 0, retry = null;
      const t0 = performance.now();
      el('res-explanation').textContent = 'Dispatching rapid burst requests to sliding-window counter...';
      try {
        while (sent < MAX) {
          const r = await api('/api/inventory');
          sent++;
          if (r.status === 429) { retry = r.retryAfter; break; }
          if (r.status === 200) allowed++;
          else { showResult('GET', '/api/inventory', r.status, r.data, r.ms, r.retryAfter); return; }
        }
        const ms = Math.round(performance.now() - t0);
        const hit = retry !== null;
        showResult('BURST', '/api/inventory (x130)', hit ? 429 : 200, {
          total_burst_sent: sent,
          allowed_200: allowed,
          throttled_429: hit ? 1 : 0,
          retry_after_seconds: retry,
          policy: '100 req / minute per IP'
        }, ms, retry);
      } finally { btn.disabled = false; }
    });

    // Invalid Token Test
    el('btn-bad-token').addEventListener('click', (e) => runBtn(e.target.closest('button'), async () => {
      const { status, data, ms, retryAfter } = await api('/api/inventory', { fakeToken: 'Bearer eyJhbGciOiJIUzI1NiJ9.invalid.signature' });
      showResult('FAULT', '/api/inventory', status, data, ms, retryAfter);
    }));

    // Copy JSON Payload
    el('btn-copy-json').addEventListener('click', () => {
      if (!lastResponseData) return;
      const str = JSON.stringify(lastResponseData, null, 2);
      navigator.clipboard.writeText(str).then(() => {
        const txt = el('copy-btn-text');
        txt.textContent = 'Copied!';
        setTimeout(() => { txt.textContent = 'Copy JSON'; }, 2000);
      }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = str; document.body.appendChild(ta); ta.select(); document.execCommand('copy');
        document.body.removeChild(ta);
        const txt = el('copy-btn-text');
        txt.textContent = 'Copied!';
        setTimeout(() => { txt.textContent = 'Copy JSON'; }, 2000);
      });
    });

    // Admin Filters
    ['filter-action', 'filter-status', 'filter-limit'].forEach((id) => el(id).addEventListener('change', loadAuditTrail));
    el('btn-refresh-audit').addEventListener('click', loadAuditTrail);
    el('auto-refresh-audit').addEventListener('change', (e) => {
      clearInterval(auditTimer); auditTimer = null;
      if (e.target.checked) auditTimer = setInterval(loadAuditTrail, 5000);
    });

    // Block IP Form
    el('block-ip-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const ip = el('block-ip-input').value.trim(), reason = el('block-reason-input').value.trim() || 'Manual console edge drop';
      if (!ip) return;
      const btn = el('btn-block-ip'); btn.disabled = true; hideMsg(el('block-ip-msg'));
      try {
        const res = await api('/admin/ips/block', { method: 'POST', body: { ip, reason } });
        if (res.status === 201) {
          showMsg(el('block-ip-msg'), `Edge drop rule created for ${ip}.`, 'alert-success');
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
          showMsg(el('change-role-msg'), `Operator ${userId} privilege updated to ${role}.`, 'alert-success');
          loadAuditTrail();
        } else showMsg(el('change-role-msg'), res.data.error || 'Failed to update role.');
      } finally { btn.disabled = false; }
    });

    // Refresh Token in Session tab
    el('btn-refresh-token').addEventListener('click', async () => {
      const btn = el('btn-refresh-token'); btn.disabled = true; hideMsg(el('session-msg'));
      try {
        const res = await api('/auth/refresh', { method: 'POST', body: { refreshToken: state.refresh }, auth: false });
        if (res.status === 200 && res.data.access) {
          saveSession(res.data.access, res.data.refresh, state.email);
          updateSession(); render();
          showMsg(el('session-msg'), 'Cryptographic tokens rotated successfully.', 'alert-success');
        } else showMsg(el('session-msg'), res.data.error || 'Failed to rotate tokens.');
      } finally { btn.disabled = false; }
    });
  }

  // App Initialization
  function init() {
    setupEvents();
    loadSession();
    render();
    checkHealth();
    initGoogleAuth();
    setInterval(checkHealth, 15000);
    window.addEventListener('load', () => setupGisIfReady());
  }

  init();
})();