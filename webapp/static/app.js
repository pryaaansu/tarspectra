// ==========================================================================
// TARSPECTRA v2.5 — JAVASCRIPT WORKBENCH CONTROLLER
// Matrix Rain Canvas, Hierarchical Site Map Tree & True-Positive Report
// ==========================================================================

const state = {
  currentScan: null,
  activeTab: 'sitemap', // 'sitemap' | 'findings'
  severityFilter: 'all',
  sourceFilter: 'all',
  searchQuery: '',
  sitemapQuery: '',
  pollTimer: null,
  eventSource: null,
  matrixRainActive: true,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

const escapeHtml = (str) =>
  String(str ?? '').replace(/[&<>'"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c])
  );

// ─────────────────────────────────────────────────────────────────────────────
// 1. MATRIX DIGITAL RAIN CANVAS ENGINE
// ─────────────────────────────────────────────────────────────────────────────
(function initMatrixRain() {
  const canvas = $('#matrix-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    initDrops();
  });

  // Matrix characters: Katakana, Latin, Digits, Math symbols
  const characters = 'ｦｱｳｴｵｶｷｹｺｻｼｽｾｿﾀﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗﾘﾜ1234567890ABCDEF<>{}/*+=~';
  const fontSize = 14;
  let columns = Math.floor(width / fontSize);
  let drops = [];

  function initDrops() {
    columns = Math.floor(width / fontSize);
    drops = [];
    for (let i = 0; i < columns; i++) {
      drops[i] = Math.random() * -100;
    }
  }
  initDrops();

  let lastTime = 0;
  const fps = 28;
  const interval = 1000 / fps;

  function render(currentTime) {
    if (state.matrixRainActive) {
      const delta = currentTime - lastTime;
      if (delta > interval) {
        lastTime = currentTime - (delta % interval);

        ctx.fillStyle = 'rgba(4, 9, 19, 0.08)';
        ctx.fillRect(0, 0, width, height);

        ctx.font = `${fontSize}px monospace`;

        for (let i = 0; i < drops.length; i++) {
          const char = characters.charAt(Math.floor(Math.random() * characters.length));
          const x = i * fontSize;
          const y = drops[i] * fontSize;

          // Bright neon head
          ctx.fillStyle = '#ffffff';
          ctx.shadowBlur = 8;
          ctx.shadowColor = '#00ff88';
          ctx.fillText(char, x, y);

          // Trail color
          ctx.fillStyle = '#00ff88';
          ctx.shadowBlur = 0;

          if (y > height && Math.random() > 0.985) {
            drops[i] = 0;
          }
          drops[i]++;
        }
      }
    }
    requestAnimationFrame(render);
  }
  requestAnimationFrame(render);

  const toggleBtn = $('#toggle-rain');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      state.matrixRainActive = !state.matrixRainActive;
      canvas.classList.toggle('paused', !state.matrixRainActive);
      toggleBtn.classList.toggle('rain-active', state.matrixRainActive);
    });
  }
})();

// ─────────────────────────────────────────────────────────────────────────────
// 2. API REQUEST WRAPPER
// ─────────────────────────────────────────────────────────────────────────────
async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body.error || 'Server returned an error.');
  }
  return body;
}

function showMessage(text = '', type = '') {
  const el = $('#form-message');
  el.textContent = text;
  el.className = `form-message ${type}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. LIVE STATUS & SSE LOG STREAMING
// ─────────────────────────────────────────────────────────────────────────────
function updateProgress(scan) {
  const panel = $('#status-panel');
  panel.classList.remove('hidden');

  const status = scan.status || 'queued';
  $('#scan-status').textContent = status.toUpperCase();
  $('#status-stage').textContent = scan.error || scan.stage || 'In progress…';

  const dot = $('#status-dot');
  dot.className = `status-dot ${status === 'completed' ? 'complete' : status === 'failed' ? 'failed' : ''}`;

  const prog = scan.progress || {};
  const found = prog.pages_found || 0;
  const scanned = prog.pages_scanned || 0;
  const subs = prog.subdomains_found || 0;
  const findings = prog.total_findings || 0;

  $('#metric-subdomains').textContent = subs;
  $('#metric-pages-found').textContent = found;
  $('#metric-pages-scanned').textContent = scanned;
  $('#metric-findings').textContent = findings;

  const pct =
    status === 'completed'
      ? 100
      : found > 0
      ? Math.min(92, Math.max(8, Math.round((scanned / found) * 100)))
      : 8;

  $('#progress-fill').style.width = `${pct}%`;
}

function startSseStream(scanId) {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }

  const logBox = $('#log-output');
  logBox.textContent = '';

  const es = new EventSource(`/api/scans/${scanId}/stream`);
  state.eventSource = es;

  es.addEventListener('message', (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.log) {
        logBox.textContent += data.log + '\n';
        logBox.scrollTop = logBox.scrollHeight;
      }
    } catch (_) {}
  });

  es.addEventListener('done', () => {
    es.close();
    state.eventSource = null;
  });

  es.onerror = () => {
    es.close();
    state.eventSource = null;
  };
}

$('#toggle-log-btn').addEventListener('click', () => {
  const drawer = $('#log-drawer');
  drawer.classList.toggle('hidden');
});
$('#clear-log-btn').addEventListener('click', () => {
  $('#log-output').textContent = '';
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. SEPARATE VIEW 1: SITE MAP & SUBDOMAINS HIERARCHY
// ─────────────────────────────────────────────────────────────────────────────
function renderSiteMap(sitemap) {
  if (!sitemap || !sitemap.subdomains) return;

  $('#sitemap-root-domain').textContent = sitemap.root_domain || 'Target Domain';
  $('#sitemap-total-subs').textContent = sitemap.total_subdomains || 0;
  $('#sitemap-total-eps').textContent = sitemap.total_endpoints || 0;
  $('#sitemap-count-pill').textContent = `${sitemap.total_subdomains} subs / ${sitemap.total_endpoints} eps`;

  const container = $('#subdomains-tree-list');
  const query = state.sitemapQuery.trim().toLowerCase();
  const subEntries = Object.entries(sitemap.subdomains);

  if (!subEntries.length) {
    container.innerHTML = '<p class="empty-state">No subdomains discovered.</p>';
    return;
  }

  const html = subEntries
    .map(([host, info]) => {
      const endpoints = (info.endpoints || []).filter((ep) => {
        if (!query) return true;
        return (
          host.includes(query) ||
          ep.path.toLowerCase().includes(query) ||
          ep.path_with_query.toLowerCase().includes(query) ||
          (ep.params || []).some((p) => p.toLowerCase().includes(query))
        );
      });

      // Skip this subdomain card if search query filters out all its endpoints and doesn't match host
      if (query && !host.includes(query) && !endpoints.length) {
        return '';
      }

      const status = info.status_code;
      const statusClass =
        status === 200 ? 'status-200' : String(status).startsWith('3') ? 'status-300' : status > 0 ? 'status-400' : 'status-unknown';

      const endpointsHtml = endpoints
        .map((ep) => {
          const methodClass = ep.forms_count > 0 ? 'method-post' : 'method-get';
          const methodLabel = ep.forms_count > 0 ? 'POST' : 'GET';
          const epStatus = ep.status_code || 200;
          const paramsBadge = (ep.params || []).length
            ? `<span class="param-pill" title="Parameters: ${escapeHtml(ep.params.join(', '))}">?${escapeHtml(ep.params.join(', '))}</span>`
            : '';
          const formBadge = ep.forms_count > 0 ? `<span class="form-pill">Forms: ${ep.forms_count}</span>` : '';

          return `
          <div class="endpoint-row">
            <div class="endpoint-left">
              <span class="method-badge ${methodClass}">${methodLabel}</span>
              <a href="${escapeHtml(ep.url)}" target="_blank" rel="noopener noreferrer" class="endpoint-path" title="${escapeHtml(ep.url)}">
                ${escapeHtml(ep.path_with_query || ep.path || '/')}
              </a>
            </div>
            <div class="endpoint-right">
              ${paramsBadge}
              ${formBadge}
              <span class="status-pill ${epStatus === 200 ? 'status-200' : 'status-300'}">${epStatus}</span>
              <button type="button" class="tiny-btn copy-url-btn" data-url="${escapeHtml(ep.url)}" title="Copy full URL">Copy</button>
            </div>
          </div>`;
        })
        .join('');

      return `
      <article class="subdomain-card" data-host="${escapeHtml(host)}">
        <div class="subdomain-header">
          <div class="subdomain-title-group">
            <span class="subdomain-toggle-icon">▼</span>
            <span class="subdomain-host">🖥️ ${escapeHtml(host)}</span>
            ${info.is_target_host ? '<span class="badge-target-host">Target Apex</span>' : ''}
            ${info.server ? `<span class="subdomain-server">Server: ${escapeHtml(info.server)}</span>` : ''}
          </div>
          <div class="subdomain-badges">
            ${status > 0 ? `<span class="status-pill ${statusClass}">${status}</span>` : '<span class="status-pill status-unknown">Passive</span>'}
            <span class="ep-count-pill">${endpoints.length} endpoints</span>
          </div>
        </div>
        <div class="endpoints-list">
          ${endpointsHtml || '<p class="empty-state">No matching endpoints under this subdomain.</p>'}
        </div>
      </article>`;
    })
    .join('');

  container.innerHTML = html || '<p class="empty-state">No subdomains or endpoints match filter.</p>';

  // Bind click-to-collapse on subdomain headers
  $$('.subdomain-header').forEach((hdr) => {
    hdr.addEventListener('click', () => {
      const card = hdr.closest('.subdomain-card');
      card.classList.toggle('collapsed');
    });
  });

  // Bind copy URL buttons
  $$('.copy-url-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      navigator.clipboard.writeText(btn.dataset.url);
      const prev = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => (btn.textContent = prev), 1500);
    });
  });
}

// Expand / Collapse All Subdomains
$('#expand-all-subs').addEventListener('click', () => {
  $$('.subdomain-card').forEach((c) => c.classList.remove('collapsed'));
});
$('#collapse-all-subs').addEventListener('click', () => {
  $$('.subdomain-card').forEach((c) => c.classList.add('collapsed'));
});
$('#sitemap-search').addEventListener('input', (e) => {
  state.sitemapQuery = e.target.value;
  if (state.currentScan?.sitemap) {
    renderSiteMap(state.currentScan.sitemap);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. SEPARATE VIEW 2: TRUE-POSITIVE VULNERABILITY REPORT
// ─────────────────────────────────────────────────────────────────────────────
function renderFindings(scan) {
  const findings = scan.consolidated_findings || [];
  $('#findings-count-pill').textContent = findings.length;

  const summary = scan.summary || { by_severity: {}, by_source: {} };
  const sevMap = summary.by_severity || {};

  $('#cnt-high').textContent = (sevMap.high || 0) + (sevMap.critical || 0);
  $('#cnt-medium').textContent = sevMap.medium || 0;
  $('#cnt-low').textContent = sevMap.low || 0;
  const toolHits = findings.filter((f) => ['nuclei', 'nikto', 'nmap', 'sqlmap'].includes(f.source)).length;
  $('#cnt-tools').textContent = toolHits;

  const container = $('#finding-list');
  const search = state.searchQuery.trim().toLowerCase();

  const filtered = findings.filter((f) => {
    const sev = (f.severity || 'low').toLowerCase();
    const src = (f.source || 'passive').toLowerCase();

    const matchSev = state.severityFilter === 'all' || sev === state.severityFilter;
    const matchSrc = state.sourceFilter === 'all' || src.includes(state.sourceFilter);

    const searchable = `${f.title || f.type} ${f.url} ${f.evidence} ${f.remediation} ${src}`.toLowerCase();
    const matchSearch = !search || searchable.includes(search);

    return matchSev && matchSrc && matchSearch;
  });

  if (!filtered.length) {
    container.innerHTML = '<p class="empty-state">No vulnerabilities match current filter criteria.</p>';
    return;
  }

  container.innerHTML = filtered
    .map((f) => {
      const sev = (f.severity || 'low').toLowerCase();
      const title = f.title || f.type || 'Security Signal';
      const conf = f.confidence || 'Medium';
      const src = f.source || 'passive';
      const scope = f.scope || 'Audited Resource';
      const curlCmd = f.curl_command || '';

      const curlBlock = curlCmd
        ? `<div class="curl-repro-block">
             <code>${escapeHtml(curlCmd)}</code>
             <button type="button" class="tiny-btn copy-curl-btn" data-curl="${escapeHtml(curlCmd)}">Copy cURL</button>
           </div>`
        : '';

      return `
      <article class="finding-card" data-severity="${escapeHtml(sev)}">
        <div class="finding-topline">
          <span class="sev-badge ${escapeHtml(sev)}">${escapeHtml(sev.toUpperCase())}</span>
          <span class="source-badge">${escapeHtml(src.toUpperCase())}</span>
          <span class="conf-badge">${escapeHtml(conf)}</span>
          <span class="scope-badge">${escapeHtml(scope)}</span>
        </div>
        <h3>${escapeHtml(title)}</h3>
        <a href="${escapeHtml(f.url)}" target="_blank" rel="noopener noreferrer" class="finding-url-link">${escapeHtml(f.url)}</a>
        <div class="finding-evidence-block">${escapeHtml(f.evidence || 'Verified through active response evaluation.')}</div>
        ${curlBlock}
        <details class="finding-remediation" open>
          <summary>Remediation Guidance</summary>
          <p>${escapeHtml(f.remediation || 'Apply defense-in-depth hardening to the affected component.')}</p>
        </details>
      </article>`;
    })
    .join('');

  $$('.copy-curl-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.curl);
      btn.textContent = 'Copied!';
      setTimeout(() => (btn.textContent = 'Copy cURL'), 1500);
    });
  });
}

// Switch between Main Tabs (Site Map vs Vulnerability Report)
$('#tab-sitemap-btn').addEventListener('click', () => {
  state.activeTab = 'sitemap';
  $('#tab-sitemap-btn').classList.add('active');
  $('#tab-findings-btn').classList.remove('active');
  $('#sitemap-view').classList.add('active');
  $('#sitemap-view').classList.remove('hidden');
  $('#findings-view').classList.remove('active');
  $('#findings-view').classList.add('hidden');
});

$('#tab-findings-btn').addEventListener('click', () => {
  state.activeTab = 'findings';
  $('#tab-findings-btn').classList.add('active');
  $('#tab-sitemap-btn').classList.remove('active');
  $('#findings-view').classList.add('active');
  $('#findings-view').classList.remove('hidden');
  $('#sitemap-view').classList.remove('active');
  $('#sitemap-view').classList.add('hidden');
});

// Findings filter events
$('#finding-search').addEventListener('input', (e) => {
  state.searchQuery = e.target.value;
  if (state.currentScan) renderFindings(state.currentScan);
});

$('#severity-filters').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-severity]');
  if (!btn) return;
  state.severityFilter = btn.dataset.severity;
  $$('#severity-filters .f-pill').forEach((b) => b.classList.toggle('active', b === btn));
  if (state.currentScan) renderFindings(state.currentScan);
});

$('#source-filters').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-source]');
  if (!btn) return;
  state.sourceFilter = btn.dataset.source;
  $$('#source-filters .f-pill').forEach((b) => b.classList.toggle('active', b === btn));
  if (state.currentScan) renderFindings(state.currentScan);
});

// Download Action Handlers
$('#download-sitemap-btn').addEventListener('click', () => {
  if (state.currentScan?.id) {
    window.location.assign(`/api/scans/${state.currentScan.id}/download-sitemap`);
  }
});
$('#download-report-btn').addEventListener('click', () => {
  if (state.currentScan?.id) {
    window.location.assign(`/api/scans/${state.currentScan.id}/download`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. SCAN LIFECYCLE & POLLING
// ─────────────────────────────────────────────────────────────────────────────
async function pollScan(scanId) {
  clearTimeout(state.pollTimer);
  try {
    const scan = await api(`/api/scans/${scanId}`);
    state.currentScan = scan;
    updateProgress(scan);
    await loadHistory();

    if (scan.status === 'completed') {
      $('#start-scan').disabled = false;
      showMessage('Assessment complete! Review the Site Map and Vulnerability tabs.', 'success');
      $('#results-panel').classList.remove('hidden');

      if (scan.sitemap) renderSiteMap(scan.sitemap);
      renderFindings(scan);
      return;
    }

    if (scan.status === 'failed') {
      $('#start-scan').disabled = false;
      showMessage(scan.error || 'Scan encountered a failure.', '');
      return;
    }

    state.pollTimer = setTimeout(() => pollScan(scanId), 1200);
  } catch (err) {
    $('#start-scan').disabled = false;
    showMessage(err.message);
  }
}

// Scan Form Submission
$('#scan-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#start-scan');
  btn.disabled = true;
  showMessage('Initializing scanner & engines…', 'success');

  $('#results-panel').classList.add('hidden');
  $('#log-drawer').classList.remove('hidden');

  const payload = {
    target: $('#target').value.trim(),
    max_pages: parseInt($('#max-pages').value, 10),
    max_depth: parseInt($('#max-depth').value, 10),
    tool_timeout: parseInt($('#tool-timeout').value, 10),
    run_nuclei: $('#run-nuclei').checked,
    run_subfinder: $('#run-subfinder').checked,
    run_nikto: $('#run-nikto').checked,
    run_nmap: $('#run-nmap').checked,
    run_sqlmap: $('#run-sqlmap').checked,
    safe_reflection: $('#safe-reflection').checked,
    check_headers: $('#check-headers') ? $('#check-headers').checked : true,
    authorization: $('#authorization').checked,
  };

  try {
    const scan = await api('/api/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    state.currentScan = scan;
    updateProgress(scan);
    startSseStream(scan.id);
    await pollScan(scan.id);
  } catch (err) {
    btn.disabled = false;
    showMessage(err.message);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. HISTORY & TOOLS INITIALIZATION
// ─────────────────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const data = await api('/api/scans');
    const scans = data.scans || [];
    const container = $('#history-list');

    if (!scans.length) {
      container.innerHTML = '<p class="empty-state">No assessments in this session.</p>';
      return;
    }

    container.innerHTML = scans
      .map(
        (s) => `
      <div class="history-row" data-id="${s.id}">
        <span class="history-target" title="${escapeHtml(s.target)}">${escapeHtml(s.target)}</span>
        <span class="history-meta">${s.progress?.subdomains_found || 0} subs · ${s.progress?.pages_scanned || 0} pages · ${s.progress?.total_findings || 0} findings</span>
        <span class="history-status ${escapeHtml(s.status)}">${escapeHtml(s.status)}</span>
      </div>`
      )
      .join('');

    $$('.history-row').forEach((row) => {
      row.addEventListener('click', async () => {
        const id = row.dataset.id;
        showMessage('Loading past scan…', 'success');
        const scan = await api(`/api/scans/${id}`);
        state.currentScan = scan;
        updateProgress(scan);
        $('#results-panel').classList.remove('hidden');
        if (scan.sitemap) renderSiteMap(scan.sitemap);
        renderFindings(scan);
      });
    });
  } catch (_) {}
}

async function checkSystem() {
  try {
    await api('/api/health');
    const pill = $('#connection');
    pill.innerHTML = '<span class="pulse-dot"></span> Workbench Ready';

    const toolsData = await api('/api/tools');
    const installed = toolsData.tools || {};

    const toolElemMap = {
      nuclei: '#run-nuclei',
      subfinder: '#run-subfinder',
      nikto: '#run-nikto',
      nmap: '#run-nmap',
      sqlmap: '#run-sqlmap',
    };

    for (const [tool, sel] of Object.entries(toolElemMap)) {
      const el = $(sel);
      if (el && !installed[tool]) {
        el.disabled = true;
        el.checked = false;
        el.closest('.tool-checkbox-card').style.opacity = '0.5';
      }
    }
  } catch (_) {
    $('#connection').innerHTML = '<span style="color:var(--sev-high)">● Disconnected</span>';
  }
}

// Initialize on Load
checkSystem();
loadHistory();
