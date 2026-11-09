/**
 * SentinelAI: Phishing & Scam Link Shield
 * Popup Controller (Manifest V3)
 *
 * Renders the active tab assessment, the Guard/Trust domain policy control,
 * observed evidence and the recent scan log. When opened outside the
 * extension (plain file:// preview) it falls back to sample data.
 */

document.addEventListener('DOMContentLoaded', () => {
  const $ = (id) => document.getElementById(id);

  const els = {
    chip: $('status-chip'),
    chipText: $('status-chip-text'),
    modelVersion: $('model-version'),
    protocol: $('protocol'),
    host: $('host'),
    path: $('path'),
    impersonation: $('impersonation'),
    brandName: $('brand-name'),
    verdictWord: $('verdict-word'),
    summary: $('summary'),
    score: $('score'),
    confidence: $('confidence'),
    ticks: $('ticks'),
    pBenign: $('p-benign'),
    pPhish: $('p-phish'),
    seg: $('seg'),
    rescan: $('btn-rescan'),
    evidenceCount: $('evidence-count'),
    evidenceList: $('evidence-list'),
    logStats: $('log-stats'),
    logBody: $('log-body'),
    console: $('btn-console')
  };

  const TICK_COUNT = 50;
  const LOG_ROWS = 4;
  const hasRuntime = typeof chrome !== 'undefined' && !!chrome.runtime?.id;

  let currentTabId = null;
  let currentAssessment = null;

  // Stagger entrance: each [data-r] block gets its index; CSS multiplies by 15ms.
  document.querySelectorAll('[data-r]').forEach((node, i) => node.style.setProperty('--i', i));

  // Build tick strip once; renders only toggle classes.
  const tickFrag = document.createDocumentFragment();
  for (let i = 0; i < TICK_COUNT; i++) tickFrag.appendChild(document.createElement('i'));
  els.ticks.appendChild(tickFrag);
  const ticks = Array.from(els.ticks.children);

  // --------------------------------------------------------------------------
  // Messaging
  // --------------------------------------------------------------------------

  function send(message) {
    if (!hasRuntime) return Promise.resolve(mockResponse(message));
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(message, (res) => {
        resolve(chrome.runtime.lastError ? null : res);
      });
    });
  }

  // --------------------------------------------------------------------------
  // Rendering
  // --------------------------------------------------------------------------

  function verdictOf(report) {
    if (report.whitelisted || report.riskLevel === 'WHITELISTED') return 'trusted';
    if (report.riskLevel === 'INTERNAL') return 'system';
    if (report.verdict) return report.verdict;
    const s = report.riskScore ?? 0;
    return s >= 0.75 ? 'malicious' : s >= 0.4 ? 'suspicious' : 'safe';
  }

  const VERDICT_COPY = {
    trusted: { word: 'TRUSTED', tone: 'ok', tag: 'TRST' },
    system: { word: 'SYSTEM', tone: 'idle', tag: 'SYS' },
    malicious: { word: 'HOSTILE', tone: 'danger', tag: 'BLCK' },
    suspicious: { word: 'SUSPECT', tone: 'warn', tag: 'SUSP' },
    unknown: { word: 'UNKNOWN', tone: 'idle', tag: '??' },
    safe: { word: 'CLEAR', tone: 'ok', tag: 'OK' }
  };

  function splitUrl(raw) {
    try {
      const u = new URL(raw);
      return { protocol: u.protocol.replace(':', ''), rest: (u.pathname + u.search) || '/' };
    } catch (e) {
      return { protocol: '', rest: raw || '' };
    }
  }

  function pad2(n) {
    return String(Math.max(0, Math.round(n))).padStart(2, '0');
  }

  function renderReport(report) {
    currentAssessment = report;
    if (!report) return;

    const v = verdictOf(report);
    const copy = VERDICT_COPY[v] || VERDICT_COPY.unknown;
    const { protocol, rest } = splitUrl(report.url || '');

    els.host.textContent = report.hostname || 'unknown host';
    els.path.textContent = rest;

    if (v === 'system') {
      els.protocol.textContent = 'INTERNAL';
      els.protocol.dataset.insecure = 'false';
    } else {
      els.protocol.textContent = (protocol || 'n/a').toUpperCase();
      els.protocol.dataset.insecure = String(protocol === 'http');
    }

    if (report.brandMatch) {
      els.brandName.textContent = report.brandMatch;
      els.impersonation.classList.remove('hidden');
    } else {
      els.impersonation.classList.add('hidden');
    }

    els.verdictWord.textContent = copy.word;
    els.verdictWord.dataset.tone = copy.tone;
    els.summary.textContent = report.summary || report.statusText || 'Analysis complete.';

    const muted = v === 'trusted' || v === 'system';
    const risk = muted ? 0 : Math.round((report.riskScore ?? 0) * 100);
    els.score.textContent = pad2(risk);
    els.confidence.textContent = `conf ${Math.round((report.confidence ?? 0.85) * 100)}%`;

    const pPhish = report.probabilities?.phishing ?? (report.riskScore || 0);
    const pBenign = report.probabilities?.benign ?? (1 - pPhish);
    els.pBenign.textContent = `${Math.round(pBenign * 100)}%`;
    els.pPhish.textContent = `${Math.round(pPhish * 100)}%`;
    renderTicks(muted ? 0 : pPhish);

    els.chip.dataset.state = copy.tone === 'danger' ? 'alert' : v === 'system' ? 'idle' : 'armed';
    els.chipText.textContent = copy.tone === 'danger' ? 'THREAT' : v === 'system' ? 'IDLE' : 'ARMED';

    if (report.modelVersion) els.modelVersion.textContent = report.modelVersion;

    setMode(report.whitelisted ? 'trust' : 'guard', false);
    els.seg.querySelectorAll('.seg-opt').forEach((b) => { b.disabled = v === 'system'; });

    renderEvidence(report.evidence || []);
  }

  function renderTicks(p) {
    const lit = Math.round(Math.max(0, Math.min(1, p)) * TICK_COUNT);
    ticks.forEach((t, i) => {
      // Right-to-left fill, 4ms per tick so the bar "ratchets" in rather than sliding.
      const idx = TICK_COUNT - 1 - i;
      t.style.transitionDelay = `${idx * 4}ms`;
      t.classList.toggle('on', i >= TICK_COUNT - lit);
      t.classList.toggle('edge', lit > 0 && i === TICK_COUNT - lit);
    });
  }

  function renderEvidence(list) {
    els.evidenceCount.textContent = pad2(list.length);
    els.evidenceList.replaceChildren();

    if (list.length === 0) {
      const li = document.createElement('li');
      li.className = 'ev-clean';
      const b = document.createElement('b');
      b.textContent = 'NIL';
      li.append(b, 'No impersonation, raw IP or credential lures observed.');
      els.evidenceList.appendChild(li);
      return;
    }

    list.forEach((item, i) => {
      const li = document.createElement('li');
      li.className = 'ev';
      const sev = (typeof item === 'object' && item.severity) || 'medium';
      li.dataset.sev = sev;

      const n = document.createElement('span');
      n.className = 'ev-n';
      n.textContent = pad2(i + 1);

      const text = document.createElement('span');
      text.className = 'ev-text';
      if (typeof item === 'object' && item.category) {
        const cat = document.createElement('small');
        cat.textContent = item.category;
        text.appendChild(cat);
      }
      text.append(typeof item === 'string' ? item : (item.detail || item.title || ''));

      const sevEl = document.createElement('span');
      sevEl.className = 'ev-sev';
      sevEl.textContent = sev === 'high' ? 'HIGH' : sev === 'low' ? 'LOW' : 'MED';

      li.append(n, text, sevEl);
      els.evidenceList.appendChild(li);
    });
  }

  function relAge(ts) {
    const s = Math.max(0, (Date.now() - (ts || Date.now())) / 1000);
    if (s < 60) return `${Math.floor(s)}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m`;
    if (s < 86400) return `${Math.floor(s / 3600)}h`;
    return `${Math.floor(s / 86400)}d`;
  }

  function renderLog(history) {
    els.logBody.replaceChildren();

    if (!history.length) {
      const tr = document.createElement('tr');
      tr.className = 'log-empty';
      const td = document.createElement('td');
      td.colSpan = 4;
      td.textContent = 'Nothing scanned yet.';
      tr.appendChild(td);
      els.logBody.appendChild(tr);
      els.logStats.textContent = '—';
      return;
    }

    const flagged = history.filter((h) => ['malicious', 'suspicious'].includes(verdictOf(h))).length;
    const avg = history.reduce((sum, h) => sum + (h.riskScore || 0), 0) / history.length;
    els.logStats.replaceChildren(
      bold(history.length), ' seen · ', bold(flagged), ' flagged · avg ', bold(pad2(avg * 100))
    );

    history.slice(0, LOG_ROWS).forEach((h) => {
      const copy = VERDICT_COPY[verdictOf(h)] || VERDICT_COPY.unknown;
      const tr = document.createElement('tr');
      tr.dataset.tone = copy.tone;
      tr.title = h.url || '';

      const age = cell('lg-age', relAge(h.timestamp));
      const host = cell('lg-host');
      const hostInner = document.createElement('span');
      hostInner.textContent = h.hostname || h.url || '—';
      host.appendChild(hostInner);
      const score = cell('lg-score', pad2((h.riskScore || 0) * 100));
      const tag = cell('lg-tag', copy.tag);

      tr.append(age, host, score, tag);
      els.logBody.appendChild(tr);
    });
  }

  function cell(cls, text) {
    const td = document.createElement('td');
    td.className = cls;
    if (text != null) td.textContent = text;
    return td;
  }

  function bold(text) {
    const b = document.createElement('b');
    b.textContent = text;
    return b;
  }

  function renderFallback(message) {
    els.summary.textContent = message;
    els.score.textContent = '--';
    els.verdictWord.textContent = 'STANDBY';
    els.verdictWord.dataset.tone = 'idle';
    els.chip.dataset.state = 'idle';
    els.chipText.textContent = 'IDLE';
  }

  // --------------------------------------------------------------------------
  // Command zone
  // --------------------------------------------------------------------------

  function setMode(mode, kick) {
    els.seg.dataset.mode = mode;
    els.seg.querySelectorAll('.seg-opt').forEach((b) => {
      b.setAttribute('aria-checked', String(b.dataset.mode === mode));
    });
    if (kick) {
      els.seg.classList.remove('is-kick');
      void els.seg.offsetWidth; // restart the thud animation
      els.seg.classList.add('is-kick');
    }
  }

  async function chooseMode(mode) {
    if (!currentAssessment?.hostname) return;
    const willTrust = mode === 'trust';
    if (!!currentAssessment.whitelisted === willTrust) return;

    setMode(mode, true); // optimistic; reverted below if the background refuses
    const res = await send({
      action: 'TOGGLE_WHITELIST',
      hostname: currentAssessment.hostname,
      whitelist: willTrust,
      tabId: currentTabId
    });

    if (res?.success) {
      currentAssessment.whitelisted = willTrust;
      if (!willTrust && currentAssessment.riskLevel === 'WHITELISTED') currentAssessment.riskLevel = null;
      renderReport(currentAssessment);
      // Background re-analyses the tab after a policy change; pick up the fresh result.
      setTimeout(loadActiveReport, 350);
    } else {
      setMode(willTrust ? 'guard' : 'trust', false);
    }
  }

  els.seg.addEventListener('click', (e) => {
    const opt = e.target.closest('.seg-opt');
    if (opt && !opt.disabled) chooseMode(opt.dataset.mode);
  });

  async function rescan() {
    if (!currentTabId || els.rescan.classList.contains('is-busy')) return;
    els.rescan.classList.add('is-busy');
    const started = performance.now();
    const res = await send({ action: 'RESCAN_TAB', tabId: currentTabId });
    // Hold the busy state long enough to read as deliberate, never as a flicker.
    const wait = Math.max(0, 420 - (performance.now() - started));
    setTimeout(() => {
      els.rescan.classList.remove('is-busy');
      if (res?.success && res.assessment) renderReport(res.assessment);
      loadHistory();
    }, wait);
  }

  els.rescan.addEventListener('click', rescan);

  els.console.addEventListener('click', () => {
    send({ action: 'OPEN_DASHBOARD', view: 'overview' });
  });

  document.addEventListener('keydown', (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const k = e.key.toLowerCase();
    if (k === 'r') rescan();
    else if (k === 'g') chooseMode('guard');
    else if (k === 't') chooseMode('trust');
  });

  // --------------------------------------------------------------------------
  // Loading
  // --------------------------------------------------------------------------

  async function loadActiveReport() {
    try {
      const tab = hasRuntime
        ? (await chrome.tabs.query({ active: true, currentWindow: true }))[0]
        : { id: 1 };
      if (!tab?.id) {
        renderFallback('No active browser tab found.');
        return;
      }
      currentTabId = tab.id;

      const res = await send({ action: 'GET_SCAN_DATA', tabId: currentTabId });
      if (res?.success && res.assessment) renderReport(res.assessment);
      else if (res === null) renderFallback('Connecting to the background engine…');
      else renderFallback('Waiting for page scan…');
    } catch (e) {
      renderFallback('Error querying browser tab.');
    }
  }

  async function loadHistory() {
    const res = await send({ action: 'GET_SCAN_HISTORY' });
    renderLog(res?.success ? res.history || [] : []);
  }

  loadActiveReport();
  loadHistory();

  // When embedded by the demo testbench, render whatever the parent page scanned.
  if (!hasRuntime) {
    window.addEventListener('message', (e) => {
      if (e.origin !== location.origin || !e.data) return;
      if (e.data.type === 'sentinel:assessment') renderReport(e.data.assessment);
      if (e.data.type === 'sentinel:history') renderLog(e.data.history || []);
    });
  }

  // --------------------------------------------------------------------------
  // Preview data (only used when opened outside the extension)
  // --------------------------------------------------------------------------

  function mockResponse(message) {
    const now = Date.now();
    const sample = {
      url: 'https://paypa1-account-verify.co/secure/login?session=8812',
      hostname: 'paypa1-account-verify.co',
      verdict: 'malicious',
      riskScore: 0.86,
      confidence: 0.92,
      brandMatch: 'PayPal',
      whitelisted: false,
      modelVersion: 'rf-20261106-b43b81',
      probabilities: { benign: 0.14, phishing: 0.86 },
      summary: 'Lookalike domain swaps "l" for "1" and serves a credential form posting to an unrelated host.',
      evidence: [
        { category: 'Brand', detail: 'Homoglyph of paypal.com in registrable domain', severity: 'high' },
        { category: 'DOM', detail: 'Password field submits cross-origin', severity: 'high' },
        { category: 'Lexical', detail: '3 lure keywords: account, verify, secure', severity: 'medium' }
      ]
    };
    switch (message.action) {
      case 'GET_SCAN_DATA':
      case 'RESCAN_TAB':
        return { success: true, assessment: { ...sample, ...(currentAssessment && { whitelisted: currentAssessment.whitelisted }) } };
      case 'TOGGLE_WHITELIST':
        return { success: true };
      case 'GET_SCAN_HISTORY':
        return {
          success: true,
          history: [
            { hostname: 'paypa1-account-verify.co', verdict: 'malicious', riskScore: 0.86, timestamp: now - 4000 },
            { hostname: 'github.com', verdict: 'safe', riskScore: 0.03, timestamp: now - 6 * 60e3 },
            { hostname: 'bit.ly', verdict: 'suspicious', riskScore: 0.47, timestamp: now - 22 * 60e3 },
            { hostname: 'docs.google.com', verdict: 'safe', riskScore: 0.05, timestamp: now - 2 * 3600e3 },
            { hostname: 'bad-login-phish.xyz', verdict: 'malicious', riskScore: 0.71, timestamp: now - 3 * 86400e3 },
            { hostname: 'news.ycombinator.com', verdict: 'safe', riskScore: 0.02, timestamp: now - 4 * 86400e3 }
          ]
        };
      default:
        return { success: true };
    }
  }
});
