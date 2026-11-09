/**
 * SentinelAI block page, caution banner and override pill.
 *
 * Shared by the extension content script (injected before content.js) and
 * the public demo page. Everything renders inside a closed-off Shadow DOM so
 * host page CSS cannot leak in. Fonts: the brand faces are used when the
 * host document has them (demo); real sites fall back to system mono.
 */
(function (root) {
  'use strict';

  if (root.SentinelBlockPage) return;

  const FONT_MONO = '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
  const FONT_SANS = '"IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

  const TOKENS = `
    --canvas: #08090a;
    --card: #121316;
    --line: #1f2124;
    --line-hi: #34373c;
    --ink: #ededed;
    --ink-2: #a1a3a8;
    --ink-3: #6b6e75;
    --ink-4: #3a3d42;
    --accent: #ff5a00;
    --accent-hi: #ff7a2e;
    --danger: #f0464e;
    --warn: #e8c547;
    --snap: cubic-bezier(0.16, 1, 0.3, 1);
  `;

  const SHIELD_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="square" aria-hidden="true"><path d="M12 21s7-3.5 7-9V5l-7-2.5L5 5v7c0 5.5 7 9 7 9z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>';

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m]));
  }

  function pad2(n) {
    return String(Math.max(0, Math.round(n))).padStart(2, '0');
  }

  function mount(id) {
    const host = document.createElement('div');
    host.id = id;
    const shadow = host.attachShadow({ mode: 'open' });
    (document.documentElement || document.body).appendChild(host);
    return { host, shadow };
  }

  // ------------------------------------------------------------------------
  // Full-screen block page
  // ------------------------------------------------------------------------

  /**
   * @param {Object} report  assessment (hostname, riskScore, brandMatch, attackChain, evidence, scamCoachTip, modelVersion)
   * @param {Object} handlers { onLeave(), onProceed() } - each receives a close() helper
   * @returns {HTMLElement} host element
   */
  function show(report, handlers = {}) {
    const existing = document.getElementById('sentinel-warning-overlay-host');
    if (existing) return existing;

    const { host, shadow } = mount('sentinel-warning-overlay-host');
    const risk = Math.round((report.riskScore ?? 0.95) * 100);
    const hostname = report.hostname || location.hostname;
    const brand = report.brandMatch;
    const facts = (report.attackChain && report.attackChain.observedFacts) || [];
    const evidence = (report.evidence || []).slice(0, 4);
    const coach = report.scamCoachTip || 'Never type a password on a page you reached from a link. Open the site yourself instead.';
    const model = report.modelVersion || 'rf-local';

    const headline = brand
      ? `This page is pretending to be <em>${esc(brand)}</em>.`
      : 'This link looks like a <em>phishing trap</em>.';

    const factRows = (facts.length ? facts : ['Suspicious URL structure and deceptive hostname characteristics.'])
      .slice(0, 4)
      .map((f, i) => `<li><span class="n">${pad2(i + 1)}</span><span>${esc(f)}</span></li>`)
      .join('');

    const evidenceRows = evidence
      .map((e, i) => `
        <li>
          <span class="n">${pad2(i + 1)}</span>
          <span><small>${esc(e.category || 'Signal')}</small>${esc(e.detail || e.title || e)}</span>
          <b class="${e.severity === 'high' ? 'hi' : ''}">${e.severity === 'high' ? 'HIGH' : e.severity === 'low' ? 'LOW' : 'MED'}</b>
        </li>`)
      .join('');

    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          ${TOKENS}
          position: fixed !important;
          inset: 0 !important;
          z-index: 2147483647 !important;
          display: block !important;
          overflow-y: auto !important;
          background: rgba(8, 9, 10, 0.985) !important;
          color: var(--ink);
          font-family: ${FONT_SANS};
          font-size: 15px;
          line-height: 1.5;
          -webkit-font-smoothing: antialiased;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ul, ol { list-style: none; }
        button { font: inherit; color: inherit; background: none; border: 0; cursor: pointer; }
        button:focus-visible { outline: 1px solid var(--accent); outline-offset: 3px; }

        .r {
          opacity: 0;
          transform: translate3d(0, 10px, 0);
          animation: in 600ms var(--snap) forwards;
          animation-delay: calc(var(--i, 0) * 45ms + 60ms);
        }
        @keyframes in { to { opacity: 1; transform: none; } }
        @media (prefers-reduced-motion: reduce) { .r { animation: none; opacity: 1; transform: none; } }

        .hazard {
          height: 6px;
          background: repeating-linear-gradient(-45deg, var(--danger) 0 10px, transparent 10px 20px);
          opacity: 0.85;
          transform-origin: 0 50%;
          animation: sweep 700ms var(--snap) both;
        }
        @keyframes sweep { from { transform: scaleX(0); } to { transform: scaleX(1); } }

        .sheet {
          max-width: 860px;
          margin: 0 auto;
          padding: 28px clamp(16px, 4vw, 40px) 40px;
        }

        .top {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 16px;
        }
        .mark {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          font-family: ${FONT_MONO};
          font-weight: 800;
          font-size: 13px;
          letter-spacing: -0.02em;
        }
        .mark i {
          width: 20px; height: 20px;
          display: grid; place-items: center;
          background: var(--danger); color: var(--canvas);
        }
        .mark i svg { width: 12px; height: 12px; }
        .mark span { color: var(--ink-4); }
        .tag {
          font-family: ${FONT_MONO};
          font-weight: 800;
          font-size: 11px;
          letter-spacing: 0.1em;
          padding: 4px 8px;
          background: var(--danger);
          color: var(--canvas);
        }

        .label {
          display: block;
          font-family: ${FONT_MONO};
          font-size: 11px;
          letter-spacing: 0.14em;
          text-transform: uppercase;
          color: var(--ink-3);
        }

        h1 {
          margin-top: 56px;
          font-family: ${FONT_MONO};
          font-weight: 800;
          font-size: clamp(34px, 5.6vw, 64px);
          line-height: 0.98;
          letter-spacing: -0.055em;
        }
        h1 em { font-style: normal; color: var(--danger); }

        .target {
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          gap: 0;
          margin-top: 36px;
          border: 1px solid var(--line-hi);
        }
        .target > div { padding: 16px 18px; min-width: 0; }
        .target > div + div { border-left: 1px solid var(--line-hi); text-align: right; }
        .host {
          display: block;
          margin-top: 8px;
          font-family: ${FONT_MONO};
          font-size: 18px;
          color: var(--ink);
          word-break: break-all;
          text-decoration: line-through;
          text-decoration-color: var(--danger);
          text-decoration-thickness: 2px;
        }
        .risk {
          display: block;
          margin-top: 4px;
          font-family: ${FONT_SANS};
          font-weight: 600;
          font-size: 44px;
          line-height: 0.9;
          letter-spacing: -0.05em;
        }
        .risk small { font-size: 13px; font-weight: 400; letter-spacing: 0; color: var(--ink-3); }

        .cols {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 32px;
          margin-top: 36px;
        }
        .col h2 {
          padding-bottom: 8px;
          border-bottom: 1px solid var(--line);
          font-family: ${FONT_MONO};
          font-weight: 800;
          font-size: 12px;
          letter-spacing: 0;
          text-transform: uppercase;
        }
        .col li {
          display: grid;
          grid-template-columns: 26px 1fr auto;
          gap: 6px;
          align-items: baseline;
          padding: 10px 0;
          border-bottom: 1px solid var(--line);
          font-size: 13.5px;
          color: var(--ink-2);
        }
        .col li .n { font-family: ${FONT_MONO}; font-size: 10px; color: var(--ink-4); }
        .col li small {
          display: block;
          font-family: ${FONT_MONO};
          font-size: 10px;
          letter-spacing: 0.06em;
          text-transform: uppercase;
          color: var(--ink-3);
        }
        .col li b { font-family: ${FONT_MONO}; font-size: 10px; letter-spacing: 0.08em; font-weight: 400; color: var(--ink-3); }
        .col li b.hi { background: var(--danger); color: var(--canvas); padding: 0 4px; font-weight: 800; }

        .guard {
          display: flex;
          gap: 12px;
          align-items: baseline;
          margin-top: 28px;
          padding: 14px 16px;
          background: var(--card);
          border-left: 2px solid var(--accent);
          font-size: 14px;
          color: var(--ink-2);
        }
        .guard b {
          flex: 0 0 auto;
          font-family: ${FONT_MONO};
          font-weight: 800;
          font-size: 11px;
          letter-spacing: 0.1em;
          color: var(--ink);
        }

        .actions {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
          margin-top: 36px;
          padding-top: 24px;
          border-top: 1px solid var(--line);
        }
        .leave {
          display: inline-flex;
          align-items: center;
          gap: 14px;
          height: 54px;
          padding: 0 26px;
          background: var(--accent);
          color: #0b0b0b;
          font-family: ${FONT_MONO};
          font-weight: 800;
          font-size: 14px;
          letter-spacing: 0.02em;
          text-transform: uppercase;
          transition: transform 220ms var(--snap), background-color 120ms linear;
        }
        .leave:hover { background: var(--accent-hi); }
        .leave:hover .arr { transform: translate3d(-3px, 0, 0); }
        .leave:active { transform: scale(0.96); transition-duration: 50ms; }
        .arr { display: inline-block; transition: transform 200ms var(--snap); }

        .proceed {
          font-family: ${FONT_MONO};
          font-size: 12px;
          color: var(--ink-3);
          border-bottom: 1px solid var(--line-hi);
          padding-bottom: 2px;
          transition: color 120ms linear, border-color 0ms;
        }
        .proceed:hover { color: var(--ink); border-bottom-color: var(--ink); }

        .foot {
          display: flex;
          justify-content: space-between;
          gap: 16px;
          margin-top: 28px;
          font-family: ${FONT_MONO};
          font-size: 11px;
          color: var(--ink-4);
        }

        @media (max-width: 640px) {
          h1 { margin-top: 40px; }
          .cols { grid-template-columns: 1fr; gap: 24px; }
          .target { grid-template-columns: 1fr; }
          .target > div + div { border-left: 0; border-top: 1px solid var(--line-hi); text-align: left; }
          .leave { width: 100%; justify-content: center; }
          .foot { flex-direction: column; }
        }
      </style>

      <div class="hazard" aria-hidden="true"></div>
      <div class="sheet" role="alertdialog" aria-modal="true" aria-labelledby="sx-title">
        <div class="top r" style="--i:0">
          <span class="mark"><i>${SHIELD_SVG}</i>SENTINEL<span>/</span>AI</span>
          <span class="tag">BLOCKED</span>
        </div>

        <h1 id="sx-title" class="r" style="--i:1">Stop. ${headline}</h1>

        <div class="target r" style="--i:2">
          <div>
            <span class="label">You were about to open</span>
            <span class="host">${esc(hostname)}</span>
          </div>
          <div>
            <span class="label">Risk</span>
            <span class="risk">${pad2(risk)}<small>/100</small></span>
          </div>
        </div>

        <div class="cols">
          <section class="col r" style="--i:3">
            <h2>What we saw</h2>
            <ol>${factRows}</ol>
          </section>
          <section class="col r" style="--i:4">
            <h2>Evidence</h2>
            <ol>${evidenceRows || '<li><span class="n">01</span><span>High-confidence model verdict.</span><b class="hi">HIGH</b></li>'}</ol>
          </section>
        </div>

        <p class="guard r" style="--i:5"><b>LOCKED</b><span>Password fields on this page are disabled. ${esc(coach)}</span></p>

        <div class="actions r" style="--i:6">
          <button class="leave" id="sx-leave" type="button"><span class="arr">&larr;</span> Back to safety</button>
          <button class="proceed" id="sx-proceed" type="button">I understand the risk, continue</button>
        </div>

        <div class="foot r" style="--i:7">
          <span>Model ${esc(model)} &middot; analysed on this device</span>
          <span>You can undo this from the extension popup</span>
        </div>
      </div>
    `;

    const close = () => host.remove();
    const leaveBtn = shadow.getElementById('sx-leave');
    leaveBtn.addEventListener('click', () => (handlers.onLeave ? handlers.onLeave(close) : close()));
    shadow.getElementById('sx-proceed').addEventListener('click', () => (handlers.onProceed ? handlers.onProceed(close) : close()));
    setTimeout(() => leaveBtn.focus({ preventScroll: true }), 50);

    return host;
  }

  // ------------------------------------------------------------------------
  // Caution banner (suspicious, non-blocking)
  // ------------------------------------------------------------------------

  function banner(report, handlers = {}) {
    if (document.getElementById('sentinel-top-banner-host') || document.getElementById('sentinel-warning-overlay-host')) return null;
    const { host, shadow } = mount('sentinel-top-banner-host');
    const risk = Math.round((report.riskScore ?? 0.5) * 100);
    const signals = (report.evidence || []).length;

    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          ${TOKENS}
          position: fixed !important;
          top: 0 !important;
          left: 0 !important;
          right: 0 !important;
          z-index: 2147483646 !important;
          display: block !important;
          font-family: ${FONT_SANS};
          -webkit-font-smoothing: antialiased;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        button { font: inherit; color: inherit; background: none; border: 0; cursor: pointer; }
        .bar {
          display: flex;
          align-items: center;
          gap: 14px;
          min-height: 46px;
          padding: 6px 10px 6px 14px;
          background: var(--card);
          border-bottom: 2px solid var(--warn);
          color: var(--ink);
          font-size: 13px;
          transform: translate3d(0, -100%, 0);
          animation: drop 520ms var(--snap) 80ms forwards;
        }
        @keyframes drop { to { transform: none; } }
        @media (prefers-reduced-motion: reduce) { .bar { animation: none; transform: none; } }
        .chip {
          flex: 0 0 auto;
          font-family: ${FONT_MONO};
          font-weight: 800;
          font-size: 10px;
          letter-spacing: 0.1em;
          padding: 2px 6px;
          border: 1px solid var(--warn);
          color: var(--warn);
        }
        .msg { flex: 1; min-width: 0; color: var(--ink-2); }
        .msg b { color: var(--ink); font-weight: 600; }
        .back {
          flex: 0 0 auto;
          height: 30px;
          padding: 0 12px;
          border: 1px solid var(--line-hi);
          font-family: ${FONT_MONO};
          font-weight: 800;
          font-size: 11px;
          text-transform: uppercase;
          transition: border-color 0ms, transform 50ms linear;
        }
        .back:hover { border-color: var(--ink); }
        .back:active { transform: scale(0.96); }
        .x {
          flex: 0 0 auto;
          width: 30px;
          height: 30px;
          font-family: ${FONT_MONO};
          color: var(--ink-3);
        }
        .x:hover { color: var(--ink); }
        @media (max-width: 560px) { .msg span { display: none; } }
      </style>
      <div class="bar" role="status">
        <span class="chip">CAUTION</span>
        <p class="msg"><b>${signals} warning sign${signals === 1 ? '' : 's'} on this page</b> <span>&middot; risk ${pad2(risk)}/100. Think twice before entering a password.</span></p>
        <button class="back" id="sb-back" type="button">Go back</button>
        <button class="x" id="sb-close" type="button" aria-label="Dismiss">&times;</button>
      </div>
    `;

    const close = () => host.remove();
    shadow.getElementById('sb-back').addEventListener('click', () => (handlers.onLeave ? handlers.onLeave(close) : close()));
    shadow.getElementById('sb-close').addEventListener('click', () => (handlers.onClose ? handlers.onClose(close) : close()));
    return host;
  }

  // ------------------------------------------------------------------------
  // Sticky override pill
  // ------------------------------------------------------------------------

  function pill(report, onReopen) {
    if (document.getElementById('sentinel-sticky-badge-host')) return null;
    const { host, shadow } = mount('sentinel-sticky-badge-host');
    const risk = Math.round((report.riskScore ?? 0.8) * 100);

    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          ${TOKENS}
          position: fixed !important;
          right: 18px !important;
          bottom: 18px !important;
          z-index: 2147483647 !important;
          display: block !important;
          font-family: ${FONT_MONO};
        }
        button {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          height: 36px;
          padding: 0 12px 0 10px;
          background: var(--card);
          border: 1px solid var(--danger);
          color: var(--ink);
          font: inherit;
          font-size: 11px;
          letter-spacing: 0.04em;
          cursor: pointer;
          transform: translate3d(0, 12px, 0);
          opacity: 0;
          animation: up 480ms var(--snap) forwards;
          transition: transform 220ms var(--snap);
        }
        @keyframes up { to { transform: none; opacity: 1; } }
        button:hover { transform: translate3d(0, -2px, 0); }
        button:active { transform: scale(0.96); transition-duration: 50ms; }
        i { width: 6px; height: 6px; background: var(--danger); animation: blink 1.6s steps(1, end) infinite; }
        @keyframes blink { 50% { opacity: 0.2; } }
        b { font-weight: 800; color: var(--danger); }
      </style>
      <button type="button" id="pill" title="Review the SentinelAI warning"><i></i>OVERRIDDEN <b>${pad2(risk)}</b></button>
    `;

    shadow.getElementById('pill').addEventListener('click', () => {
      host.remove();
      if (onReopen) onReopen();
    });
    return host;
  }

  root.SentinelBlockPage = { show, banner, pill };
})(typeof window !== 'undefined' ? window : this);
