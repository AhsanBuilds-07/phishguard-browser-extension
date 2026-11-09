/**
 * SentinelAI landing page
 * Motion: GSAP + ScrollTrigger + SplitText, smooth scroll via Lenis.
 * The hero scanner runs the real on-device model through SentinelScan.
 */
(function () {
  'use strict';

  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const hasGsap = typeof window.gsap !== 'undefined';
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const SNAP = 'expo.out';

  if (hasGsap) {
    gsap.registerPlugin(ScrollTrigger, SplitText);
    gsap.defaults({ ease: SNAP, duration: 0.9 });
  }

  // ------------------------------------------------------------------------
  // Toast
  // ------------------------------------------------------------------------

  const toastEl = $('#toast');
  let toastTimer;
  function toast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2800);
  }

  // ------------------------------------------------------------------------
  // Smooth scroll
  // ------------------------------------------------------------------------

  let lenis = null;
  if (!reduced && typeof window.Lenis !== 'undefined') {
    lenis = new Lenis({ lerp: 0.11, wheelMultiplier: 1, smoothWheel: true });
    if (hasGsap) {
      lenis.on('scroll', ScrollTrigger.update);
      gsap.ticker.add((t) => lenis.raf(t * 1000));
      gsap.ticker.lagSmoothing(0);
    } else {
      const raf = (t) => { lenis.raf(t); requestAnimationFrame(raf); };
      requestAnimationFrame(raf);
    }
  }

  function scrollToTarget(target) {
    if (lenis) lenis.scrollTo(target, { offset: -72, duration: 1.2, easing: (t) => 1 - Math.pow(1 - t, 4) });
    else target.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth' });
  }

  $$('a[href^="#"]').forEach((a) => {
    a.addEventListener('click', (e) => {
      const id = a.getAttribute('href');
      const target = id.length > 1 && document.querySelector(id);
      if (!target) return;
      e.preventDefault();
      closeMenu();
      scrollToTarget(target);
    });
  });

  // ------------------------------------------------------------------------
  // Nav
  // ------------------------------------------------------------------------

  const nav = $('#nav');
  const burger = $('#nav-burger');
  let lastY = 0;

  function onScroll(y) {
    nav.classList.toggle('is-scrolled', y > 12);
    const goingDown = y > lastY && y > 400;
    nav.classList.toggle('is-hidden', goingDown && !nav.classList.contains('is-open'));
    lastY = y;
  }

  if (lenis) lenis.on('scroll', ({ scroll }) => onScroll(scroll));
  else window.addEventListener('scroll', () => onScroll(window.scrollY), { passive: true });

  function closeMenu() {
    nav.classList.remove('is-open');
    burger.setAttribute('aria-expanded', 'false');
  }

  burger.addEventListener('click', () => {
    const open = !nav.classList.contains('is-open');
    nav.classList.toggle('is-open', open);
    burger.setAttribute('aria-expanded', String(open));
  });

  // ------------------------------------------------------------------------
  // Hero entrance
  // ------------------------------------------------------------------------

  const strike = $('#hero-strike');

  if (hasGsap && !reduced) {
    const tl = gsap.timeline({ delay: 0.1 });
    tl.from('.hero-title .line-in', { yPercent: 110, duration: 1.1, stagger: 0.09 })
      .from('[data-hero]', { y: 24, opacity: 0, duration: 1, stagger: 0.07 }, 0.25)
      .to(strike, { '--strike': 1, duration: 0.7, ease: 'power3.inOut' }, 0.95)
      .from('.hero-field', { opacity: 0, duration: 1.6, ease: 'none' }, 0);
  } else {
    strike.style.setProperty('--strike', 1);
  }

  // ------------------------------------------------------------------------
  // Count-ups
  // ------------------------------------------------------------------------

  function countUp(el) {
    const end = parseFloat(el.dataset.count);
    const decimals = parseInt(el.dataset.decimals || '0', 10);
    const prefix = el.dataset.prefix || '';
    const suffix = el.dataset.suffix || '';
    const sup = el.querySelector('sup');
    const text = document.createTextNode('');
    el.replaceChildren(text);
    if (sup) el.appendChild(sup);
    const obj = { v: 0 };
    const render = () => {
      text.nodeValue = `${prefix}${obj.v.toFixed(decimals)}${suffix}`;
    };
    if (!hasGsap || reduced || end === 0) { obj.v = end; render(); return; }
    gsap.to(obj, { v: end, duration: 1.6, ease: 'power3.out', onUpdate: render });
  }

  // ------------------------------------------------------------------------
  // Scroll reveals
  // ------------------------------------------------------------------------

  if (hasGsap && !reduced) {
    $$('[data-split]').forEach((el) => {
      SplitText.create(el, {
        type: 'lines',
        mask: 'lines',
        linesClass: 'split-line',
        autoSplit: true,
        onSplit(self) {
          return gsap.from(self.lines, {
            yPercent: 105,
            duration: 1.1,
            stagger: 0.08,
            scrollTrigger: { trigger: el, start: 'top 85%', once: true }
          });
        }
      });
    });

    ScrollTrigger.batch('[data-reveal]', {
      start: 'top 88%',
      once: true,
      onEnter: (els) => gsap.to(els, { opacity: 1, y: 0, duration: 1, stagger: 0.08 })
    });

    $$('[data-count]').forEach((el) => {
      if (el.closest('[data-hero]')) {
        gsap.delayedCall(0.8, () => countUp(el));
      } else {
        ScrollTrigger.create({ trigger: el, start: 'top 90%', once: true, onEnter: () => countUp(el) });
      }
    });
  } else {
    $$('[data-reveal]').forEach((el) => { el.style.opacity = 1; el.style.transform = 'none'; });
  }

  // ------------------------------------------------------------------------
  // Ticker: constant drift, accelerated by scroll velocity
  // ------------------------------------------------------------------------

  const track = $('#ticker-track');
  if (track) {
    track.innerHTML += track.innerHTML; // seamless loop
    if (hasGsap && !reduced) {
      const loop = gsap.to(track, { xPercent: -50, duration: 46, ease: 'none', repeat: -1 });
      if (lenis) {
        lenis.on('scroll', ({ velocity }) => {
          const boost = 1 + Math.min(Math.abs(velocity) / 6, 5);
          gsap.to(loop, { timeScale: velocity < 0 ? -boost : boost, duration: 0.3, overwrite: true });
        });
      }
    }
  }

  // ------------------------------------------------------------------------
  // Pipeline: rail fills with scroll, steps light up, readout types values
  // ------------------------------------------------------------------------

  const steps = $$('.step');
  const fill = $('#steps-fill');

  function typeInto(el, text, hit) {
    if (el.dataset.done) return;
    el.dataset.done = '1';
    el.classList.toggle('hit', !!hit);
    if (reduced) { el.textContent = text; return; }
    let i = 0;
    el.textContent = '';
    const tick = () => {
      el.textContent = text.slice(0, ++i);
      if (i < text.length) setTimeout(tick, 18 + Math.random() * 22);
    };
    tick();
  }

  function lightStep(step) {
    step.classList.add('is-on');
    const ro = document.getElementById(step.dataset.ro);
    if (ro) typeInto(ro, step.dataset.val, step.hasAttribute('data-hit'));
  }

  if (hasGsap && !reduced) {
    gsap.to(fill, {
      scaleY: 1,
      ease: 'none',
      scrollTrigger: { trigger: '#steps', start: 'top 60%', end: 'bottom 60%', scrub: 0.4 }
    });
    steps.forEach((step) => {
      ScrollTrigger.create({ trigger: step, start: 'top 62%', once: true, onEnter: () => lightStep(step) });
    });
  } else {
    if (fill) fill.style.transform = 'scaleY(1)';
    steps.forEach(lightStep);
  }

  // ------------------------------------------------------------------------
  // Feature spotlight follows the cursor
  // ------------------------------------------------------------------------

  $$('[data-spot]').forEach((card) => {
    card.addEventListener('pointermove', (e) => {
      const r = card.getBoundingClientRect();
      card.style.setProperty('--mx', `${e.clientX - r.left}px`);
      card.style.setProperty('--my', `${e.clientY - r.top}px`);
    });
  });

  // ------------------------------------------------------------------------
  // Homoglyph swap loop
  // ------------------------------------------------------------------------

  const glyphWord = $('#glyph-word');
  if (glyphWord) {
    const swappable = $$('span[data-alt]', glyphWord);
    let swapped = false;
    const swap = () => {
      swapped = !swapped;
      swappable.forEach((s, i) => {
        const apply = () => {
          if (swapped) {
            s.dataset.orig = s.dataset.orig || s.textContent;
            s.textContent = s.dataset.alt;
            s.classList.add('swapped');
          } else {
            s.textContent = s.dataset.orig || s.textContent;
            s.classList.remove('swapped');
          }
        };
        if (hasGsap && !reduced) {
          gsap.timeline({ delay: i * 0.12 })
            .to(s, { yPercent: -30, opacity: 0, duration: 0.18, ease: 'power2.in' })
            .add(apply)
            .fromTo(s, { yPercent: 30, opacity: 0 }, { yPercent: 0, opacity: 1, duration: 0.5 });
        } else {
          apply();
        }
      });
    };
    let glyphTimer = null;
    const start = () => { if (!glyphTimer) { swap(); glyphTimer = setInterval(swap, 2600); } };
    const stop = () => { clearInterval(glyphTimer); glyphTimer = null; };
    if (hasGsap) {
      ScrollTrigger.create({ trigger: glyphWord, start: 'top 85%', end: 'bottom 10%', onToggle: (s) => (s.isActive ? start() : stop()) });
    } else {
      start();
    }
  }

  // ------------------------------------------------------------------------
  // Live scanner
  // ------------------------------------------------------------------------

  const TICKS = 60;
  const scanner = $('#scanner');
  const form = $('#scanner-form');
  const input = $('#scan-input');
  const el = {
    status: $('#scan-status'),
    host: $('#scan-host'),
    verdict: $('#scan-verdict'),
    score: $('#scan-score'),
    conf: $('#scan-conf'),
    ticks: $('#scan-ticks'),
    pb: $('#scan-pb'),
    pp: $('#scan-pp'),
    evidence: $('#scan-evidence'),
    model: $('#scan-model'),
    time: $('#scan-time'),
    scanline: $('#scanline')
  };

  for (let i = 0; i < TICKS; i++) el.ticks.appendChild(document.createElement('i'));
  const tickEls = Array.from(el.ticks.children);

  const VERDICTS = {
    malicious: { word: 'HOSTILE', tone: 'danger' },
    suspicious: { word: 'SUSPECT', tone: 'warn' },
    unknown: { word: 'UNSURE', tone: 'warn' },
    safe: { word: 'CLEAR', tone: 'ok' }
  };

  const GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ#/%&*+=<>';

  function scramble(node, finalText, duration = 520) {
    if (reduced) { node.textContent = finalText; return; }
    let start = null;
    const frame = (now) => {
      if (start === null) start = now;
      const p = Math.min(1, Math.max(0, (now - start) / duration));
      const settled = Math.floor(p * finalText.length);
      let out = finalText.slice(0, settled);
      for (let i = settled; i < finalText.length; i++) out += GLYPHS[(Math.random() * GLYPHS.length) | 0];
      node.textContent = out;
      if (p < 1) requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  }

  function pad2(n) {
    return String(Math.max(0, Math.round(n))).padStart(2, '0');
  }

  function renderTicks(p, tone) {
    const lit = Math.round(Math.max(0, Math.min(1, p)) * TICKS);
    el.ticks.dataset.tone = tone;
    tickEls.forEach((t, i) => {
      t.style.transitionDelay = reduced ? '0ms' : `${i * 6}ms`;
      t.classList.toggle('on', i < lit);
    });
  }

  function renderEvidence(report) {
    el.evidence.replaceChildren();
    const items = (report.evidence || []).slice(0, 4);
    if (!items.length) {
      const li = document.createElement('li');
      li.className = 'clean';
      li.textContent = 'No impersonation, raw IP, lure keywords or risky TLD found.';
      el.evidence.appendChild(li);
      return;
    }
    items.forEach((item, i) => {
      const li = document.createElement('li');
      const n = document.createElement('span');
      n.className = 'n';
      n.textContent = pad2(i + 1);
      const text = document.createElement('span');
      text.textContent = item.detail || item.title || String(item);
      const sev = document.createElement('span');
      sev.className = `sev ${item.severity === 'high' ? 'high' : ''}`;
      sev.textContent = item.severity === 'high' ? 'HIGH' : item.severity === 'low' ? 'LOW' : 'MED';
      li.append(n, text, sev);
      el.evidence.appendChild(li);
    });
    if (hasGsap && !reduced) {
      gsap.from(el.evidence.children, { x: -8, opacity: 0, duration: 0.6, stagger: 0.05 });
    }
  }

  function runScan(url) {
    let report;
    try {
      report = SentinelScan.investigate(url);
    } catch (err) {
      toast(err.message || 'Could not scan that URL.');
      return;
    }

    const v = VERDICTS[report.verdict] || VERDICTS.unknown;
    const risk = Math.round((report.riskScore || 0) * 100);

    scanner.classList.add('is-scanning');
    el.status.textContent = 'SCANNING';

    const reveal = () => {
      scanner.classList.remove('is-scanning');
      el.status.textContent = 'MODEL LOADED';
      el.host.textContent = report.hostname;
      el.verdict.dataset.tone = v.tone;
      scramble(el.verdict, v.word);
      el.conf.textContent = `conf ${Math.round((report.confidence || 0) * 100)}%`;
      el.pb.textContent = `${Math.round(report.probabilities.benign * 100)}%`;
      el.pp.textContent = `${Math.round(report.probabilities.phishing * 100)}%`;
      el.model.textContent = report.modelVersion || 'rf-local';
      el.time.textContent = report.elapsedMs < 0.1 ? '<0.1 ms on your CPU' : `${report.elapsedMs.toFixed(2)} ms on your CPU`;
      renderTicks(report.riskScore || 0, v.tone);
      renderEvidence(report);

      if (hasGsap && !reduced) {
        const o = { v: 0 };
        gsap.to(o, { v: risk, duration: 0.9, ease: 'power3.out', onUpdate: () => (el.score.textContent = pad2(o.v)) });
      } else {
        el.score.textContent = pad2(risk);
      }
    };

    if (hasGsap && !reduced) {
      gsap.fromTo(el.scanline, { opacity: 1, y: 0 }, {
        y: scanner.offsetHeight - 110,
        duration: 0.42,
        ease: 'power2.inOut',
        onComplete: () => { gsap.to(el.scanline, { opacity: 0, duration: 0.15 }); reveal(); }
      });
    } else {
      reveal();
    }
  }

  // Typewriter for the auto-demo and preset clicks
  let typing = null;
  function typeUrl(url, then) {
    clearTimeout(typing);
    if (reduced) { input.value = url; then(); return; }
    input.value = '';
    let i = 0;
    const step = () => {
      input.value = url.slice(0, ++i);
      input.scrollLeft = input.scrollWidth;
      if (i < url.length) typing = setTimeout(step, 14 + Math.random() * 26);
      else typing = setTimeout(then, 180);
    };
    step();
  }

  let userTookOver = false;
  const presets = $$('.preset');

  function takeOver() {
    userTookOver = true;
    clearInterval(autoTimer);
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    takeOver();
    clearTimeout(typing);
    const url = input.value.trim();
    if (!url) { input.focus(); return; }
    runScan(url);
  });

  input.addEventListener('focus', takeOver);

  presets.forEach((b) => {
    b.addEventListener('click', () => {
      takeOver();
      typeUrl(b.dataset.url, () => runScan(b.dataset.url));
    });
  });

  $('#cta-try').addEventListener('click', () => {
    takeOver();
    setTimeout(() => input.focus({ preventScroll: true }), 700);
  });

  // Auto-demo: cycle samples until the visitor interacts
  let autoIdx = 0;
  let autoTimer = null;
  const autoSamples = presets.map((p) => p.dataset.url);

  function autoNext() {
    if (userTookOver) return;
    const url = autoSamples[autoIdx++ % autoSamples.length];
    typeUrl(url, () => !userTookOver && runScan(url));
  }

  if (window.SentinelScan && window.SentinelFeatures) {
    setTimeout(autoNext, reduced ? 0 : 1300);
    if (!reduced) autoTimer = setInterval(autoNext, 6200);
  } else {
    el.status.textContent = 'MODEL OFFLINE';
  }

  // Pause the auto-demo when the hero is off screen
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(([entry]) => {
      if (userTookOver || reduced) return;
      if (entry.isIntersecting && !autoTimer) autoTimer = setInterval(autoNext, 6200);
      if (!entry.isIntersecting) { clearInterval(autoTimer); autoTimer = null; }
    }).observe(scanner);
  }
})();
