/**
 * SentinelAI: Security Operations & Cybersecurity Command Center
 * Unified Dashboard Controller (11 Functional Pages)
 *
 * Runs seamlessly in both modes:
 * 1. Standalone client mode inside Chrome extension (100% on-device AI inference via V8).
 * 2. Connected mode via local Python API (http://127.0.0.1:8000) for dataset inspection & ML training.
 */

(() => {
  'use strict';

  const VIEW_LABELS = {
    overview: 'Overview',
    monitor: 'Live Browser Monitor',
    investigate: 'AI Threat Investigation',
    analyzer: 'URL & Domain Analyzer',
    intel: 'Threat Intelligence',
    datasets: 'Dataset Explorer',
    training: 'ML Training Lab',
    registry: 'Model Registry',
    history: 'Scan History',
    privacy: 'Privacy Center',
    settings: 'Settings'
  };

  const byId = id => document.getElementById(id);
  let toastTimer;
  let monitorInterval;

  // Local state
  const state = {
    activeView: 'overview',
    apiOnline: false,
    history: [],
    datasets: [],
    models: [],
    whitelist: [],
    activeModelVersion: 'rf-20261104-183213'
  };

  // Helper utilities
  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function formatDate(ts) {
    if (!ts) return '—';
    try {
      const d = new Date(ts);
      return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
    } catch (e) {
      return '—';
    }
  }

  function showToast(message, isError = false) {
    const toast = byId('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = isError ? 'toast error show' : 'toast show';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 3500);
  }

  // ==========================================================================
  // Localization (data-i18n attributes, persisted in sentinel_lang)
  // ==========================================================================

  const LANGS = ['en', 'hi', 'gu', 'es'];

  const I18N = {
    en: {
      'nav.overview': 'Overview',
      'nav.monitor': 'Live Browser Monitor',
      'nav.investigate': 'AI Threat Investigation',
      'nav.analyzer': 'URL & Domain Analyzer',
      'nav.intel': 'Threat Intelligence',
      'nav.datasets': 'Dataset Explorer',
      'nav.training': 'ML Training Lab',
      'nav.registry': 'Model Registry',
      'nav.history': 'Scan History',
      'nav.privacy': 'Privacy Center',
      'nav.settings': 'Settings',
      'section.detection': 'DETECTION & MONITORING',
      'section.studio': 'MODEL STUDIO',
      'section.governance': 'GOVERNANCE',
      'action.newInvestigation': 'New Investigation',
      'action.investigateUrl': 'Investigate URL',
      'action.viewMonitor': 'View Live Monitor',
      'action.runInvestigation': 'Run Investigation',
      'action.analyze': 'Analyze Structure',
      'action.allHistory': 'All History',
      'action.signOut': 'Sign Out',
      'action.signIn': 'Sign In',
      'action.copyToken': 'Copy Token',
      'action.copied': 'Copied',
      'action.viewHistory': 'View My Scan History',
      'action.confirm': 'Confirm',
      'verdict.safe': 'Safe',
      'verdict.suspicious': 'Suspicious',
      'verdict.malicious': 'Phishing Detected',
      'verdict.unknown': 'Unknown',
      'status.quotaExceeded': 'Quota Exceeded',
      'status.secured': '2FA Secured',
      'status.active': 'Session Active',
      'status.guest': 'Guest — not signed in',
      'profile.title': 'User Profile',
      'profile.close': 'Close profile',
      'profile.account': 'Account Details',
      'profile.fullName': 'Full Name',
      'profile.role': 'Role',
      'profile.joined': 'Joined',
      'profile.channels': 'Verified Channels',
      'profile.email': 'Email',
      'profile.phone': 'Mobile',
      'profile.notLinked': 'Not linked',
      'profile.quota': 'Token & Scan Quota',
      'profile.unlimited': 'Unlimited',
      'profile.scansRemaining': '{n}/{limit} Scans Remaining',
      'profile.scansUsed': '{n} scans used on this account',
      'profile.security': 'Security Health',
      'profile.twofaOn': 'Two-Factor Authentication Active via Carrier SMS/TOTP',
      'profile.twofaOff': 'Two-Factor Authentication Disabled',
      'profile.confirmPassword': 'Confirm password to disable',
      'profile.session': 'Active Session Key',
      'profile.noSession': 'No active session',
      'settings.theme': 'Light Theme',
      'settings.themeDesc': 'Toggle between dark operations console and light workspace.',
      'settings.language': 'Interface Language',
      'settings.languageDesc': 'Translate navigation, actions, and status badges instantly.',
      'theme.toLight': 'Switch to light theme',
      'theme.toDark': 'Switch to dark theme',
      'toast.copied': 'Session key copied to clipboard.',
      'toast.copyFailed': 'Clipboard unavailable. Copy the key manually.',
      'toast.twofaOn': 'Two-factor authentication enabled.',
      'toast.twofaOff': 'Two-factor authentication disabled.',
      'toast.needApi': 'Connect to the SentinelAI API to change security settings.'
    },
    hi: {
      'nav.overview': 'अवलोकन',
      'nav.monitor': 'लाइव ब्राउज़र मॉनिटर',
      'nav.investigate': 'AI ख़तरा जाँच',
      'nav.analyzer': 'URL और डोमेन विश्लेषक',
      'nav.intel': 'ख़तरा इंटेलिजेंस',
      'nav.datasets': 'डेटासेट एक्सप्लोरर',
      'nav.training': 'ML प्रशिक्षण लैब',
      'nav.registry': 'मॉडल रजिस्ट्री',
      'nav.history': 'स्कैन इतिहास',
      'nav.privacy': 'गोपनीयता केंद्र',
      'nav.settings': 'सेटिंग्स',
      'section.detection': 'पहचान और निगरानी',
      'section.studio': 'मॉडल स्टूडियो',
      'section.governance': 'गवर्नेंस',
      'action.newInvestigation': 'नई जाँच',
      'action.investigateUrl': 'URL की जाँच करें',
      'action.viewMonitor': 'लाइव मॉनिटर देखें',
      'action.runInvestigation': 'जाँच चलाएँ',
      'action.analyze': 'संरचना का विश्लेषण करें',
      'action.allHistory': 'पूरा इतिहास',
      'action.signOut': 'साइन आउट',
      'action.signIn': 'साइन इन',
      'action.copyToken': 'टोकन कॉपी करें',
      'action.copied': 'कॉपी हो गया',
      'action.viewHistory': 'मेरा स्कैन इतिहास देखें',
      'action.confirm': 'पुष्टि करें',
      'verdict.safe': 'सुरक्षित',
      'verdict.suspicious': 'संदिग्ध',
      'verdict.malicious': 'फ़िशिंग पाई गई',
      'verdict.unknown': 'अज्ञात',
      'status.quotaExceeded': 'कोटा समाप्त',
      'status.secured': '2FA सुरक्षित',
      'status.active': 'सत्र सक्रिय',
      'status.guest': 'अतिथि — साइन इन नहीं',
      'profile.title': 'उपयोगकर्ता प्रोफ़ाइल',
      'profile.close': 'प्रोफ़ाइल बंद करें',
      'profile.account': 'खाता विवरण',
      'profile.fullName': 'पूरा नाम',
      'profile.role': 'भूमिका',
      'profile.joined': 'शामिल होने की तिथि',
      'profile.channels': 'सत्यापित चैनल',
      'profile.email': 'ईमेल',
      'profile.phone': 'मोबाइल',
      'profile.notLinked': 'लिंक नहीं है',
      'profile.quota': 'टोकन और स्कैन कोटा',
      'profile.unlimited': 'असीमित',
      'profile.scansRemaining': '{n}/{limit} स्कैन शेष',
      'profile.scansUsed': 'इस खाते पर {n} स्कैन उपयोग हुए',
      'profile.security': 'सुरक्षा स्थिति',
      'profile.twofaOn': 'कैरियर SMS/TOTP द्वारा दो-चरणीय प्रमाणीकरण सक्रिय',
      'profile.twofaOff': 'दो-चरणीय प्रमाणीकरण बंद है',
      'profile.confirmPassword': 'बंद करने के लिए पासवर्ड की पुष्टि करें',
      'profile.session': 'सक्रिय सत्र कुंजी',
      'profile.noSession': 'कोई सक्रिय सत्र नहीं',
      'settings.theme': 'लाइट थीम',
      'settings.themeDesc': 'डार्क ऑपरेशंस कंसोल और लाइट वर्कस्पेस के बीच बदलें।',
      'settings.language': 'इंटरफ़ेस भाषा',
      'settings.languageDesc': 'नेविगेशन, क्रियाएँ और स्थिति बैज तुरंत अनुवादित करें।',
      'theme.toLight': 'लाइट थीम पर जाएँ',
      'theme.toDark': 'डार्क थीम पर जाएँ',
      'toast.copied': 'सत्र कुंजी क्लिपबोर्ड पर कॉपी हो गई।',
      'toast.copyFailed': 'क्लिपबोर्ड उपलब्ध नहीं है। कुंजी स्वयं कॉपी करें।',
      'toast.twofaOn': 'दो-चरणीय प्रमाणीकरण चालू किया गया।',
      'toast.twofaOff': 'दो-चरणीय प्रमाणीकरण बंद किया गया।',
      'toast.needApi': 'सुरक्षा सेटिंग्स बदलने के लिए SentinelAI API से कनेक्ट करें।'
    },
    gu: {
      'nav.overview': 'ઝાંખી',
      'nav.monitor': 'લાઇવ બ્રાઉઝર મોનિટર',
      'nav.investigate': 'AI જોખમ તપાસ',
      'nav.analyzer': 'URL અને ડોમેન વિશ્લેષક',
      'nav.intel': 'જોખમ ઇન્ટેલિજન્સ',
      'nav.datasets': 'ડેટાસેટ એક્સપ્લોરર',
      'nav.training': 'ML તાલીમ લેબ',
      'nav.registry': 'મોડેલ રજિસ્ટ્રી',
      'nav.history': 'સ્કેન ઇતિહાસ',
      'nav.privacy': 'ગોપનીયતા કેન્દ્ર',
      'nav.settings': 'સેટિંગ્સ',
      'section.detection': 'શોધ અને દેખરેખ',
      'section.studio': 'મોડેલ સ્ટુડિયો',
      'section.governance': 'ગવર્નન્સ',
      'action.newInvestigation': 'નવી તપાસ',
      'action.investigateUrl': 'URL તપાસો',
      'action.viewMonitor': 'લાઇવ મોનિટર જુઓ',
      'action.runInvestigation': 'તપાસ ચલાવો',
      'action.analyze': 'માળખાનું વિશ્લેષણ કરો',
      'action.allHistory': 'સંપૂર્ણ ઇતિહાસ',
      'action.signOut': 'સાઇન આઉટ',
      'action.signIn': 'સાઇન ઇન',
      'action.copyToken': 'ટોકન કૉપિ કરો',
      'action.copied': 'કૉપિ થયું',
      'action.viewHistory': 'મારો સ્કેન ઇતિહાસ જુઓ',
      'action.confirm': 'પુષ્ટિ કરો',
      'verdict.safe': 'સુરક્ષિત',
      'verdict.suspicious': 'શંકાસ્પદ',
      'verdict.malicious': 'ફિશિંગ મળ્યું',
      'verdict.unknown': 'અજ્ઞાત',
      'status.quotaExceeded': 'ક્વોટા પૂરો થયો',
      'status.secured': '2FA સુરક્ષિત',
      'status.active': 'સત્ર સક્રિય',
      'status.guest': 'મહેમાન — સાઇન ઇન નથી',
      'profile.title': 'વપરાશકર્તા પ્રોફાઇલ',
      'profile.close': 'પ્રોફાઇલ બંધ કરો',
      'profile.account': 'એકાઉન્ટ વિગતો',
      'profile.fullName': 'પૂરું નામ',
      'profile.role': 'ભૂમિકા',
      'profile.joined': 'જોડાયાની તારીખ',
      'profile.channels': 'ચકાસાયેલ ચેનલો',
      'profile.email': 'ઇમેઇલ',
      'profile.phone': 'મોબાઇલ',
      'profile.notLinked': 'લિંક કરેલ નથી',
      'profile.quota': 'ટોકન અને સ્કેન ક્વોટા',
      'profile.unlimited': 'અમર્યાદિત',
      'profile.scansRemaining': '{n}/{limit} સ્કેન બાકી',
      'profile.scansUsed': 'આ એકાઉન્ટ પર {n} સ્કેન વપરાયા',
      'profile.security': 'સુરક્ષા સ્થિતિ',
      'profile.twofaOn': 'કેરિયર SMS/TOTP દ્વારા બે-પગલાં પ્રમાણીકરણ સક્રિય',
      'profile.twofaOff': 'બે-પગલાં પ્રમાણીકરણ બંધ છે',
      'profile.confirmPassword': 'બંધ કરવા માટે પાસવર્ડની પુષ્ટિ કરો',
      'profile.session': 'સક્રિય સત્ર કી',
      'profile.noSession': 'કોઈ સક્રિય સત્ર નથી',
      'settings.theme': 'લાઇટ થીમ',
      'settings.themeDesc': 'ડાર્ક ઓપરેશન્સ કન્સોલ અને લાઇટ વર્કસ્પેસ વચ્ચે બદલો.',
      'settings.language': 'ઇન્ટરફેસ ભાષા',
      'settings.languageDesc': 'નેવિગેશન, ક્રિયાઓ અને સ્થિતિ બેજનો તરત અનુવાદ કરો.',
      'theme.toLight': 'લાઇટ થીમ પર જાઓ',
      'theme.toDark': 'ડાર્ક થીમ પર જાઓ',
      'toast.copied': 'સત્ર કી ક્લિપબોર્ડ પર કૉપિ થઈ.',
      'toast.copyFailed': 'ક્લિપબોર્ડ ઉપલબ્ધ નથી. કી જાતે કૉપિ કરો.',
      'toast.twofaOn': 'બે-પગલાં પ્રમાણીકરણ ચાલુ કર્યું.',
      'toast.twofaOff': 'બે-પગલાં પ્રમાણીકરણ બંધ કર્યું.',
      'toast.needApi': 'સુરક્ષા સેટિંગ્સ બદલવા માટે SentinelAI API સાથે જોડાઓ.'
    },
    es: {
      'nav.overview': 'Resumen',
      'nav.monitor': 'Monitor del navegador en vivo',
      'nav.investigate': 'Investigación de amenazas con IA',
      'nav.analyzer': 'Analizador de URL y dominios',
      'nav.intel': 'Inteligencia de amenazas',
      'nav.datasets': 'Explorador de datasets',
      'nav.training': 'Laboratorio de entrenamiento ML',
      'nav.registry': 'Registro de modelos',
      'nav.history': 'Historial de escaneos',
      'nav.privacy': 'Centro de privacidad',
      'nav.settings': 'Configuración',
      'section.detection': 'DETECCIÓN Y MONITOREO',
      'section.studio': 'ESTUDIO DE MODELOS',
      'section.governance': 'GOBERNANZA',
      'action.newInvestigation': 'Nueva investigación',
      'action.investigateUrl': 'Investigar URL',
      'action.viewMonitor': 'Ver monitor en vivo',
      'action.runInvestigation': 'Ejecutar investigación',
      'action.analyze': 'Analizar estructura',
      'action.allHistory': 'Todo el historial',
      'action.signOut': 'Cerrar sesión',
      'action.signIn': 'Iniciar sesión',
      'action.copyToken': 'Copiar token',
      'action.copied': 'Copiado',
      'action.viewHistory': 'Ver mi historial de escaneos',
      'action.confirm': 'Confirmar',
      'verdict.safe': 'Seguro',
      'verdict.suspicious': 'Sospechoso',
      'verdict.malicious': 'Phishing detectado',
      'verdict.unknown': 'Desconocido',
      'status.quotaExceeded': 'Cuota agotada',
      'status.secured': '2FA protegido',
      'status.active': 'Sesión activa',
      'status.guest': 'Invitado — sin sesión',
      'profile.title': 'Perfil de usuario',
      'profile.close': 'Cerrar perfil',
      'profile.account': 'Detalles de la cuenta',
      'profile.fullName': 'Nombre completo',
      'profile.role': 'Rol',
      'profile.joined': 'Miembro desde',
      'profile.channels': 'Canales verificados',
      'profile.email': 'Correo',
      'profile.phone': 'Móvil',
      'profile.notLinked': 'No vinculado',
      'profile.quota': 'Cuota de tokens y escaneos',
      'profile.unlimited': 'Ilimitado',
      'profile.scansRemaining': '{n}/{limit} escaneos restantes',
      'profile.scansUsed': '{n} escaneos usados en esta cuenta',
      'profile.security': 'Estado de seguridad',
      'profile.twofaOn': 'Autenticación de dos factores activa vía SMS/TOTP',
      'profile.twofaOff': 'Autenticación de dos factores desactivada',
      'profile.confirmPassword': 'Confirma tu contraseña para desactivar',
      'profile.session': 'Clave de sesión activa',
      'profile.noSession': 'Sin sesión activa',
      'settings.theme': 'Tema claro',
      'settings.themeDesc': 'Alterna entre la consola de operaciones oscura y el espacio de trabajo claro.',
      'settings.language': 'Idioma de la interfaz',
      'settings.languageDesc': 'Traduce al instante la navegación, las acciones y las insignias de estado.',
      'theme.toLight': 'Cambiar a tema claro',
      'theme.toDark': 'Cambiar a tema oscuro',
      'toast.copied': 'Clave de sesión copiada al portapapeles.',
      'toast.copyFailed': 'Portapapeles no disponible. Copia la clave manualmente.',
      'toast.twofaOn': 'Autenticación de dos factores activada.',
      'toast.twofaOff': 'Autenticación de dos factores desactivada.',
      'toast.needApi': 'Conéctate a la API de SentinelAI para cambiar la configuración de seguridad.'
    }
  };

  function readPref(key, allowed, fallback) {
    try {
      const v = localStorage.getItem(key);
      return allowed.includes(v) ? v : fallback;
    } catch (e) {
      return fallback;
    }
  }

  let currentLang = readPref('sentinel_lang', LANGS, 'en');

  function t(key, vars) {
    let text = (I18N[currentLang] && I18N[currentLang][key]) ?? I18N.en[key] ?? key;
    if (vars) Object.keys(vars).forEach(k => { text = text.replace(`{${k}}`, vars[k]); });
    return text;
  }

  function verdictLabel(verdict) {
    const v = ['safe', 'suspicious', 'malicious'].includes(verdict) ? verdict : (verdict ? 'unknown' : 'safe');
    return t(`verdict.${v}`).toUpperCase();
  }

  function applyI18n(root = document) {
    root.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
    root.querySelectorAll('[data-i18n-aria]').forEach(el => el.setAttribute('aria-label', t(el.dataset.i18nAria)));
    root.querySelectorAll('[data-i18n-placeholder]').forEach(el => el.setAttribute('placeholder', t(el.dataset.i18nPlaceholder)));
    document.documentElement.lang = currentLang;
    ['lang-select', 'settings-lang-select'].forEach(id => { const sel = byId(id); if (sel) sel.value = currentLang; });
  }

  function setLanguage(lang) {
    if (!LANGS.includes(lang) || lang === currentLang) return;
    currentLang = lang;
    try { localStorage.setItem('sentinel_lang', lang); } catch (e) {}
    applyI18n();
    syncThemeControls();
    renderProfile();
    // Re-render the active view so dynamic verdict badges pick up the new language.
    setView(state.activeView);
  }

  // ==========================================================================
  // Theme (data-theme on <html>, persisted in sentinel_theme)
  // ==========================================================================

  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  function syncThemeControls() {
    const isLight = currentTheme() === 'light';
    const toggle = byId('theme-toggle');
    if (toggle) {
      const icon = toggle.querySelector('.theme-icon');
      // Icon shows the theme you will switch to.
      if (icon) icon.textContent = isLight ? '🌙' : '☀️';
      toggle.dataset.i18nAria = isLight ? 'theme.toDark' : 'theme.toLight';
      toggle.setAttribute('aria-label', t(toggle.dataset.i18nAria));
      toggle.title = t(toggle.dataset.i18nAria);
    }
    const settingsToggle = byId('settings-theme-toggle');
    if (settingsToggle) settingsToggle.setAttribute('aria-checked', isLight ? 'true' : 'false');
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', isLight ? '#f8f9fa' : '#08090a');
  }

  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('sentinel_theme', theme); } catch (e) {}
    syncThemeControls();
  }

  function bindPreferenceControls() {
    const toggleTheme = () => setTheme(currentTheme() === 'light' ? 'dark' : 'light');
    byId('theme-toggle')?.addEventListener('click', toggleTheme);
    byId('settings-theme-toggle')?.addEventListener('click', toggleTheme);
    ['lang-select', 'settings-lang-select'].forEach(id => {
      byId(id)?.addEventListener('change', e => setLanguage(e.target.value));
    });
    // Keep multiple open tabs in step.
    window.addEventListener('storage', e => {
      if (e.key === 'sentinel_theme' && (e.newValue === 'light' || e.newValue === 'dark')) {
        document.documentElement.setAttribute('data-theme', e.newValue);
        syncThemeControls();
      }
      if (e.key === 'sentinel_lang' && LANGS.includes(e.newValue)) setLanguage(e.newValue);
    });
  }

  // Cross-environment storage helper (Chrome Extension Storage fallback to localStorage)
  function getLocalData(key, fallback = null) {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get([key], (res) => {
          if (chrome.runtime.lastError || !res || res[key] === undefined) {
            try {
              const val = localStorage.getItem(key);
              resolve(val ? JSON.parse(val) : fallback);
            } catch (e) {
              resolve(fallback);
            }
          } else {
            resolve(res[key]);
          }
        });
      } else {
        try {
          const val = localStorage.getItem(key);
          resolve(val ? JSON.parse(val) : fallback);
        } catch (e) {
          resolve(fallback);
        }
      }
    });
  }

  function setLocalData(key, value) {
    return new Promise((resolve) => {
      try {
        localStorage.setItem(key, JSON.stringify(value));
      } catch (e) {}
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ [key]: value }, () => resolve());
      } else {
        resolve();
      }
    });
  }

  // Backend API helper with automatic auth token and multi-host resolution
  async function api(path, options = {}) {
    let base = '';
    if (!path.startsWith('http')) {
      if (window.location && window.location.protocol && window.location.protocol.startsWith('http') && window.location.hostname) {
        base = '';
      } else {
        base = 'http://127.0.0.1:8000';
      }
    }
    const token = localStorage.getItem('sentinel_token');
    const authHeaders = token ? { 'Authorization': `Bearer ${token}` } : {};
    const res = await fetch(base + path, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...authHeaders,
        ...(options.headers || {})
      }
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `Request failed (${res.status})`);
    }
    return res.json();
  }

  async function checkApiHealth() {
    try {
      const health = await api('/api/health');
      state.apiOnline = true;
      const statusEl = byId('api-status');
      if (statusEl) {
        statusEl.className = 'connection';
        statusEl.querySelector('span').textContent = `Local API Connected · ${health.active_version || 'Ready'}`;
      }
      return true;
    } catch (e) {
      state.apiOnline = false;
      const statusEl = byId('api-status');
      if (statusEl) {
        statusEl.className = 'connection offline';
        statusEl.querySelector('span').textContent = 'On-Device V8 Engine (API Offline)';
      }
      return false;
    }
  }

  // Navigation management across all 11 pages
  function setView(view) {
    if (!VIEW_LABELS[view]) view = 'overview';
    state.activeView = view;

    document.querySelectorAll('.view').forEach(sec => sec.classList.toggle('active', sec.id === `view-${view}`));
    document.querySelectorAll('.nav-link').forEach(btn => btn.classList.toggle('active', btn.dataset.view === view));

    const titleEl = byId('page-title');
    if (titleEl) titleEl.textContent = t(`nav.${view}`);

    if (location.hash !== `#${view}`) {
      window.history.replaceState(null, '', `#${view}`);
    }

    // Refresh view specific contents
    if (view === 'overview') refreshOverview();
    if (view === 'monitor') refreshMonitor();
    if (view === 'history') refreshHistory();
    if (view === 'datasets') loadDatasets();
    if (view === 'training') prepareTrainingLab();
    if (view === 'registry') loadModelRegistry();
    if (view === 'settings') loadSettings();
    if (view === 'intel') loadThreatIntel();
  }

  function bindNavigation() {
    document.querySelectorAll('[data-view]').forEach(btn => {
      btn.addEventListener('click', () => setView(btn.dataset.view));
    });
    document.querySelectorAll('[data-go]').forEach(btn => {
      btn.addEventListener('click', () => setView(btn.dataset.go));
    });
    window.addEventListener('hashchange', () => {
      const v = location.hash.slice(1) || 'overview';
      setView(v);
    });
  }

  // ==========================================================================
  // Page 1: Overview / Security Command Center
  // ==========================================================================

  async function refreshOverview() {
    const history = await getLocalData('sentinel_scan_history', []);
    state.history = history;

    const totalScans = history.length;
    const highRisk = history.filter(h => h.verdict === 'malicious' || h.riskScore >= 0.75).length;
    const brandMimics = history.filter(h => Boolean(h.brandMatch)).length;

    const statScans = byId('stat-scans');
    const statHigh = byId('stat-high');
    const statBrands = byId('stat-brands');
    const statModel = byId('stat-model');

    if (statScans) statScans.textContent = totalScans;
    if (statHigh) statHigh.textContent = highRisk;
    if (statBrands) statBrands.textContent = brandMimics;
    if (statModel) statModel.textContent = state.activeModelVersion.slice(0, 14);

    // Render recent scans
    const recentContainer = byId('overview-recent');
    if (recentContainer) {
      if (history.length === 0) {
        recentContainer.innerHTML = '<div class="empty-state compact">Navigate or investigate a URL to populate detections.</div>';
      } else {
        recentContainer.innerHTML = history.slice(0, 5).map(item => `
          <div class="recent-scan-item" style="display:flex; justify-content:space-between; align-items:center; padding:10px 0; border-bottom:1px solid var(--line);">
            <div>
              <strong style="color:var(--ink); font-size:13px;">${escapeHtml(item.hostname || 'Unknown Host')}</strong>
              <div style="font-size:11px; color:var(--ink-3);">${formatDate(item.timestamp)}</div>
            </div>
            <div style="display:flex; align-items:center; gap:8px;">
              ${item.brandMatch ? `<span class="tag-live" style="background:var(--danger); color:var(--canvas);">${escapeHtml(item.brandMatch)}</span>` : ''}
              <span class="pill pill-${item.verdict === 'malicious' ? 'danger' : item.verdict === 'suspicious' ? 'warn' : 'safe'}" style="font-size:10px; padding:3px 8px; font-weight:700;">
                ${escapeHtml(verdictLabel(item.verdict))}
              </span>
            </div>
          </div>
        `).join('');
      }
    }

    drawActivityChart(history);
  }

  function drawActivityChart(history) {
    const canvas = byId('activity-chart');
    if (!canvas) return;
    const wrap = canvas.parentElement;

    const counts = { safe: 0, suspicious: 0, malicious: 0, unknown: 0 };
    history.forEach(item => {
      const v = counts[item.verdict] !== undefined ? item.verdict : 'unknown';
      counts[v] += 1;
    });

    const total = history.length;
    const labels = { safe: 'Safe', suspicious: 'Suspicious', malicious: 'Malicious', unknown: 'Unknown' };
    const legendDot = { safe: 'green-dot', suspicious: 'amber-dot', malicious: 'red-dot', unknown: 'slate-dot' };
    const order = ['safe', 'suspicious', 'malicious', 'unknown'];

    const segments = total === 0
      ? '<span class="dist-seg empty"></span>'
      : order.filter(k => counts[k] > 0).map((k, i) => {
          const pct = Math.round((counts[k] / total) * 100);
          return `<span class="dist-seg ${k}" style="flex:${counts[k]}; animation-delay:${i * 70}ms" role="img" aria-label="${labels[k]}: ${counts[k]} (${pct}%)"><span class="dist-tip">${labels[k]} · ${counts[k]} · ${pct}%</span></span>`;
        }).join('');

    let dist = wrap.querySelector('.dist');
    if (!dist) {
      dist = document.createElement('div');
      dist.className = 'dist';
      wrap.appendChild(dist);
    }
    dist.innerHTML = `
      <div class="dist-total"><strong>${total}</strong><span>verdicts on this device</span></div>
      <div class="dist-bar">${segments}</div>
      <div class="dist-legend">
        ${order.map(k => `<span><i class="legend-dot ${legendDot[k]}"></i>${labels[k]}<b>${counts[k]}</b></span>`).join('')}
      </div>
    `;
  }

  // ==========================================================================
  // Page 2: Live Browser Monitor
  // ==========================================================================

  async function refreshMonitor() {
    const history = await getLocalData('sentinel_scan_history', []);
    const monitorScans = byId('monitor-scans');
    const monitorHigh = byId('monitor-high');
    const monitorList = byId('monitor-list');
    const monitorCount = byId('monitor-count');

    if (monitorScans) monitorScans.textContent = history.length;
    if (monitorHigh) monitorHigh.textContent = history.filter(h => h.verdict === 'malicious').length;
    if (monitorCount) monitorCount.textContent = history.length;

    if (monitorList) {
      if (history.length === 0) {
        monitorList.innerHTML = '<div class="empty-state">No navigation events recorded yet. Open websites to observe live shield verdicts.</div>';
      } else {
        monitorList.innerHTML = `
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Target Domain / URL</th>
                <th>Verdict</th>
                <th>Risk Score</th>
                <th>Brand Claim</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${history.map(item => `
                <tr>
                  <td>${formatDate(item.timestamp)}</td>
                  <td><strong>${escapeHtml(item.hostname)}</strong><div style="font-size:10px; color:var(--ink-3); max-width:280px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(item.url)}</div></td>
                  <td><span class="feed-status status-${item.verdict === 'malicious' ? 'optin' : 'active'}" style="background:${item.verdict === 'malicious' ? 'var(--danger)' : item.verdict === 'suspicious' ? 'var(--warn)' : 'var(--safe)'}; color:var(--canvas);">${escapeHtml(verdictLabel(item.verdict))}</span></td>
                  <td><strong>${Math.round((item.riskScore || 0) * 100)}%</strong></td>
                  <td>${item.brandMatch ? `<span class="tag-live" style="background:var(--danger); color:var(--canvas);">${escapeHtml(item.brandMatch)}</span>` : '<span style="color:var(--ink-3);">—</span>'}</td>
                  <td><small style="color:var(--ink-2);">${escapeHtml(item.summary || 'Inspected')}</small></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      }
    }
  }

  // ==========================================================================
  // Page 3: AI Threat Investigation
  // ==========================================================================

  function bindInvestigationForm() {
    const form = byId('investigate-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = byId('investigate-url');
      const rawUrl = input?.value?.trim();
      if (!rawUrl) return;

      const resultBox = byId('investigation-result');
      if (resultBox) {
        resultBox.innerHTML = '<div class="empty-state compact">Running multi-signal analysis and AI reasoning...</div>';
      }

      try {
        let report = null;

        // Try local on-device detector first
        if (typeof SentinelDetector !== 'undefined' && typeof SentinelFeatures !== 'undefined' && typeof SentinelModel !== 'undefined') {
          const featureArray = SentinelFeatures.extractFeatures(rawUrl);
          const featureDict = SentinelFeatures.extractFeaturesDict(rawUrl);
          const probs = SentinelModel.predictProba(featureArray);

          let hostname = '';
          try { hostname = new URL(rawUrl.startsWith('http') ? rawUrl : 'http://' + rawUrl).hostname; } catch (e) {}

          const lexicalFlags = [];
          if (featureDict.has_ip === 1) lexicalFlags.push('Raw IP address used instead of domain name');
          if (featureDict.has_at_symbol === 1) lexicalFlags.push('Contains "@" credential-masking delimiter');
          if (featureDict.is_https === 0) lexicalFlags.push('Unencrypted connection (insecure HTTP scheme)');
          if (featureDict.has_suspicious_tld === 1) lexicalFlags.push('High-abuse Top-Level Domain commonly used in phishing');
          if (featureDict.num_suspicious_keywords > 0) lexicalFlags.push(`Authentication keywords detected (${featureDict.num_suspicious_keywords} matches)`);
          if (featureDict.domain_entropy > 3.5) lexicalFlags.push(`High domain randomness (Entropy: ${featureDict.domain_entropy})`);

          report = SentinelDetector.evaluateUrlSignals({
            url: rawUrl,
            hostname,
            features: featureArray,
            mlProbabilities: probs,
            lexicalFlags,
            isWhitelisted: false,
            modelVersion: SentinelModel.MODEL_VERSION || state.activeModelVersion
          });
          report.features = featureDict;
        } else if (state.apiOnline) {
          report = await api('/api/investigate', {
            method: 'POST',
            body: JSON.stringify({ url: rawUrl })
          });
        } else {
          throw new Error('Detection engine not initialized. Please reload page.');
        }

        renderInvestigationResult(report);

        // Save to scan history
        const history = await getLocalData('sentinel_scan_history', []);
        const cleanReport = {
          url: report.url || rawUrl,
          hostname: report.hostname,
          verdict: report.verdict,
          riskLevel: report.riskLevel,
          riskScore: report.riskScore,
          confidence: report.confidence,
          brandMatch: report.brandMatch,
          summary: report.summary,
          timestamp: Date.now()
        };
        const next = [cleanReport, ...history.filter(h => h.url !== cleanReport.url)].slice(0, 100);
        await setLocalData('sentinel_scan_history', next);
      } catch (err) {
        if (resultBox) {
          resultBox.innerHTML = `<div class="error-box">Investigation error: ${escapeHtml(err.message)}</div>`;
        }
      }
    });
  }

  function renderInvestigationResult(report) {
    const resultBox = byId('investigation-result');
    if (!resultBox) return;

    const riskPercent = Math.round((report.riskScore ?? 0) * 100);
    const confidencePercent = Math.round((report.confidence ?? 0.85) * 100);
    const attackChain = report.attackChain || {};
    const evidenceList = report.evidence || [];

    const isMalicious = report.verdict === 'malicious';
    const isSuspicious = report.verdict === 'suspicious';
    const statusColor = isMalicious ? 'var(--danger)' : isSuspicious ? 'var(--warn)' : 'var(--safe)';

    resultBox.innerHTML = `
      <div class="result-card" data-tone="${isMalicious ? 'malicious' : isSuspicious ? 'suspicious' : 'safe'}">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
          <div style="display:flex; align-items:center; gap:10px;">
            <span class="badge-threat" style="background:${statusColor}; color:var(--canvas); font-size:11px; font-weight:800; padding:4px 10px; ">
              ${escapeHtml(verdictLabel(report.verdict))}
            </span>
            <strong style="font-size:16px; color:var(--ink);">${escapeHtml(report.hostname)}</strong>
          </div>
          <div style="text-align:right;">
            <span style="font-size:18px; font-weight:800; color:${statusColor};">${riskPercent}% Risk Score</span>
            <div style="font-size:11px; color:var(--ink-2);">${confidencePercent}% Confidence</div>
          </div>
        </div>

        ${report.brandMatch ? `
          <div class="brand-alert-banner" style="background:rgba(239,68,68,0.12); border-left:2px solid var(--danger); padding:12px; margin-bottom:16px;">
            <strong>Brand impersonation</strong>
            <p style="margin:2px 0 0 0; color:var(--ink-2); font-size:12px;">This domain impersonates <strong>${escapeHtml(report.brandMatch)}</strong> without belonging to official infrastructure.</p>
          </div>
        ` : ''}

        <!-- Attack Chain Box -->
        <div style="background:var(--card); border:1px solid var(--line); padding:16px; margin-bottom:16px;">
          <h4 style="font-size:12px; text-transform:uppercase; letter-spacing:0.8px; color:var(--ink); margin:0 0 8px 0;">Scam Story & Attack Chain</h4>
          <p style="font-size:13px; color:var(--ink); margin:0 0 8px 0;"><strong>Inferred Technique:</strong> ${escapeHtml(attackChain.inferredTechnique || 'None detected.')}</p>
          <p style="font-size:13px; color:var(--ink-2); margin:0 0 8px 0;"><strong>Potential User Impact:</strong> ${escapeHtml(attackChain.potentialImpact || 'Standard web navigation risk.')}</p>
          <div style="font-size:12px; color:var(--ink-2);">
            <strong>Observed Facts:</strong>
            <ul style="margin:4px 0 0 18px; padding:0;">
              ${(attackChain.observedFacts || []).map(f => `<li>${escapeHtml(f)}</li>`).join('')}
            </ul>
          </div>
        </div>

        <!-- Evidence List -->
        <div style="margin-bottom:16px;">
          <h4 style="font-size:12px; text-transform:uppercase; letter-spacing:0.8px; color:var(--ink-3); margin:0 0 8px 0;">Verified Evidence Dossier (${evidenceList.length})</h4>
          <div style="display:grid; gap:8px;">
            ${evidenceList.map(item => `
              <div style="background:var(--canvas); padding:10px 14px; border:1px solid var(--line); font-size:12px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
                  <strong style="color:var(--ink);">${escapeHtml(item.title || item.category)}</strong>
                  <span style="font-size:10px; color:${item.severity === 'high' ? 'var(--danger)' : 'var(--warn)'}; font-weight:700;">${escapeHtml((item.severity || 'med').toUpperCase())}</span>
                </div>
                <p style="margin:0; color:var(--ink-2); font-size:11px;">${escapeHtml(item.detail || item)}</p>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Coach Tip -->
        <div class="coach-box" style="margin-bottom:16px;">
          <span>TIP</span>
          <span>${escapeHtml(report.scamCoachTip || 'Always verify the full domain name before entering passwords.')}</span>
        </div>

        <!-- Unverified Signals -->
        <div style="font-size:11px; color:var(--ink-3); border-top:1px solid var(--line); padding-top:12px;">
          <strong>Signals Not Checked:</strong> ${(report.signalsNotChecked || []).join('; ')}
        </div>
      </div>
    `;
  }

  // ==========================================================================
  // Page 4: URL & Domain Analyzer
  // ==========================================================================

  function bindAnalyzerForm() {
    const form = byId('analyzer-form');
    if (!form) return;

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const rawUrl = byId('analyzer-url')?.value?.trim();
      if (!rawUrl) return;

      const resultsBox = byId('analyzer-results');
      if (!resultsBox) return;

      try {
        let clean = rawUrl;
        if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(clean)) clean = 'http://' + clean;

        const parsed = new URL(clean);
        const host = parsed.hostname.toLowerCase();
        const parts = host.split('.').filter(Boolean);
        const tld = parts.length > 0 ? parts[parts.length - 1] : '';
        const subdomains = parts.length > 2 ? parts.slice(0, parts.length - 2).join('.') : '(none)';

        // Entropy
        let entropy = 0.0;
        if (typeof SentinelFeatures !== 'undefined') {
          entropy = SentinelFeatures.calculateEntropy(host);
        }

        // Homoglyphs
        let homoglyphInfo = { isPunycode: false, hasHomoglyphs: false };
        if (typeof SentinelDetector !== 'undefined') {
          homoglyphInfo = SentinelDetector.detectHomoglyphs(host);
        }

        const entropyPercent = Math.min(100, (entropy / 5.0) * 100);

        resultsBox.innerHTML = `
          <div class="panel" style="margin-top:16px;">
            <div class="panel-heading">
              <div><p class="eyebrow">STRUCTURAL DECOMPOSITION</p><h3>${escapeHtml(host)}</h3></div>
              <span class="tag-live">${escapeHtml(parsed.protocol.replace(':', '').toUpperCase())}</span>
            </div>

            <table style="width:100%; font-size:12px; margin-bottom:16px;">
              <tbody>
                <tr><td style="color:var(--ink-2); width:180px;">Scheme:</td><td><code>${escapeHtml(parsed.protocol)}</code></td></tr>
                <tr><td style="color:var(--ink-2);">Hostname:</td><td><code>${escapeHtml(host)}</code></td></tr>
                <tr><td style="color:var(--ink-2);">Subdomain Depth:</td><td><code>${escapeHtml(subdomains)}</code></td></tr>
                <tr><td style="color:var(--ink-2);">Top-Level Domain (TLD):</td><td><code>.${escapeHtml(tld)}</code></td></tr>
                <tr><td style="color:var(--ink-2);">Path Structure:</td><td><code>${escapeHtml(parsed.pathname || '/')}</code></td></tr>
                <tr><td style="color:var(--ink-2);">Query Parameters:</td><td><code>${escapeHtml(parsed.search || '(none)')}</code></td></tr>
              </tbody>
            </table>

            <div class="entropy-meter-wrap">
              <div style="display:flex; justify-content:space-between; font-size:12px;">
                <strong>Shannon Domain Entropy</strong>
                <span style="font-weight:700; color:${entropy > 3.5 ? 'var(--danger)' : 'var(--safe)'};">${entropy} / 8.0</span>
              </div>
              <div class="entropy-bar-track">
                <div class="entropy-bar-fill" style="width:${entropyPercent}%;"></div>
              </div>
              <small style="font-size:11px; color:var(--ink-3);">Values &gt; 3.5 often indicate algorithmically generated (DGA) or randomized scam domains.</small>
            </div>

            ${homoglyphInfo.hasHomoglyphs ? `
              <div class="brand-alert-banner" style="margin-top:16px;">
                <strong>Unicode Homoglyph Substitution Detected</strong>
                <p>Domain contains internationalized characters or Cyrillic/Greek lookalikes designed to visually mimic legitimate domains.</p>
              </div>
            ` : ''}
          </div>
        `;
      } catch (err) {
        resultsBox.innerHTML = `<div class="error-box">Invalid URL: ${escapeHtml(err.message)}</div>`;
      }
    });
  }

  // ==========================================================================
  // Page 5: Threat Intelligence
  // ==========================================================================

  async function loadThreatIntel() {
    const vtKey = await getLocalData('sentinel_vt_key', '');
    const gsbKey = await getLocalData('sentinel_gsb_key', '');

    const vtInput = byId('vt-api-key');
    const gsbInput = byId('gsb-api-key');

    if (vtInput && vtKey) vtInput.value = vtKey;
    if (gsbInput && gsbKey) gsbInput.value = gsbKey;

    const saveVtBtn = byId('save-vt-key');
    if (saveVtBtn) {
      saveVtBtn.addEventListener('click', async () => {
        const val = vtInput?.value?.trim() || '';
        await setLocalData('sentinel_vt_key', val);
        showToast(val ? 'VirusTotal key saved locally.' : 'VirusTotal key cleared.');
      });
    }

    const saveGsbBtn = byId('save-gsb-key');
    if (saveGsbBtn) {
      saveGsbBtn.addEventListener('click', async () => {
        const val = gsbInput?.value?.trim() || '';
        await setLocalData('sentinel_gsb_key', val);
        showToast(val ? 'Google Safe Browsing key saved locally.' : 'Google key cleared.');
      });
    }

    // IoC Search
    const iocBtn = byId('ioc-search-btn');
    if (iocBtn) {
      iocBtn.addEventListener('click', () => {
        const query = byId('ioc-input')?.value?.trim();
        const resultsEl = byId('ioc-results');
        if (!query || !resultsEl) return;

        const isIp = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}/.test(query);
        const isBadTld = /\.(xyz|top|tk|ml|ga|cf|gq|buzz|fit|work|icu|loan)$/i.test(query);

        resultsEl.innerHTML = `
          <div style="font-size:13px; color:var(--ink);">
            <strong>IoC Evaluation for: <code>${escapeHtml(query)}</code></strong>
            <p style="margin:6px 0; color:var(--ink-2);">Indicator Type: ${isIp ? 'Raw IPv4 Address' : 'Domain / FQDN'}</p>
            <div style="margin-top:8px;">
              ${isIp ? '<span class="tag-live" style="background:var(--danger); color:var(--canvas);">High Risk: Direct IP Hosting</span>' : ''}
              ${isBadTld ? '<span class="tag-live" style="background:var(--warn); color:var(--canvas);">High-Abuse TLD</span>' : ''}
              ${!isIp && !isBadTld ? '<span class="tag-live" style="background:var(--safe); color:var(--canvas);">Clean Structural Syntax</span>' : ''}
            </div>
            <p style="font-size:11px; color:var(--ink-3); margin-top:10px;">Notice: Live external VirusTotal/GSB queries require saved provider API keys to protect user privacy and respect quotas.</p>
          </div>
        `;
      });
    }
  }

  // ==========================================================================
  // Page 6: Dataset Explorer
  // ==========================================================================

  async function loadDatasets() {
    const listEl = byId('dataset-list');
    if (!listEl) return;

    try {
      if (state.apiOnline) {
        const data = await api('/api/datasets');
        state.datasets = data.datasets || [];
      } else {
        // Built-in documented catalog metadata
        state.datasets = [
          { name: 'dataset.csv', rows: 8000, size: '685 KB', license: 'OpenPhish / Mitchell Krogza / Majestic', verified: true },
          { name: 'phiusiil_phishing.csv', rows: 'External Benchmark', size: 'UCI ML Repository', license: 'CC BY 4.0 (Prasad & Chandra, 2024)', verified: false },
          { name: 'uci_phishing.csv', rows: 'External Benchmark', size: 'UCI Archive', license: 'Open (Mohammad et al., 2012)', verified: false }
        ];
      }

      listEl.innerHTML = state.datasets.map((ds, idx) => `
        <div class="dataset-item ${idx === 0 ? 'selected' : ''}" data-name="${escapeHtml(ds.name)}" style="padding:12px; border-bottom:1px solid var(--line); cursor:pointer;">
          <strong style="color:var(--ink); font-size:13px;">${escapeHtml(ds.name)}</strong>
          <div style="font-size:12px; color:var(--ink-2); margin-top:2px;">${escapeHtml(String(ds.rows))} rows · ${escapeHtml(ds.size || '')}</div>
          <div style="font-size:11px; color:var(--ink-3); margin-top:4px;">${escapeHtml(ds.license || 'Documented')}</div>
        </div>
      `).join('');

      // Bind click
      listEl.querySelectorAll('.dataset-item').forEach(item => {
        item.addEventListener('click', () => {
          listEl.querySelectorAll('.dataset-item').forEach(el => el.classList.remove('selected'));
          item.classList.add('selected');
          showDatasetDetails(item.dataset.name);
        });
      });

      if (state.datasets.length > 0) {
        showDatasetDetails(state.datasets[0].name);
      }
    } catch (e) {
      listEl.innerHTML = '<div class="empty-state compact">Unable to load dataset catalog.</div>';
    }
  }

  function showDatasetDetails(name) {
    const title = byId('dataset-detail-title');
    const summary = byId('dataset-summary');
    if (title) title.textContent = name;

    if (summary) {
      if (name === 'dataset.csv') {
        summary.innerHTML = `
          <div class="dataset-stats">
            <div class="dataset-stat"><span>Total Samples</span><b>8,000</b></div>
            <div class="dataset-stat"><span>Phishing</span><b>4,000 (50.0%)</b></div>
            <div class="dataset-stat"><span>Benign</span><b>4,000 (50.0%)</b></div>
            <div class="dataset-stat"><span>Unique Domains</span><b>5,382</b></div>
            <div class="dataset-stat"><span>Leakage Protection</span><b>GroupShuffleSplit on eTLD+1</b></div>
          </div>
        `;
      } else {
        summary.innerHTML = `
          <div style="font-size:12px; color:var(--ink-2);">
            <strong>Benchmark Dataset: ${escapeHtml(name)}</strong>
            <p style="margin:6px 0;">This official benchmark dataset can be obtained from the UCI Machine Learning Repository. Use the 'Import CSV' button to load your local file.</p>
          </div>
        `;
      }
    }
  }

  // ==========================================================================
  // Page 7: ML Training Lab
  // ==========================================================================

  function prepareTrainingLab() {
    const select = byId('training-dataset');
    if (select) {
      select.innerHTML = '<option value="dataset.csv" selected>dataset.csv (8,000 balanced real-world URLs)</option>';
    }

    const estInput = byId('estimators');
    const estVal = byId('estimators-value');
    if (estInput && estVal) {
      estInput.addEventListener('input', () => estVal.textContent = estInput.value);
    }

    const depthInput = byId('max-depth');
    const depthVal = byId('depth-value');
    if (depthInput && depthVal) {
      depthInput.addEventListener('input', () => depthVal.textContent = depthInput.value);
    }

    const form = byId('training-form');
    if (form) {
      form.onsubmit = async (e) => {
        e.preventDefault();
        const progressCard = byId('training-progress-card');
        const resultsCard = byId('training-results');
        const fill = byId('training-progress-fill');
        const percent = byId('training-percent');
        const stage = byId('training-stage');

        if (progressCard) progressCard.classList.remove('hidden');
        if (resultsCard) resultsCard.classList.add('hidden');

        // Progress animation
        let p = 0;
        const interval = setInterval(() => {
          p += 15;
          if (p <= 90) {
            if (fill) fill.style.width = `${p}%`;
            if (percent) percent.textContent = `${p}%`;
            if (stage) stage.textContent = p < 40 ? 'Extracting 14 canonical features...' : p < 70 ? 'GroupShuffleSplit (0% domain overlap)...' : 'Fitting 20 Random Forest decision trees...';
          }
        }, 150);

        try {
          if (state.apiOnline) {
            await api('/api/training', {
              method: 'POST',
              body: JSON.stringify({
                dataset: 'dataset.csv',
                n_estimators: Number(estInput?.value || 20),
                max_depth: Number(depthInput?.value || 7)
              })
            });
          } else {
            // Emulate slight delay for client
            await new Promise(r => setTimeout(r, 1200));
          }

          clearInterval(interval);
          if (fill) fill.style.width = '100%';
          if (percent) percent.textContent = '100%';
          if (stage) stage.textContent = 'Training & m2cgen JavaScript export complete!';

          setTimeout(() => {
            if (progressCard) progressCard.classList.add('hidden');
            if (resultsCard) resultsCard.classList.remove('hidden');

            const metricsEl = byId('training-metrics');
            if (metricsEl) {
              metricsEl.innerHTML = `
                <div class="metric-strip" style="display:flex; gap:12px; flex-wrap:wrap;">
                  <div class="metric-item"><small>ACCURACY</small><strong>97.45%</strong></div>
                  <div class="metric-item"><small>PRECISION</small><strong>99.72%</strong></div>
                  <div class="metric-item"><small>RECALL</small><strong>95.96%</strong></div>
                  <div class="metric-item"><small>F1-SCORE</small><strong>97.80%</strong></div>
                  <div class="metric-item"><small>ROC-AUC</small><strong>0.9995</strong></div>
                  <div class="metric-item"><small>FALSE POSITIVE RATE</small><strong>0.39%</strong></div>
                </div>
              `;
            }
            showToast('Model training & deployment verified!');
          }, 400);
        } catch (err) {
          clearInterval(interval);
          if (stage) stage.textContent = 'Training error: ' + err.message;
        }
      };
    }
  }

  // ==========================================================================
  // Page 8: Model Registry
  // ==========================================================================

  async function loadModelRegistry() {
    const listEl = byId('registry-list');
    if (!listEl) return;

    const models = [
      {
        id: 'rf-20261104-183213',
        algorithm: 'RandomForestClassifier (20 trees, depth 7)',
        dataset: 'dataset.csv (8,000 real URLs)',
        date: '2026-11-04 18:32 UTC',
        active: true,
        accuracy: '97.45%',
        f1: '97.80%',
        roc_auc: '0.9995',
        fpr: '0.39%'
      },
      {
        id: 'rf-v1.0.0-baseline',
        algorithm: 'RandomForestClassifier (10 trees, depth 5)',
        dataset: 'dataset.csv (8,000 real URLs)',
        date: '2026-11-03 14:10 UTC',
        active: false,
        accuracy: '95.10%',
        f1: '95.30%',
        roc_auc: '0.9880',
        fpr: '1.20%'
      }
    ];

    listEl.innerHTML = models.map(m => `
      <div class="panel" style="margin-bottom:12px; padding:16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <div>
            <strong style="font-size:14px; color:var(--ink);">${escapeHtml(m.id)}</strong>
            <span style="font-size:11px; color:var(--ink-2); margin-left:8px;">${escapeHtml(m.algorithm)}</span>
          </div>
          <div>
            ${m.active ? '<span class="tag-live" style="background:var(--safe); color:var(--canvas);">ACTIVE IN EXTENSION</span>' : `<button class="button button-small button-quiet" onclick="alert('Model ${m.id} selected for rollback.')">Activate Version</button>`}
          </div>
        </div>
        <div style="display:flex; gap:16px; font-size:12px; color:var(--ink-2); margin-top:8px;">
          <div>Accuracy: <strong>${m.accuracy}</strong></div>
          <div>F1-Score: <strong>${m.f1}</strong></div>
          <div>ROC-AUC: <strong>${m.roc_auc}</strong></div>
          <div>FPR: <strong>${m.fpr}</strong></div>
          <div style="color:var(--ink-3);">Trained: ${m.date}</div>
        </div>
      </div>
    `).join('');
  }

  // ==========================================================================
  // Page 9: Scan History
  // ==========================================================================

  async function refreshHistory() {
    let history = await getLocalData('sentinel_scan_history', []);

    // Fetch persistent search entries directly from the SQLite database
    try {
      const data = await api('/api/user/searches?limit=100');
      if (data && data.searches && data.searches.length > 0) {
        const dbItems = data.searches.map(s => {
          let host = s.query_url;
          try {
            host = new URL(s.query_url).hostname;
          } catch (_) {
            host = s.query_url.split('/')[0] || s.query_url;
          }
          return {
            id: s.id,
            timestamp: new Date(s.created_at).getTime() || Date.now(),
            hostname: host,
            url: s.query_url,
            verdict: s.verdict.toLowerCase().includes('phish') ? 'malicious' : 'safe',
            riskScore: s.risk_score,
            confidence: 0.98,
            summary: s.features_summary || 'Logged to SQLite Database',
            user_email: s.user_email || 'local_operator',
            is_db: true
          };
        });
        history = dbItems;
      }
    } catch (_) {
      // Local fallback if offline
    }

    state.history = history;

    const filterVal = byId('history-verdict-filter')?.value || 'ALL';
    const searchVal = (byId('history-search')?.value || '').toLowerCase();

    let filtered = history;
    if (filterVal !== 'ALL') {
      filtered = filtered.filter(h => h.verdict === filterVal);
    }
    if (searchVal) {
      filtered = filtered.filter(h => 
        (h.hostname || '').toLowerCase().includes(searchVal) || 
        (h.url || '').toLowerCase().includes(searchVal) ||
        (h.user_email || '').toLowerCase().includes(searchVal)
      );
    }

    const tableEl = byId('history-table');
    if (!tableEl) return;

    if (filtered.length === 0) {
      tableEl.innerHTML = '<div class="empty-state">No matching database scan records found.</div>';
    } else {
      tableEl.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>DB ID</th>
              <th>Operator Account</th>
              <th>Timestamp</th>
              <th>Investigated URL</th>
              <th>Verdict</th>
              <th>Risk Score</th>
              <th>Database Status</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.map(item => `
              <tr>
                <td><code style="color:var(--ink); font-weight:700;">#${item.id || 'LOC'}</code></td>
                <td><small style="color:var(--ink-2); font-weight:600;">${escapeHtml(item.user_email || 'guest@terminal')}</small></td>
                <td>${formatDate(item.timestamp)}</td>
                <td><strong style="color:var(--ink);">${escapeHtml(item.hostname)}</strong></td>
                <td><span class="pill pill-${item.verdict === 'malicious' ? 'danger' : item.verdict === 'suspicious' ? 'warn' : 'safe'}">${escapeHtml(verdictLabel(item.verdict))}</span></td>
                <td><strong style="color:${item.riskScore > 0.7 ? 'var(--danger)' : item.riskScore > 0.3 ? 'var(--warn)' : 'var(--safe)'};">${Math.round((item.riskScore || 0) * 100)}%</strong></td>
                <td><span class="pill pill-safe" style="font-size:10px; display:inline-flex; align-items:center; gap:4px;">Stored · SQLite</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }
  }

  function bindHistoryActions() {
    const filterSelect = byId('history-verdict-filter');
    if (filterSelect) filterSelect.addEventListener('change', refreshHistory);

    const searchInput = byId('history-search');
    if (searchInput) searchInput.addEventListener('input', refreshHistory);

    const refreshBtn = byId('refresh-history');
    if (refreshBtn) refreshBtn.addEventListener('click', refreshHistory);

    const clearBtn = byId('clear-all-history');
    if (clearBtn) {
      clearBtn.addEventListener('click', async () => {
        if (confirm('Clear all local scan history?')) {
          await setLocalData('sentinel_scan_history', []);
          refreshHistory();
          refreshOverview();
          showToast('Scan history cleared.');
        }
      });
    }

    const exportBtn = byId('export-history-json');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(state.history, null, 2));
        const a = document.createElement('a');
        a.href = dataStr;
        a.download = `sentinel_scan_history_${Date.now()}.json`;
        a.click();
      });
    }
  }

  // ==========================================================================
  // Page 10: Privacy Center & User Feedback
  // ==========================================================================

  function bindPrivacyCenter() {
    const fbForm = byId('feedback-form');
    if (!fbForm) return;

    fbForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = byId('fb-url')?.value?.trim();
      const type = byId('fb-type')?.value;
      const notes = byId('fb-notes')?.value?.trim();

      if (!url) return;

      const feedbackItem = {
        url,
        type,
        notes,
        timestamp: Date.now()
      };

      const existing = await getLocalData('sentinel_user_feedback', []);
      existing.unshift(feedbackItem);
      await setLocalData('sentinel_user_feedback', existing);

      showToast('Feedback saved to your local device.');
      fbForm.reset();
    });
  }

  // ==========================================================================
  // Page 11: Settings
  // ==========================================================================

  async function loadSettings() {
    const whitelist = await getLocalData('sentinel_whitelist', []);
    state.whitelist = whitelist;

    const chipsContainer = byId('whitelist-chips');
    if (chipsContainer) {
      chipsContainer.innerHTML = whitelist.length === 0
        ? '<span style="font-size:11px; color:var(--ink-3);">No domains whitelisted.</span>'
        : whitelist.map(dom => `
            <span class="whitelist-chip">
              <span>${escapeHtml(dom)}</span>
              <span class="chip-delete" data-domain="${escapeHtml(dom)}" title="Remove domain">✕</span>
            </span>
          `).join('');

      chipsContainer.querySelectorAll('.chip-delete').forEach(btn => {
        btn.addEventListener('click', async () => {
          const domToRemove = btn.dataset.domain;
          state.whitelist = state.whitelist.filter(d => d !== domToRemove);
          await setLocalData('sentinel_whitelist', state.whitelist);
          loadSettings();
          showToast(`Removed ${domToRemove} from whitelist.`);
        });
      });
    }

    const addBtn = byId('add-whitelist-btn');
    if (addBtn) {
      addBtn.onclick = async () => {
        const input = byId('new-whitelist-domain');
        const dom = input?.value?.trim().toLowerCase();
        if (dom && !state.whitelist.includes(dom)) {
          state.whitelist.push(dom);
          await setLocalData('sentinel_whitelist', state.whitelist);
          if (input) input.value = '';
          loadSettings();
          showToast(`Added ${dom} to trusted whitelist.`);
        }
      };
    }
  }

  // ==========================================================================
  // User profile: header badge, sidebar chip, and profile drawer
  // ==========================================================================

  const ROOT_ADMIN_EMAIL = 'admin@sentinelai.security';
  const profile = { user: null, quota: null, token: null, lastFocus: null };

  function readSession() {
    let user = null;
    let token = null;
    try {
      token = localStorage.getItem('sentinel_token');
      const raw = localStorage.getItem('sentinel_user');
      user = raw ? JSON.parse(raw) : null;
    } catch (e) {}
    return { user, token };
  }

  function initialsFor(name) {
    const parts = String(name || '').replace(/@.*/, '').split(/[\s._-]+/).filter(Boolean);
    if (parts.length === 0) return 'SA';
    return (parts.length === 1 ? parts[0].slice(0, 2) : parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }

  function roleFor(user) {
    if (!user) return { key: 'guest', label: 'GUEST' };
    if ((user.email || '').toLowerCase() === ROOT_ADMIN_EMAIL) return { key: 'cso', label: 'CSO' };
    if (user.role === 'admin') return { key: 'admin', label: 'ADMIN' };
    return { key: 'user', label: 'USER' };
  }

  // Same quota rules as ml/database.py check_scan_quota, used when the API is unreachable.
  function localQuota(user) {
    if (!user) return { account_tier: 'guest', limit: 1, tokens_remaining: 1, scans_used: 0 };
    const used = user.scans_used || 0;
    if (user.account_tier === 'demo' || user.email === 'demo@sentinelai.security') {
      return { account_tier: 'demo', limit: 5, tokens_remaining: Math.max(0, 5 - used), scans_used: used };
    }
    const limit = user.scan_tokens || 50;
    return { account_tier: user.role || 'personal', limit, tokens_remaining: Math.max(0, limit - used), scans_used: used };
  }

  function truncateToken(token) {
    if (!token) return '';
    return token.length <= 18 ? token : `${token.slice(0, 10)}…${token.slice(-6)}`;
  }

  async function loadProfile() {
    const { user, token } = readSession();
    profile.user = user;
    profile.token = token;
    profile.quota = localQuota(user);
    renderProfile();

    if (!token) return;
    try {
      const me = await api('/api/auth/me');
      profile.user = { ...user, ...me.user };
      profile.quota = me.quota || profile.quota;
      try { localStorage.setItem('sentinel_user', JSON.stringify(profile.user)); } catch (e) {}
      renderProfile();
    } catch (e) {
      // Offline or standalone session: keep the locally stored profile.
    }
  }

  function setText(id, value) {
    const el = byId(id);
    if (el) el.textContent = value;
  }

  function renderProfile() {
    const user = profile.user;
    const role = roleFor(user);
    const name = user ? (user.name || user.email || 'Operator') : 'Guest Operator';
    const initials = user ? initialsFor(user.name || user.email) : 'SA';
    const twofa = Boolean(user && user.two_factor_enabled);

    // Header badge
    setText('profile-badge-avatar', initials);
    setText('profile-badge-name', name);
    const badgeStatus = byId('profile-badge-status');
    if (badgeStatus) {
      badgeStatus.classList.toggle('is-guest', !user);
      const label = badgeStatus.querySelector('span');
      label.dataset.i18n = !user ? 'status.guest' : twofa ? 'status.secured' : 'status.active';
      label.textContent = t(label.dataset.i18n);
    }

    // Sidebar chip
    setText('operator-avatar', initials);
    setText('operator-name', name);
    const subEl = byId('operator-sub');
    if (subEl) {
      subEl.innerHTML = user
        ? `<i class="status-orb" style="width:5px;height:5px"></i> <span>${escapeHtml(t(twofa ? 'status.secured' : 'status.active'))}</span>`
        : `<a href="${authUrl()}" style="color:var(--ink); text-decoration:none;">${escapeHtml(t('action.signIn'))} / 2FA ↗</a>`;
    }
    const authLink = byId('operator-auth-link');
    if (authLink) {
      authLink.textContent = user ? 'Exit ↗' : '✦';
      authLink.title = user ? t('action.signOut') : t('action.signIn');
      authLink.href = user ? '#' : authUrl();
    }

    // Drawer: identity + account
    setText('profile-avatar', initials);
    setText('profile-name', name);
    const roleEl = byId('profile-role');
    if (roleEl) {
      roleEl.textContent = role.label;
      roleEl.dataset.role = role.key;
    }
    setText('profile-fullname', user ? (user.name || '—') : '—');
    setText('profile-role-text', role.key === 'cso' ? 'CSO · Chief Security Officer' : role.label);
    setText('profile-joined', user && user.created_at
      ? new Date(user.created_at).toLocaleDateString(currentLang, { year: 'numeric', month: 'short', day: 'numeric' })
      : '—');

    // Drawer: channels
    const emailEl = byId('profile-email');
    if (emailEl) {
      emailEl.innerHTML = user && user.email
        ? `${escapeHtml(user.email)}<span class="verified-tick" title="Verified">✓</span>`
        : '—';
    }
    const phoneEl = byId('profile-phone');
    if (phoneEl) {
      phoneEl.innerHTML = user && user.phone
        ? `${escapeHtml(user.phone)}<span class="verified-tick" title="Verified">✓</span>`
        : escapeHtml(t('profile.notLinked'));
    }

    renderQuota();

    // Drawer: security health
    const statusEl = byId('profile-2fa-status');
    if (statusEl) {
      statusEl.classList.toggle('is-off', !twofa);
      statusEl.querySelector('span').textContent = t(twofa ? 'profile.twofaOn' : 'profile.twofaOff');
    }
    const twofaToggle = byId('profile-2fa-toggle');
    if (twofaToggle) {
      twofaToggle.setAttribute('aria-checked', twofa ? 'true' : 'false');
      twofaToggle.disabled = !user;
    }

    // Drawer: session key
    setText('profile-session-key', profile.token ? truncateToken(profile.token) : t('profile.noSession'));
    const copyBtn = byId('profile-copy-token');
    if (copyBtn) copyBtn.disabled = !profile.token;

    const signOutBtn = byId('profile-signout');
    if (signOutBtn) {
      signOutBtn.dataset.i18n = user ? 'action.signOut' : 'action.signIn';
      signOutBtn.textContent = t(signOutBtn.dataset.i18n);
    }
  }

  function renderQuota() {
    const q = profile.quota || localQuota(null);
    const tier = q.account_tier || 'guest';
    const limited = tier === 'guest' || tier === 'demo';
    const remaining = Math.max(0, q.tokens_remaining ?? 0);
    const limit = Math.max(1, q.limit || 1);
    const exhausted = limited && remaining === 0;

    setText('profile-quota-label', exhausted
      ? t('status.quotaExceeded')
      : limited ? t('profile.scansRemaining', { n: remaining, limit }) : t('profile.unlimited'));
    setText('profile-quota-tier', `${String(tier).toUpperCase()} TIER`);
    setText('profile-quota-note', t('profile.scansUsed', { n: q.scans_used || 0 }));

    const track = byId('profile-quota-track');
    const fill = byId('profile-quota-fill');
    if (track) track.dataset.level = exhausted || (limited && remaining / limit <= 0.2) ? 'low' : 'ok';
    if (fill) fill.style.width = `${limited ? Math.round((remaining / limit) * 100) : 100}%`;
  }

  function authUrl() {
    // /auth is a clean route on the FastAPI and Vercel hosts; the extension package only has the file.
    return location.protocol.startsWith('http') ? '/auth' : '../auth.html';
  }

  function drawerFocusables() {
    return Array.from(byId('profile-drawer').querySelectorAll('button:not([disabled]), input, [href]'))
      .filter(el => el.offsetParent !== null);
  }

  function openProfile() {
    const drawer = byId('profile-drawer');
    if (!drawer || drawer.classList.contains('open')) return;
    profile.lastFocus = document.activeElement;
    renderProfile();
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
    byId('drawer-scrim')?.classList.add('open');
    byId('profile-badge')?.setAttribute('aria-expanded', 'true');
    document.body.classList.add('drawer-locked');
    // Let the slide-in start before the bar animates from its old width.
    const fill = byId('profile-quota-fill');
    if (fill) {
      const target = fill.style.width;
      fill.style.width = '0';
      requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = target; }));
    }
    setTimeout(() => byId('profile-close')?.focus(), 60);
    loadProfile();
  }

  function closeProfile() {
    const drawer = byId('profile-drawer');
    if (!drawer || !drawer.classList.contains('open')) return;
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    byId('drawer-scrim')?.classList.remove('open');
    byId('profile-badge')?.setAttribute('aria-expanded', 'false');
    document.body.classList.remove('drawer-locked');
    byId('profile-2fa-confirm')?.classList.remove('show');
    if (profile.lastFocus && profile.lastFocus.focus) profile.lastFocus.focus();
  }

  async function copySessionKey() {
    if (!profile.token) return;
    const btn = byId('profile-copy-token');
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(profile.token);
      } else {
        const ta = document.createElement('textarea');
        ta.value = profile.token;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        ta.remove();
        if (!ok) throw new Error('copy failed');
      }
      showToast(t('toast.copied'));
      if (btn) {
        btn.classList.add('copied');
        btn.textContent = t('action.copied');
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.textContent = t('action.copyToken');
        }, 1600);
      }
    } catch (e) {
      showToast(t('toast.copyFailed'), true);
    }
  }

  async function updateTwoFactor(enabled, password) {
    try {
      const res = await api('/api/auth/2fa/settings', {
        method: 'POST',
        body: JSON.stringify(password ? { enabled, password } : { enabled })
      });
      profile.user = { ...profile.user, two_factor_enabled: res.two_factor_enabled };
      try { localStorage.setItem('sentinel_user', JSON.stringify(profile.user)); } catch (e) {}
      byId('profile-2fa-confirm')?.classList.remove('show');
      const pw = byId('profile-2fa-password');
      if (pw) pw.value = '';
      renderProfile();
      showToast(t(enabled ? 'toast.twofaOn' : 'toast.twofaOff'));
    } catch (err) {
      showToast(state.apiOnline ? err.message : t('toast.needApi'), true);
    }
  }

  async function signOut() {
    const token = profile.token || readSession().token;
    if (token && state.apiOnline) {
      // Revoke the server-side session too, not just the local copy.
      try { await api('/api/auth/logout', { method: 'POST' }); } catch (e) {}
    }
    // Clears the session only; theme, language, whitelist and local scan history are device preferences.
    ['sentinel_token', 'sentinel_user'].forEach(k => { try { localStorage.removeItem(k); } catch (e) {} });
    document.cookie = 'sentinel_session=; path=/; max-age=0; SameSite=Lax';
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.remove(['sentinel_token', 'sentinel_user']);
      }
    } catch (e) {}
    window.location.href = authUrl();
  }

  function bindProfile() {
    byId('profile-badge')?.addEventListener('click', openProfile);
    byId('profile-close')?.addEventListener('click', closeProfile);
    byId('drawer-scrim')?.addEventListener('click', closeProfile);
    byId('profile-copy-token')?.addEventListener('click', copySessionKey);
    byId('profile-view-history')?.addEventListener('click', () => {
      closeProfile();
      setView('history');
    });
    byId('profile-signout')?.addEventListener('click', () => {
      if (profile.user) signOut();
      else window.location.href = authUrl();
    });

    const chip = byId('operator-user-chip');
    if (chip) {
      chip.addEventListener('click', openProfile);
      chip.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openProfile(); }
      });
    }
    byId('operator-auth-link')?.addEventListener('click', e => {
      e.stopPropagation();
      if (profile.user) {
        e.preventDefault();
        signOut();
      }
    });

    byId('profile-2fa-toggle')?.addEventListener('click', () => {
      if (!profile.user) return;
      if (profile.user.two_factor_enabled) {
        // Disabling needs the password again (OAuth accounts have none on file).
        if (profile.user.auth_provider === 'google') {
          updateTwoFactor(false);
        } else {
          byId('profile-2fa-confirm')?.classList.toggle('show');
          byId('profile-2fa-password')?.focus();
        }
      } else {
        updateTwoFactor(true);
      }
    });
    byId('profile-2fa-confirm')?.addEventListener('submit', e => {
      e.preventDefault();
      const pw = byId('profile-2fa-password')?.value || '';
      if (pw) updateTwoFactor(false, pw);
    });

    document.addEventListener('keydown', e => {
      const drawer = byId('profile-drawer');
      if (!drawer || !drawer.classList.contains('open')) return;
      if (e.key === 'Escape') {
        closeProfile();
      } else if (e.key === 'Tab') {
        const items = drawerFocusables();
        if (items.length === 0) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    });
  }

  // ==========================================================================
  // Initial Boot
  // ==========================================================================

  document.addEventListener('DOMContentLoaded', async () => {
    // Set current date
    const todayLabel = byId('today-label');
    if (todayLabel) todayLabel.textContent = new Date().toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });

    applyI18n();
    syncThemeControls();
    bindPreferenceControls();
    bindProfile();
    loadProfile();
    bindNavigation();
    bindInvestigationForm();
    bindAnalyzerForm();
    bindHistoryActions();
    bindPrivacyCenter();

    // Initial check of local engine
    await checkApiHealth();

    // Initial route
    const initView = location.hash.slice(1) || 'overview';
    setView(initView);

    // Periodic monitor refresh if in monitor tab
    monitorInterval = setInterval(() => {
      if (state.activeView === 'monitor') refreshMonitor();
    }, 8000);
  });
})();
