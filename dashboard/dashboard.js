(() => {
  'use strict';

  const FEATURE_NAMES = [
    'url_length', 'domain_length', 'num_dots', 'has_ip', 'has_at_symbol',
    'num_hyphens', 'num_subdomains', 'is_https', 'has_double_slash_in_path',
    'num_suspicious_keywords', 'has_suspicious_tld', 'num_query_params',
    'special_char_count', 'domain_entropy'
  ];
  const VIEW_LABELS = {
    overview: 'Overview', monitor: 'Live monitoring', investigate: 'Investigate URL',
    agent: 'AI investigation', datasets: 'Dataset explorer', training: 'Training lab',
    registry: 'Model registry', history: 'Scan history', settings: 'Settings'
  };
  const state = { datasets: [], selectedDataset: null, datasetValidation: null, datasetOffset: 0, models: [], history: [] };
  const byId = id => document.getElementById(id);
  let toastTimer;
  let monitorTimer;

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
  }

  function formatDate(value, options = { dateStyle: 'medium', timeStyle: 'short' }) {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat(undefined, options).format(date);
  }

  function showToast(message, isError = false) {
    const toast = byId('toast');
    toast.textContent = message;
    toast.classList.toggle('error', isError);
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 3700);
  }

  async function api(path, options = {}) {
    let response;
    try {
      response = await fetch(path, { ...options, headers: { ...(options.body instanceof File ? {} : { 'Content-Type': 'application/json' }), ...options.headers } });
    } catch (error) {
      throw new Error('Cannot reach the local SentinelAI API. Start it with: uvicorn ml.platform_api:app --host 127.0.0.1 --port 8000');
    }
    const contentType = response.headers.get('content-type') || '';
    const body = contentType.includes('application/json') ? await response.json() : await response.text();
    if (!response.ok) {
      const message = typeof body === 'object' ? (body.detail || body.error) : body;
      throw new Error(message || `Request failed (${response.status}).`);
    }
    return body;
  }

  function setView(view) {
    if (!VIEW_LABELS[view]) return;
    document.querySelectorAll('.view').forEach(section => section.classList.toggle('active', section.id === `view-${view}`));
    document.querySelectorAll('.nav-link').forEach(button => button.classList.toggle('active', button.dataset.view === view));
    byId('page-title').textContent = VIEW_LABELS[view];
    if (location.hash !== `#${view}`) history.replaceState(null, '', `#${view}`);
    if (view === 'overview' || view === 'monitor') refreshOverview();
    if (view === 'datasets') loadDatasets();
    if (view === 'training') loadDatasets();
    if (view === 'registry') loadModels();
    if (view === 'history') loadHistory();
    if (view === 'agent') loadAgentLatest();
  }

  function bindNavigation() {
    document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => setView(button.dataset.view)));
    document.querySelectorAll('[data-go]').forEach(button => button.addEventListener('click', () => setView(button.dataset.go)));
    window.addEventListener('hashchange', () => setView(location.hash.slice(1) || 'overview'));
  }

  function setConnection(online, modelVersion) {
    const status = byId('api-status');
    status.classList.toggle('offline', !online);
    status.querySelector('span').textContent = online ? `Local engine · ${modelVersion || 'ready'}` : 'Local engine offline';
  }

  function metricMarkup(metadata, names = ['accuracy', 'precision', 'recall', 'roc_auc']) {
    const metrics = metadata?.evaluation_metrics || {};
    return `<div class="metric-strip">${names.map(name => `<div class="metric-item"><small>${escapeHtml(name.replaceAll('_', ' ').toUpperCase())}</small><strong>${Number.isFinite(metrics[name]) ? `${(metrics[name] * 100).toFixed(1)}%` : '—'}</strong></div>`).join('')}</div>`;
  }

  function riskClass(score) {
    return score > 0.75 ? 'high' : score >= 0.4 ? 'medium' : 'low';
  }

  function riskLevelText(level) {
    return ({ high: 'High risk', medium: 'Review', low: 'Low risk' })[level] || level || 'Unknown';
  }

  function renderRecentScans(items, container) {
    if (!items?.length) {
      container.innerHTML = '<div class="empty-state compact">Run a URL investigation to populate local activity.</div>';
      return;
    }
    container.innerHTML = items.slice(0, 7).map(item => {
      const risk = riskClass(item.risk_score ?? item.riskScore ?? 0);
      return `<div class="recent-item"><i class="risk-bar ${risk}"></i><span class="recent-host" title="${escapeHtml(item.url)}">${escapeHtml(item.hostname || item.url)}</span><time class="recent-time">${escapeHtml(formatDate(item.created_at || item.timestamp, { hour: '2-digit', minute: '2-digit' }))}</time></div>`;
    }).join('');
  }

  function drawActivity(items) {
    const canvas = byId('activity-chart');
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(rect.width * dpr));
    canvas.height = Math.max(1, Math.floor(rect.height * dpr));
    const context = canvas.getContext('2d');
    context.scale(dpr, dpr);
    const width = rect.width;
    const height = rect.height;
    const style = getComputedStyle(document.body);
    const gridColor = document.body.classList.contains('light-theme') ? '#dce4ea' : '#263441';
    const textColor = document.body.classList.contains('light-theme') ? '#718496' : '#718397';
    const now = new Date();
    const days = Array.from({ length: 7 }, (_, index) => {
      const day = new Date(now);
      day.setHours(0, 0, 0, 0);
      day.setDate(day.getDate() - 6 + index);
      return { day, counts: [0, 0, 0] };
    });
    for (const item of items || []) {
      const date = new Date(item.created_at || item.timestamp);
      const index = days.findIndex(entry => entry.day.toDateString() === date.toDateString());
      if (index >= 0) {
        const score = item.risk_score ?? item.riskScore ?? 0;
        days[index].counts[score > 0.75 ? 2 : score >= 0.4 ? 1 : 0] += 1;
      }
    }
    const totals = days.map(entry => entry.counts.reduce((sum, count) => sum + count, 0));
    const max = Math.max(4, ...totals);
    const pad = { left: 23, right: 12, top: 10, bottom: 23 };
    const chartHeight = height - pad.top - pad.bottom;
    const chartWidth = width - pad.left - pad.right;
    context.strokeStyle = gridColor;
    context.lineWidth = 1;
    context.fillStyle = textColor;
    context.font = '9px system-ui';
    for (let tick = 0; tick <= 3; tick += 1) {
      const y = pad.top + chartHeight * tick / 3;
      context.beginPath();
      context.moveTo(pad.left, y);
      context.lineTo(width - pad.right, y);
      context.stroke();
      context.fillText(String(Math.round(max * (1 - tick / 3))), 1, y + 3);
    }
    const points = totals.map((value, index) => ({
      x: pad.left + chartWidth * (index + 0.5) / 7,
      y: pad.top + chartHeight * (1 - value / max)
    }));
    const fill = context.createLinearGradient(0, pad.top, 0, height - pad.bottom);
    fill.addColorStop(0, '#59ceda35');
    fill.addColorStop(1, '#59ceda00');
    context.beginPath();
    points.forEach((point, index) => index ? context.lineTo(point.x, point.y) : context.moveTo(point.x, point.y));
    context.lineTo(points.at(-1).x, height - pad.bottom);
    context.lineTo(points[0].x, height - pad.bottom);
    context.closePath();
    context.fillStyle = fill;
    context.fill();
    context.beginPath();
    points.forEach((point, index) => index ? context.lineTo(point.x, point.y) : context.moveTo(point.x, point.y));
    context.strokeStyle = style.getPropertyValue('--cyan').trim() || '#66d9e8';
    context.lineWidth = 2;
    context.stroke();
    days.forEach((entry, index) => {
      const x = pad.left + chartWidth * (index + 0.5) / 7;
      context.fillStyle = textColor;
      context.textAlign = 'center';
      context.fillText(entry.day.toLocaleDateString(undefined, { weekday: 'short' }), x, height - 5);
      if (totals[index]) {
        context.beginPath();
        context.arc(points[index].x, points[index].y, 3, 0, Math.PI * 2);
        context.fillStyle = style.getPropertyValue('--cyan').trim() || '#66d9e8';
        context.fill();
      }
    });
  }

  async function refreshOverview() {
    try {
      const [overview, models, datasets] = await Promise.all([
        api('/api/overview'), api('/api/models'), api('/api/datasets')
      ]);
      const active = models.items.find(item => item.model_version === models.active_version);
      setConnection(true, models.active_version);
      byId('hero-model-version').textContent = models.active_version.toUpperCase();
      byId('stat-scans').textContent = overview.investigations.toLocaleString();
      byId('stat-high').textContent = overview.high_risk.toLocaleString();
      byId('stat-datasets').textContent = datasets.items.length.toLocaleString();
      byId('stat-rows').textContent = datasets.items.length ? `${datasets.items.length} local CSV file${datasets.items.length === 1 ? '' : 's'}` : 'Import a labeled CSV';
      byId('stat-model').textContent = models.active_version;
      byId('monitor-count').textContent = String(overview.investigations);
      byId('monitor-scans').textContent = overview.investigations.toLocaleString();
      byId('monitor-high').textContent = overview.high_risk.toLocaleString();
      byId('overview-model-date').textContent = active?.date_trained ? `Trained ${active.date_trained} · ${active.dataset?.total_samples?.toLocaleString() || '—'} samples` : 'Active trained model';
      byId('overview-metrics').innerHTML = metricMarkup(active);
      renderRecentScans(overview.recent_scans, byId('overview-recent'));
      renderMonitor(overview.recent_scans);
      drawActivity(overview.recent_scans);
      byId('monitor-updated').textContent = `Updated ${formatDate(new Date(), { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
      if (byId('agent-model-version')) byId('agent-model-version').textContent = models.active_version;
    } catch (error) {
      setConnection(false);
      byId('hero-model-version').textContent = 'ENGINE OFFLINE';
      byId('overview-recent').innerHTML = `<div class="empty-state compact">${escapeHtml(error.message)}</div>`;
      showToast(error.message, true);
    }
  }

  function renderMonitor(items) {
    const target = byId('monitor-list');
    if (!items?.length) {
      target.innerHTML = '<div class="empty-state">No events yet. Run an investigation to see real model results here.</div>';
      return;
    }
    target.innerHTML = `<table><thead><tr><th>Risk</th><th>URL / host</th><th>Prediction</th><th>Model score</th><th>Model version</th><th>Time</th></tr></thead><tbody>${items.map(item => {
      const risk = riskClass(item.risk_score ?? item.riskScore ?? 0);
      const score = item.risk_score ?? item.riskScore ?? 0;
      return `<tr><td><span class="risk-pill ${risk}">${escapeHtml(riskLevelText(risk))}</span></td><td><span class="table-url" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</span></td><td>${escapeHtml(item.prediction || (score >= .5 ? 'phishing' : 'benign'))}</td><td>${(score * 100).toFixed(2)}%</td><td>${escapeHtml(item.model_version || item.modelVersion || '—')}</td><td>${escapeHtml(formatDate(item.created_at || item.timestamp))}</td></tr>`;
    }).join('')}</tbody></table>`;
  }

  function renderInvestigation(report) {
    const result = byId('investigation-result');
    const score = Number(report.risk_score);
    const level = riskClass(score);
    const features = report.features || {};
    const signals = report.signals || report.evidence?.map(detail => ({ severity: 'medium', detail })) || [];
    result.innerHTML = `<article class="result-card">
      <div class="result-top"><div><p class="eyebrow">INVESTIGATION COMPLETE · ${escapeHtml(formatDate(report.created_at || report.timestamp))}</p><strong class="result-domain">${escapeHtml(report.hostname || report.url)}</strong><span class="result-url">${escapeHtml(report.url)}</span></div><div class="risk-score-wrap"><span class="risk-pill ${level}">${escapeHtml(riskLevelText(level))}</span><strong class="risk-score ${level}">${(score * 100).toFixed(2)}%</strong></div></div>
      <div class="result-model">MODEL <strong>${escapeHtml(report.model_type || report.modelType || 'RandomForestClassifier')}</strong> <span>·</span> VERSION <strong>${escapeHtml(report.model_version || report.modelVersion || 'unknown')}</strong> <span>·</span> ${escapeHtml(report.prediction || (score >= .5 ? 'phishing' : 'benign')).toUpperCase()} PROBABILITY</div>
      <div class="result-body"><section class="result-section"><h4>Actual model probabilities</h4><div class="probability-row"><span>Benign</span><div class="probability-track"><span style="width:${Math.max(0, Math.min(100, (report.probabilities?.benign ?? 1 - score) * 100))}%"></span></div><strong>${((report.probabilities?.benign ?? 1 - score) * 100).toFixed(2)}%</strong></div><div class="probability-row phishing"><span>Phishing</span><div class="probability-track"><span style="width:${Math.max(0, Math.min(100, score * 100))}%"></span></div><strong>${(score * 100).toFixed(2)}%</strong></div><h4 style="margin-top:16px">Observed URL signals</h4>${signals.length ? signals.map(signal => `<div class="signal-row"><span class="signal-severity ${escapeHtml(signal.severity || '')}">${escapeHtml((signal.severity || 'signal').toUpperCase())}</span><span>${escapeHtml(signal.detail || signal)}</span></div>`).join('') : '<div class="signal-row"><span class="signal-severity low">CLEAR</span><span>No listed URL heuristic matched. This does not guarantee a site is safe.</span></div>'}</section>
      <section class="result-section"><h4>Canonical 14-feature vector</h4><p class="panel-meta">Values fed to the model in training schema order.</p><div class="feature-grid">${(report.feature_names || FEATURE_NAMES).map(name => `<div class="feature-cell"><small title="${escapeHtml(name)}">${escapeHtml(name)}</small><strong>${escapeHtml(features[name] ?? '—')}</strong></div>`).join('')}</div></section>
      ${(report.limitations || []).length ? `<div class="limitations"><strong>Scope & limitations</strong>${report.limitations.map(item => `<div>• ${escapeHtml(item)}</div>`).join('')}</div>` : ''}
      </div></article>`;
  }

  function showInvestigationError(message) {
    byId('investigation-result').innerHTML = `<div class="result-placeholder"><div class="placeholder-radar"><span>!</span></div><h3>Investigation unavailable</h3><p>${escapeHtml(message)}</p></div>`;
  }

  function renderSchema() {
    byId('schema-list').innerHTML = FEATURE_NAMES.map((name, index) => `<span class="schema-item" title="${index}. ${escapeHtml(name)}">${String(index).padStart(2, '0')} · ${escapeHtml(name)}</span>`).join('');
  }

  function bindInvestigation() {
    byId('investigate-form').addEventListener('submit', async event => {
      event.preventDefault();
      const button = event.currentTarget.querySelector('button[type="submit"]');
      const label = button.querySelector('.scan-label');
      const url = byId('investigate-url').value.trim();
      button.disabled = true;
      label.textContent = 'Analyzing locally…';
      try {
        const report = await api('/api/investigate', { method: 'POST', body: JSON.stringify({ url }) });
        renderInvestigation(report);
        showToast(`Investigation complete · ${(report.risk_score * 100).toFixed(2)}% phishing probability`);
        refreshOverview();
      } catch (error) {
        showInvestigationError(error.message);
        showToast(error.message, true);
      } finally {
        button.disabled = false;
        label.textContent = 'Analyze URL';
      }
    });
  }

  function renderHistoryTable(items, target) {
    if (!items.length) {
      target.innerHTML = '<div class="empty-state">No investigations yet. Run an analysis to create your local audit trail.</div>';
      return;
    }
    target.innerHTML = `<table><thead><tr><th>Result</th><th>URL</th><th>Model score</th><th>Model version</th><th>Investigated</th></tr></thead><tbody>${items.map(item => {
      const score = Number(item.risk_score || 0);
      const level = riskClass(score);
      return `<tr><td><span class="risk-pill ${level}">${escapeHtml(item.prediction || riskLevelText(level))}</span></td><td><span class="table-url" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</span></td><td>${(score * 100).toFixed(2)}%</td><td>${escapeHtml(item.model_version || '—')}</td><td>${escapeHtml(formatDate(item.created_at))}</td></tr>`;
    }).join('')}</tbody></table>`;
  }

  async function loadHistory() {
    try {
      const data = await api('/api/history?limit=500');
      state.history = data.items;
      byId('history-count').textContent = `${data.items.length.toLocaleString()} investigation${data.items.length === 1 ? '' : 's'}`;
      byId('history-updated').textContent = `Refreshed ${formatDate(new Date(), { hour: '2-digit', minute: '2-digit' })}`;
      renderHistoryTable(data.items, byId('history-table'));
    } catch (error) {
      byId('history-table').innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    }
  }

  async function loadAgentLatest() {
    try {
      const data = await api('/api/history?limit=1');
      const target = byId('agent-latest');
      if (!data.items.length) {
        target.className = 'empty-state';
        target.textContent = 'No investigations yet. Submit a URL to create the first report.';
        return;
      }
      const item = data.items[0];
      const level = riskClass(item.risk_score);
      target.className = 'recent-item';
      target.innerHTML = `<i class="risk-bar ${level}"></i><span class="recent-host" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</span><span class="risk-pill ${level}">${(item.risk_score * 100).toFixed(1)}%</span>`;
    } catch (error) {
      byId('agent-latest').textContent = error.message;
    }
  }

  async function loadDatasets() {
    try {
      const response = await api('/api/datasets');
      state.datasets = response.items;
      renderDatasetList();
      const select = byId('training-dataset');
      const current = select.value;
      select.innerHTML = state.datasets.length
        ? state.datasets.map(item => `<option value="${escapeHtml(item.filename)}">${escapeHtml(item.filename)} (${formatBytes(item.size_bytes)})</option>`).join('')
        : '<option value="">Import a CSV dataset first</option>';
      if (state.datasets.some(item => item.filename === current)) select.value = current;
      if (state.selectedDataset && !state.datasets.some(item => item.filename === state.selectedDataset)) state.selectedDataset = null;
      if (!state.selectedDataset && state.datasets.length) state.selectedDataset = state.datasets[0].filename;
      renderDatasetList();
      if (state.selectedDataset) await selectDataset(state.selectedDataset);
    } catch (error) {
      byId('dataset-list').innerHTML = `<div class="empty-state compact">${escapeHtml(error.message)}</div>`;
      byId('training-dataset').innerHTML = '<option value="">Local API unavailable</option>';
    }
  }

  function formatBytes(value) {
    if (!value) return '0 B';
    const index = Math.min(3, Math.floor(Math.log(value) / Math.log(1024)));
    return `${(value / Math.pow(1024, index)).toFixed(index ? 1 : 0)} ${['B', 'KB', 'MB', 'GB'][index]}`;
  }

  function renderDatasetList() {
    const target = byId('dataset-list');
    if (!state.datasets.length) {
      target.innerHTML = '<div class="empty-state compact">No local CSV datasets. Import one to get started.</div>';
      return;
    }
    target.innerHTML = state.datasets.map(item => `<div class="dataset-item ${state.selectedDataset === item.filename ? 'selected' : ''}" data-dataset="${escapeHtml(item.filename)}" role="button" tabindex="0"><span class="dataset-file-icon">▤</span><span><strong>${escapeHtml(item.filename)}</strong><small>${formatBytes(item.size_bytes)}</small></span></div>`).join('');
    target.querySelectorAll('[data-dataset]').forEach(item => {
      item.addEventListener('click', () => selectDataset(item.dataset.dataset));
      item.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') selectDataset(item.dataset.dataset); });
    });
  }

  async function selectDataset(filename) {
    state.selectedDataset = filename;
    state.datasetOffset = 0;
    renderDatasetList();
    byId('dataset-detail-title').textContent = filename;
    byId('dataset-summary').className = 'dataset-summary empty-state compact';
    byId('dataset-summary').textContent = 'Validating rows and loading a preview…';
    try {
      const [validation] = await Promise.all([
        api(`/api/datasets/${encodeURIComponent(filename)}/validate`),
        loadDatasetRows()
      ]);
      state.datasetValidation = validation;
      renderValidation(validation);
    } catch (error) {
      byId('dataset-summary').textContent = error.message;
      byId('dataset-validity').textContent = 'Validation failed';
      byId('dataset-validity').className = 'validation-bad';
    }
  }

  function renderValidation(result) {
    const valid = result.invalid_urls === 0 && result.invalid_labels === 0 && result.has_both_classes;
    byId('dataset-validity').textContent = valid ? 'VALID · both labels present' : 'NEEDS CLEANING';
    byId('dataset-validity').className = valid ? 'validation-ok' : 'validation-bad';
    byId('dataset-summary').className = 'dataset-summary';
    byId('dataset-summary').innerHTML = `<div class="summary-cards"><div class="summary-chip"><small>Total rows</small><strong>${result.total_rows.toLocaleString()}</strong></div><div class="summary-chip"><small>Valid unique</small><strong>${result.valid_rows.toLocaleString()}</strong></div><div class="summary-chip"><small>Benign / phishing</small><strong>${result.class_counts.benign.toLocaleString()} / ${result.class_counts.phishing.toLocaleString()}</strong></div><div class="summary-chip"><small>Invalid / duplicate</small><strong>${(result.invalid_urls + result.invalid_labels + result.duplicate_urls).toLocaleString()}</strong></div></div><button id="clean-dataset" class="button button-small button-quiet">Clean & de-duplicate dataset</button> <span class="panel-meta">Training automatically uses cleaned data.</span>`;
    byId('clean-dataset').addEventListener('click', cleanSelectedDataset);
  }

  async function loadDatasetRows() {
    const filename = encodeURIComponent(state.selectedDataset);
    const response = await api(`/api/datasets/${filename}/rows?offset=${state.datasetOffset}&limit=25`);
    byId('dataset-columns').innerHTML = `<tr>${response.columns.map(column => `<th>${escapeHtml(column)}</th>`).join('')}</tr>`;
    byId('dataset-rows').innerHTML = response.items.map(row => `<tr>${response.columns.map(column => `<td title="${escapeHtml(row[column])}">${escapeHtml(row[column])}</td>`).join('')}</tr>`).join('');
    byId('dataset-page-label').textContent = `Rows ${state.datasetOffset + 1}–${state.datasetOffset + response.items.length}`;
    byId('dataset-prev').disabled = state.datasetOffset === 0;
    byId('dataset-next').disabled = response.items.length < 25;
  }

  async function cleanSelectedDataset() {
    if (!state.selectedDataset) return;
    try {
      const result = await api(`/api/datasets/${encodeURIComponent(state.selectedDataset)}/clean`, { method: 'POST', body: '{}' });
      showToast(`Cleaned ${result.kept_rows.toLocaleString()} rows · dropped ${result.rejected_rows + result.duplicate_rows} invalid/duplicate rows`);
      state.selectedDataset = result.filename;
      await loadDatasets();
    } catch (error) {
      showToast(error.message, true);
    }
  }

  function bindDatasetExplorer() {
    byId('dataset-upload').addEventListener('change', async event => {
      const file = event.target.files[0];
      if (!file) return;
      const name = file.name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 75);
      const filename = name.toLowerCase().endsWith('.csv') ? name : `${name}.csv`;
      showToast(`Importing ${filename}…`);
      try {
        const result = await api(`/api/datasets/${encodeURIComponent(filename)}`, { method: 'PUT', body: file, headers: { 'Content-Type': 'text/csv' } });
        showToast(`Imported ${result.validation.valid_rows.toLocaleString()} valid rows`);
        state.selectedDataset = filename;
        await loadDatasets();
      } catch (error) {
        showToast(error.message, true);
      } finally {
        event.target.value = '';
      }
    });
    byId('refresh-datasets').addEventListener('click', loadDatasets);
    byId('dataset-prev').addEventListener('click', async () => { state.datasetOffset = Math.max(0, state.datasetOffset - 25); await loadDatasetRows(); });
    byId('dataset-next').addEventListener('click', async () => { state.datasetOffset += 25; await loadDatasetRows(); });
  }

  function metricLabel(name) {
    return ({ accuracy: 'Accuracy', precision: 'Precision', recall: 'Recall', f1_score: 'F1 score', roc_auc: 'ROC-AUC', pr_auc: 'PR-AUC', false_positive_rate: 'False positive', false_negative_rate: 'False negative' })[name] || name;
  }

  function renderTrainingResult(job) {
    const target = byId('training-results');
    target.classList.remove('hidden');
    byId('training-model-version').textContent = job.model_version;
    const metrics = job.metrics || {};
    const names = ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc', 'pr_auc', 'false_positive_rate', 'false_negative_rate'];
    byId('training-metrics').innerHTML = names.map(name => `<div class="training-metric"><small>${metricLabel(name)}</small><strong>${Number.isFinite(metrics[name]) ? `${(metrics[name] * 100).toFixed(2)}%` : '—'}</strong></div>`).join('');
    const cm = metrics.confusion_matrix || {};
    byId('training-confusion').innerHTML = `<table><caption>Held-out confusion matrix</caption><thead><tr><th></th><th>Predicted benign</th><th>Predicted phishing</th></tr></thead><tbody><tr><th>Actual benign</th><td>${cm.true_negative ?? '—'}</td><td>${cm.false_positive ?? '—'}</td></tr><tr><th>Actual phishing</th><td>${cm.false_negative ?? '—'}</td><td>${cm.true_positive ?? '—'}</td></tr></tbody></table>`;
    loadModels();
  }

  async function startTraining(event) {
    event.preventDefault();
    const button = byId('start-training');
    const dataset = byId('training-dataset').value;
    if (!dataset) return showToast('Import a dataset before training.', true);
    button.disabled = true;
    byId('training-results').classList.add('hidden');
    byId('training-progress-card').classList.remove('hidden');
    byId('training-error').classList.add('hidden');
    try {
      const job = await api('/api/training', { method: 'POST', body: JSON.stringify({
        dataset,
        n_estimators: Number(byId('estimators').value),
        max_depth: Number(byId('max-depth').value)
      }) });
      let done = false;
      while (!done) {
        await new Promise(resolve => setTimeout(resolve, 1100));
        const status = await api(`/api/training/${encodeURIComponent(job.job_id)}`);
        byId('training-stage').textContent = status.stage || 'Training';
        byId('training-percent').textContent = `${status.progress || 0}%`;
        byId('training-progress-fill').style.width = `${Math.max(0, Math.min(100, status.progress || 0))}%`;
        byId('training-job-info').textContent = `Job ${status.id.slice(0, 12)} · ${status.status}`;
        if (status.status === 'completed') {
          done = true;
          renderTrainingResult(status);
          showToast(`Model ${status.model_version} trained and deployed`);
          refreshOverview();
        } else if (status.status === 'failed') {
          done = true;
          byId('training-error').textContent = status.error || 'Training failed without additional detail.';
          byId('training-error').classList.remove('hidden');
          showToast(status.error || 'Training failed.', true);
        }
      }
    } catch (error) {
      byId('training-error').textContent = error.message;
      byId('training-error').classList.remove('hidden');
      showToast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  function bindTraining() {
    byId('estimators').addEventListener('input', event => { byId('estimators-value').value = event.target.value; });
    byId('max-depth').addEventListener('input', event => { byId('depth-value').value = event.target.value; });
    byId('training-form').addEventListener('submit', startTraining);
  }

  async function loadModels() {
    try {
      const result = await api('/api/models');
      state.models = result.items;
      byId('registry-list').innerHTML = state.models.length ? state.models.map(metadata => {
        const version = metadata.model_version;
        const metrics = metadata.evaluation_metrics || {};
        const active = metadata.active || version === result.active_version;
        return `<article class="registry-card ${active ? 'active-model' : ''}"><div class="registry-card-top"><div class="model-hex">RF</div><div><strong class="registry-card-title">${escapeHtml(metadata.model_type || 'RandomForestClassifier')}</strong><span class="registry-card-version">${escapeHtml(version)}</span></div>${active ? '<span class="active-tag">ACTIVE</span>' : ''}</div><div class="registry-meta"><span>${escapeHtml(metadata.date_trained || 'Training date unavailable')}</span><span>${Number(metadata.dataset?.total_samples || 0).toLocaleString()} samples</span><span>${Number(metadata.hyperparameters?.n_estimators || 0)} trees</span></div>${metricMarkup(metadata)}<div class="registry-actions"><a class="button button-small button-quiet" href="/api/models/${encodeURIComponent(version)}/export">Export JS</a><span class="panel-meta">${escapeHtml(metadata.split_strategy?.type || 'Recorded evaluation')}</span></div></article>`;
      }).join('') : '<div class="empty-state">No model artifacts found.</div>';
      const options = state.models.map(item => `<option value="${escapeHtml(item.model_version)}">${escapeHtml(item.model_version)}${item.active ? ' · active' : ''}</option>`).join('');
      byId('compare-left').innerHTML = options;
      byId('compare-right').innerHTML = options;
      if (state.models.length > 1) byId('compare-right').selectedIndex = 1;
      byId('agent-model-version').textContent = result.active_version;
    } catch (error) {
      byId('registry-list').innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    }
  }

  async function compareModels(event) {
    event.preventDefault();
    const left = byId('compare-left').value;
    const right = byId('compare-right').value;
    if (!left || !right) return showToast('At least one model version is required.', true);
    try {
      const result = await api(`/api/models/compare?left=${encodeURIComponent(left)}&right=${encodeURIComponent(right)}`);
      byId('compare-results').innerHTML = `<table><thead><tr><th>Metric</th><th>${escapeHtml(result.left)}</th><th>${escapeHtml(result.right)}</th></tr></thead><tbody>${Object.entries(result.metrics).map(([name, values]) => `<tr><td>${metricLabel(name)}</td><td>${values[left] == null ? '—' : `${(values[left] * 100).toFixed(2)}%`}</td><td>${values[right] == null ? '—' : `${(values[right] * 100).toFixed(2)}%`}</td></tr>`).join('')}</tbody></table>`;
    } catch (error) {
      showToast(error.message, true);
    }
  }

  async function setTheme(isLight) {
    document.body.classList.toggle('light-theme', isLight);
    localStorage.setItem('sentinel-theme-light', String(isLight));
    byId('settings-theme-toggle').setAttribute('aria-checked', String(isLight));
    byId('theme-toggle').title = isLight ? 'Switch to dark theme' : 'Switch to light theme';
    byId('settings-theme-toggle').setAttribute('aria-label', isLight ? 'Switch to dark theme' : 'Switch to light theme');
    byId('theme-toggle').setAttribute('aria-label', isLight ? 'Switch to dark theme' : 'Switch to light theme');
    drawActivity(state.history);
  }

  function bindSettings() {
    const initialLight = localStorage.getItem('sentinel-theme-light') === 'true';
    const reducedMotion = localStorage.getItem('sentinel-reduce-motion') === 'true';
    setTheme(initialLight);
    document.body.classList.toggle('reduce-motion', reducedMotion);
    byId('motion-toggle').setAttribute('aria-checked', String(reducedMotion));
    const toggleTheme = () => setTheme(!document.body.classList.contains('light-theme'));
    byId('theme-toggle').addEventListener('click', toggleTheme);
    byId('settings-theme-toggle').addEventListener('click', toggleTheme);
    byId('motion-toggle').addEventListener('click', () => {
      const enabled = !document.body.classList.contains('reduce-motion');
      document.body.classList.toggle('reduce-motion', enabled);
      localStorage.setItem('sentinel-reduce-motion', String(enabled));
      byId('motion-toggle').setAttribute('aria-checked', String(enabled));
    });
    byId('check-engine').addEventListener('click', async () => {
      try {
        const health = await api('/api/health');
        setConnection(true, health.model_version);
        showToast(`Local inference engine is ready · ${health.model_version}`);
      } catch (error) {
        setConnection(false);
        showToast(error.message, true);
      }
    });
    byId('clear-history').addEventListener('click', async () => {
      if (!window.confirm('Clear all URL investigation history stored by this local platform?')) return;
      try {
        await api('/api/history', { method: 'DELETE' });
        await Promise.all([loadHistory(), refreshOverview()]);
        showToast('Platform investigation history cleared.');
      } catch (error) {
        showToast(error.message, true);
      }
    });
  }

  function init() {
    byId('today-label').textContent = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date());
    byId('settings-theme-toggle').setAttribute('aria-checked', 'false');
    bindNavigation();
    bindInvestigation();
    bindDatasetExplorer();
    bindTraining();
    byId('refresh-history').addEventListener('click', loadHistory);
    byId('compare-form').addEventListener('submit', compareModels);
    byId('investigate-url').addEventListener('input', event => {
      const clean = event.target.value.trim();
      if (clean && !/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(clean)) event.target.setCustomValidity('Enter a full URL including http:// or https://');
      else event.target.setCustomValidity('');
    });
    byId('schema-list').innerHTML = FEATURE_NAMES.map((name, index) => `<span class="schema-item">${String(index).padStart(2, '0')} · ${escapeHtml(name)}</span>`).join('');
    bindSettings();
    const requestedView = location.hash.slice(1);
    setView(VIEW_LABELS[requestedView] ? requestedView : 'overview');
    refreshOverview();
    monitorTimer = setInterval(() => {
      if (['overview', 'monitor'].includes(location.hash.slice(1) || 'overview')) refreshOverview();
    }, 10_000);
    window.addEventListener('resize', () => drawActivity(state.history));
  }

  document.addEventListener('DOMContentLoaded', init);
})();
