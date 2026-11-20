let D = null, tab = 'ops', openInc = new Set(), lastAck = 0, detailSrc = null, selPayload = null, thrDirty = false;
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const pill = s => `<span class="pill s-${s}">${s}</span>`;
const sev = s => `<span class="sev sev-${s}">${s}</span>`;

function cssVar(name, fallback) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

function setTheme(name) {
  const mode = name === 'medcity' ? 'medcity' : 'humming';
  if (mode === 'medcity') document.documentElement.setAttribute('data-theme', 'medcity');
  else document.documentElement.removeAttribute('data-theme');
  const bh = $('th-humming'), bm = $('th-medcity');
  if (bh) { bh.classList.toggle('active', mode === 'humming'); bh.setAttribute('aria-pressed', String(mode === 'humming')); }
  if (bm) { bm.classList.toggle('active', mode === 'medcity'); bm.setAttribute('aria-pressed', String(mode === 'medcity')); }
  try { localStorage.setItem('hd-theme', mode); } catch (e) {}
  render();
  if (detailSrc && tab === 'fleet') loadDetail(detailSrc, true);
}

try {
  const saved = localStorage.getItem('hd-theme');
  if (saved === 'medcity') setTheme('medcity');
} catch (e) {}

function fmtT(ms, tz) {
  if (!ms) return '–';
  const d = new Date(typeof ms === 'string' ? Date.parse(ms) : ms);
  const mode = $('tzmode') ? $('tzmode').value : 'utc';
  if (mode === 'utc' || (mode === 'src' && !tz)) return d.toISOString().slice(11, 19) + 'Z';
  try {
    return d.toLocaleTimeString('en-GB', {timeZone: mode === 'src' ? tz : undefined, hour12: false}) + (mode === 'src' ? ` ${tz.split('/').pop()}` : '');
  } catch (e) { return d.toISOString().slice(11, 19) + 'Z'; }
}
// date + time in the selected time zone (UTC / source / local), for logs and payloads
function fmtDT(ms, tz) {
  if (!ms) return '–';
  const d = new Date(typeof ms === 'string' ? Date.parse(ms) : ms);
  const mode = $('tzmode') ? $('tzmode').value : 'utc';
  if (mode === 'utc' || (mode === 'src' && !tz)) return d.toISOString().slice(0, 19).replace('T', ' ') + 'Z';
  try {
    return d.toLocaleString('sv-SE', {timeZone: mode === 'src' ? tz : undefined, hour12: false});
  } catch (e) { return d.toISOString().slice(0, 19).replace('T', ' ') + 'Z'; }
}
const STATE_CLS = {Excellent: 'okc', Good: 'goodc', Fair: 'warnc', Poor: 'bad'};
const empty = text => `<p class="empty">${text}</p>`;
const ago = ms => ms ?`${Math.max(0, Math.round((Date.now() - (typeof ms === 'string' ? Date.parse(ms) : ms)) / 1000))}s ago` : '';

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) { showLogin(); throw new Error('auth'); }
  return r.json().then(j => (j.__status = r.status, j));
}
function showLogin() { $('login').classList.remove('hidden'); $('app').classList.add('hidden'); }
async function doLogin(e) {
  e.preventDefault();
  const r = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: $('lu').value, password: $('lp').value})});
  if (!r.ok) { $('lerr').textContent = 'Invalid credentials'; return false; }
  $('login').classList.add('hidden'); $('app').classList.remove('hidden'); thrDirty = false; load();
  return false;
}
async function logout() { await fetch('/api/logout', {method: 'POST'}); location.reload(); }

document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('on', x === b));
  tab = b.dataset.tab;
  document.querySelectorAll('.tab').forEach(s => s.classList.toggle('hidden', s.id !== 'tab-' + tab));
  if (tab === 'proof') loadPayloads();
  render();
});

async function load() {
  try { D = await api('/api/overview'); } catch (e) { return; }
  $('app').classList.remove('hidden'); $('login').classList.add('hidden');
  render();
  // collection -> dashboard latency: event timestamp of the newest point vs. the moment it is rendered here
  if (D.newest_event_ms && D.newest_event_ms !== lastAck) {
    lastAck = D.newest_event_ms;
    requestAnimationFrame(() => fetch('/api/render-ack', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({event_ts_ms: D.newest_event_ms, render_ms: Date.now()})}));
  }
  if (detailSrc && tab === 'fleet') loadDetail(detailSrc, true);
}

function render() {
  if (!D) return;
  const T = D.tenant;
  $('tname').textContent = T.name;
  $('tstate').className = 'pill s-' + T.state; $('tstate').textContent = T.state;
  $('tstate').title = T.reason;
  $('hmeta').innerHTML = `<span>Residency ${esc(T.region)} (${esc(T.region_name)})</span><span>Server time ${fmtT(D.server_time)}</span>`;
  $('who').textContent = `${D.user.username} (${D.user.role})`;
  if (tab === 'ops') renderOps();
  if (tab === 'fleet') renderFleet();
  if (tab === 'slo') renderSlo();
  if (tab === 'settings') renderSettings();
}

// ------------------------------------------------------------------ monitoring charts
const CPCB = {pm25_ugm3: [30, 60, 90, 120, 250], pm10_ugm3: [50, 100, 250, 350, 430], no2_ugm3: [40, 80, 180, 280, 400]};
const CPCB_NAMES = ['Good', 'Satisfactory', 'Moderate', 'Poor', 'Very Poor', 'Severe'];
const CPCB_COLORS = ['#16843D', '#65A30D', '#CA8A04', '#EA580C', '#DC2626', '#9F1239'];
const SERIES_COLORS = ['#4263A3', '#D97706', '#16843D', '#9333EA', '#0891B2', '#DC2626', '#64748B', '#DB2777'];
const LABELS = {pm25_ugm3: 'PM2.5', pm10_ugm3: 'PM10', no2_ugm3: 'NO2', cpu_pct: 'CPU', mem_pct: 'Memory', disk_pct: 'Disk',
  latency_ms: 'Latency', packet_loss_pct: 'Packet loss', bw_in_mbps: 'Inbound traffic'};
const UNITS = {pm25_ugm3: 'µg/m³', pm10_ugm3: 'µg/m³', no2_ugm3: 'µg/m³', cpu_pct: '%', mem_pct: '%', disk_pct: '%',
  latency_ms: 'ms', packet_loss_pct: '%', bw_in_mbps: 'Mbps'};
let trend = {key: null, at: 0, data: null};

function cpcbIndex(metric, v) { const b = CPCB[metric] || []; const i = b.findIndex(x => v <= x); return i < 0 ? b.length : i; }
function tenantIsAir() { return D.sources.some(isAir); }
function niceStep(x) { const p = Math.pow(10, Math.floor(Math.log10(x || 1))); return [1, 2, 2.5, 5, 10].map(m => m * p).find(v => v >= x) || p * 10; }
function fmtNum(v) { return Math.abs(v) >= 10 || v === 0 ? String(Math.round(v)) : v.toFixed(1); }
// canvas text uses the page's own font, so charts match the rest of the UI
const chartFont = (size, weight) => `${weight || 400} ${size || 12}px ${getComputedStyle(document.body).fontFamily}`;
function fmtAxisT(t, span) {
  const mode = $('tzmode') ? $('tzmode').value : 'utc';
  const opt = mode === 'utc' ? {timeZone: 'UTC'} : mode === 'src' && tenantIsAir() ? {timeZone: 'Asia/Kolkata'} : {};
  const d = new Date(t);
  return span > 36 * 3600e3
    ? d.toLocaleString('en-GB', Object.assign({weekday: 'short', hour: '2-digit', hour12: false}, opt)) + 'h'
    : d.toLocaleTimeString('en-GB', Object.assign({hour: '2-digit', minute: '2-digit', hour12: false}, opt));
}

// Line chart with a shared y scale, axes, time labels, dashed reference lines (bands) and alert shading.
function drawChart(c, o) {
  const dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
  if (!w || !h) return;
  c.width = w * dpr; c.height = h * dpr;
  const g = c.getContext('2d'); g.scale(dpr, dpr); g.clearRect(0, 0, w, h);
  const muted = cssVar('--color-text-muted', '#65766C'), grid = cssVar('--border-subtle', '#E1EAE3');
  const cErr = cssVar('--status-poor-dot', '#DC2626');
  g.font = chartFont(12);
  const pts = o.series.flatMap(s => s.pts || []);
  if (!pts.length) { g.fillStyle = muted; g.fillText(o.empty || 'no data yet', 12, h / 2); return; }
  const L = 46, R = 12, T = o.unit ? 22 : 10, B = 22;
  const t0 = Math.min(...pts.map(p => p[0])), t1 = Math.max(...pts.map(p => p[0]));
  const bands = (o.bands || []).filter(b => b.v != null);
  let hi = Math.max(...pts.map(p => p[1]), ...bands.map(b => b.v)) * 1.08 || 1;
  const step = niceStep(hi / 4); hi = Math.ceil(hi / step) * step;
  const X = t => L + (w - L - R) * (t - t0) / Math.max(t1 - t0, 1);
  const Y = v => T + (h - T - B) * (1 - Math.min(Math.max(v, 0), hi) / hi);
  g.lineWidth = 1; g.strokeStyle = grid; g.fillStyle = muted; g.textAlign = 'right'; g.textBaseline = 'middle';
  for (let v = 0; v <= hi + 1e-9; v += step) {
    g.beginPath(); g.moveTo(L, Y(v)); g.lineTo(w - R, Y(v)); g.stroke(); g.fillText(fmtNum(v), L - 6, Y(v));
  }
  g.textAlign = 'center'; g.textBaseline = 'top';
  const ticks = w < 420 ? 2 : 4;
  for (let i = 0; i <= ticks; i++) { const t = t0 + (t1 - t0) * i / ticks; g.fillText(fmtAxisT(t, t1 - t0), Math.min(Math.max(X(t), L + 18), w - R - 18), h - B + 6); }
  if (o.unit) { g.textAlign = 'left'; g.textBaseline = 'top'; g.fillText(o.unit, 4, 2); }
  (o.shade || []).forEach(([a, b]) => {
    const x0 = X(Math.max(a, t0)), x1 = X(Math.min(b || t1, t1));
    g.fillStyle = cErr; g.globalAlpha = 0.12; g.fillRect(x0, T, Math.max(2, x1 - x0), h - T - B); g.globalAlpha = 1;
  });
  const used = [];
  bands.slice().sort((a, b) => b.v - a.v).forEach(b => {
    g.setLineDash([5, 4]); g.strokeStyle = b.color; g.globalAlpha = 0.8; g.lineWidth = 1.2;
    g.beginPath(); g.moveTo(L, Y(b.v)); g.lineTo(w - R, Y(b.v)); g.stroke(); g.setLineDash([]); g.globalAlpha = 1;
    // label inside the plot on the left, skipped when it would collide with the previous one
    if (b.label && used.every(y => Math.abs(y - Y(b.v)) > 13)) {
      used.push(Y(b.v)); g.fillStyle = b.color; g.textAlign = 'left'; g.textBaseline = 'bottom'; g.fillText(b.label, L + 4, Y(b.v) - 2);
    }
  });
  o.series.forEach(s => {
    const p = s.pts || []; if (!p.length) return;
    g.strokeStyle = s.color; g.lineWidth = s.width || 2; g.lineJoin = 'round'; g.lineCap = 'round';
    g.beginPath(); p.forEach((q, i) => i ? g.lineTo(X(q[0]), Y(q[1])) : g.moveTo(X(q[0]), Y(q[1]))); g.stroke();
    const last = p[p.length - 1]; g.fillStyle = s.color; g.beginPath(); g.arc(X(last[0]), Y(last[1]), 3, 0, 7); g.fill();
  });
}

// Horizontal bars grouped (e.g. monitors by city), coloured per row, with dashed vertical reference lines.
function drawBars(c, groups, o) {
  const rowH = 20, groupH = 22, n = groups.reduce((a, g) => a + g.rows.length, 0);
  c.style.height = (n * rowH + groups.length * groupH + 34) + 'px';
  const dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
  if (!w || !h) return;
  c.width = w * dpr; c.height = h * dpr;
  const g = c.getContext('2d'); g.scale(dpr, dpr); g.clearRect(0, 0, w, h);
  const muted = cssVar('--color-text-muted', '#65766C'), text = cssVar('--color-text-primary', '#1F2A24'), grid = cssVar('--border-subtle', '#E1EAE3');
  g.font = chartFont(12);
  if (!n) { g.fillStyle = muted; g.fillText(o.empty || 'no data yet', 12, h / 2); return; }
  const L = Math.max(90, Math.min(150, w * 0.4)), R = 44, T = 22;
  const vals = groups.flatMap(gr => gr.rows.map(r => r.value));
  let hi = Math.max(...vals, ...(o.bands || []).map(b => b.v)) * 1.05 || 1;
  const step = niceStep(hi / (w < 420 ? 2 : 4)); hi = Math.ceil(hi / step) * step;
  const fit = s => { let t = s; while (t.length > 2 && g.measureText(t).width > L - 12) t = t.slice(0, -2) + '…'; return t; };
  const X = v => L + (w - L - R) * Math.min(v, hi) / hi;
  const bottom = h - 12;
  g.strokeStyle = grid; g.fillStyle = muted; g.textAlign = 'center'; g.textBaseline = 'bottom';
  for (let v = 0; v <= hi + 1e-9; v += step) { g.beginPath(); g.moveTo(X(v), T); g.lineTo(X(v), bottom); g.stroke(); g.fillText(fmtNum(v), X(v), T - 4); }
  (o.bands || []).forEach(b => {
    g.setLineDash([5, 4]); g.strokeStyle = b.color; g.lineWidth = 1.2; g.beginPath(); g.moveTo(X(b.v), T); g.lineTo(X(b.v), bottom); g.stroke();
    g.setLineDash([]); g.lineWidth = 1;
  });
  let y = T + 4;
  groups.forEach(gr => {
    g.fillStyle = text; g.font = chartFont(12, 600); g.textAlign = 'left'; g.textBaseline = 'middle';
    g.fillText(gr.name, 4, y + groupH / 2); y += groupH;
    g.font = chartFont(12);
    gr.rows.forEach(r => {
      g.fillStyle = muted; g.textAlign = 'right'; g.fillText(fit(r.label), L - 8, y + rowH / 2);
      g.fillStyle = r.color; g.fillRect(L, y + 4, Math.max(2, X(r.value) - L), rowH - 8);
      g.fillStyle = text; g.textAlign = 'left'; g.fillText(fmtNum(r.value), X(r.value) + 5, y + rowH / 2);
      y += rowH;
    });
  });
}

function legend(items) {
  return items.map(i => `<span class="lg"><i class="${i.dash ? 'dash' : ''}" style="--c:${i.color}"></i>${esc(i.label)}</span>`).join('');
}

function monMetricOptions(air) {
  const sel = $('mon-metric'), want = air ? ['pm25_ugm3', 'pm10_ugm3', 'no2_ugm3'] : ['cpu_pct', 'latency_ms', 'mem_pct', 'packet_loss_pct'];
  if (sel.dataset.kind !== (air ? 'air' : 'host')) {
    sel.innerHTML = want.map(m => `<option value="${m}">${LABELS[m]}</option>`).join('');
    sel.dataset.kind = air ? 'air' : 'host';
  }
  return sel.value;
}

async function renderMonitoring() {
  const air = tenantIsAir(), metric = monMetricOptions(air);
  // A: air -> current value per monitor grouped by city, coloured by CPCB category; hosts -> CPU per service
  if (air) {
    const bySite = {};
    D.sources.filter(isAir).forEach(s => {
      const v = s.latest[metric]; if (!v) return;
      (bySite[s.site] = bySite[s.site] || []).push({label: s.service, value: v.value, color: CPCB_COLORS[cpcbIndex(metric, v.value)]});
    });
    const groups = Object.keys(bySite).sort().map(k => ({name: k, rows: bySite[k].sort((a, b) => b.value - a.value)}));
    $('mon-a-title').innerHTML = `${LABELS[metric]} by monitor <span class="sub">Latest reading, µg/m³</span>`;
    drawBars($('mon-a'), groups, {bands: (CPCB[metric] || []).slice(0, 3).map((v, i) => ({v, color: CPCB_COLORS[i + 1]}))});
    $('mon-a-legend').innerHTML = legend(CPCB_NAMES.map((n, i) => ({label: `${n}${CPCB[metric] && i < 5 ? ' up to ' + CPCB[metric][i] : ''}`, color: CPCB_COLORS[i]})));
  }
  // B: trend from /api/trends (per city for air, per source for hosts); refreshed every 60 s / 10 s
  const minutes = air ? 4 * 1440 : 30, key = `${metric}:${minutes}`;
  if (trend.key !== key || Date.now() - trend.at > (air ? 60000 : 10000)) {
    trend = {key, at: Date.now(), data: trend.key === key ? trend.data : null};
    trend.data = await api(`/api/trends?metric=${metric}&minutes=${minutes}`);
  }
  const td = trend.data; if (!td || !td.sources) return;
  if (air) {
    const series = td.sites.map((s, i) => ({pts: s.points, color: SERIES_COLORS[i % SERIES_COLORS.length], label: s.site}));
    $('mon-b-title').innerHTML = `${LABELS[metric]} by city <span class="sub">Average per city, last 4 days</span>`;
    const bands = (CPCB[metric] || []).slice(0, 3).map((v, i) => ({v, color: CPCB_COLORS[i + 1]}));
    drawChart($('mon-b'), {series, unit: 'µg/m³', bands});
    $('mon-b-legend').innerHTML = legend(series.map(s => ({label: s.label, color: s.color}))
      .concat(bands.map((b, i) => ({label: `${CPCB_NAMES[i]} limit ${b.v}`, color: b.color, dash: true}))));
  } else {
    const series = td.sources.map((s, i) => ({pts: s.points, color: SERIES_COLORS[i % SERIES_COLORS.length], label: `${s.service} (${s.source_id.slice(4, 9)})`, width: 1.6}));
    const thr = D.thresholds[metric];
    $('mon-a-title').innerHTML = `${LABELS[metric]} by source <span class="sub">Last 30 minutes</span>`;
    drawChart($('mon-a'), {series, unit: UNITS[metric], bands: thr ? [{v: thr[2], color: cssVar('--status-poor-dot', '#DC2626')}] : []});
    $('mon-a-legend').innerHTML = legend(series.map(s => ({label: s.label, color: s.color}))
      .concat(thr ? [{label: `Safety limit ${thr[2]}`, color: cssVar('--status-poor-dot', '#DC2626'), dash: true}] : []));
    const bySite = td.sites.map((s, i) => ({pts: s.points, color: SERIES_COLORS[i % SERIES_COLORS.length], label: s.site}));
    $('mon-b-title').innerHTML = `${LABELS[metric]} by site <span class="sub">Average per site, last 30 minutes</span>`;
    drawChart($('mon-b'), {series: bySite, unit: UNITS[metric]});
    $('mon-b-legend').innerHTML = legend(bySite.map(s => ({label: s.label, color: s.color})));
  }
}

function renderOps() {
  renderMonitoring();
  const cnt = {Excellent: 0, Good: 0, Fair: 0, Poor: 0};
  D.sources.forEach(s => cnt[s.state]++); D.collectors.forEach(c => cnt[c.state]++);
  const openI = D.incidents.filter(i => i.status === 'open').length;
  const openA = D.alerts.filter(a => a.status === 'open').length;
  const n = D.counters.noise || {};
  const total = D.sources.length + D.collectors.length;
  $('summary').innerHTML = [
    ['Overall', `<span class="${STATE_CLS[D.tenant.state] || 'unkc'}">${esc(D.tenant.state)}</span>`, esc(D.tenant.reason)],
    ['Open incidents', `<span class="${openI ? 'bad' : ''}">${openI}</span>`, `${openA} open alerts grouped into incidents`],
    ['Monitored', `${total}`, `<span class="okc">${cnt.Excellent} Excellent</span>, <span class="goodc">${cnt.Good} Good</span>, <span class="warnc">${cnt.Fair} Fair</span>, <span class="bad">${cnt.Poor} Poor</span>`],
    ['Noise reduced', `${n.duplicates_suppressed || 0}`, `repeat notifications folded into ${n.alerts_raised || 0} alerts and ${n.incidents || 0} incidents`],
  ].map(([l, v, s]) => `<div class="card stat"><div class="l">${l}</div><div class="v">${v}</div><div class="small mut clamp2">${s}</div></div>`).join('');

  $('incidents').innerHTML = D.incidents.length ? D.incidents.map(incidentHtml).join('')
    : empty('No incidents. Inject a scenario from a collector console to see detection, correlation and recommendations.');
  const ents = [...D.collectors.map(c => ({n: c.collector_id, s: c.state || 'Unknown', r: c.reason, k: null})),
                ...D.sources.map(s => ({n: `${s.service}, ${s.site}`, s: s.state || 'Unknown', r: s.reason, k: s.source_id}))];
  $('healthmap').innerHTML = ents.length ? ents.map(e => `<div class="hcell s-${esc(e.s)}" title="${esc(e.r)}"><div class="hcell-top"><span class="hcell-name">${esc(e.n)}</span><span class="small strong">${esc(e.s)}</span></div>`
    + `${e.k ? `<span class="small mono">${esc(e.k)}</span>` : '<span class="small">Collector</span>'}<span class="small clamp2">${esc(e.r)}</span></div>`).join('') : empty('Nothing reporting yet.');
  const open = D.alerts.filter(a => a.status === 'open');
  $('alerts').innerHTML = open.length ? `<table><tbody>${open.map(a => `<tr><td>${sev(a.severity)}</td><td>${esc(a.title)}<div class="small mut"><span class="mono">${esc(a.source_id || a.collector_id)}</span>, ${esc(a.kind)}, ${a.count} ${a.count === 1 ? 'time' : 'times'}, since ${fmtT(a.first_event_ms)}${a.incident_id ? `, incident ${a.incident_id}` : ''}</div></td></tr>`).join('')}</tbody></table>`
    : empty('No open alerts.');
  $('history').innerHTML = D.history.length ? `<table><thead><tr><th>Time</th><th>Entity</th><th>Change</th></tr></thead><tbody>${D.history.map(h => `<tr><td>${fmtT(h.ts_ms)}</td><td>${esc(h.entity)}</td><td>${h.prev ? `${pill(h.prev)} <span class="small mut">to</span> ` : ''}${pill(h.state)}<div class="small mut">${esc(h.reason)}</div></td></tr>`).join('')}</tbody></table>`
    : empty('No health transitions yet.');
}

function srcTz(sid) { const s = D.sources.find(x => x.source_id === sid); return s && s.tz; }

// ML feature 2: share of total deviation per (source, signal), root and symptoms drawn separately.
function deviationHtml(dev) {
  if (!dev || !(dev.root.length + dev.symptoms.length)) return '';
  const bar = (r, cls) => `<div class="dev-row"><span class="dev-label">${esc(r.service)}, ${esc(r.signal)}</span>
    <span class="dev-track"><span class="dev-bar ${cls}" style="--w:${Math.max(1, r.share)}%"></span></span>
    <span class="dev-val">${r.share.toFixed(1)}% <span class="mut small">z ${r.z}</span></span></div>`;
  const ev = dev.events.length ? `<p class="small mut">Event signals (no z-score, not in the shares): ${dev.events.map(e => esc(e.signal)).join(', ')}</p>` : '';
  return `<h3>Share of total deviation <span class="sub">Composite score ${dev.composite_score}</span></h3>
    <div class="dev">${dev.root.map(r => bar(r, 'root')).join('')}${dev.symptoms.map(r => bar(r, 'sym')).join('')}</div>
    <p class="small mut">Darker bars: root (${esc(dev.root[0] ? dev.root[0].service : 'n/a')}). Lighter bars: symptoms. Size of deviation is not cause; the root is chosen by onset time and dependency position.</p>${ev}`;
}

function incidentHtml(i) {
  const a = i.analysis || {}, r = a.recommendation || {}, open = openInc.has(i.id);
  const conf = Math.round((r.confidence || 0) * 100);
  let body = '';
  if (open) {
    const sigRows = (a.signals || []).map(s => {
      const d = s.detail || {};
      const val = d.value !== undefined ? `${d.value}${d.unit || ''}` : (d.count !== undefined ? `count ${d.count}` : '');
      const base = d.baseline !== undefined && d.baseline !== null ? `${d.baseline}${d.unit || ''} ± ${d.spread}` : '–';
      const role = (a.ranking && a.ranking[0] && (s.source_id || s.collector_id) === a.ranking[0].source) ? '<span class="tag warn">root</span>' : '<span class="mut">symptom</span>';
      return `<tr><td>${role}</td><td>${esc(s.service)}<div class="small mono mut">${esc(s.source_id || s.collector_id)}</div></td><td>${esc(s.signal)}<div class="small mut">${esc(s.kind)}${s.classification ? ', ' + esc(s.classification) : ''}</div></td>
        <td>${esc(val)}</td><td>${esc(base)}</td><td>${d.z ?? '–'}${d.peak_z ? `<div class="small mut">peak ${d.peak_z}</div>` : ''}</td><td>${fmtT(s.onset, s.source_id && srcTz(s.source_id))}</td><td>${s.status}</td></tr>`;
    }).join('');
    const corr = (a.correlation || []).map(c => `<li>alert #${c.alert} joined ${c.joined.slice(11, 19)}Z: ${esc(c.reason)}</li>`).join('');
    const rank = (a.ranking || []).map(x => `<tr><td>${esc(x.service)} <span class="small mono mut">${esc(x.source)}</span></td><td class="num">${x.score}</td><td class="small">onset ${x.factors.earliest_onset}, upstream ${x.factors.upstream_of_affected}, severity ${x.factors.severity}, signals ${x.factors.signal_count}</td></tr>`).join('');
    body = `<div class="inc-b">
      <h3>Likely cause</h3><p>${esc(r.likely_cause)}</p>
      <h3>Contributing signals</h3>
      <div class="scroll table-wrap"><table><thead><tr><th>Role</th><th>Source</th><th>Signal</th><th>Value</th><th>Baseline (median ± spread)</th><th class="num">z</th><th>Onset</th><th>Status</th></tr></thead><tbody>${sigRows}</tbody></table></div>
      ${deviationHtml(r.deviation)}
      <h3>Reasoning path</h3><ol>${(r.reasoning || []).map(x => `<li>${esc(x)}</li>`).join('')}</ol>
      <h3>Confidence ${conf}%</h3><ul>${(r.confidence_factors || []).map(x => `<li>${esc(x)}</li>`).join('')}</ul>
      ${rank && (a.ranking || []).length > 1 ? `<h3>Root-cause ranking</h3><div class="table-wrap"><table><thead><tr><th>Source</th><th class="num">Score</th><th>Factors</th></tr></thead><tbody>${rank}</tbody></table></div>` : ''}
      <h3>Correlation</h3><ul>${corr}</ul>
      ${a.noise ? `<p class="small mut">${a.noise.alerts} alerts from ${a.noise.sources} sources merged; ${a.noise.duplicates_suppressed} repeat notifications suppressed.</p>` : ''}
      ${actionHtml(i, r)}
    </div>`;
  }
  return `<div class="inc ${open ? 'is-open' : ''}"><div class="inc-h" data-call="toggleInc" data-arg="${i.id}" tabindex="0" role="button" aria-expanded="${open}">${sev(i.severity)}<span class="t">Incident ${i.id}: ${esc(i.title)}</span>
    <span class="conf small">${conf}% <span class="bar"><i style="--w:${conf}%"></i></span></span>
    <span class="small mut">${i.status === 'open' ? 'Open' : 'Resolved'}, ${(a.signals || []).length} signals, ${ago(i.updated_ms)}</span></div>${body}</div>`;
}

function actionHtml(i, r) {
  const act = r.action;
  if (!act) return '';
  const rows = i.actions || [];
  const head = `<div class="action"><h3>Recommended action: ${esc(act.label)}</h3>
    <div class="row"><span class="tag">risk ${esc(act.risk)}</span><span class="tag">${act.reversible ? 'reversible' : 'not reversible'}</span><span class="tag">${act.automatable ? 'automatable (simulated)' : 'manual runbook'}</span></div>
    <dl class="meta note"><dt>Why</dt><dd>${esc(act.why)}</dd><dt>Rollback</dt><dd>${esc(act.rollback)}</dd>
    ${(r.alternatives || []).length ? `<dt>Alternatives</dt><dd>${r.alternatives.map(esc).join('; ')}</dd>` : ''}</dl>`;
  const acts = rows.map(a => {
    const pol = a.policy_preview;
    const checks = pol ? `<ul class="chk small">${pol.checks.map(c => `<li class="${c.ok ? '' : 'no'}"><span>${esc(c.check)}${c.detail ? ` <span class="mut">(${esc(c.detail)})</span>` : ''}${c.ok ? '' : ' <span class="bad">blocked</span>'}</span></li>`).join('')}</ul>` : '';
    let btn = '';
    if (a.status === 'proposed') btn = `<button data-call="doAct" data-arg="${a.id}" data-arg2="approve" ${pol && pol.allowed ? '' : 'disabled'}>Approve &amp; run (simulated)</button> <button class="sec" data-call="doAct" data-arg="${a.id}" data-arg2="reject">Reject</button>`;
    if (a.status === 'executed') btn = `<button class="danger" data-call="doAct" data-arg="${a.id}" data-arg2="rollback">Roll back</button>`;
    return `<div class="action-item"><span class="strong">Action ${a.id}:</span> ${esc(a.action)} on <span class="mono">${esc(a.source_id)}</span> <span class="tag">${esc(a.status)}</span>
      ${a.approved_by ? `<span class="small mut">approved by ${esc(a.approved_by)}</span>` : ''}${a.result ? `<div class="small mut">${esc(a.result)}</div>` : ''}
      ${a.status === 'proposed' ? '<div class="small mut note">Policy check before approval:</div>' + checks : ''}<div class="action-btns">${btn}</div></div>`;
  }).join('');
  return head + acts + '</div>';
}
function toggleInc(id) { openInc.has(id) ? openInc.delete(id) : openInc.add(id); renderOps(); }
async function doAct(id, op) {
  const r = await api(`/api/actions/${id}/${op}`, {method: 'POST', body: '{}'});
  if (r.__status !== 200) alert(r.error + (r.policy ? '\n' + r.policy.checks.filter(c => !c.ok).map(c => 'Failed: ' + c.check).join('\n') : ''));
  load();
}

function renderFleet() {
  $('collectors').innerHTML = D.collectors.length ? `<table><thead><tr><th>Collector</th><th>State</th><th>Last seen</th><th>Version</th><th>Resources</th><th class="num">Buffer</th><th>Sequence</th></tr></thead><tbody>${D.collectors.map(c => `
    <tr><td><span class="strong">${esc(c.collector_id)}</span><div class="small mut">${esc(c.site)}, ${esc(c.tz)}</div></td><td>${pill(c.state)}<div class="small mut">${esc(c.reason)}</div></td>
    <td>${c.age_s} s ago<div class="small mut">${fmtT(c.last_seen, c.tz)}</div></td><td>${esc(c.version)}<div class="small mut"><span class="mono">${esc(c.config_hash)}</span>, policy ${esc(c.policy_version)}</div></td>
    <td>CPU ${c.stats.cpu_pct ?? '–'}%<div class="small mut">${c.stats.rss_mb ?? '–'} MB memory</div></td><td class="num">${c.stats.buffer_depth ?? 0}</td>
    <td>${c.stats.seq_created ?? '–'} created, ${c.received} received<div class="small ${c.missing ? 'bad' : 'mut'}">${c.missing ? c.missing + ' missing' : 'no gaps'}</div></td></tr>`).join('')}</tbody></table>`
    : empty('No collector has connected yet.');
  const val = (L, k) => L[k] ? `${L[k].value} ${UNITS[k]}` : '–';
  $('sources').innerHTML = D.sources.length ? D.sources.map(s => {
    const L = s.latest, keys = isAir(s) ? ['pm25_ugm3', 'pm10_ugm3', 'no2_ugm3'] : ['cpu_pct', 'mem_pct', 'disk_pct', 'latency_ms', 'packet_loss_pct', 'bw_in_mbps'];
    return `<div class="src ${detailSrc === s.source_id ? 'is-selected' : ''}" tabindex="0" role="button" data-call="loadDetail" data-arg="${esc(s.source_id)}">
      <div class="src-head"><span class="src-name">${esc(s.service)}</span>${pill(s.state || 'Unknown')}</div>
      <div class="small mut"><span class="mono">${esc(s.source_id)}</span>, ${esc(s.role)}, ${esc(s.site)}</div>
      <div class="kv">${keys.map(k => `<span>${LABELS[k]}<br>${val(L, k)}</span>`).join('')}</div>
      ${isAir(s) ? `<div class="small mut">Measured ${airAge(L)} ago</div>` : ''}
      <canvas class="spark" data-spark="${esc(s.source_id)}"></canvas><div class="small mut clamp2">${esc(s.reason)}</div></div>`;
  }).join('') : empty('No sources reporting yet.');
  const primary = cssVar('--color-primary', '#4263A3'), secondary = cssVar('--status-fair-dot', '#D97706');
  document.querySelectorAll('canvas[data-spark]').forEach(c => {
    const s = D.sources.find(x => x.source_id === c.dataset.spark);
    drawLines(c, isAir(s) ? [{pts: s.spark.pm25_ugm3, color: primary}, {pts: s.spark.pm10_ugm3, color: secondary}]
      : [{pts: s.spark.cpu_pct, color: primary, max: 100}, {pts: s.spark.latency_ms, color: secondary}]);
  });
}

function airAge(L) {
  const ts = ['pm25_ugm3', 'pm10_ugm3', 'no2_ugm3'].map(k => L[k] && Date.parse(L[k].ts)).filter(Boolean);
  if (!ts.length) return '–';
  const m = Math.round((Date.now() - Math.max(...ts)) / 60000);
  return m < 90 ? `${m} min` : `${(m / 60).toFixed(1)} h`;
}
// a live air-quality monitor (OpenAQ) reports pollutant concentrations instead of host metrics
function isAir(s) { return !!(s && s.latest && (s.latest.pm25_ugm3 || s.latest.pm10_ugm3 || s.role === 'air-monitor')); }

let detailCache = {sid: null, at: 0, r: null};
async function loadDetail(sid, quiet) {
  detailSrc = sid;
  const s = D.sources.find(x => x.source_id === sid) || {};
  const air = isAir(s);
  if (!quiet || detailCache.sid !== sid || Date.now() - detailCache.at > (air ? 30000 : 1000)) {
    detailCache = {sid, at: Date.now(), r: await api(`/api/series?source=${sid}&minutes=${air ? 4 * 1440 : 10}`)};
  }
  const r = detailCache.r;
  $('detail').classList.remove('hidden');
  $('dtitle').innerHTML = `${esc(s.service)} <span class="sub mono">${esc(sid)}</span>`;
  $('dstatus').innerHTML = `${pill(s.state || 'Unknown')}<span class="small mut">${esc(s.reason)}</span><span class="small mut">${air ? 'Last 4 days' : 'Last 10 minutes'}; shaded areas are alerts.</span>`;
  const names = isAir(s) ? ['pm25_ugm3', 'pm10_ugm3', 'no2_ugm3']
    : ['cpu_pct', 'mem_pct', 'disk_pct', 'latency_ms', 'packet_loss_pct', 'bw_in_mbps'];
  if (!quiet || $('dcharts').dataset.sid !== sid) {
    $('dcharts').dataset.sid = sid;
    $('dcharts').innerHTML = names.map(n => `<div><h3>${LABELS[n] || n} <span class="sub">${UNITS[n] || ''}</span></h3><canvas id="ch-${n}"></canvas><p class="small mut note" id="cn-${n}"></p></div>`).join('');
  }
  const primary = cssVar('--color-primary', '#4263A3'), cOk = cssVar('--color-success', '#16843D'),
    cWarn = cssVar('--status-fair-dot', '#D97706'), cErr = cssVar('--status-poor-dot', '#DC2626');
  names.forEach(n => {
    const pts = (r.series[n] || []).map(p => [p[0], p[1]]);
    const thr = D.thresholds[n], mode = (D.threshold_modes || {})[n];
    const lim = (((D.learned_limits || {})[n]) || []).find(x => x.source_id === sid);
    let bands = [], note = '';
    if (thr && mode === 'learned' && lim) {
      bands = [{v: lim.limits[0], color: cOk, label: 'Excellent <'}, {v: lim.limits[1], color: cWarn, label: 'Good <'},
               {v: lim.limits[2], color: cErr, label: 'Fair <'}, {v: thr[2], color: cssVar('--status-severe', '#9F1239'), label: 'Safety limit'}];
      note = `Learned (ML) limits for this ${air ? 'monitor' : 'source'}: ${lim.limits.join(' / ')} (its own baseline + 2σ / 4σ / 8σ: what is unusual here). ` +
        `Safety limit ${thr[2]}${air ? ' (CPCB Moderate)' : ''}: at or above it the ${air ? 'air is rated Poor' : 'source is Poor'} whatever its history.`;
    } else if (thr) {
      bands = [{v: thr[0], color: cOk, label: 'Excellent <'}, {v: thr[1], color: cWarn, label: 'Good <'}, {v: thr[2], color: cErr, label: 'Fair <'}];
      note = mode === 'learned' ? 'Learned (ML) limits appear once a baseline exists; manual limits apply until then.' : 'Manual limits.';
    }
    const shade = r.alerts.filter(a => a.signal === n).map(a => [a.first_event_ms, a.resolved_ms]);
    drawChart($('ch-' + n), {series: [{pts, color: primary}], bands, shade, unit: UNITS[n] || ''});
    const cn = $('cn-' + n); if (cn) cn.textContent = note;
  });
  document.querySelectorAll('.src').forEach(el => el.classList.toggle('is-selected', el.dataset.arg === sid));
  if (!quiet) $('detail').scrollIntoView({behavior: 'smooth'});
}

function closeDetail() {
  detailSrc = null;
  $('detail').classList.add('hidden');
  document.querySelectorAll('.src').forEach(el => el.classList.remove('is-selected'));
}

function drawLines(c, series, alerts, thr) {
  const dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight;
  if (!w || !h) return;
  c.width = w * dpr; c.height = h * dpr;
  const g = c.getContext('2d'); g.scale(dpr, dpr); g.clearRect(0, 0, w, h);
  const all = series.flatMap(s => s.pts || []);
  if (!all.length) return;
  const t0 = Math.min(...all.map(p => p[0])), t1 = Math.max(...all.map(p => p[0]));
  const X = t => 6 + (w - 12) * (t - t0) / Math.max(t1 - t0, 1);
  const cOk = cssVar('--color-success', '#16843D'), cWarn = cssVar('--status-fair-dot', '#D97706'), cErr = cssVar('--status-poor-dot', '#DC2626');
  (alerts || []).forEach(a => {
    g.fillStyle = cErr; g.globalAlpha = 0.14;
    const x0 = X(Math.max(a.first_event_ms, t0)), x1 = X(a.resolved_ms ? Math.min(a.resolved_ms, t1) : t1);
    g.fillRect(x0, 0, Math.max(2, x1 - x0), h);
    g.globalAlpha = 1;
  });
  series.forEach(s => {
    const pts = s.pts || []; if (!pts.length) return;
    const vals = pts.map(p => p[1]);
    let hi = s.max || Math.max(...vals) * 1.15 || 1; if (thr) hi = Math.max(hi, thr[2] * 1.05);
    const Y = v => h - 5 - (h - 10) * Math.min(v, hi) / hi;
    if (thr) {
      g.setLineDash([4, 3]);
      [[cOk, 0], [cWarn, 1], [cErr, 2]].forEach(([col, i]) => {
        g.strokeStyle = col; g.globalAlpha = 0.55; g.beginPath(); g.moveTo(0, Y(thr[i])); g.lineTo(w, Y(thr[i])); g.stroke();
      });
      g.setLineDash([]); g.globalAlpha = 1;
    }
    g.strokeStyle = s.color; g.lineWidth = 2; g.lineJoin = 'round'; g.lineCap = 'round'; g.beginPath();
    pts.forEach((p, i) => i ? g.lineTo(X(p[0]), Y(p[1])) : g.moveTo(X(p[0]), Y(p[1]))); g.stroke();
  });
}

async function loadPayloads() {
  const r = await api('/api/payloads?kind=' + $('pkind').value);
  $('payloads').innerHTML = r.payloads.length ? r.payloads.map(p => `<tr class="click ${p.payload_id === selPayload ? 'sel' : ''}" data-call="showPayload" data-arg="${esc(p.payload_id)}"><td>${esc(p.collector_id)}</td><td class="num">${p.seq ?? '–'}</td><td>${fmtT(p.received_ms)}</td><td class="mono">${esc(p.sha256.slice(0, 12))}…</td><td class="num">${p.bytes}</td><td>${p.out_of_order ? '<span class="tag warn">out of order</span>' : ''}</td></tr>`).join('')
    : '<tr><td colspan="6" class="empty">No payloads received yet.</td></tr>';
  window._payloads = Object.fromEntries(r.payloads.map(p => [p.payload_id, p]));
}
function showPayload(id) {
  selPayload = id; const p = window._payloads[id];
  $('pmeta').innerHTML = `<dl class="meta"><dt>Payload</dt><dd class="mono">${esc(id)}</dd><dt>SHA-256</dt><dd class="mono">${esc(p.sha256)}</dd><dt>Created</dt><dd>${fmtDT(p.created_ms)}</dd><dt>Received</dt><dd>${fmtDT(p.received_ms)}</dd></dl>`;
  $('pbody').textContent = JSON.stringify(JSON.parse(p.body), null, 2); loadPayloads();
}
async function searchMeta() {
  const q = $('sterm').value; if (!q) return;
  const r = await api('/api/search-metadata?q=' + encodeURIComponent(q));
  $('sres').innerHTML = `Matches in the SaaS store for this value: <span class="${r.payload_matches ? 'bad' : 'okc'}">${r.payload_matches} payloads</span>, <span class="${r.event_matches ? 'bad' : 'okc'}">${r.event_matches} event contexts</span>.`;
}

function renderSlo() {
  const S = D.slo, f = v => v === undefined ? '–' : (v / 1000).toFixed(2) + ' s';
  const card = (l, st, target, note) => {
    const val = st.p95 ?? st.max; const ok = st.n ? (val <= target) : null;
    const status = ok === null ? '<span class="pill">not measured yet</span>' : ok ? '<span class="pill s-Excellent">target met</span>' : '<span class="pill s-Poor">target missed</span>';
    return `<div class="card stat"><div class="l">${l}</div><div class="v">${st.n ? f(val) : '–'}</div><div>${status}</div>
      <div class="small mut">Target ${target / 1000} s; n ${st.n}, p50 ${f(st.p50)}, max ${f(st.max)}</div><div class="small mut">${note}</div></div>`;
  };
  $('slo').innerHTML = card('Collection to dashboard (p95)', S.dashboard, S.targets.dashboard_p95_ms, 'From event time to browser render (measured from window start)') +
    card('Breach or anomaly to alert (p95)', S.alert, S.targets.alert_ms, 'From the first breaching event to the alert') +
    card('Collector offline detection', S.offline_detect, S.targets.offline_detect_ms, 'From the last heartbeat to status Poor') +
    card('Collection to SaaS ingest (p95)', S.ingest, S.targets.dashboard_p95_ms, 'From event time to stored');
  const dl = D.counters.delivery || {};
  $('reliab').innerHTML = (D.collectors.length ? `<div class="table-wrap"><table><thead><tr><th>Collector</th><th class="num">Created</th><th class="num">Delivered</th><th class="num">Received</th><th class="num">Gaps</th><th class="num">Duplicates</th><th class="num">Out of order</th><th class="num">Buffered</th></tr></thead><tbody>${D.collectors.map(c => `
    <tr><td class="strong">${esc(c.collector_id)}</td><td class="num">${c.stats.seq_created ?? '–'}</td><td class="num">${c.stats.seq_delivered ?? '–'}</td><td class="num">${c.received}<div class="small mut">max seq ${c.max_seq ?? '–'}</div></td><td class="num ${c.missing ? 'bad' : ''}">${c.missing}</td><td class="num">${c.duplicates_ignored}</td><td class="num">${c.out_of_order}</td><td class="num">${c.stats.buffer_depth ?? 0}</td></tr>`).join('')}</tbody></table></div>`
    : empty('No collector has connected yet.')) +
    `<p class="small mut note">Created and delivered are counted by the collector, received by the SaaS (distinct payloads). Gaps come from the per-collector sequence numbers; duplicates are payload IDs already stored. Late metric points merged by event time: ${dl.late_points || 0}.</p>`;
  const n = D.counters.noise || {}, sc = D.counters.security || {};
  $('noise').innerHTML = `<p>${n.alerts_raised || 0} alerts grouped into ${n.incidents || 0} incidents; ${n.duplicates_suppressed || 0} repeat notifications suppressed. Policy rejections at ingest: ${sc.policy_rejections || 0}. DLP rejections: ${sc.dlp_rejections || 0}.</p>`;
}

function renderSettings() {
  const admin = D.user.role === 'admin';
  if (!thrDirty) {
    $('thr').innerHTML = `<div class="thr thr-head"><span>Metric</span><span>Limits</span><span>Excellent below</span><span>Good below</span><span>Fair below</span></div>` +
      Object.entries(D.thresholds).map(([k, v]) => thrRow(k, v, admin)).join('') +
      `<p class="small mut note">Learned (ML), the default: each source gets its own limits from its baseline (median and robust spread, per hour of day once seasonal history exists): Excellent below baseline + 2σ, Good below + 4σ, Fair below + 8σ. The Fair value stays as a safety limit: at or above it the source is Poor and alerts, whatever its baseline. Until a baseline exists (about 20 s), the manual limits apply.</p>` +
      `<p class="small mut">Data older than ${D.health_settings.stale_after_s} s makes a source Fair; no data for ${D.health_settings.no_data_after_s} s makes it Poor. A collector is offline after ${D.health_settings.collector_offline_after_s} s without a heartbeat.</p>`;
  }
  $('savethr').disabled = !admin;
  const deps = Object.entries(D.tenant.dependencies);
  $('deps').innerHTML = deps.length ? deps.map(([k, v]) => `<div class="dep-row"><span class="tag">${esc(k)}</span><span class="small mut">depends on</span>${v.map(x => `<span class="tag">${esc(x)}</span>`).join('')}</div>`).join('')
    : empty('No dependencies declared for this tenant.');
  $('resid').innerHTML = `<p>All metadata for ${esc(D.tenant.name)} is stored in region ${esc(D.tenant.region)} (${esc(D.tenant.region_name)}). Collectors discover this endpoint at startup; a payload sent to another region is refused with 421 Misdirected and never stored.</p>`;
  $('audit').innerHTML = D.audit.length ? `<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead><tbody>${D.audit.map(a => `<tr><td>${fmtDT(a.ts_ms)}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td class="small mut break">${esc(a.detail)}</td></tr>`).join('')}</tbody></table>`
    : empty('No audit entries yet.');
}
function thrRow(k, v, admin) {
  const learned = (D.threshold_modes || {})[k] === 'learned';
  const dis = i => (!admin || (learned && i < 2)) ? 'disabled' : '';
  const name = sid => { const s = D.sources.find(x => x.source_id === sid); return s ? `${s.service} (${s.role})` : sid; };
  const now = ((D.learned_limits || {})[k] || []).slice(0, 4).map(x => `${esc(name(x.source_id))} ${x.limits.join(' / ')}`).join('; ');
  const more = Math.max(0, ((D.learned_limits || {})[k] || []).length - 4);
  const label = `${LABELS[k] || k}`, limitName = ['Excellent', 'Good', 'Fair'];
  return `<div class="thr"><span class="thr-metric">${esc(label)} <span class="small mut">${UNITS[k] || ''}</span></span>` +
    `<select data-mode="${k}" ${admin ? '' : 'disabled'} aria-label="${esc(label)} limits"><option value="manual" ${learned ? '' : 'selected'}>Manual</option><option value="learned" ${learned ? 'selected' : ''}>Learned (ML)</option></select>` +
    v.map((x, i) => `<input type="number" step="any" data-m="${k}" data-i="${i}" value="${x}" ${dis(i)} class="${learned && i === 2 ? 'safety' : ''}" aria-label="${esc(label)}: ${limitName[i]} below" title="${learned && i === 2 ? 'Safety limit: Poor at or above, whatever the baseline' : ''}">`).join('') +
    (learned ? `<div class="thr-learned small mut">${now ? `Learned now: ${now}${more ? `; ${more} more` : ''}.` : 'Learning baselines.'} Safety limit ${v[2]}.</div>` : '') + `</div>`;
}
async function saveThr() {
  const t = {}, modes = {};
  document.querySelectorAll('#thr input').forEach(i => { (t[i.dataset.m] = t[i.dataset.m] || [])[+i.dataset.i] = +i.value; });
  document.querySelectorAll('#thr select[data-mode]').forEach(s => { modes[s.dataset.mode] = s.value; });
  const r = await api('/api/config', {method: 'POST', body: JSON.stringify({thresholds: t, threshold_modes: modes})});
  $('thrmsg').className = 'small ' + (r.__status === 200 ? 'okc' : 'bad');
  $('thrmsg').textContent = r.__status === 200 ? 'Saved (audited)' : r.error; thrDirty = false; load();
}

// One delegated listener instead of inline handlers, so the page runs under a strict CSP
// (script-src 'self'). Only functions listed here can be triggered from markup.
const CALLS = {toggleInc, doAct, loadDetail, closeDetail, showPayload, logout, searchMeta, saveThr, setTheme};
const argOf = v => (v !== undefined && /^\d+$/.test(v)) ? Number(v) : v;
document.addEventListener('click', e => {
  const el = e.target.closest('[data-call]');
  if (!el || el.disabled || !CALLS[el.dataset.call]) return;
  CALLS[el.dataset.call](argOf(el.dataset.arg), argOf(el.dataset.arg2));
});
document.addEventListener('keydown', e => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const el = e.target.closest('[data-call][tabindex]');
  if (!el || el.disabled || !CALLS[el.dataset.call]) return;
  e.preventDefault();
  CALLS[el.dataset.call](argOf(el.dataset.arg), argOf(el.dataset.arg2));
});
$('loginform').addEventListener('submit', doLogin);
$('searchform').addEventListener('submit', e => { e.preventDefault(); searchMeta(); });
$('tzmode').addEventListener('change', () => render());
$('mon-metric').addEventListener('change', () => { trend.at = 0; render(); });
$('pkind').addEventListener('change', () => loadPayloads());
document.addEventListener('input', e => { if (e.target.closest('#thr')) thrDirty = true; });
// switching a metric's mode shows at once which inputs still apply (the save button stores it)
document.addEventListener('change', e => {
  const m = e.target.dataset && e.target.dataset.mode;
  if (!m) return;
  document.querySelectorAll(`#thr input[data-m="${m}"]`).forEach(i => { if (+i.dataset.i < 2) i.disabled = e.target.value === 'learned'; });
});

setInterval(() => { if (!document.hidden && !$('app').classList.contains('hidden')) load(); }, 1000);
fetch('/api/me').then(r => r.ok ? load() : showLogin());
