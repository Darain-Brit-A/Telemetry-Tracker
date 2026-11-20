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
  if (bh) bh.classList.toggle('active', mode === 'humming');
  if (bm) bm.classList.toggle('active', mode === 'medcity');
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
const ago = ms => ms ? `${Math.max(0, Math.round((Date.now() - (typeof ms === 'string' ? Date.parse(ms) : ms)) / 1000))}s ago` : '';

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
  $('hmeta').innerHTML = `<span>${esc(T.reason)}</span><span>Residency <b>${T.region}</b> (${esc(T.region_name)})</span><span>Server ${D.server_time.slice(11, 19)}Z</span>`;
  $('who').textContent = `${D.user.username} · ${D.user.role}`;
  if (tab === 'ops') renderOps();
  if (tab === 'fleet') renderFleet();
  if (tab === 'slo') renderSlo();
  if (tab === 'settings') renderSettings();
}

function renderOps() {
  const cnt = {Excellent: 0, Good: 0, Fair: 0, Poor: 0};
  D.sources.forEach(s => cnt[s.state]++); D.collectors.forEach(c => cnt[c.state]++);
  const openI = D.incidents.filter(i => i.status === 'open').length;
  const openA = D.alerts.filter(a => a.status === 'open').length;
  const n = D.counters.noise || {};
  $('summary').innerHTML = [
    ['Overall', pill(D.tenant.state), esc(D.tenant.reason)],
    ['Open incidents', `<span class="${openI ? 'bad' : 'okc'}">${openI}</span>`, `${openA} open alerts grouped`],
    ['Health', `<span class="okc">${cnt.Excellent}</span> · <span class="goodc">${cnt.Good}</span> · <span class="warnc">${cnt.Fair}</span> · <span class="bad">${cnt.Poor}</span>`, 'Excellent · Good · Fair · Poor'],
    ['Noise reduced', `${n.duplicates_suppressed || 0}`, `repeat notifications folded into ${n.alerts_raised || 0} alerts / ${n.incidents || 0} incidents`],
  ].map(([l, v, s]) => `<div class="stat"><div class="l">${l}</div><div class="v">${v}</div><div class="small mut">${s}</div></div>`).join('');

  $('incidents').innerHTML = D.incidents.length ? D.incidents.map(incidentHtml).join('') : '<p class="mut">No incidents. Inject a scenario from a collector console to see detection, correlation and recommendations.</p>';
  const ents = [...D.collectors.map(c => ({n: c.collector_id, s: c.state || 'Unknown', r: c.reason, k: 'collector'})),
                ...D.sources.map(s => ({n: `${s.service} · ${s.site}`, s: s.state || 'Unknown', r: s.reason, k: s.source_id}))];
  $('healthmap').innerHTML = ents.map(e => `<div class="hcell s-${esc(e.s)}" title="${esc(e.r)}"><div class="hcell-top"><b>${esc(e.n)}</b><span class="hcell-state">${esc(e.s)}</span></div><span class="small mono">${esc(e.k)}</span><span class="small">${esc(e.r).slice(0, 68)}</span></div>`).join('');
  const open = D.alerts.filter(a => a.status === 'open');
  $('alerts').innerHTML = open.length ? `<table>${open.map(a => `<tr><td>${sev(a.severity)}</td><td>${esc(a.title)}<div class="small mut"><span class="mono">${esc(a.source_id || a.collector_id)}</span> · ${a.kind} · ×${a.count} · since ${fmtT(a.first_event_ms)}${a.incident_id ? ' · incident #' + a.incident_id : ''}</div></td></tr>`).join('')}</table>` : '<p class="mut">None</p>';
  $('history').innerHTML = D.history.length ? `<table>${D.history.map(h => `<tr><td class="mono">${new Date(h.ts_ms).toISOString().slice(11, 23)}Z</td><td>${esc(h.entity)}</td><td>${h.prev ? pill(h.prev) + ' → ' : ''}${pill(h.state)}<div class="small mut">${esc(h.reason)}</div></td></tr>`).join('')}</table>` : '<p class="mut">No transitions yet.</p>';
}

function srcTz(sid) { const s = D.sources.find(x => x.source_id === sid); return s && s.tz; }

// ML feature 2: share of total deviation per (source, signal), root and symptoms drawn separately.
function deviationHtml(dev) {
  if (!dev || !(dev.root.length + dev.symptoms.length)) return '';
  const bar = (r, cls) => `<div class="dev-row"><span class="dev-label">${esc(r.service)} · ${esc(r.signal)}</span>
    <span class="dev-track"><span class="dev-bar ${cls}" style="width:${Math.max(1, r.share)}%"></span></span>
    <span class="dev-val">${r.share.toFixed(1)}% <span class="mut small">z ${r.z}</span></span></div>`;
  const ev = dev.events.length ? `<div class="small mut">Event signals (no z-score, not in the shares): ${dev.events.map(e => esc(e.signal)).join(', ')}</div>` : '';
  return `<h3>Share of total deviation <span class="small mut">(composite score ${dev.composite_score})</span></h3>
    <div class="dev">${dev.root.map(r => bar(r, 'root')).join('')}${dev.symptoms.map(r => bar(r, 'sym')).join('')}</div>
    <div class="small mut">Darker bars: root (${esc(dev.root[0] ? dev.root[0].service : 'n/a')}). Lighter bars: symptoms. Size of deviation is not cause; the root is chosen by onset time and dependency position.</div>${ev}`;
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
      const role = (a.ranking && a.ranking[0] && (s.source_id || s.collector_id) === a.ranking[0].source) ? '<b>root</b>' : 'symptom';
      return `<tr><td>${role}</td><td>${esc(s.service)}<div class="small mono mut">${esc(s.source_id || s.collector_id)}</div></td><td>${esc(s.signal)}<div class="small mut">${s.kind}${s.classification ? ' · ' + s.classification : ''}</div></td>
        <td>${esc(val)}</td><td>${esc(base)}</td><td>${d.z ?? '–'}${d.peak_z ? `<div class="small mut">peak ${d.peak_z}</div>` : ''}</td><td>${fmtT(s.onset, s.source_id && srcTz(s.source_id))}</td><td>${s.status}</td></tr>`;
    }).join('');
    const corr = (a.correlation || []).map(c => `<li>alert #${c.alert} joined ${c.joined.slice(11, 19)}Z: ${esc(c.reason)}</li>`).join('');
    const rank = (a.ranking || []).map(x => `<tr><td>${esc(x.service)} <span class="small mono mut">${esc(x.source)}</span></td><td><b>${x.score}</b></td><td class="small">onset ${x.factors.earliest_onset} · upstream ${x.factors.upstream_of_affected} · severity ${x.factors.severity} · signals ${x.factors.signal_count}</td></tr>`).join('');
    body = `<div class="inc-b">
      <h3>Likely cause</h3><p>${esc(r.likely_cause)}</p>
      <h3>Why it was flagged: contributing signals</h3>
      <div class="scroll"><table><thead><tr><th>Role</th><th>Source</th><th>Signal</th><th>Value</th><th>Baseline (median ± spread)</th><th>z</th><th>Onset</th><th>Status</th></tr></thead><tbody>${sigRows}</tbody></table></div>
      ${deviationHtml(r.deviation)}
      <h3>Reasoning path</h3><ol class="reason">${(r.reasoning || []).map(x => `<li>${esc(x)}</li>`).join('')}</ol>
      <h3>Confidence ${conf}%</h3><ul class="small">${(r.confidence_factors || []).map(x => `<li>${esc(x)}</li>`).join('')}</ul>
      ${rank && (a.ranking || []).length > 1 ? `<h3>Root-cause ranking</h3><table>${rank}</table>` : ''}
      <h3>Correlation (noise reduction)</h3><ul class="small">${corr}</ul>
      <p class="small mut">${a.noise ? `${a.noise.alerts} alert(s) from ${a.noise.sources} source(s) merged; ${a.noise.duplicates_suppressed} repeat notifications suppressed.` : ''}</p>
      ${actionHtml(i, r)}
    </div>`;
  }
  return `<div class="inc ${open ? 'is-open' : ''}"><div class="inc-h" data-call="toggleInc" data-arg="${i.id}">${sev(i.severity)}<span class="t">#${i.id} ${esc(i.title)}</span>
    <span class="conf small">${conf}% <span class="bar"><i style="width:${conf}%"></i></span></span>
    <span class="small mut">${i.status === 'open' ? 'open' : 'resolved'} · ${(a.signals || []).length} signals · ${ago(i.updated_ms)}</span></div>${body}</div>`;
}

function actionHtml(i, r) {
  const act = r.action;
  if (!act) return '';
  const rows = i.actions || [];
  const head = `<div class="action"><b>Recommended action: ${esc(act.label)}</b> <span class="tag">risk ${act.risk}</span> <span class="tag">${act.reversible ? 'reversible' : 'not reversible'}</span> <span class="tag">${act.automatable ? 'automatable (simulated)' : 'manual runbook'}</span>
    <p><b>Why this action:</b> ${esc(act.why)}</p><p class="small"><b>Rollback plan:</b> ${esc(act.rollback)}</p>
    ${(r.alternatives || []).length ? `<p class="small"><b>Alternatives considered:</b> ${r.alternatives.map(esc).join('; ')}</p>` : ''}`;
  const acts = rows.map(a => {
    const pol = a.policy_preview;
    const checks = pol ? `<ul class="chk small">${pol.checks.map(c => `<li class="${c.ok ? '' : 'no'}">${esc(c.check)}${c.detail ? ` <span class="mut">(${esc(c.detail)})</span>` : ''}</li>`).join('')}</ul>` : '';
    let btn = '';
    if (a.status === 'proposed') btn = `<button data-call="doAct" data-arg="${a.id}" data-arg2="approve" ${pol && pol.allowed ? '' : 'disabled'}>Approve &amp; run (simulated)</button> <button class="sec" data-call="doAct" data-arg="${a.id}" data-arg2="reject">Reject</button>`;
    if (a.status === 'executed') btn = `<button class="danger" data-call="doAct" data-arg="${a.id}" data-arg2="rollback">Roll back</button>`;
    return `<div class="action-item"><b>Action #${a.id}</b> ${esc(a.action)} → <span class="mono">${esc(a.source_id)}</span> · status <b>${a.status}</b>
      ${a.approved_by ? ` · approved by ${esc(a.approved_by)}` : ''}${a.result ? `<div class="small mut">${esc(a.result)}</div>` : ''}
      ${a.status === 'proposed' ? '<div class="small mut" style="margin-top:6px">Policy check before approval:</div>' + checks : ''}<div class="action-btns">${btn}</div></div>`;
  }).join('');
  return head + acts + '</div>';
}
function toggleInc(id) { openInc.has(id) ? openInc.delete(id) : openInc.add(id); renderOps(); }
async function doAct(id, op) {
  const r = await api(`/api/actions/${id}/${op}`, {method: 'POST', body: '{}'});
  if (r.__status !== 200) alert(r.error + (r.policy ? '\n' + r.policy.checks.filter(c => !c.ok).map(c => '✗ ' + c.check).join('\n') : ''));
  load();
}

function renderFleet() {
  $('collectors').innerHTML = `<table><thead><tr><th>Collector</th><th>State</th><th>Last seen</th><th>Version / Config / Policy</th><th>Resources</th><th>Buffer</th><th>Seq created → received</th></tr></thead><tbody>${D.collectors.map(c => `
    <tr><td><b>${esc(c.collector_id)}</b><div class="small mut">site ${esc(c.site)} · ${esc(c.tz)}</div></td><td>${pill(c.state)}<div class="small mut">${esc(c.reason)}</div></td>
    <td>${c.age_s}s ago<div class="small mut">${fmtT(c.last_seen, c.tz)}</div></td><td>v${esc(c.version)}<div class="small mono mut">${esc(c.config_hash)} · ${esc(c.policy_version)}</div></td>
    <td>CPU ${c.stats.cpu_pct ?? '–'}% · ${c.stats.rss_mb ?? '–'} MB</td><td>${c.stats.buffer_depth ?? 0}</td>
    <td>${c.stats.seq_created ?? '–'} → ${c.received} <span class="small ${c.missing ? 'bad' : 'okc'}">${c.missing ? c.missing + ' missing' : 'no gaps'}</span></td></tr>`).join('')}</tbody></table>`;
  $('sources').innerHTML = D.sources.map(s => {
    const L = s.latest, v = k => L[k] ? L[k].value : '–';
    return `<div class="src ${detailSrc === s.source_id ? 'is-selected' : ''}" tabindex="0" data-call="loadDetail" data-arg="${esc(s.source_id)}"><div class="src-head"><b>${esc(s.service)}</b>${pill(s.state || 'Unknown')}</div>
      <div class="small mono mut">${s.source_id} · ${esc(s.role)} · ${esc(s.site)}</div>
      <div class="kv"><span>CPU ${v('cpu_pct')}%</span><span>Mem ${v('mem_pct')}%</span><span>Disk ${v('disk_pct')}%</span><span>Lat ${v('latency_ms')}ms</span><span>Loss ${v('packet_loss_pct')}%</span><span>In ${v('bw_in_mbps')}Mb</span></div>
      <canvas data-spark="${s.source_id}"></canvas><div class="small mut">${esc(s.reason).slice(0, 110)}</div></div>`;
  }).join('');
  const primary = cssVar('--color-primary', '#4263A3'), secondary = cssVar('--status-fair-dot', '#D97706');
  document.querySelectorAll('canvas[data-spark]').forEach(c => {
    const s = D.sources.find(x => x.source_id === c.dataset.spark);
    drawLines(c, [{pts: s.spark.cpu_pct, color: primary, max: 100}, {pts: s.spark.latency_ms, color: secondary}]);
  });
}

async function loadDetail(sid, quiet) {
  detailSrc = sid;
  const r = await api(`/api/series?source=${sid}&minutes=10`);
  const s = D.sources.find(x => x.source_id === sid) || {};
  $('detail').classList.remove('hidden');
  $('dtitle').innerHTML = `<span>${esc(s.service)} <span class="mono small mut">${sid}</span></span> <span>${pill(s.state || 'Unknown')} <span class="sub">${esc(s.reason)}</span></span>`;
  const names = ['cpu_pct', 'mem_pct', 'disk_pct', 'latency_ms', 'packet_loss_pct', 'bw_in_mbps'];
  if (!quiet || !$('dcharts').children.length) $('dcharts').innerHTML = names.map(n => `<div><div class="small"><b>${n}</b> <span class="mut">(event time; shaded = alert)</span></div><canvas id="ch-${n}"></canvas></div>`).join('');
  const primary = cssVar('--color-primary', '#4263A3');
  names.forEach(n => {
    const pts = (r.series[n] || []).map(p => [p[0], p[1]]);
    const thr = D.thresholds[n];
    drawLines($('ch-' + n), [{pts, color: primary}], r.alerts.filter(a => a.signal === n), thr);
  });
  document.querySelectorAll('.src').forEach(el => el.classList.toggle('is-selected', el.dataset.arg === sid));
  if (!quiet) $('detail').scrollIntoView({behavior: 'smooth'});
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
  $('payloads').innerHTML = r.payloads.map(p => `<tr class="click ${p.payload_id === selPayload ? 'sel' : ''}" data-call="showPayload" data-arg="${esc(p.payload_id)}"><td>${esc(p.collector_id)}</td><td>${p.seq ?? '–'}</td><td class="mono">${new Date(p.received_ms).toISOString().slice(11, 23)}</td><td class="mono">${p.sha256.slice(0, 12)}…</td><td>${p.bytes}</td><td>${p.out_of_order ? '<span class="tag">arrived out of order</span>' : ''}</td></tr>`).join('');
  window._payloads = Object.fromEntries(r.payloads.map(p => [p.payload_id, p]));
}
function showPayload(id) {
  selPayload = id; const p = window._payloads[id];
  $('pmeta').innerHTML = `<b>${esc(id)}</b><br>sha256 <span class="mono">${p.sha256}</span><br>created ${new Date(p.created_ms).toISOString()} · received ${new Date(p.received_ms).toISOString()}`;
  $('pbody').textContent = JSON.stringify(JSON.parse(p.body), null, 2); loadPayloads();
}
async function searchMeta() {
  const q = $('sterm').value; if (!q) return;
  const r = await api('/api/search-metadata?q=' + encodeURIComponent(q));
  $('sres').innerHTML = ` payloads: <b class="${r.payload_matches ? 'bad' : 'okc'}">${r.payload_matches}</b> · event contexts: <b class="${r.event_matches ? 'bad' : 'okc'}">${r.event_matches}</b>`;
}

function renderSlo() {
  const S = D.slo, f = v => v === undefined ? '–' : (v / 1000).toFixed(2) + ' s';
  const card = (l, st, target, note) => {
    const val = st.p95 ?? st.max; const ok = st.n ? (val <= target) : null;
    return `<div class="stat"><div class="l">${l}</div><div class="v ${ok === null ? '' : ok ? 'okc' : 'bad'}">${st.n ? f(val) : '–'}</div><div class="small mut">target ≤ ${target / 1000}s · n=${st.n} · p50 ${f(st.p50)} · max ${f(st.max)}<br>${note}</div></div>`;
  };
  $('slo').innerHTML = card('Collection → dashboard (p95)', S.dashboard, S.targets.dashboard_p95_ms, 'event timestamp → browser render (conservative: from window start)') +
    card('Threshold breach / anomaly → alert (p95)', S.alert, S.targets.alert_ms, 'first breaching event time → alert created') +
    card('Collector offline detection', S.offline_detect, S.targets.offline_detect_ms, 'last heartbeat → status Poor') +
    card('Collection → SaaS ingest (p95)', S.ingest, S.targets.dashboard_p95_ms, 'event timestamp → stored');
  const dl = D.counters.delivery || {};
  $('reliab').innerHTML = `<table><thead><tr><th>Collector</th><th>Created (collector)</th><th>Delivered (collector ack)</th><th>Received distinct (SaaS)</th><th>Sequence gaps</th><th>Duplicates ignored</th><th>Arrived out of order</th><th>Buffered now</th></tr></thead><tbody>${D.collectors.map(c => `
    <tr><td><b>${esc(c.collector_id)}</b></td><td>${c.stats.seq_created ?? '–'}</td><td>${c.stats.seq_delivered ?? '–'}</td><td>${c.received} (max seq ${c.max_seq ?? '–'})</td><td class="${c.missing ? 'bad' : 'okc'}">${c.missing}</td><td>${c.duplicates_ignored}</td><td>${c.out_of_order}</td><td>${c.stats.buffer_depth ?? 0}</td></tr>`).join('')}</tbody></table>
    <p class="small mut" style="margin-top:10px">Late metric points merged by event time: ${dl.late_points || 0}. Gaps are computed from the contiguous per-collector sequence numbers; duplicates are payload IDs already stored.</p>`;
  const n = D.counters.noise || {}, sc = D.counters.security || {};
  $('noise').innerHTML = `<p style="margin:0">${n.alerts_raised || 0} alerts → ${n.incidents || 0} incidents; ${n.duplicates_suppressed || 0} repeat notifications suppressed. Policy rejections at ingest: ${sc.policy_rejections || 0}; DLP rejections: ${sc.dlp_rejections || 0}.</p>`;
}

function renderSettings() {
  const admin = D.user.role === 'admin';
  if (!thrDirty) {
    $('thr').innerHTML = `<div class="thr small mut"><span>Metric</span><span>Excellent &lt;</span><span>Good &lt;</span><span>Fair &lt;</span></div>` +
      Object.entries(D.thresholds).map(([k, v]) => `<div class="thr"><span>${k}</span>${v.map((x, i) => `<input data-m="${k}" data-i="${i}" value="${x}" ${admin ? '' : 'disabled'}>`).join('')}</div>`).join('') +
      `<div class="small mut" style="margin-top:8px">Stale after ${D.health_settings.stale_after_s}s → Fair; no data after ${D.health_settings.no_data_after_s}s → Poor; collector offline after ${D.health_settings.collector_offline_after_s}s.</div>`;
  }
  $('savethr').disabled = !admin;
  $('deps').innerHTML = Object.entries(D.tenant.dependencies).map(([k, v]) => `<div class="dep-row"><span class="tag">${esc(k)}</span> depends on ${v.map(x => `<span class="tag">${esc(x)}</span>`).join(' ')}</div>`).join('');
  $('resid').innerHTML = `<p style="margin:0">All metadata for <b>${esc(D.tenant.name)}</b> is stored in region <b>${D.tenant.region}</b> (${esc(D.tenant.region_name)}). Collectors discover this endpoint at startup; a payload sent to another region is refused with 421 Misdirected and never stored.</p>`;
  $('audit').innerHTML = `<table>${D.audit.map(a => `<tr><td class="mono">${new Date(a.ts_ms).toISOString().slice(0, 19)}Z</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td class="small mut">${esc(a.detail)}</td></tr>`).join('')}</table>`;
}
async function saveThr() {
  const t = {};
  document.querySelectorAll('#thr input').forEach(i => { (t[i.dataset.m] = t[i.dataset.m] || [])[+i.dataset.i] = +i.value; });
  const r = await api('/api/config', {method: 'POST', body: JSON.stringify({thresholds: t})});
  $('thrmsg').className = 'small ' + (r.__status === 200 ? 'okc' : 'bad');
  $('thrmsg').textContent = r.__status === 200 ? 'Saved (audited)' : r.error; thrDirty = false; load();
}

// One delegated listener instead of inline handlers, so the page runs under a strict CSP
// (script-src 'self'). Only functions listed here can be triggered from markup.
const CALLS = {toggleInc, doAct, loadDetail, showPayload, logout, searchMeta, saveThr, setTheme};
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
$('tzmode').addEventListener('change', () => render());
$('pkind').addEventListener('change', () => loadPayloads());
document.addEventListener('input', e => { if (e.target.closest('#thr')) thrDirty = true; });

setInterval(() => { if (!document.hidden && !$('app').classList.contains('hidden')) load(); }, 1000);
fetch('/api/me').then(r => r.ok ? load() : showLogin());
