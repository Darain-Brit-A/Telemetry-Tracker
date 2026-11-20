let S=null, selected=null;
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const t=ms=>ms?new Date(ms).toISOString().slice(11,23):'';
function hiSecrets(raw){
  let h=esc(raw);
  const rx=[/(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)(\s*[=:]\s*)([^\s,;&"\\]+)/gi,/\b(AKIA[0-9A-Z]{16})\b/g,/\b(eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{4,})/g,/(Bearer\s+)([\w.~+\/=-]{8,})/g,/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g];
  h=h.replace(rx[0],(m,a,b,c)=>`${a}${b}<span class="sec">${c}</span>`).replace(rx[1],'<span class="sec">$1</span>').replace(rx[2],'<span class="sec">$1</span>').replace(rx[3],'$1<span class="sec">$2</span>').replace(rx[4],'<span class="sec">$1</span>');
  return h;
}
function hiRed(s){return esc(s).replace(/\[REDACTED:[a-z_]+\]/g,m=>`<span class="red">${m}</span>`)}
async function load(){
  try{S=await (await fetch('/api/state')).json();}catch(e){return}
  $('cid').textContent=S.collector_id;
  $('kv').innerHTML=`<span>site <b>${esc(S.site)}</b></span><span>source tz <b>${esc(S.tz)}</b></span><span>version <b>${S.version}</b></span><span>region <b>${esc(S.region||'discovering…')}</b></span><span>TLS <b>${S.tls?'on (pinned CA)':'OFF'}</b></span><span>policy <b>${esc(S.policy.policy_version)}</b></span>`;
  const ok=S.link==='connected';
  $('link').innerHTML=`<span>status <b class="${ok?'link-ok':'link-bad'}">${esc(S.link)}</b></span><span>buffer depth <b>${S.stats.buffer_depth}</b></span><span>seq created/delivered <b>${S.stats.seq_created} / ${S.stats.seq_delivered}</b></span><span>send errors <b>${S.stats.send_errors}</b></span><span>redactions <b>${S.stats.redactions_total}</b></span><span>DLP-blocked <b>${S.stats.blocked_payloads}</b></span><span>raw events <b>${S.stats.raw_events_total}</b></span>${S.last_error?`<span>last error <b class="link-bad">${esc(S.last_error)}</b></span>`:''}`;
  $('bpart').className=S.partition?'on':''; $('bpart').textContent=S.partition?'Restore SaaS link':'Simulate SaaS outage';
  $('bchaos').className=S.chaos?'on':''; $('bchaos').textContent=S.chaos?'Chaos ON (click to stop)':'Chaos: duplicate + out-of-order delivery';
  const hs=$('host'); if(!hs.options.length){S.pseudonyms.forEach(p=>hs.add(new Option(`${p.host} (${p.service})`,p.host)))}
  if(document.activeElement!==$('ret')) $('ret').value=S.retention_min;
  $('raw').innerHTML=S.raw.filter(r=>r.type!=='metric'||r.findings).slice(0,40).map(r=>`<tr${r.findings?' class="raw-hit"':''}><td class="mono">${t(r.ts_ms)}</td><td>${esc(r.host)}</td><td class="mono">${hiSecrets(r.raw)}</td><td class="mono">${hiRed(r.redacted)}</td></tr>`).join('')||'<tr><td colspan=4 class="note">waiting for events…</td></tr>';
  const eg=S.egress.filter(e=>$('showhb').checked||e.kind!=='heartbeat');
  $('eg').innerHTML=eg.map(e=>`<tr class="click ${e.payload_id===selected?'sel':''}" data-call="pick" data-arg="${esc(e.payload_id)}"><td>${e.seq??'–'}</td><td>${e.kind}</td><td class="mono">${t(e.created_ms)}</td><td>${e.bytes}</td><td class="mono">${e.sha256.slice(0,12)}…</td><td><span class="st ${e.status}">${e.status}</span></td><td>${e.attempts}</td></tr>`).join('');
  $('find').innerHTML=S.findings.map(f=>`<tr><td class="mono">${f.ts.slice(11,19)}</td><td>${esc(f.host)}</td><td><b>${esc(f.kind)}</b><br>${esc(f.detail)}${f.raw_redacted?`<br><span class="mono red">${esc(f.raw_redacted)}</span>`:''}</td></tr>`).join('')||'<tr><td class="note">none yet</td></tr>';
  $('pseudo').innerHTML=S.pseudonyms.map(p=>`<tr><td>${esc(p.host)}</td><td class="mono">${p.source_id}</td><td>${esc(p.role)}</td><td>${esc(p.service)}</td></tr>`).join('');
  $('audit').innerHTML=S.audit.map(a=>`<tr><td class="mono">${new Date(a.ts_ms).toISOString().slice(0,19)}Z</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td></tr>`).join('');
}
async function pick(id){
  selected=id; const r=await (await fetch('/api/egress/'+id)).json();
  let pretty=r.body; try{pretty=JSON.stringify(JSON.parse(r.body),null,2)}catch(e){}
  const dropped=JSON.parse(r.dropped||'[]'), dlp=JSON.parse(r.dlp||'[]');
  $('egmeta').innerHTML=`<b>payload ${id}</b><br>sha256 <span class="mono">${r.sha256}</span><br>status <span class="st ${r.status}">${r.status}</span> · allow-list removed: ${dropped.length?esc(dropped.join(', ')):'nothing'} · DLP: ${dlp.length?'<b class="link-bad">'+esc(dlp.join(','))+'</b>':'clean'}${r.note?'<br>'+esc(r.note):''}`;
  $('egbody').textContent=pretty; load();
}
async function post(p,b){return (await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})).json()}
async function toggle(k){await post('/api/'+k,{on:!S[k]}); load()}
async function scn(name,site){site=!!site;const r=await post('/api/scenario',{name,host:site?null:$('host').value}); $('scnmsg').textContent=r.error?r.error:`Injected '${name}' at ${r.injected_at} (UTC)${r.host?' on '+r.host:''}`;}
async function setRet(){await post('/api/retention',{minutes:+$('ret').value}); load()}
async function search(){const q=$('term').value; if(!q)return; const r=await (await fetch('/api/raw-search?q='+encodeURIComponent(q))).json();
  $('searchres').innerHTML=` local raw store: <b>${r.raw_matches_local}</b> match(es) · outbound payloads: <b class="${r.egress_matches?'link-bad':'link-ok'}">${r.egress_matches}</b>`}
const CALLS={toggle,scn,search,setRet,pick};
document.addEventListener('click',e=>{const el=e.target.closest('[data-call]');if(!el||el.disabled||!CALLS[el.dataset.call])return;CALLS[el.dataset.call](el.dataset.arg,el.dataset.arg2);});
$('showhb').addEventListener('change',()=>load());
setInterval(load,1000); load();
