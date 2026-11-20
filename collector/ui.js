let S=null, selected=null;
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const t=ms=>ms?new Date(ms).toISOString().slice(11,19):'';
const dt=ms=>ms?new Date(ms).toISOString().slice(0,19).replace('T',' ')+'Z':'';
// payload status -> the dashboard's status chip colours
const ST={delivered:'s-Excellent',pending:'s-Fair',dropped:'s-Poor',rejected:'s-Poor',blocked:'s-Poor'};
const status=s=>`<span class="pill ${ST[s]||''}">${esc(s)}</span>`;
const emptyRow=(cols,text)=>`<tr><td colspan="${cols}" class="empty">${text}</td></tr>`;
const fact=(label,value,cls)=>`<span>${label} <span class="v ${cls||''}">${value}</span></span>`;
function hiSecrets(raw){
  let h=esc(raw);
  const rx=[/(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)(\s*[=:]\s*)([^\s,;&"\\]+)/gi,/\b(AKIA[0-9A-Z]{16})\b/g,/\b(eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{4,})/g,/(Bearer\s+)([\w.~+\/=-]{8,})/g,/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g];
  h=h.replace(rx[0],(m,a,b,c)=>`${a}${b}<span class="secret">${c}</span>`).replace(rx[1],'<span class="secret">$1</span>').replace(rx[2],'<span class="secret">$1</span>').replace(rx[3],'$1<span class="secret">$2</span>').replace(rx[4],'<span class="secret">$1</span>');
  return h;
}
function hiRed(s){return esc(s).replace(/\[REDACTED:[a-z_]+\]/g,m=>`<span class="redacted">${m}</span>`)}
async function load(){
  try{S=await (await fetch('/api/state')).json();}catch(e){return}
  $('cid').textContent=S.collector_id;
  $('kv').innerHTML=`<span>Site ${esc(S.site)}</span><span>Source time zone ${esc(S.tz)}</span><span>Version ${esc(S.version)}</span><span>Region ${esc(S.region||'discovering')}</span><span>TLS ${S.tls?'on (pinned CA)':'off'}</span><span>Policy ${esc(S.policy.policy_version)}</span>`;
  const ok=S.link==='connected';
  $('link').innerHTML=fact('Status',esc(S.link),ok?'okc':'bad')+fact('Buffer depth',S.stats.buffer_depth)+fact('Created / delivered',`${S.stats.seq_created} / ${S.stats.seq_delivered}`)
    +fact('Send errors',S.stats.send_errors)+fact('Redactions',S.stats.redactions_total)+fact('DLP-blocked',S.stats.blocked_payloads)+fact('Raw events',S.stats.raw_events_total)
    +(S.last_error?fact('Last error',esc(S.last_error),'bad'):'');
  $('bpart').className=S.partition?'danger':'ghost'; $('bpart').textContent=S.partition?'Restore SaaS link':'Simulate SaaS outage';
  $('bchaos').className=S.chaos?'danger':'ghost'; $('bchaos').textContent=S.chaos?'Stop chaos delivery':'Chaos delivery';
  const hs=$('host'); if(!hs.options.length){S.pseudonyms.forEach(p=>hs.add(new Option(`${p.host} (${p.service})`,p.host)))}
  if(document.activeElement!==$('ret')) $('ret').value=S.retention_min;
  $('raw').innerHTML=S.raw.filter(r=>r.type!=='metric'||r.findings).slice(0,40).map(r=>`<tr${r.findings?' class="raw-hit"':''}><td>${t(r.ts_ms)}</td><td>${esc(r.host)}</td><td class="mono">${hiSecrets(r.raw)}</td><td class="mono">${hiRed(r.redacted)}</td></tr>`).join('')||emptyRow(4,'Waiting for events.');
  const eg=S.egress.filter(e=>$('showhb').checked||e.kind!=='heartbeat');
  $('eg').innerHTML=eg.map(e=>`<tr class="click ${e.payload_id===selected?'sel':''}" data-call="pick" data-arg="${esc(e.payload_id)}"><td class="num">${e.seq??'–'}</td><td>${esc(e.kind)}</td><td>${t(e.created_ms)}</td><td class="num">${e.bytes}</td><td class="mono">${esc(e.sha256.slice(0,12))}…</td><td>${status(e.status)}</td><td class="num">${e.attempts}</td></tr>`).join('')||emptyRow(7,'No payloads yet.');
  $('find').innerHTML=S.findings.map(f=>`<tr><td>${esc(f.ts.slice(11,19))}</td><td>${esc(f.host)}</td><td><span class="strong">${esc(f.kind)}</span><div class="small mut">${esc(f.detail)}</div>${f.raw_redacted?`<div class="mono redacted">${esc(f.raw_redacted)}</div>`:''}</td></tr>`).join('')||emptyRow(3,'No findings yet.');
  $('pseudo').innerHTML=S.pseudonyms.map(p=>`<tr><td>${esc(p.host)}</td><td class="mono">${esc(p.source_id)}</td><td>${esc(p.role)}</td><td>${esc(p.service)}</td></tr>`).join('')||emptyRow(4,'No hosts seen yet.');
  $('audit').innerHTML=S.audit.map(a=>`<tr><td>${dt(a.ts_ms)}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td class="small mut break">${esc(a.detail)}</td></tr>`).join('')||emptyRow(4,'No audit entries yet.');
}
async function pick(id){
  selected=id; const r=await (await fetch('/api/egress/'+id)).json();
  let pretty=r.body; try{pretty=JSON.stringify(JSON.parse(r.body),null,2)}catch(e){}
  const dropped=JSON.parse(r.dropped||'[]'), dlp=JSON.parse(r.dlp||'[]');
  $('egmeta').innerHTML=`<dl class="meta"><dt>Payload</dt><dd class="mono">${esc(id)}</dd><dt>SHA-256</dt><dd class="mono">${esc(r.sha256)}</dd><dt>Status</dt><dd>${status(r.status)}</dd>`
    +`<dt>Allow-list removed</dt><dd>${dropped.length?esc(dropped.join(', ')):'nothing'}</dd><dt>DLP</dt><dd>${dlp.length?`<span class="bad">${esc(dlp.join(', '))}</span>`:'clean'}</dd>${r.note?`<dt>Note</dt><dd>${esc(r.note)}</dd>`:''}</dl>`;
  $('egbody').textContent=pretty; load();
}
async function post(p,b){return (await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})).json()}
async function toggle(k){await post('/api/'+k,{on:!S[k]}); load()}
async function scn(name,site){site=!!site;const r=await post('/api/scenario',{name,host:site?null:$('host').value}); $('scnmsg').textContent=r.error?r.error:`Injected ${name} at ${r.injected_at} (UTC)${r.host?' on '+r.host:''}.`;}
async function setRet(){await post('/api/retention',{minutes:+$('ret').value}); load()}
async function search(){const q=$('term').value; if(!q)return; const r=await (await fetch('/api/raw-search?q='+encodeURIComponent(q))).json();
  $('searchres').innerHTML=`Local raw store: ${r.raw_matches_local} matches. Outbound payloads: <span class="${r.egress_matches?'bad':'okc'}">${r.egress_matches} matches</span>.`}
const CALLS={toggle,scn,search,setRet,pick};
document.addEventListener('click',e=>{const el=e.target.closest('[data-call]');if(!el||el.disabled||!CALLS[el.dataset.call])return;CALLS[el.dataset.call](el.dataset.arg,el.dataset.arg2);});
$('searchform').addEventListener('submit',e=>{e.preventDefault();search();});
$('showhb').addEventListener('change',()=>load());
setInterval(load,1000); load();
