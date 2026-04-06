'use strict';
const S = {
  view:'dashboard', mode:'user', manualRepos:[], discovered:[],
  currentJobId:null, allResults:[], patterns:[], pollTimer:null,
  activeFilter:'all', activeSort:'risk', jobs:{},
};

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', ()=>{
  initBg();
  checkRate();
  loadStats();
  loadPatterns();
  setInterval(tickJobs, 2500);
  setInterval(loadStats, 30000);
});

// ── Nav ───────────────────────────────────────────────────────────────────────
function go(name, el){
  S.view = name;
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.ntab').forEach(t=>t.classList.remove('active'));
  document.getElementById(`view-${name}`).classList.add('active');
  el.classList.add('active');
  if(name==='queue')   renderJobs();
  if(name==='results') renderResults();
  if(name==='patterns') renderPatterns();
  if(name==='alerts')  loadAlertLog();
  if(name==='dashboard') loadStats();
}

function switchMode(m, el){
  S.mode = m;
  document.querySelectorAll('.itab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.imode').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById(`mode-${m}`).classList.add('active');
}

// ── Rate limit ────────────────────────────────────────────────────────────────
async function checkRate(){
  const tok = document.getElementById('ghToken').value.trim();
  try{
    const d = await apiFetch(`/api/ratelimit?token=${encodeURIComponent(tok)}`);
    const rem=d.remaining??'?', lim=d.limit??'?';
    document.getElementById('rateVal').textContent=`${rem}/${lim}`;
    document.getElementById('rateMeter').style.color = rem<20?'#ff3b3b':rem<100?'#ffd700':'#00d4ff';
  } catch{ document.getElementById('rateVal').textContent='—'; }
}

function toggleEye(id,btn){
  const inp=document.getElementById(id);
  const show=inp.type==='password';
  inp.type=show?'text':'password';
  btn.innerHTML=`<i class="fas fa-${show?'eye-slash':'eye'}"></i>`;
}

// ── Dashboard stats ───────────────────────────────────────────────────────────
async function loadStats(){
  try{
    const s = await apiFetch('/api/stats');
    numAnim('gs-jobs', s.total_jobs||0);
    numAnim('gs-repos', s.total_repos||0);
    numAnim('gs-findings', s.total_findings||0);
    numAnim('gs-alerts', s.alerts_sent||0);

    const maxC = Math.max(...(s.top_secret_types||[]).map(t=>t.count),1);
    document.getElementById('topTypes').innerHTML = (s.top_secret_types||[]).map(t=>`
      <div class="type-row">
        <span style="flex:1;font-size:12px;color:var(--tx2);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(t.type)}</span>
        <div class="type-bar-wrap"><div class="type-bar" style="width:${Math.round(t.count/maxC*100)}%"></div></div>
        <span class="type-cnt">${t.count}</span>
      </div>`).join('') || '<div class="hint p-2">No data yet.</div>';

    const jobs = await apiFetch('/api/jobs');
    document.getElementById('recentJobs').innerHTML = (jobs||[]).slice(0,5).map(j=>`
      <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--bd);font-size:12px">
        <div>
          <span style="font-family:var(--mono);color:var(--acc)">#${esc(j.id)}</span>
          <span style="color:var(--tx3);margin-left:8px">${j.total||0} repos</span>
        </div>
        <div class="d-flex gap-2 align-items-center">
          <span class="jstag ${j.status}">${j.status}</span>
          ${j.status==='complete'?`<button class="btn-xs" onclick="loadJob('${esc(j.id)}')">View</button>`:''}
        </div>
      </div>`).join('') || '<div class="hint">No jobs yet.</div>';
  } catch(e){ console.error('stats error',e); }
}

// ── Discover ──────────────────────────────────────────────────────────────────
async function discoverRepos(){
  const handle = document.getElementById('handleInput').value.trim();
  const maxR   = parseInt(document.getElementById('maxRepos').value)||30;
  const token  = document.getElementById('ghToken').value.trim();
  if(!handle){ toast('⚠️ Enter a GitHub username or org'); return; }
  const btn = document.querySelector('.btn-discover');
  btn.innerHTML='<i class="fas fa-spinner fa-spin me-2"></i>Discovering…';
  btn.disabled=true;
  try{
    const d = await apiFetch('/api/discover',{method:'POST',body:{handle,token,max_repos:maxR}});
    if(d.error){ toast('❌ '+d.error); return; }
    S.discovered = d.repos||[];
    renderDiscovery(d);
    updateQCount();
  } catch(e){ toast('❌ '+e.message);
  } finally{ btn.innerHTML='<i class="fas fa-radar me-2"></i>Discover Repositories'; btn.disabled=false; }
}

function renderDiscovery(data){
  document.getElementById('discoverPane').style.display='block';
  document.getElementById('discoveredUser').innerHTML=`
    <img src="${esc(data.avatar)}" alt="" onerror="this.style.display='none'"/>
    <div>
      <div class="disc-user-name">${esc(data.name||data.handle)}</div>
      <div class="disc-user-bio">${esc(data.type)} · ${data.public_repos||0} public repos</div>
    </div>`;
  document.getElementById('discCountLabel').textContent=`${data.repos.length} repos found`;
  document.getElementById('discGrid').innerHTML = data.repos.map(r=>`
    <label class="disc-chip sel" for="dc_${esc(r.full_name.replace('/','__'))}">
      <input type="checkbox" id="dc_${esc(r.full_name.replace('/','__'))}" value="${esc(r.full_name)}" checked onchange="updateQCount()"/>
      <span class="dc-name">${esc(r.repo)}</span>
      <span class="dc-lang">${esc(r.owner)}</span>
    </label>`).join('');
  updateQCount();
}

function selectDisc(v){
  document.querySelectorAll('#discGrid input').forEach(cb=>cb.checked=v);
  updateQCount();
}

// ── Manual list ───────────────────────────────────────────────────────────────
function addRepo(){
  const inp=document.getElementById('singleRepo');
  const p=parseRepo(inp.value.trim());
  if(!p){ toast('⚠️ Invalid format. Use owner/repo or URL.'); return; }
  if(S.manualRepos.includes(p)){ toast('Already queued.'); return; }
  S.manualRepos.push(p); inp.value='';
  renderTags(); updateQCount();
}
function removeRepo(name){ S.manualRepos=S.manualRepos.filter(r=>r!==name); renderTags(); updateQCount(); }
function renderTags(){
  document.getElementById('repoTags').innerHTML = S.manualRepos.map(n=>`
    <span class="repo-tag"><i class="fas fa-github"></i>${esc(n)}<button onclick="removeRepo('${esc(n)}')"><i class="fas fa-xmark"></i></button></span>`).join('');
}

// ── Bulk paste ────────────────────────────────────────────────────────────────
function parsePaste(){
  const lines=document.getElementById('pasteBox').value.split('\n');
  let added=0,bad=0;
  for(const line of lines){
    const t=line.trim(); if(!t) continue;
    const p=parseRepo(t);
    if(p&&!S.manualRepos.includes(p)){ S.manualRepos.push(p); added++; }
    else if(!p) bad++;
  }
  toast(`✅ ${added} repos added${bad?` · ${bad} invalid skipped`:''}`);
  renderTags(); updateQCount();
  document.querySelectorAll('.itab')[1].click();
}

// ── Queue counter ─────────────────────────────────────────────────────────────
function updateQCount(){
  const n=collectTargets().length;
  document.getElementById('qCount').textContent=`${n} repo${n!==1?'s':''} queued`;
}
function collectTargets(){
  const s=new Set();
  document.querySelectorAll('#discGrid input:checked').forEach(cb=>s.add(cb.value));
  S.manualRepos.forEach(r=>s.add(r));
  return [...s];
}

// ── Launch ────────────────────────────────────────────────────────────────────
async function launchScan(){
  const targets=collectTargets();
  if(!targets.length){ toast('⚠️ No repos queued'); return; }
  const token   =document.getElementById('ghToken').value.trim();
  const history =document.getElementById('optHistory').checked;
  const btn=document.getElementById('btnLaunch');
  btn.disabled=true; document.getElementById('launchLbl').innerHTML='<i class="fas fa-spinner fa-spin me-2"></i>Launching…';
  try{
    const d=await apiFetch('/api/scan',{method:'POST',body:{targets,token,scan_history:history}});
    if(d.error){ toast('❌ '+d.error); return; }
    S.currentJobId=d.job_id;
    if(d.invalid?.length) toast(`⚠️ ${d.invalid.length} invalid targets skipped`);
    toast(`🚀 Job ${d.job_id} launched — ${d.queued} repos`);
    setBadge('qBadge',d.queued);
    addJobToSelector(d.job_id);
    document.querySelector('[data-view="queue"]').click();
    startPoll(d.job_id);
  } catch(e){ toast('❌ '+e.message);
  } finally{ btn.disabled=false; document.getElementById('launchLbl').textContent='Launch Mass Scan'; }
}

// ── Job polling ───────────────────────────────────────────────────────────────
function startPoll(jobId){
  if(S.pollTimer) clearInterval(S.pollTimer);
  S.pollTimer=setInterval(async()=>{
    const j=await apiFetch(`/api/job/${jobId}`).catch(()=>null);
    if(!j) return;
    S.jobs[jobId]=j;
    if(S.view==='queue') renderJobs();
    if(['complete','cancelled','error'].includes(j.status)){
      clearInterval(S.pollTimer);
      toast(`${j.status==='complete'?'✅':'⚠️'} Job ${jobId} ${j.status}`);
      if(j.status==='complete') await loadJob(jobId);
    }
  },2200);
}

async function tickJobs(){
  const jobs=await apiFetch('/api/jobs').catch(()=>null);
  if(!jobs) return;
  jobs.forEach(j=>{ S.jobs[j.id]=j; });
  if(S.view==='queue') renderJobs();
  const running=jobs.filter(j=>j.status==='running').length;
  if(running>0) setBadge('qBadge',running); else hideBadge('qBadge');
}

function renderJobs(){
  const jobs=Object.values(S.jobs).sort((a,b)=>b.created_at.localeCompare(a.created_at));
  const noJ=document.getElementById('noJobs');
  const jl=document.getElementById('jobList');
  if(!jobs.length){ noJ.style.display='block'; jl.innerHTML=''; return; }
  noJ.style.display='none';
  jl.innerHTML=jobs.map(j=>{
    const repos=j.repos||{};
    const names=Object.keys(repos);
    const total=j.total||names.length;
    const done=(j.completed||0)+(j.errored||0);
    const pct=total?Math.round(done/total*100):0;
    const rows=names.slice(0,24).map(n=>{
      const r=repos[n]||{}; const cls=r.status||'queued';
      const ic={scanning:'<i class="fas fa-circle-notch fa-spin"></i>',complete:'✓',error:'✗',queued:'○',cancelled:'—'}[cls]||'○';
      return `<div class="jr"><span class="jr-name">${esc(n)}</span><span class="jr-st ${cls}">${ic} ${cls}${r.findings?' ('+r.findings+')':''}</span></div>`;
    }).join('');
    const overflow=names.length>24?`<div style="text-align:center;padding:6px 18px;font-size:11px;color:var(--tx3)">+${names.length-24} more</div>`:'';
    return `<div class="job-card">
      <div class="jc-head">
        <div><span class="jc-id">JOB #${esc(j.id)}</span><span class="jc-meta ms-2">${j.created_at?.split('T')[0]||''} · ${total} repos</span></div>
        <div class="jc-actions">
          <span style="font-size:11px;color:var(--tx3);font-family:var(--mono)">${done}/${total}</span>
          <span class="jstag ${j.status}">${j.status}</span>
          ${j.status==='running'?`<button class="btn-xs" onclick="cancelJob('${esc(j.id)}')"><i class="fas fa-stop me-1"></i>Cancel</button>`:''}
          ${j.status==='complete'?`<button class="btn-xs" onclick="loadJob('${esc(j.id)}'); document.querySelector('[data-view=results]').click()"><i class="fas fa-chart-bar me-1"></i>Results</button>`:''}
        </div>
      </div>
      <div class="jc-prog"><div class="jc-bar"><div class="jc-fill" style="width:${pct}%"></div></div></div>
      <div class="jc-repos">${rows}</div>${overflow}
    </div>`;
  }).join('');
}

async function cancelJob(jobId){
  await apiFetch(`/api/job/${jobId}/cancel`,{method:'POST'});
  toast(`⛔ Cancelling job ${jobId}`);
}

// ── Results ───────────────────────────────────────────────────────────────────
async function loadJob(jobId){
  S.currentJobId=jobId;
  const results=await apiFetch(`/api/job/${jobId}/results`).catch(()=>[]);
  S.allResults=results;
  setBadge('rBadge',results.length);
  syncJobSelectors(jobId);
  renderResults();
}

function syncJobSelectors(jobId){
  ['jobSelector','alertJobSel'].forEach(id=>{
    const sel=document.getElementById(id);
    if(sel && !Array.from(sel.options).some(o=>o.value===jobId)){
      const opt=new Option(`Job #${jobId}`, jobId);
      sel.add(opt);
    }
    if(sel) sel.value=jobId;
  });
}

function addJobToSelector(jobId){
  ['jobSelector','alertJobSel'].forEach(id=>{
    const sel=document.getElementById(id);
    if(sel&&!Array.from(sel.options).some(o=>o.value===jobId)){
      sel.add(new Option(`Job #${jobId}`,jobId));
    }
  });
}

async function switchJob(jobId){
  if(!jobId) return;
  await loadJob(jobId);
  if(S.view!=='results') document.querySelector('[data-view="results"]').click();
}

function renderResults(){
  const res=S.allResults;
  const grid=document.getElementById('resultsGrid');
  const noR=document.getElementById('noResults');
  const tb=document.getElementById('resultsTb');
  const agg=document.getElementById('aggBar');
  if(!res.length){ grid.innerHTML=''; noR.style.display='block'; tb.style.display='none'; agg.style.display='none'; return; }
  noR.style.display='none'; tb.style.display='flex'; agg.style.display='flex';

  // Aggregates
  let tf=0,tc=0,th=0,tm=0,tnew=0,tfixed=0;
  res.forEach(r=>{
    const sc=r.summary?.severity_counts||{};
    tf+=r.summary?.total_findings||0; tc+=sc.critical||0; th+=sc.high||0; tm+=sc.medium||0;
    const d=r.diff||{}; tnew+=(d.new||[]).length; tfixed+=(d.fixed||[]).length;
  });
  numAnim('aggR',res.length); numAnim('aggF',tf); numAnim('aggC',tc);
  numAnim('aggH',th); numAnim('aggM',tm); numAnim('aggNew',tnew); numAnim('aggFixed',tfixed);

  const search=(document.getElementById('searchBox')?.value||'').toLowerCase();
  const sort=document.getElementById('sortSel')?.value||'risk';
  let filtered=[...res];

  if(S.activeFilter==='critical') filtered=filtered.filter(r=>(r.summary?.severity_counts?.critical||0)>0);
  else if(S.activeFilter==='high')   filtered=filtered.filter(r=>(r.summary?.severity_counts?.high||0)>0);
  else if(S.activeFilter==='medium') filtered=filtered.filter(r=>(r.summary?.severity_counts?.medium||0)>0);
  else if(S.activeFilter==='clean')  filtered=filtered.filter(r=>(r.summary?.total_findings||0)===0);
  else if(S.activeFilter==='new')    filtered=filtered.filter(r=>(r.diff?.new||[]).length>0);
  else if(S.activeFilter==='history') filtered=filtered.filter(r=>(r.findings||[]).some(f=>f.from_history));

  if(search) filtered=filtered.filter(r=>
    r.full_name?.toLowerCase().includes(search)||
    (r.findings||[]).some(f=>(f.type||'').toLowerCase().includes(search)||(f.file_path||f.file||'').toLowerCase().includes(search))
  );

  if(sort==='risk')     filtered.sort((a,b)=>(b.summary?.risk_score||0)-(a.summary?.risk_score||0));
  else if(sort==='findings') filtered.sort((a,b)=>(b.summary?.total_findings||0)-(a.summary?.total_findings||0));
  else if(sort==='name') filtered.sort((a,b)=>(a.full_name||'').localeCompare(b.full_name||''));
  else if(sort==='new')  filtered.sort((a,b)=>((b.diff?.new||[]).length||0)-((a.diff?.new||[]).length||0));

  grid.innerHTML=filtered.map(r=>buildCard(r)).join('');
}

function buildCard(r){
  const info=r.repo_info||{}; const summ=r.summary||{};
  const sc=summ.severity_counts||{}; const risk=summ.risk_score||0;
  const findings=r.findings||[]; const diff=r.diff||{};
  const riskCls=risk>=70?'critical':risk>=35?'high':risk>=10?'medium':'clean';

  const badges=[
    sc.critical?`<span class="rc-sev critical">🔴 ${sc.critical}</span>`:'',
    sc.high?`<span class="rc-sev high">🟠 ${sc.high}</span>`:'',
    sc.medium?`<span class="rc-sev medium">🟡 ${sc.medium}</span>`:'',
  ].filter(Boolean).join('');

  const diffHtml=Object.keys(diff).length?`
    <div class="rc-diff">
      <span style="color:#00e676">▲ ${(diff.new||[]).length} new</span>
      <span style="color:#ff8c00">▼ ${(diff.fixed||[]).length} fixed</span>
      <span>= ${(diff.persisted||[]).length} unchanged</span>
    </div>`:'';

  const preview=findings.slice(0,3);
  const fhtml=preview.length===0
    ?`<div class="rc-clean"><i class="fas fa-shield-check me-2"></i>No secrets detected</div>`
    :preview.map(f=>`
      <div class="rf">
        <div class="rf-sev ${f.severity}">${f.severity}</div>
        <div class="rf-body">
          <div class="rf-type">${esc(f.type)}${f.from_history?'<span style="font-size:9px;color:#ff8c00;margin-left:5px">[history]</span>':''}</div>
          <div class="rf-file"><i class="fas fa-file-code me-1"></i>${esc(f.file_path||f.file||'')}:${f.line_number||f.line||''}</div>
          <div class="rf-masked"><i class="fas fa-eye-slash me-1"></i>${esc(f.masked_value||f.masked||'')}</div>
          <div class="rf-meta">
            <span>entropy: ${f.entropy??'?'}</span>
            ${f.confidence&&f.confidence!=='high'?`<span style="color:${f.confidence==='low'?'#ff8c00':'#ffd700'}">confidence: ${f.confidence}</span>`:''}
            ${f.is_test_file?`<span style="color:#ffd700">test file</span>`:''}
            <button class="suppress-btn" onclick="suppressFinding('${esc(f.fingerprint)}',event)">suppress</button>
          </div>
          <div class="rf-rem"><i class="fas fa-wrench me-1" style="color:var(--acc)"></i>${esc(f.remediation||f.remediation||'')}</div>
        </div>
      </div>`).join('')+
    (findings.length>3?`<div class="rc-more" onclick="openModal('${esc(r.full_name||'')}')">+ ${findings.length-3} more findings — click to view all</div>`:'');

  return `<div class="rc risk-${riskCls}">
    <div class="rch" onclick="openModal('${esc(r.full_name||'')}')">
      <img class="rc-av" src="${esc(info.owner_avatar||'')}" alt="" onerror="this.style.display='none'"/>
      <div style="flex:1;min-width:0">
        <div class="rc-name">${esc(r.full_name||'')}</div>
        <div class="rc-meta">
          ${esc(info.language||'?')} · ⭐${info.stars||0} · 🍴${info.forks||0} · ${info.private?'🔒':'🌐'} · ${summ.files_scanned||0} files
          ${summ.history_scanned?'· 📜 history':''} ${info.truncated_tree?'· ⚠️ tree truncated':''}
        </div>
      </div>
      <div class="rc-badges">${badges}<span class="rc-risk">Risk ${risk}/100</span></div>
    </div>
    ${diffHtml}
    <div class="rc-body">${fhtml}</div>
  </div>`;
}

function filterRes(f,btn){
  S.activeFilter=f;
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active'); renderResults();
}

// ── Suppress finding ──────────────────────────────────────────────────────────
async function suppressFinding(fp, e){
  e.stopPropagation();
  if(!fp) return;
  const reason=prompt('Reason for suppressing (optional):','false positive');
  if(reason===null) return;
  await apiFetch('/api/suppress',{method:'POST',body:{fingerprint:fp,reason}});
  toast('✅ Finding suppressed');
  await loadJob(S.currentJobId);
}

// ── Repo detail modal ─────────────────────────────────────────────────────────
function openModal(fullName){
  const r=S.allResults.find(x=>x.full_name===fullName);
  if(!r) return;
  document.getElementById('repoModalTitle').textContent=fullName;
  const findings=r.findings||[];
  const body=document.getElementById('repoModalBody');
  if(!findings.length){
    body.innerHTML='<div style="padding:40px;text-align:center;color:#00e676"><i class="fas fa-shield-check" style="font-size:32px;display:block;margin-bottom:12px"></i>No secrets detected.</div>';
  } else {
    body.innerHTML=findings.map(f=>`
      <div style="border-bottom:1px solid var(--bd);padding:14px 18px">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
          <span class="sev-tag ${f.severity}">${f.severity}</span>
          <strong style="font-size:13px">${esc(f.type)}${f.from_history?'<span style="font-size:9px;color:#ff8c00;margin-left:5px">[history]</span>':''}</strong>
          <span style="font-family:var(--mono);font-size:11px;color:var(--acc);margin-left:auto">${esc(f.file_path||f.file||'')}:${f.line_number||f.line||''}</span>
        </div>
        <div style="font-size:12px;color:var(--tx2);margin-bottom:5px">${esc(f.description||'')}</div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--crit);margin-bottom:5px"><i class="fas fa-eye-slash me-1"></i>${esc(f.masked_value||f.masked||'')}</div>
        <div style="font-size:10px;color:var(--tx3);margin-bottom:6px;display:flex;gap:10px;flex-wrap:wrap">
          <span>entropy: ${f.entropy??'?'}</span>
          <span>confidence: ${f.confidence||'?'}</span>
          ${f.is_test_file?'<span style="color:#ffd700">test file</span>':''}
          <button class="suppress-btn" onclick="suppressFinding('${esc(f.fingerprint)}',event)">suppress</button>
        </div>
        ${f.context_snippet||f.context?`<pre style="background:rgba(2,4,8,.7);border:1px solid var(--bd);border-left:3px solid var(--bd3);border-radius:5px;padding:9px;font-size:10px;color:var(--tx2);overflow-x:auto;margin-bottom:6px;white-space:pre">${esc(f.context_snippet||f.context||'')}</pre>`:''}
        <div style="font-size:12px;color:var(--tx2);margin-bottom:4px"><i class="fas fa-wrench me-1" style="color:var(--acc)"></i>${esc(f.remediation||'')}</div>
        ${f.docs_url||f.docs?`<a href="${esc(f.docs_url||f.docs)}" target="_blank" style="font-size:11px;color:var(--acc)"><i class="fas fa-external-link me-1"></i>Docs</a>`:''}
      </div>`).join('');
  }
  new bootstrap.Modal(document.getElementById('repoModal')).show();
}

// ── Alerts ────────────────────────────────────────────────────────────────────
async function doEmailAlert(){
  const jobId=document.getElementById('alertJobSel').value;
  const email=document.getElementById('alertEmail').value.trim();
  if(!email){ toast('⚠️ Enter recipient email'); return; }
  if(!jobId){ toast('⚠️ Select a job'); return; }
  const statusEl=document.getElementById('emailStatus');
  statusEl.style.display='block'; statusEl.className='alert-status';
  statusEl.innerHTML='<i class="fas fa-spinner fa-spin me-2"></i>Sending…';
  try{
    const d=await apiFetch('/api/alert/email',{method:'POST',body:{
      job_id:jobId, email,
      smtp:{host:document.getElementById('smtpHost').value.trim(),
            port:document.getElementById('smtpPort').value||587,
            user:document.getElementById('smtpUser').value.trim(),
            password:document.getElementById('smtpPass').value,tls:true}
    }});
    if(d.error){ statusEl.className='alert-status err'; statusEl.innerHTML=`<i class="fas fa-circle-xmark me-2"></i>${esc(d.error)}`; }
    else if(d.preview_html){
      statusEl.className='alert-status ok'; statusEl.innerHTML='<i class="fas fa-eye me-2"></i>Preview generated (no SMTP configured)';
      document.getElementById('previewFrame').srcdoc=d.preview_html;
      new bootstrap.Modal(document.getElementById('previewModal')).show();
    } else {
      statusEl.className='alert-status ok'; statusEl.innerHTML=`<i class="fas fa-circle-check me-2"></i>${esc(d.message)}`;
      toast('📧 Alert sent!');
    }
  } catch(e){ statusEl.className='alert-status err'; statusEl.innerHTML='Network error: '+esc(e.message); }
  loadAlertLog();
}

async function previewEmail(){
  const jobId=document.getElementById('alertJobSel').value||S.currentJobId;
  if(!jobId){ toast('⚠️ Select a job'); return; }
  try{
    const d=await apiFetch('/api/alert/email',{method:'POST',body:{job_id:jobId,email:'preview@example.com',smtp:{}}});
    if(d.preview_html){ document.getElementById('previewFrame').srcdoc=d.preview_html; new bootstrap.Modal(document.getElementById('previewModal')).show(); }
    else if(d.error) toast('❌ '+d.error);
  } catch(e){ toast('❌ '+e.message); }
}

async function doWebhook(){
  const url=document.getElementById('webhookUrl').value.trim();
  const jobId=document.getElementById('alertJobSel').value||S.currentJobId;
  if(!url){ toast('⚠️ Enter webhook URL'); return; }
  if(!jobId){ toast('⚠️ Select a job'); return; }
  const st=document.getElementById('webhookStatus');
  st.style.display='block'; st.className='alert-status';
  st.innerHTML='<i class="fas fa-spinner fa-spin me-2"></i>Sending…';
  try{
    const d=await apiFetch('/api/alert/webhook',{method:'POST',body:{job_id:jobId,webhook_url:url}});
    st.className='alert-status '+(d.success?'ok':'err');
    st.innerHTML=`<i class="fas fa-${d.success?'circle-check':'circle-xmark'} me-2"></i>${esc(d.message)}`;
  } catch(e){ st.className='alert-status err'; st.innerHTML='Error: '+esc(e.message); }
  loadAlertLog();
}

async function doGithubIssues(){
  const token=document.getElementById('issueToken').value.trim();
  const jobId=document.getElementById('alertJobSel').value||S.currentJobId;
  if(!token){ toast('⚠️ GitHub token required'); return; }
  if(!jobId){ toast('⚠️ Select a job'); return; }
  const st=document.getElementById('issueStatus');
  st.style.display='block'; st.className='alert-status';
  st.innerHTML='<i class="fas fa-spinner fa-spin me-2"></i>Creating issues…';
  try{
    const d=await apiFetch('/api/alert/github-issues',{method:'POST',body:{job_id:jobId,token}});
    const ok=d.created?.length||0; const fail=d.failed?.length||0;
    st.className='alert-status '+(ok>0?'ok':'err');
    st.innerHTML=`<i class="fas fa-${ok>0?'circle-check':'circle-xmark'} me-2"></i>${ok} issues created${fail?`, ${fail} failed`:''}`;
    if(ok>0) toast(`✅ ${ok} GitHub issues created`);
  } catch(e){ st.className='alert-status err'; st.innerHTML='Error: '+esc(e.message); }
  loadAlertLog();
}

async function loadAlertLog(){
  const rows=await apiFetch('/api/alert/log').catch(()=>[]);
  const el=document.getElementById('alertLog');
  if(!rows?.length){ el.innerHTML='<div class="hint p-3">No alerts sent yet.</div>'; return; }
  el.innerHTML=rows.map(r=>`
    <div class="al-row">
      <span class="al-ch">${esc(r.channel)}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--tx3)">${r.sent_at?.replace('T',' ').slice(0,19)||''}</span>
      <span style="flex:1;font-size:12px;color:var(--tx2)">${esc(r.recipient)}</span>
      <span style="font-size:11px;font-family:var(--mono);color:var(--tx3)">${r.repo_count||0} repos · ${r.finding_count||0} findings</span>
      <span class="${r.status==='sent'?'al-ok':'al-err'}" style="font-size:11px;font-family:var(--mono)">${r.status}</span>
    </div>`).join('');
}

// ── Export ────────────────────────────────────────────────────────────────────
function exportCsv(){ if(S.currentJobId) window.open(`/api/export/${S.currentJobId}/csv`,'_blank'); else toast('⚠️ No job selected'); }
function exportJson(){ if(S.currentJobId) window.open(`/api/export/${S.currentJobId}/json`,'_blank'); else toast('⚠️ No job selected'); }
function exportReport(){ if(S.currentJobId) window.open(`/api/export/${S.currentJobId}/report`,'_blank'); else toast('⚠️ No job selected'); }

// ── Patterns ──────────────────────────────────────────────────────────────────
async function loadPatterns(){
  S.patterns=await apiFetch('/api/patterns').catch(()=>[]);
  renderPatterns();
}
function renderPatterns(){
  const search=(document.getElementById('patSearch')?.value||'').toLowerCase();
  const cat=document.getElementById('patCat')?.value;
  const sev=document.getElementById('patSev')?.value;
  const catSel=document.getElementById('patCat');
  if(catSel&&catSel.options.length===1){
    [...new Set(S.patterns.map(p=>p.category))].sort().forEach(c=>catSel.add(new Option(c,c)));
  }
  let p=[...S.patterns];
  if(search) p=p.filter(x=>x.name.toLowerCase().includes(search)||x.description.toLowerCase().includes(search));
  if(cat) p=p.filter(x=>x.category===cat);
  if(sev) p=p.filter(x=>x.severity===sev);
  const el=document.getElementById('patGrid');
  if(!el) return;
  el.innerHTML=p.map(x=>`
    <div class="pat-card">
      <div class="pat-top">
        <span class="sev-tag ${x.severity}">${x.severity}</span>
        <span class="pat-name">${esc(x.name)}</span>
        <span class="pat-cat">${esc(x.category)}</span>
      </div>
      ${x.min_entropy?`<div class="pat-ent">Min entropy: ${x.min_entropy}</div>`:''}
      <div class="pat-desc">${esc(x.description)}</div>
      <div class="pat-rem"><i class="fas fa-wrench me-1" style="color:var(--acc)"></i>${esc(x.remediation)}</div>
    </div>`).join('');
  const cnt=document.getElementById('patCount');
  if(cnt) cnt.textContent=`${p.length} / ${S.patterns.length} patterns`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
async function apiFetch(url, opts={}){
  const r=await fetch(url,{
    method:opts.method||'GET',
    headers:{'Content-Type':'application/json'},
    body:opts.body?JSON.stringify(opts.body):undefined
  });
  if(r.status===401){ window.location='/login'; throw new Error('Not authenticated'); }
  if(!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
function esc(s){
  if(s==null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
function toast(msg){
  document.getElementById('toastMsg').textContent=msg;
  new bootstrap.Toast(document.getElementById('toastEl'),{delay:3800}).show();
}
function numAnim(id,target){
  const el=document.getElementById(id); if(!el) return;
  const dur=500,t0=performance.now();
  const tick=n=>{ const p=Math.min((n-t0)/dur,1); el.textContent=Math.round(target*(1-Math.pow(1-p,3))); if(p<1) requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
}
function parseRepo(raw){
  const ps=[/github\.com\/([A-Za-z0-9_.\-]+)\/([A-Za-z0-9_.\-]+)/,/^([A-Za-z0-9_.\-]+)\/([A-Za-z0-9_.\-]+)$/];
  for(const p of ps){ const m=raw.match(p); if(m) return `${m[1]}/${m[2].replace(/\.git$/,'')}`; }
  return null;
}
function setBadge(id,n){ const el=document.getElementById(id); if(el){el.style.display='inline';el.textContent=n;} }
function hideBadge(id){ const el=document.getElementById(id); if(el) el.style.display='none'; }

// ── Background particles ──────────────────────────────────────────────────────
function initBg(){
  const cv=document.getElementById('bgCanvas'); if(!cv) return;
  const cx=cv.getContext('2d');
  let W,H,pts;
  function resize(){ W=cv.width=innerWidth; H=cv.height=innerHeight; }
  resize(); addEventListener('resize',resize);
  pts=Array.from({length:55},()=>({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.28,vy:(Math.random()-.5)*.28,a:Math.random()}));
  function draw(){
    cx.clearRect(0,0,W,H);
    for(const p of pts){
      p.x=(p.x+p.vx+W)%W; p.y=(p.y+p.vy+H)%H;
      cx.beginPath(); cx.arc(p.x,p.y,p.a*1.4+.3,0,Math.PI*2);
      cx.fillStyle=`rgba(0,212,255,${p.a*.45})`; cx.fill();
    }
    for(let i=0;i<pts.length;i++) for(let j=i+1;j<pts.length;j++){
      const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);
      if(d<110){ cx.beginPath(); cx.moveTo(pts[i].x,pts[i].y); cx.lineTo(pts[j].x,pts[j].y);
        cx.strokeStyle=`rgba(0,212,255,${.055*(1-d/110)})`; cx.lineWidth=.5; cx.stroke(); }
    }
    requestAnimationFrame(draw);
  }
  draw();
}
