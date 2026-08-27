/* =====================================================================
   Reconix — Security Control System (Frontend v2.0)
   NEXUS Dashboard Style
===================================================================== */

const state = {
  history: [],
  lastResult: null,
  rawResult: null,
  currentPage: 'dashboard',
  scanTimer: null,
  uptimeStart: Date.now(),
  currentFilter: 'all',
};

const SEV_COLORS = {
  CRITICAL: '#ff2a6d', HIGH: '#ff7b00', MEDIUM: '#ffd700', LOW: '#00f5a0', INFO: '#6b7a9c'
};
const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
const RISK_COLORS = {
  LOW: '#00f5a0', MEDIUM: '#ffd700', HIGH: '#ff7b00', CRITICAL: '#ff2a6d'
};
const RISK_LABELS = {
  LOW: 'MINIMAL', MEDIUM: 'ELEVATED', HIGH: 'SEVERE', CRITICAL: 'CRITICAL'
};

/* ==================== DOM REFS ==================== */
const $ = id => document.getElementById(id);
const els = {
  urlInput: $('urlInput'), scanBtn: $('scanBtn'), scanBtnText: $('scanBtnText'),
  apiBase: $('apiBase'), advToggle: $('advToggle'), advPanel: $('advPanel'),
  errorBanner: $('errorBanner'), errorText: $('errorText'),
  connDot: $('connDot'), connLabel: $('connLabel'),
  // Dashboard
  dashScoreNum: $('dashScoreNum'), dashScoreStatus: $('dashScoreStatus'),
  gaugeValue: $('gaugeValue'), gaugeValueInner: $('gaugeValueInner'),
  mstatCritical: $('mstatCritical'), mstatHigh: $('mstatHigh'), mstatMedium: $('mstatMedium'), mstatLow: $('mstatLow'),
  targetName: $('targetName'), targetStatus: $('targetStatus'),
  cstatAssets: $('cstatAssets'), cstatFindings: $('cstatFindings'), cstatDuration: $('cstatDuration'),
  cstatRisk: $('cstatRisk'), cstatRiskDelta: $('cstatRiskDelta'),
  shieldProgress: $('shieldProgress'), shieldLevel: $('shieldLevel'), shieldSub: $('shieldSub'),
  threatList: $('threatList'), moduleList: $('moduleList'),
  activityChart: $('activityChart'),
  // Scan
  scanProgressList: $('scanProgressList'), scanProgressBar: $('scanProgressBar'), scanProgressStatus: $('scanProgressStatus'),
  // Findings
  findingsTableBody: $('findingsTableBody'), findingsCount: $('findingsCount'),
  // History
  historyComparison: $('historyComparison'), prevScore: $('prevScore'), currScore: $('currScore'),
  prevTarget: $('prevTarget'), currTarget: $('currTarget'), compChange: $('compChange'), historyList: $('historyList'),
  // Modal
  findingModal: $('findingModal'), modalClose: $('modalClose'),
  modalTitle: $('modalTitle'), modalSev: $('modalSev'), modalCategory: $('modalCategory'),
  modalStatus: $('modalStatus'), modalDesc: $('modalDesc'), modalImpact: $('modalImpact'),
  modalEvidence: $('modalEvidence'), modalRec: $('modalRec'), modalRefs: $('modalRefs'),
  // Discovered identities + OSINT lookup
  identitiesPanel: $('identitiesPanel'), identitiesList: $('identitiesList'),
  osintModal: $('osintModal'), osintModalClose: $('osintModalClose'),
  osintModalKind: $('osintModalKind'), osintModalTitle: $('osintModalTitle'),
  osintModalLoading: $('osintModalLoading'), osintModalBody: $('osintModalBody'),
  // Standalone manual OSINT page (independent of scan flow)
  osintKindTabs: $('osintKindTabs'), osintValueInput: $('osintValueInput'),
  osintInputPrefix: $('osintInputPrefix'), osintCountryWrap: $('osintCountryWrap'),
  osintCountryInput: $('osintCountryInput'), osintRunBtn: $('osintRunBtn'),
  osintRunBtnText: $('osintRunBtnText'), osintErrorBanner: $('osintErrorBanner'),
  osintErrorText: $('osintErrorText'), osintPageResults: $('osintPageResults'),
  // Bottom bar
  sysTime: $('sysTime'), sysDate: $('sysDate'), sysUptime: $('sysUptime'),
  sysLoad: $('sysLoad'),
  scanQueue: $('scanQueue'),
  sysLatency: $('sysLatency'), packetLoss: $('packetLoss'),
  // World map stats
  wmsNodes: $('wmsNodes'), wmsConnections: $('wmsConnections'), wmsTime: $('wmsTime'), wmsThreats: $('wmsThreats'),
};

/* ==================== HEALTH CHECK ==================== */
async function checkHealth(){
  els.connDot.className = 'conn-dot checking';
  els.connLabel.textContent = 'CHECKING';
  try{
    const base = els.apiBase.value.replace(/\/$/,'');
    const res = await fetch(base + '/api/v1/master/health', { method:'GET' });
    if(!res.ok) throw new Error('bad');
    els.connDot.className = 'conn-dot online';
    els.connLabel.textContent = 'ONLINE';
  }catch(e){
    els.connDot.className = 'conn-dot offline';
    els.connLabel.textContent = 'OFFLINE';
  }
}
checkHealth();
let healthDebounce;
els.apiBase.addEventListener('input', ()=>{ clearTimeout(healthDebounce); healthDebounce = setTimeout(checkHealth, 600); });

/* ==================== NAVIGATION ==================== */
function showPage(name){
  state.currentPage = name;
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active', p.id === 'page-'+name));
  document.querySelectorAll('.top-link').forEach(l=>l.classList.toggle('active', l.dataset.page === name));
  document.querySelectorAll('.side-btn').forEach(l=>l.classList.toggle('active', l.dataset.page === name));
  if(name === 'robots') renderRobotsPage();
}
document.querySelectorAll('[data-page]').forEach(el=>{
  el.addEventListener('click', (e)=>{ e.preventDefault(); showPage(el.dataset.page); });
});

/* ==================== UI HELPERS ==================== */
els.advToggle.addEventListener('click', ()=>{
  els.advPanel.classList.toggle('open');
  els.advToggle.querySelector('svg').style.transform = els.advPanel.classList.contains('open') ? 'rotate(90deg)' : 'none';
});
document.querySelectorAll('.scan-chip').forEach(chip=>{
  chip.addEventListener('click', ()=>{ els.urlInput.value = chip.dataset.url; showPage('scan'); });
});
els.urlInput.addEventListener('keydown', (e)=>{ if(e.key === 'Enter') runScan(); });
els.scanBtn.addEventListener('click', runScan);

/* ==================== BOTTOM BAR CLOCK ====================
   Only the wall clock and the page-open uptime are genuinely "live" values —
   everything else here used to be Math.random() filler. The rest of the
   bottom bar (Modules OK / HTTP Status / Response Time / Redirects) now only
   updates from real scan data inside renderResult() / resetStatsBar(). */
function updateClock(){
  const now = new Date();
  els.sysTime.textContent = now.toLocaleTimeString('en-US', {hour12:false});
  els.sysDate.textContent = now.toISOString().slice(0,10).replace(/-/g,'.');
  const diff = Math.floor((now - state.uptimeStart)/1000);
  const d = Math.floor(diff/86400), h = Math.floor((diff%86400)/3600), m = Math.floor((diff%3600)/60);
  els.sysUptime.textContent = `${d}d ${String(h).padStart(2,'0')}h ${String(m).padStart(2,'0')}m`;
}
setInterval(updateClock, 1000); updateClock();

// Shows "—" placeholders until a real scan has run.
function resetStatsBar(){
  els.sysLoad.textContent = '—';
  els.scanQueue.textContent = '—';
  els.sysLatency.textContent = '—';
  els.packetLoss.textContent = '—';
}
resetStatsBar();

// Populates the bottom bar from the real scan payload only.
function updateStatsBar(data, raw){
  const httpScan = raw?.combined_scanner?.http_scan;

  if(data?.modules){
    const values = Object.values(data.modules);
    const ok = values.filter(m => m.status === 'completed').length;
    els.sysLoad.textContent = `${ok}/${values.length}`;
  }
  if(httpScan){
    els.scanQueue.textContent = httpScan.status_code != null ? String(httpScan.status_code) : '—';
    els.sysLatency.textContent = httpScan.response_time_seconds != null
      ? Math.round(httpScan.response_time_seconds * 1000) + 'ms' : '—';
    els.packetLoss.textContent = httpScan.redirect_count != null ? String(httpScan.redirect_count) : '—';
  } else {
    els.scanQueue.textContent = '—';
    els.sysLatency.textContent = '—';
    els.packetLoss.textContent = '—';
  }
}

/* ==================== CHART ====================
   Bar chart of the 5 real scan modules (recon, web_security, attack_surface,
   threat_detection, risk_engine) — green bar if that module actually
   completed on the last scan, dim/red if it failed. No random data. */
const MODULE_CHART_LABELS = [
  {key:'recon', label:'RECON'},
  {key:'web_security', label:'HTTP SEC'},
  {key:'attack_surface', label:'ATTACK SURF'},
  {key:'threat_detection', label:'THREAT DET'},
  {key:'risk_engine', label:'RISK ENGINE'},
];

function drawChart(){
  const c = els.activityChart;
  if(!c) return;
  const ctx = c.getContext('2d');
  const w = c.width, h = c.height;
  ctx.clearRect(0,0,w,h);

  const modules = state.lastResult?.modules;

  if(!modules){
    ctx.fillStyle = 'rgba(216,168,160,0.55)';
    ctx.font = '11px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('NO SCAN DATA YET — RUN A SCAN', w/2, h/2);
    return;
  }

  const padTop = 10, padBottom = 26, padSide = 14;
  const chartH = h - padTop - padBottom;
  const barW = (w - padSide*2) / MODULE_CHART_LABELS.length;

  // Baseline
  ctx.strokeStyle = 'rgba(255,60,0,0.15)'; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(padSide, h-padBottom); ctx.lineTo(w-padSide, h-padBottom); ctx.stroke();

  MODULE_CHART_LABELS.forEach((m, i) => {
    const ok = modules[m.key]?.status === 'completed';
    const barH = ok ? chartH : chartH * 0.12; // failed modules show as a short stub, not a lie
    const x = padSide + i*barW + barW*0.2;
    const bw = barW*0.6;
    const y = h - padBottom - barH;

    const grad = ctx.createLinearGradient(0, y, 0, h-padBottom);
    if(ok){ grad.addColorStop(0, '#ff6600'); grad.addColorStop(1, 'rgba(255,69,0,0.25)'); }
    else { grad.addColorStop(0, '#5a2a20'); grad.addColorStop(1, 'rgba(90,42,32,0.25)'); }
    ctx.fillStyle = grad;
    ctx.fillRect(x, y, bw, barH);

    ctx.fillStyle = ok ? '#ff8533' : '#a85a4a';
    ctx.font = 'bold 9px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText(ok ? 'OK' : 'FAIL', x + bw/2, y - 4 < padTop ? padTop+8 : y - 4);

    ctx.fillStyle = 'rgba(216,168,160,0.75)';
    ctx.font = '8px "JetBrains Mono", monospace';
    ctx.fillText(m.label, x + bw/2, h - 10);
  });
}

/* ==================== RESULT NORMALIZATION ====================
   master_link.py's /api/v1/master/scan returns:
     { target, scan_timestamp, execution_time_ms,
       unified_assessment: { unified_score_percent, rating, components },
       security_behavior_engine: { success, report: { overall, anomalies, correlated_risks, ... } },
       combined_scanner: { success, overall_score_percent, confirmed_security_findings, ... },
       robots_txt_analysis: { success, robots_found, interesting_paths, summary, ... } }
   The dashboard widgets (gauge, mini-stats, findings table, modal, threat
   list, history) all read a flat shape instead (security_score, risk_level,
   severity_counts, findings[], modules{}, attack_surface.assets_count).
   This adapter bridges the two so real scan results actually render. */
function normalizeScanResult(raw){
  const unified = raw.unified_assessment || {};
  const behavior = raw.security_behavior_engine || {};
  const scanner = raw.combined_scanner || {};
  const robots = raw.robots_txt_analysis || {};

  const score = unified.unified_score_percent ?? 0;

  let risk = (behavior.success && behavior.report?.overall?.risk_level) || null;
  if(!risk){
    risk = score >= 90 ? 'LOW' : score >= 50 ? 'MEDIUM' : score >= 25 ? 'HIGH' : 'CRITICAL';
  }
  if(risk === 'LOW/MEDIUM') risk = 'MEDIUM'; // collapse the engine's hybrid label onto the 4 dashboard buckets

  const findings = [];
  let fid = 1;

  if(behavior.success && behavior.report){
    (behavior.report.anomalies || []).forEach(a=>{
      findings.push({
        id: `AN-${String(fid++).padStart(3,'0')}`,
        title: a.title, category: a.category || 'Behavioral Anomaly',
        severity: (a.severity || 'INFO').toUpperCase(), status: 'OPEN',
        module: 'Security Behavior Engine', description: a.description,
        evidence: a.evidence, recommendation: null, impact: null,
      });
    });
    (behavior.report.correlated_risks || []).forEach(r=>{
      findings.push({
        id: `CR-${String(fid++).padStart(3,'0')}`,
        title: r.title, category: 'Correlated Risk',
        severity: (r.severity || 'INFO').toUpperCase(), status: 'OPEN',
        module: 'Security Behavior Engine', description: r.combined_mechanism,
        evidence: r.evidence, recommendation: r.recommendation, impact: r.impact,
      });
    });
  }

  if(scanner.success){
    (scanner.confirmed_security_findings || []).forEach(f=>{
      findings.push({
        id: `HTTP-${String(fid++).padStart(3,'0')}`,
        title: f.check, category: f.finding_type || 'HTTP Security',
        severity: (f.severity || 'INFO').toUpperCase(), status: 'OPEN',
        module: 'HTTP Security Analysis', description: `${f.check}: ${f.status}`,
        evidence: f.details, recommendation: f.recommendation, impact: null,
      });
    });
  }

  if(robots.success && robots.robots_found){
    (robots.interesting_paths || []).forEach(p=>{
      findings.push({
        id: `RB-${String(fid++).padStart(3,'0')}`,
        title: `Exposed path: ${p.path}`, category: p.category || 'Attack Surface',
        severity: (p.severity || 'INFO').toUpperCase(), status: 'OPEN',
        module: 'Attack Surface Discovery', description: `Disclosed via robots.txt (${robots.robots_url}).`,
        evidence: [p.path], recommendation: null, impact: null,
      });
    });
  }

  const severity_counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};
  findings.forEach(f=>{
    const s = severity_counts[f.severity] !== undefined ? f.severity : 'INFO';
    severity_counts[s]++;
  });

  const assets_count =
    (robots.robots_found ? (robots.summary?.disallowed_count ?? 0) + (robots.summary?.allowed_count ?? 0) + (robots.summary?.sitemaps_count ?? 0) : 0)
    + (scanner.success ? 1 : 0) + (behavior.success ? 1 : 0);

  const modules = {
    recon: { status: scanner.success ? 'completed' : 'failed' },
    web_security: { status: scanner.success ? 'completed' : 'failed' },
    attack_surface: { status: robots.success ? 'completed' : 'failed' },
    threat_detection: { status: behavior.success ? 'completed' : 'failed' },
    risk_engine: { status: 'completed' },
  };

  return {
    target: raw.target,
    scan_timestamp: raw.scan_timestamp,
    security_score: score,
    risk_level: risk,
    severity_counts,
    findings,
    findings_count: findings.length,
    modules,
    attack_surface: { assets_count },
    execution_time_ms: raw.execution_time_ms ?? 0,
  };
}

/* ==================== DISCOVERED IDENTITIES + OSINT LOOKUP ====================
   master_link.py's /api/v1/master/scan now also returns:
     user_discovery: { success, discovered_identities: [{type, value, platform?, source, ...}], note }
   This section renders that list and wires each "LOOKUP" button to the
   new single-identifier /api/v1/osint/* endpoints. Nothing here runs
   automatically — a lookup only fires when the operator explicitly clicks
   LOOKUP on one specific, already-visible identifier. */
function renderIdentities(raw){
  const ud = raw.user_discovery || {};
  els.identitiesPanel.style.display = 'block';

  if(!ud.success){
    els.identitiesList.innerHTML = `<div class="empty-state">IDENTITY DISCOVERY FAILED${ud.error ? ': ' + escapeHtml(ud.error) : ''}.</div>`;
    return;
  }

  const identities = ud.discovered_identities || [];
  if(identities.length === 0){
    els.identitiesList.innerHTML = '<div class="empty-state">NO EXPOSED USERNAMES, EMAILS OR SOCIAL HANDLES FOUND ON THIS TARGET.</div>';
    return;
  }

  const LOOKUP_KIND = { username: 'username', social_handle: 'username', email: 'email' };

  els.identitiesList.innerHTML = identities.map((ident, i)=>{
    const kind = LOOKUP_KIND[ident.type];
    const platform = ident.platform ? `<span class="identity-platform">[${escapeHtml(ident.platform)}]</span>` : '';
    const foundOn = ident.found_on ? `<span class="identity-platform">on ${escapeHtml(ident.found_on)}</span>` : '';
    const btn = kind
      ? `<button class="identity-lookup-btn" data-idx="${i}" data-kind="${kind}" data-value="${escapeHtml(ident.value)}">LOOKUP</button>`
      : '';
    return `
      <div class="identity-item">
        <span class="identity-type">${escapeHtml(ident.type.replace('_',' '))}</span>
        <span class="identity-value">${escapeHtml(ident.value)}</span>
        ${platform}
        ${foundOn}
        ${btn}
      </div>`;
  }).join('') + `<div class="identities-note">${escapeHtml(ud.note || '')}</div>`;

  els.identitiesList.querySelectorAll('.identity-lookup-btn').forEach(btn=>{
    btn.addEventListener('click', ()=> runOsintLookup(btn.dataset.kind, btn.dataset.value, btn));
  });
}

function escapeHtml(str){
  return String(str ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function runOsintLookup(kind, value, btnEl){
  if(btnEl){ btnEl.disabled = true; btnEl.textContent = '...'; }

  els.osintModalKind.textContent = kind.toUpperCase();
  els.osintModalTitle.textContent = `OSINT LOOKUP — ${value}`;
  els.osintModalLoading.style.display = 'block';
  els.osintModalBody.innerHTML = '';
  els.osintModal.classList.add('show');

  try{
    const base = els.apiBase.value.replace(/\/$/,'');
    const res = await fetch(`${base}/api/v1/osint/${kind}`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ value }),
    });
    const data = await res.json();
    els.osintModalLoading.style.display = 'none';

    if(!data.success){
      els.osintModalBody.innerHTML = `<div class="modal-field"><label>ERROR</label><div>${escapeHtml(data.error || 'Lookup failed')}</div></div>`;
      return;
    }
    els.osintModalBody.innerHTML = renderOsintResult(data);
  }catch(err){
    els.osintModalLoading.style.display = 'none';
    els.osintModalBody.innerHTML = `<div class="modal-field"><label>ERROR</label><div>BACKEND UNREACHABLE — ${escapeHtml(err.message || '')}</div></div>`;
  }finally{
    if(btnEl){ btnEl.disabled = false; btnEl.textContent = 'LOOKUP'; }
  }
}

function renderOsintResult(data){
  if(data.kind === 'username'){
    const rows = data.results.map(r=>
      `<div class="osint-result-row"><span class="osint-result-platform">${escapeHtml(r.platform)}</span><span class="osint-result-status-${r.status}">${r.status}</span></div>`
    ).join('');
    return `
      <div class="modal-field"><label>USERNAME</label><div>${escapeHtml(data.query)}</div></div>
      <div class="modal-field"><label>FOUND ON ${data.found_count} / ${data.checked_count} PLATFORMS</label></div>
      ${rows}`;
  }
  if(data.kind === 'email'){
    return `
      <div class="modal-field"><label>EMAIL</label><div>${escapeHtml(data.normalized)}</div></div>
      <div class="modal-field"><label>DOMAIN</label><div>${escapeHtml(data.domain)}</div></div>
      <div class="modal-field"><label>MX / SPF / DMARC</label><div>${data.mx_present?'MX ✓':'MX ✗'} &nbsp; ${data.spf_present?'SPF ✓':'SPF ✗'} &nbsp; ${data.dmarc_present?'DMARC ✓':'DMARC ✗'}</div></div>`;
  }
  if(data.kind === 'ip'){
    return `
      <div class="modal-field"><label>IP</label><div>${escapeHtml(data.query)} (${data.version})</div></div>
      <div class="modal-field"><label>REVERSE DNS</label><div>${escapeHtml(data.reverse_dns)}</div></div>
      <div class="modal-field"><label>ORGANIZATION</label><div>${escapeHtml(data.organization)}</div></div>`;
  }
  if(data.kind === 'phone'){
    return `
      <div class="modal-field"><label>NUMBER</label><div>${escapeHtml(data.normalized)}</div></div>
      <div class="modal-field"><label>COUNTRY / CARRIER</label><div>${escapeHtml(data.country)} — ${escapeHtml(data.carrier)}</div></div>
      <div class="modal-field"><label>TYPE</label><div>${escapeHtml(data.type)}</div></div>`;
  }
  return `<pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
}

els.osintModalClose.addEventListener('click', ()=> els.osintModal.classList.remove('show'));
els.osintModal.addEventListener('click', (e)=>{ if(e.target === els.osintModal) els.osintModal.classList.remove('show'); });

/* ==================== STANDALONE MANUAL OSINT PAGE ====================
   Independent of the scan flow — lets the operator run any single-
   identifier lookup (username / email / ip / phone) directly against
   the existing /api/v1/osint/* endpoints, for ad-hoc testing or when
   the identifier didn't come from a scan's discovered-identities list. */
const OSINT_PAGE_META = {
  username: { prefix: 'USERNAME://', placeholder: 'e.g. johndoe' },
  email:    { prefix: 'EMAIL://',    placeholder: 'e.g. name@example.com' },
  ip:       { prefix: 'IP://',       placeholder: 'e.g. 8.8.8.8' },
  phone:    { prefix: 'PHONE://',    placeholder: 'e.g. +201001234567' },
};
let osintPageKind = 'username';

els.osintKindTabs.querySelectorAll('.osint-kind-tab').forEach(tab=>{
  tab.addEventListener('click', ()=>{
    osintPageKind = tab.dataset.kind;
    els.osintKindTabs.querySelectorAll('.osint-kind-tab').forEach(t=>t.classList.toggle('active', t===tab));
    const meta = OSINT_PAGE_META[osintPageKind];
    els.osintInputPrefix.textContent = meta.prefix;
    els.osintValueInput.placeholder = meta.placeholder;
    els.osintCountryWrap.style.display = (osintPageKind === 'phone') ? 'flex' : 'none';
    els.osintPageResults.innerHTML = '';
    els.osintErrorBanner.style.display = 'none';
  });
});

async function runOsintPageLookup(){
  const value = els.osintValueInput.value.trim();
  els.osintErrorBanner.style.display = 'none';
  els.osintPageResults.innerHTML = '';

  if(!value){
    els.osintErrorText.textContent = 'ENTER A VALUE TO LOOK UP FIRST.';
    els.osintErrorBanner.style.display = 'flex';
    return;
  }

  els.osintRunBtn.disabled = true;
  els.osintRunBtnText.textContent = 'RUNNING...';
  els.osintPageResults.innerHTML = '<div class="empty-state">LOOKING UP...</div>';

  try{
    const base = els.apiBase.value.replace(/\/$/,'');
    const body = { value };
    if(osintPageKind === 'phone' && els.osintCountryInput.value.trim()){
      body.country = els.osintCountryInput.value.trim().toUpperCase();
    }
    const res = await fetch(`${base}/api/v1/osint/${osintPageKind}`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    const data = await res.json();

    if(!data.success){
      els.osintPageResults.innerHTML = '';
      els.osintErrorText.textContent = data.error || 'LOOKUP FAILED.';
      els.osintErrorBanner.style.display = 'flex';
      return;
    }
    els.osintPageResults.innerHTML = renderOsintResult(data);
  }catch(err){
    els.osintPageResults.innerHTML = '';
    els.osintErrorText.textContent = `BACKEND UNREACHABLE — ${err.message || ''}`;
    els.osintErrorBanner.style.display = 'flex';
  }finally{
    els.osintRunBtn.disabled = false;
    els.osintRunBtnText.textContent = 'RUN LOOKUP';
  }
}

els.osintRunBtn.addEventListener('click', runOsintPageLookup);
els.osintValueInput.addEventListener('keydown', (e)=>{ if(e.key === 'Enter') runOsintPageLookup(); });

/* ==================== SCAN FLOW ==================== */
const PROGRESS_STEPS = [
  'Target Reconnaissance','DNS Analysis','Technology Detection','HTTP Security Analysis',
  'Attack Surface Discovery','Vulnerability Assessment','Risk Calculation','Report Generation'
];

async function runScan(){
  const rawUrl = els.urlInput.value.trim();
  if(!rawUrl){ showError('ENTER TARGET URL FIRST.'); return; }
  hideError(); setScanning(true); showPage('scan'); resetScanProgress();
  els.identitiesPanel.style.display = 'none';
  els.identitiesList.innerHTML = '<div class="empty-state">NO SCAN RUN YET.</div>';
  animateScanProgress(); // start live step-by-step animation

  try{
    const base = els.apiBase.value.replace(/\/$/,'');
    const res = await fetch(base + '/api/v1/master/scan', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({url: rawUrl, timeout: 10}),
    });
    const raw = await res.json();
    if(!res.ok) throw new Error(raw.error || `SERVER ERROR (${res.status})`);
    if(raw.scan_failed){
      throw new Error(
        'SCAN COULD NOT BE COMPLETED — the target blocked the request or is unreachable. '
        + (raw.scan_failure_reason ? `(${raw.scan_failure_reason})` : '')
      );
    }

    // The backend (master_link.py) returns a nested report shape
    // (unified_assessment / security_behavior_engine / combined_scanner /
    // robots_txt_analysis) — normalize it into the flat shape the
    // dashboard widgets read from.
    const data = normalizeScanResult(raw);
    state.rawResult = raw; // keep the full backend payload for JSON export

    completeScanProgress();
    renderResult(data, raw);
    renderIdentities(raw);
    renderScanTools(raw);
    pushHistory(data);
    setTimeout(()=> showPage('dashboard'), 1000);
    renderRobotsPage();
  }catch(err){
    showError(err.message || 'BACKEND UNREACHABLE. START APP.PY');
    setScanning(false);
    clearInterval(state.scanTimer);
  }
}

function setScanning(on){
  els.scanBtn.disabled = on;
  els.scanBtnText.textContent = on ? 'SCANNING...' : 'INITIATE SCAN';
}
function showError(msg){ els.errorText.textContent = msg; els.errorBanner.classList.add('show'); }
function hideError(){ els.errorBanner.classList.remove('show'); }

function resetScanProgress(){
  document.querySelectorAll('.sp-item').forEach((el,i)=>{
    el.className = 'sp-item';
    el.querySelector('.sp-status').textContent = '○';
  });
  els.scanProgressBar.style.width = '0%';
  els.scanProgressStatus.textContent = 'INITIALIZING...';
}

function completeScanProgress(){
  document.querySelectorAll('.sp-item').forEach(el=>{
    el.classList.add('done');
    el.querySelector('.sp-status').textContent = '✓';
  });
  els.scanProgressBar.style.width = '100%';
  els.scanProgressStatus.textContent = 'SCAN COMPLETED';
  setScanning(false);
}

// Animate progress steps during scan — marks each step done immediately
function animateScanProgress(){
  let step = 0;
  clearInterval(state.scanTimer);
  state.scanTimer = setInterval(()=>{
    if(step < PROGRESS_STEPS.length){
      // Mark previous step as done (if any)
      if(step > 0){
        const prevEl = document.querySelector(`.sp-item[data-step="${step}"]`);
        if(prevEl && !prevEl.classList.contains('done')){
          prevEl.classList.remove('active');
          prevEl.classList.add('done');
          prevEl.querySelector('.sp-status').textContent = '✓';
        }
      }
      // Activate current step
      const el = document.querySelector(`.sp-item[data-step="${step+1}"]`);
      if(el){ el.classList.add('active'); el.querySelector('.sp-status').textContent = '◉'; }
      els.scanProgressStatus.textContent = `RUNNING: ${PROGRESS_STEPS[step]}...`;
      step++;
      els.scanProgressBar.style.width = Math.min(100, (step/PROGRESS_STEPS.length)*100) + '%';
    } else {
      // All steps shown, mark last as done
      const lastEl = document.querySelector(`.sp-item[data-step="${PROGRESS_STEPS.length}"]`);
      if(lastEl && !lastEl.classList.contains('done')){
        lastEl.classList.remove('active');
        lastEl.classList.add('done');
        lastEl.querySelector('.sp-status').textContent = '✓';
      }
    }
  }, 700);
}

/* ==================== RENDER RESULT ==================== */
function renderResult(data, raw){
  state.lastResult = data;
  const score = data.security_score ?? 0;
  const risk = data.risk_level ?? 'LOW';
  const counts = data.severity_counts ?? {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0};

  // Gauge
  const c = 490, offset = c - (score/100)*c;
  els.gaugeValue.style.strokeDashoffset = offset;
  els.gaugeValueInner.style.strokeDashoffset = (389.6 - (score/100)*389.6);
  animateNumber(els.dashScoreNum, score);
  els.dashScoreStatus.textContent = RISK_LABELS[risk] || 'UNKNOWN';
  els.dashScoreStatus.className = 'gauge-status ' + (risk === 'CRITICAL' ? 'danger' : risk === 'HIGH' ? 'warning' : '');

  // Mini stats
  els.mstatCritical.textContent = counts.CRITICAL;
  els.mstatHigh.textContent = counts.HIGH;
  els.mstatMedium.textContent = counts.MEDIUM;
  els.mstatLow.textContent = counts.LOW;

  // Target
  els.targetName.textContent = data.target || 'UNKNOWN';
  els.targetStatus.textContent = 'SCAN COMPLETE';
  els.targetStatus.className = 'target-status';

  // Center stats
  const assets = data.attack_surface?.assets_count ?? 0;
  els.cstatAssets.textContent = assets;
  els.cstatFindings.textContent = data.findings_count ?? 0;
  els.cstatDuration.textContent = ((data.execution_time_ms ?? 0)/1000).toFixed(1) + 's';
  els.cstatRisk.textContent = risk;
  els.cstatRisk.style.color = RISK_COLORS[risk] || '#6b7a9c';
  els.cstatRiskDelta.textContent = score >= 75 ? 'ACCEPTABLE' : 'REVIEW REQUIRED';
  els.cstatRiskDelta.style.color = score >= 75 ? RISK_COLORS.LOW : RISK_COLORS.CRITICAL;

  // Shield
  const sc = 515, so = sc - (score/100)*sc;
  els.shieldProgress.style.strokeDashoffset = so;
  els.shieldLevel.textContent = RISK_LABELS[risk] || 'UNKNOWN';
  els.shieldLevel.style.color = RISK_COLORS[risk] || '#6b7a9c';
  els.shieldSub.textContent = score >= 75 ? 'SYSTEM FULLY PROTECTED' : 'SECURITY REVIEW REQUIRED';

  // Module list
  renderModuleList(data.modules);

  // Threat list
  renderThreatList(data.findings);

  // Chart
  drawChart();

  // Findings page removed - data shown on dashboard only
  // renderFindingsTable();

  // World map live stats
  updateWorldMapStats(data);
  drawSeverityDonut();

  // Bottom bar (real values only — HTTP status, response time, redirects, module count)
  updateStatsBar(data, raw);
}

function updateWorldMapStats(data){
  if(!els.wmsNodes) return;
  const counts = data.severity_counts || {};
  const threats = (counts.CRITICAL||0) + (counts.HIGH||0);
  els.wmsNodes.textContent = data.attack_surface?.assets_count ?? 0;
  els.wmsConnections.textContent = data.findings_count ?? 0;
  els.wmsTime.textContent = ((data.execution_time_ms ?? 0)/1000).toFixed(1) + 's';
  els.wmsThreats.textContent = threats;
  els.wmsThreats.style.color = threats > 0 ? '#ff4d6d' : '#cfe8ff';
}

function animateNumber(el, target){
  const start = 0, dur = 900, t0 = performance.now();
  function tick(t){
    const p = Math.min(1,(t-t0)/dur);
    const eased = 1 - Math.pow(1-p, 3);
    el.textContent = Math.round(start + (target-start)*eased);
    if(p<1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function renderModuleList(modules){
  if(!modules) return;
  const map = [
    {key:'recon', name:'Target Reconnaissance', id:'RECON-001'},
    {key:'web_security', name:'HTTP Security Analysis', id:'HTTP-002'},
    {key:'attack_surface', name:'Attack Surface Discovery', id:'ATK-003'},
    {key:'threat_detection', name:'Threat Detection', id:'THR-004'},
    {key:'risk_engine', name:'Risk Engine', id:'RISK-005'},
  ];
  els.moduleList.innerHTML = map.map(m=>{
    const mod = modules[m.key];
    const pct = mod && mod.status === 'completed' ? 100 : 0;
    return `
      <div class="proc-item">
        <div class="proc-icon">${pct===100?'✓':'○'}</div>
        <div class="proc-info">
          <span class="proc-name">${m.name}</span>
          <span class="proc-id">ID: ${m.id}</span>
        </div>
        <div class="proc-bar"><div class="proc-fill" style="width:${pct}%"></div></div>
        <span class="proc-pct">${pct}%</span>
      </div>`;
  }).join('');
}

function renderThreatList(findings){
  if(!findings || findings.length === 0){
    els.threatList.innerHTML = `<div class="threat-item empty"><span class="threat-icon">◉</span><span class="threat-name">No threats detected</span><span class="threat-status">—</span><span class="threat-time">—</span></div>`;
    return;
  }
  const top = findings.slice(0, 6);
  els.threatList.innerHTML = top.map((f,i)=>{
    const statusClass = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'open' :
                        f.severity === 'MEDIUM' ? 'quarantined' : 'monitoring';
    const statusText = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'OPEN' :
                       f.severity === 'MEDIUM' ? 'QUARANTINED' : 'MONITORING';
    return `
      <div class="threat-item">
        <span class="threat-icon" style="color:${SEV_COLORS[f.severity]||'#6b7a9c'}">◉</span>
        <span class="threat-name">${escapeHtml(f.title)}</span>
        <span class="threat-status ${statusClass}">${statusText}</span>
        <span class="threat-time">${i*2+2} min ago</span>
      </div>`;
  }).join('');
}

/* ==================== FINDINGS TABLE ==================== */
document.querySelectorAll('.f-filter').forEach(btn=>{
  btn.addEventListener('click', ()=>{
    document.querySelectorAll('.f-filter').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    state.currentFilter = btn.dataset.filter;
    renderFindingsTable();
  });
});

function renderFindingsTable(){
  if(!els.findingsTableBody || !els.findingsCount) return;
  if(!state.lastResult){
    els.findingsTableBody.innerHTML = '<tr class="empty-row"><td colspan="6">NO FINDINGS DETECTED. INITIATE SCAN.</td></tr>';
    els.findingsCount.textContent = '0 FINDINGS';
    return;
  }
  const findings = state.lastResult.findings || [];
  const filtered = state.currentFilter === 'all' ? findings : findings.filter(f=>f.severity === state.currentFilter);
  if(els.findingsCount) els.findingsCount.textContent = `${filtered.length} FINDINGS`;

  if(filtered.length === 0){
    if(els.findingsTableBody) els.findingsTableBody.innerHTML = '<tr class="empty-row"><td colspan="6">NO FINDINGS MATCH SELECTED FILTER.</td></tr>';
    return;
  }
  if(els.findingsTableBody) els.findingsTableBody.innerHTML = filtered.map(f=>`
    <tr class="finding-row" data-id="${escapeHtml(f.id)}">
      <td class="mono">${escapeHtml(f.id)}</td>
      <td>${escapeHtml(f.title)}</td>
      <td>${escapeHtml(f.category)}</td>
      <td><span class="sev-pill" style="color:${SEV_COLORS[f.severity]||'#6b7a9c'};border-color:${SEV_COLORS[f.severity]||'#6b7a9c'}">${f.severity}</span></td>
      <td><span class="status-pill-small">${f.status}</span></td>
      <td>${escapeHtml(f.module)}</td>
    </tr>
  `).join('');

  document.querySelectorAll('.finding-row').forEach(row=>{
    row.addEventListener('click', ()=> openFindingModal(row.dataset.id));
  });
}

/* ==================== MODAL ==================== */
function openFindingModal(id){
  if(!state.lastResult) return;
  const f = state.lastResult.findings.find(x=>x.id === id);
  if(!f) return;
  els.modalTitle.textContent = f.title;
  els.modalSev.textContent = f.severity;
  els.modalSev.style.color = SEV_COLORS[f.severity] || '#6b7a9c';
  els.modalSev.style.borderColor = SEV_COLORS[f.severity] || '#6b7a9c';
  els.modalCategory.textContent = f.category;
  els.modalStatus.textContent = f.status || 'OPEN';
  els.modalDesc.textContent = f.description || '—';
  els.modalImpact.textContent = f.impact || '—';
  els.modalEvidence.textContent = JSON.stringify(f.evidence || {}, null, 2);
  els.modalRec.textContent = f.recommendation || '—';
  els.modalRefs.innerHTML = (f.references || []).map(r=>`<a href="#" style="color:#ff4500;text-decoration:none;margin-right:8px;">${escapeHtml(r)}</a>`).join('');
  els.findingModal.classList.add('show');
}
els.modalClose.addEventListener('click', ()=> els.findingModal.classList.remove('show'));
els.findingModal.addEventListener('click', (e)=>{ if(e.target === els.findingModal) els.findingModal.classList.remove('show'); });

/* ==================== HISTORY ==================== */
function pushHistory(data){
  const prev = state.history[0] || null;
  state.history.unshift({
    target: data.target, score: data.security_score, risk: data.risk_level,
    ts: data.scan_timestamp, findings_count: data.findings_count,
  });
  state.history = state.history.slice(0, 10);
  renderHistory(prev, data);
}

function renderHistory(prevScan, currentScan){
  if(prevScan){
    els.historyComparison.style.display = 'flex';
    els.prevScore.textContent = prevScan.score + '/100';
    els.prevScore.style.color = RISK_COLORS[prevScan.risk] || '#6b7a9c';
    els.prevTarget.textContent = prevScan.target;
    els.currScore.textContent = currentScan.security_score + '/100';
    els.currScore.style.color = RISK_COLORS[currentScan.risk_level] || '#6b7a9c';
    els.currTarget.textContent = currentScan.target;
    const diff = (currentScan.security_score || 0) - (prevScan.score || 0);
    const sign = diff > 0 ? '+' : '';
    els.compChange.innerHTML = `<span style="color:${diff>=0?'#ff7b00':'#ff1a1a'}">${sign}${diff} SECURITY ${diff>=0?'IMPROVEMENT':'REGRESSION'}</span>`;
  } else {
    els.historyComparison.style.display = 'none';
  }
  els.historyList.innerHTML = state.history.map((h,i)=>`
    <div class="history-item" data-idx="${i}">
      <div class="hist-main">
        <span class="hist-target">${escapeHtml(h.target)}</span>
        <span class="hist-time">${fmtTime(h.ts)}</span>
      </div>
      <div class="hist-meta">
        <span class="hist-score" style="color:${RISK_COLORS[h.risk]||'#6b7a9c'}">${h.score}%</span>
        <span class="hist-risk">${h.risk}</span>
        <span class="hist-count">${h.findings_count} FINDINGS</span>
      </div>
    </div>
  `).join('');
}

function fmtTime(iso){
  if(!iso) return '—';
  try{ const d = new Date(iso); return d.toLocaleString('en-US', {hour:'2-digit', minute:'2-digit', day:'2-digit', month:'short'}); }
  catch(e){ return iso; }
}

/* ==================== EXPORT ==================== */
$('exportJsonBtn').addEventListener('click', ()=>{
  if(!state.lastResult){ alert('RUN SCAN FIRST BEFORE EXPORTING.'); return; }
  const payload = state.rawResult || state.lastResult; // prefer the full backend report
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `security-report-${state.lastResult.target.replace(/[^a-z0-9]/gi,'_')}-${Date.now()}.json`;
  a.click(); URL.revokeObjectURL(url);
});

/* ==================== PDF REPORT ====================
   Builds a full professional PDF straight from the browser using jsPDF +
   jspdf-autotable (loaded via CDN in index.html). Pulls from state.rawResult
   (the raw master_link.py payload) and state.lastResult (the normalized
   dashboard shape) so the PDF always mirrors exactly what's on screen. */
const SEV_PDF_COLORS = {
  CRITICAL: [255, 26, 26], HIGH: [255, 123, 0], MEDIUM: [255, 149, 0],
  LOW: [255, 255, 255], INFO: [140, 140, 150],
};

$('exportPdfBtn').addEventListener('click', ()=> buildPdfReport());

function buildPdfReport(){
  if(!state.lastResult){ alert('RUN SCAN FIRST BEFORE EXPORTING.'); return; }
  if(typeof window.jspdf === 'undefined'){
    alert('PDF ENGINE FAILED TO LOAD — CHECK YOUR INTERNET CONNECTION AND RETRY.');
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageW = doc.internal.pageSize.getWidth();
  const margin = 40;
  let y = 0;

  const data = state.lastResult;
  const raw = state.rawResult || {};
  const httpScan = raw.combined_scanner?.http_scan || {};
  const robots = raw.robots_txt_analysis || {};
  const unified = raw.unified_assessment || {};
  const risk = data.risk_level || 'LOW';
  const riskRGB = { LOW:[255,123,0], MEDIUM:[255,149,0], HIGH:[255,102,0], CRITICAL:[255,26,26] }[risk] || [140,140,150];

  const addFooter = () => {
    const pages = doc.internal.getNumberOfPages();
    for(let i=1;i<=pages;i++){
      doc.setPage(i);
      doc.setFont('helvetica','normal'); doc.setFontSize(8); doc.setTextColor(140,140,150);
      doc.text('Reconix — Passive, non-intrusive scan. Not a substitute for a full penetration test.', margin, 812);
      doc.text(`Page ${i} / ${pages}`, pageW - margin, 812, { align: 'right' });
    }
  };

  // ---------- Cover / header band ----------
  doc.setFillColor(9, 5, 5);
  doc.rect(0, 0, pageW, 130, 'F');
  doc.setDrawColor(...riskRGB); doc.setLineWidth(2);
  doc.line(0, 130, pageW, 130);

  doc.setFont('helvetica','bold'); doc.setFontSize(22); doc.setTextColor(255,255,255);
  doc.text('SECURITY ASSESSMENT REPORT', margin, 48);
  doc.setFont('helvetica','normal'); doc.setFontSize(11); doc.setTextColor(216,168,160);
  doc.text('Reconix — Security Control System', margin, 66);

  doc.setFont('helvetica','bold'); doc.setFontSize(12); doc.setTextColor(255,255,255);
  doc.text(`TARGET: ${data.target || 'UNKNOWN'}`, margin, 92);
  doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(180,150,145);
  doc.text(`Scanned: ${fmtTime(data.scan_timestamp)}   |   Generated: ${new Date().toLocaleString('en-US')}`, margin, 108);

  doc.setFont('helvetica','bold'); doc.setFontSize(28); doc.setTextColor(...riskRGB);
  doc.text(`${data.security_score ?? 0}%`, pageW - margin, 60, { align: 'right' });
  doc.setFont('helvetica','normal'); doc.setFontSize(10); doc.setTextColor(255,255,255);
  doc.text(`RISK: ${risk}${unified.rating ? '  (' + unified.rating + ')' : ''}`, pageW - margin, 78, { align: 'right' });

  y = 155;

  // ---------- Executive summary ----------
  doc.setFont('helvetica','bold'); doc.setFontSize(13); doc.setTextColor(30,20,20);
  doc.text('1. EXECUTIVE SUMMARY', margin, y); y += 8;

  const counts = data.severity_counts || {};
  doc.autoTable({
    startY: y + 6,
    theme: 'grid',
    margin: { left: margin, right: margin },
    styles: { font: 'helvetica', fontSize: 9, cellPadding: 6 },
    headStyles: { fillColor: [18, 8, 8], textColor: 255, fontStyle: 'bold' },
    head: [['Unified Score', 'Risk Level', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Total Findings', 'Duration']],
    body: [[
      `${data.security_score ?? 0}%`, risk,
      counts.CRITICAL ?? 0, counts.HIGH ?? 0, counts.MEDIUM ?? 0, counts.LOW ?? 0, counts.INFO ?? 0,
      data.findings_count ?? 0, `${((data.execution_time_ms ?? 0)/1000).toFixed(1)}s`,
    ]],
  });
  y = doc.lastAutoTable.finalY + 26;

  // ---------- Target information ----------
  doc.setFont('helvetica','bold'); doc.setFontSize(13); doc.setTextColor(30,20,20);
  doc.text('2. TARGET INFORMATION', margin, y); y += 8;

  const targetRows = [
    ['Requested URL', httpScan.requested_url || data.target || '—'],
    ['Final URL (after redirects)', httpScan.final_url || '—'],
    ['HTTP Status Code', httpScan.status_code != null ? String(httpScan.status_code) : '—'],
    ['Response Time', httpScan.response_time_seconds != null ? `${httpScan.response_time_seconds}s` : '—'],
    ['Redirected', httpScan.redirected != null ? (httpScan.redirected ? `Yes (${httpScan.redirect_count})` : 'No') : '—'],
    ['Server Header', httpScan.headers?.Server || httpScan.headers?.server || 'Not disclosed'],
  ];
  doc.autoTable({
    startY: y + 6,
    theme: 'grid',
    margin: { left: margin, right: margin },
    styles: { font: 'helvetica', fontSize: 9, cellPadding: 6, overflow: 'linebreak' },
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 160 } },
    body: targetRows,
  });
  y = doc.lastAutoTable.finalY + 26;

  // ---------- Findings ----------
  if(y > 680){ doc.addPage(); y = 40; }
  doc.setFont('helvetica','bold'); doc.setFontSize(13); doc.setTextColor(30,20,20);
  doc.text('3. SECURITY FINDINGS', margin, y); y += 8;

  const findings = (data.findings || []).slice().sort(
    (a,b)=> SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  if(findings.length === 0){
    doc.setFont('helvetica','normal'); doc.setFontSize(10); doc.setTextColor(80,80,80);
    doc.text('No findings were detected during this scan.', margin, y + 20);
    y += 40;
  } else {
    doc.autoTable({
      startY: y + 6,
      theme: 'grid',
      margin: { left: margin, right: margin },
      styles: { font: 'helvetica', fontSize: 8.5, cellPadding: 5, overflow: 'linebreak', valign: 'top' },
      headStyles: { fillColor: [18, 8, 8], textColor: 255, fontStyle: 'bold' },
      columnStyles: {
        0: { cellWidth: 50 }, 1: { cellWidth: 55 }, 2: { cellWidth: 100 },
        3: { cellWidth: 90 }, 4: { cellWidth: 190 },
      },
      head: [['ID', 'Severity', 'Title', 'Module', 'Description / Recommendation']],
      body: findings.map(f => [
        f.id || '—', f.severity || 'INFO', f.title || '—', f.module || '—',
        [f.description, f.recommendation ? `Fix: ${f.recommendation}` : null].filter(Boolean).join('\n'),
      ]),
      didParseCell: (hook) => {
        if(hook.section === 'body' && hook.column.index === 1){
          const sev = hook.cell.raw;
          const c = SEV_PDF_COLORS[sev] || [140,140,150];
          hook.cell.styles.textColor = sev === 'LOW' ? [20,20,20] : c;
          hook.cell.styles.fontStyle = 'bold';
        }
      },
    });
    y = doc.lastAutoTable.finalY + 26;
  }

  // ---------- Attack surface (robots.txt) ----------
  if(y > 650){ doc.addPage(); y = 40; }
  doc.setFont('helvetica','bold'); doc.setFontSize(13); doc.setTextColor(30,20,20);
  doc.text('4. ATTACK SURFACE (robots.txt)', margin, y); y += 8;

  if(!robots.success || !robots.robots_found){
    doc.setFont('helvetica','normal'); doc.setFontSize(10); doc.setTextColor(80,80,80);
    doc.text(robots.note || 'robots.txt was not found or not accessible for this target.', margin, y + 20);
    y += 40;
  } else {
    const s = robots.summary || {};
    doc.autoTable({
      startY: y + 6,
      theme: 'grid',
      margin: { left: margin, right: margin },
      styles: { font: 'helvetica', fontSize: 9, cellPadding: 6 },
      headStyles: { fillColor: [18, 8, 8], textColor: 255, fontStyle: 'bold' },
      head: [['User-Agents', 'Disallowed Paths', 'Allowed Paths', 'Sitemaps', 'Interesting Paths']],
      body: [[
        s.user_agents_count ?? 0, s.disallowed_count ?? 0, s.allowed_count ?? 0,
        s.sitemaps_count ?? 0, s.interesting_paths_count ?? 0,
      ]],
    });
    y = doc.lastAutoTable.finalY + 20;

    const interesting = robots.interesting_paths || [];
    if(interesting.length){
      doc.autoTable({
        startY: y,
        theme: 'grid',
        margin: { left: margin, right: margin },
        styles: { font: 'helvetica', fontSize: 8.5, cellPadding: 5 },
        headStyles: { fillColor: [18, 8, 8], textColor: 255, fontStyle: 'bold' },
        head: [['Path', 'Category', 'Severity']],
        body: interesting.map(p => [p.path, p.category || '—', p.severity || '—']),
        didParseCell: (hook) => {
          if(hook.section === 'body' && hook.column.index === 2){
            const c = SEV_PDF_COLORS[String(hook.cell.raw).toUpperCase()] || [140,140,150];
            hook.cell.styles.textColor = c; hook.cell.styles.fontStyle = 'bold';
          }
        },
      });
    }
  }

  addFooter();
  doc.save(`security-report-${(data.target||'target').replace(/[^a-z0-9]/gi,'_')}-${Date.now()}.pdf`);
}

/* ==================== UTILS ==================== */
function escapeHtml(str){
  if(str == null) return '';
  return String(str).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}


/* ==================== SEVERITY DISTRIBUTION PANEL ====================
   This used to be a decorative "world map" — animated cities, flying data
   packets and a radar sweep — that had nothing to do with the actual
   target being scanned. It's replaced with a real donut chart of the
   findings' severity breakdown (state.lastResult.severity_counts), redrawn
   whenever a scan completes or the window resizes. No random data. */
let severityCanvasEl = null;

function initSeverityPanel(){
  severityCanvasEl = document.getElementById('worldMapCanvas');
  if(!severityCanvasEl){ console.warn('Severity panel canvas not found'); return; }
  resizeSeverityCanvas();
  drawSeverityDonut();
  window.addEventListener('resize', ()=>{ resizeSeverityCanvas(); drawSeverityDonut(); });
}

function resizeSeverityCanvas(){
  const canvas = severityCanvasEl;
  if(!canvas) return;
  const wrap = canvas.parentElement;
  if(!wrap) return;
  const rect = wrap.getBoundingClientRect();
  const w = Math.max(rect.width, 300), h = Math.max(rect.height, 200);
  canvas.width = w; canvas.height = h;
  canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
}

function drawSeverityDonut(){
  const canvas = severityCanvasEl;
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0,0,w,h);

  const counts = state.lastResult?.severity_counts;
  const total = counts ? Object.values(counts).reduce((a,b)=>a+b,0) : 0;

  const cx = w*0.34, cy = h/2, rOuter = Math.min(w,h)*0.30, rInner = rOuter*0.58;

  if(!counts || total === 0){
    ctx.fillStyle = 'rgba(216,168,160,0.5)';
    ctx.font = '12px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('NO SCAN DATA YET — RUN A SCAN', w/2, h/2);
    return;
  }

  let startAngle = -Math.PI/2;
  SEV_ORDER.forEach(sev => {
    const val = counts[sev] || 0;
    if(val === 0) return;
    const sliceAngle = (val/total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, rOuter, startAngle, startAngle + sliceAngle);
    ctx.closePath();
    ctx.fillStyle = SEV_COLORS[sev] || '#6b7a9c';
    ctx.globalAlpha = 0.85;
    ctx.fill();
    ctx.globalAlpha = 1;
    startAngle += sliceAngle;
  });

  // Punch the donut hole
  ctx.globalCompositeOperation = 'destination-out';
  ctx.beginPath();
  ctx.arc(cx, cy, rInner, 0, Math.PI*2);
  ctx.fill();
  ctx.globalCompositeOperation = 'source-over';

  // Center label — total findings (real)
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 22px "JetBrains Mono", monospace';
  ctx.textAlign = 'center';
  ctx.fillText(String(total), cx, cy + 7);
  ctx.fillStyle = 'rgba(216,168,160,0.7)';
  ctx.font = '9px "JetBrains Mono", monospace';
  ctx.fillText('FINDINGS', cx, cy + 22);

  // Legend
  const legendX = w*0.62;
  let legendY = h/2 - (SEV_ORDER.length*20)/2 + 6;
  SEV_ORDER.forEach(sev => {
    const val = counts[sev] || 0;
    ctx.fillStyle = SEV_COLORS[sev] || '#6b7a9c';
    ctx.beginPath(); ctx.arc(legendX, legendY, 5, 0, Math.PI*2); ctx.fill();
    ctx.fillStyle = 'rgba(255,240,240,0.9)';
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.textAlign = 'left';
    ctx.fillText(`${sev}  ${val}`, legendX + 12, legendY + 3);
    legendY += 20;
  });
}


/* ==================== ROBOTS PAGE ==================== */
function renderRobotsPage(){
  if(!state.rawResult){
    $('robotsFound').textContent = '—';
    $('robotsUserAgents').textContent = '0';
    $('robotsDisallowed').textContent = '0';
    $('robotsAllowed').textContent = '0';
    $('robotsSitemaps').textContent = '0';
    $('robotsInteresting').textContent = '0';
    $('robotsUrl').textContent = '—';
    $('robotsUrl').href = '#';
    $('robotsInterestingBody').innerHTML = '<tr class="empty-row"><td colspan="3">NO SCAN DATA. INITIATE SCAN.</td></tr>';
    $('robotsDisallowedList').innerHTML = '<div class="empty-state">NO SCAN DATA.</div>';
    $('robotsAllowedList').innerHTML = '<div class="empty-state">NO SCAN DATA.</div>';
    $('robotsSitemapsList').innerHTML = '<div class="empty-state">NO SCAN DATA.</div>';
    return;
  }
  const robots = state.rawResult.robots_txt_analysis || {};
  const summary = robots.summary || {};

  $('robotsFound').textContent = robots.robots_found ? 'FOUND' : 'NOT FOUND';
  $('robotsFound').style.color = robots.robots_found ? '#00f5a0' : '#ff1a1a';
  $('robotsUserAgents').textContent = summary.user_agents_count ?? 0;
  $('robotsDisallowed').textContent = summary.disallowed_count ?? 0;
  $('robotsAllowed').textContent = summary.allowed_count ?? 0;
  $('robotsSitemaps').textContent = summary.sitemaps_count ?? 0;
  $('robotsInteresting').textContent = summary.interesting_paths_count ?? 0;

  if(robots.robots_url){
    $('robotsUrl').textContent = robots.robots_url;
    $('robotsUrl').href = robots.robots_url;
  } else {
    $('robotsUrl').textContent = '—';
    $('robotsUrl').href = '#';
  }

  // Interesting paths
  const interesting = robots.interesting_paths || [];
  if(interesting.length === 0){
    $('robotsInterestingBody').innerHTML = '<tr class="empty-row"><td colspan="3">NO INTERESTING PATHS FOUND.</td></tr>';
  } else {
    $('robotsInterestingBody').innerHTML = interesting.map(p=>{
      const pathStr = typeof p === 'string' ? p : (p.path || p.url || JSON.stringify(p));
      const category = typeof p === 'string' ? '—' : (p.category || '—');
      const severity = typeof p === 'string' ? 'INFO' : (p.severity?.toUpperCase() || 'INFO');
      return `
      <tr>
        <td class="mono"><a href="${escapeHtml(robots.robots_url || '#')}" target="_blank" style="color:#ff4500;text-decoration:none;">${escapeHtml(pathStr)}</a></td>
        <td>${escapeHtml(category)}</td>
        <td><span class="sev-pill" style="color:${SEV_COLORS[severity]||'#6b7a9c'};border-color:${SEV_COLORS[severity]||'#6b7a9c'}">${severity}</span></td>
      </tr>
    `}).join('');
  }

  // Disallowed paths
  const disallowed = robots.disallowed_paths || [];
  $('robotsDisallowedList').innerHTML = disallowed.length
    ? disallowed.map(p=>{
        const pathStr = typeof p === 'string' ? p : (p.path || p.url || JSON.stringify(p));
        return `<div class="robots-list-item">🚫 ${escapeHtml(pathStr)}</div>`;
      }).join('')
    : '<div class="empty-state">NO DISALLOWED PATHS.</div>';

  // Allowed paths
  const allowed = robots.allowed_paths || [];
  $('robotsAllowedList').innerHTML = allowed.length
    ? allowed.map(p=>{
        const pathStr = typeof p === 'string' ? p : (p.path || p.url || JSON.stringify(p));
        return `<div class="robots-list-item">✅ ${escapeHtml(pathStr)}</div>`;
      }).join('')
    : '<div class="empty-state">NO ALLOWED PATHS.</div>';

  // Sitemaps
  const sitemaps = robots.sitemaps || [];
  $('robotsSitemapsList').innerHTML = sitemaps.length
    ? sitemaps.map(p=>{
        const pathStr = typeof p === 'string' ? p : (p.path || p.url || JSON.stringify(p));
        return `<div class="robots-list-item">🗺️ <a href="${escapeHtml(pathStr)}" target="_blank" style="color:#ff4500;text-decoration:none;">${escapeHtml(pathStr)}</a></div>`;
      }).join('')
    : '<div class="empty-state">NO SITEMAPS FOUND.</div>';
}

/* ==================== SCAN TOOLS DETAILS ==================== */
function renderScanTools(raw){
  const panel = $('scanToolsPanel');
  const list = $('scanToolsList');
  panel.style.display = 'block';

  if(!raw){
    list.innerHTML = '<div class="empty-state">NO SCAN RUN YET.</div>';
    return;
  }

  const modules = [];

  // 1. HTTP Security Analysis
  const http = raw.combined_scanner?.http_scan;
  if(http){
    const headers = http.headers || {};
    const headerRows = Object.entries(headers).map(([k,v])=>`<div class="tool-detail-row"><span class="tool-detail-key">${escapeHtml(k)}</span><span class="tool-detail-val">${escapeHtml(String(v))}</span></div>`).join('');
    modules.push({
      name: 'HTTP Security Analysis',
      id: 'HTTP-002',
      status: raw.combined_scanner?.success ? 'COMPLETED' : 'FAILED',
      icon: '🌐',
      details: `
        <div class="tool-detail-row"><span class="tool-detail-key">Status Code</span><span class="tool-detail-val">${http.status_code != null ? http.status_code : '—'}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Final URL</span><span class="tool-detail-val">${escapeHtml(http.final_url || '—')}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Response Time</span><span class="tool-detail-val">${http.response_time_seconds != null ? http.response_time_seconds + 's' : '—'}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Redirected</span><span class="tool-detail-val">${http.redirected ? 'Yes (' + (http.redirect_count||0) + ')' : 'No'}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Server</span><span class="tool-detail-val">${escapeHtml(headers.Server || headers.server || 'Not disclosed')}</span></div>
        <div class="tool-detail-sep">RESPONSE HEADERS</div>
        ${headerRows || '<div class="tool-detail-row"><span class="tool-detail-key">—</span><span class="tool-detail-val">No headers captured</span></div>'}
      `
    });
  }

  // 2. Security Behavior Engine
  const behavior = raw.security_behavior_engine;
  if(behavior){
    const anomalies = behavior.report?.anomalies || [];
    const risks = behavior.report?.correlated_risks || [];
    modules.push({
      name: 'Security Behavior Engine',
      id: 'BEHAVIOR-001',
      status: behavior.success ? 'COMPLETED' : 'FAILED',
      icon: '🛡️',
      details: `
        <div class="tool-detail-row"><span class="tool-detail-key">Overall Risk</span><span class="tool-detail-val" style="color:${RISK_COLORS[behavior.report?.overall?.risk_level]||'#6b7a9c'}">${behavior.report?.overall?.risk_level || '—'}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Anomalies</span><span class="tool-detail-val">${anomalies.length}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Correlated Risks</span><span class="tool-detail-val">${risks.length}</span></div>
        <div class="tool-detail-sep">ANOMALIES</div>
        ${anomalies.map(a=>`<div class="tool-detail-row"><span class="tool-detail-key">${escapeHtml(a.title)}</span><span class="tool-detail-val" style="color:${SEV_COLORS[a.severity?.toUpperCase()]||'#6b7a9c'}">${a.severity?.toUpperCase()||'INFO'}</span></div>`).join('') || '<div class="tool-detail-row"><span class="tool-detail-key">—</span><span class="tool-detail-val">None</span></div>'}
      `
    });
  }

  // 3. robots.txt Analysis
  const robots = raw.robots_txt_analysis;
  if(robots){
    const summary = robots.summary || {};
    modules.push({
      name: 'robots.txt Analysis',
      id: 'ROBOTS-003',
      status: robots.success ? 'COMPLETED' : 'FAILED',
      icon: '🤖',
      details: `
        <div class="tool-detail-row"><span class="tool-detail-key">Found</span><span class="tool-detail-val">${robots.robots_found ? 'Yes' : 'No'}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">User-Agents</span><span class="tool-detail-val">${summary.user_agents_count ?? 0}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Disallowed</span><span class="tool-detail-val">${summary.disallowed_count ?? 0}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Allowed</span><span class="tool-detail-val">${summary.allowed_count ?? 0}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Sitemaps</span><span class="tool-detail-val">${summary.sitemaps_count ?? 0}</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Interesting</span><span class="tool-detail-val">${summary.interesting_paths_count ?? 0}</span></div>
      `
    });
  }

  // 4. Unified Assessment
  const unified = raw.unified_assessment;
  if(unified){
    modules.push({
      name: 'Unified Risk Assessment',
      id: 'UNIFIED-004',
      status: 'COMPLETED',
      icon: '⚖️',
      details: `
        <div class="tool-detail-row"><span class="tool-detail-key">Score</span><span class="tool-detail-val" style="color:${RISK_COLORS[raw.risk_level]||'#6b7a9c'}">${unified.unified_score_percent ?? 0}%</span></div>
        <div class="tool-detail-row"><span class="tool-detail-key">Rating</span><span class="tool-detail-val">${escapeHtml(unified.rating || '—')}</span></div>
        <div class="tool-detail-sep">COMPONENTS</div>
        ${Object.entries(unified.components||{}).map(([k,v])=>`<div class="tool-detail-row"><span class="tool-detail-key">${escapeHtml(k)}</span><span class="tool-detail-val">${escapeHtml(String(v))}</span></div>`).join('') || '<div class="tool-detail-row"><span class="tool-detail-key">—</span><span class="tool-detail-val">—</span></div>'}
      `
    });
  }

  list.innerHTML = modules.map(m=>`
    <div class="scan-tool-card">
      <div class="scan-tool-header">
        <div class="scan-tool-icon">${m.icon}</div>
        <div class="scan-tool-info">
          <span class="scan-tool-name">${escapeHtml(m.name)}</span>
          <span class="scan-tool-id">ID: ${escapeHtml(m.id)}</span>
        </div>
        <span class="scan-tool-status ${m.status === 'COMPLETED' ? 'ok' : 'fail'}">${m.status}</span>
      </div>
      <div class="scan-tool-body">
        ${m.details}
      </div>
    </div>
  `).join('');
}

/* ==================== INIT ==================== */
showPage('dashboard');
drawChart();
setTimeout(initSeverityPanel, 100);