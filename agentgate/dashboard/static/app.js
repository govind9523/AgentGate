'use strict';
const $ = (selector) => document.querySelector(selector);
const content = $('#content');
const views = {
  overview: ['Execution overview', 'A clear view of what your agents are allowed to do.'],
  tools: ['Tool registry', 'Explicit capabilities. Defined owners. Visible boundaries.'],
  approvals: ['Approval queue', 'Review the evidence before a sensitive action proceeds.'],
  traces: ['Execution traces', 'Follow a request from inspection to final outcome.'],
  evaluations: ['Evaluation lab', 'Measure policy behavior against repeatable security cases.'],
  harness: ['Agent harness', 'Compare the same seeded task with and without protection.'],
  research: ['Repository research', 'Read public repository evidence through the execution boundary.'],
};
let token = '';
let publicDemo = true;
let generation = 0;
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}
function button(label, action, secondary = true) {
  const node = el('button', secondary ? 'button secondary' : 'button', label);
  node.type = 'button';
  node.addEventListener('click', async () => {
    node.disabled = true;
    try { await action(); } catch (error) { status(error.message, true); }
    finally { node.disabled = false; }
  });
  return node;
}
function status(message, error = false) {
  $('#status').hidden = !message;
  $('#status').textContent = message;
  $('#status').className = error ? 'error' : '';
}
async function api(path, body) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`/api/v1${path}`, {method: body === undefined ? 'GET' : 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body)});
  let data;
  try { data = await response.json(); } catch { throw new Error(`Server returned ${response.status} without a JSON response.`); }
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${response.status}). ${JSON.stringify(data.detail || data.error || '')}`);
  return data;
}
function list(data) { return Array.isArray(data) ? data : data.items || data.runs || data.traces || data.tools || data.approvals || []; }
function json(value) { return el('pre', 'json', JSON.stringify(value, null, 2)); }
function badge(value) { const text = String(value ?? 'Unknown'); return el('span', `pill ${text.toLowerCase().replaceAll('_', '-')}`, text.replaceAll('_', ' ')); }
function empty(title, description) { const node = el('div', 'empty'); node.append(el('strong', '', title), document.createTextNode(description)); return node; }
function panel(title, subtitle, body) {
  const node = el('section', 'panel');
  const heading = el('div', 'panel-heading'); const copy = el('div');
  copy.append(el('h2', '', title)); if (subtitle) copy.append(el('p', 'panel-subtitle', subtitle));
  heading.append(copy); node.append(heading); if (body) node.append(body); return node;
}
function table(headers, rows) {
  const wrap = el('div', 'table-wrap'); const table = el('table'); const head = el('thead'); const row = el('tr');
  headers.forEach((text) => { const th = el('th', '', text); th.scope = 'col'; row.append(th); }); head.append(row); table.append(head);
  const body = el('tbody'); rows.forEach((cells) => { const tr = el('tr'); cells.forEach((value) => {const td = el('td'); td.append(value instanceof Node ? value : document.createTextNode(String(value ?? '—'))); tr.append(td);}); body.append(tr); });
  table.append(body); wrap.append(table); return wrap;
}
function fields(data) {
  const node = el('dl', 'detail-fields');
  Object.entries(data).forEach(([key, value]) => {node.append(el('dt', '', key.replaceAll('_', ' '))); const dd = el('dd'); dd.append(value !== null && typeof value === 'object' ? json(value) : document.createTextNode(String(value ?? '—'))); node.append(dd);}); return node;
}
function showDetail(title, data) {
  $('#detail-title').textContent = title;
  const target = $('#detail-content'); target.replaceChildren();
  const events = data.events || data.trajectory_events || data.trajectory;
  const summary = Object.fromEntries(Object.entries(data).filter(([key]) => !['events', 'trajectory_events', 'trajectory'].includes(key)));
  target.append(fields(summary));
  if (Array.isArray(events)) {
    const timeline = el('div', 'timeline');
    events.forEach((event, index) => {const item = el('section', 'event'); item.append(el('h3', '', `${String(index + 1).padStart(2, '0')} / ${event.event_type || event.type || event.kind || 'Event'}`), json(event)); timeline.append(item);}); target.append(timeline);
  }
  if (!$('#detail-dialog').open) $('#detail-dialog').showModal();
}
function detailLink(label, action) { const node = button(label, action); node.className = 'cell-button'; return node; }
function traceRows(traces) { return traces.map((trace) => [detailLink(trace.tool_name || trace.tool || trace.id || trace.trace_id, async () => showDetail('Execution trace', await api(`/traces/${encodeURIComponent(trace.id || trace.trace_id)}`))), badge(trace.decision), trace.actor_id || trace.actor || '—', trace.created_at ? new Date(typeof trace.created_at === 'number' ? trace.created_at * 1000 : trace.created_at).toLocaleString() : '—']); }
async function overview() {
  const data = await api('/overview'); publicDemo = data.public_demo !== false;
  $('#mode-badge').textContent = publicDemo ? 'PUBLIC DEMO' : 'OPERATOR MODE';
  $('footer span:last-child').textContent = publicDemo ? 'Isolated demo · Synthetic data' : 'Operator workspace';
  const root = el('div'); const metrics = el('div', 'metrics');
  [['Total requests', data.total_requests, data.window || 'Recorded at the execution boundary'], ['Allowed', data.counts?.ALLOW, 'Passed policy inspection'], ['Blocked', data.counts?.DENY, 'Stopped before execution'], ['Needs approval', data.counts?.REQUIRE_HUMAN_APPROVAL, 'Human review required']].forEach(([name, value, note], index) => {
    const metric = el('section', 'metric'); metric.append(el('div', 'metric-label', name), el('div', index === 2 ? 'metric-value metric-accent' : 'metric-value', value ?? '—'), el('div', 'metric-note', note)); metrics.append(metric);
  }); root.append(metrics);
  const grid = el('div', 'grid'); const left = el('div'); const right = el('div');
  const traces = data.recent_traces || [];
  left.append(panel('Recent activity', 'Decisions recorded by the runtime', traces.length ? table(['Request / tool', 'Decision', 'Actor', 'Time'], traceRows(traces)) : empty('Your execution log starts here', 'Run a scenario to inspect its decision and evidence.')));
  const blocked = traces.filter((trace) => trace.decision === 'DENY');
  left.append(panel('Recent blocked actions', 'Denied calls do not reach the tool', blocked.length ? table(['Request / tool', 'Decision', 'Actor', 'Time'], traceRows(blocked)) : empty('No blocked actions recorded', 'Denied requests appear here after a scenario runs.')));
  const findings = traces.flatMap((trace) => (trace.findings || []).map((finding) => ({trace_id: trace.id || trace.trace_id, finding})));
  left.append(panel('Inspection findings', 'Findings attached to recent traces', findings.length ? table(['Trace', 'Finding'], findings.map((item) => [detailLink(String(item.trace_id).slice(0, 12) + '…', async () => showDetail('Execution trace', await api(`/traces/${encodeURIComponent(item.trace_id)}`))), typeof item.finding === 'string' ? item.finding : `${item.finding.severity || 'Finding'} · ${item.finding.message || item.finding.category}`])) : empty('No recent findings', 'Inspection evidence will appear when it is returned by the runtime.')));
  const dark = el('section', 'dark-panel'); dark.append(el('p', 'eyebrow', 'THE EXECUTION BOUNDARY'), el('h2', '', 'Permission before action.'), el('p', '', 'Every proposed tool call passes through inspection and policy before it can execute.'));
  const flow = el('div', 'flow'); ['Inspect', 'Decide', 'Execute', 'Trace'].forEach((label, i) => {if(i) flow.append(el('b', '', '→')); flow.append(el('span', '', label));}); dark.append(flow); right.append(dark);
  const scenarios = el('div', 'panel-body');
  [['normal-read', 'A routine read', 'An allowed, low-risk lookup.'], ['high-value-refund', 'A high-value refund', 'A sensitive write that needs review.'], ['prompt-injection', 'An injected instruction', 'Untrusted content meets the boundary.'], ['cross-tenant', 'A tenant boundary', 'An attempt to access another tenant.']].forEach(([id, name, description], index) => {
    const row = el('div', 'scenario'); const copy = el('div', 'scenario-copy'); copy.append(el('strong', '', name), el('small', '', description)); row.append(el('span', 'scenario-number', `0${index + 1}`), copy, button('Run ↗', async () => {status(`Running ${name.toLowerCase()}…`); const result = await api(`/demo/${id}`, {}); await render(); showDetail(name, result);})); scenarios.append(row);
  }); right.append(panel('Try the boundary', 'Four isolated scenarios. Real policy decisions.', scenarios));
  const health = el('div', 'panel-body'); health.append(fields({average_decision_latency: !data.total_requests || data.average_latency_ms == null ? 'Not measured' : `${Number(data.average_latency_ms).toFixed(2)} ms`, latest_evaluation: data.latest_eval ? `${data.latest_eval.status || 'Recorded'} · ${data.latest_eval.metrics?.passed_cases ?? '—'}/${data.latest_eval.metrics?.total_cases ?? '—'} cases passed` : 'No evaluation has run'})); right.append(panel('Runtime evidence', 'Measured values from this workspace', health)); grid.append(left,right); root.append(grid); return root;
}
async function toolsView() {
  const items = list(await api('/tools'));
  return panel('Registered tools', `${items.length} capabilities in the registry`, items.length ? table(['Tool / version', 'Operation', 'Risk', 'Owner', 'Environment', 'Approval', 'State'], items.map((tool) => {
    const name = el('div', '', tool.name); name.append(el('small', '', tool.version || '—'));
    return [name, tool.operation, badge(tool.risk_level), tool.owner, (tool.allowed_environments || []).join(', ') || '—', tool.requires_approval ?? tool.approval_required ?? 'Policy-defined', badge(tool.enabled ? 'Enabled' : 'Disabled')];
  })) : empty('No tools registered', 'Registered capabilities will appear here.'));
}
async function approvalsView() {
  if (publicDemo) return panel('Review requests', 'Operator access is disabled in the public demo.', empty('Approval review is available in operator mode', 'Run the high-value refund scenario to inspect an approval-required decision without changing a live account.'));
  const items = list(await api('/approvals')); const body = el('div');
  if (!items.length) body.append(empty('Nothing waiting for review', 'Calls requiring human approval will appear here.'));
  items.forEach((item) => { const card = el('article', 'approval'); card.append(el('h3', '', item.tool_name || item.tool || 'Approval request'), fields(item));
    if (!publicDemo && (!item.status || item.status.toLowerCase() === 'pending')) {
      const actions = el('div', 'approval-actions'); ['approve', 'deny'].forEach((action) => actions.append(button(action === 'approve' ? 'Approve request' : 'Deny request', async () => {const result = await api(`/approvals/${encodeURIComponent(item.id || item.approval_id)}/${action}`, {}); await render(); showDetail('Approval decision', result);}, action === 'deny'))); card.append(actions);
    } body.append(card);
  }); return panel('Review requests', publicDemo ? 'Public demo is read-only. Approval decisions require operator access.' : 'Decisions are bound to the recorded request and policy.', body);
}
async function tracesView() { const items = list(await api('/traces')); return panel('Execution log', 'Select a request to inspect its complete evidence timeline', items.length ? table(['Request / tool', 'Decision', 'Actor', 'Time'], traceRows(items)) : empty('No traces yet', 'Run a scenario from Overview to create a trace.')); }
async function evaluationsView() {
  const root = el('div'); const bar = el('div', 'toolbar'); bar.append(button('Run evaluation suite ↗', async () => {status('Evaluating the dataset…'); const result = await api('/evals/runs', {}); await render(); showDetail('Evaluation report', result);}, false)); root.append(bar);
  const items = list(await api('/evals/runs'));
  root.append(panel('Evaluation runs', 'Open a report for case outcomes, failure evidence, and measured metrics', items.length ? table(['Run', 'Dataset', 'Passed', 'Failed', 'Unauthorized actions'], items.map((run) => [detailLink(run.id || run.run_id || 'View report', () => showDetail('Evaluation report', run)), run.dataset_version || '—', run.passed ?? run.pass_count ?? run.metrics?.passed_cases ?? run.metrics?.passed ?? '—', run.failed ?? run.fail_count ?? run.metrics?.failed_cases ?? run.metrics?.failed ?? '—', run.unauthorized_action_count ?? run.metrics?.unauthorized_execution_count ?? run.metrics?.unauthorized_action_count ?? '—'])) : empty('No evaluation reports yet', 'Run the suite to measure the policy against the security dataset.'))); return root;
}
async function harnessView() {
  const root = el('div'); const bar = el('div', 'toolbar'); const taskLabel = el('label', '', 'Task'); const task = el('select');
  [['refund-approval', 'Refund approval'], ['prompt-injection', 'Prompt injection'], ['allowed-read', 'Normal read'], ['cross-tenant', 'Cross-tenant attempt']].forEach(([value,text]) => {const option = el('option', '', text); option.value = value; task.append(option);}); taskLabel.append(task);
  const seedLabel = el('label', '', 'Seed'); const seed = el('input'); seed.type = 'number'; seed.value = '42'; seed.min = '0'; seed.step = '1'; seedLabel.append(seed);
  bar.append(taskLabel, seedLabel, button('Compare both modes ↗', async () => {
    if (!seed.checkValidity() || !Number.isSafeInteger(Number(seed.value))) throw new Error('Enter a whole-number seed.');
    status('Running the same seeded task in both modes…');
    const baseline = await api('/harness/runs', {task_id: task.value, mode:'baseline', seed:Number(seed.value)});
    const protectedRun = await api('/harness/runs', {task_id: task.value, mode:'protected', seed:Number(seed.value)});
    await render(); $('#detail-title').textContent = 'Same task. Same seed. Two boundaries.'; const compare = el('div', 'comparison');
    [['Baseline · sandbox only', baseline], ['Protected', protectedRun]].forEach(([title,data]) => { const column = el('section'); column.append(el('h3','',title),json(data)); compare.append(column); }); $('#detail-content').replaceChildren(compare); $('#detail-dialog').showModal();
  }, false)); root.append(bar, el('p','note','Baseline runs only against fake, isolated tools. Comparison does not enable unprotected external execution.'));
  const items = list(await api('/harness/runs'));
  root.append(panel('Harness runs', 'Inspect trajectories and verify saved evidence with strict offline replay', items.length ? table(['Run / task', 'Mode', 'Seed', 'Outcome', 'Evidence'], items.map((run) => { const id = run.id || run.run_id; return [detailLink(`${run.task_id || 'Task'} · ${String(id).slice(0,8)}`, async () => showDetail('Harness trajectory', await api(`/harness/runs/${encodeURIComponent(id)}`))), badge(run.mode === 'baseline' ? 'Baseline · sandbox' : run.mode), run.seed, badge(run.outcome ?? run.status ?? run.success ?? 'Recorded'), button('Replay', async () => showDetail('Offline replay', await api(`/harness/runs/${encodeURIComponent(id)}/replay`, {})))]; })) : empty('No trajectories recorded', 'Compare a seeded task to see proposals, decisions, side effects, and safety graders.'))); return root;
}
function sourceLink(url, label) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port || !['github.com', 'api.github.com', 'osv.dev', 'www.osv.dev', 'api.osv.dev'].includes(parsed.hostname)) throw new Error('Unsupported source');
    const link = el('a', 'source-link', label || parsed.hostname); link.href = parsed.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; return link;
  } catch { return el('span', 'note', label ? `${label} · link unavailable` : 'Source link unavailable'); }
}
function researchDetail(report) {
  $('#detail-title').textContent = `Research / ${report.repository || 'Public repository'}`;
  const root = $('#detail-content'); root.replaceChildren();
  const intro = el('div', 'research-summary'); intro.append(badge('Live internet evidence'), badge(report.status), el('p', '', report.summary || 'No summary was returned.')); root.append(intro);
  const metadata = report.repository_metadata || {};
  const header = el('div', 'research-facts');
  header.append(fields({repository: report.repository, commit: report.commit_sha, language: metadata.language, archived: metadata.archived, stars: metadata.stargazers_count, forks: metadata.forks_count, open_issues: metadata.open_issues_count, updated: metadata.updated_at, branch: metadata.default_branch}));
  header.append(el('p', 'note', `${report.mode || 'evidence'} mode · ${(report.sources || []).length} sources · ${report.metrics?.http_requests ?? '—'} requests · ${report.metrics?.duration_ms == null ? 'Duration unavailable' : (report.metrics.duration_ms / 1000).toFixed(2) + ' s'}`)); root.append(header);
  const sources = report.sources || [];

  const dependencies = report.dependencies || [];
  root.append(panel('Exact-version dependency checks', 'A bounded sample; unchecked dependencies and version ranges are not a clean bill of health.', dependencies.length ? table(['Package', 'Version / ecosystem', 'Status', 'Known vulnerabilities'], dependencies.map((dep) => {
    const issues = el('div'); (dep.vulnerabilities || []).forEach((issue) => {const item = el('div'); item.append(sourceLink(issue.url, issue.id), el('small', '', issue.summary || '')); issues.append(item);});
    if (!issues.childNodes.length) issues.append(el('span', 'note', dep.status === 'checked' ? 'None returned for this exact version' : 'Not established'));
    return [dep.name, `${dep.version || '—'} / ${dep.ecosystem || '—'}`, badge(dep.status), issues];
  })) : empty('No supported exact versions collected', 'Only supported pinned dependency formats are checked.')));
  const dependencyTable = root.querySelector('.table-wrap');
  if (dependencyTable) { dependencyTable.classList.add('dependency-table'); dependencyTable.querySelectorAll('tbody tr').forEach((row) => [...row.children].forEach((cell, index) => { cell.dataset.label = ['Package', 'Version / ecosystem', 'Status', 'Known vulnerabilities'][index]; })); }
  root.append(panel('Sources', 'Bounded samples fetched from public APIs', sources.length ? table(['Source', 'Fetched', 'Evidence'], sources.map((source) => [sourceLink(source.url, [source.source_id, source.kind].filter(Boolean).join(' · ') || 'Source'), source.fetched_at || '—', detailLink('Inspect evidence', () => showDetail('Source evidence', source))])) : empty('No sources collected', 'Read the limitations and call results below.')));
  const calls = report.calls || [];
  root.append(panel('Runtime calls', 'Inspect decisions and source-linked execution evidence', calls.length ? table(['Tool', 'Decision', 'Trace'], calls.map((call) => [call.tool_name, badge(call.decision), call.trace_id ? detailLink(String(call.trace_id).slice(0, 12) + '…', async () => showDetail('Research tool trace', await api(`/traces/${encodeURIComponent(call.trace_id)}`))) : 'Unavailable'])) : empty('No runtime calls recorded', 'Check the report limitations.')));
  if (report.model) {
    const model = el('div', 'panel-body'); model.append(badge('Unverified model narrative'), el('p', 'model-narrative', report.model.narrative || `Model status: ${report.model.status || 'unavailable'}`));
    const citations = el('div', 'source-citations'); (report.model.citations || []).forEach((id) => {const source = sources.find((item) => item.source_id === id); citations.append(source ? sourceLink(source.url, id) : el('span', 'note', `${id} · unsupported citation`));}); model.append(citations);
    root.append(panel('Optional model interpretation', 'Generated assertions are not independently verified facts.', model));
  }
  const limitations = el('ul', 'research-limitations'); (report.limitations || ['No limitations were supplied; coverage is not established.']).forEach((text) => limitations.append(el('li', '', text))); root.append(panel('Coverage and limitations', '', limitations));
  if (!$('#detail-dialog').open) $('#detail-dialog').showModal();
}
async function researchView() {
  const config = await api('/research/config'); const root = el('div');
  const banner = el('div', 'research-banner'); banner.append(badge('Live internet'), el('p', '', 'This view reads a public GitHub repository and queries OSV through AgentGate. It does not execute repository code. The synthetic harness remains a separate, network-free experiment.')); root.append(banner);
  if (!config.enabled) root.append(panel('Research is disabled', '', empty('Enable public repository research on the server', 'No external requests are made from this view while the feature is disabled.')));
  else {
    const form = el('form', 'toolbar research-form'); const label = el('label', '', 'Public GitHub repository'); const repository = el('input'); repository.type = 'text'; repository.required = true; repository.placeholder = 'owner/repository'; repository.maxLength = 160; repository.autocomplete = 'off'; repository.pattern = '[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'; label.append(repository);
    const modeLabel = el('label', '', 'Analysis mode'); const mode = el('select'); const evidence = el('option', '', 'Evidence only'); evidence.value = 'evidence'; mode.append(evidence);
    const model = el('option', '', 'Model narrative · unverified'); model.value = 'model'; model.disabled = !config.model_available || publicDemo; mode.append(model); modeLabel.append(mode);
    const run = el('button', 'button', 'Research repository ↗'); run.type = 'submit'; form.append(label, modeLabel, run);
    form.addEventListener('submit', async (event) => {event.preventDefault(); if (!form.reportValidity()) return; run.disabled = true; status('Collecting bounded public evidence…'); try {const report = await api('/research/runs', {repository:repository.value.trim(),mode:mode.value}); await render(); researchDetail(report);} catch(error) {status(error.message,true);} finally {run.disabled = false;}}); root.append(form);
    root.append(el('p', 'note', config.model_available && !publicDemo ? 'Model mode uses the server-configured provider. Treat its narrative as unverified and inspect the cited evidence.' : 'Evidence mode needs no model credentials. Hosted model mode requires operator access and a configured server key; it never silently substitutes a scripted model.'));
  }
  if (config.enabled) {
    const reports = list(await api('/research/runs'));
    root.append(panel('Research reports', 'Public evidence with recorded sources, omissions, and runtime traces', reports.length ? table(['Repository', 'Mode', 'Status', 'Dependencies checked'], reports.map((report) => [detailLink(report.repository || report.run_id, async () => researchDetail(await api(`/research/runs/${encodeURIComponent(report.run_id)}`))), report.mode, badge(report.status), report.metrics?.dependencies_checked ?? '—'])) : empty('No repository reports yet', 'Enter a public owner/repository to collect evidence.')));
  }
  return root;
}
async function render() {
  const current = ++generation; const view = location.hash.slice(1) in views ? location.hash.slice(1) : 'overview';
  $('#page-title').textContent = views[view][0]; $('#page-description').textContent = views[view][1]; $('#breadcrumb').textContent = view === 'tools' ? 'Tool registry' : views[view][0]; $('#section-number').textContent = String(Object.keys(views).indexOf(view) + 1).padStart(2,'0');
  document.querySelectorAll('[data-view]').forEach((link) => {link.classList.toggle('active',link.dataset.view === view); if(link.dataset.view === view) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current');});
  content.setAttribute('aria-busy','true'); content.replaceChildren(el('div','loading','Loading workspace evidence…')); status('');
  try {
    if (view !== 'overview') { const data = await api('/overview'); publicDemo = data.public_demo !== false; $('#mode-badge').textContent = publicDemo ? 'PUBLIC DEMO' : 'OPERATOR MODE'; }
    const node = await ({overview,tools:toolsView,approvals:approvalsView,traces:tracesView,evaluations:evaluationsView,harness:harnessView,research:researchView})[view]();
    if(current === generation) { content.replaceChildren(node); $('footer span:last-child').textContent = view === 'research' ? 'Public internet evidence · Read-only adapters' : publicDemo ? 'Isolated demo · Synthetic data' : 'Operator workspace'; $('.workspace small').textContent = view === 'research' ? 'Public repository evidence' : 'Deterministic sandbox'; }
  } catch (error) { if(current === generation) {status(error.message,true); content.replaceChildren(empty('Workspace data is unavailable', 'Check the connection or operator credentials, then refresh.'));} }
  finally {if(current === generation) content.setAttribute('aria-busy','false');}
}
$('#refresh-button').addEventListener('click', render);
$('#close-detail').addEventListener('click', () => $('#detail-dialog').close());
$('#access-button').addEventListener('click', () => {const panel = $('#access-panel'); panel.hidden = !panel.hidden; $('#access-button').setAttribute('aria-expanded', String(!panel.hidden)); if (!panel.hidden) $('#operator-token').focus();});
$('#apply-token').addEventListener('click', () => {token = $('#operator-token').value.trim(); $('#operator-token').value = ''; $('#access-panel').hidden = true; $('#access-button').setAttribute('aria-expanded','false'); render();});
$('#clear-token').addEventListener('click', () => {token = ''; $('#operator-token').value = ''; render();});
window.addEventListener('hashchange', render);
render();
