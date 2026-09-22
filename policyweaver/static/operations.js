'use strict';
const el = id => document.getElementById(id);
const number = value => new Intl.NumberFormat().format(value ?? 0);
const date = value => new Date(value * 1000).toLocaleString();
let state;
function paint(data) {
  state = data;
  el('alert').className = 'notice';
  if (!data.configured) {
    el('alert').textContent = data.error || 'Configure an environment to begin. This console does not grant access or publish policies.';
    return;
  }
  el('alert').textContent = 'Native serving requires verified consumer identity, SQL access mode and revocation tests. The watchdog must run independently; OneLake policies do not expire on their own.';
  el('environment').textContent = data.environment;
  el('deployment').textContent = data.deployment;
  const latest = data.runs[0];
  el('readers').textContent = latest?.summary?.reader_count != null ? number(latest.summary.reader_count) : data.discover_readers ? 'Discover' : number(data.configured_readers);
  el('reader-limit').textContent = `Up to ${number(data.maximum_readers)} readers · ${data.tables.length} selected tables`;
  el('shards').textContent = number(Object.keys(data.serving_items).length);
  el('quota').textContent = `${number(data.role_limit)} roles/item · ${data.reserved_roles} reserved`;
  el('rows').textContent = latest?.summary?.total_rows != null ? number(latest.summary.total_rows) : '—';
  el('run-count').textContent = `${data.runs.length} recent runs`;
  el('empty').hidden = data.runs.length > 0;
  el('runs').replaceChildren();
  data.runs.forEach(run => {
    const tr = document.createElement('tr');
    const id = document.createElement('td'); id.textContent = String(run.generation);
    const started = document.createElement('small'); started.textContent = date(run.started); id.append(started); tr.append(id);
    for (const key of ['reader_count','total_rows']) { const td = document.createElement('td'); td.textContent = run.summary[key] == null ? '—' : number(run.summary[key]); tr.append(td); }
    const td = document.createElement('td'); const badge = document.createElement('span');
    badge.className = `pill state-${run.status}`; badge.textContent = run.status.replaceAll('_',' '); td.append(badge);
    if (run.error_code) { const error = document.createElement('small'); error.textContent = run.error_code; td.append(error); }
    tr.append(td); el('runs').append(tr);
  });
  el('updated').textContent = `Updated ${date(data.server_time)}`;
  tick();
}
function tick() {
  if (!state?.active) { el('freshness').textContent = 'Inactive'; return; }
  const remaining = Math.floor(state.active.expires - Date.now()/1000);
  if (state.active.summary?.retention_mode === 'manual') {
    el('freshness').textContent = 'Manual retention';
    el('alert').className = 'notice';
    el('alert').textContent = 'This generation uses manual retention. With matching watchdog configuration, roles remain until explicitly withdrawn or replaced; security changes require a new publication.' +
      (remaining <= 0 ? ' Its source snapshot is past the publication freshness deadline.' : ' The source freshness deadline does not automatically remove these roles.');
    return;
  }
  el('freshness').textContent = remaining > 0 ? `${Math.floor(remaining/60)}m ${remaining%60}s` : 'Expired';
  if (remaining <= 0) { el('alert').className = 'notice error'; el('alert').textContent = 'The active generation is stale. Verify withdrawal immediately. A local timer does not revoke native Fabric access.'; }
}
async function refresh() {
  el('refresh').disabled = true;
  try { const response = await fetch('/api/adapter/status', {cache:'no-store'}); const data = await response.json(); paint(data); }
  catch { el('alert').className = 'notice error'; el('alert').textContent = 'The local journal is unavailable. Refresh failed; do not infer that previously published permissions were withdrawn.'; }
  finally { el('refresh').disabled = false; }
}
el('refresh').addEventListener('click', refresh);
refresh(); setInterval(refresh, 15000); setInterval(tick, 1000);
