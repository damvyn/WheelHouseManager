(function () {
  'use strict';

  // ---------------------------------------------------------------- session
  var params = new URLSearchParams(location.search);
  var token = params.get('t');
  try {
    if (token) { sessionStorage.setItem('whm-token', token); }
    else { token = sessionStorage.getItem('whm-token'); }
  } catch (e) { /* storage blocked: the token stays in memory only */ }
  if (params.has('t')) { history.replaceState(null, '', location.pathname + location.hash); }

  function api(method, path, body) {
    var opts = { method: method, headers: { 'X-Wheelhouse-Token': token || '' } };
    if (method !== 'GET') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body || {});
    }
    return fetch(path, opts).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (!res.ok) {
          var message = (data && data.error) || text || (res.status + ' ' + res.statusText);
          if (res.status === 401) { message = 'The session token is missing or wrong. Open the address printed by Start-WheelhouseUI.ps1 again.'; }
          throw new Error(message);
        }
        return data;
      });
    });
  }

  // ---------------------------------------------------------------- helpers
  function h(tag, attrs) {
    var el = document.createElement(tag);
    var a = attrs || {};
    Object.keys(a).forEach(function (k) {
      var v = a[k];
      if (k === 'class') { el.className = v; }
      else if (k.indexOf('on') === 0) { el.addEventListener(k.slice(2), v); }
      else if (k === 'value') { el.value = v; }
      else if (v === true) { el.setAttribute(k, ''); }
      else if (v !== false && v !== null && v !== undefined) { el.setAttribute(k, v); }
    });
    var kids = Array.prototype.slice.call(arguments, 2);
    (function add(list) {
      list.forEach(function (kid) {
        if (kid === null || kid === undefined || kid === false) { return; }
        if (Array.isArray(kid)) { add(kid); return; }
        el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
      });
    })(kids);
    return el;
  }
  function $(id) { return document.getElementById(id); }
  function clear(el) { while (el.firstChild) { el.removeChild(el.firstChild); } }
  function badge(text, kind, title) {
    return h('span', { class: 'badge' + (kind ? ' ' + kind : ''), title: title || null }, text);
  }
  function fmtBytes(n) {
    if (n === null || n === undefined) { return ''; }
    if (n < 1024) { return n + ' B'; }
    if (n < 1048576) { return (n / 1024).toFixed(0) + ' KB'; }
    return (n / 1048576).toFixed(1) + ' MB';
  }
  function fmtDate(s) {
    if (!s) { return ''; }
    var d = new Date(s);
    return isNaN(d.getTime()) ? s : d.toLocaleString();
  }
  function toast(message, kind) {
    var el = h('div', { class: 'toast ' + (kind || 'ok') }, message);
    $('toasts').append(el);
    setTimeout(function () { el.remove(); }, kind === 'bad' ? 9000 : 4500);
  }
  function fail(err) { toast(err.message || String(err), 'bad'); }
  function pinKey(p) { return p.name + '==' + p.version; }

  function confirmDialog(title, bodyNodes, okLabel, danger) {
    return new Promise(function (resolve) {
      var dlg = $('dialog');
      clear(dlg);
      var ok = h('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), type: 'button' }, okLabel);
      var cancel = h('button', { class: 'btn', type: 'button' }, 'Cancel');
      var result = false;
      ok.addEventListener('click', function () { result = true; dlg.close(); });
      cancel.addEventListener('click', function () { dlg.close(); });
      dlg.append(h('h3', {}, title), bodyNodes, h('div', { class: 'actions' }, cancel, ok));
      dlg.onclose = function () { resolve(result); };
      dlg.showModal();
    });
  }

  // ---------------------------------------------------------------- state
  var state = {
    info: null,
    pkgs: [],
    groups: [],
    untracked: [],
    selected: {},
    filter: '',
    statusFilter: 'all',
    settings: null,
    currentTab: 'packages',
    watchedJob: null,
    pollTimer: null
  };

  // ---------------------------------------------------------------- header / tabs
  function renderStatus() {
    var box = $('status');
    clear(box);
    var info = state.info;
    if (!info) { return; }
    box.append(
      h('span', { class: 'mono' }, info.wheelhouse_path || '(wheelhouse folder not set)'),
      badge('Python ' + info.python_version + ' / ' + info.platform),
      info.defender ? badge('Defender available', 'ok') : badge('Defender not available', 'warn'),
      info.is_admin ? badge('elevated', 'ok') : badge('not elevated', 'warn', 'Defender scans need an elevated PowerShell')
    );
    var banner = $('banner');
    if (!info.configured) {
      banner.textContent = 'The wheelhouse folder is not set. Open the Settings tab and enter it.';
      banner.className = 'banner bad';
    } else if (!info.reachable) {
      banner.textContent = 'The wheelhouse folder does not exist or is not reachable: ' + info.wheelhouse_path;
      banner.className = 'banner bad';
    } else {
      banner.className = 'banner hidden';
    }
  }

  function showTab(name) {
    state.currentTab = name;
    Array.prototype.forEach.call(document.querySelectorAll('#tabs button'), function (b) {
      b.classList.toggle('active', b.getAttribute('data-tab') === name);
    });
    Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (s) {
      s.classList.toggle('hidden', s.id !== 'tab-' + name);
    });
    var loaders = {
      packages: loadPackages, add: renderAdd, quarantine: loadQuarantine,
      denylist: loadDenylist, settings: loadSettings, jobs: loadJobs
    };
    loaders[name]();
  }

  // ---------------------------------------------------------------- packages tab
  function loadPackages() {
    return api('GET', '/api/packages').then(function (data) {
      state.pkgs = data.packages.map(function (p) {
        p.groups = [].concat(p.groups || []);
        p.vulnerabilities = [].concat(p.vulnerabilities || []);
        return p;
      });
      state.groups = data.groups;
      state.untracked = data.untracked;
      var present = {};
      state.pkgs.forEach(function (p) { present[pinKey(p)] = true; });
      Object.keys(state.selected).forEach(function (k) { if (!present[k]) { delete state.selected[k]; } });
      renderPackages();
    }).catch(function (err) {
      clear($('tab-packages'));
      $('tab-packages').append(h('div', { class: 'empty' }, err.message));
    });
  }

  function visiblePackages() {
    var text = state.filter.trim().toLowerCase();
    return state.pkgs.filter(function (p) {
      if (text && (p.name + ' ' + p.version + ' ' + p.file + ' ' + p.groups.join(' ')).toLowerCase().indexOf(text) < 0) { return false; }
      switch (state.statusFilter) {
        case 'vulnerable': return p.audit_status === 'Vulnerable';
        case 'threat': return p.scan_status === 'Threat';
        case 'unaudited': return p.audit_status === 'Unknown';
        case 'unscanned': return p.scan_status === 'Unknown';
        case 'denylisted': return p.denylisted !== null;
        case 'missing': return p.file_missing;
        default: return true;
      }
    });
  }

  function selectedPins() {
    var seen = {};
    var pins = [];
    state.pkgs.forEach(function (p) {
      var k = pinKey(p);
      if (state.selected[k] && !seen[k]) { seen[k] = true; pins.push({ name: p.name, version: p.version }); }
    });
    return pins;
  }
  function selectedFiles() {
    return state.pkgs.filter(function (p) { return state.selected[pinKey(p)]; }).map(function (p) { return p.file; });
  }

  function renderPackages() {
    var root = $('tab-packages');
    clear(root);
    var visible = visiblePackages();
    var pins = selectedPins();
    var none = pins.length === 0;

    var filter = h('input', { type: 'text', placeholder: 'Filter by name, version, group...', value: state.filter });
    filter.addEventListener('input', function () {
      state.filter = filter.value;
      renderPackages();
      var again = $('tab-packages').querySelector('input[type=text]');
      again.focus();
      again.setSelectionRange(again.value.length, again.value.length);
    });
    var statusFilter = h('select', {},
      [['all', 'All packages'], ['vulnerable', 'Vulnerable'], ['threat', 'Defender threat'], ['unaudited', 'Never audited'],
        ['unscanned', 'Never scanned'], ['denylisted', 'On the denylist'], ['missing', 'File missing']].map(function (o) {
        return h('option', { value: o[0], selected: state.statusFilter === o[0] }, o[1]);
      }));
    statusFilter.addEventListener('change', function () { state.statusFilter = statusFilter.value; renderPackages(); });

    var toolbar = h('div', { class: 'toolbar' },
      h('div', { class: 'group' }, filter, statusFilter, h('button', { class: 'btn', type: 'button', onclick: loadPackages }, 'Refresh')),
      h('div', { class: 'group' },
        h('button', { class: 'btn', type: 'button', disabled: none, onclick: function () { runAudit(false); } }, 'Audit selected'),
        h('button', { class: 'btn', type: 'button', onclick: function () { runAudit(true); } }, 'Audit all')),
      h('div', { class: 'group' },
        h('button', { class: 'btn', type: 'button', disabled: none, onclick: function () { runScan(false); } }, 'Scan selected'),
        h('button', { class: 'btn', type: 'button', onclick: function () { runScan(true); } }, 'Scan all')),
      h('div', { class: 'group' },
        h('button', { class: 'btn', type: 'button', disabled: none, onclick: function () { removeSelected('quarantine'); } }, 'Quarantine'),
        h('button', { class: 'btn danger', type: 'button', disabled: none, onclick: function () { removeSelected('delete'); } }, 'Delete')),
      h('span', { class: 'muted' }, pins.length + ' selected / ' + visible.length + ' shown / ' + state.pkgs.length + ' files'));
    root.append(toolbar);

    if (state.info && (!state.info.defender || !state.info.is_admin)) {
      root.append(h('div', { class: 'banner' }, 'Defender scans need Microsoft Defender and an elevated PowerShell (Run as administrator) for Start-WheelhouseUI.ps1.'));
    }
    if (state.untracked.length > 0) {
      root.append(h('div', { class: 'banner' },
        state.untracked.length + ' wheel file(s) are in the folder but not tracked by manifest.json (never added by this tool): ' + state.untracked.join(', ')));
    }

    if (visible.length === 0) {
      root.append(h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, state.pkgs.length === 0 ? 'The wheelhouse has no tracked packages yet. Use "Add packages".' : 'Nothing matches the filter.')));
      return;
    }

    var allBox = h('input', { type: 'checkbox', title: 'Select all shown', checked: visible.every(function (p) { return state.selected[pinKey(p)]; }) });
    allBox.addEventListener('change', function () {
      visible.forEach(function (p) { if (allBox.checked) { state.selected[pinKey(p)] = true; } else { delete state.selected[pinKey(p)]; } });
      renderPackages();
    });

    var rows = visible.map(function (p) {
      var k = pinKey(p);
      var box = h('input', { type: 'checkbox', checked: !!state.selected[k] });
      box.addEventListener('change', function () {
        if (box.checked) { state.selected[k] = true; } else { delete state.selected[k]; }
        renderPackages();
      });
      var auditCell = p.audit_status === 'Vulnerable'
        ? badge('Vulnerable', 'bad', p.vulnerabilities.join(', '))
        : p.audit_status === 'Passed' ? badge('Passed', 'ok', 'Last audit ' + p.last_audit) : badge('Not audited');
      var scanCell = p.scan_status === 'Threat'
        ? badge('Threat', 'bad')
        : p.scan_status === 'Clean' ? badge('Clean', 'ok', 'Last scan ' + p.last_scan) : badge('Not scanned');
      return h('tr', { class: state.selected[k] ? 'selected' : '' },
        h('td', {}, box),
        h('td', {}, h('strong', {}, p.name), p.file_missing ? [' ', badge('file missing', 'bad')] : null),
        h('td', { class: 'mono' }, p.version),
        h('td', {}, p.groups.length ? p.groups.join(', ') : h('span', { class: 'muted' }, 'not listed')),
        h('td', {}, auditCell, p.vulnerabilities.length ? h('div', { class: 'mono muted' }, p.vulnerabilities.join(', ')) : null),
        h('td', {}, scanCell),
        h('td', {}, p.denylisted !== null ? badge('blocked', 'warn', p.denylisted) : ''),
        h('td', {}, fmtDate(p.downloaded_utc)),
        h('td', { class: 'num' }, fmtBytes(p.size_bytes)),
        h('td', { class: 'mono' }, p.file));
    });
    root.append(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, allBox), h('th', {}, 'Package'), h('th', {}, 'Version'), h('th', {}, 'Groups'),
        h('th', {}, 'Audit'), h('th', {}, 'Defender'), h('th', {}, 'Denylist'), h('th', {}, 'Downloaded'), h('th', {}, 'Size'), h('th', {}, 'File'))),
      h('tbody', {}, rows))));
  }

  function startJobRequest(promise) {
    return promise.then(function (data) {
      if (data.job) { watchJob(data.job.id); }
      return data;
    }).catch(fail);
  }
  function runAudit(all) {
    var body = all ? { all: true } : { packages: selectedPins() };
    startJobRequest(api('POST', '/api/packages/audit', body));
  }
  function runScan(all) {
    var body = all ? { all: true } : { files: selectedFiles() };
    startJobRequest(api('POST', '/api/packages/scan', body));
  }

  function removeSelected(mode) {
    var pins = selectedPins();
    if (pins.length === 0) { return; }
    var reason = h('input', { type: 'text', class: 'wide', placeholder: 'Reason (optional, kept in the denylist and quarantine log)' });
    var understand = h('input', { type: 'checkbox' });
    var list = h('ul', {}, pins.map(function (p) { return h('li', { class: 'mono' }, pinKey(p)); }));
    var nodes = h('div', {},
      h('p', {}, mode === 'quarantine'
        ? 'The pins are removed from the group files and the manifest, and the wheel files are moved to the _quarantine folder. They can be restored later.'
        : 'The pins are removed from the group files and the manifest, and the wheel files are DELETED. This cannot be undone.'),
      h('p', {}, 'Each version is also added to the denylist, so the next update will not download it again.'),
      list, reason,
      mode === 'delete' ? h('p', {}, h('label', {}, understand, ' I understand the files will be deleted permanently')) : null);
    confirmDialog((mode === 'quarantine' ? 'Quarantine ' : 'Delete ') + pins.length + ' package(s)?', nodes,
      mode === 'quarantine' ? 'Quarantine' : 'Delete', mode === 'delete').then(function (ok) {
      if (!ok) { return; }
      if (mode === 'delete' && !understand.checked) { toast('Tick the confirmation box to delete.', 'bad'); return; }
      api('POST', '/api/packages/remove', { packages: pins, mode: mode, reason: reason.value, confirm: mode === 'delete' }).then(function (data) {
        var failed = data.results.filter(function (r) { return !r.ok; });
        var done = data.results.length - failed.length;
        if (done > 0) { toast(done + ' package(s) ' + (mode === 'quarantine' ? 'quarantined' : 'deleted') + '.'); }
        failed.forEach(function (r) { toast(r.name + '==' + r.version + ': ' + r.error, 'bad'); });
        state.selected = {};
        loadPackages();
      }).catch(fail);
    });
  }

  // ---------------------------------------------------------------- add tab
  function renderAdd() {
    var root = $('tab-add');
    clear(root);
    var specs = h('textarea', { placeholder: 'numpy\npandas>=2.0\nrequests==2.32.3' });
    var resolveOnly = h('input', { type: 'checkbox' });
    var output = h('div', {});
    var go = h('button', { class: 'btn primary', type: 'button' }, 'Add and process');
    go.addEventListener('click', function () {
      var list = specs.value.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(function (s) { return s && s.charAt(0) !== '#'; });
      if (list.length === 0) { toast('Enter at least one package.', 'bad'); return; }
      api('POST', '/api/packages/add', { specs: list, resolve_only: resolveOnly.checked }).then(function (data) {
        clear(output);
        if (data.added.length) {
          output.append(h('p', {}, 'Added to requirements.in:'), h('ul', { class: 'result-list' }, data.added.map(function (a) { return h('li', { class: 'mono' }, a); })));
        }
        if (data.skipped.length) {
          output.append(h('p', {}, 'Not added:'), h('ul', { class: 'result-list' }, data.skipped.map(function (s) { return h('li', { class: 'bad' }, h('span', { class: 'mono' }, s.Spec), ' - ', s.Reason); })));
        }
        if (data.job) { specs.value = ''; watchJob(data.job.id); }
      }).catch(fail);
    });
    root.append(
      h('div', { class: 'card' },
        h('h2', {}, 'Add packages to the wheelhouse'),
        h('p', { class: 'muted' }, 'One requirement per line, for example numpy or pandas>=2.0. The names go into requirements.in; then Update-Requirement.ps1 resolves them (with the cooldown) and Update-Wheelhouse.ps1 audits, checks the age of and downloads every new package. A package that fails any check is rejected with the reason and never reaches the wheelhouse.'),
        specs,
        h('p', {}, h('label', {}, resolveOnly, ' Resolve only: stop after requirements.txt so it can be reviewed first (nothing is downloaded)')),
        h('div', { class: 'toolbar' }, go)),
      output,
      h('div', { class: 'card', id: 'rejected-card' }));
    loadRejected();
  }

  function loadRejected() {
    api('GET', '/api/rejected').then(function (data) {
      var card = $('rejected-card');
      if (!card) { return; }
      clear(card);
      card.append(h('h2', {}, 'Latest rejected packages'));
      if (!data.file || data.items.length === 0) {
        card.append(h('p', { class: 'muted' }, 'No package was rejected in the latest update.'));
        return;
      }
      card.append(h('p', { class: 'muted' }, 'From ' + data.file),
        h('div', { class: 'table-wrap' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Package'), h('th', {}, 'Group'), h('th', {}, 'Reason'))),
          h('tbody', {}, data.items.map(function (r) {
            return h('tr', {}, h('td', { class: 'mono' }, r.Package + '==' + r.Version), h('td', {}, r.Group), h('td', {}, r.Reason));
          })))));
    }).catch(function () { /* the card stays empty */ });
  }

  // ---------------------------------------------------------------- quarantine tab
  function loadQuarantine() {
    var root = $('tab-quarantine');
    api('GET', '/api/quarantine').then(function (data) {
      data.items.forEach(function (q) { q.files = [].concat(q.files || []); q.groups = [].concat(q.groups || []); });
      clear(root);
      root.append(h('div', { class: 'card' }, h('h2', {}, 'Quarantined packages'),
        h('p', { class: 'muted' }, 'Wheel files moved out of the wheelhouse. Restoring checks the file hash and puts the package back into the manifest and its group files; it also lifts the denylist entry that quarantining created. Audit it again before clients use it.')));
      if (data.items.length === 0) {
        root.append(h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, 'Nothing is in quarantine.')));
        return;
      }
      root.append(h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Package'), h('th', {}, 'Files'), h('th', {}, 'Groups'), h('th', {}, 'Reason'), h('th', {}, 'When / who'), h('th', {}, ''))),
        h('tbody', {}, data.items.map(function (q) {
          var restore = h('button', { class: 'btn small', type: 'button' }, 'Restore');
          restore.addEventListener('click', function () {
            confirmDialog('Restore ' + q.name + '==' + q.version + '?', h('p', {}, 'The package goes back into the wheelhouse and its group files. The denylist entry created by quarantining is removed.'), 'Restore', false).then(function (ok) {
              if (!ok) { return; }
              api('POST', '/api/quarantine/restore', { id: q.id }).then(function () { toast('Restored ' + q.name + '==' + q.version + '.'); loadQuarantine(); }).catch(fail);
            });
          });
          return h('tr', {}, h('td', { class: 'mono' }, q.name + '==' + q.version), h('td', { class: 'mono' }, q.files.join(', ')),
            h('td', {}, q.groups.join(', ')), h('td', {}, q.reason), h('td', {}, fmtDate(q.quarantined_utc), h('div', { class: 'muted' }, q.quarantined_by)), h('td', {}, restore));
        })))));
    }).catch(function (err) { clear(root); root.append(h('div', { class: 'empty' }, err.message)); });
  }

  // ---------------------------------------------------------------- denylist tab
  function loadDenylist() {
    var root = $('tab-denylist');
    api('GET', '/api/denylist').then(function (data) {
      clear(root);
      var name = h('input', { type: 'text', placeholder: 'package name' });
      var version = h('input', { type: 'text', placeholder: 'version or *', value: '*' });
      var reason = h('input', { type: 'text', placeholder: 'reason (optional)', class: 'wide' });
      var add = h('button', { class: 'btn primary', type: 'button' }, 'Add to denylist');
      add.addEventListener('click', function () {
        api('POST', '/api/denylist/add', { name: name.value.trim(), version: version.value.trim() || '*', reason: reason.value }).then(function () {
          toast('Added to the denylist.');
          loadDenylist();
        }).catch(fail);
      });
      root.append(h('div', { class: 'card' },
        h('h2', {}, 'Denylist'),
        h('p', { class: 'muted' }, 'Blocked packages are rejected at intake and never downloaded; versions listed here are also excluded when requirements.in is resolved. Use * to block every version of a package. Packages that you delete or quarantine are added here automatically.'),
        h('div', { class: 'toolbar' }, name, version, reason, add)));

      if (data.items.length === 0) {
        root.append(h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, 'The denylist is empty.')));
        return;
      }
      root.append(h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Package'), h('th', {}, 'Version'), h('th', {}, 'Reason'), h('th', {}, 'Source'), h('th', {}, 'Added'), h('th', {}, ''))),
        h('tbody', {}, data.items.map(function (e) {
          var remove = h('button', { class: 'btn small', type: 'button' }, 'Remove');
          remove.addEventListener('click', function () {
            api('POST', '/api/denylist/remove', { name: e.name, version: e.version }).then(function () { toast('Removed from the denylist.'); loadDenylist(); }).catch(fail);
          });
          return h('tr', {}, h('td', {}, h('strong', {}, e.name), e.installed ? [' ', badge('still in wheelhouse', 'warn', 'Quarantine or delete it on the Packages tab')] : null),
            h('td', { class: 'mono' }, e.version), h('td', {}, e.reason), h('td', {}, badge(e.source)),
            h('td', {}, fmtDate(e.added_utc), h('div', { class: 'muted' }, e.added_by)), h('td', {}, remove));
        })))));
    }).catch(function (err) { clear(root); root.append(h('div', { class: 'empty' }, err.message)); });
  }

  // ---------------------------------------------------------------- settings tab
  function loadSettings() {
    var root = $('tab-settings');
    api('GET', '/api/settings').then(function (data) {
      clear(root);
      var inputs = {};
      var card = h('div', { class: 'card' }, h('h2', {}, 'Settings'),
        h('p', { class: 'muted' }, 'Stored in config\\settings.psd1. Scripts started from the UI use the saved values; an explicit parameter on a manual run still wins.'));
      data.fields.forEach(function (f) {
        var value = data.values[f.key];
        var control;
        if (f.type === 'choice') {
          control = h('select', {}, f.options.map(function (o) { return h('option', { value: o, selected: o === value }, o); }));
          inputs[f.key] = function () { return control.value; };
        } else if (f.type === 'multichoice') {
          var current = Array.isArray(value) ? value : [value];
          var boxes = f.options.map(function (o) { return { option: o, box: h('input', { type: 'checkbox', checked: current.indexOf(o) >= 0 }) }; });
          control = h('div', { class: 'checks' }, boxes.map(function (b) { return h('label', {}, b.box, ' ' + b.option); }));
          inputs[f.key] = function () { return boxes.filter(function (b) { return b.box.checked; }).map(function (b) { return b.option; }); };
        } else if (f.type === 'int') {
          control = h('input', { type: 'number', min: f.min, max: f.max, value: value });
          inputs[f.key] = function () { return control.value === '' ? '' : Number(control.value); };
        } else {
          control = h('input', { type: 'text', class: 'wide', value: value === null || value === undefined ? '' : value });
          inputs[f.key] = function () { return control.value; };
        }
        card.append(h('div', { class: 'field' }, h('label', {}, f.label), h('div', {}, control, h('div', { class: 'help' }, f.help))));
      });
      var save = h('button', { class: 'btn primary', type: 'button' }, 'Save settings');
      save.addEventListener('click', function () {
        var updates = {};
        data.fields.forEach(function (f) {
          var now = inputs[f.key]();
          var before = data.values[f.key];
          if (JSON.stringify(now) !== JSON.stringify(Array.isArray(before) ? before : (f.type === 'int' ? Number(before) : (before === null || before === undefined ? '' : before)))) {
            updates[f.key] = now;
          }
        });
        if (Object.keys(updates).length === 0) { toast('Nothing changed.'); return; }
        api('POST', '/api/settings', { updates: updates }).then(function (res) {
          toast('Saved: ' + res.saved.join(', '));
          refreshState().then(loadSettings);
        }).catch(fail);
      });
      card.append(h('div', { class: 'toolbar' }, save));
      root.append(card);
    }).catch(function (err) { clear(root); root.append(h('div', { class: 'empty' }, err.message)); });
  }

  // ---------------------------------------------------------------- jobs
  function jobBadge(job) {
    var kind = job.status === 'Succeeded' ? 'ok' : job.status === 'Running' ? 'warn' : 'bad';
    var label = job.status === 'Failed' ? 'Finished with problems' : job.status;
    return badge(label, kind, job.message);
  }

  function loadJobs() {
    var root = $('tab-jobs');
    api('GET', '/api/jobs').then(function (data) {
      clear(root);
      if (data.jobs.length === 0) {
        root.append(h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, 'No job has run in this session yet.')));
        return;
      }
      root.append(h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, '#'), h('th', {}, 'Job'), h('th', {}, 'Status'), h('th', {}, 'Started'), h('th', {}, 'Ended'), h('th', {}, ''))),
        h('tbody', {}, data.jobs.map(function (j) {
          return h('tr', {}, h('td', {}, j.id), h('td', {}, j.title), h('td', {}, jobBadge(j)), h('td', {}, fmtDate(j.started_utc)), h('td', {}, fmtDate(j.ended_utc)),
            h('td', {}, h('button', { class: 'btn small', type: 'button', onclick: function () { watchJob(j.id); } }, 'Open log')));
        })))));
    }).catch(function (err) { clear(root); root.append(h('div', { class: 'empty' }, err.message)); });
  }

  function watchJob(id) {
    if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
    state.watchedJob = id;
    $('jobbar').classList.remove('hidden');
    $('jobbar-log').classList.remove('collapsed');
    $('jobbar-toggle').textContent = 'Hide log';
    pollJob(true);
  }

  function pollJob(first) {
    var id = state.watchedJob;
    if (id === null) { return; }
    api('GET', '/api/jobs/' + id).then(function (data) {
      if (state.watchedJob !== id) { return; }
      var job = data.job;
      $('jobbar-title').textContent = '#' + job.id + '  ' + job.title + (job.steps > 1 ? '  (step ' + job.step + '/' + job.steps + ')' : '');
      var state_ = $('jobbar-state');
      state_.textContent = job.status === 'Failed' ? 'Finished with problems' : job.status;
      state_.className = 'badge ' + (job.status === 'Succeeded' ? 'ok' : job.status === 'Running' ? 'warn' : 'bad');
      $('jobbar-cancel').classList.toggle('hidden', job.status !== 'Running');
      var log = $('jobbar-log');
      var atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
      log.textContent = job.log || '';
      if (atBottom || first) { log.scrollTop = log.scrollHeight; }

      if (job.status === 'Running') {
        state.pollTimer = setTimeout(function () { pollJob(false); }, 1500);
      } else {
        state.pollTimer = null;
        if (!first) { toast(job.title + ': ' + (job.status === 'Succeeded' ? 'finished.' : job.message), job.status === 'Succeeded' ? 'ok' : 'bad'); }
        onJobFinished(job);
      }
    }).catch(function (err) {
      $('jobbar-state').textContent = 'lost';
      toast(err.message, 'bad');
    });
  }

  function onJobFinished(job) {
    if (state.currentTab === 'packages') { loadPackages(); }
    else if (state.currentTab === 'jobs') { loadJobs(); }
    else if (state.currentTab === 'add') { loadRejected(); }
    refreshState();
  }

  // ---------------------------------------------------------------- start up
  function refreshState() {
    return api('GET', '/api/state').then(function (info) {
      state.info = info;
      renderStatus();
      return info;
    }).catch(fail);
  }

  function init() {
    Array.prototype.forEach.call(document.querySelectorAll('#tabs button'), function (b) {
      b.addEventListener('click', function () { showTab(b.getAttribute('data-tab')); });
    });
    $('jobbar-close').addEventListener('click', function () {
      state.watchedJob = null;
      if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
      $('jobbar').classList.add('hidden');
    });
    $('jobbar-toggle').addEventListener('click', function () {
      var log = $('jobbar-log');
      log.classList.toggle('collapsed');
      $('jobbar-toggle').textContent = log.classList.contains('collapsed') ? 'Show log' : 'Hide log';
    });
    $('jobbar-cancel').addEventListener('click', function () {
      if (state.watchedJob === null) { return; }
      api('POST', '/api/jobs/' + state.watchedJob + '/cancel', {}).then(function () { pollJob(false); }).catch(fail);
    });
    $('stop-ui').addEventListener('click', function () {
      confirmDialog('Stop the UI?', h('p', {}, 'The server on this computer stops. A running job is cancelled. Start it again with Start-WheelhouseUI.ps1.'), 'Stop', true).then(function (ok) {
        if (!ok) { return; }
        api('POST', '/api/shutdown', {}).then(function () {
          document.body.innerHTML = '';
          document.body.append(h('div', { class: 'empty' }, 'The UI has stopped. You can close this tab.'));
        }).catch(fail);
      });
    });

    refreshState().then(function (info) {
      if (!info) { return; }
      var tabs = ['packages', 'add', 'quarantine', 'denylist', 'settings', 'jobs'];
      var wanted = location.hash.replace('#', '');
      if (!info.configured) { showTab('settings'); }
      else { showTab(tabs.indexOf(wanted) >= 0 ? wanted : 'packages'); }
      if (info.running_job) { watchJob(info.running_job.id); }
    });
  }

  init();
})();
