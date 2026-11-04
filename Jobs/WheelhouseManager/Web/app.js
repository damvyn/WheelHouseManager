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

  // Busy feedback for every request: a bar sweeps under the top bar while one is in flight
  // (after a short delay, so quick reads do not flicker), and the button whose click sent a
  // change spins until the answer comes. Job polling does not count - the top bar pill and
  // setJobRunning show a running job.
  var busy = { count: 0, timer: null, button: null, buttonTime: 0 };
  document.addEventListener('click', function (e) {
    var b = e.target && e.target.closest ? e.target.closest('button') : null;
    if (b) { busy.button = b; busy.buttonTime = Date.now(); }
  }, true);
  function showBusy() {
    var bar = document.getElementById('busybar');
    if (bar) { bar.classList.toggle('active', busy.count > 0 || document.body.classList.contains('job-running')); }
  }
  function busyStart(method, path) {
    if (/^\/api\/jobs/.test(path)) { return null; }
    busy.count++;
    if (!busy.timer) { busy.timer = setTimeout(function () { busy.timer = null; showBusy(); }, method === 'GET' ? 250 : 0); }
    // The clicked button spins only for a change sent right after the click (or a dialog's OK).
    var b = method !== 'GET' && busy.button && Date.now() - busy.buttonTime < 2000 && busy.button.isConnected ? busy.button : null;
    if (b) { b.classList.add('loading'); b.setAttribute('aria-busy', 'true'); }
    busy.button = null;
    return function () {
      busy.count = Math.max(0, busy.count - 1);
      if (b) { b.classList.remove('loading'); b.removeAttribute('aria-busy'); }
      if (busy.count === 0 && busy.timer) { clearTimeout(busy.timer); busy.timer = null; }
      showBusy();
    };
  }

  function api(method, path, body) {
    var opts = { method: method, headers: { 'X-Wheelhouse-Token': token || '' } };
    if (method !== 'GET') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body || {});
    }
    var done = busyStart(method, path);
    var finish = function (value) { if (done) { done(); done = null; } return value; };
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
    }).then(finish, function (err) { finish(); throw err; });
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
  function fmtDay(s) {
    if (!s) { return ''; }
    var d = new Date(s);
    return isNaN(d.getTime()) ? s : d.toLocaleDateString();
  }
  // A toast with an action ({ label, run }) is a button: clicking it closes it and runs the action.
  function toast(message, kind, action, sticky) {
    var el = h('div', { class: 'toast ' + (kind || 'ok') + (action ? ' actionable' : ''), role: action ? 'button' : null, tabindex: action ? '0' : null },
      message, action ? h('div', { class: 'toast-action' }, action.label + ' >') : null);
    if (action) {
      var go = function () { el.remove(); action.run(); };
      el.addEventListener('click', go);
      el.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
    }
    $('toasts').append(el);
    if (!sticky) { setTimeout(function () { el.remove(); }, action ? 20000 : (kind === 'bad' ? 9000 : 4500)); }
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

  function infoDialog(title, bodyNodes) {
    var dlg = $('dialog');
    clear(dlg);
    var close = h('button', { class: 'btn primary', type: 'button' }, 'Close');
    close.addEventListener('click', function () { dlg.close(); });
    dlg.onclose = null;
    dlg.append(h('h3', {}, title), bodyNodes, h('div', { class: 'actions' }, close));
    dlg.showModal();
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
    currentTab: 'overview',
    watchedJob: null,
    pollTimer: null,
    shown: {},
    // The Add tab is rebuilt every time it is shown: an unsaved edit of requirements.in (null
    // when there is none), the publish checkbox and the lines a save refused live here.
    add: { draft: null, publish: false, problems: null }
  };

  // ---------------------------------------------------------------- header / tabs
  function renderStatus() {
    var box = $('status');
    clear(box);
    var info = state.info;
    if (!info) { return; }
    // Element.append() would print a nested list as "[object HTMLSpanElement]": pass a flat list.
    var parts = [
      h('span', { class: 'mono' }, info.wheelhouse_path || '(wheelhouse folder not set)'),
      badge('Target Python ' + info.python_version + ' / ' + info.platform),
      info.defender ? badge('Defender available', 'ok') : badge('Defender not available', 'warn'),
      info.is_admin ? badge('elevated', 'ok') : badge('not elevated', 'warn', 'Defender scans need an elevated PowerShell')
    ].concat([].concat(info.tools || []).map(function (t) {
      return badge(t.name + (t.available ? ' ' + t.version : ' missing'), t.level, t.message || ('Found: ' + t.name + ' ' + t.version));
    }));
    parts.forEach(function (p) { box.append(p); });
    // Every problem that stops something from working, worst first.
    var problems = [];
    if (!info.configured) {
      problems.push({ level: 'bad', text: 'The wheelhouse folder is not set. Open the Settings tab and enter it.' });
    } else if (!info.reachable) {
      problems.push({ level: 'bad', text: 'The wheelhouse folder does not exist or is not reachable: ' + info.wheelhouse_path });
    }
    [].concat(info.tools || []).forEach(function (t) {
      if (t.level !== 'ok' && t.message) { problems.push({ level: t.level, text: t.message }); }
    });
    var banner = $('banner');
    clear(banner);
    if (problems.length === 0) {
      banner.className = 'banner hidden';
      return;
    }
    problems.sort(function (a, b) { return (a.level === 'bad' ? 0 : 1) - (b.level === 'bad' ? 0 : 1); });
    problems.forEach(function (p) { banner.append(h('div', {}, p.text)); });
    banner.className = problems[0].level === 'bad' ? 'banner bad' : 'banner';
  }

  function showTab(name) {
    if (state.currentTab === 'settings' && name !== 'settings' && state.settingsDirty &&
      !window.confirm('Your settings changes are not saved yet. Leave the Settings tab and discard them?')) { return; }
    state.settingsDirty = false;
    state.currentTab = name;
    // The Packages tab keeps its toolbar in place and scrolls the table alone.
    $('page').classList.toggle('fill', name === 'packages');
    Array.prototype.forEach.call(document.querySelectorAll('#tabs button'), function (b) {
      b.classList.toggle('active', b.getAttribute('data-tab') === name);
    });
    Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (s) {
      s.classList.toggle('hidden', s.id !== 'tab-' + name);
    });
    var loaders = {
      overview: loadOverview, packages: loadPackages, add: renderAdd, audit: loadAudits, quarantine: loadQuarantine,
      denylist: loadDenylist, schedule: loadScheduleTab, settings: loadSettings, jobs: loadJobs
    };
    return loaders[name]();
  }

  // One-time messages for the Packages tab, as toasts that stay until clicked (once per page load).
  function showPackageNotices() {
    if (state.checkOverdue && !state.shown.checkOverdue) {
      state.shown.checkOverdue = true;
      toast('The scheduled check is not running. ' + (state.lastCheck
        ? 'Test-Wheelhouse.ps1 last completed ' + fmtDate(state.lastCheck) + ', more than ' + state.freshnessDays + ' day(s) ago.'
        : 'Test-Wheelhouse.ps1 has never completed for this wheelhouse.') +
        ' New vulnerabilities in published packages go unnoticed until it runs again.', 'bad',
        { label: 'Set up the weekly check', run: function () { showTab('schedule'); } }, true);
    }
    if (state.info && (!state.info.defender || !state.info.is_admin) && !state.shown.defender) {
      state.shown.defender = true;
      toast('Defender scans need Microsoft Defender and an elevated PowerShell (Run as administrator) for Start-WheelhouseUI.ps1.', 'warn',
        { label: 'OK', run: function () { } }, true);
    }
  }

  // Brings a card into view and outlines it as the place to look next.
  function highlight(el) {
    if (!el) { return; }
    el.classList.add('next-step');
    setTimeout(function () { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 50);
  }

  // Where to look after a job that ended with findings or failed, as a toast action.
  function jobNextStep(job) {
    if (job.kind === 'remediate' && job.status === 'Succeeded') {
      return { label: 'Review and publish the fix', run: function () { state.reviewFix = true; showTab('add'); } };
    }
    if (job.status === 'Succeeded' || job.status === 'Cancelled' || job.status === 'Running') { return null; }
    var showLog = { label: 'Open the log', run: function () { watchJob(job.id, true); } };
    if (job.status === 'Failed') { return showLog; }
    // An "add" job resolves first (step 1) and may then publish: only the publish step
    // produces rejected packages; a resolve that needs attention is explained in the log.
    var publishing = job.kind === 'update' || (job.kind === 'add' && job.steps > 1 && job.step === job.steps);
    if (publishing) {
      return { label: 'Show what needs attention', run: function () { showUpdateResult(job); } };
    }
    if (job.kind === 'add') { return { label: 'Open the log to see why', run: function () { watchJob(job.id, true); } }; }
    if (job.kind === 'remediate') { return { label: 'Open the log to see why', run: function () { watchJob(job.id, true); } }; }
    if (job.kind === 'audit') { return { label: 'Show the vulnerable packages', run: function () { showPackagesFiltered('vulnerable', job); } }; }
    if (job.kind === 'scan') { return { label: 'Show the threats', run: function () { showPackagesFiltered('threat', job); } }; }
    return showLog;
  }
  function showPackagesFiltered(filter, job) {
    state.statusFilter = filter;
    var loading = showTab('packages');
    if (!loading) { return; }
    loading.then(function () {
      if (visiblePackages().length === 0) {
        // Nothing of that kind in the table: the details are in the job's log.
        state.statusFilter = 'all';
        renderPackages();
        toast('No package is marked like that in the table - the details are in the log.', 'bad');
        watchJob(job.id, true);
      }
    });
  }
  // An update needs attention for rejected packages (Add tab), vulnerable published ones
  // (Packages tab) or notices such as a wheel missing from the share (the log).
  function showUpdateResult(job) {
    api('GET', '/api/rejected').then(function (data) {
      var started = new Date(job.started_utc).getTime();
      var fresh = data.file && data.items.length > 0 && new Date(data.modified_utc).getTime() >= started - 5000;
      if (fresh) {
        state.highlightRejected = true;
        showTab('add');
      } else {
        showPackagesFiltered('vulnerable', job);
      }
    }).catch(function () { watchJob(job.id, true); });
  }

  // ---------------------------------------------------------------- overview tab
  // The state of the wheelhouse at a glance, and what needs attention - each item leads to
  // the tab (and filter) where it is handled.
  function loadOverview() {
    var root = $('tab-overview');
    return api('GET', '/api/overview').then(function (o) {
      clear(root);
      var tile = function (value, label, kind, target) {
        var el = h('div', { class: 'tile' + (kind && value ? ' ' + kind : '') + (target ? ' link' : '') }, h('div', { class: 'tile-value' }, String(value)), h('div', { class: 'tile-label' }, label));
        if (target) { el.addEventListener('click', function () { goTo(target); }); }
        return el;
      };
      root.append(h('div', { class: 'tiles' },
        tile(o.packages, 'packages (' + o.published + ' versions, ' + o.groups + ' group files)', null, 'packages'),
        tile(o.open, 'open vulnerabilities', 'warn', 'packages:vulnerable'),
        tile(o.overdue, 'past their fix-by date', 'bad', 'packages:overdue'),
        tile(o.waived, 'risks accepted (waived)', null, 'packages:waived'),
        tile(o.yanked, 'yanked on PyPI', 'warn', 'packages:yanked'),
        tile(o.unverified, 'without a recent audit', 'bad', 'packages:unaudited'),
        tile(o.quarantined, 'quarantined', null, 'quarantine')));

      var attention = [].concat(o.attention || []);
      var list = h('div', { class: 'card' }, h('h2', {}, 'Needs attention'));
      if (attention.length === 0) {
        list.append(h('p', {}, badge('all clear', 'ok'), ' Nothing needs attention right now.'));
      }
      attention.forEach(function (a) {
        list.append(h('div', { class: 'attention-item' }, badge(a.level === 'bad' ? 'act now' : 'review', a.level), ' ', a.text, ' ',
          h('button', { class: 'btn small', type: 'button', onclick: function () { goTo(a.target); } }, 'Open')));
      });
      root.append(list);

      var task = o.task;
      root.append(h('div', { class: 'card' }, h('h2', {}, 'Weekly check'),
        h('p', {}, 'Last completed: ', o.last_check_utc ? fmtDate(o.last_check_utc) : 'never', o.check_overdue ? [' ', badge('overdue', 'bad')] : ''),
        h('p', {}, 'Scheduled Task: ', task ? task.state + (task.next_run_utc ? ', next run ' + fmtDate(task.next_run_utc) : '') + (task.last_result ? ' - last result: ' + task.last_result : '') : 'not registered', ' ',
          h('button', { class: 'btn small', type: 'button', onclick: function () { showTab('schedule'); } }, task ? 'Manage' : 'Set it up'))));
    }).catch(function (err) { clear(root); root.append(h('div', { class: 'empty' }, err.message)); });
  }

  // "tab" or "packages:<status filter>".
  function goTo(target) {
    var parts = String(target).split(':');
    if (parts[0] === 'packages') { state.statusFilter = parts[1] || 'all'; }
    showTab(parts[0]);
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
      state.lastCheck = data.last_check_utc;
      state.checkOverdue = data.check_overdue;
      state.freshnessDays = data.audit_freshness_days;
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
        case 'overdue': return p.overdue;
        case 'waived': return p.waived_findings > 0;
        case 'threat': return p.scan_status === 'Threat';
        case 'unaudited': return p.audit_status === 'Unknown';
        case 'unscanned': return p.scan_status === 'Unknown';
        case 'yanked': return !!p.yanked;
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
      [['all', 'All packages'], ['vulnerable', 'Vulnerable'], ['overdue', 'Fix overdue'], ['waived', 'Risk accepted (waived)'],
        ['threat', 'Defender threat'], ['unaudited', 'Never audited'],
        ['unscanned', 'Never scanned'], ['yanked', 'Yanked on PyPI'], ['denylisted', 'On the denylist'], ['missing', 'File missing']].map(function (o) {
        return h('option', { value: o[0], selected: state.statusFilter === o[0] }, o[1]);
      }));
    statusFilter.addEventListener('change', function () { state.statusFilter = statusFilter.value; renderPackages(); });

    showPackageNotices();
    var toolbar = h('div', { class: 'toolbar' },
      h('div', { class: 'group' }, filter, statusFilter, h('button', { class: 'btn', type: 'button', onclick: loadPackages }, 'Refresh')),
      h('div', { class: 'group' },
        h('button', { class: 'btn', type: 'button', 'data-idle': true, disabled: none, onclick: function () { runAudit(false); } }, 'Audit selected'),
        h('button', { class: 'btn', type: 'button', 'data-idle': true, onclick: function () { runAudit(true); } }, 'Audit all')),
      h('div', { class: 'group' },
        h('button', { class: 'btn', type: 'button', 'data-idle': true, disabled: none, onclick: function () { runScan(false); } }, 'Scan selected'),
        h('button', { class: 'btn', type: 'button', 'data-idle': true, onclick: function () { runScan(true); } }, 'Scan all')),
      h('div', { class: 'group' },
        h('button', { class: 'btn', type: 'button', 'data-idle': true, disabled: none, onclick: function () { removeSelected('quarantine'); } }, 'Quarantine'),
        h('button', { class: 'btn danger', type: 'button', 'data-idle': true, disabled: none, onclick: function () { removeSelected('delete'); } }, 'Delete')),
      h('span', { class: 'muted' }, pins.length + ' selected / ' + visible.length + ' shown / ' + state.pkgs.length + ' files'));
    root.append(toolbar);


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
      var auditCell;
      if (p.open_findings > 0) {
        auditCell = [badge(p.severity || 'Vulnerable', severityKind(p.severity), p.vulnerabilities.join(', ')), ' ',
          p.overdue ? badge('overdue', 'bad', 'Fix was due ' + fmtDate(p.due)) : h('span', { class: 'muted' }, 'fix by ' + fmtDay(p.due))];
      } else if (p.waived_findings > 0) {
        auditCell = badge('Risk accepted', 'warn', 'Every finding is waived - see History');
      } else if (p.audit_status === 'Vulnerable') {
        auditCell = badge('Vulnerable', 'bad', p.vulnerabilities.join(', '));
      } else {
        auditCell = p.audit_status === 'Passed' ? badge('Passed', 'ok', 'Last audit ' + p.last_audit) : badge('Not audited');
      }
      var scanCell = p.scan_status === 'Threat'
        ? badge('Threat', 'bad')
        : p.scan_status === 'Clean' ? badge('Clean', 'ok', 'Last scan ' + p.last_scan) : badge('Not scanned');
      return h('tr', { class: state.selected[k] ? 'selected' : '' },
        h('td', {}, box),
        h('td', {}, h('strong', {}, p.name), p.file_missing ? [' ', badge('file missing', 'bad')] : null,
          p.yanked ? [' ', badge('yanked', 'warn', 'Yanked on PyPI: ' + p.yanked)] : null),
        h('td', { class: 'mono' }, p.version),
        h('td', {}, p.groups.length ? p.groups.join(', ') : h('span', { class: 'muted' }, 'not listed')),
        h('td', {}, auditCell, p.vulnerabilities.length ? h('div', { class: 'mono muted' }, p.vulnerabilities.join(', ')) : null),
        h('td', {}, scanCell),
        h('td', {}, p.denylisted !== null ? badge('blocked', 'warn', p.denylisted) : ''),
        h('td', {}, fmtDate(p.downloaded_utc)),
        h('td', { class: 'num' }, fmtBytes(p.size_bytes)),
        h('td', { class: 'mono' }, p.file),
        h('td', {}, h('button', { class: 'btn small', type: 'button', onclick: function () { showHistory(p.name, p.version); } }, 'History')));
    });
    root.append(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, allBox), h('th', {}, 'Package'), h('th', {}, 'Version'), h('th', {}, 'Groups'),
        h('th', {}, 'Audit'), h('th', {}, 'Defender'), h('th', {}, 'Denylist'), h('th', {}, 'Downloaded'), h('th', {}, 'Size'), h('th', {}, 'File'), h('th', {}, ''))),
      h('tbody', {}, rows))));
  }

  // State, latest checks and the history of one package version (catalog + events.jsonl).
  function showHistory(name, version) {
    // Names and versions only contain [A-Za-z0-9._+!-], all literal in a URL path.
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) || !/^[A-Za-z0-9][A-Za-z0-9._+!-]*$/.test(version)) { return; }
    api('GET', '/api/packages/' + name + '/' + version + '/history').then(function (data) {
      var record = data.record;
      var checks = (record && record.checks) || {};
      var line = function (label, check, text) {
        return h('div', {}, h('strong', {}, label + ': '), check ? text(check) + ' (' + fmtDate(check.last_run) + ')' : 'not checked yet');
      };
      var summary = h('div', { class: 'card' },
        record ? h('p', {}, h('strong', {}, 'State: '), record.state, record.state_since ? ' since ' + fmtDate(record.state_since) : '',
          record.state_reason ? ' - ' + record.state_reason : '') : h('p', { class: 'muted' }, 'Not in the catalog.'),
        record && record.groups && record.groups.length ? h('div', {}, h('strong', {}, 'Groups: '), [].concat(record.groups).join(', ')) : null,
        line('Audit', checks.audit, function (c) { return c.status + (c.vulnerabilities && [].concat(c.vulnerabilities).length ? ' - ' + [].concat(c.vulnerabilities).join(', ') : ''); }),
        line('Defender', checks.scan, function (c) { return c.status; }),
        line('PyPI', checks.pypi, function (c) { return c.status + (c.reason ? ' - ' + c.reason : ''); }));
      var findings = [].concat((record && record.findings) || []);
      var findingTable = findings.length === 0 ? null : h('div', {}, h('h3', {}, 'Vulnerabilities'),
        h('div', { class: 'table-wrap' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Advisory'), h('th', {}, 'Severity'), h('th', {}, 'Fix by'), h('th', {}, 'Status'), h('th', {}, 'Fixed in'), h('th', {}, ''))),
          h('tbody', {}, findings.map(function (f) {
            var action;
            if (f.waiver) {
              action = h('button', { class: 'btn small', type: 'button' }, 'Remove waiver');
              action.addEventListener('click', function () {
                api('POST', '/api/waivers/remove', { name: data.name, version: data.version, id: f.id }).then(function () {
                  toast('Waiver removed - ' + f.id + ' is alerted again.');
                  closeOpenDialogs();
                  showHistory(data.name, data.version);
                  loadPackages();
                }).catch(fail);
              });
            } else {
              action = h('button', { class: 'btn small', type: 'button' }, 'Accept risk');
              action.addEventListener('click', function () { acceptRisk(data.name, data.version, f); });
            }
            if ([].concat(f.fix_versions || []).length) {
              var fix = h('button', { class: 'btn small primary', type: 'button', 'data-idle': true }, 'Fix');
              fix.addEventListener('click', function () { planFix(data.name, data.version); });
              action = h('div', { class: 'row-actions' }, fix, action);
            }
            var status = f.status === 'Overdue' ? badge('overdue', 'bad') : f.status === 'Waived'
              ? badge('waived', 'warn', f.waiver.reason + ' (' + f.waiver.by + ')') : badge('open');
            return h('tr', {},
              h('td', {}, h('span', { class: 'mono' }, f.id), [].concat(f.aliases || []).length ? h('div', { class: 'muted mono' }, [].concat(f.aliases).join(', ')) : null,
                f.summary ? h('div', { class: 'muted' }, f.summary) : null),
              h('td', {}, badge(f.severity, severityKind(f.severity)), f.score !== null && f.score !== undefined ? ' ' + f.score : ''),
              h('td', {}, fmtDay(f.due)),
              h('td', {}, status, f.waiver ? h('div', { class: 'muted' }, 'until ' + fmtDay(f.waiver.expires_utc)) : null),
              h('td', { class: 'mono' }, [].concat(f.fix_versions || []).join(', ') || h('span', { class: 'muted' }, 'none yet')),
              h('td', {}, action));
          })))));
      var events = [].concat(data.events || []);
      var table = events.length === 0 ? h('p', { class: 'muted' }, 'No history recorded yet.') :
        h('div', { class: 'table-wrap' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'What'), h('th', {}, 'Who'), h('th', {}, 'Details'))),
          h('tbody', {}, events.map(function (e) {
            return h('tr', {}, h('td', {}, fmtDate(e.ts)), h('td', {}, e.action), h('td', {}, e.user), h('td', {}, e.detail));
          }))));
      infoDialog(data.name + '==' + data.version, h('div', {}, summary, findingTable, table));
    }).catch(fail);
  }

  function severityKind(severity) {
    return severity === 'Critical' || severity === 'High' || severity === 'Unknown' ? 'bad' : 'warn';
  }
  function closeOpenDialogs() {
    Array.prototype.forEach.call(document.querySelectorAll('dialog[open]'), function (d) { d.close(); });
  }

  // Remediation: show the plan (fix version, the requirements.in change), ask for an
  // expedite reason when the fix is newer than the cooldown, then start the job that
  // resolves and proposes it. Nothing is published before the proposal is approved.
  function planFix(name, version) {
    closeOpenDialogs();
    toast('Working out the fix for ' + name + '==' + version + ' (asks PyPI)...');
    api('GET', '/api/packages/' + name + '/' + version + '/remediation').then(function (plan) {
      var reason = h('input', { type: 'text', class: 'wide', placeholder: 'Why can the fix not wait for the cooldown? (required)' });
      var body = h('div', {},
        h('p', {}, plan.summary),
        h('p', {}, 'requirements.in: ', h('span', { class: 'mono' }, plan.old_line || '(not listed - added as a direct requirement)'), ' -> ', h('span', { class: 'mono' }, plan.new_line)),
        h('p', { class: 'muted' }, 'This resolves requirements.txt again and records a fix proposal. After it is approved and published, the fixed version replaces ' + name + '==' + version + ' in its group files and ' + name + '==' + version + ' is quarantined.'),
        plan.needs_expedite ? h('div', {}, h('p', {}, badge('cooldown', 'warn'), ' The fix (' + plan.expedite_version + ') is newer than the cooldown. Only this package skips it, with your reason:'), reason) : null);
      confirmDialog('Fix ' + name + '==' + version + '?', body, 'Prepare the fix', false).then(function (ok) {
        if (!ok) { return; }
        var request = { name: name, version: version };
        if (plan.needs_expedite) { request.expedite_reason = reason.value; }
        startJobRequest(api('POST', '/api/packages/remediate', request));
      });
    }).catch(fail);
  }

  // A waiver accepts one advisory for one version until a date; it is never permanent.
  function acceptRisk(name, version, finding) {
    var reason = h('input', { type: 'text', class: 'wide', placeholder: 'Why is this acceptable? (required, kept in the history)' });
    var days = h('input', { type: 'number', min: '1', value: '30' });
    var body = h('div', {},
      h('p', {}, 'Accept ', h('span', { class: 'mono' }, finding.id), ' (' + finding.severity + ') for ', h('span', { class: 'mono' }, name + '==' + version), '.'),
      h('p', { class: 'muted' }, 'It is not alerted while the waiver lasts. When the waiver ends it is alerted again. Other advisories and other versions are not covered.'),
      h('div', { class: 'toolbar' }, reason), h('label', {}, 'Days: ', days));
    closeOpenDialogs();
    confirmDialog('Accept the risk?', body, 'Accept risk', false).then(function (ok) {
      if (!ok) { showHistory(name, version); return; }
      api('POST', '/api/waivers/add', { name: name, version: version, id: finding.id, reason: reason.value, days: days.value }).then(function (data) {
        toast('Risk accepted until ' + fmtDay(data.expires_utc) + '.');
        loadPackages();
        showHistory(name, version);
      }).catch(function (err) { fail(err); showHistory(name, version); });
    });
  }

  function startJobRequest(promise) {
    return promise.then(function (data) {
      if (data.job) { watchJob(data.job.id, false); }
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
    var reviewFix = state.reviewFix;
    state.reviewFix = false;
    // The box is requirements.in itself. An edit not saved yet is kept in state.add.draft,
    // so switching tabs does not lose it; otherwise the box shows the file as it is now.
    var specs = h('textarea', { id: 'requirements-in', spellcheck: 'false', placeholder: 'numpy\npandas>=2.0\nrequests==2.32.3' });
    specs.readOnly = document.body.classList.contains('job-running');
    specs.addEventListener('input', function () { state.add.draft = specs.value; showDirty(); });
    var publishNow = h('input', { type: 'checkbox' });
    publishNow.checked = state.add.publish;
    publishNow.addEventListener('change', function () { state.add.publish = publishNow.checked; });
    var info = h('span', { class: 'muted', id: 'requirements-in-info' });
    var output = h('div', { class: 'add-result hidden', id: 'requirements-in-problems' });
    var go = h('button', { class: 'btn primary', type: 'button', 'data-idle': true }, 'Add and resolve');
    var undo = h('button', { class: 'btn', type: 'button', title: 'Discard the changes and show requirements.in as it is' }, 'Discard changes');
    function showDirty() {
      undo.classList.toggle('hidden', state.add.draft === null);
      info.textContent = state.add.draft === null ? info.getAttribute('data-saved') || '' : 'Not saved yet.';
    }
    undo.addEventListener('click', function () { state.add.draft = null; state.add.problems = null; renderProblems(output); loadRequirementsIn(); });
    go.addEventListener('click', function () {
      api('POST', '/api/requirements/in', { text: specs.value, publish: publishNow.checked }).then(function (data) {
        state.add.problems = data.saved ? null : [].concat(data.problems || []);
        renderProblems(output);
        if (!data.saved) { return; }
        state.add.draft = null;
        if (data.job) { watchJob(data.job.id, false); } else { toast('requirements.in saved. It lists no package, so there is nothing new to resolve.'); loadRequirements(); }
        loadRequirementsIn();
      }).catch(fail);
    });
    root.append(
      h('div', { class: 'card' },
        h('h2', {}, '1. Add packages'),
        h('p', { class: 'muted' }, 'This is requirements.in: one requirement per line, for example numpy or pandas>=2.0. Edit it here and click Add and resolve: Update-Requirement.ps1 resolves it (with the cooldown) together with the pins still waiting below into requirements.txt. Nothing is downloaded yet: review the result below first. When the resolve succeeds, requirements.in is emptied - its packages are then listed below. When it fails, the box keeps the lines so you can fix them.'),
        specs,
        h('p', {}, h('label', {}, publishNow, ' Also publish right away (skips the review step)')),
        h('div', { class: 'toolbar' }, go, undo, info),
        output),
      h('div', { class: 'card', id: 'requirements-card' }),
      h('div', { class: 'card', id: 'rejected-card' }));
    showDirty();
    renderProblems(output);
    loadRequirementsIn();
    loadRequirements(reviewFix ? 'fix' : false);
    loadRejected();
  }

  // Shows requirements.in in the Add tab's box - unless an edit is not saved yet.
  function loadRequirementsIn() {
    var box = $('requirements-in');
    if (!box) { return; }
    if (state.add.draft !== null) { box.value = state.add.draft; return; }
    api('GET', '/api/requirements/in').then(function (data) {
      if (state.add.draft !== null || !$('requirements-in')) { return; }
      box.value = data.text || '';
      var info = $('requirements-in-info');
      if (info) {
        var saved = (data.path || 'requirements.in') + (data.modified_utc ? ' (changed ' + fmtDate(data.modified_utc) + ')' : '');
        info.setAttribute('data-saved', saved);
        info.textContent = saved;
      }
    }).catch(fail);
  }

  // The lines "Save and resolve" refused (nothing was written), until they are fixed.
  function renderProblems(output) {
    var problems = state.add.problems || [];
    clear(output);
    output.classList.toggle('hidden', problems.length === 0);
    if (problems.length === 0) { return; }
    output.append(h('div', { class: 'add-result-head' }, h('strong', {}, 'Not saved:'), ' ', badge(problems.length + ' line(s) to fix', 'bad')),
      h('div', { class: 'result-scroll' }, h('ul', { class: 'result-list' }, problems.map(function (p) {
        return h('li', { class: 'bad' }, 'Line ' + p.Line + ': ', h('span', { class: 'mono' }, p.Spec), ' - ', p.Reason);
      }))));
  }

  function loadRequirements(showNextStep) {
    var card = $('requirements-card');
    if (!card) { return; }
    api('GET', '/api/requirements').then(function (data) {
      clear(card);
      if (showNextStep) {
        card.classList.add('next-step');
        card.append(h('p', { class: 'next-hint' }, showNextStep === 'fix'
          ? 'Fix prepared. Next: review what changes below, then publish it to the wheelhouse.'
          : 'Resolved. Next: review the pins below, then publish them to the wheelhouse.'));
        setTimeout(function () { card.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 50);
      } else {
        card.classList.remove('next-step');
      }
      card.append(h('h2', {}, '2. Review and publish'),
        h('p', { class: 'muted' }, 'Resolved pins in ' + (data.path || 'requirements.txt') + (data.modified_utc ? ' (changed ' + fmtDate(data.modified_utc) + ')' : '') +
          '. Publishing runs Update-Wheelhouse.ps1: every new pin is checked against the denylist, audited, checked for the cooldown and for yanked releases, downloaded into a staging folder, verified against the sha256 published on PyPI and scanned with Defender. Only then is it copied into the wheelhouse. Pins already in the wheelhouse are skipped.'));
      // The latest "Add and resolve" failed: what to fix in step 1, and no publishing until then.
      var failure = data.resolve_failure && data.resolve_failure.failed ? data.resolve_failure : null;
      if (failure) {
        var lines = [].concat(failure.packages || []);
        card.append(h('div', { class: 'banner' }, h('strong', {}, 'The latest resolve failed' + (failure.time_utc ? ' (' + fmtDate(failure.time_utc) + ')' : '') + '. '), failure.message || '',
          ' Fix the lines in step 1 and click Add and resolve again; publishing stays off until then.'));
        if (lines.length) {
          card.append(h('div', { class: 'table-wrap scroll-list' }, h('table', {},
            h('thead', {}, h('tr', {}, h('th', {}, 'Line in step 1'), h('th', {}, 'Status'))),
            h('tbody', {}, lines.map(function (l) {
              return h('tr', {}, h('td', { class: 'mono' }, l.spec), h('td', {}, l.ok ? badge('ok', 'ok') : [badge('problem', 'bad'), ' ', l.status]));
            })))));
        }
      }
      if (!data.pin_count) {
        card.append(h('div', { class: 'empty' }, 'requirements.txt is empty - add packages above first.'));
        return;
      }
      // Only what publishing would add; pins already in the wheelhouse are only counted.
      var pending = [].concat(data.pending || []);
      var whole = h('details', {}, h('summary', {}, 'Show the whole requirements.txt (' + data.pin_count + ' pin(s))'), h('pre', { class: 'log review' }, data.text));
      if (data.published_count > 0) {
        card.append(h('p', {}, data.published_count + ' pin(s) of requirements.txt are already in the wheelhouse and are not listed here.'));
      }
      if (pending.length === 0) {
        card.append(h('div', { class: 'empty' }, 'Everything in requirements.txt is already in the wheelhouse - there is nothing to publish. Add packages above to resolve new ones.'), whole);
        return;
      }
      var rejectedCount = pending.filter(function (p) { return p.rejected; }).length;
      card.append(h('div', { class: 'table-wrap scroll-list' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Not yet in the wheelhouse'), h('th', {}, 'Requested by'), h('th', {}, 'Status'), rejectedCount ? h('th', {}, '') : null)),
        h('tbody', {}, pending.map(function (p) {
          // Only a pin the latest publish rejected can be taken out of requirements.txt here; a
          // dependency of another requirement goes away only with that requirement.
          var action = null;
          if (p.rejected) {
            action = p.direct
              ? h('button', { class: 'btn small danger', type: 'button', 'data-idle': true, title: 'Take ' + p.name + ' (and what only it needs) out of requirements.txt', onclick: function () { removeRequirement(p); } }, 'Remove')
              : h('span', { class: 'muted', title: 'Not asked for: another package depends on it' }, 'dependency');
          }
          var status = !p.rejected ? badge('new', 'ok')
            : p.retryable ? [badge('waiting for cooldown', 'warn'), ' ', p.rejected] : [badge('rejected', 'bad'), ' ', p.rejected];
          var by = [].concat(p.requested_by || []);
          return h('tr', {}, h('td', { class: 'mono' }, p.name + '==' + p.version),
            h('td', {}, by.length ? by.map(function (b, i) { return [i ? ', ' : '', b === 'User input' ? h('strong', {}, b) : h('span', { class: 'mono' }, b)]; }) : h('span', { class: 'muted' }, '-')),
            h('td', {}, status),
            rejectedCount ? h('td', { class: 'num' }, action) : null);
        })))));
      // A rejected pin is not counted for publishing; one rejected only for the cooldown is,
      // because it passes once the cooldown is over.
      var publishable = pending.filter(function (p) { return !p.rejected || p.retryable; }).length;
      var blocked = pending.filter(function (p) { return p.rejected && !p.retryable; }).length;
      var waiting = rejectedCount - blocked;
      if (blocked > 0) {
        card.append(h('p', { class: 'muted' }, blocked + ' pin(s) were rejected by the latest publish for the reason shown and are not counted for publishing. Click Remove to take them out of requirements.txt.'));
      }
      if (waiting > 0) {
        card.append(h('p', { class: 'muted' }, waiting + ' pin(s) are newer than the cooldown. Publishing again adds them once the cooldown has passed; Remove takes them out if you do not want to wait.'));
      }
      var clearable = pending.length > 0;
      card.append(renderApproval(data.approval, failure ? 0 : publishable, clearable, !!failure), whole);
    }).catch(function (err) { clear(card); card.append(h('div', { class: 'empty' }, err.message)); });
  }

  // Takes a pin (and the pins only it needed) out of requirements.txt.
  function removeRequirement(p) {
    confirmDialog('Remove ' + p.name + '?', h('div', {},
      h('p', {}, h('span', { class: 'mono' }, p.name + '==' + p.version), ' is taken out of requirements.txt, together with the dependencies only it needed, so it is no longer waiting to be published.'),
      h('p', { class: 'muted' }, 'Nothing in the wheelhouse changes.')), 'Remove', true).then(function (ok) {
      if (!ok) { return; }
      api('POST', '/api/requirements/remove', { name: p.name }).then(function (data) {
        if (data.job) { watchJob(data.job.id, false); } else { toast(p.name + ' removed.'); loadRequirements(); }
      }).catch(fail);
    });
  }

  // The proposal behind requirements.txt and the buttons. With the default approval mode the
  // person who publishes is recorded and there is nothing to approve separately; the
  // SeparateApprover mode (decision D3) keeps Approve / Reject for a second person.
  function renderApproval(a, publishable, clearable, resolveFailed) {
    var box = h('div', { class: 'approval' });
    var p = a.proposal;
    var separate = a.mode === 'SeparateApprover';
    if (p && a.current) {
      if (separate) {
        var stateKind = p.state === 'Approved' || p.state === 'Published' ? 'ok' : p.state === 'Rejected' ? 'bad' : 'warn';
        box.append(h('p', {}, h('strong', {}, (p.kind === 'remediation' ? 'Fix proposal ' : 'Proposal ') + p.id), ' ', badge(p.state, stateKind),
          ' requested by ' + p.requested_by + ' on ' + fmtDate(p.requested_utc),
          p.approved_by ? ', approved by ' + p.approved_by + (p.approved_utc ? ' on ' + fmtDate(p.approved_utc) : '') : '',
          p.rejected_by ? ', rejected by ' + p.rejected_by + ': ' + p.decision_note : ''));
      } else {
        box.append(h('p', { class: 'muted' }, (p.kind === 'remediation' ? 'Fix prepared by ' : 'Resolved by ') + p.requested_by + ' on ' + fmtDate(p.requested_utc) + '.',
          p.state === 'Published' && p.approved_by ? ' Last published by ' + p.approved_by + (p.approved_utc ? ' on ' + fmtDate(p.approved_utc) : '') + '.' : ''));
      }
      if (p.note && separate) { box.append(h('p', { class: 'muted' }, p.note)); }
      var retire = [].concat(p.retire || []);
      if (p.kind === 'remediation' && retire.length) {
        box.append(h('ul', { class: 'result-list' },
          [].concat(p.replace || []).map(function (r) { return h('li', { class: 'mono' }, r.name + ': ' + (r.from || '(new)') + ' -> ' + r.to); }),
          retire.map(function (r) { return h('li', {}, 'then quarantine ', h('span', { class: 'mono' }, r.name + '==' + r.version), ' (' + [].concat(r.ids).join(', ') + ')'); })),
          h('p', { class: 'muted' }, 'The fixed versions replace the old ones in the group files that list the vulnerable version - the files clients install from.'));
      }
      if (p.expedite_reason) { box.append(h('p', {}, badge('cooldown skipped', 'warn'), ' ' + p.expedite_reason)); }
    } else if (p && separate) {
      box.append(h('p', { class: 'muted' }, 'requirements.txt changed after proposal ' + p.id + ' was made - it is not covered by it.'));
    } else if (separate) {
      box.append(h('p', { class: 'muted' }, 'No proposal yet for requirements.txt.'));
    }
    box.append(h('p', { class: 'muted' }, separate
      ? 'Approval: another person than the requester must approve it before it can be published. You are ' + a.current_user + '.'
      : 'Publishing records who published it. You are ' + a.current_user + '.'));
    if (a.blocked_by) { box.append(h('div', { class: 'banner' }, a.blocked_by)); }

    var buttons = h('div', { class: 'toolbar after-output' });
    if (separate && a.can_approve && p && p.state === 'Proposed') {
      var approve = h('button', { class: 'btn', type: 'button', 'data-idle': true }, 'Approve');
      approve.addEventListener('click', function () {
        api('POST', '/api/proposal/approve', { id: p.id }).then(function () { toast('Proposal ' + p.id + ' approved.'); loadRequirements(); }).catch(fail);
      });
      buttons.append(approve);
    }
    if (separate && a.can_reject && p) {
      var reject = h('button', { class: 'btn danger', type: 'button', 'data-idle': true }, 'Reject');
      reject.addEventListener('click', function () {
        var reason = h('input', { type: 'text', class: 'wide', placeholder: 'Why? (required, recorded)' });
        confirmDialog('Reject proposal ' + p.id + '?', h('div', {}, h('p', {}, 'Nothing of it is published. To try again, change requirements.in and resolve again.'), reason), 'Reject', true).then(function (ok) {
          if (!ok) { return; }
          api('POST', '/api/proposal/reject', { id: p.id, reason: reason.value }).then(function () { toast('Proposal rejected.'); loadRequirements(); }).catch(fail);
        });
      });
      buttons.append(reject);
    }
    if (!a.current && separate) {
      var propose = h('button', { class: 'btn', type: 'button', 'data-idle': true }, 'Propose this requirements.txt');
      propose.addEventListener('click', function () {
        api('POST', '/api/proposal/new', {}).then(function () { toast('Proposed. Another person has to approve it before it can be published.'); loadRequirements(); }).catch(fail);
      });
      buttons.append(propose);
    }
    var publish = h('button', { class: 'btn primary', type: 'button', 'data-idle': true, disabled: !a.can_publish || publishable === 0 },
      resolveFailed ? 'Fix the resolve first' : publishable === 0 ? 'Nothing to publish' : 'Publish ' + publishable + ' pin(s)');
    publish.addEventListener('click', function () {
      confirmDialog('Publish ' + publishable + ' pin(s)?', h('div', {},
        h('p', {}, 'Every pin that is not yet in the wheelhouse goes through all checks; a package that fails one is rejected with the reason and nothing about it is published.'),
        h('p', { class: 'muted' }, 'Recorded as published by ' + a.current_user + '.')), 'Publish', false).then(function (ok) {
        if (!ok) { return; }
        startJobRequest(api('POST', '/api/wheelhouse/update', { confirm: true }));
      });
    });
    buttons.append(publish);
    if (clearable) {
      var clearList = h('button', { class: 'btn danger', type: 'button', 'data-idle': true, title: 'Take every package waiting here out of requirements.txt' }, 'Clear list');
      clearList.addEventListener('click', function () {
        confirmDialog('Clear the list?', h('div', {},
          h('p', {}, 'requirements.txt is emptied, so nothing waits to be published any more. Nothing in the wheelhouse changes.')), 'Clear list', true).then(function (ok) {
          if (!ok) { return; }
          api('POST', '/api/requirements/clear', {}).then(function (data) {
            if (data.job) { watchJob(data.job.id, false); } else { toast('The list is cleared.'); loadRequirements(); }
          }).catch(fail);
        });
      });
      buttons.append(clearList);
    }
    box.append(buttons);
    return box;
  }

  function loadRejected() {
    api('GET', '/api/rejected').then(function (data) {
      var card = $('rejected-card');
      if (!card) { return; }
      clear(card);
      card.append(h('h2', {}, 'Latest rejected packages'));
      if (state.highlightRejected) {
        state.highlightRejected = false;
        card.append(h('p', { class: 'next-hint' }, 'These packages were not published. Each reason says what to change: Remove them in step 2 and add a fitting requirement in step 1, or wait for the date given.'));
        highlight(card);
      } else {
        card.classList.remove('next-step');
      }
      if (!data.file || data.items.length === 0) {
        card.append(h('p', { class: 'muted' }, 'No package was rejected in the latest update.'));
        return;
      }
      card.append(h('p', { class: 'muted' }, 'From ' + data.file),
        h('div', { class: 'table-wrap scroll-list' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Package'), h('th', {}, 'Group'), h('th', {}, 'Reason'))),
          h('tbody', {}, data.items.map(function (r) {
            return h('tr', {}, h('td', { class: 'mono' }, r.Package + '==' + r.Version), h('td', {}, r.Group), h('td', {}, r.Reason));
          })))));
    }).catch(function () { /* the card stays empty */ });
  }

  // ---------------------------------------------------------------- audit tab
  // The pip-audit reports in <wheelhouse>\reports: one row per report, newest first; Open shows
  // what it found (vulnerable packages first, with advisories and fix versions).
  var stageNames = {
    Scheduled: 'Weekly check', PreDownload: 'Before download', Deployed: 'Published packages', Manual: 'Manual audit'
  };
  function loadAudits() {
    var root = $('tab-audit');
    state.auditOpen = state.auditOpen || {};
    return api('GET', '/api/audits').then(function (data) {
      clear(root);
      var reports = [].concat(data.reports || []);
      var onlyVulnerable = h('input', { type: 'checkbox', checked: !!state.auditOnlyVulnerable });
      onlyVulnerable.addEventListener('change', function () { state.auditOnlyVulnerable = onlyVulnerable.checked; loadAudits(); });
      root.append(h('div', { class: 'card' }, h('h2', {}, 'Audit reports'),
        h('p', { class: 'muted' }, 'Every pip-audit run saves a report in ' + data.folder + '. They are kept for the report retention set in Settings. Click a report to show or hide what it found.'),
        h('div', { class: 'toolbar' }, h('label', {}, onlyVulnerable, ' Only reports with vulnerabilities'),
          h('button', { class: 'btn', type: 'button', onclick: loadAudits }, 'Refresh'),
          h('span', { class: 'muted' }, reports.length + ' report(s)'))));
      var shown = state.auditOnlyVulnerable ? reports.filter(function (r) { return r.vulnerable > 0 || r.error; }) : reports;
      if (shown.length === 0) {
        root.append(h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, reports.length ? 'No report found a vulnerability.' : 'No audit report yet. Audits run when packages are published, by the weekly check and from the Packages tab.')));
        return;
      }
      var body = h('tbody', {});
      shown.forEach(function (r) {
        var result = r.error ? badge('unreadable', 'bad', r.error)
          : r.vulnerable > 0 ? badge(r.vulnerable + ' vulnerable (' + r.advisories + ' advisories)', 'bad') : badge('clean', 'ok');
        var caret = h('span', { class: 'caret' }, '▸');
        var row = h('tr', { class: 'report-row', tabindex: '0', role: 'button', 'aria-expanded': 'false', title: 'Show or hide this report' },
          h('td', {}, caret, ' ', fmtDate(r.time)), h('td', {}, stageNames[r.stage] || r.stage), h('td', {}, r.group || h('span', { class: 'muted' }, '-')),
          h('td', {}, r.service), h('td', { class: 'num' }, r.packages + (r.skipped ? ' (+' + r.skipped + ' skipped)' : '')), h('td', {}, result));
        var cell = h('td', { colspan: '6', class: 'report-detail' });
        var detailRow = h('tr', { class: 'hidden' }, cell);
        var loaded = false;
        var toggle = function () {
          var open = detailRow.classList.contains('hidden');
          detailRow.classList.toggle('hidden', !open);
          row.classList.toggle('selected', open);
          row.setAttribute('aria-expanded', open ? 'true' : 'false');
          caret.textContent = open ? '▾' : '▸';
          if (open) { state.auditOpen[r.file] = true; } else { delete state.auditOpen[r.file]; }
          if (open && !loaded) {
            loaded = true;
            if (r.error) { cell.append(h('p', { class: 'bad' }, r.error)); } else { showAuditReport(r.file, cell); }
          }
        };
        row.addEventListener('click', toggle);
        row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
        body.append(row, detailRow);
        if (state.auditOpen[r.file]) { toggle(); }
      });
      root.append(h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'Run'), h('th', {}, 'Group'), h('th', {}, 'Service'), h('th', {}, 'Packages'), h('th', {}, 'Result'))),
        body)));
    }).catch(function (err) { clear(root); root.append(h('div', { class: 'empty' }, err.message)); });
  }

  // What one report found, inside its expanded row: vulnerable packages with their advisories,
  // then (folded) the clean and the skipped packages.
  function showAuditReport(file, box) {
    box.append(h('p', { class: 'muted' }, 'Loading...'));
    api('GET', '/api/audits/' + encodeURIComponent(file)).then(function (r) {
      clear(box);
      var deps = [].concat(r.dependencies || []);
      var vulnerable = deps.filter(function (d) { return [].concat(d.vulns || []).length > 0; });
      var clean = deps.filter(function (d) { return [].concat(d.vulns || []).length === 0 && !d.skipped; });
      var skipped = deps.filter(function (d) { return d.skipped; });
      box.append(h('p', { class: 'muted mono' }, r.file));
      if (vulnerable.length === 0) {
        box.append(h('p', {}, badge('clean', 'ok'), ' No known vulnerability in the ' + r.packages + ' audited package(s).'));
      } else {
        var rows = [];
        vulnerable.forEach(function (d) {
          [].concat(d.vulns).forEach(function (v, i) {
            rows.push(h('tr', {},
              h('td', { class: 'mono' }, i === 0 ? d.name + '==' + d.version : ''),
              h('td', {}, h('span', { class: 'mono' }, v.id), [].concat(v.aliases || []).length ? h('div', { class: 'muted mono' }, [].concat(v.aliases).join(', ')) : null),
              h('td', { class: 'mono' }, [].concat(v.fix_versions || []).join(', ') || h('span', { class: 'muted' }, 'none yet')),
              h('td', { class: 'audit-desc' }, (v.description || '').replace(/#+\s*/g, '').replace(/\s+/g, ' ').trim())));
          });
        });
        box.append(h('p', {}, badge(vulnerable.length + ' vulnerable', 'bad'), ' of ' + r.packages + ' audited package(s). Fix them from the package\'s History on the Packages tab.'),
          h('div', { class: 'table-wrap scroll-list' }, h('table', {},
            h('thead', {}, h('tr', {}, h('th', {}, 'Package'), h('th', {}, 'Advisory'), h('th', {}, 'Fixed in'), h('th', {}, 'Description'))),
            h('tbody', {}, rows))));
      }
      if (clean.length) {
        box.append(h('details', {}, h('summary', {}, 'Show the ' + clean.length + ' package(s) without findings'),
          h('ul', { class: 'result-list scroll-box' }, clean.map(function (d) { return h('li', { class: 'mono' }, d.name + '==' + d.version); }))));
      }
      if (skipped.length) {
        box.append(h('details', {}, h('summary', {}, 'Show the ' + skipped.length + ' skipped package(s)'),
          h('ul', { class: 'result-list scroll-box' }, skipped.map(function (d) { return h('li', {}, h('span', { class: 'mono' }, d.name + (d.version ? '==' + d.version : '')), ' - ', d.skipped); }))));
      }
    }).catch(function (err) { clear(box); box.append(h('p', { class: 'bad' }, err.message)); });
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
          var restore = h('button', { class: 'btn small', type: 'button', 'data-idle': true }, 'Restore');
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
    }).catch(function (err) { clear(root); root.append(h('div', { class: 'empty' }, err.message)); })
      .then(loadWaivers);
  }

  // Accepted risks are listed under the denylist: both decide what is alerted and blocked.
  function loadWaivers() {
    var root = $('tab-denylist');
    api('GET', '/api/waivers').then(function (data) {
      var card = h('div', { class: 'card' }, h('h2', {}, 'Accepted risks (waivers)'),
        h('p', { class: 'muted' }, 'A waiver accepts one advisory for one package version until a date (at most ' + data.max_days +
          ' days). Waived findings are not alerted; when the waiver ends they are alerted again. Add one from a package\'s History.'));
      root.append(card);
      if (data.items.length === 0) {
        root.append(h('div', { class: 'table-wrap' }, h('div', { class: 'empty' }, 'No waivers.')));
        return;
      }
      root.append(h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Package'), h('th', {}, 'Advisory'), h('th', {}, 'Reason'), h('th', {}, 'Until'), h('th', {}, 'Added'), h('th', {}, ''))),
        h('tbody', {}, data.items.map(function (w) {
          var remove = h('button', { class: 'btn small', type: 'button' }, 'Remove');
          remove.addEventListener('click', function () {
            api('POST', '/api/waivers/remove', { name: w.name, version: w.version, id: w.id }).then(function () { toast('Waiver removed.'); loadDenylist(); }).catch(fail);
          });
          return h('tr', {}, h('td', {}, h('strong', {}, w.name), ' ', h('span', { class: 'mono' }, w.version)), h('td', { class: 'mono' }, w.id), h('td', {}, w.reason),
            h('td', {}, w.expired ? badge('expired', 'bad') : fmtDay(w.expires_utc)),
            h('td', {}, fmtDate(w.added_utc), h('div', { class: 'muted' }, w.added_by)), h('td', {}, remove));
        })))));
    }).catch(function (err) { root.append(h('div', { class: 'empty' }, err.message)); });
  }

  // ---------------------------------------------------------------- settings tab
  function loadSettings() {
    var root = $('tab-settings');
    return api('GET', '/api/settings').then(function (data) {
      clear(root);
      state.settingsDirty = false;
      var inputs = {};
      var save = h('button', { class: 'btn primary', type: 'button', disabled: true }, 'Save settings');
      var discard = h('button', { class: 'btn', type: 'button', disabled: true }, 'Discard changes');
      var note = h('span', { class: 'muted' }, 'No unsaved changes.');
      var bar = h('div', { class: 'savebar' }, save, discard, note);
      var card = h('div', { class: 'card' }, h('h2', {}, 'Settings'),
        h('p', { class: 'muted' }, 'Stored in config\\settings.psd1. Changes take effect only after Save settings. Scripts started from the UI use the saved values; an explicit parameter on a manual run still wins.'));
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
        } else if (f.type === 'bool') {
          var flag = h('input', { type: 'checkbox', checked: value === true });
          control = h('label', {}, flag, ' On');
          inputs[f.key] = function () { return flag.checked; };
        } else if (f.type === 'int') {
          control = h('input', { type: 'number', min: f.min, max: f.max, value: value });
          inputs[f.key] = function () { return control.value === '' ? '' : Number(control.value); };
        } else {
          control = h('input', { type: 'text', class: 'wide', value: value === null || value === undefined ? '' : value });
          inputs[f.key] = function () { return control.value; };
        }
        card.append(h('div', { class: 'field' }, h('label', {}, f.label), h('div', {}, control, h('div', { class: 'help' }, f.help))));
      });
      var changes = function () {
        var updates = {};
        data.fields.forEach(function (f) {
          var now = inputs[f.key]();
          var before = data.values[f.key];
          if (JSON.stringify(now) !== JSON.stringify(Array.isArray(before) ? before : (f.type === 'int' ? Number(before) : (before === null || before === undefined ? '' : before)))) {
            updates[f.key] = now;
          }
        });
        return updates;
      };
      var labels = {};
      data.fields.forEach(function (f) { labels[f.key] = f.label; });
      var update = function () {
        var keys = Object.keys(changes());
        state.settingsDirty = keys.length > 0;
        save.disabled = discard.disabled = !state.settingsDirty;
        bar.className = state.settingsDirty ? 'savebar dirty' : 'savebar';
        note.textContent = state.settingsDirty
          ? 'Unsaved changes: ' + keys.map(function (k) { return labels[k]; }).join(', ') + '.'
          : 'No unsaved changes.';
      };
      card.addEventListener('input', update);
      card.addEventListener('change', update);
      discard.addEventListener('click', function () { loadSettings(); });
      save.addEventListener('click', function () {
        var updates = changes();
        if (Object.keys(updates).length === 0) { toast('Nothing changed.'); return; }
        api('POST', '/api/settings', { updates: updates }).then(function (res) {
          toast('Saved: ' + res.saved.join(', '));
          state.settingsDirty = false;
          refreshState().then(loadSettings);
        }).catch(fail);
      });
      root.append(bar, card);
    }).catch(function (err) { clear(root); root.append(h('div', { class: 'empty' }, err.message)); });
  }

  // ---------------------------------------------------------------- schedule tab
  function loadScheduleTab() {
    var root = $('tab-schedule');
    clear(root);
    var card = h('div', { class: 'card', id: 'schedule-card' }, h('h2', {}, 'Weekly check (Scheduled Task)'), h('p', { class: 'muted' }, 'Loading...'));
    root.append(card);
    loadSchedule(card);
  }

  // The weekly check (Test-Wheelhouse.ps1) as a Windows Scheduled Task.
  function loadSchedule(card) {
    api('GET', '/api/schedule').then(function (s) {
      clear(card);
      card.append(h('h2', {}, 'Weekly check (Scheduled Task)'),
        h('p', { class: 'muted' }, 'Test-Wheelhouse.ps1 re-checks everything published and sends the alerts. It should run at least weekly, under an account that can read and write the wheelhouse share.'));
      if (s.mapped_drive) {
        var useUnc = h('button', { class: 'btn small', type: 'button' }, 'Use ' + s.mapped_drive.unc);
        useUnc.addEventListener('click', function () {
          api('POST', '/api/settings', { updates: { WheelhousePath: s.mapped_drive.unc } }).then(function () {
            toast('Wheelhouse folder changed to ' + s.mapped_drive.unc + '.');
            refreshState().then(loadScheduleTab);
          }).catch(fail);
        });
        card.append(h('div', { class: 'banner bad' }, 'The wheelhouse folder is set to ' + s.wheelhouse_path + ', a mapped network drive (' + s.mapped_drive.drive + ' = ' + s.mapped_drive.unc +
          '). A Scheduled Task does not see the drive mappings of your session, so the weekly check would fail. Use the UNC path instead. ', useUnc));
      }
      var status;
      if (s.registered) {
        status = h('div', { class: 'kv' },
          h('div', {}, h('strong', {}, 'Status: '), badge(s.state || 'registered', s.state === 'Disabled' ? 'bad' : 'ok'), s.for_this_installation ? '' : [' ', badge('runs another installation', 'warn', 'The task does not start ' + s.script)]),
          h('div', {}, h('strong', {}, 'Runs: '), (s.days.length ? [].concat(s.days).join(', ') : 'custom schedule') + (s.time ? ' at ' + s.time : '') + ' as ' + s.user),
          h('div', {}, h('strong', {}, 'Last run: '), s.last_run_utc ? fmtDate(s.last_run_utc) + ' - ' + s.last_result : 'not yet'),
          h('div', {}, h('strong', {}, 'Next run: '), s.next_run_utc ? fmtDate(s.next_run_utc) : '-'),
          h('div', {}, h('strong', {}, 'Last completed check: '), s.last_check_utc ? fmtDate(s.last_check_utc) : 'never'));
      } else {
        status = h('div', { class: 'banner' }, 'Not registered yet. Fill in the form below and click Register.');
      }
      card.append(status);

      var dayNames = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
      var chosen = s.registered && s.days.length ? [].concat(s.days) : ['Sunday'];
      var dayBoxes = dayNames.map(function (d) { return { day: d, box: h('input', { type: 'checkbox', checked: chosen.indexOf(d) >= 0 }) }; });
      var time = h('input', { type: 'time', value: s.time || '02:00' });
      var user = h('input', { type: 'text', class: 'wide', value: s.user || s.current_user, autocomplete: 'off' });
      var password = h('input', { type: 'password', class: 'wide', autocomplete: 'new-password', placeholder: 'password of this account' });
      var register = h('button', { class: 'btn primary', type: 'button' }, s.registered ? 'Update the task' : 'Register the task');
      register.addEventListener('click', function () {
        var days = dayBoxes.filter(function (b) { return b.box.checked; }).map(function (b) { return b.day; });
        register.disabled = true;
        api('POST', '/api/schedule', { days: days, time: time.value, user: user.value.trim(), password: password.value }).then(function (res) {
          password.value = '';
          toast('Weekly check registered' + (res.next_run_utc ? ' - next run ' + fmtDate(res.next_run_utc) : '') + '.');
          loadSchedule(card);
        }).catch(function (err) { register.disabled = false; fail(err); });
      });
      var form = h('div', {},
        h('div', { class: 'field' }, h('label', {}, 'Days'), h('div', { class: 'checks' }, dayBoxes.map(function (b) { return h('label', {}, b.box, ' ' + b.day.slice(0, 3)); }))),
        h('div', { class: 'field' }, h('label', {}, 'Time'), h('div', {}, time, h('div', { class: 'help' }, 'Local time of this server. A run missed while the server was off starts as soon as possible.'))),
        h('div', { class: 'field' }, h('label', {}, 'Account'), h('div', {}, user, h('div', { class: 'help' }, 'DOMAIN\\user or user@domain. It needs read/write access to the wheelhouse share and network access to PyPI and OSV; no administrator rights. Registering a task for another account needs the UI started as administrator.'))),
        h('div', { class: 'field' }, h('label', {}, 'Password'), h('div', {}, password, h('div', { class: 'help' }, 'Required so the task can reach the share while nobody is logged on. It is handed to Windows Task Scheduler and not stored or logged by Wheelhouse Manager. Enter it again whenever you update the task or the password changes.'))));
      var actions = h('div', { class: 'toolbar after-output' }, register);
      if (s.registered) {
        var run = h('button', { class: 'btn', type: 'button' }, 'Run now');
        run.addEventListener('click', function () {
          api('POST', '/api/schedule/run', {}).then(function () {
            toast('The weekly check was started by Task Scheduler. Its result appears here and in the Packages tab when it finishes.');
            setTimeout(function () { loadSchedule(card); }, 3000);
          }).catch(fail);
        });
        var remove = h('button', { class: 'btn danger', type: 'button' }, 'Remove the task');
        remove.addEventListener('click', function () {
          confirmDialog('Remove the weekly check?', h('p', {}, 'Published packages are then no longer re-checked automatically and no alerts are sent.'), 'Remove', true).then(function (ok) {
            if (!ok) { return; }
            api('POST', '/api/schedule/remove', { confirm: true }).then(function () { toast('Weekly check removed.'); loadSchedule(card); }).catch(fail);
          });
        });
        actions.append(run, remove);
      }
      card.append(form, actions);

    }).catch(function (err) { clear(card); card.append(h('h2', {}, 'Weekly check (Scheduled Task)'), h('div', { class: 'empty' }, err.message)); });
  }

  // ---------------------------------------------------------------- jobs
  // Succeeded / Running / Attention (findings or rejected packages) / Failed / Cancelled.
  function jobKind(status) {
    return status === 'Succeeded' ? 'ok' : (status === 'Running' || status === 'Attention') ? 'warn' : 'bad';
  }
  function jobLabel(status) {
    return status === 'Failed' ? 'Failed' : status === 'Attention' ? 'Needs attention' : status;
  }
  function jobBadge(job) {
    return badge(jobLabel(job.status), jobKind(job.status), job.message);
  }

  // A job's action, and a small button that lists what it worked on (packages, files).
  function jobTitleCell(job) {
    var detail = [].concat(job.detail || []);
    if (detail.length === 0) { return job.title; }
    var list = h('ul', { class: 'result-list job-detail hidden' }, detail.map(function (d) { return h('li', { class: 'mono' }, d); }));
    var label = function (show) { return show ? 'show' : 'hide'; };
    var more = h('button', { class: 'link-toggle', type: 'button', 'aria-expanded': 'false' }, label(true));
    more.addEventListener('click', function () {
      var show = list.classList.contains('hidden');
      list.classList.toggle('hidden', !show);
      more.textContent = label(!show);
      more.setAttribute('aria-expanded', show ? 'true' : 'false');
    });
    return h('div', {}, h('div', {}, job.title), more, list);
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
          return h('tr', {}, h('td', {}, j.id), h('td', {}, jobTitleCell(j)), h('td', {}, jobBadge(j)), h('td', {}, fmtDate(j.started_utc)), h('td', {}, fmtDate(j.ended_utc)),
            h('td', {}, h('button', { class: 'btn small', type: 'button', onclick: function () { watchJob(j.id, true); } }, 'Open log')));
        })))));
    }).catch(function (err) { clear(root); root.append(h('div', { class: 'empty' }, err.message)); });
  }

  // Follows a job. Actions only start following it - the pulsing indicator in the top bar
  // shows it is running and opens the log on click; "open" shows the log panel at once
  // (Jobs tab, "Open the log" links).
  function watchJob(id, open) {
    if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
    if (state.watchedJob !== id) { $('jobbar-log').textContent = ''; }
    state.watchedJob = id;
    if (open) { showJobPanel(true); }
    pollJob(true);
  }
  function showJobPanel(show) {
    $('jobbar').classList.toggle('hidden', !show);
    if (show) {
      $('jobbar-log').classList.remove('collapsed');
      $('jobbar-toggle').textContent = 'Hide log';
      var log = $('jobbar-log');
      log.scrollTop = log.scrollHeight;
    }
    renderJobIndicator(state.lastJob);
  }
  // The top bar pill: pulsing while the followed job runs, its result when it ended.
  function renderJobIndicator(job) {
    var pill = $('job-indicator');
    if (!job || state.watchedJob === null) { pill.className = 'job-indicator hidden'; return; }
    var open = !$('jobbar').classList.contains('hidden');
    var running = job.status === 'Running';
    pill.className = 'job-indicator ' + (running ? 'running' : jobKind(job.status));
    pill.title = open ? 'Hide the log' : 'Show the log';
    clear(pill);
    pill.append(h('span', { class: 'dot' }), (running ? 'Running: ' : jobLabel(job.status) + ': ') + job.title, h('span', { class: 'pill-action' }, open ? 'hide log' : 'view log'));
  }

  function pollJob(first) {
    var id = state.watchedJob;
    if (id === null) { return; }
    api('GET', '/api/jobs/' + id).then(function (data) {
      if (state.watchedJob !== id) { return; }
      var job = data.job;
      state.lastJob = job;
      setJobRunning(job.status === 'Running');
      renderJobIndicator(job);
      $('jobbar-title').textContent = '#' + job.id + '  ' + job.title + (job.steps > 1 ? '  (step ' + job.step + '/' + job.steps + ')' : '');
      var state_ = $('jobbar-state');
      state_.textContent = jobLabel(job.status);
      state_.className = 'badge ' + jobKind(job.status);
      $('jobbar-cancel').classList.toggle('hidden', job.status !== 'Running');
      var log = $('jobbar-log');
      var atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
      log.textContent = job.log || '';
      if (atBottom || first) { log.scrollTop = log.scrollHeight; }

      if (job.status === 'Running') {
        state.pollTimer = setTimeout(function () { pollJob(false); }, 1500);
      } else {
        state.pollTimer = null;
        if (!first) { toast(job.title + ': ' + (job.status === 'Succeeded' ? 'finished.' : job.message), job.status === 'Succeeded' ? 'ok' : 'bad', jobNextStep(job)); }
        onJobFinished(job);
      }
    }).catch(function (err) {
      $('jobbar-state').textContent = 'lost';
      setJobRunning(false);
      toast(err.message, 'bad');
    });
  }

  // While a job runs, every button that would start another job or change the wheelhouse
  // (marked data-idle) looks disabled and its clicks are swallowed: the server refuses them anyway.
  function setJobRunning(running) {
    document.body.classList.toggle('job-running', !!running);
    // While a job runs, requirements.in cannot be edited either (step 1 of the Add tab).
    var box = $('requirements-in');
    if (box) { box.readOnly = !!running; }
    showBusy();
  }
  document.addEventListener('click', function (e) {
    if (!document.body.classList.contains('job-running')) { return; }
    var target = e.target && e.target.closest ? e.target.closest('[data-idle]') : null;
    if (!target) { return; }
    e.preventDefault();
    e.stopImmediatePropagation();
    toast('A job is still running. Wait for it to finish (or cancel it) first.', 'warn');
  }, true);

  function onJobFinished(job) {
    if (state.currentTab === 'packages') { loadPackages(); }
    else if (state.currentTab === 'jobs') { loadJobs(); }
    else if (state.currentTab === 'add') {
      // After a successful "Save and resolve", the next step is reviewing the result.
      var next = job.kind === 'add' && job.status === 'Succeeded';
      if (job.kind === 'remediate' && job.status === 'Succeeded') { next = 'fix'; }
      loadRequirements(next);
      loadRequirementsIn();
      loadRejected();
    }
    if (job.kind === 'remediate' && job.status === 'Succeeded' && state.currentTab !== 'add') {
      state.reviewFix = true;
    }
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
      // A running job is still followed (the indicator stays); a finished one is let go.
      if (!state.lastJob || state.lastJob.status !== 'Running') {
        state.watchedJob = null;
        if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
      }
      showJobPanel(false);
    });
    $('job-indicator').addEventListener('click', function () {
      showJobPanel($('jobbar').classList.contains('hidden'));
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
      var tabs = ['overview', 'packages', 'add', 'audit', 'quarantine', 'denylist', 'schedule', 'settings', 'jobs'];
      var wanted = location.hash.replace('#', '');
      if (!info.configured) { showTab('settings'); }
      else { showTab(tabs.indexOf(wanted) >= 0 ? wanted : 'overview'); }
      if (info.running_job) { setJobRunning(true); watchJob(info.running_job.id, false); }
    });
  }

  init();
})();
