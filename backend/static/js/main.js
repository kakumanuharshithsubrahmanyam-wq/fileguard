/* ==========================================================
   FILEGUARD — integrated frontend (same-origin REST API)
   ========================================================== */
(function () {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const PAGE = document.body.dataset.page || '';
  const MAX_SIZE = 50 * 1024 * 1024;

  class ApiError extends Error {
    constructor(message, status, data) {
      super(message);
      this.name = 'ApiError';
      this.status = status;
      this.data = data;
    }
  }

  /* ---------- Shared helpers ---------- */
  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function showToast(msg, type = 'info', ms = 3200) {
    const box = $('#toasts');
    if (!box) return;
    const icons = {
      success: 'fa-circle-check',
      error: 'fa-circle-xmark',
      warning: 'fa-triangle-exclamation',
      info: 'fa-circle-info',
    };
    const t = document.createElement('div');
    t.className = 'toast toast--' + type;
    t.innerHTML =
      '<i class="fa-solid ' +
      (icons[type] || icons.info) +
      '"></i><span></span>';
    t.lastChild.textContent = msg;
    box.appendChild(t);
    requestAnimationFrame(() => t.classList.add('show'));
    setTimeout(() => {
      t.classList.remove('show');
      setTimeout(() => t.remove(), 250);
    }, ms);
  }

  async function apiFetch(url, options = {}) {
    try {
      const response = await fetch(url, options);
      let data = null;
      const ct = response.headers.get('content-type') || '';
      if (ct.includes('application/json')) {
        data = await response.json();
      }
      if (!response.ok) {
        const msg = data && data.error ? data.error : 'Request failed.';
        throw new ApiError(msg, response.status, data);
      }
      if (data && data.success === false) {
        throw new ApiError(data.error || 'Request failed.', response.status, data);
      }
      return data;
    } catch (err) {
      if (err instanceof ApiError) throw err;
      throw new ApiError('Unable to connect to FileGuard.', 0, null);
    }
  }

  function formatSize(bytes) {
    if (bytes == null || isNaN(bytes)) return '—';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  const MONTHS = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
  ];

  function formatDateTime(value) {
    if (!value) return '—';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '—';
    const h = d.getHours();
    const mm = String(d.getMinutes()).padStart(2, '0');
    return (
      d.getDate() +
      ' ' +
      MONTHS[d.getMonth()] +
      ' ' +
      d.getFullYear() +
      ', ' +
      String(h % 12 || 12).padStart(2, '0') +
      ':' +
      mm +
      ' ' +
      (h >= 12 ? 'PM' : 'AM')
    );
  }

  function formatDateShort(value) {
    if (!value) return '—';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '—';
    return d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' + d.getFullYear();
  }

  function shortenHash(hash) {
    if (!hash || hash.length < 20) return hash || '—';
    return hash.slice(0, 8) + '...' + hash.slice(-9);
  }

  function setButtonLoading(btn, on) {
    if (!btn) return;
    btn.classList.toggle('is-loading', on);
    btn.disabled = on;
  }

  function fileDetailsPath(fileId) {
    if (!fileId) return null;
    return '/files/' + encodeURIComponent(fileId);
  }

  const TYPES = {
    pdf: ['PDF', 'fa-file-pdf ico-pdf'],
    doc: ['DOC', 'fa-file-word ico-doc'],
    docx: ['DOCX', 'fa-file-word ico-doc'],
    xls: ['XLS', 'fa-file-excel ico-xls'],
    xlsx: ['XLSX', 'fa-file-excel ico-xls'],
    csv: ['CSV', 'fa-file-csv ico-xls'],
    txt: ['TXT', 'fa-file-lines ico-gen'],
    zip: ['ZIP', 'fa-file-zipper ico-zip'],
    png: ['PNG', 'fa-file-image ico-gen'],
    jpg: ['JPG', 'fa-file-image ico-gen'],
    jpeg: ['JPEG', 'fa-file-image ico-gen'],
    py: ['PY', 'fa-file-code ico-gen'],
    js: ['JS', 'fa-file-code ico-gen'],
    html: ['HTML', 'fa-file-code ico-gen'],
  };

  function fileIconClass(filename, fileType) {
    const ext = (String(filename || '').split('.').pop() || '').toLowerCase();
    if (TYPES[ext]) return TYPES[ext][1];
    if (fileType && fileType !== 'UNKNOWN') return 'fa-file ico-gen';
    return 'fa-file ico-gen';
  }

  function fileKindLabel(filename, fileType) {
    const ext = (String(filename || '').split('.').pop() || '').toLowerCase();
    if (TYPES[ext]) return TYPES[ext][0];
    if (fileType) return fileType;
    return 'File';
  }

  function statusBadgeHtml(status) {
    if (status === 'VERIFIED') {
      return '<span class="badge badge--ok">VERIFIED</span>';
    }
    if (status === 'TAMPERED') {
      return '<span class="badge badge--bad">TAMPERED</span>';
    }
    if (status === 'NOT_REGISTERED') {
      return '<span class="badge badge--warn">NOT REGISTERED</span>';
    }
    if (status === 'REGISTERED') {
      return '<span class="badge badge--info">REGISTERED</span>';
    }
    return '<span class="badge badge--info">NOT CHECKED</span>';
  }

  function registryRowStatusKey(latestStatus) {
    if (latestStatus === 'VERIFIED') return 'verified';
    if (latestStatus === 'TAMPERED') return 'tampered';
    return 'unchecked';
  }

  function handleApiError(err, fallback) {
    if (err instanceof ApiError) {
      if (err.status === 413) {
        showToast('File exceeds the 50 MB upload limit.', 'error');
        return;
      }
      showToast(err.message || fallback, 'error');
      return;
    }
    showToast(fallback, 'error');
  }

  /* ---------- Hash rendering ---------- */
  function renderHashes(root) {
    const scope = root || document;
    $$('.hash[data-hash]', scope).forEach((el) => {
      const h = el.dataset.hash || '';
      const other = el.dataset.diffAgainst || '';
      const mk = (s, off) => {
        if (!other) return document.createTextNode(s);
        const frag = document.createDocumentFragment();
        [...s].forEach((c, i) => {
          if (c !== other[off + i]) {
            const m = document.createElement('mark');
            m.className = 'diff';
            m.textContent = c;
            frag.appendChild(m);
          } else {
            frag.appendChild(document.createTextNode(c));
          }
        });
        return frag;
      };
      el.textContent = '';
      if (!h) return;
      [
        [0, 32],
        [32, 64],
      ].forEach(([a, b]) => {
        const line = document.createElement('span');
        line.className = 'ln';
        line.appendChild(mk(h.slice(a, b), a));
        el.appendChild(line);
      });
    });
  }

  function setHashElement(el, hash, diffAgainst) {
    if (!el) return;
    el.dataset.hash = hash || '';
    if (diffAgainst !== undefined) {
      if (diffAgainst) el.dataset.diffAgainst = diffAgainst;
      else delete el.dataset.diffAgainst;
    }
  }

  /* ---------- Copy hash ---------- */
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try {
        ok = document.execCommand('copy');
      } catch (__) {}
      ta.remove();
      return ok;
    }
  }

  function initCopy() {
    $$('[data-copy]').forEach((btn) =>
      btn.addEventListener('click', async () => {
        const target = $(btn.dataset.copy);
        const text = target
          ? target.dataset.hash || target.textContent.trim()
          : '';
        if (!text) {
          showToast('Nothing to copy.', 'warning');
          return;
        }
        const ok = await copyText(text);
        if (!ok) {
          showToast('Copy failed. Select the hash and copy it manually.', 'error');
          return;
        }
        const label = $('span', btn);
        const old = label ? label.textContent : '';
        btn.classList.add('copied');
        if (label) label.textContent = 'Copied!';
        showToast('SHA-256 hash copied to clipboard.', 'success', 2000);
        setTimeout(() => {
          btn.classList.remove('copied');
          if (label) label.textContent = old;
        }, 1800);
      })
    );
  }

  /* ---------- Sidebar ---------- */
  function initSidebar() {
    const close = () => document.body.classList.remove('nav-open');
    $('#menuBtn')?.addEventListener('click', () =>
      document.body.classList.toggle('nav-open')
    );
    $('#overlay')?.addEventListener('click', close);
    $$('.nav-link').forEach((a) => a.addEventListener('click', close));
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') close();
    });
    window.addEventListener('resize', () => {
      if (window.innerWidth > 1024) close();
    });
  }

  /* ---------- Health ---------- */
  async function initHealth() {
    const sysState = $('#sysState');
    const sysPill = $('#sysPill');
    try {
      await apiFetch('/api/health');
    } catch (_) {
      if (sysState) {
        sysState.innerHTML =
          '<span class="dot dot--bad"></span>Service Unavailable';
      }
      if (sysPill) {
        sysPill.innerHTML =
          '<span class="dot dot--bad"></span>Service Unavailable';
      }
    }
  }

  /* ---------- Dropzone ---------- */
  function initDropzone() {
    const zone = $('#dropzone');
    const input = $('#fileInput');
    if (!zone || !input) return null;
    const preview = $('#filePreview');
    const state = { file: null, onChange: () => {} };

    function set(file) {
      if (!file) return;
      if (file.size > MAX_SIZE) {
        showToast('File is larger than 50 MB. Choose a smaller file.', 'error');
        return;
      }
      state.file = file;
      const icon = fileIconClass(file.name).split(' ').slice(-2).join(' ');
      $('#fpName').textContent = file.name;
      $('#fpMeta').textContent =
        fileKindLabel(file.name) + ' • ' + formatSize(file.size);
      $('#fpIcon').className = 'fa-solid ' + icon;
      preview.hidden = false;
      state.onChange(file);
    }
    function clear() {
      state.file = null;
      input.value = '';
      preview.hidden = true;
      state.onChange(null);
    }
    state.clear = clear;

    zone.addEventListener('click', (e) => {
      if (
        e.target.closest('[data-browse]') ||
        e.target === zone ||
        zone.contains(e.target)
      ) {
        input.click();
      }
    });
    zone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        input.click();
      }
    });
    input.addEventListener('click', (e) => e.stopPropagation());
    input.addEventListener('change', () => set(input.files[0]));
    ['dragenter', 'dragover'].forEach((ev) =>
      zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
      })
    );
    ['dragleave', 'drop'].forEach((ev) =>
      zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
      })
    );
    zone.addEventListener('drop', (e) => set(e.dataTransfer.files[0]));
    $('#fpRemove')?.addEventListener('click', clear);
    ['dragover', 'drop'].forEach((ev) =>
      window.addEventListener(ev, (e) => {
        if (!zone.contains(e.target)) e.preventDefault();
      })
    );
    return state;
  }

  /* ---------- Dashboard ---------- */
  async function initDashboard() {
    if (PAGE !== 'dashboard') return;
    try {
      const data = await apiFetch('/api/dashboard');
      const stats = data.stats || {};
      const overview = data.integrity_overview || {};
      $('#dashTotalFiles').textContent = stats.total_files ?? 0;
      $('#dashVerified').textContent = stats.successful_verifications ?? 0;
      $('#dashTampered').textContent = stats.tampering_detected ?? 0;
      $('#dashVerifications').textContent = stats.total_verifications ?? 0;
      $('#dashOverviewLabel').textContent =
        (stats.total_files ?? 0) + ' registered files';

      const v = overview.verified || 0;
      const t = overview.tampered || 0;
      const n = overview.not_registered || 0;
      const total = v + t + n;
      const pct = (x) => (total ? Math.round((x / total) * 1000) / 10 : 0);
      const pv = pct(v);
      const pt = pct(t);
      const pn = total ? Math.max(0, 100 - pv - pt) : 0;
      $('#meterVerified').style.width = pv + '%';
      $('#meterTampered').style.width = pt + '%';
      $('#meterOther').style.width = pn + '%';
      $('#pctVerified').textContent = pv + '%';
      $('#pctTampered').textContent = pt + '%';
      $('#pctOther').textContent = pn + '%';
      $('#legendVerified').textContent = v + ' checks';
      $('#legendTampered').textContent = t + ' checks';
      $('#legendOther').textContent = n + ' checks';

      const tbody = $('#dashActivityBody');
      const empty = $('#dashActivityEmpty');
      const activity = data.recent_activity || [];
      tbody.innerHTML = '';
      if (!activity.length) {
        empty.hidden = false;
        return;
      }
      empty.hidden = true;
      activity.forEach((item) => {
        const tr = document.createElement('tr');
        const action =
          item.event === 'registration'
            ? 'File Registration'
            : 'Integrity Verification';
        const icon = fileIconClass(item.filename);
        tr.innerHTML =
          '<td class="fname"><i class="fa-solid ' +
          escapeHtml(icon) +
          '"></i>' +
          escapeHtml(item.filename || '—') +
          '</td><td>' +
          escapeHtml(action) +
          '</td><td>' +
          statusBadgeHtml(item.status) +
          '</td><td>' +
          escapeHtml(formatDateTime(item.timestamp)) +
          '</td>';
        tbody.appendChild(tr);
      });
    } catch (err) {
      handleApiError(err, 'Could not load dashboard.');
    }
  }

  /* ---------- Register ---------- */
  function initRegister() {
    if (PAGE !== 'register') return;
    const btn = $('#registerBtn');
    if (!btn) return;
    const dz = initDropzone();
    const form = $('#registerForm');
    const loading = $('#loadingPanel');
    const success = $('#registerSuccess');

    btn.addEventListener('click', async () => {
      if (!dz.file) {
        showToast('No file selected.', 'warning');
        return;
      }
      setButtonLoading(btn, true);
      form.hidden = true;
      loading.hidden = false;
      success.hidden = true;

      const formData = new FormData();
      formData.append('file', dz.file);
      try {
        const data = await apiFetch('/api/files/register', {
          method: 'POST',
          body: formData,
        });
        const file = data.file || {};
        $('#rsId').textContent = file.file_id || '—';
        $('#rsName').textContent = file.filename || '—';
        $('#rsSize').textContent =
          file.file_size_formatted || formatSize(file.file_size);
        $('#rsDate').textContent = formatDateTime(file.registered_at);
        const dup = $('#rsDuplicateNote');
        if (dup) dup.hidden = !data.already_registered;
        setHashElement($('#rsHash'), file.sha256_hash);
        loading.hidden = true;
        success.hidden = false;
        renderHashes(success);
        showToast(
          data.already_registered
            ? 'Existing integrity record loaded.'
            : 'File registered successfully.',
          'success'
        );
      } catch (err) {
        form.hidden = false;
        loading.hidden = true;
        handleApiError(err, 'Registration failed.');
      } finally {
        setButtonLoading(btn, false);
      }
    });

    $('#registerAnother')?.addEventListener('click', () => {
      dz.clear();
      success.hidden = true;
      form.hidden = false;
      const dup = $('#rsDuplicateNote');
      if (dup) dup.hidden = true;
    });
  }

  /* ---------- Verify ---------- */
  function initVerify() {
    if (PAGE !== 'verify') return;
    const btn = $('#verifyBtn');
    if (!btn) return;
    const dz = initDropzone();
    const form = $('#verifyForm');
    const loading = $('#loadingPanel');
    const results = $('#verifyResults');
    const kinds = ['verified', 'tampered', 'unregistered'];

    function showPanel(kind) {
      kinds.forEach((k) => {
        const el = $('#res-' + k);
        if (el) el.hidden = k !== kind;
      });
      form.hidden = true;
      loading.hidden = true;
      results.hidden = false;
      renderHashes(results);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function reset() {
      results.hidden = true;
      loading.hidden = true;
      form.hidden = false;
      if (dz) dz.clear();
    }

    function fillVerified(data) {
      const file = data.file || {};
      $('#vOkName').textContent = file.filename || '—';
      $('#vOkFileId').textContent = file.file_id || '—';
      $('#vOkVerId').textContent = data.verification_id || '—';
      $('#vOkRegistered').textContent = formatDateTime(data.registered_at);
      $('#vOkVerified').textContent = formatDateTime(data.verified_at);
      setHashElement($('#vOkStored'), data.stored_hash);
      setHashElement($('#vOkCurrent'), data.current_hash);
      const link = $('#vOkViewRecord');
      const path = fileDetailsPath(file.file_id);
      if (link && path) link.href = path;
    }

    function fillTampered(data) {
      const file = data.file || {};
      $('#vBadName').textContent = file.filename || '—';
      $('#vBadFileId').textContent = file.file_id || '—';
      $('#vBadVerId').textContent = data.verification_id || '—';
      $('#vBadRegistered').textContent = formatDateTime(data.registered_at);
      $('#vBadVerified').textContent = formatDateTime(data.verified_at);
      setHashElement($('#vBadStored'), data.stored_hash, data.current_hash);
      setHashElement($('#vBadCurrent'), data.current_hash, data.stored_hash);
      const link = $('#vBadViewRecord');
      const path = fileDetailsPath(file.file_id);
      if (link && path) link.href = path;
    }

    function fillUnregistered(data) {
      $('#vUnregName').textContent = data.filename || '—';
      $('#vUnregVerId').textContent = data.verification_id || '—';
      $('#vUnregVerified').textContent = formatDateTime(data.verified_at);
      setHashElement($('#vUnregHash'), data.current_hash);
    }

    btn.addEventListener('click', async () => {
      if (!dz.file) {
        showToast('No file selected.', 'warning');
        return;
      }
      setButtonLoading(btn, true);
      form.hidden = true;
      loading.hidden = false;
      results.hidden = true;

      const formData = new FormData();
      formData.append('file', dz.file);
      try {
        const data = await apiFetch('/api/files/verify', {
          method: 'POST',
          body: formData,
        });
        if (data.status === 'VERIFIED') {
          fillVerified(data);
          showPanel('verified');
          showToast('File integrity verified.', 'success');
        } else if (data.status === 'TAMPERED') {
          fillTampered(data);
          showPanel('tampered');
          showToast('Tampering detected.', 'error');
        } else if (data.status === 'NOT_REGISTERED') {
          fillUnregistered(data);
          showPanel('unregistered');
          showToast('File is not registered.', 'warning');
        } else {
          throw new ApiError('Unexpected verification response.', 200, data);
        }
      } catch (err) {
        form.hidden = false;
        loading.hidden = true;
        handleApiError(err, 'Verification failed.');
      } finally {
        setButtonLoading(btn, false);
      }
    });

    $$('[data-reset]').forEach((b) => b.addEventListener('click', reset));
  }

  /* ---------- File registry ---------- */
  function initRegistry() {
    if (PAGE !== 'files') return;
    const tbody = $('#registryBody');
    const table = $('#dataTable');
    const search = $('#tableSearch');
    if (!tbody || !search) return;

    let allFiles = [];
    let filter = 'all';
    let searchTimer = null;

    function renderRows(files) {
      tbody.innerHTML = '';
      const filtered = files.filter((f) => {
        const key = registryRowStatusKey(f.latest_status);
        return filter === 'all' || filter === key;
      });

      filtered.forEach((f) => {
        const tr = document.createElement('tr');
        tr.dataset.status = registryRowStatusKey(f.latest_status);
        const icon = fileIconClass(f.filename, f.file_type);
        const path = fileDetailsPath(f.file_id);
        tr.innerHTML =
          '<td class="mono">' +
          escapeHtml(f.file_id) +
          '</td><td class="fname"><i class="fa-solid ' +
          escapeHtml(icon) +
          '"></i>' +
          escapeHtml(f.filename) +
          '</td><td>' +
          escapeHtml(f.file_type || '—') +
          '</td><td>' +
          escapeHtml(f.file_size_formatted || formatSize(f.file_size)) +
          '</td><td class="mono hash-short" data-tip="' +
          escapeHtml(f.sha256_hash) +
          '">' +
          escapeHtml(shortenHash(f.sha256_hash)) +
          '</td><td>' +
          escapeHtml(formatDateShort(f.registered_at)) +
          '</td><td>' +
          statusBadgeHtml(f.latest_status) +
          '</td><td><a class="btn btn--sm btn--outline" href="' +
          escapeHtml(path) +
          '">View</a></td>';
        tbody.appendChild(tr);
      });

      const total = allFiles.length;
      const shown = filtered.length;
      $('#rowCount').textContent =
        'Showing ' + shown + ' of ' + total + ' files';
      $('#emptyRegistry').hidden = total > 0;
      $('#emptyFilter').hidden = total === 0 || shown > 0;
      table.style.display = total === 0 || shown > 0 ? '' : 'none';
    }

    async function loadFiles(query) {
      try {
        let data;
        if (query) {
          data = await apiFetch(
            '/api/files/search?q=' + encodeURIComponent(query)
          );
        } else {
          data = await apiFetch('/api/files');
        }
        allFiles = data.files || [];
        renderRows(allFiles);
      } catch (err) {
        handleApiError(err, 'Could not load file registry.');
      }
    }

    search.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        const q = search.value.trim();
        loadFiles(q || null);
      }, 300);
    });

    $$('[data-filter]').forEach((b) =>
      b.addEventListener('click', () => {
        filter = b.dataset.filter;
        $$('[data-filter]').forEach((x) =>
          x.classList.toggle('active', x === b)
        );
        renderRows(allFiles);
      })
    );

    loadFiles(null);
  }

  /* ---------- Verification history ---------- */
  function initHistory() {
    if (PAGE !== 'history') return;
    const tbody = $('#historyBody');
    if (!tbody) return;
    let historyFilter = 'all';

    async function loadHistoryStats() {
      try {
        const data = await apiFetch('/api/dashboard');
        const stats = data.stats || {};
        const overview = data.integrity_overview || {};
        $('#histTotal').textContent = stats.total_verifications ?? 0;
        $('#histVerified').textContent = overview.verified ?? 0;
        $('#histTampered').textContent = overview.tampered ?? 0;
      } catch (err) {
        handleApiError(err, 'Could not load history summary.');
      }
    }

    async function loadHistory() {
      let url = '/api/history';
      if (historyFilter !== 'all') {
        url += '?status=' + encodeURIComponent(historyFilter);
      }
      try {
        const data = await apiFetch(url);
        const rows = data.history || [];
        tbody.innerHTML = '';
        const empty = $('#historyEmpty');
        if (!rows.length) {
          empty.hidden = false;
          $('#historyCount').textContent =
            'Showing 0 of 0 verifications';
          return;
        }
        empty.hidden = true;
        rows.forEach((row) => {
          const tr = document.createElement('tr');
          const icon = fileIconClass(row.filename);
          let actionHtml = '—';
          if (row.file_id) {
            const path = fileDetailsPath(row.file_id);
            actionHtml =
              '<a class="btn btn--sm btn--outline" href="' +
              escapeHtml(path) +
              '">View Details</a>';
          } else if (row.status === 'NOT_REGISTERED') {
            actionHtml =
              '<a class="btn btn--sm btn--outline" href="/register">Register</a>';
          }
          tr.innerHTML =
            '<td class="mono">' +
            escapeHtml(row.verification_id) +
            '</td><td class="fname"><i class="fa-solid ' +
            escapeHtml(icon) +
            '"></i>' +
            escapeHtml(row.filename) +
            '</td><td class="mono">' +
            escapeHtml(row.file_id || '—') +
            '</td><td>' +
            statusBadgeHtml(row.status) +
            '</td><td>' +
            escapeHtml(formatDateTime(row.verified_at)) +
            '</td><td>' +
            actionHtml +
            '</td>';
          tbody.appendChild(tr);
        });
        $('#historyCount').textContent =
          'Showing ' + rows.length + ' of ' + rows.length + ' verifications';
      } catch (err) {
        handleApiError(err, 'Could not load verification history.');
      }
    }

    $$('[data-history-filter]').forEach((b) =>
      b.addEventListener('click', () => {
        historyFilter = b.dataset.historyFilter;
        $$('[data-history-filter]').forEach((x) =>
          x.classList.toggle('active', x === b)
        );
        loadHistory();
      })
    );

    loadHistoryStats();
    loadHistory();
  }

  /* ---------- File details ---------- */
  async function initDetails() {
    const wrap = $('#detailsContent');
    if (!wrap || !wrap.dataset.fileId) return;

    const fileId = wrap.dataset.fileId;
    const notFound = $('#detailsNotFound');

    try {
      const data = await apiFetch('/api/files/' + encodeURIComponent(fileId));
      const file = data.file || {};
      wrap.hidden = false;
      if (notFound) notFound.hidden = true;

      $$('[data-f]', wrap).forEach((el) => {
        const k = el.dataset.f;
        if (k === 'id') el.textContent = file.file_id || '—';
        else if (k === 'name') el.textContent = file.filename || '—';
        else if (k === 'type') {
          el.textContent =
            fileKindLabel(file.filename, file.file_type) +
            (file.file_type ? ' (' + file.file_type + ')' : '');
        } else if (k === 'size') {
          el.textContent =
            file.file_size_formatted || formatSize(file.file_size);
        } else if (k === 'reg') {
          el.textContent = formatDateTime(file.registered_at);
        } else if (k === 'attempts') {
          el.textContent = String(file.verification_attempts ?? 0);
        } else if (k === 'last') {
          el.textContent = file.last_verified
            ? formatDateTime(file.last_verified)
            : '—';
        }
      });

      setHashElement($('#detailHash'), file.sha256_hash);
      renderHashes(wrap);

      const card = $('#statusCard');
      const status = file.last_status;
      const bad = status === 'TAMPERED';
      const ok = status === 'VERIFIED';
      card.classList.toggle('status-card--bad', bad);
      card.classList.toggle('status-card--ok', ok || !status);
      $('#statusText').textContent = status || 'NOT CHECKED';
      $('#statusIcon').className =
        'fa-solid ' +
        (bad
          ? 'fa-triangle-exclamation'
          : ok
            ? 'fa-circle-check'
            : 'fa-circle-question');

      const histBody = $('#detailHistory');
      const histEmpty = $('#detailHistoryEmpty');
      const history = file.recent_verifications || [];
      histBody.innerHTML = '';
      if (!history.length) {
        if (histEmpty) histEmpty.hidden = false;
      } else {
        if (histEmpty) histEmpty.hidden = true;
        history.forEach((item) => {
          const match =
            item.status === 'VERIFIED' &&
            item.stored_hash &&
            item.current_hash === item.stored_hash;
          const tr = document.createElement('tr');
          tr.innerHTML =
            '<td>' +
            escapeHtml(formatDateTime(item.verified_at)) +
            '</td><td>' +
            (item.status === 'NOT_REGISTERED'
              ? '<span class="muted">No registered fingerprint</span>'
              : match
                ? '<i class="fa-solid fa-check text-ok"></i> Hash match'
                : '<i class="fa-solid fa-xmark text-bad"></i> Hash mismatch') +
            '</td><td>' +
            statusBadgeHtml(item.status) +
            '</td>';
          histBody.appendChild(tr);
        });
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        wrap.hidden = true;
        if (notFound) notFound.hidden = false;
        return;
      }
      handleApiError(err, 'Could not load file details.');
    }
  }

  /* ---------- Boot ---------- */
  document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initHealth();
    initCopy();
    initDashboard();
    initRegister();
    initVerify();
    initRegistry();
    initHistory();
    initDetails();
  });
})();
