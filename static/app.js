'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const colors = ['#688ed0', '#53a799', '#b18ad0', '#cc9e67', '#d38395', '#719dc0', '#92a765', '#ae8c78'];
  const defaultFields = ['resource.service.name', 'resource.deployment.environment.name', 'resource.k8s.namespace.name', 'resource.k8s.pod.name', 'span.http.response.status_code', 'span.http.route'];
  const state = { mode: null, traces: [], attributes: [], advanced: false, sort: 'start', descending: true, searchController: null, facetController: null, traceController: null, valueController: null, queryEpoch: 0, traceEpoch: 0, activeTraceId: null, selectedSpan: null, collapsed: new Set(), trace: null, lastFocus: null, dateRange: null };
  state.fields = [...defaultFields];
  const auth = { user: null, csrf: '', enabled: true, epoch: 0 };
  const admin = { users: [], events: [], userOffset: 0, auditBefore: null, userSearch: '', auditActor: '', auditEvent: '', userEpoch: 0, auditEpoch: 0, usersController: null, auditController: null };
  state.resultLimit = 50;
  const dateFormat = new Intl.DateTimeFormat('ru-RU', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const timeFormat = new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const formatNumber = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 2 });
  const el = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = String(text); return node; };
  const setVisible = (node, visible) => { node.hidden = !visible; };
  const duration = (ms) => !Number.isFinite(ms) ? '—' : ms < 1 ? `${formatNumber.format(ms * 1000)} µs` : ms < 1000 ? `${formatNumber.format(ms)} ms` : `${formatNumber.format(ms / 1000)} s`;
  const serviceColor = (name) => { let hash = 0; for (const ch of String(name)) hash = ((hash << 5) - hash + ch.charCodeAt(0)) | 0; return colors[Math.abs(hash) % colors.length]; };
  const safeDate = (ms, formatter = dateFormat) => { const date = new Date(ms); return Number.isFinite(date.getTime()) ? formatter.format(date) : '—'; };
  const localDatetime = (date) => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
  const ns = (value) => { try { return BigInt(value || 0); } catch { return 0n; } };
  const nsToMs = (value) => Number(ns(value) / 1000n) / 1000;
  const nsDeltaMs = (left, right) => Number(ns(left) - ns(right)) / 1000000;
  const relativeTime = (ms) => { const diff = Math.round((Date.now() - ms) / 1000); if (diff < 0) return 'в будущем'; if (diff < 60) return `${diff} сек. назад`; if (diff < 3600) return `${Math.floor(diff / 60)} мин. назад`; if (diff < 86400) return `${Math.floor(diff / 3600)} ч. назад`; return `${Math.floor(diff / 86400)} дн. назад`; };
  const displayValue = (value) => typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value, null, 2);
  const unwrapValue = (value) => {
    if (!value || typeof value !== 'object') return value;
    for (const key of ['stringValue', 'intValue', 'doubleValue', 'boolValue', 'bytesValue', 'string_value', 'int_value', 'double_value', 'bool_value', 'bytes_value']) if (key in value) return value[key];
    const array = value.arrayValue || value.array_value;
    if (array) return (array.values || []).map(unwrapValue);
    const kvlist = value.kvlistValue || value.kvlist_value;
    if (kvlist) return Object.fromEntries((kvlist.values || []).map((entry) => [entry.key, unwrapValue(entry.value)]));
    return value;
  };
  const attributesObject = (list) => Array.isArray(list) ? Object.fromEntries(list.map((item) => [item.key, unwrapValue(item.value)])) : list || {};
  const normalizeId = (value) => {
    if (typeof value !== 'string') return '';
    if (/^[a-f\d]{16}$|^[a-f\d]{32}$/i.test(value)) return value.toLowerCase();
    try { const binary = atob(value); if (![8, 16].includes(binary.length)) return value; return Array.from(binary, (ch) => ch.charCodeAt(0).toString(16).padStart(2, '0')).join(''); } catch { return value; }
  };
  const errorCode = (status) => status?.code === 2 || status?.code === '2' || status?.code === 'STATUS_CODE_ERROR' || status?.code === 'ERROR';
  function serviceLabel(name) { const label = el('span', 'service-label'); const dot = el('span', 'service-dot'); dot.style.backgroundColor = serviceColor(name); label.append(dot, el('span', '', name)); return label; }
  function toast(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toast.timer); toast.timer = setTimeout(() => { $('toast').hidden = true; }, 3000); }

  async function api(path, params = {}, signal, options = {}) {
    const url = new URL(path, window.location.origin);
    for (const [key, value] of Object.entries(params)) if (value !== '' && value != null) url.searchParams.set(key, value);
    const epoch = auth.epoch;
    const headers = { Accept: 'application/json' };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (options.method && options.method !== 'GET' && path !== '/api/login') headers['X-CSRF-Token'] = auth.csrf;
    const response = await fetch(url, { signal, credentials: 'same-origin', cache: 'no-store', method: options.method || 'GET', headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
    if (epoch !== auth.epoch) throw new DOMException('Сессия изменилась', 'AbortError');
    if (response.status === 401 && path !== '/api/login') showLogin(auth.user ? 'Сессия завершена. Войдите снова.' : 'Используйте вашу доменную учётную запись.');
    if (response.ok && options.raw) return response;
    let body;
    try { body = await response.json(); } catch { const error = new Error(`Сервер вернул некорректный ответ (HTTP ${response.status}).`); error.status = response.status; throw error; }
    if (response.ok && epoch !== auth.epoch) throw new DOMException('Сессия изменилась', 'AbortError');
    if (!response.ok) { const error = new Error(body.error || `Ошибка запроса: HTTP ${response.status}`); error.status = response.status; throw error; }
    return body;
  }

  function showLogin(message = 'Используйте вашу доменную учётную запись.') {
    auth.epoch++; auth.user = null; auth.csrf = '';
    for (const key of ['searchController', 'facetController', 'traceController', 'valueController']) state[key]?.abort();
    admin.usersController?.abort(); admin.auditController?.abort(); admin.userEpoch++; admin.auditEpoch++;
    state.queryEpoch++; state.traceEpoch++; state.traces = []; state.trace = null; state.selectedSpan = null; state.activeTraceId = null;
    state.attributes = []; state.fields = [...defaultFields]; state.advanced = false; state.collapsed.clear(); state.dateRange = null; state.lastFocus = null;
    admin.users = []; admin.events = []; admin.userOffset = 0; admin.auditBefore = null; admin.userSearch = ''; admin.auditActor = ''; admin.auditEvent = '';
    for (const id of ['results-body', 'empty-state', 'drawer-content', 'trace-histogram', 'histogram-axis', 'field-list', 'filter-chips', 'admin-users-body', 'admin-audit-body', 'attribute-names', 'attribute-values', 'environments']) $(id).replaceChildren();
    for (const id of ['trace-title', 'trace-id', 'account-label', 'results-window', 'table-summary', 'help-backend', 'admin-users-status', 'admin-audit-status', 'toast', 'facet-notice', 'error-banner', 'admin-error']) $(id).textContent = '';
    for (const id of ['stat-count', 'stat-median', 'stat-max', 'stat-services']) $(id).textContent = '—';
    for (const id of ['discover-workspace', 'admin-panel', 'trace-drawer', 'drawer-backdrop', 'advanced-panel', 'attribute-builder', 'custom-range', 'histogram-panel', 'stats-strip', 'demo-banner', 'error-banner', 'facet-notice', 'toast', 'admin-button', 'logout-button', 'account-label']) $(id).hidden = true;
    for (const id of ['search-form', 'id-form', 'admin-users-form', 'admin-audit-form']) $(id).reset();
    for (const id of ['operation', 'service', 'status', 'environment', 'min-duration', 'max-duration', 'add-filter-button']) $(id).disabled = false;
    $('service').replaceChildren(new Option('Все сервисы', ''));
    $('field-search').value = ''; $('attribute-name').value = ''; $('attribute-value').value = ''; $('traceql').value = '{}'; $('query-preview').textContent = '{}';
    $('advanced-toggle').setAttribute('aria-expanded', 'false'); $('result-count').textContent = '0'; $('field-count').textContent = '0';
    $('updated-label').textContent = 'Ещё не обновлялось'; $('histogram-summary').textContent = ''; $('backend-label').textContent = 'Не подключено';
    $('connection-dot').className = 'connection-dot'; $('account-label').title = ''; $('login-password').value = ''; $('login-error').textContent = ''; $('login-error').hidden = true;
    for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
    document.body.style.overflow = ''; document.body.classList.add('auth-pending');
    if (location.hash.startsWith('#trace/')) history.replaceState(null, '', location.pathname + location.search);
    $('auth-screen').hidden = false; $('login-form').hidden = false; $('auth-retry').hidden = true; $('auth-status').textContent = message;
    $('login-username').focus();
  }

  function acceptSession(session) {
    if (!session?.user?.username || !['admin', 'viewer'].includes(session.user.role)) throw new Error('Сервер вернул некорректную сессию.');
    auth.user = session.user; auth.csrf = session.csrf || ''; auth.enabled = session.authEnabled !== false;
    document.body.classList.remove('auth-pending'); $('auth-screen').hidden = true; $('discover-workspace').hidden = false;
    $('account-label').textContent = auth.user.username; $('account-label').title = `${auth.user.username} · ${auth.user.role === 'admin' ? 'Администратор' : 'Просмотр трейсов'}`;
    $('account-label').hidden = false; $('logout-button').hidden = !auth.enabled; $('admin-button').hidden = auth.user.role !== 'admin';
    const now = new Date(); $('time-end').value = localDatetime(now); $('time-start').value = localDatetime(new Date(now.getTime() - 3600000));
    renderFields(); renderChips(); $('attribute-names').replaceChildren(...state.fields.map((name) => new Option(name, name)));
  }

  function recordEvent(event, fields = {}) {
    if (!auth.user || !auth.enabled) return;
    api('/api/events', {}, undefined, { method: 'POST', body: { event, ...fields } }).catch(() => { /* Audit is best effort; no telemetry payloads or credentials are sent here. */ });
  }

  async function checkSession() {
    $('auth-status').textContent = 'Проверяем сессию…'; $('auth-retry').hidden = true; $('login-form').hidden = true;
    try { acceptSession(await api('/api/me')); await loadWorkspace(); }
    catch (error) {
      if (error.status === 401 || error.name === 'AbortError') return;
      $('auth-status').textContent = error.message; $('auth-retry').hidden = false;
    }
  }

  async function login(event) {
    event.preventDefault(); $('login-submit').disabled = true; $('login-error').hidden = true;
    try {
      const pending = api('/api/login', {}, undefined, { method: 'POST', body: { username: $('login-username').value.trim(), password: $('login-password').value } });
      $('login-password').value = '';
      acceptSession(await pending); await loadWorkspace();
    } catch (error) {
      if (error.name !== 'AbortError') { $('login-error').textContent = error.message; $('login-error').hidden = false; $('login-password').focus(); }
    } finally { $('login-password').value = ''; $('login-submit').disabled = false; }
  }

  async function logout() {
    $('logout-button').disabled = true;
    try { await api('/api/logout', {}, undefined, { method: 'POST', body: {} }); showLogin('Вы вышли из учётной записи.'); }
    catch (error) { if (error.status !== 401 && error.name !== 'AbortError') toast(`Не удалось завершить сессию: ${error.message}`); }
    finally { $('logout-button').disabled = false; }
  }

  async function downloadTrace() {
    const id = state.activeTraceId; if (!id || !auth.user) return;
    const epoch = auth.epoch; $('download-trace').disabled = true;
    try {
      const response = await api(`/api/traces/${encodeURIComponent(id)}/download`, {}, undefined, { raw: true });
      const blob = await response.blob(); if (epoch !== auth.epoch) return;
      const url = URL.createObjectURL(blob); const link = el('a'); link.href = url; link.download = `trace-${id}.json`; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) { if (error.status !== 401 && error.name !== 'AbortError') toast(`Не удалось скачать трейс: ${error.message}`); }
    finally { $('download-trace').disabled = false; }
  }

  function adminTime(value) {
    if (value == null || value === '') return '—';
    const date = typeof value === 'number' ? new Date(value < 1e12 ? value * 1000 : value) : new Date(value);
    return Number.isFinite(date.getTime()) ? dateFormat.format(date) : String(value);
  }

  function adminError(error) {
    if (!auth.user || error.status === 401 || error.name === 'AbortError') return;
    $('admin-error').textContent = error.message; $('admin-error').hidden = false;
  }

  function emptyAdminRow(body, columns, message) {
    const row = el('tr', 'admin-empty'); const cell = el('td', '', message); cell.colSpan = columns; row.append(cell); body.append(row);
  }

  function renderAdminUsers() {
    const body = $('admin-users-body'); body.replaceChildren();
    for (const user of admin.users) {
      const row = el('tr'); const status = el('td'); status.append(el('span', `admin-state${user.blocked ? ' blocked' : ''}`, user.blocked ? 'Заблокирован' : 'Активен'));
      const action = el('td'); const protectedUser = user.role === 'admin' || user.username?.toLowerCase() === auth.user?.username?.toLowerCase();
      if (protectedUser) action.append(el('span', 'muted', 'Защищённая учётная запись'));
      else {
        const button = el('button', `button secondary${user.blocked ? '' : ' admin-block-button'}`, user.blocked ? 'Разблокировать' : 'Заблокировать'); button.type = 'button';
        button.addEventListener('click', async () => {
          button.disabled = true; $('admin-error').hidden = true;
          try {
            const result = await api('/api/admin/users/block', {}, undefined, { method: 'POST', body: { username: user.username, blocked: !user.blocked } });
            const index = admin.users.findIndex((item) => item.username === user.username);
            if (index >= 0) admin.users[index] = { ...user, ...result.user };
            renderAdminUsers(); loadAdminAudit();
          } catch (error) { adminError(error); button.disabled = false; }
        });
        action.append(button);
      }
      row.append(el('td', '', user.username), el('td', '', user.role === 'admin' ? 'Администратор' : 'Просмотр'), status, el('td', '', adminTime(user.last_login)), action); body.append(row);
    }
    if (!admin.users.length) emptyAdminRow(body, 5, 'Пользователи не найдены.');
    $('admin-users-status').textContent = `Загружено пользователей: ${admin.users.length}`;
  }

  async function loadAdminUsers(append = false) {
    if (auth.user?.role !== 'admin') return;
    admin.usersController?.abort(); admin.usersController = new AbortController(); const epoch = ++admin.userEpoch;
    $('admin-users-more').disabled = true; $('admin-error').hidden = true;
    if (!append) { admin.users = []; admin.userOffset = 0; admin.userSearch = $('admin-users-search').value.trim(); $('admin-users-body').replaceChildren(); $('admin-users-status').textContent = 'Загружаем пользователей…'; $('admin-users-more').hidden = true; }
    try {
      const data = await api('/api/admin/users', { limit: 100, offset: admin.userOffset, search: admin.userSearch }, admin.usersController.signal);
      if (epoch !== admin.userEpoch) return;
      if (!Array.isArray(data.users)) throw new Error('Сервер вернул некорректный список пользователей.');
      admin.userOffset += data.users.length;
      admin.users = [...new Map([...admin.users, ...data.users].map((user) => [user.username, user])).values()]; renderAdminUsers();
      $('admin-users-more').hidden = data.users.length < 100;
    } catch (error) { adminError(error); if (epoch === admin.userEpoch && error.name !== 'AbortError') $('admin-users-status').textContent = 'Не удалось загрузить пользователей.'; }
    finally { if (epoch === admin.userEpoch) $('admin-users-more').disabled = false; }
  }

  function renderAdminAudit() {
    const body = $('admin-audit-body'); body.replaceChildren();
    for (const event of admin.events) {
      const row = el('tr');
      const details = event.details == null ? '—' : typeof event.details === 'string' ? event.details : JSON.stringify(event.details, null, 2);
      row.append(el('td', '', adminTime(event.created_at)), el('td', '', event.actor || '—'), el('td', '', event.event || '—'), el('td', 'admin-target-cell', event.target || '—'), el('td', '', event.outcome || '—'), el('td', '', event.ip || '—'), el('td', 'admin-detail-cell', details)); body.append(row);
    }
    if (!admin.events.length) emptyAdminRow(body, 7, 'События по выбранным условиям не найдены.');
    $('admin-audit-status').textContent = `Загружено событий: ${admin.events.length}`;
  }

  async function loadAdminAudit(append = false) {
    if (auth.user?.role !== 'admin') return;
    admin.auditController?.abort(); admin.auditController = new AbortController(); const epoch = ++admin.auditEpoch;
    $('admin-audit-more').disabled = true; $('admin-error').hidden = true;
    if (!append) { admin.events = []; admin.auditBefore = null; admin.auditActor = $('admin-audit-actor').value.trim(); admin.auditEvent = $('admin-audit-event').value.trim(); $('admin-audit-body').replaceChildren(); $('admin-audit-status').textContent = 'Загружаем события…'; $('admin-audit-more').hidden = true; }
    try {
      const data = await api('/api/admin/audit', { limit: 100, before: admin.auditBefore, actor: admin.auditActor, event: admin.auditEvent }, admin.auditController.signal);
      if (epoch !== admin.auditEpoch) return;
      if (!Array.isArray(data.events)) throw new Error('Сервер вернул некорректный журнал действий.');
      admin.events = [...new Map([...admin.events, ...data.events].map((event) => [String(event.id), event])).values()];
      admin.auditBefore = data.events.at(-1)?.id ?? null; renderAdminAudit();
      $('admin-audit-more').hidden = data.events.length < 100 || admin.auditBefore == null;
    } catch (error) { adminError(error); if (epoch === admin.auditEpoch && error.name !== 'AbortError') $('admin-audit-status').textContent = 'Не удалось загрузить события.'; }
    finally { if (epoch === admin.auditEpoch) $('admin-audit-more').disabled = false; }
  }

  function openAdmin() {
    if (auth.user?.role !== 'admin') return;
    if (!$('trace-drawer').hidden) closeTrace();
    $('discover-workspace').hidden = true; $('admin-panel').hidden = false; $('admin-back').focus();
    loadAdminUsers(); loadAdminAudit();
  }

  function range() {
    const selected = $('time-range').value;
    if (selected !== 'custom') { const end = Math.floor(Date.now() / 1000); return { start: end - Number(selected), end }; }
    const start = Math.floor(new Date($('time-start').value).getTime() / 1000);
    const end = Math.floor(new Date($('time-end').value).getTime() / 1000);
    if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) throw new Error('Укажите корректный период: начало должно быть раньше окончания.');
    return { start, end };
  }
  const quote = (value) => JSON.stringify(String(value));
  const regexLiteral = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  function visualQuery() {
    const clauses = [];
    if ($('service').value) clauses.push(`resource.service.name = ${quote($('service').value)}`);
    if ($('operation').value.trim()) clauses.push(`name =~ ${quote(`.*${regexLiteral($('operation').value.trim())}.*`)}`);
    if ($('environment').value.trim()) clauses.push(`resource.deployment.environment.name = ${quote($('environment').value.trim())}`);
    if ($('status').value) clauses.push(`status = ${$('status').value}`);
    for (const [id, operator] of [['min-duration', '>='], ['max-duration', '<=']]) {
      const raw = $(id).value;
      if (raw !== '') { const value = Number(raw); if (!Number.isFinite(value) || value < 0) throw new Error('Длительность должна быть неотрицательным числом.'); clauses.push(`duration ${operator} ${value}ms`); }
    }
    if ($('min-duration').value && $('max-duration').value && Number($('min-duration').value) > Number($('max-duration').value)) throw new Error('Минимальная длительность не может быть больше максимальной.');
    for (const filter of state.attributes) clauses.push(`${filter.field} ${filter.operator} ${filter.type === 'string' ? quote(filter.value) : filter.value}`);
    return `{ ${clauses.join(' && ')} }`;
  }
  function query() { return state.advanced ? $('traceql').value.trim() || '{}' : visualQuery(); }
  function renderQueryPreview() {
    try { $('query-preview').textContent = query(); }
    catch (error) { $('query-preview').textContent = error.message; }
  }
  function renderFields() {
    const term = $('field-search').value.trim().toLowerCase();
    const fields = state.fields.filter((field) => field.toLowerCase().includes(term));
    $('field-count').textContent = String(fields.length);
    $('field-list').replaceChildren();
    for (const field of fields) {
      const item = el('button', 'field-item');
      item.type = 'button';
      item.disabled = state.advanced;
      item.title = state.advanced ? 'Выключите редактор TraceQL, чтобы добавить визуальный фильтр' : `Добавить фильтр: ${field}`;
      item.setAttribute('aria-label', `Добавить фильтр: ${field}`);
      const scope = el('span', 'field-type', field.startsWith('resource.') ? 'R' : 'S');
      scope.setAttribute('aria-hidden', 'true');
      item.append(scope, el('span', 'field-name', field));
      item.addEventListener('click', () => {
        $('attribute-builder').hidden = false;
        $('attribute-name').value = field;
        $('attribute-value').value = '';
        $('attribute-operator').value = '=';
        $('attribute-type').value = 'string';
        loadAttributeValues();
        $('attribute-value').focus();
        $('attribute-builder').scrollIntoView({ block: 'nearest' });
      });
      $('field-list').append(item);
    }
    if (!fields.length) $('field-list').append(el('p', 'field-empty', 'Поля не найдены. Попробуйте другое название.'));
  }
  function renderHistogram() {
    const chart = $('trace-histogram');
    chart.replaceChildren(); $('histogram-axis').replaceChildren();
    $('histogram-panel').hidden = !state.dateRange;
    if (!state.dateRange) return;
    const { start, end } = state.dateRange;
    const count = Math.min(30, Math.max(1, end - start));
    const boundaries = Array.from({ length: count + 1 }, (_, i) => start + Math.floor((end - start) * i / count));
    const bins = Array(count).fill(0);
    for (const trace of state.traces) {
      const seconds = trace.startMs / 1000;
      if (!Number.isFinite(seconds) || seconds < start || seconds > end) continue;
      const index = boundaries.findIndex((boundary, i) => i > 0 && seconds < boundary);
      bins[index === -1 ? count - 1 : index - 1]++;
    }
    const maximum = Math.max(1, ...bins);
    for (let i = 0; i < count; i++) {
      const slot = el('div', 'histogram-slot');
      const bar = el(bins[i] ? 'button' : 'span', `histogram-bar${bins[i] ? '' : ' empty'}`);
      bar.style.height = `${bins[i] ? Math.max(4, bins[i] / maximum * 100) : 1}%`;
      const label = `${safeDate(boundaries[i] * 1000)} — ${safeDate(boundaries[i + 1] * 1000)}: ${bins[i]} ${plural(bins[i], ['трейс', 'трейса', 'трейсов'])}`;
      bar.title = label;
      if (bins[i]) {
        bar.type = 'button';
        bar.setAttribute('aria-label', `${label}. Сузить период`);
        bar.addEventListener('click', () => {
          $('time-range').value = 'custom'; $('custom-range').hidden = false;
          $('time-start').value = localDatetime(new Date(boundaries[i] * 1000));
          $('time-end').value = localDatetime(new Date(boundaries[i + 1] * 1000));
          search(); loadFacets();
        });
      } else { bar.setAttribute('aria-hidden', 'true'); }
      slot.append(bar); chart.append(slot);
    }
    for (const fraction of [0, .5, 1]) $('histogram-axis').append(el('span', '', safeDate((start + (end - start) * fraction) * 1000, end - start >= 86400 ? dateFormat : timeFormat)));
    const capped = state.traces.length >= state.resultLimit;
    $('histogram-summary').textContent = `${state.traces.length} ${plural(state.traces.length, ['трейс', 'трейса', 'трейсов'])} в выборке${capped ? ' · Достигнут лимит, распределение неполное' : ''}`;
  }
  function renderChips() {
    renderQueryPreview();
    const chips = $('filter-chips'); chips.replaceChildren();
    if (state.advanced) { chips.append(el('span', 'muted', 'Выполняется запрос из редактора TraceQL')); return; }
    function chip(text, remove) { const node = el('span', 'chip'); node.append(el('span', '', text)); node.title = text; const button = el('button', '', '×'); button.type = 'button'; button.setAttribute('aria-label', `Убрать фильтр ${text}`); button.addEventListener('click', () => { remove(); renderChips(); search(); }); node.append(button); chips.append(node); }
    for (const [id, label] of [['service', 'service'], ['status', 'status'], ['environment', 'env'], ['operation', 'name'], ['min-duration', 'duration ≥'], ['max-duration', 'duration ≤']]) if ($(id).value) chip(`${label}: ${$(id).value}${id.includes('duration') ? ' ms' : ''}`, () => { $(id).value = ''; });
    state.attributes.forEach((filter, index) => chip(`${filter.field} ${filter.operator} ${filter.value}`, () => state.attributes.splice(index, 1)));
    if (!chips.children.length) chips.append(el('span', 'muted', 'Без дополнительных фильтров'));
  }
  function setSearchBusy(busy) { $('search-button').disabled = busy; $('search-button').textContent = busy ? 'Поиск…' : 'Найти'; $('refresh-button').classList.toggle('busy', busy); document.querySelector('.results-panel').setAttribute('aria-busy', String(busy)); document.querySelectorAll('.sort-button').forEach((button) => { button.disabled = busy; }); }
  function showEmpty(title, message, busy = false) { const node = $('empty-state'); node.replaceChildren(el('div', busy ? 'spinner' : 'empty-symbol', busy ? '' : '⌁'), el('h3', '', title), el('p', '', message)); node.hidden = false; }
  async function search() {
    if (!auth.user) return;
    let params;
    try { params = { ...range(), limit: Number($('limit').value), q: query() }; } catch (error) { $('error-banner').textContent = error.message; $('error-banner').hidden = false; return; }
    state.searchController?.abort();
    state.searchController = new AbortController();
    const epoch = ++state.queryEpoch;
    state.traces = []; state.dateRange = null; $('histogram-panel').hidden = true; $('results-window').textContent = '';
    renderChips(); setSearchBusy(true); $('error-banner').hidden = true; $('results-body').replaceChildren(); $('stats-strip').hidden = true; $('result-count').textContent = '…';
    showEmpty('Ищем трейсы', 'Запрос выполняется в Tempo.', true);
    $('table-summary').textContent = 'Получаем результаты…';
    try {
      const data = await api('/api/search', params, state.searchController.signal);
      if (epoch !== state.queryEpoch) return;
      if (!Array.isArray(data.traces) && data.traces != null) throw new Error('Tempo вернул неожиданный формат результатов поиска.');
      state.traces = (data.traces || []).map((trace) => ({ ...trace, traceID: normalizeId(trace.traceID || trace.traceId), rootServiceName: trace.rootServiceName || 'unknown-service', rootTraceName: trace.rootTraceName || '(операция без имени)', durationMs: Number(trace.durationMs || 0), startMs: nsToMs(trace.startTimeUnixNano), matched: Array.isArray(trace.spanSets) ? trace.spanSets.reduce((sum, set) => sum + Number(set.matched ?? set.spans?.length ?? 0), 0) : null }));
      state.dateRange = { start: params.start, end: params.end }; state.resultLimit = params.limit; renderResults(); renderHistogram();
      $('connection-dot').className = 'connection-dot ready'; $('updated-label').textContent = `Обновлено в ${timeFormat.format(new Date())}`;
      $('results-window').textContent = `${safeDate(params.start * 1000, timeFormat)} — ${safeDate(params.end * 1000, timeFormat)}`;
      const capped = state.traces.length >= params.limit;
      let summary = `${state.traces.length} ${plural(state.traces.length, ['трейс', 'трейса', 'трейсов'])} · ${safeDate(params.start * 1000)} — ${safeDate(params.end * 1000)}`;
      if (capped) summary += ' · Достигнут лимит: сузьте период или увеличьте лимит';
      $('table-summary').textContent = summary;
    } catch (error) {
      if (error.name === 'AbortError' || epoch !== state.queryEpoch) return;
      state.traces = []; $('result-count').textContent = '—'; $('connection-dot').className = 'connection-dot error';
      $('error-banner').textContent = error.message; $('error-banner').hidden = false;
      showEmpty('Не удалось получить трейсы', 'Проверьте подключение к Tempo и повторите запрос.'); $('table-summary').textContent = 'Поиск завершился ошибкой';
    } finally { if (epoch === state.queryEpoch) setSearchBusy(false); }
  }
  function plural(value, forms) { const n = Math.abs(value) % 100; const last = n % 10; return n > 10 && n < 20 ? forms[2] : last === 1 ? forms[0] : last > 1 && last < 5 ? forms[1] : forms[2]; }
  function renderResults() {
    const traces = [...state.traces].sort((a, b) => { const cmp = state.sort === 'service' ? a.rootServiceName.localeCompare(b.rootServiceName) : state.sort === 'duration' ? a.durationMs - b.durationMs : a.startMs - b.startMs; return state.descending ? -cmp : cmp; });
    $('result-count').textContent = String(traces.length); $('results-body').replaceChildren(); $('empty-state').hidden = traces.length > 0; $('stats-strip').hidden = !traces.length;
    if (!traces.length) { showEmpty('Трейсы не найдены', 'Увеличьте временной диапазон или уберите часть фильтров.'); return; }
    const sortedDurations = traces.map((trace) => trace.durationMs).sort((a, b) => a - b); const middle = Math.floor(traces.length / 2); const median = traces.length % 2 ? sortedDurations[middle] : (sortedDurations[middle - 1] + sortedDurations[middle]) / 2; const maximum = sortedDurations[sortedDurations.length - 1];
    $('stat-count').textContent = formatNumber.format(traces.length); $('stat-median').textContent = duration(median); $('stat-max').textContent = duration(maximum); $('stat-services').textContent = new Set(traces.map((trace) => trace.rootServiceName)).size;
    for (const trace of traces) {
      const row = el('tr'); row.tabIndex = 0; row.setAttribute('aria-label', `Открыть трейс ${trace.rootTraceName}, ${trace.rootServiceName}, ${duration(trace.durationMs)}`);
      const service = el('td'); service.append(serviceLabel(trace.rootServiceName));
      const operation = el('td'); const name = el('div', 'operation-name', trace.rootTraceName); name.title = trace.rootTraceName; operation.append(name, el('div', 'trace-id-preview', trace.traceID));
      const time = el('td'); time.title = safeDate(trace.startMs); time.append(el('div', 'time-primary', safeDate(trace.startMs, timeFormat)), el('div', 'time-secondary', relativeTime(trace.startMs)));
      const latency = el('td'); const latencyContent = el('div', 'duration-cell'); const track = el('div', 'duration-track'); const bar = el('div', `duration-bar${maximum > 0 && trace.durationMs >= maximum * .85 ? ' slow' : ''}`); bar.style.width = `${maximum ? Math.max(2, trace.durationMs / maximum * 100) : 0}%`; track.append(bar); latencyContent.append(el('span', 'duration-value', duration(trace.durationMs)), track); latency.append(latencyContent);
      const spans = el('td'); spans.append(el('span', 'matched-badge', trace.matched == null ? '—' : trace.matched));
      row.append(time, service, operation, latency, spans, el('td', 'row-arrow', '↗'));
      row.addEventListener('click', () => openTrace(trace.traceID)); row.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openTrace(trace.traceID); } }); $('results-body').append(row);
    }
    document.querySelectorAll('.sort-button').forEach((button) => { button.querySelector('span').textContent = button.dataset.sort === state.sort ? state.descending ? '↓' : '↑' : ''; button.closest('th').setAttribute('aria-sort', button.dataset.sort === state.sort ? state.descending ? 'descending' : 'ascending' : 'none'); });
  }

  async function loadFacets() {
    if (!auth.user) return;
    let params; try { params = range(); } catch { return; }
    state.facetController?.abort(); state.facetController = new AbortController(); const signal = state.facetController.signal;
    const requests = await Promise.allSettled([api('/api/tag-values', { ...params, tag: 'resource.service.name' }, signal), api('/api/tag-values', { ...params, tag: 'resource.deployment.environment.name' }, signal), api('/api/tags', params, signal)]);
    if (signal.aborted) return;
    const values = (data) => (data.tagValues || []).map((item) => typeof item === 'string' ? item : item.value).filter((value) => value != null).map(String).sort();
    if (requests[0].status === 'fulfilled') {
      const current = $('service').value; const names = [...new Set(values(requests[0].value))]; if (current && !names.includes(current)) names.unshift(current);
      $('service').replaceChildren(new Option('Все сервисы', ''), ...names.map((name) => new Option(name, name))); $('service').value = current;
    }
    if (requests[1].status === 'fulfilled') $('environments').replaceChildren(...values(requests[1].value).map((name) => new Option(name, name)));
    if (requests[2].status === 'fulfilled') {
      const data = requests[2].value; const tags = new Set(defaultFields);
      for (const scope of data.scopes || []) for (const tag of scope.tags || []) { const value = typeof tag === 'string' ? tag : tag.name; if (value && ['resource', 'span'].includes(scope.name)) tags.add(value.startsWith(`${scope.name}.`) ? value : `${scope.name}.${value}`); }
      for (const tag of data.tagNames || []) if (typeof tag === 'string' && /^(resource|span)\./.test(tag)) tags.add(tag);
      state.fields = [...tags].filter(validAttribute).sort();
      $('attribute-names').replaceChildren(...state.fields.map((name) => new Option(name, name))); renderFields();
    }
    const failed = requests.filter((result) => result.status === 'rejected' && result.reason.name !== 'AbortError');
    $('facet-notice').hidden = !failed.length;
    if (failed.length) $('facet-notice').textContent = `Некоторые подсказки фильтров недоступны. Атрибуты и окружение можно ввести вручную; сервис — через TraceQL. ${failed[0].reason.message}`;
  }
  async function loadAttributeValues() {
    state.valueController?.abort(); $('attribute-values').replaceChildren(); const tag = $('attribute-name').value.trim(); if (!validAttribute(tag)) return;
    state.valueController = new AbortController(); const signal = state.valueController.signal;
    try {
      const data = await api('/api/tag-values', { ...range(), tag }, signal);
      if (!signal.aborted) {
        const values = data.tagValues || [];
        $('attribute-values').replaceChildren(...values.map((item) => new Option(String(item.value ?? item), String(item.value ?? item))));
        const types = new Set(values.map((item) => item.type));
        $('attribute-type').value = types.size === 1 && types.has('bool') ? 'boolean' : types.size > 0 && [...types].every((type) => ['int', 'float', 'double'].includes(type)) ? 'number' : 'string';
      }
    } catch { /* Value suggestions are optional; manual entry remains available. */ }
  }
  function validAttribute(field) { return /^(resource|span)\.[a-zA-Z_][a-zA-Z0-9_.-]*$/.test(field); }
  function addAttribute() {
    const field = $('attribute-name').value.trim(); const value = $('attribute-value').value; const type = $('attribute-type').value; const operator = $('attribute-operator').value;
    if (!validAttribute(field)) { toast('Укажите атрибут вида resource.service.name или span.http.route'); $('attribute-name').focus(); return; }
    if (!value) { toast('Введите значение атрибута'); $('attribute-value').focus(); return; }
    if (type === 'number' && (!/^-?\d+(\.\d+)?$/.test(value) || !Number.isFinite(Number(value)))) { toast('Для числового атрибута введите число, например 500'); return; }
    if (type === 'boolean' && !['true', 'false'].includes(value)) { toast('Для логического атрибута введите true или false'); return; }
    if (['=~', '!~'].includes(operator) && type !== 'string') { toast('Регулярные выражения применяются к строкам'); return; }
    state.attributes.push({ field, value, operator, type }); $('attribute-builder').hidden = true; $('attribute-name').value = ''; $('attribute-value').value = ''; renderChips(); search();
  }

  function normalizeTrace(raw) {
    const data = raw.trace || raw; const spans = [];
    const batches = data.batches || data.resourceSpans || data.resource_spans || [];
    for (const batch of batches) {
      const resource = attributesObject(batch.resource?.attributes);
      for (const scope of batch.scopeSpans || batch.instrumentationLibrarySpans || batch.scope_spans || batch.instrumentation_library_spans || []) {
        for (const original of scope.spans || []) {
          const start = ns(original.startTimeUnixNano || original.start_time_unix_nano); const rawEnd = ns(original.endTimeUnixNano || original.end_time_unix_nano); const end = rawEnd < start ? start : rawEnd;
          spans.push({ ...original, id: normalizeId(original.spanId || original.spanID || original.span_id), parentId: normalizeId(original.parentSpanId || original.parentSpanID || original.parent_span_id), traceId: normalizeId(original.traceId || original.traceID || original.trace_id), name: original.name || '(спан без имени)', start, end, durationMs: nsDeltaMs(end, start), resource, attrs: attributesObject(original.attributes), scope: scope.scope || scope.instrumentationLibrary || {}, service: String(resource['service.name'] || 'unknown-service'), error: errorCode(original.status), children: [] });
        }
      }
    }
    if (!spans.length) throw new Error('В ответе Tempo нет спанов. Трейс может ещё записываться или уже выйти за срок хранения.');
    const ids = new Map(); for (const span of spans) { if (!span.id) span.id = `missing-${ids.size}`; if (ids.has(span.id)) span.id = `${span.id}-${ids.size}`; ids.set(span.id, span); }
    const roots = [];
    for (const span of spans) { const parent = ids.get(span.parentId); if (parent && parent !== span) parent.children.push(span); else roots.push(span); }
    const compare = (a, b) => a.start < b.start ? -1 : a.start > b.start ? 1 : 0;
    roots.sort(compare); spans.forEach((span) => span.children.sort(compare));
    // Malformed cycles must never make rendering loop, or hide all spans.
    const reachable = new Set(); const stack = [...roots]; while (stack.length) { const current = stack.pop(); if (reachable.has(current.id)) continue; reachable.add(current.id); stack.push(...current.children); }
    for (const span of spans) if (!reachable.has(span.id)) { roots.push(span); stack.push(span); while (stack.length) { const current = stack.pop(); if (reachable.has(current.id)) continue; reachable.add(current.id); stack.push(...current.children); } }
    let start = spans[0].start; let end = spans[0].end; for (const span of spans) { if (span.start < start) start = span.start; if (span.end > end) end = span.end; }
    return { spans, roots, start, end, durationMs: nsDeltaMs(end, start), services: [...new Set(spans.map((span) => span.service))], errors: spans.filter((span) => span.error).length };
  }
  async function openTrace(id, updateHash = true) {
    if (!auth.user) return;
    id = normalizeId(id); if (!/^[a-f\d]{16}$|^[a-f\d]{32}$/i.test(id)) { toast('Некорректный Trace ID'); return; }
    state.traceController?.abort(); state.traceController = new AbortController(); const epoch = ++state.traceEpoch;
    if ($('trace-drawer').hidden) state.lastFocus = document.activeElement;
    state.activeTraceId = id; state.trace = null; state.selectedSpan = null; state.collapsed.clear();
    $('trace-drawer').hidden = false; $('drawer-backdrop').hidden = false; document.body.style.overflow = 'hidden'; $('trace-title').textContent = 'Загрузка трейса…'; $('trace-id').textContent = id;
    $('drawer-content').replaceChildren(el('div', 'spinner'), el('p', 'span-empty', 'Получаем спаны из Tempo…')); $('close-trace').focus();
    if (updateHash && location.hash !== `#trace/${id}`) history.pushState(null, '', `#trace/${id}`);
    try {
      const raw = await api(`/api/traces/${encodeURIComponent(id)}`, {}, state.traceController.signal); if (epoch !== state.traceEpoch) return;
      state.trace = normalizeTrace(raw); $('trace-title').textContent = state.trace.roots[0]?.name || 'Трейс'; renderTrace();
    } catch (error) { if (error.name === 'AbortError' || epoch !== state.traceEpoch) return; $('trace-title').textContent = 'Не удалось открыть трейс'; const box = el('div', 'drawer-error'); box.append(el('h3', '', 'Tempo не вернул трейс'), el('p', '', error.message)); const retry = el('button', 'button secondary', 'Повторить запрос'); retry.addEventListener('click', () => openTrace(id, false)); box.append(retry); $('drawer-content').replaceChildren(box); }
  }
  function closeTrace(updateHash = true) { state.traceController?.abort(); state.traceEpoch++; state.activeTraceId = null; $('trace-drawer').hidden = true; $('drawer-backdrop').hidden = true; document.body.style.overflow = ''; if (updateHash && location.hash.startsWith('#trace/')) history.replaceState(null, '', location.pathname + location.search); state.lastFocus?.focus(); }
  function renderTrace() {
    const trace = state.trace; const content = $('drawer-content'); content.replaceChildren();
    const summary = el('div', 'trace-summary');
    for (const [label, value, className] of [['ДЛИТЕЛЬНОСТЬ', duration(trace.durationMs), ''], ['СПАНЫ', trace.spans.length, ''], ['СЕРВИСЫ', trace.services.length, ''], ['СПАНЫ С ОШИБКОЙ', trace.errors, trace.errors ? 'has-errors' : ''], ['НАЧАЛО', safeDate(nsToMs(trace.start)), '']]) { const item = el('div'); item.append(el('span', 'summary-label', label), el('strong', className, value)); summary.append(item); }
    const services = el('div', 'trace-services'); trace.services.forEach((service) => services.append(serviceLabel(service))); content.append(summary, services);
    const waterfall = el('section', 'waterfall'); const heading = el('div', 'waterfall-heading'); heading.append(el('h3', '', 'Водопад спанов'), el('span', '', 'Выберите спан для подробностей')); waterfall.append(heading);
    const scroll = el('div', 'waterfall-scroll'); const inner = el('div', 'waterfall-inner'); const ruler = el('div', 'waterfall-ruler'); const marks = el('div', 'ruler-marks');
    for (let i = 0; i <= 4; i++) { const mark = el('span', '', duration(trace.durationMs * i / 4)); mark.style.left = `${i * 25}%`; marks.append(mark); }
    ruler.append(el('span', '', 'ОПЕРАЦИЯ'), marks, el('span', '', 'ВРЕМЯ')); inner.append(ruler); const rows = el('div'); rows.id = 'span-rows'; inner.append(rows); scroll.append(inner); waterfall.append(scroll); content.append(waterfall);
    const note = el('p', 'trace-note', 'Время спанов показано относительно начала трейса. Вложенные спаны могут перекрываться; их длительности не суммируются.'); content.append(note); const detail = el('section', 'span-detail'); detail.id = 'span-detail'; content.append(detail);
    renderSpanRows(); selectSpan(trace.roots[0] || trace.spans[0]);
  }
  function renderSpanRows() {
    const trace = state.trace; const rows = $('span-rows'); rows.replaceChildren(); const seen = new Set(); const stack = [...trace.roots].reverse().map((span) => ({ span, depth: 0 }));
    while (stack.length) {
      const { span, depth } = stack.pop(); if (seen.has(span.id)) continue; seen.add(span.id);
      const row = el('div', `span-row${state.selectedSpan?.id === span.id ? ' selected' : ''}`); row.tabIndex = 0; row.setAttribute('role', 'button'); row.dataset.span = span.id; row.setAttribute('aria-label', `${span.service}: ${span.name}, ${duration(span.durationMs)}${span.error ? ', ошибка' : ''}`);
      const label = el('div', 'span-label'); label.style.paddingLeft = `${12 + Math.min(depth, 12) * 13}px`; const expand = el('button', `span-expand${span.children.length ? '' : ' placeholder'}`, state.collapsed.has(span.id) ? '▸' : '▾'); expand.type = 'button'; expand.tabIndex = span.children.length ? 0 : -1; expand.setAttribute('aria-label', state.collapsed.has(span.id) ? 'Развернуть дочерние спаны' : 'Свернуть дочерние спаны'); expand.setAttribute('aria-expanded', String(!state.collapsed.has(span.id))); expand.addEventListener('click', (event) => { event.stopPropagation(); if (state.collapsed.has(span.id)) state.collapsed.delete(span.id); else state.collapsed.add(span.id); renderSpanRows(); }); expand.addEventListener('keydown', (event) => event.stopPropagation());
      const dot = el('span', 'service-dot'); dot.style.backgroundColor = serviceColor(span.service); const name = el('span', 'span-name', span.name); label.title = `${span.service} · ${span.name}`; label.append(expand, dot, name); if (span.error) label.append(el('span', 'span-error', '●'));
      const timeline = el('div', 'span-timeline'); const bar = el('div', `span-bar${span.error ? ' error-bar' : ''}`); const total = trace.durationMs || .001; bar.style.left = `${Math.min(100, Math.max(0, nsDeltaMs(span.start, trace.start) / total * 100))}%`; bar.style.width = `${Math.max(.1, Math.min(100, span.durationMs / total * 100))}%`; bar.style.backgroundColor = serviceColor(span.service); timeline.append(bar); timeline.title = `${duration(nsDeltaMs(span.start, trace.start))} → ${duration(nsDeltaMs(span.end, trace.start))}`; row.append(label, timeline, el('span', 'span-duration', duration(span.durationMs)));
      row.addEventListener('click', () => selectSpan(span)); row.addEventListener('keydown', (event) => { if (event.target !== row) return; if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectSpan(span); } }); rows.append(row);
      if (!state.collapsed.has(span.id)) for (const child of [...span.children].reverse()) stack.push({ span: child, depth: depth + 1 });
    }
  }
  function attributeTable(attributes) {
    const table = el('table', 'attr-table'); const body = el('tbody'); for (const [key, value] of Object.entries(attributes).sort(([a], [b]) => a.localeCompare(b))) { const row = el('tr'); row.append(el('td', '', key), el('td', '', displayValue(value))); body.append(row); } table.append(body); return table;
  }
  function selectSpan(span) {
    recordEvent('span.select', { traceId: state.activeTraceId, spanId: span.id });
    state.selectedSpan = span; document.querySelectorAll('.span-row').forEach((row) => { row.classList.toggle('selected', row.dataset.span === span.id); row.setAttribute('aria-pressed', String(row.dataset.span === span.id)); });
    const detail = $('span-detail'); detail.replaceChildren(); const header = el('div', 'span-detail-header'); const title = el('div'); title.append(el('h3', '', span.name), el('code', '', `Span ID ${span.id}`));
    const kinds = { 0: 'UNSPECIFIED', 1: 'INTERNAL', 2: 'SERVER', 3: 'CLIENT', 4: 'PRODUCER', 5: 'CONSUMER' }; const kind = kinds[span.kind] || String(span.kind || 'UNSPECIFIED').replace('SPAN_KIND_', ''); header.append(title, el('span', 'span-kind', kind)); detail.append(header);
    const facts = el('div', 'span-facts');
    const status = span.error ? 'ERROR' : [1, '1', 'STATUS_CODE_OK', 'OK'].includes(span.status?.code) ? 'OK' : 'UNSET';
    for (const [label, value] of [['Сервис', span.service], ['Длительность', duration(span.durationMs)], ['Начало', `+${duration(nsDeltaMs(span.start, state.trace.start))}`], ['Статус', status]]) { const item = el('span', '', label); item.append(el('strong', label === 'Статус' && span.error ? 'error-status' : '', value)); facts.append(item); } detail.append(facts);
    const tabs = el('div', 'span-tabs'); tabs.setAttribute('role', 'tablist'); const panel = el('div', 'span-tab-content'); panel.id = 'span-tab-panel'; panel.setAttribute('role', 'tabpanel');
    const events = span.events || []; const links = span.links || []; const attributeCount = Object.keys(span.attrs).length + Object.keys(span.resource).length;
    for (const [key, label] of [['attributes', `Атрибуты · ${attributeCount}`], ['events', `События · ${events.length}`], ['links', `Связи · ${links.length}`]]) { const tab = el('button', `span-tab${key === 'attributes' ? ' active' : ''}`, label); tab.type = 'button'; tab.id = `span-tab-${key}`; tab.setAttribute('role', 'tab'); tab.setAttribute('aria-controls', panel.id); tab.setAttribute('aria-selected', String(key === 'attributes')); tab.addEventListener('click', () => { tabs.querySelectorAll('button').forEach((button) => { button.classList.toggle('active', button === tab); button.setAttribute('aria-selected', String(button === tab)); }); panel.setAttribute('aria-labelledby', tab.id); renderSpanTab(panel, key, span); }); tabs.append(tab); }
    detail.append(tabs, panel); panel.setAttribute('aria-labelledby', 'span-tab-attributes'); renderSpanTab(panel, 'attributes', span);
  }
  function renderSpanTab(panel, key, span) {
    recordEvent('span.tab', { traceId: state.activeTraceId, spanId: span.id, tab: key });
    panel.replaceChildren();
    if (key === 'attributes') {
      if (span.status?.message) { panel.append(el('div', 'attr-section error-status', 'Status message'), el('p', 'trace-note error-status', span.status.message)); }
      for (const [title, attrs] of [['Span attributes', span.attrs], ['Resource attributes', span.resource], ['Instrumentation scope', span.scope]]) if (Object.keys(attrs).length) panel.append(el('h4', 'attr-section', title), attributeTable(attrs));
      if (!panel.children.length) panel.append(el('div', 'span-empty', 'У этого спана нет атрибутов.'));
    } else if (key === 'events') {
      for (const event of span.events || []) { const item = el('div', 'event-entry'); item.append(el('h4', '', event.name || 'event'), el('span', '', `+${duration(nsDeltaMs(event.timeUnixNano || event.time_unix_nano, span.start))} от начала спана`)); const attrs = attributesObject(event.attributes); if (Object.keys(attrs).length) item.append(attributeTable(attrs)); panel.append(item); }
      if (!panel.children.length) panel.append(el('div', 'span-empty', 'У этого спана нет событий.'));
    } else {
      for (const link of span.links || []) { const item = el('div', 'event-entry'); const id = normalizeId(link.traceId || link.trace_id); const button = el('button', 'text-button link-id', `Trace ${id} ↗`); button.addEventListener('click', () => openTrace(id)); item.append(button, el('p', 'trace-note', `Span ${normalizeId(link.spanId || link.span_id)}`)); const attrs = attributesObject(link.attributes); if (Object.keys(attrs).length) item.append(attributeTable(attrs)); panel.append(item); }
      if (!panel.children.length) panel.append(el('div', 'span-empty', 'У этого спана нет связей.'));
    }
  }

  async function copy(text, success, event, fields = {}) {
    const epoch = auth.epoch;
    try { await navigator.clipboard.writeText(text); if (epoch !== auth.epoch) return; toast(success); if (event) recordEvent(event, fields); }
    catch {
      if (epoch !== auth.epoch) return;
      const area = el('textarea'); area.value = text; area.style.position = 'fixed'; area.style.opacity = '0'; document.body.append(area); area.select(); let copied = false; try { copied = document.execCommand('copy'); } catch { /* Non-secure origins may deny clipboard access. */ } area.remove(); toast(copied ? success : 'Не удалось скопировать. Выделите и скопируйте ID вручную.'); if (copied && event) recordEvent(event, fields);
    }
  }
  function handleHash() { if (!auth.user) return; const match = location.hash.match(/^#trace\/([a-f\d]{16}|[a-f\d]{32})$/i); if (match && match[1] !== state.activeTraceId) openTrace(match[1], false); else if (!match && !$('trace-drawer').hidden) closeTrace(false); }
  function bindEvents() {
    $('login-form').addEventListener('submit', login); $('auth-retry').addEventListener('click', checkSession);
    $('logout-button').addEventListener('click', logout); $('admin-button').addEventListener('click', openAdmin);
    $('admin-back').addEventListener('click', () => { $('admin-panel').hidden = true; $('discover-workspace').hidden = false; $('operation').focus(); });
    $('admin-users-form').addEventListener('submit', (event) => { event.preventDefault(); loadAdminUsers(); });
    $('admin-users-more').addEventListener('click', () => loadAdminUsers(true));
    $('admin-audit-form').addEventListener('submit', (event) => { event.preventDefault(); loadAdminAudit(); });
    $('admin-audit-more').addEventListener('click', () => loadAdminAudit(true));
    $('download-trace').addEventListener('click', downloadTrace);
    $('search-form').addEventListener('submit', (event) => { event.preventDefault(); search(); });
    $('refresh-button').addEventListener('click', () => { search(); loadFacets(); });
    $('time-range').addEventListener('change', () => { const custom = $('time-range').value === 'custom'; $('custom-range').hidden = !custom; if (!custom) { search(); loadFacets(); } });
    for (const id of ['service', 'status', 'environment', 'min-duration', 'max-duration']) $(id).addEventListener('change', () => { renderChips(); if (!state.advanced) search(); });
    $('operation').addEventListener('input', renderChips);
    $('field-search').addEventListener('input', renderFields);
    $('traceql').addEventListener('input', renderQueryPreview);
    $('copy-query').addEventListener('click', () => { try { copy(query(), 'TraceQL скопирован', 'query.copy'); } catch (error) { toast(error.message); } });
    $('reset-filters').addEventListener('click', () => {
      state.advanced = false; state.attributes = [];
      state.valueController?.abort(); $('attribute-values').replaceChildren();
      for (const id of ['operation', 'service', 'status', 'environment', 'min-duration', 'max-duration']) { $(id).value = ''; $(id).disabled = false; }
      $('add-filter-button').disabled = false; $('advanced-panel').hidden = true; $('attribute-builder').hidden = true;
      $('advanced-toggle').setAttribute('aria-expanded', 'false'); $('traceql').value = '{}';
      renderChips(); renderFields(); search();
    });
    $('limit').addEventListener('change', search);
    $('advanced-toggle').addEventListener('click', () => {
      if (!state.advanced) { try { $('traceql').value = visualQuery(); } catch (error) { toast(error.message); return; } }
      state.advanced = !state.advanced; $('advanced-panel').hidden = !state.advanced; $('advanced-toggle').setAttribute('aria-expanded', String(state.advanced));
      for (const id of ['operation', 'service', 'status', 'environment', 'min-duration', 'max-duration', 'add-filter-button']) $(id).disabled = state.advanced;
      state.valueController?.abort(); $('attribute-builder').hidden = true; renderChips(); renderFields(); if (state.advanced) $('traceql').focus();
    });
    $('traceql').addEventListener('keydown', (event) => { if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) { event.preventDefault(); search(); } });
    $('add-filter-button').addEventListener('click', () => { $('attribute-builder').hidden = !$('attribute-builder').hidden; if (!$('attribute-builder').hidden) $('attribute-name').focus(); });
    $('cancel-attribute').addEventListener('click', () => { state.valueController?.abort(); $('attribute-builder').hidden = true; }); $('apply-attribute').addEventListener('click', addAttribute); $('attribute-name').addEventListener('change', loadAttributeValues);
    $('attribute-value').addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); addAttribute(); } });
    for (const id of ['time-start', 'time-end']) $(id).addEventListener('change', () => { try { range(); loadFacets(); } catch { /* Wait until the user completes the range. */ } });
    document.querySelectorAll('.sort-button').forEach((button) => button.addEventListener('click', () => { if (state.sort === button.dataset.sort) state.descending = !state.descending; else { state.sort = button.dataset.sort; state.descending = state.sort !== 'service'; } renderResults(); }));
    $('close-trace').addEventListener('click', () => closeTrace()); $('drawer-backdrop').addEventListener('click', () => closeTrace());
    $('copy-trace-id').addEventListener('click', () => copy(state.activeTraceId, 'Trace ID скопирован', 'trace.copy', { traceId: state.activeTraceId })); $('copy-trace-link').addEventListener('click', () => copy(`${location.origin}${location.pathname}${location.search}#trace/${state.activeTraceId}`, 'Ссылка на трейс скопирована', 'trace.link.copy', { traceId: state.activeTraceId }));
    $('open-id-button').addEventListener('click', () => { $('id-dialog').showModal(); $('trace-id-input').focus(); }); $('cancel-id').addEventListener('click', () => $('id-dialog').close());
    $('id-form').addEventListener('submit', (event) => { event.preventDefault(); const id = $('trace-id-input').value.trim(); if (/^[a-f\d]{16}$|^[a-f\d]{32}$/i.test(id)) { $('id-dialog').close(); openTrace(id); } });
    $('trace-id-input').addEventListener('input', () => { $('trace-id-input').value = $('trace-id-input').value.trim(); });
    $('help-button').addEventListener('click', () => $('help-dialog').showModal()); $('close-help').addEventListener('click', () => $('help-dialog').close());
    window.addEventListener('hashchange', handleHash);
    document.addEventListener('keydown', (event) => {
      if (!auth.user || !$('admin-panel').hidden) return;
      const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName) || document.activeElement.isContentEditable;
      if (event.key === '/' && !typing && $('trace-drawer').hidden && !document.querySelector('dialog[open]')) { event.preventDefault(); (state.advanced ? $('traceql') : $('operation')).focus(); }
      if (event.key === 'Escape' && !$('trace-drawer').hidden && !document.querySelector('dialog[open]')) closeTrace();
      if (event.key === 'Tab' && !$('trace-drawer').hidden && !document.querySelector('dialog[open]')) {
        const focusable = [...$('trace-drawer').querySelectorAll('button:not([disabled]),a[href],input,[tabindex="0"]')].filter((node) => node.offsetParent !== null);
        const first = focusable[0], last = focusable[focusable.length - 1]; if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    });
  }
  async function loadWorkspace() {
    try {
      const config = await api('/api/config'); state.mode = config.mode; $('backend-label').textContent = state.mode === 'demo' ? 'Tempo · демо' : 'Tempo'; $('demo-banner').hidden = state.mode !== 'demo'; $('help-backend').textContent = state.mode === 'demo' ? 'Сейчас включён демонстрационный режим с синтетическими данными.' : 'Источник: Tempo. Запросы идут через сервер Traceyard; адрес и учётные данные хранилища не передаются браузеру.';
      if ([20, 50, 100, 200].includes(Number(config.defaultLimit))) $('limit').value = String(config.defaultLimit);
      $('connection-dot').className = 'connection-dot ready'; handleHash(); await Promise.allSettled([search(), loadFacets()]);
    } catch (error) { if (!auth.user || error.status === 401 || error.name === 'AbortError') return; $('backend-label').textContent = 'Нет подключения'; $('connection-dot').className = 'connection-dot error'; $('error-banner').textContent = error.message; $('error-banner').hidden = false; showEmpty('Приложение не подключилось', 'Обновите страницу после восстановления связи с сервером.'); }
  }
  async function init() { bindEvents(); await checkSession(); }
  init();
})();
