/**
 * psst-secret — opt-in history of receive requests, kept only in this browser.
 *
 * Nothing is written to localStorage until the user turns the feature on. Each entry
 * holds the view link (with its reveal token and, unless password-protected, the key
 * seed), the submit link, an optional label, and status metadata. Labels never leave
 * the browser and decrypted content is never stored.
 *
 * Status checks use GET /api/v1/whisper/<id>/status, which never consumes a view.
 * Entries are removed when they expire, when the server reports them gone, and right
 * after the final allowed reveal.
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'psst.receiveHistory';
    const LOCK_NAME = 'psst.receiveHistory';
    const SCHEMA_VERSION = 1;
    const STATUS_INTERVAL_MS = 30000;
    const MIN_CHECK_GAP_MS = 15000;
    const LABEL_MAX_LENGTH = 100;
    const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    const STATUSES = ['pending', 'submitted', 'revealed', 'expired', 'burned'];
    const COMPLETED = ['submitted', 'revealed'];

    const listeners = [];

    // ---- Storage ----

    function storage() {
        try {
            return window.localStorage;
        } catch (e) {
            return null;
        }
    }

    function parseHttpUrl(value) {
        if (typeof value !== 'string') return null;
        try {
            const url = new URL(value);
            return url.protocol === 'https:' || url.protocol === 'http:' ? url : null;
        } catch (e) {
            return null;
        }
    }

    function validEntry(entry) {
        if (!entry || typeof entry !== 'object' || !UUID.test(entry.id)) return false;
        const view = parseHttpUrl(entry.viewUrl);
        const submit = parseHttpUrl(entry.submitUrl);
        return !!view && view.pathname === '/whisper/' + entry.id
            && !!submit && submit.pathname.startsWith('/submit/')
            && STATUSES.includes(entry.status)
            && Number.isFinite(entry.expiresAt);
    }

    /** Upgrade older stored schemas here. Unknown versions are left untouched. */
    function migrate(data) {
        if (!data || typeof data !== 'object' || data.version !== SCHEMA_VERSION) return null;
        return {
            version: SCHEMA_VERSION,
            enabled: data.enabled === true,
            entries: Array.isArray(data.entries) ? data.entries.filter(validEntry) : [],
        };
    }

    function load() {
        const store = storage();
        const empty = { version: SCHEMA_VERSION, enabled: false, entries: [] };
        if (!store) return empty;
        let raw;
        try {
            raw = store.getItem(STORAGE_KEY);
        } catch (e) {
            return empty;
        }
        if (raw === null) return empty;
        try {
            return migrate(JSON.parse(raw)) || empty;
        } catch (e) {
            return empty;
        }
    }

    /** Write data; return true only once the browser has accepted it. */
    function save(data) {
        const store = storage();
        if (!store) return false;
        try {
            if (!data.enabled && data.entries.length === 0) {
                store.removeItem(STORAGE_KEY);
            } else {
                store.setItem(STORAGE_KEY, JSON.stringify(data));
            }
        } catch (e) {
            // Storage full or blocked: report the failure to the caller.
            return false;
        }
        notify();
        return true;
    }

    /**
     * Apply fn to freshly loaded data and save it, holding a lock shared by every tab
     * so one tab's stale copy can never undo another tab's change. Resolves to true
     * when a change was persisted. fn returns false to skip saving.
     */
    function modify(fn) {
        const run = () => {
            const data = load();
            return fn(data) === false ? false : save(data);
        };
        const locks = navigator.locks;
        if (locks && typeof locks.request === 'function') {
            return locks.request(LOCK_NAME, run).catch(() => false);
        }
        return Promise.resolve(run());
    }

    function notify() {
        listeners.forEach(fn => fn());
    }

    // ---- Public data API ----

    function isEnabled() {
        return load().enabled;
    }

    function entries() {
        return load().entries;
    }

    function find(id) {
        return entries().find(e => e.id === id) || null;
    }

    async function enable() {
        if (!storage()) return false;
        await modify(data => { data.enabled = true; });
        return isEnabled();
    }

    /** Turn the feature off; delete every entry when deleteEntries is true. */
    function disable(deleteEntries) {
        return modify(data => {
            data.enabled = false;
            if (deleteEntries) data.entries = [];
        });
    }

    function cleanLabel(label) {
        return typeof label === 'string' ? label.trim().slice(0, LABEL_MAX_LENGTH) : '';
    }

    /** Save a new request; resolves to true only if it was persisted. */
    function add(details) {
        const expiresAt = Date.parse(details.expiresAt);
        const entry = {
            id: details.id,
            viewUrl: details.viewUrl,
            submitUrl: details.submitUrl,
            label: cleanLabel(details.label),
            createdAt: Date.now(),
            expiresAt: Number.isFinite(expiresAt) ? expiresAt : NaN,
            maxViews: Number.isInteger(details.maxViews) ? details.maxViews : null,
            remainingViews: Number.isInteger(details.maxViews) && details.maxViews > 0 ? details.maxViews : null,
            passwordProtected: !!details.passwordProtected,
            status: 'pending',
            checkedAt: 0,
        };
        if (!validEntry(entry)) return Promise.resolve(false);
        return modify(data => {
            if (!data.enabled) return false;
            data.entries = data.entries.filter(e => e.id !== entry.id);
            data.entries.unshift(entry);
        });
    }

    /** Patch an entry; fn receives the current entry and returns the patch or null. */
    function update(id, fn) {
        return modify(data => {
            const entry = data.entries.find(e => e.id === id);
            const patch = entry && fn(entry);
            if (!patch) return false;
            Object.assign(entry, patch);
        });
    }

    function setLabel(id, label) {
        return update(id, () => ({ label: cleanLabel(label) }));
    }

    function removeWhere(predicate) {
        return modify(data => {
            const before = data.entries.length;
            data.entries = data.entries.filter(e => !predicate(e));
            return data.entries.length !== before;
        });
    }

    function remove(id) {
        return removeWhere(e => e.id === id);
    }

    function clear() {
        return removeWhere(() => true);
    }

    /** Delete entries past their expiry without asking the server. */
    function removeExpired() {
        const now = Date.now();
        return removeWhere(e => !(e.expiresAt > now));
    }

    /** Record a reveal of a saved request; forget it once no views remain. */
    function recordReveal(id, result) {
        if (!result) return Promise.resolve(false);
        if (result.max_views > 0 && result.remaining_views <= 0) return remove(id);
        return update(id, () => ({
            status: 'revealed',
            maxViews: result.max_views,
            remainingViews: result.max_views > 0 ? result.remaining_views : null,
        }));
    }

    let refreshing = null;

    /** Ask the server about one entry; resolves to 'throttled' on HTTP 429. */
    async function checkStatus(entry) {
        let response;
        try {
            response = await fetch('/api/v1/whisper/' + entry.id + '/status', {
                credentials: 'same-origin',
                headers: { Accept: 'application/json' },
            });
        } catch (e) {
            return;
        }
        if (response.status === 429) return 'throttled';
        if (response.status === 404 || response.status === 410) {
            await remove(entry.id);
            return;
        }
        if (!response.ok) return;
        let data;
        try {
            data = await response.json();
        } catch (e) {
            return;
        }
        const expiresAt = Date.parse(data.expires_at);
        await update(entry.id, current => {
            let status = data.status === 'submitted' ? 'submitted' : 'pending';
            if (status === 'submitted' && (current.status === 'revealed' || data.view_count > 0)) {
                status = 'revealed';
            }
            let remainingViews = data.max_views > 0 ? data.remaining_views : null;
            // Views only decrease, so a response sent before a reveal in another tab must not restore them.
            if (Number.isInteger(remainingViews) && Number.isInteger(current.remainingViews)) {
                remainingViews = Math.min(remainingViews, current.remainingViews);
            }
            return {
                status,
                expiresAt: Number.isFinite(expiresAt) ? expiresAt : current.expiresAt,
                maxViews: data.max_views,
                remainingViews,
                checkedAt: Date.now(),
            };
        });
    }

    /** Remove expired entries and ask the server about the rest, least recently checked first. */
    function refresh(force) {
        if (refreshing) return refreshing;
        refreshing = (async () => {
            await removeExpired();
            const now = Date.now();
            const due = entries()
                .filter(e => force || now - (e.checkedAt || 0) >= MIN_CHECK_GAP_MS)
                .sort((a, b) => (a.checkedAt || 0) - (b.checkedAt || 0));
            for (const entry of due) {
                if (await checkStatus(entry) === 'throttled') break;
            }
        })().finally(() => { refreshing = null; });
        return refreshing;
    }

    function onChange(fn) {
        listeners.push(fn);
    }

    // ---- Formatting helpers ----

    function statusLabel(status) {
        switch (status) {
            case 'pending': return gettext('Waiting for sender');
            case 'submitted': return gettext('Ready to view');
            case 'revealed': return gettext('Viewed');
            case 'expired': return gettext('Expired');
            default: return gettext('Burned');
        }
    }

    function statusClasses(status) {
        if (status === 'pending') return 'bg-gray-900 border-gray-600 text-gray-300';
        if (status === 'submitted') return 'bg-brand-900/60 border-brand-700 text-brand-300';
        return 'bg-gray-900 border-gray-700 text-gray-400';
    }

    function language() {
        return document.documentElement.lang || undefined;
    }

    function formatDate(ms) {
        try {
            return new Date(ms).toLocaleString(language());
        } catch (e) {
            return new Date(ms).toLocaleString();
        }
    }

    function relativeTime(ms) {
        let seconds = Math.max(0, Math.round((ms - Date.now()) / 1000));
        const units = [['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
        let format;
        try {
            format = new Intl.RelativeTimeFormat(language(), { numeric: 'always' });
        } catch (e) {
            format = new Intl.RelativeTimeFormat(undefined, { numeric: 'always' });
        }
        for (const [unit, size] of units) {
            if (seconds >= size || unit === 'second') {
                return format.format(Math.floor(seconds / size), unit);
            }
        }
        return '';
    }

    function expiryText(ms) {
        return interpolate(gettext('Expires %s'), [relativeTime(ms)]);
    }

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    function statusBadge(status) {
        const badge = el('span', 'inline-block shrink-0 px-2 py-0.5 rounded-full text-xs font-semibold border ' + statusClasses(status), statusLabel(status));
        badge.dataset.statusBadge = status;
        return badge;
    }

    function expiryNode(entry, className) {
        const node = el('span', className, expiryText(entry.expiresAt));
        node.dataset.expiresAt = String(entry.expiresAt);
        node.title = formatDate(entry.expiresAt);
        return node;
    }

    function openWhisper(entry) {
        const url = parseHttpUrl(entry.viewUrl);
        if (url && url.pathname === '/whisper/' + entry.id) window.location.assign(url.toString());
    }

    function copyText(text, button) {
        navigator.clipboard.writeText(text).then(() => {
            const original = button.textContent;
            button.textContent = gettext('Copied!');
            setTimeout(() => { button.textContent = original; }, 2000);
        });
    }

    // ---- Opt-in toggles ----

    function syncToggles() {
        const enabled = isEnabled();
        document.querySelectorAll('[data-receive-history-toggle]').forEach(input => {
            input.checked = enabled;
        });
        document.querySelectorAll('[data-receive-history-when-enabled]').forEach(node => {
            node.classList.toggle('hidden', !enabled);
        });
    }

    function confirmDisable() {
        const count = entries().length;
        if (count === 0) return disable(true);
        const question = interpolate(
            ngettext(
                'Also delete the %s saved receive request from this browser? Choose Cancel to keep it.',
                'Also delete all %s saved receive requests from this browser? Choose Cancel to keep them.',
                count
            ),
            [count]
        );
        return disable(window.confirm(question));
    }

    function mountToggles() {
        document.querySelectorAll('[data-receive-history-toggle]').forEach(input => {
            input.addEventListener('change', async () => {
                if (input.checked) {
                    if (!(await enable())) input.checked = false;
                } else {
                    await confirmDisable();
                }
                syncToggles();
            });
        });
        syncToggles();
    }

    // ---- Drawer ----

    function mountDrawer() {
        const drawer = document.getElementById('receive-drawer');
        if (!drawer) return null;
        const toggle = document.getElementById('receive-drawer-toggle');
        const panel = document.getElementById('receive-drawer-panel');
        const list = document.getElementById('receive-drawer-list');
        const count = document.getElementById('receive-drawer-count');

        function setOpen(open) {
            toggle.setAttribute('aria-expanded', String(open));
            panel.hidden = !open;
            if (open) refresh();
        }

        toggle.addEventListener('click', () => setOpen(panel.hidden));
        drawer.addEventListener('keydown', event => {
            if (event.key === 'Escape' && !panel.hidden) {
                setOpen(false);
                toggle.focus();
            }
        });

        function render() {
            const data = load();
            const visible = data.enabled && data.entries.length > 0;
            drawer.classList.toggle('hidden', !visible);
            if (!visible) {
                setOpen(false);
                return;
            }
            count.textContent = String(data.entries.length);
            list.replaceChildren(...data.entries.map(entry => {
                const item = el('li', 'px-4 py-3 space-y-1');
                item.dataset.entryId = entry.id;
                const top = el('div', 'flex items-center justify-between gap-2');
                top.append(
                    el('span', 'truncate text-sm ' + (entry.label ? 'text-gray-100' : 'italic text-gray-500'), entry.label || gettext('No label')),
                    statusBadge(entry.status)
                );
                item.append(top, expiryNode(entry, 'block text-xs text-gray-500'));
                return item;
            }));
        }

        return { render, isOpen: () => !panel.hidden };
    }

    // ---- Dedicated page ----

    function mountPage() {
        const root = document.getElementById('receive-history-page');
        if (!root) return null;
        const list = document.getElementById('receive-history-list');
        const empty = document.getElementById('receive-history-empty');
        const clearButton = document.getElementById('receive-history-clear');
        const filters = root.querySelectorAll('[data-receive-filter]');
        let filter = 'all';
        let editing = null;
        let draft = '';
        let focusEditor = false;
        let returnFocus = null;

        filters.forEach(button => {
            button.addEventListener('click', () => {
                filter = button.dataset.receiveFilter;
                render();
            });
        });

        clearButton.addEventListener('click', () => {
            if (window.confirm(gettext('Delete all saved receive requests from this browser? You will no longer be able to open them from here.'))) {
                clear();
            }
        });

        function matches(entry) {
            if (filter === 'pending') return entry.status === 'pending';
            if (filter === 'completed') return COMPLETED.includes(entry.status);
            return true;
        }

        function button(label, className, onClick) {
            const node = el('button', className, label);
            node.type = 'button';
            node.addEventListener('click', onClick);
            return node;
        }

        const secondary = 'px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-white text-sm font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400';

        function closeEditor(id) {
            editing = null;
            returnFocus = id;
            render();
        }

        function labelEditor(entry) {
            const form = el('form', 'flex flex-wrap gap-2');
            const input = el('input', 'flex-1 min-w-0 rounded-lg bg-gray-900 border border-gray-600 text-gray-100 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500');
            input.type = 'text';
            input.maxLength = LABEL_MAX_LENGTH;
            input.value = draft;
            input.addEventListener('input', () => { draft = input.value; });
            input.setAttribute('aria-label', gettext('Label'));
            input.placeholder = gettext('e.g. AWS credentials from Bob');
            input.dataset.labelInput = '';
            input.dataset.action = 'label';
            const saveButton = el('button', 'px-3 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-semibold transition', gettext('Save'));
            saveButton.type = 'submit';
            saveButton.dataset.action = 'save-label';
            const cancelButton = button(gettext('Cancel'), secondary, () => closeEditor(entry.id));
            cancelButton.dataset.action = 'cancel-label';
            form.append(input, saveButton, cancelButton);
            form.addEventListener('submit', event => {
                event.preventDefault();
                editing = null;
                returnFocus = entry.id;
                setLabel(entry.id, input.value).finally(render);
            });
            form.addEventListener('keydown', event => {
                if (event.key === 'Escape') closeEditor(entry.id);
            });
            if (focusEditor) {
                focusEditor = false;
                setTimeout(() => input.focus(), 0);
            }
            return form;
        }

        function card(entry) {
            const item = el('li', 'rounded-lg bg-gray-800 border border-gray-700 p-4 space-y-3');
            item.dataset.entryId = entry.id;
            item.dataset.status = entry.status;

            const header = el('div', 'flex flex-wrap items-start justify-between gap-2');
            const title = el('h2', 'min-w-0 break-words font-semibold ' + (entry.label ? 'text-white' : 'italic text-gray-500'), entry.label || gettext('No label'));
            title.dataset.entryLabel = '';
            header.append(title, statusBadge(entry.status));

            const meta = el('p', 'flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-500');
            meta.append(
                el('span', '', interpolate(gettext('Created %s'), [formatDate(entry.createdAt)])),
                expiryNode(entry, '')
            );
            if (entry.maxViews > 0 && Number.isInteger(entry.remainingViews)) {
                meta.append(el('span', '', interpolate(
                    ngettext('%s view remaining', '%s views remaining', entry.remainingViews),
                    [entry.remainingViews]
                )));
            } else if (entry.maxViews === 0) {
                meta.append(el('span', '', gettext('Unlimited views')));
            }
            if (entry.passwordProtected) {
                meta.append(el('span', '', gettext('Password-protected')));
            }

            const submit = el('div', 'flex gap-2');
            const submitInput = el('input', 'flex-1 min-w-0 rounded-lg bg-gray-900 border border-gray-600 text-gray-300 px-3 py-1.5 font-mono text-xs focus:outline-none');
            submitInput.type = 'text';
            submitInput.readOnly = true;
            submitInput.value = entry.submitUrl;
            submitInput.setAttribute('aria-label', gettext('Submit link'));
            submitInput.dataset.action = 'submit-link';
            const copyButton = button(gettext('Copy submit link'), secondary, () => copyText(entry.submitUrl, copyButton));
            copyButton.dataset.action = 'copy-submit';
            submit.append(submitInput, copyButton);

            const actions = el('div', 'flex flex-wrap gap-2');
            const viewBtn = button(gettext('View whisper'), 'px-3 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400', () => openWhisper(entry));
            viewBtn.dataset.action = 'view';
            const editBtn = button(gettext('Edit label'), secondary, () => {
                editing = entry.id;
                draft = entry.label;
                focusEditor = true;
                render();
            });
            editBtn.dataset.action = 'edit';
            const removeBtn = button(gettext('Remove'), 'px-3 py-1.5 rounded-lg bg-gray-900 border border-red-800 text-red-300 hover:bg-red-900/40 text-sm font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500', () => remove(entry.id));
            removeBtn.dataset.action = 'remove';
            actions.append(viewBtn, editBtn, removeBtn);

            item.append(header, meta, submit);
            if (editing === entry.id) item.append(labelEditor(entry));
            item.append(actions);
            return item;
        }

        function render() {
            const all = entries();
            const shown = all.filter(matches);
            filters.forEach(node => {
                const active = node.dataset.receiveFilter === filter;
                node.setAttribute('aria-pressed', String(active));
                node.classList.toggle('bg-brand-600', active);
                node.classList.toggle('text-white', active);
                node.classList.toggle('bg-gray-800', !active);
                node.classList.toggle('text-gray-400', !active);
            });
            clearButton.disabled = all.length === 0;
            empty.classList.toggle('hidden', shown.length > 0);
            empty.textContent = all.length === 0
                ? gettext('No saved receive requests in this browser.')
                : gettext('No receive requests match this filter.');
            const active = document.activeElement;
            const activeItem = active && list.contains(active) ? active.closest('[data-entry-id]') : null;
            const focus = activeItem && active.dataset.action ? {
                id: activeItem.dataset.entryId,
                action: active.dataset.action,
                caret: active.tagName === 'INPUT' ? [active.selectionStart, active.selectionEnd] : null,
            } : null;
            list.replaceChildren(...shown.map(card));
            const cardFor = id => Array.from(list.children).find(node => node.dataset.entryId === id);
            if (returnFocus) {
                // The closed label editor took focus with it; hand it back to the card.
                const editButton = cardFor(returnFocus)?.querySelector('[data-action="edit"]');
                returnFocus = null;
                if (editButton) {
                    editButton.focus();
                    return;
                }
            }
            // Rebuilt cards would otherwise drop keyboard focus on every status refresh.
            const item = focus && cardFor(focus.id);
            const target = item && item.querySelector('[data-action="' + focus.action + '"]');
            if (target) {
                target.focus();
                if (focus.caret && target.tagName === 'INPUT') target.setSelectionRange(focus.caret[0], focus.caret[1]);
            }
        }

        return { render };
    }

    // ---- Page hooks ----

    function currentWhisperId() {
        const match = window.location.pathname.match(/^\/whisper\/([0-9a-f-]{36})$/);
        return match && UUID.test(match[1]) ? match[1] : null;
    }

    /** Update the saved entry for the whisper shown on this page, if any. */
    function syncCurrentPage() {
        const id = currentWhisperId();
        if (!id || !find(id)) return;
        if (document.querySelector('[data-whisper-gone]')) {
            remove(id);
            return;
        }
        const pasteData = document.getElementById('paste-data');
        if (pasteData) {
            try {
                recordReveal(id, JSON.parse(pasteData.textContent));
            } catch (e) {
                // Malformed page data: leave the entry for the next status check.
            }
        }
    }

    function init() {
        removeExpired();
        syncCurrentPage();
        mountToggles();
        const views = [mountDrawer(), mountPage()].filter(Boolean);
        const renderAll = () => {
            syncToggles();
            views.forEach(view => view.render());
        };
        onChange(renderAll);
        window.addEventListener('storage', event => {
            if (event.key === STORAGE_KEY || event.key === null) renderAll();
        });
        renderAll();

        if (entries().length > 0) refresh(!!document.getElementById('receive-history-page'));
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') refresh();
        });
        setInterval(() => {
            if (document.visibilityState !== 'visible') return;
            const pageOpen = !!document.getElementById('receive-history-page');
            const drawerOpen = views.some(view => view.isOpen && view.isOpen());
            if (pageOpen || drawerOpen) refresh();
        }, STATUS_INTERVAL_MS);
        // Keep countdowns current and drop entries the moment they expire.
        setInterval(() => {
            const now = Date.now();
            let expired = false;
            document.querySelectorAll('[data-expires-at]').forEach(node => {
                const at = Number(node.dataset.expiresAt);
                if (at <= now) expired = true;
                node.textContent = expiryText(at);
            });
            if (expired) removeExpired();
        }, 1000);
    }

    window.PsstReceiveHistory = {
        isEnabled,
        enable,
        disable,
        entries,
        find,
        add,
        setLabel,
        remove,
        clear,
        refresh,
        recordReveal,
        onChange,
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
