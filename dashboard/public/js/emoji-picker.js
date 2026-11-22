/**
 * Dashboard custom-emoji picker.
 *
 * Enhances every `[data-emoji-picker]` input with a button that opens a search
 * modal populated from `/api/emojis`. The chosen value is stored as the
 * canonical Discord token (`<:name:id>` / `<a:name:id>`), so the id and
 * animated flag survive a save and reload. The API only returns emojis that
 * exist in the live guild collections.
 */
(function () {
    'use strict';

    const CUSTOM_RE = /^<(a?):([A-Za-z0-9_~]+):(\d{15,22})>$/;
    const state = { data: null, inflight: null, input: null, modal: null };

    function parse(value) {
        const m = CUSTOM_RE.exec(String(value || '').trim());
        return m ? { animated: m[1] === 'a', name: m[2], id: m[3] } : null;
    }

    function token(emoji) {
        return `<${emoji.animated ? 'a' : ''}:${emoji.name}:${emoji.id}>`;
    }

    function cdn(emoji, size) {
        return `https://cdn.discordapp.com/emojis/${emoji.id}.${emoji.animated ? 'gif' : 'png'}?size=${size || 40}&quality=lossless`;
    }

    async function load() {
        if (state.data) return state.data;
        if (state.inflight) return state.inflight;
        state.inflight = (window.api ? window.api('/api/emojis') : fetch('/api/emojis').then(r => r.json()))
            .then(data => {
                state.data = data || { emojis: [] };
                return state.data;
            })
            .catch(() => ({ emojis: [], ready: false }))
            .finally(() => { state.inflight = null; });
        return state.inflight;
    }

    function ensureModal() {
        if (state.modal) return state.modal;
        const overlay = document.createElement('div');
        overlay.className = 'emoji-picker-overlay';
        overlay.innerHTML = `
            <div class="emoji-picker-modal" role="dialog" aria-modal="true" aria-label="Choose a custom emoji">
                <div class="emoji-picker-head">
                    <strong>Choose a custom emoji</strong>
                    <button type="button" class="emoji-picker-close" aria-label="Close">×</button>
                </div>
                <input type="search" class="emoji-picker-search" placeholder="Search emojis…" autocomplete="off" />
                <div class="emoji-picker-grid" role="listbox"></div>
                <div class="emoji-picker-status"></div>
            </div>`;
        document.body.appendChild(overlay);
        overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
        overlay.querySelector('.emoji-picker-close').addEventListener('click', close);
        const search = overlay.querySelector('.emoji-picker-search');
        search.addEventListener('input', () => render(search.value));
        state.modal = overlay;
        return overlay;
    }

    function close() {
        if (state.modal) state.modal.classList.remove('open');
        state.input = null;
    }

    function render(query) {
        const modal = ensureModal();
        const grid = modal.querySelector('.emoji-picker-grid');
        const status = modal.querySelector('.emoji-picker-status');
        const list = (state.data && state.data.emojis) || [];
        const q = String(query || '').trim().toLowerCase();
        const filtered = q
            ? list.filter(e => e.name.toLowerCase().includes(q) || (e.semanticKey || '').toLowerCase().includes(q))
            : list;
        grid.innerHTML = '';
        if (!filtered.length) {
            grid.innerHTML = '<div class="emoji-picker-empty">No emojis available. Check the bot\'s emoji-server access.</div>';
        }
        for (const emoji of filtered) {
            const item = document.createElement('button');
            item.type = 'button';
            item.className = 'emoji-picker-item';
            item.title = `${emoji.name}${emoji.sourceGuildId ? ` • ${emoji.sourceGuildId}` : ''}`;
            item.innerHTML = `<img src="${cdn(emoji, 40)}" alt="" loading="lazy" /><span>${emoji.name}</span>`;
            item.addEventListener('click', () => choose(emoji));
            grid.appendChild(item);
        }
        const guilds = (state.data && state.data.guilds) || [];
        const ok = guilds.filter(g => g.ok).length;
        status.textContent = state.data && state.data.ready
            ? `${filtered.length} emoji${filtered.length === 1 ? '' : 's'} • ${ok}/${guilds.length} emoji servers reachable`
            : 'Emoji catalog unavailable — existing values are left unchanged.';
    }

    function choose(emoji) {
        if (!state.input) return;
        state.input.value = token(emoji);
        state.input.dataset.emojiId = emoji.id;
        state.input.dataset.emojiName = emoji.name;
        state.input.dataset.emojiAnimated = emoji.animated ? 'true' : 'false';
        state.input.dispatchEvent(new Event('input', { bubbles: true }));
        state.input.dispatchEvent(new Event('change', { bubbles: true }));
        syncTrigger(state.input);
        close();
    }

    function syncTrigger(input) {
        const trigger = input._emojiPickerTrigger;
        if (!trigger) return;
        const emoji = parse(input.value);
        if (emoji) {
            trigger.innerHTML = `<img src="${cdn(emoji, 24)}" alt="" />`;
            trigger.classList.add('has-emoji');
        } else {
            trigger.textContent = '☺';
            trigger.classList.remove('has-emoji');
        }
    }

    function enhance(input) {
        if (!input || input.dataset.emojiPickerReady === '1') return;
        input.dataset.emojiPickerReady = '1';
        const trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'emoji-picker-trigger';
        trigger.title = 'Pick a custom emoji';
        trigger.setAttribute('aria-label', 'Pick a custom emoji');
        trigger.addEventListener('click', () => openFor(input));
        input._emojiPickerTrigger = trigger;
        input.insertAdjacentElement('afterend', trigger);
        input.addEventListener('input', () => syncTrigger(input));
        syncTrigger(input);
    }

    async function openFor(input) {
        state.input = input;
        const modal = ensureModal();
        modal.classList.add('open');
        const search = modal.querySelector('.emoji-picker-search');
        search.value = '';
        await load();
        render('');
        search.focus();
    }

    function initAll(root) {
        (root || document).querySelectorAll('input[data-emoji-picker]').forEach(enhance);
    }

    document.addEventListener('DOMContentLoaded', () => {
        initAll();
        const observer = new MutationObserver((records) => {
            for (const record of records) {
                for (const node of record.addedNodes) {
                    if (node.nodeType !== 1) continue;
                    if (node.matches && node.matches('input[data-emoji-picker]')) enhance(node);
                    if (node.querySelectorAll) initAll(node);
                }
            }
        });
        observer.observe(document.body, { childList: true, subtree: true });
    });

    window.PrimeBotEmojiPicker = { initAll, openFor, parse, token, load };
})();
