/* PrimeBot Dashboard — Embed Builder client (Features → Embed).
 *
 * A fully client-side Discord embed builder: live preview, dynamic fields
 * (add/duplicate/delete/reorder), templates, JSON import/export, Discord
 * limit validation, localStorage draft, and saved-embeds CRUD. Nothing is
 * written to the database while typing — only explicit Save/Rename/Duplicate/
 * Delete actions hit POST/PATCH/DELETE /api/guilds/:guildId/embeds, so Neon
 * compute stays minimal.
 *
 * All user-provided values are rendered via textContent (never innerHTML), so
 * imported JSON / typed content can never inject markup or script.
 */
(function () {
  'use strict';

  const GUILD_ID = (() => {
    const el = document.getElementById('guild-data');
    try { return el ? (JSON.parse(el.textContent).guildId || '') : ''; } catch { return ''; }
  })();

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // Discord embed limits (official).
  const LIMITS = {
    TITLE: 256,
    DESC: 4096,
    FIELD_NAME: 256,
    FIELD_VALUE: 1024,
    FIELD_COUNT: 25,
    FOOTER: 2048,
    AUTHOR: 256,
    TOTAL: 6000,
  };

  const DEFAULT_STATE = {
    content: '',
    title: '',
    description: '',
    url: '',
    color: '#5865F2',
    timestamp: true,
    authorEnabled: false,
    authorName: '',
    authorUrl: '',
    authorIcon: '',
    thumbnailEnabled: false,
    thumbnailUrl: '',
    imageEnabled: false,
    imageUrl: '',
    footerEnabled: false,
    footerText: '',
    footerIcon: '',
    fields: [],
  };

  const DRAFT_KEY = 'primebot.embed.draft.v1';

  let savedEmbeds = [];
  let editingId = null;   // saved embed being edited (modal save → PATCH)

  // ── state ──────────────────────────────────────────────────────────────
  function readFieldRow(card) {
    return {
      name: ($('.edb-field-name', card) || { value: '' }).value.trim(),
      value: ($('.edb-field-value', card) || { value: '' }).value,
      inline: !!($('.edb-field-inline-inp', card) || { checked: false }).checked,
    };
  }

  function readState() {
    const fields = [];
    $$('#eb-fields-list .edb-field-card').forEach((card) => {
      const f = readFieldRow(card);
      if (!f.name && !String(f.value).trim()) return;
      fields.push(f);
    });
    return {
      content: $('#eb-content') ? $('#eb-content').value : '',
      title: $('#eb-title').value.trim(),
      description: $('#eb-description').value,
      url: $('#eb-url').value.trim(),
      color: ($('#eb-color-text').value.trim() || '#5865F2'),
      timestamp: $('#eb-timestamp').checked,
      authorEnabled: $('#eb-author-enabled').checked,
      authorName: $('#eb-author-name').value.trim(),
      authorUrl: $('#eb-author-url').value.trim(),
      authorIcon: $('#eb-author-icon').value.trim(),
      thumbnailEnabled: $('#eb-thumbnail-enabled').checked,
      thumbnailUrl: $('#eb-thumbnail-url').value.trim(),
      imageEnabled: $('#eb-image-enabled').checked,
      imageUrl: $('#eb-image-url').value.trim(),
      footerEnabled: $('#eb-footer-enabled').checked,
      footerText: $('#eb-footer-text').value.trim(),
      footerIcon: $('#eb-footer-icon').value.trim(),
      fields: fields.slice(0, LIMITS.FIELD_COUNT),
    };
  }

  function applyState(s) {
    const st = Object.assign({}, DEFAULT_STATE, s || {});
    if ($('#eb-content')) $('#eb-content').value = st.content || '';
    $('#eb-title').value = st.title;
    $('#eb-description').value = st.description;
    $('#eb-url').value = st.url;
    const color = /^#[0-9a-fA-F]{6}$/.test(st.color) ? st.color : '#5865F2';
    $('#eb-color').value = color;
    $('#eb-color-text').value = color;
    $('#eb-timestamp').checked = !!st.timestamp;
    $('#eb-author-enabled').checked = !!st.authorEnabled;
    $('#eb-author-name').value = st.authorName;
    $('#eb-author-url').value = st.authorUrl;
    $('#eb-author-icon').value = st.authorIcon;
    $('#eb-thumbnail-enabled').checked = !!st.thumbnailEnabled;
    $('#eb-thumbnail-url').value = st.thumbnailUrl;
    $('#eb-image-enabled').checked = !!st.imageEnabled;
    $('#eb-image-url').value = st.imageUrl;
    $('#eb-footer-enabled').checked = !!st.footerEnabled;
    $('#eb-footer-text').value = st.footerText;
    $('#eb-footer-icon').value = st.footerIcon;
    renderFieldRows((st.fields || []).slice(0, LIMITS.FIELD_COUNT));
    syncSectionStates();
    renderPreview();
    updateValidation();
  }

  // ── fields ─────────────────────────────────────────────────────────────
  function renderFieldRows(fields) {
    const list = $('#eb-fields-list');
    if (!list) return;
    list.innerHTML = '';
    (fields && fields.length ? fields : []).forEach((f, i) => {
      list.appendChild(fieldRow(f, i));
    });
    reindexFields();
  }

  function fieldRow(f, i) {
    const row = document.createElement('div');
    row.className = 'edb-field-card';
    row.dataset.fieldIndex = String(i);
    row.setAttribute('draggable', 'true');
    row.innerHTML = `
      <div class="edb-field-card-head">
        <span class="edb-grip" title="Drag to reorder">${window.svgIcon ? window.svgIcon('grip') : '⋮⋮'}</span>
        <span class="edb-field-num">Field ${i + 1}</span>
        <span class="edb-field-actions">
          <button type="button" class="btn btn-secondary btn-sm edb-field-dupe" title="Duplicate field">Duplicate</button>
          <button type="button" class="btn btn-danger btn-sm edb-field-del" title="Delete field">Delete</button>
        </span>
      </div>
      <div class="edb-duo edb-field-name-row">
        <div class="edb-field">
          <label class="edb-label" for="eb-field-${i}-name">Field name</label>
          <input type="text" id="eb-field-${i}-name" class="edb-field-name" maxlength="${LIMITS.FIELD_NAME}" placeholder="Field name" />
          <span class="edb-counter" data-counter-for="eb-field-${i}-name">0 / ${LIMITS.FIELD_NAME}</span>
        </div>
      </div>
      <div class="edb-field">
        <label class="edb-label" for="eb-field-${i}-value">Field value</label>
        <textarea id="eb-field-${i}-value" class="edb-field-value" rows="3" maxlength="${LIMITS.FIELD_VALUE}" placeholder="Field value"></textarea>
        <span class="edb-counter" data-counter-for="eb-field-${i}-value">0 / ${LIMITS.FIELD_VALUE}</span>
      </div>
      <div class="edb-field-inline">
        <label class="switch" for="eb-field-${i}-inline"><input type="checkbox" class="edb-field-inline-inp" id="eb-field-${i}-inline"/><span class="slider"></span></label>
        <span class="edb-label-inline">Inline</span>
      </div>`;
    const nameInp = $('.edb-field-name', row);
    const valInp = $('.edb-field-value', row);
    const inlInp = $('.edb-field-inline-inp', row);
    if (nameInp) nameInp.value = f.name || '';
    if (valInp) valInp.value = f.value || '';
    if (inlInp) inlInp.checked = !!f.inline;
    return row;
  }

  function reindexFields() {
    $$('#eb-fields-list .edb-field-card').forEach((card, i) => {
      card.dataset.fieldIndex = String(i);
      card.setAttribute('draggable', 'true');
      const num = $('.edb-field-num', card);
      if (num) num.textContent = `Field ${i + 1}`;
      const nameInp = $('.edb-field-name', card);
      const valInp = $('.edb-field-value', card);
      const inlInp = $('.edb-field-inline-inp', card);
      if (nameInp) nameInp.id = `eb-field-${i}-name`;
      if (valInp) valInp.id = `eb-field-${i}-value`;
      if (inlInp) inlInp.id = `eb-field-${i}-inline`;
      const counters = $$('.edb-counter', card);
      if (counters[0]) counters[0].dataset.counterFor = `eb-field-${i}-name`;
      if (counters[1]) counters[1].dataset.counterFor = `eb-field-${i}-value`;
    });
  }

  function addField(beforeCard) {
    const list = $('#eb-fields-list');
    if (!list) return;
    if ($$('.edb-field-card', list).length >= LIMITS.FIELD_COUNT) {
      window.toast?.('You can add up to 25 fields.', 'error');
      return;
    }
    const row = fieldRow({ name: '', value: '', inline: false }, $$('.edb-field-card', list).length);
    if (beforeCard) beforeCard.after(row); else list.appendChild(row);
    reindexFields();
    schedule();
    updateCounters();
  }

  function deleteField(card) {
    card.remove();
    renderFieldRows(readState().fields);
    schedule();
  }

  function duplicateField(card) {
    const list = $('#eb-fields-list');
    if (!list) return;
    if ($$('.edb-field-card', list).length >= LIMITS.FIELD_COUNT) {
      window.toast?.('You can add up to 25 fields.', 'error');
      return;
    }
    const src = readFieldRow(card);
    const row = fieldRow({ name: src.name, value: src.value, inline: src.inline }, $$('.edb-field-card', list).length);
    card.after(row);
    reindexFields();
    schedule();
  }

  let dragCard = null;
  function bindDrag() {
    const list = $('#eb-fields-list');
    if (!list) return;
    list.addEventListener('dragstart', (e) => {
      const card = e.target.closest('.edb-field-card');
      if (!card) return;
      dragCard = card;
      card.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      try { e.dataTransfer.setData('text/plain', 'field'); } catch { /* older browsers */ }
    });
    list.addEventListener('dragover', (e) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      const after = closestRow(e.clientY);
      if (after) {
        list.insertBefore(dragCard, after.nextSibling || null);
        reindexFields();
      }
    });
    list.addEventListener('dragend', () => {
      $$('.edb-field-card.dragging', list).forEach(c => c.classList.remove('dragging'));
      dragCard = null;
      reindexFields();
      schedule();
    });
    list.addEventListener('drop', (e) => {
      e.preventDefault();
      reindexFields();
      schedule();
    });
  }
  function closestRow(y) {
    const list = $('#eb-fields-list');
    if (!list) return null;
    let result = null;
    $$('.edb-field-card', list).forEach(card => {
      if (card === dragCard) return;
      const r = card.getBoundingClientRect();
      if (y > r.top + r.height / 2) result = card;
    });
    return result;
  }

  // ── preview ────────────────────────────────────────────────────────────
  function renderPreview() {
    const s = readState();
    const text = (v) => v == null ? '' : String(v);
    // Author
    const authorShown = s.authorEnabled && (s.authorName || s.authorIcon);
    $('#eb-pv-author').classList.toggle('hidden', !authorShown);
    $('#eb-pv-author-name').textContent = s.authorName || '';
    $('#eb-pv-author-icon').classList.toggle('hidden', !s.authorIcon);
    if (s.authorIcon) $('#eb-pv-author-icon').src = s.authorIcon;
    const authorLink = $('#eb-pv-author-link');
    if (s.authorUrl && isValidUrl(s.authorUrl)) { authorLink.href = s.authorUrl; authorLink.removeAttribute('target'); }
    else authorLink.removeAttribute('href');
    // Title
    const titleShown = !!s.title;
    $('#eb-pv-title').classList.toggle('hidden', !titleShown);
    const titleLink = $('#eb-pv-title-link');
    titleLink.textContent = s.title || '';
    if (s.url && isValidUrl(s.url) && s.title) { titleLink.href = s.url; titleLink.removeAttribute('target'); }
    else titleLink.removeAttribute('href');
    // Description
    $('#eb-pv-desc').classList.toggle('hidden', !s.description);
    $('#eb-pv-desc').textContent = s.description || '';
    // Thumbnail
    const thumbShown = s.thumbnailEnabled && s.thumbnailUrl && isValidUrl(s.thumbnailUrl);
    $('#eb-pv-thumb').classList.toggle('hidden', !thumbShown);
    if (thumbShown) $('#eb-pv-thumb-img').src = s.thumbnailUrl;
    // Image
    const imageShown = s.imageEnabled && s.imageUrl && isValidUrl(s.imageUrl);
    $('#eb-pv-image').classList.toggle('hidden', !imageShown);
    if (imageShown) $('#eb-pv-image-img').src = s.imageUrl;
    // Fields
    const fields = s.fields;
    const pv = $('#eb-pv-fields');
    pv.innerHTML = '';
    fields.forEach((f) => {
      const rowEl = document.createElement('div');
      rowEl.className = 'tk-preview-embed-field' + (f.inline ? ' inline' : '');
      const n = document.createElement('div');
      n.className = 'tk-preview-embed-field-name';
      n.textContent = f.name || 'Field name';
      const v = document.createElement('div');
      v.className = 'tk-preview-embed-field-value';
      v.textContent = f.value || '\u200b';
      rowEl.appendChild(n);
      rowEl.appendChild(v);
      pv.appendChild(rowEl);
    });
    pv.classList.toggle('hidden', !fields.length);
    // Footer
    const footerShown = s.footerEnabled && (s.footerText || s.footerIcon);
    $('#eb-pv-footer').classList.toggle('hidden', !footerShown);
    $('#eb-pv-footer-text').textContent = s.footerText || '';
    $('#eb-pv-footer-icon').classList.toggle('hidden', !s.footerIcon);
    if (s.footerIcon) $('#eb-pv-footer-icon').src = s.footerIcon;
    const time = $('#eb-pv-time');
    if (s.timestamp) {
      time.textContent = '';
      time.classList.remove('hidden');
    } else {
      time.classList.add('hidden');
    }
    // Color bar
    const colorBar = $('#eb-preview-bar');
    if (colorBar) colorBar.style.background = /^#[0-9a-fA-F]{6}$/.test(s.color) ? s.color : '#5865F2';
    syncSectionStates();
  }

  // Grey out the input regions that are disabled (author/thumbnail/image/footer).
  function syncSectionStates() {
    const s = readState();
    const region = (sel, on) => {
      const el = $(sel);
      if (el) el.classList.toggle('embed-region-disabled', !on);
    };
    region('[data-region="author"]', s.authorEnabled);
    region('[data-region="thumbnail"]', s.thumbnailEnabled);
    region('[data-region="image"]', s.imageEnabled);
    region('[data-region="footer"]', s.footerEnabled);
  }

  // ── validation ─────────────────────────────────────────────────────────
  function isValidUrl(str) {
    if (!str) return false;
    try {
      const u = new URL(str);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
      return false;
    }
  }

  // Discord total-embed size contribution (characters, official rules).
  function totalCharacters(s) {
    let total = 0;
    total += (s.title || '').length;
    total += (s.description || '').length;
    total += (s.authorName || '').length;
    total += (s.footerText || '').length;
    for (const f of s.fields || []) total += (f.name || '').length + (f.value || '').length;
    return total;
  }

  function validateState(s) {
    const errors = [];
    const warn = [];
    const urlFields = [
      ['url', 'Embed URL'],
      ['authorUrl', 'Author URL'],
      ['authorIcon', 'Author icon URL'],
      ['thumbnailUrl', 'Thumbnail URL'],
      ['imageUrl', 'Image URL'],
      ['footerIcon', 'Footer icon URL'],
    ];
    for (const [key, label] of urlFields) {
      const v = (s || {})[key];
      if (v && !isValidUrl(v)) errors.push(`${label} is not a valid http(s) URL.`);
    }
    if ((s.content || '').length > 2000) errors.push(`Message content is ${(s.content || '').length}/2000 — max 2,000 characters.`);
    if ((s.title || '').length > LIMITS.TITLE) errors.push(`Title is ${(s.title || '').length}/${LIMITS.TITLE} — max ${LIMITS.TITLE} characters.`);
    if ((s.description || '').length > LIMITS.DESC) errors.push(`Description is ${(s.description || '').length}/${LIMITS.DESC} — max ${LIMITS.DESC} characters.`);
    if ((s.authorName || '').length > LIMITS.AUTHOR) errors.push(`Author name is ${(s.authorName || '').length}/${LIMITS.AUTHOR} — max ${LIMITS.AUTHOR} characters.`);
    if ((s.footerText || '').length > LIMITS.FOOTER) errors.push(`Footer text is ${(s.footerText || '').length}/${LIMITS.FOOTER} — max ${LIMITS.FOOTER} characters.`);
    if ((s.fields || []).length > LIMITS.FIELD_COUNT) errors.push(`Too many fields (${(s.fields || []).length}/${LIMITS.FIELD_COUNT}).`);
    for (let i = 0; i < (s.fields || []).length; i++) {
      const f = s.fields[i];
      if ((f.name || '').length > LIMITS.FIELD_NAME) errors.push(`Field ${i + 1} name exceeds ${LIMITS.FIELD_NAME} characters.`);
      if ((f.value || '').length > LIMITS.FIELD_VALUE) errors.push(`Field ${i + 1} value exceeds ${LIMITS.FIELD_VALUE} characters.`);
      if (!f.name && !String(f.value || '').trim()) errors.push(`Field ${i + 1} is empty — fill in a name and value, or delete it.`);
    }
    const total = totalCharacters(s);
    if (total > LIMITS.TOTAL) {
      errors.push(`Total embed is ${total.toLocaleString()}/${LIMITS.TOTAL.toLocaleString()} — max 6,000 characters.`);
    } else if (total > LIMITS.TOTAL - 2000) {
      warn.push(`${total.toLocaleString()} / ${LIMITS.TOTAL.toLocaleString()} characters — close to the 6,000 limit.`);
    }
    return { errors, warns: warn, total };
  }

  function updateValidation() {
    const s = readState();
    const strip = $('#eb-validation-strip');
    if (!strip) return;
    const { errors, warns, total } = validateState(s);
    updateFieldCounters(s);
    strip.innerHTML = '';
    if (errors.length) {
      errors.slice(0, 3).forEach((msg) => {
        const p = document.createElement('p');
        p.className = 'edb-validation-error';
        p.textContent = `⚠ ${msg}`;
        strip.appendChild(p);
      });
      strip.classList.add('has-error');
      strip.classList.remove('has-warn');
    } else if (warns.length) {
      warns.slice(0, 2).forEach((msg) => {
        const p = document.createElement('p');
        p.className = 'edb-validation-warn';
        p.textContent = msg;
        strip.appendChild(p);
      });
      strip.classList.remove('has-error');
      strip.classList.add('has-warn');
    } else {
      strip.classList.remove('has-error', 'has-warn');
      const ok = document.createElement('p');
      ok.className = 'edb-validation-ok';
      ok.textContent = `✓ Valid embed — ${total.toLocaleString()} / ${LIMITS.TOTAL.toLocaleString()} characters`;
      strip.appendChild(ok);
    }
  }

  function updateFieldCounters(s) {
    // The live reader counts the DOM rows; the preview reads normalized state.
    const count = (s.fields || []).length;
    const el = $('#eb-fields-counter');
    if (el) el.textContent = `${count} / ${LIMITS.FIELD_COUNT}`;
    const emptyEl = $('#eb-fields-empty');
    if (emptyEl) emptyEl.classList.toggle('hidden', count > 0);
  }

  function updateCounters() {
    const targets = ['eb-title', 'eb-description', 'eb-author-name', 'eb-footer-text', 'eb-content'];
    const maxes = { 'eb-title': LIMITS.TITLE, 'eb-description': LIMITS.DESC, 'eb-author-name': LIMITS.AUTHOR, 'eb-footer-text': LIMITS.FOOTER, 'eb-content': 2000 };
    for (const id of targets) {
      const el = document.getElementById(id);
      if (!el) continue;
      const counter = el.closest('.edb-field')?.querySelector('.edb-counter');
      if (!counter) continue;
      const max = maxes[id];
      const n = el.value.length;
      counter.textContent = `${n} / ${max}`;
      counter.classList.toggle('edb-over', n > max);
      el.classList.toggle('edb-input-over', n > max);
    }
    // Fields count + empty state live in the Fields section header/empty area.
    const fieldCount = $$('#eb-fields-list .edb-field-card').length;
    const countEl = $('#eb-fields-counter');
    if (countEl) countEl.textContent = `${fieldCount} / ${LIMITS.FIELD_COUNT}`;
    const emptyEl = $('#eb-fields-empty');
    if (emptyEl) emptyEl.classList.toggle('hidden', fieldCount > 0);
    $$('#eb-fields-list .edb-field-card').forEach((card) => {
      const nameEl = $('.edb-field-name', card);
      const valEl = $('.edb-field-value', card);
      const counters = $$('.edb-counter', card);
      if (nameEl && counters[0]) {
        counters[0].textContent = `${nameEl.value.length} / ${LIMITS.FIELD_NAME}`;
        counters[0].classList.toggle('edb-over', nameEl.value.length > LIMITS.FIELD_NAME);
      }
      if (valEl && counters[1]) {
        counters[1].textContent = `${valEl.value.length} / ${LIMITS.FIELD_VALUE}`;
        counters[1].classList.toggle('edb-over', valEl.value.length > LIMITS.FIELD_VALUE);
      }
    });
    // URL notes.
    $$('.edb-note[data-url-for]').forEach((note) => {
      const input = document.getElementById(note.dataset.urlFor);
      const val = input ? input.value.trim() : '';
      if (!val) { note.textContent = ''; note.classList.remove('edb-url-error'); return; }
      const ok = isValidUrl(val);
      note.textContent = ok ? '' : 'Invalid URL — must start with http:// or https://';
      note.classList.toggle('edb-url-error', !ok);
      note.classList.toggle('edb-char-limit', !ok);
    });
  }

  // ── templates ──────────────────────────────────────────────────────────
  const TEMPLATES = {
    announcement: {
      title: '📢 Announcement',
      description: 'This is an important announcement for everyone in the community!\n\nPlease read it carefully and react below if you have any questions.',
      color: '#5865F2',
      timestamp: true,
      authorEnabled: true, authorName: 'PrimeBot', authorUrl: '', authorIcon: '',
      footerEnabled: true, footerText: 'PrimeBot Announcements', footerIcon: '',
      fields: [],
    },
    welcome: {
      title: '👋 Welcome to the server!',
      description: 'We are so glad you joined! Grab your roles, read the rules, and say hi in #general.\n\n**Need help?** Open a ticket or mention a moderator.',
      color: '#3ba55d',
      timestamp: true,
      authorEnabled: true, authorName: 'Welcome Team', authorIcon: '',
      footerEnabled: true, footerText: 'We hope you enjoy your stay!',
      fields: [{ name: 'Rules', value: 'Check <#rules> first!', inline: true }, { name: 'Roles', value: 'Self-assign in #roles', inline: true }],
    },
    rules: {
      title: '📜 Server Rules',
      description: 'Follow these rules to keep the community fun and safe for everyone.',
      color: '#5865F2',
      timestamp: true,
      fields: [
        { name: '1. Be respectful', value: 'Treat others how you want to be treated. No harassment or hate speech.', inline: false },
        { name: '2. No spam', value: 'Keep messages on-topic and avoid flooding channels.', inline: true },
        { name: '3. No NSFW', value: 'Keep all content safe for work.', inline: true },
        { name: '4. Follow Discord ToS', value: 'No illegal content or activities.', inline: true },
      ],
    },
    giveaway: {
      title: '🎉 Giveaway Time!',
      description: 'We are giving away an amazing prize!\n\n**How to enter:**\n1. React with 🎉\n2. Invite a friend\n3. Wait for the winner announcement',
      color: '#f0b232',
      timestamp: true,
      footerEnabled: true, footerText: 'Giveaway ends in 24 hours',
      fields: [{ name: 'Prize', value: '1x Nitro — 1 month', inline: true }, { name: 'Entries', value: 'Open to all members', inline: true }],
    },
    ticket: {
      title: '🎫 Support Tickets',
      description: 'Need help? Click the button below to open a ticket and our team will assist you as soon as possible.',
      color: '#5865F2',
      timestamp: true,
      footerEnabled: true, footerText: 'Average response time: <15 minutes',
      fields: [{ name: 'Before opening', value: 'Check the FAQ channel first — your answer may already be there.', inline: false }],
    },
    warning: {
      title: '⚠️ Warning',
      description: 'Your behavior does not match our community guidelines. Please review the rules carefully.',
      color: '#f0b232',
      timestamp: true,
      footerEnabled: true, footerText: 'Moderation Team',
      fields: [{ name: 'Reason', value: 'Repeated rule violations', inline: true }, { name: 'Next step', value: 'Further violations may lead to a ban', inline: true }],
    },
    success: {
      title: '✅ Success!',
      description: 'Your request has been processed successfully. You should see the changes right away.',
      color: '#3ba55d',
      timestamp: true,
      fields: [{ name: 'What changed', value: 'Your roles and permissions were updated.', inline: false }],
    },
    error: {
      title: '❌ Something went wrong',
      description: 'We could not process your request. Please try again in a few minutes.',
      color: '#ed4245',
      timestamp: true,
      footerEnabled: true, footerText: 'If this persists, please open a ticket.',
      fields: [{ name: 'Error code', value: 'ERR_UNKNOWN', inline: true }, { name: 'Suggested fix', value: 'Try again later', inline: true }],
    },
    information: {
      title: 'ℹ️ Information',
      description: 'Here is some useful information that might answer your question.',
      color: '#4eb2e0',
      timestamp: true,
      fields: [{ name: 'Topic', value: 'General', inline: true }, { name: 'Status', value: 'Live', inline: true }],
    },
    moderation: {
      title: '🛡️ Moderation Notice',
      description: 'This is an official moderation notice regarding recent activity in this server.',
      color: '#ed4245',
      timestamp: true,
      authorEnabled: true, authorName: 'Moderation', 
      footerEnabled: true, footerText: 'PrimeBot Moderators',
      fields: [
        { name: 'Action', value: 'Muted for 24h', inline: true },
        { name: 'Reason', value: 'Repeated spam in general chat', inline: true },
      ],
    },
    event: {
      title: '📅 Upcoming Event',
      description: 'Join us for this fun community event!\n\n**When:** This Friday at 8 PM UTC\n**Where:** Voice channel "Community Stage"',
      color: '#4eb2e0',
      timestamp: true,
      footerEnabled: true, footerText: 'Mark your calendars!',
      fields: [{ name: 'Host', value: 'Event Team', inline: true }, { name: 'Prizes', value: 'Exclusive roles & more', inline: true }],
    },
  };

  function loadTemplate(key) {
    const t = TEMPLATES[key];
    if (!t) return;
    const base = readState();
    // Preserve fields input but replace the rest with the template (fully edit after).
    applyState(Object.assign({}, base, t, { fields: t.fields || [] }));
    saveDraft();
    window.toast?.(`Loaded the ${(key[0].toUpperCase() + key.slice(1))} template`, 'success');
  }

  // ── import / export ────────────────────────────────────────────────────
  function normalizeImported(raw) {
    // Accept either a full message payload ({ content, embeds: [...] }) or a
    // bare embed object ({ title, fields, … }). Always return a state object.
    const src = (raw && typeof raw === 'object') ? raw : {};
    const embeds = Array.isArray(src.embeds) ? src.embeds : (Array.isArray(src.embed) ? src.embed : (src.embed ? [src.embed] : []));
    let embed;
    if (Array.isArray(embeds) && embeds.length) {
      embed = embeds[0];
    } else if (src.title !== undefined || src.description !== undefined || src.fields !== undefined
        || src.color !== undefined || src.footer || src.author || src.image || src.thumbnail) {
      // A bare embed object (Discord embed JSON) — use it directly.
      embed = src;
    } else {
      embed = {};
    }
    const color = typeof embed.color === 'number'
      ? '#' + ('000000' + (embed.color & 0xFFFFFF).toString(16)).slice(-6)
      : (typeof embed.color === 'string' && /^#[0-9a-fA-F]{6}$/.test(embed.color) ? embed.color : '#5865F2');
    return {
      content: typeof src.content === 'string' ? src.content.slice(0, 2000) : '',
      title: embed.title || '',
      description: embed.description || '',
      url: embed.url || '',
      color,
      timestamp: typeof embed.timestamp === 'string' ? true : (embed.timestamp != null ? !!embed.timestamp : false),
      authorEnabled: !!embed.author,
      authorName: (embed.author && embed.author.name) || '',
      authorUrl: (embed.author && embed.author.url) || '',
      authorIcon: (embed.author && embed.author.icon_url) || '',
      thumbnailEnabled: !!embed.thumbnail,
      thumbnailUrl: (embed.thumbnail && embed.thumbnail.url) || '',
      imageEnabled: !!embed.image,
      imageUrl: (embed.image && embed.image.url) || '',
      footerEnabled: !!embed.footer,
      footerText: (embed.footer && embed.footer.text) || '',
      footerIcon: (embed.footer && embed.footer.icon_url) || '',
      fields: Array.isArray(embed.fields) ? embed.fields.map((f) => ({
        name: f.name || '',
        value: f.value || '',
        inline: !!f.inline,
      })).slice(0, LIMITS.FIELD_COUNT) : [],
    };
  }

  function buildEmbedObject(s) {
    const embed = {};
    if (s.authorEnabled && (s.authorName || s.authorIcon)) {
      embed.author = {};
      if (s.authorName) embed.author.name = s.authorName;
      if (s.authorUrl && isValidUrl(s.authorUrl)) embed.author.url = s.authorUrl;
      if (s.authorIcon && isValidUrl(s.authorIcon)) embed.author.icon_url = s.authorIcon;
      if (!Object.keys(embed.author).length) delete embed.author;
    }
    if (s.title) embed.title = s.title;
    if (s.description) embed.description = s.description;
    if (s.url && isValidUrl(s.url)) embed.url = s.url;
    embed.color = parseInt((/^#[0-9a-fA-F]{6}$/.test(s.color) ? s.color : '#5865F2').slice(1), 16);
    if (s.timestamp) embed.timestamp = new Date().toISOString();
    if (s.thumbnailEnabled && s.thumbnailUrl && isValidUrl(s.thumbnailUrl)) embed.thumbnail = { url: s.thumbnailUrl };
    if (s.imageEnabled && s.imageUrl && isValidUrl(s.imageUrl)) embed.image = { url: s.imageUrl };
    if (s.footerEnabled && (s.footerText || s.footerIcon)) {
      embed.footer = {};
      if (s.footerText) embed.footer.text = s.footerText;
      if (s.footerIcon && isValidUrl(s.footerIcon)) embed.footer.icon_url = s.footerIcon;
      if (!Object.keys(embed.footer).length) delete embed.footer;
    }
    if (s.fields && s.fields.length) {
      embed.fields = s.fields.map((f) => ({ name: f.name || '\u200b', value: f.value || '\u200b', inline: !!f.inline }));
    }
    return embed;
  }

  function buildPayload(s) {
    const payload = {};
    if (s.content) payload.content = s.content;
    const embed = buildEmbedObject(s);
    if (Object.keys(embed).length) payload.embeds = [embed];
    return payload;
  }

  function currentIsValid() {
    return validateState(readState()).errors.length === 0;
  }

  function exportEmbedJson() {
    const s = readState();
    const v = validateState(s);
    if (v.errors.length) {
      window.toast?.(v.errors[0], 'error');
      return null;
    }
    return buildEmbedObject(s);
  }

  async function copyText(text, verb) {
    try {
      await navigator.clipboard.writeText(text);
      window.toast?.(`${verb} copied to clipboard`, 'success');
    } catch {
      // Fallback for non-secure contexts / older browsers.
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
        window.toast?.(`${verb} copied to clipboard`, 'success');
      } catch {
        window.toast?.('Could not copy — your browser blocked clipboard access.', 'error');
      }
    }
  }

  function importJsonPrompt() {
    const text = window.prompt('Paste Discord embed/message JSON:', '');
    if (text == null) return;
    try {
      const parsed = JSON.parse(text);
      const st = normalizeImported(parsed);
      applyState(st);
      saveDraft();
      window.toast?.('JSON imported successfully', 'success');
    } catch (err) {
      window.toast?.(`Invalid JSON: ${err.message}`, 'error');
    }
  }

  // ── draft (localStorage) ───────────────────────────────────────────────
  function saveDraft() {
    try {
      localStorage.setItem(DRAFT_KEY, JSON.stringify({ v: 1, ts: Date.now(), state: readState() }));
    } catch { /* private mode — skip */ }
  }

  function loadDraft() {
    try {
      const raw = localStorage.getItem(DRAFT_KEY);
      if (!raw) return false;
      const parsed = JSON.parse(raw);
      if (!parsed || parsed.v !== 1 || !parsed.state) return false;
      // Only restore a draft that is still reasonably fresh (e.g. within 7 days).
      if (parsed.ts && (Date.now() - parsed.ts) > 7 * 24 * 60 * 60 * 1000) return false;
      applyState(parsed.state);
      return true;
    } catch {
      return false;
    }
  }

  function clearDraft() {
    try { localStorage.removeItem(DRAFT_KEY); } catch { /* ignore */ }
  }

  // ── saved embeds (API) ────────────────────────────────────────────────
  async function refreshSavedEmbeds(query = '') {
    const list = $('#eb-saved-list');
    if (!list) return;
    try {
      const data = await window.api(`/api/guilds/${GUILD_ID}/embeds`);
      savedEmbeds = (data && data.embeds) || [];
      renderSavedList(query);
    } catch (err) {
      list.innerHTML = `<p class="live-empty">Could not load saved embeds: ${window.esc ? window.esc(err.message) : err.message}</p>`;
    }
  }

  function renderSavedList(query = '') {
    const list = $('#eb-saved-list');
    if (!list) return;
    const q = (query || '').trim().toLowerCase();
    const items = savedEmbeds.filter((e) => !q || String(e.name || '').toLowerCase().includes(q));
    if (!items.length) {
      list.innerHTML = `<p class="live-empty">${savedEmbeds.length ? 'No saved embeds match your search.' : 'No saved embeds yet. Build an embed and hit "Save current embed".'}</p>`;
      return;
    }
    list.innerHTML = '';
    items.forEach((e) => {
      const row = document.createElement('div');
      row.className = 'embed-saved-row';
      const name = document.createElement('div');
      name.className = 'embed-saved-name';
      const nameSpan = document.createElement('span');
      nameSpan.textContent = e.name;
      nameSpan.title = e.name;
      name.appendChild(nameSpan);
      const meta = document.createElement('div');
      meta.className = 'embed-saved-meta';
      meta.textContent = `updated ${new Date(e.updatedAt).toLocaleString()}`;
      name.appendChild(meta);
      const actions = document.createElement('div');
      actions.className = 'embed-saved-actions-group';
      actions.innerHTML = `
        <button type="button" class="btn btn-secondary btn-sm eb-load" title="Load this embed into the builder">Load</button>
        <button type="button" class="btn btn-secondary btn-sm eb-rename" title="Rename this embed">Rename</button>
        <button type="button" class="btn btn-secondary btn-sm eb-dupe" title="Duplicate this saved embed">Duplicate</button>
        <button type="button" class="btn btn-danger btn-sm eb-del" title="Delete this saved embed">Delete</button>`;
      actions.querySelector('.eb-load').addEventListener('click', () => loadSavedEmbed(e.id));
      actions.querySelector('.eb-rename').addEventListener('click', () => openRenameModal(e));
      actions.querySelector('.eb-dupe').addEventListener('click', () => duplicateSavedEmbed(e.id));
      actions.querySelector('.eb-del').addEventListener('click', () => deleteSavedEmbed(e.id));
      row.appendChild(name);
      row.appendChild(actions);
      list.appendChild(row);
    });
  }

  function loadSavedEmbed(id) {
    const embed = savedEmbeds.find((e) => Number(e.id) === Number(id));
    if (!embed) {
      window.toast?.('That saved embed is no longer available.', 'error');
      refreshSavedEmbeds($('#eb-saved-search') ? $('#eb-saved-search').value : '');
      return;
    }
    // The saved payload is our own builder state shape → apply directly.
    applyState(embed.payload || DEFAULT_STATE);
    saveDraft();
    window.toast?.(`Loaded “${embed.name}”`, 'success');
  }

  function openSaveModal() {
    editingId = null;
    $('#eb-modal-title').textContent = 'Save embed';
    $('#eb-modal-name').value = '';
    $('#eb-modal-name').focus();
    $('#eb-modal-hint').textContent = 'Save the current builder state as a named embed for this server.';
    $('#eb-modal-validation').innerHTML = '';
    $('#eb-modal-overlay').classList.remove('hidden');
  }

  function openRenameModal(embed) {
    editingId = embed.id;
    $('#eb-modal-title').textContent = 'Rename embed';
    $('#eb-modal-name').value = embed.name;
    $('#eb-modal-name').focus();
    $('#eb-modal-hint').textContent = 'Only the name is changed — the saved payload stays the same.';
    $('#eb-modal-validation').innerHTML = '';
    $('#eb-modal-overlay').classList.remove('hidden');
  }

  function closeModal() {
    $('#eb-modal-overlay').classList.add('hidden');
    editingId = null;
  }

  async function confirmModal() {
    const name = $('#eb-modal-name').value.trim();
    const validation = $('#eb-modal-validation');
    validation.innerHTML = '';
    if (!name) {
      validation.innerHTML = '<p class="edb-validation-error">⚠ An embed name is required.</p>';
      $('#eb-modal-name').focus();
      return;
    }
    try {
      const btn = $('#eb-modal-confirm');
      btn.disabled = true;
      btn.textContent = 'Saving…';
      if (editingId) {
        await window.api(`/api/guilds/${GUILD_ID}/embeds/${editingId}`, { method: 'PATCH', body: JSON.stringify({ name }) });
        window.toast?.('Embed renamed', 'success');
      } else {
        const body = JSON.stringify({ name, payload: readState() });
        await window.api(`/api/guilds/${GUILD_ID}/embeds`, { method: 'POST', body });
        window.toast?.('Embed saved', 'success');
      }
      closeModal();
      clearDraft();
      refreshSavedEmbeds($('#eb-saved-search').value);
    } catch (err) {
      validation.innerHTML = `<p class="edb-validation-error">⚠ ${window.esc ? window.esc(err.message) : err.message}</p>`;
    } finally {
      const btn = $('#eb-modal-confirm');
      btn.disabled = false;
      btn.textContent = 'Save';
    }
  }

  async function duplicateSavedEmbed(id) {
    try {
      await window.api(`/api/guilds/${GUILD_ID}/embeds/${id}/duplicate`, { method: 'POST' });
      window.toast?.('Embed duplicated', 'success');
      refreshSavedEmbeds($('#eb-saved-search').value);
    } catch (err) {
      window.toast?.(err.message || 'Failed to duplicate the embed.', 'error');
    }
  }

  async function deleteSavedEmbed(id) {
    if (!window.confirm('Delete this saved embed? This cannot be undone.')) return;
    try {
      await window.api(`/api/guilds/${GUILD_ID}/embeds/${id}`, { method: 'DELETE' });
      window.toast?.('Embed deleted', 'success');
      refreshSavedEmbeds($('#eb-saved-search').value);
    } catch (err) {
      window.toast?.(err.message || 'Failed to delete the embed.', 'error');
    }
  }

  // ── scheduling (debounced) ─────────────────────────────────────────────
  let scheduleT = null;
  function schedule() {
    clearTimeout(scheduleT);
    scheduleT = setTimeout(() => {
      renderPreview();
      updateValidation();
      saveDraft();
    }, 60);
  }

  // ── reset ──────────────────────────────────────────────────────────────
  function resetBuilder() {
    if (!window.confirm('Reset the builder? All unsaved changes will be lost.')) return;
    applyState(DEFAULT_STATE);
    clearDraft();
    window.toast?.('Builder reset', 'success');
  }

  // ── bind ───────────────────────────────────────────────────────────────
  function bind() {
    if (!document.getElementById('eb-title')) return; // not on this page

    // Live-preview triggers (input/change keyspaces).
    const inputRoot = document.querySelector('.embed-builder-grid') || document.body;
    inputRoot.addEventListener('input', (e) => {
      const id = e.target && e.target.id;
      if (id === 'eb-color') { $('#eb-color-text').value = e.target.value; }
      if (id === 'eb-color-text' && /^#[0-9a-fA-F]{6}$/.test(e.target.value)) { $('#eb-color').value = e.target.value; }
      updateCounters();
      schedule();
    });
    inputRoot.addEventListener('change', schedule);

    // Field actions (add / delete / duplicate / drag).
    $('#eb-add-field').addEventListener('click', () => addField());
    $('#eb-fields-list').addEventListener('click', (e) => {
      const card = e.target.closest('.edb-field-card');
      if (!card) return;
      if (e.target.closest('.edb-field-dupe')) duplicateField(card);
      else if (e.target.closest('.edb-field-del')) deleteField(card);
    });
    bindDrag();

    // Toolbar.
    $('#eb-import-json').addEventListener('click', importJsonPrompt);
    $('#eb-export-json').addEventListener('click', async () => {
      const obj = exportEmbedJson();
      if (obj) await copyText(JSON.stringify(obj, null, 2), 'Embed JSON');
    });
    $('#eb-copy-payload').addEventListener('click', async () => {
      const s = readState();
      const v = validateState(s);
      if (v.errors.length) { window.toast?.(v.errors[0], 'error'); return; }
      await copyText(JSON.stringify(buildPayload(s), null, 2), 'Message payload');
    });
    $('#eb-reset').addEventListener('click', resetBuilder);

    // Templates.
    $$('.embed-template-chip').forEach((chip) => {
      chip.addEventListener('click', () => loadTemplate(chip.dataset.template));
    });

    // Saved embeds.
    $('#eb-save-embed').addEventListener('click', openSaveModal);
    $('#eb-saved-search').addEventListener('input', (e) => renderSavedList(e.target.value));
    $('#eb-modal-close').addEventListener('click', closeModal);
    $('#eb-modal-cancel').addEventListener('click', closeModal);
    $('#eb-modal-confirm').addEventListener('click', confirmModal);

    // Beforeunload: save the draft on navigation back / refresh.
    window.addEventListener('beforeunload', saveDraft);

    // Init — restore the draft first (local), then refresh saved list (API).
    if (!loadDraft()) applyState(DEFAULT_STATE);
    updateCounters();
    renderPreview();
    updateValidation();
    refreshSavedEmbeds();
  }

  // Expose the pure, DOM-free logic for tests / advanced tooling. The DOM
  // wiring stays private; nothing here touches the document.
  if (typeof window !== 'undefined') {
    window.PrimeBotEmbedBuilder = {
      LIMITS,
      DEFAULT_STATE: Object.assign({}, DEFAULT_STATE),
      TEMPLATES,
      validUrl: isValidUrl,
      totalCharacters,
      validateState,
      normalizeImported,
      buildEmbedObject,
      buildPayload,
    };
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bind);
  } else {
    bind();
  }
})();