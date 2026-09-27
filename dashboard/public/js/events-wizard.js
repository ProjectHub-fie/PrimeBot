/* Event Management wizard (/guild/:id/events/new).
 *
 * A multi-step create interface with a progress indicator. All state lives in
 * the DOM; nothing is persisted until the final "Create Event" POST. The live
 * embed preview is rendered client-side into the page's preview box.
 */

(function () {
  'use strict';

  const GUILD_ID = window.guildData && window.guildData.guildId;
  if (!GUILD_ID) return;

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const form = $('#ev-wizard-form');
  if (!form) return;

  const STEP_COUNT = $$('.ev-step-panel', form).length;
  let step = 0;

  // ── Step navigation ───────────────────────────────────────────────────────
  function showStep(n) {
    step = Math.max(0, Math.min(STEP_COUNT - 1, n));
    $$('.ev-step-panel', form).forEach(p => p.classList.toggle('hidden', Number(p.dataset.step) !== step));
    $$('.ev-step').forEach(b => b.classList.toggle('active', Number(b.dataset.step) === step));
    $('#ev-prev').disabled = step === 0;
    const last = step === STEP_COUNT - 1;
    $('#ev-next').classList.toggle('hidden', last);
    $('#ev-save').classList.toggle('hidden', !last);
    renderDots();
    if (last) renderReview();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function renderDots() {
    const dots = $('#ev-wizard-dots');
    if (!dots) return;
    dots.innerHTML = Array.from({ length: STEP_COUNT }, (_, i) =>
      `<span class="ev-dot${i === step ? ' active' : ''}${i < step ? ' done' : ''}"></span>`).join('');
  }

  $$('.ev-step').forEach(b => b.addEventListener('click', () => showStep(Number(b.dataset.step))));
  $('#ev-prev').addEventListener('click', () => showStep(step - 1));
  $('#ev-next').addEventListener('click', () => {
    if (step === 0 && !$('#ev-name').value.trim()) { toast('Event name is required', 'error'); return; }
    showStep(step + 1);
  });

  // ── Location type switching ───────────────────────────────────────────────
  const LOC = window.__EVENT_LOCATION_TYPES || [];
  function syncLocation() {
    const type = $('#ev-location-type').value;
    const isDiscord = ['voice', 'stage', 'text'].includes(type);
    $('#ev-loc-channel-wrap').classList.toggle('hidden', !isDiscord);
    $('#ev-loc-url-wrap').classList.toggle('hidden', type !== 'external');
    $('#ev-loc-custom-wrap').classList.toggle('hidden', type !== 'custom');
  }
  $('#ev-location-type').addEventListener('change', syncLocation);
  syncLocation();

  // ── "No end time" toggle ──────────────────────────────────────────────────
  function syncNoEnd() {
    const on = $('#ev-no-end').checked;
    $('#ev-end-date').disabled = on;
    $('#ev-end-time').disabled = on;
    $('#ev-duration').disabled = on;
    if (on) { $('#ev-end-date').value = ''; $('#ev-end-time').value = ''; $('#ev-duration').value = ''; }
  }
  $('#ev-no-end').addEventListener('change', syncNoEnd);
  syncNoEnd();

  // ── Embed fields + live preview ───────────────────────────────────────────
  function fieldRowHTML(name = '', value = '', inline = false) {
    const row = document.createElement('div');
    row.className = 'ev-field-row';
    row.innerHTML = `
      <input type="text" class="ev-field-name" maxlength="256" placeholder="Field name" value="${esc(name)}" />
      <textarea class="ev-field-value" maxlength="1024" rows="1" placeholder="Field value">${esc(value)}</textarea>
      <label class="ev-inline"><input type="checkbox" class="ev-field-inline" ${inline ? 'checked' : ''}/> Inline</label>
      <button type="button" class="btn btn-secondary ev-field-remove">✕</button>`;
    row.querySelector('.ev-field-remove').addEventListener('click', () => { row.remove(); renderPreview(); });
    row.querySelectorAll('input, textarea').forEach(el => el.addEventListener('input', renderPreview));
    return row;
  }
  const addFieldBtn = $('#ev-add-field');
  if (addFieldBtn) addFieldBtn.addEventListener('click', () => {
    $('#ev-embed-fields').appendChild(fieldRowHTML());
  });

  function readFields() {
    return $$('#ev-embed-fields .ev-field-row').map(r => ({
      name: r.querySelector('.ev-field-name').value,
      value: r.querySelector('.ev-field-value').value,
      inline: r.querySelector('.ev-field-inline').checked,
    })).filter(f => f.name || f.value);
  }

  function collect() {
    const type = ($('input[name="ev-type"]:checked') || {}).value || 'community';
    const regMode = ($('input[name="ev-reg-mode"]:checked') || {}).value || 'open';
    const locType = $('#ev-location-type').value;
    let locValue = null;
    if (['voice', 'stage', 'text'].includes(locType)) locValue = $('#ev-location-channel').value || null;
    else if (locType === 'external') locValue = $('#ev-location-url').value || null;
    else if (locType === 'custom') locValue = $('#ev-location-custom').value || null;

    // Build the start/end timestamps. The dashboard sends the local wall-clock
    // value; the server stores it as a UTC timestamp.
    const startDate = $('#ev-start-date').value;
    const startTime = $('#ev-start-time').value;
    const startAt = startDate ? new Date(`${startDate}T${startTime || '00:00'}`).toISOString() : null;
    let endAt = null;
    if (!$('#ev-no-end').checked) {
      if ($('#ev-end-date').value) endAt = new Date(`${$('#ev-end-date').value}T${$('#ev-end-time').value || '00:00'}`).toISOString();
      else if ($('#ev-duration').value && startAt) endAt = new Date(new Date(startAt).getTime() + Number($('#ev-duration').value) * 60000).toISOString();
    }

    return {
      name: $('#ev-name').value.trim(),
      description: $('#ev-description').value,
      type,
      startAt, endAt,
      timezone: $('#ev-timezone').value || 'UTC',
      locationType: locType,
      locationValue: locValue,
      registrationMode: regMode,
      maxParticipants: $('#ev-max-participants').value ? Number($('#ev-max-participants').value) : null,
      waitlistEnabled: $('#ev-waitlist').checked,
      registrationDeadline: $('#ev-reg-deadline').value ? new Date($('#ev-reg-deadline').value).toISOString() : null,
      trackAttendance: $('#ev-attendance').checked,
      announcementChannelId: $('#ev-announce-channel').value || null,
      participantRoleId: $('#ev-participant-role').value || null,
      staffRoleId: $('#ev-staff-role').value || null,
      winnerRoleId: $('#ev-winner-role').value || null,
      attendanceRoleId: $('#ev-attendance-role').value || null,
      eventManagerRoleId: $('#ev-manager-role').value || null,
      eventPermissions: $$('.ev-perm').filter(c => c.checked).map(c => c.value),
      imageUrl: $('#ev-image-url').value || null,
      thumbnailUrl: $('#ev-thumb-url').value || null,
      embedTitle: $('#ev-embed-title').value || null,
      embedDescription: $('#ev-embed-description').value || null,
      embedColor: $('#ev-embed-color').value || '#5865F2',
      embedFields: readFields(),
      embedFooter: $('#ev-embed-footer').value || null,
      reminders: $$('.ev-reminder').filter(c => c.checked).map(c => c.value),
    };
  }

  function previewEmbed() {
    const d = collect();
    const type = (window.__EVENT_TYPES || []).find(t => t.key === d.type) || {};
    const fields = (d.embedFields || []).map(f =>
      `<div class="ev-preview-field${f.inline ? ' inline' : ''}"><strong>${esc(f.name || '\u200b')}</strong><br/>${esc(f.value || '\u200b')}</div>`).join('');
    const when = d.startAt ? new Date(d.startAt).toLocaleString() : 'Not scheduled';
    return `
      <div class="ev-preview-embed" style="border-left-color:${esc(d.embedColor)}">
        ${d.imageUrl ? `<div class="ev-preview-img" style="background-image:url('${esc(d.imageUrl)}')"></div>` : ''}
        <div class="ev-preview-title">${esc(d.embedTitle || `${type.icon || ''} ${d.name || 'Event name'}`)}</div>
        <div class="ev-preview-desc">${esc(d.embedDescription || d.description || 'No description')}</div>
        <div class="ev-preview-fields">
          <div class="ev-preview-field inline"><strong>📅 When</strong><br/>${esc(when)}</div>
          <div class="ev-preview-field inline"><strong>📍 Where</strong><br/>${esc(d.locationValue || 'Not set')}</div>
          <div class="ev-preview-field inline"><strong>👥 Participants</strong><br/>0${d.maxParticipants ? ' / ' + d.maxParticipants : ''}</div>
        </div>
        ${fields}
        <div class="ev-preview-footer">${esc(d.embedFooter || 'PrimeBot Events')}</div>
      </div>
      <div class="ev-preview-buttons">
        <span class="ev-fake-btn primary">🎟️ Join Event</span>
        <span class="ev-fake-btn">👥 Participants</span>
        <span class="ev-fake-btn">ℹ️ Event Info</span>
        <span class="ev-fake-btn">🔔 Remind Me</span>
      </div>`;
  }
  function renderPreview() {
    const box = $('#ev-preview');
    if (box) box.innerHTML = previewEmbed();
  }

  // ── Review ────────────────────────────────────────────────────────────────
  function renderReview() {
    const d = collect();
    const box = $('#ev-review');
    if (!box) return;
    const rows = [
      ['Name', d.name || '—'],
      ['Type', d.type],
      ['When', d.startAt ? new Date(d.startAt).toLocaleString() : 'Not scheduled'],
      ['Ends', d.endAt ? new Date(d.endAt).toLocaleString() : 'No end time'],
      ['Location', d.locationValue || d.locationType],
      ['Registration', d.registrationMode + (d.maxParticipants ? ` · max ${d.maxParticipants}` : '')],
      ['Reminders', (d.reminders || []).join(', ') || 'none'],
      ['Announcement channel', d.announcementChannelId ? '#' + d.announcementChannelId : 'not set'],
    ];
    box.innerHTML = `
      <table class="ev-review-table"><tbody>
        ${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(String(v))}</td></tr>`).join('')}
      </tbody></table>
      ${d.embedFields && d.embedFields.length ? '' : ''}
      <div class="ev-preview">${previewEmbed()}</div>`;
  }

  // Re-render the preview whenever any tracked control changes.
  form.addEventListener('input', () => { if ($('#ev-preview')) renderPreview(); });
  form.addEventListener('change', () => { if ($('#ev-preview')) renderPreview(); });

  // ── Submit ────────────────────────────────────────────────────────────────
  $('#ev-save').addEventListener('click', async () => {
    const body = collect();
    if (!body.name) { toast('Event name is required', 'error'); showStep(0); return; }
    const publishNow = $('#ev-publish-now').checked;
    const btn = $('#ev-save');
    btn.disabled = true;
    const orig = btn.textContent;
    btn.textContent = 'Creating…';
    try {
      const res = await api(`/api/guilds/${GUILD_ID}/events`, { method: 'POST', body: JSON.stringify({ ...body, publish: publishNow }) });
      toast('Event created!');
      const id = res.event && res.event.id;
      window.location.assign(`/guild/${GUILD_ID}/events/${id}`);
    } catch (e) {
      toast(e.message || 'Failed to create the event', 'error');
      btn.disabled = false;
      btn.textContent = orig;
    }
  });

  showStep(0);
  renderPreview();
})();
