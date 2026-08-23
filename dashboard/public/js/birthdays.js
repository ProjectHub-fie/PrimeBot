/* Birthdays page — lists every registered birthday (sorted by next occurrence),
 * lets admins add/remove entries, and saves the announcement channel, birthday
 * role and custom embed image URL via the floating save bar (saveBar).
 *
 * Data comes from GET/PATCH/POST/DELETE /api/guilds/:id/birthdays, which read/
 * write the birthdays + birthdays_guilds tables in the BIRTHDAY_DATABASE_URL
 * pool. The bot re-reads those tables every ~5s, so edits take effect live.
 */

const BD_GUILD_ID = window.guildData?.guildId;

const BD_MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];

function bdDateLabel(b) {
  return `${BD_MONTHS[b.month - 1] || b.month} ${b.day}${b.year ? `, ${b.year}` : ''}`;
}

function bdCountdownLabel(b) {
  if (b.daysUntil === 0) return '🎉 Today!';
  if (b.daysUntil === 1) return 'Tomorrow';
  return `in ${b.daysUntil} days`;
}

function bdRowHTML(b, i) {
  return `
    <tr>
      <td class="bd-num">${i + 1}</td>
      <td class="bd-user"><code>${esc(b.userId)}</code></td>
      <td class="bd-date">${esc(bdDateLabel(b))}</td>
      <td class="bd-countdown">${esc(bdCountdownLabel(b))}</td>
      <td class="bd-actions"><button class="btn btn-secondary btn-sm bd-remove-btn" data-user-id="${esc(b.userId)}">Remove</button></td>
    </tr>`;
}

function renderBirthdays(birthdays) {
  const wrap = document.getElementById('bd-list');
  if (!wrap) return;
  if (!Array.isArray(birthdays) || birthdays.length === 0) {
    wrap.innerHTML = `<p class="live-empty">No birthdays have been set in this server yet.</p>`;
    return;
  }
  wrap.innerHTML = `
    <div class="wlog-wrap">
      <table class="wlog-table bd-table">
        <thead>
          <tr><th>#</th><th>Member ID</th><th>Birthday</th><th>Next</th><th></th></tr>
        </thead>
        <tbody>${birthdays.map(bdRowHTML).join('')}</tbody>
      </table>
    </div>`;
  bindRemoveButtons();
}

async function loadBirthdays() {
  try {
    const { birthdays } = await api(`/api/guilds/${BD_GUILD_ID}/birthdays`);
    renderBirthdays(birthdays);
  } catch (err) {
    const wrap = document.getElementById('bd-list');
    if (wrap) wrap.innerHTML = `<p class="live-empty">Failed to load birthdays: ${esc(err.message || '')}</p>`;
  }
}

function bindRemoveButtons() {
  document.querySelectorAll('.bd-remove-btn').forEach(btn => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = '1';
    btn.addEventListener('click', async () => {
      const userId = btn.dataset.userId;
      if (!confirm(`Remove the birthday for member ${userId}?`)) return;
      btn.disabled = true;
      try {
        const { birthdays } = await api(`/api/guilds/${BD_GUILD_ID}/birthdays/${userId}`, { method: 'DELETE' });
        toast('Birthday removed', 'success');
        renderBirthdays(birthdays);
      } catch (err) {
        toast(err.message || 'Failed to remove birthday', 'error');
        btn.disabled = false;
      }
    });
  });
}

// ── Add a birthday ────────────────────────────────────────────────────────────

document.getElementById('bd-add-btn')?.addEventListener('click', async () => {
  const userId = document.getElementById('bd-add-userid').value.trim();
  const month = parseInt(document.getElementById('bd-add-month').value, 10);
  const day = parseInt(document.getElementById('bd-add-day').value, 10);
  const yearRaw = document.getElementById('bd-add-year').value.trim();
  const year = yearRaw ? parseInt(yearRaw, 10) : null;
  if (!/^\d{17,20}$/.test(userId)) { toast('Enter a valid member user ID (17-20 digits).', 'error'); return; }
  if (!Number.isFinite(month) || month < 1 || month > 12) { toast('Pick a month.', 'error'); return; }
  if (!Number.isFinite(day) || day < 1 || day > 31) { toast('Enter a valid day (1-31).', 'error'); return; }
  const btn = document.getElementById('bd-add-btn');
  btn.disabled = true;
  btn.textContent = 'Adding…';
  try {
    const { birthdays } = await api(`/api/guilds/${BD_GUILD_ID}/birthdays`, {
      method: 'POST',
      body: JSON.stringify({ userId, month, day, year }),
    });
    toast('Birthday added', 'success');
    document.getElementById('bd-add-userid').value = '';
    document.getElementById('bd-add-month').value = '';
    document.getElementById('bd-add-day').value = '';
    document.getElementById('bd-add-year').value = '';
    renderBirthdays(birthdays);
  } catch (err) {
    toast(err.message || 'Failed to add birthday', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Add';
  }
});

document.getElementById('bd-refresh')?.addEventListener('click', (e) => {
  e.preventDefault();
  loadBirthdays();
});

// ── Settings save (channel / role / custom embed image URL) via the save bar ──

function updateImagePreview() {
  const url = document.getElementById('bd-image-url')?.value.trim() || '';
  const wrap = document.getElementById('bd-image-preview-wrap');
  const img = document.getElementById('bd-image-preview');
  if (!wrap || !img) return;
  if (url) {
    img.src = url;
    wrap.classList.remove('hidden');
  } else {
    img.removeAttribute('src');
    wrap.classList.add('hidden');
  }
}

document.getElementById('bd-image-url')?.addEventListener('input', updateImagePreview);

async function saveBirthdaySettings() {
  const settings = {
    channelId: document.getElementById('bd-channel')?.value || null,
    roleId: document.getElementById('bd-role')?.value || null,
    imageUrl: document.getElementById('bd-image-url')?.value.trim() || null,
  };
  await api(`/api/guilds/${BD_GUILD_ID}/birthdays`, {
    method: 'PATCH',
    body: JSON.stringify(settings),
  });
  toast('Birthday settings saved', 'success');
}

if (window.saveBar) {
  window.saveBar.register(saveBirthdaySettings);
  window.saveBar.track(document.body);
}

loadBirthdays();
