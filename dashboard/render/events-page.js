/**
 * Event Management dashboard pages (server-rendered).
 *
 * Three real pages, following the dashboard's multi-page convention:
 *   • eventsPage          → /guild/:guildId/events                (hub: hero, stats, list, create)
 *   • eventWizardPage     → /guild/:guildId/events/new             (multi-step create wizard)
 *   • eventManagePage     → /guild/:guildId/events/:id             (manage: overview/participants/
 *                                  announcements/reminders/settings/activity)
 *
 * Everything is real markup usable before JS runs; the client scripts
 * (public/js/events-hub.js, events-wizard.js, events-manage.js) only add
 * interactivity. Icons are SVG (dashboard chrome), never emoji.
 */

const { esc, channelOptions, roleOptions, svgIcon, jsonForScript } = require('./layout');
const { guildDataScript, guildHeaderHTML, tabNavHTML } = require('./guild');

// Re-use the shared "Coming Soon" overlay so Event Management matches the
// Anti-Nuke tab exactly. Required lazily inside wrapUpcoming() to avoid a
// circular require (guild-pages -> events-page -> guild-pages).
function wrapUpcoming(innerHTML, guild) {
    // Developer/owner bot roles bypass the upcoming gate (guild._bypassUpcoming,
    // set by requireGuildAdminPage) so the feature can be exercised before it
    // ships — the same bypass eventsPage/Anti-Nuke honor.
    if (guild && guild._bypassUpcoming) return innerHTML;
    const { upcomingOverlayWrap } = require('./guild-pages');
    return upcomingOverlayWrap(innerHTML, { icon: 'calendar', title: 'Event Management' });
}

const {
    EVENT_TYPES, EVENT_STATUSES, REGISTRATION_MODES, LOCATION_TYPES,
    REMINDER_PRESETS, EVENT_PERMISSIONS, EVENT_TEMPLATES,
    eventTypeMeta, eventStatusMeta, normalizeEventPermissions,
} = require('../../shared/eventConstants');

const SUPPORT_URL = 'https://discord.gg/gd7UNSfX86';

// ── Small render helpers ────────────────────────────────────────────────────

function statusBadge(status) {
    const meta = eventStatusMeta(status);
    return `<span class="ev-badge ev-badge-${esc(meta.key)}">${svgIcon(meta.icon)} ${esc(meta.label)}</span>`;
}

function typeChip(type) {
    const meta = eventTypeMeta(type);
    return `<span class="ev-type-chip">${svgIcon(meta.iconName)} ${esc(meta.label)}</span>`;
}

function fmtDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString('en-US', { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

function pct(n, max) {
    if (!max || max <= 0) return 0;
    return Math.min(100, Math.round((n / max) * 100));
}

/** A countdown card. Data attributes drive the client-side live countdown. */
function countdownHTML(startAt, status) {
    if (status === 'completed') return `<div class="ev-countdown ev-countdown-done">${svgIcon('check')} Completed</div>`;
    if (status === 'cancelled') return `<div class="ev-countdown ev-countdown-cancelled">${svgIcon('ban')} Cancelled</div>`;
    if (status === 'live') return `<div class="ev-countdown ev-countdown-live">${svgIcon('activity')} Live now</div>`;
    if (!startAt) return `<div class="ev-countdown ev-countdown-none">${svgIcon('calendar')} Not scheduled</div>`;
    return `<div class="ev-countdown" data-ev-countdown="${esc(startAt)}"><span class="ev-countdown-label">Starts in</span><span class="ev-countdown-value">—</span></div>`;
}

function progressHTML(count, max) {
    if (!max) return '';
    const p = pct(count, max);
    return `<div class="ev-progress" title="${count} / ${max}"><div class="ev-progress-bar" style="width:${p}%"></div></div><div class="ev-progress-text">${count} / ${max}</div>`;
}

/** One event card for the hub list. */
function eventCardHTML(ev) {
    const meta = eventTypeMeta(ev.type);
    const count = ev.participantCount != null ? ev.participantCount : (ev.participantCount === 0 ? 0 : null);
    return `
    <div class="ev-card" data-ev-id="${ev.id}">
      <div class="ev-card-cover"${ev.imageUrl ? ` style="background-image:url('${esc(ev.imageUrl)}')"` : ''}>
        ${ev.imageUrl ? '' : `<div class="ev-card-cover-fallback">${svgIcon(meta.iconName)}</div>`}
        <div class="ev-card-cover-badges">${statusBadge(ev.status)}</div>
      </div>
      <div class="ev-card-body">
        <div class="ev-card-title">${svgIcon(meta.iconName)} ${esc(ev.name)}</div>
        <div class="ev-card-meta">${typeChip(ev.type)}</div>
        <div class="ev-card-when">${svgIcon('clock')} ${esc(fmtDate(ev.startAt))}</div>
        ${countdownHTML(ev.startAt, ev.status)}
        <div class="ev-card-participants">
          ${svgIcon('users')} ${count == null ? '—' : count} participant${count === 1 ? '' : 's'}
          ${progressHTML(count || 0, ev.maxParticipants)}
        </div>
      </div>
      <div class="ev-card-actions">
        <a class="btn btn-primary" href="/guild/${esc(ev.guildId)}/events/${ev.id}">${svgIcon('settings')} Manage</a>
        <a class="btn btn-secondary" href="/guild/${esc(ev.guildId)}/events/${ev.id}?tab=overview">${svgIcon('eye')} View</a>
      </div>
    </div>`;
}

function emptyStateHTML(guildId) {
    return `
    <div class="ev-empty">
      <div class="ev-empty-emoji">🎉</div>
      <h3>No events yet</h3>
      <p>Create your first community event and manage participants, reminders, announcements, and more.</p>
      <a class="btn btn-primary" href="/guild/${esc(guildId)}/events/new">${svgIcon('plus')} Create Event</a>
    </div>`;
}

/** Quick-start template cards (prefill the wizard only). */
function templateCardsHTML(guildId) {
    return EVENT_TEMPLATES.map(t => `
      <a class="ev-template" href="/guild/${esc(guildId)}/events/new?template=${esc(t.key)}">
        <div class="ev-template-emoji">${t.icon}</div>
        <div class="ev-template-name">${esc(t.label)}</div>
        <div class="ev-template-desc">${esc(t.description)}</div>
      </a>`).join('');
}

// ── Hub page ────────────────────────────────────────────────────────────────

function eventsPage({ guild, user }) {
    const cfg = guild._config || {};
    const events = Array.isArray(cfg.events) ? cfg.events : [];
    const policy = cfg.eventPolicy || { managerRoleId: null, permissions: [] };
    const total = cfg.eventTotal != null ? cfg.eventTotal : events.length;

    const active = events.filter(e => e.status === 'live').length;
    const upcoming = events.filter(e => ['scheduled', 'registration_open', 'registration_closed'].includes(e.status)).length;
    const completed = events.filter(e => e.status === 'completed').length;
    const totalParticipants = events.reduce((sum, e) => sum + (e.participantCount || 0), 0);

    // Upcoming list (soonest first) for the "Upcoming Events" section.
    const upcomingList = events
        .filter(e => ['scheduled', 'registration_open', 'registration_closed'].includes(e.status))
        .sort((a, b) => {
            const at = a.startAt ? new Date(a.startAt).getTime() : Infinity;
            const bt = b.startAt ? new Date(b.startAt).getTime() : Infinity;
            return at - bt;
        })
        .slice(0, 6);

    const innerPanelHTML = `
    <div class="ev-page">
      <section class="ev-hero">
        <div class="ev-hero-main">
          <div class="ev-hero-icon">${svgIcon('calendar')}</div>
          <div>
            <h2 class="ev-hero-title">Event Management</h2>
            <p class="ev-hero-sub">Create, manage, and run Discord events with ease.</p>
            <div class="ev-hero-pills">
              <span class="ev-pill ev-pill-premium">${svgIcon('rocket')} Premium event tools. Free for everyone.</span>
              <span class="ev-pill">${svgIcon('sparkles')} Premium features in free.</span>
            </div>
          </div>
        </div>
        <div class="ev-hero-actions">
          <a class="btn btn-primary" href="/guild/${esc(guild.id)}/events/new">${svgIcon('plus')} Create Event</a>
          <a class="btn btn-secondary" href="#ev-list-anchor">${svgIcon('list')} Manage Events</a>
        </div>
      </section>

      <section class="ev-stats">
        <div class="ev-stat"><div class="ev-stat-num">${active}</div><div class="ev-stat-label">${svgIcon('activity')} Active Events</div></div>
        <div class="ev-stat"><div class="ev-stat-num">${upcoming}</div><div class="ev-stat-label">${svgIcon('calendar')} Upcoming Events</div></div>
        <div class="ev-stat"><div class="ev-stat-num">${completed}</div><div class="ev-stat-label">${svgIcon('check')} Completed Events</div></div>
        <div class="ev-stat"><div class="ev-stat-num">${totalParticipants}</div><div class="ev-stat-label">${svgIcon('users')} Total Participants</div></div>
      </section>

      <section class="ev-section">
        <div class="ev-section-head">
          <h3>${svgIcon('calendar')} Upcoming Events</h3>
          <a class="ev-refresh" href="#" id="ev-refresh-upcoming">${svgIcon('refresh')} Refresh</a>
        </div>
        <div class="ev-upcoming-list" id="ev-upcoming-list">
          ${upcomingList.length
            ? upcomingList.map(eventCardHTML).join('')
            : `<p class="ev-muted">No upcoming events yet. <a href="/guild/${esc(guild.id)}/events/new">Create one →</a></p>`}
        </div>
      </section>

      <section class="ev-section">
        <div class="ev-section-head">
          <h3>${svgIcon('rocket')} Start from a template</h3>
        </div>
        <div class="ev-templates">${templateCardsHTML(guild.id)}</div>
      </section>

      <section class="ev-section" id="ev-list-anchor">
        <div class="ev-section-head">
          <h3>${svgIcon('list')} All Events</h3>
        </div>
        <div class="ev-toolbar">
          <div class="ev-search">${svgIcon('search')}<input type="search" id="ev-search" placeholder="Search events by name…" /></div>
          <select id="ev-filter-status" class="ev-select">
            <option value="">All statuses</option>
            ${EVENT_STATUSES.map(s => `<option value="${esc(s.key)}">${esc(s.label)}</option>`).join('')}
          </select>
          <select id="ev-sort" class="ev-select">
            <option value="start">Sort: Start date</option>
            <option value="created">Sort: Created date</option>
            <option value="participants">Sort: Participants</option>
          </select>
        </div>
        <div class="ev-list" id="ev-list">
          ${events.length ? events.map(eventCardHTML).join('') : emptyStateHTML(guild.id)}
        </div>
        <div class="ev-pager" id="ev-pager" data-total="${total}"></div>
      </section>
    </div>`;

    // Event Management is an upcoming feature: ordinary users see the Coming
    // Soon overlay; developer/owner roles bypass it (guild._bypassUpcoming).
    const panelHTML = wrapUpcoming(innerPanelHTML, guild);
    const body = `
    ${guildHeaderHTML(guild)}
    ${tabNavHTML(guild.id, 'events')}
    ${panelHTML}
    ${guildDataScript({ guildId: guild.id, channels: guild._channels, roles: guild._roles, extra: { eventPolicy: policy } })}
    <script>
      window.__EVENT_TYPES=${jsonForScript(EVENT_TYPES)};
      window.__EVENT_STATUSES=${jsonForScript(EVENT_STATUSES)};
    </script>`;
    return { body, scripts: ['/js/guild-common.js', '/js/events-hub.js'], title: `PrimeBot · ${guild.name} · Events` };
}

// ── Wizard page ─────────────────────────────────────────────────────────────

const WIZARD_STEPS = [
    'Basic Information', 'Schedule', 'Location', 'Registration',
    'Roles & Permissions', 'Discord Message', 'Advanced Settings', 'Review & Publish',
];

function wizardStepNavHTML() {
    return WIZARD_STEPS.map((label, i) => `
      <button type="button" class="ev-step${i === 0 ? ' active' : ''}" data-step="${i}">
        <span class="ev-step-num">${i + 1}</span>
        <span class="ev-step-label">${esc(label)}</span>
      </button>`).join('');
}

function eventTypeCardsHTML() {
    return EVENT_TYPES.map(t => `
      <label class="ev-type-card">
        <input type="radio" name="ev-type" value="${esc(t.key)}" ${t.key === 'community' ? 'checked' : ''}/>
        <span class="ev-type-card-body">
          <span class="ev-type-card-ico">${svgIcon(t.iconName)}</span>
          <span class="ev-type-card-name">${esc(t.label)}</span>
          <span class="ev-type-card-desc">${esc(t.description)}</span>
        </span>
      </label>`).join('');
}

function reminderTogglesHTML(selected = ['24h', '1h']) {
    return REMINDER_PRESETS.map(r => `
      <label class="switch mini">
        <input type="checkbox" class="ev-reminder" value="${esc(r.key)}" ${selected.includes(r.key) ? 'checked' : ''}/>
        <span class="slider"></span>
        <span class="switch-text">${esc(r.label)}</span>
      </label>`).join('');
}

function permissionTogglesHTML(selected) {
    const set = new Set(selected || []);
    return EVENT_PERMISSIONS.map(p => `
      <label class="switch mini">
        <input type="checkbox" class="ev-perm" value="${esc(p.key)}" data-perm-label="${esc(p.label)}" ${set.has(p.key) ? 'checked' : ''}/>
        <span class="slider"></span>
        <span class="switch-text">${svgIcon('shield')} ${esc(p.label)}</span>
      </label>`).join('');
}

function eventWizardPage({ guild, user, template = 'custom' }) {
    const tpl = EVENT_TEMPLATES.find(t => t.key === template) || EVENT_TEMPLATES[EVENT_TEMPLATES.length - 1];
    const pre = tpl.patch || {};
    const managerRoles = guild._roles || [];

    const innerPanelHTML = `
    <div class="ev-wizard" id="ev-wizard" data-template="${esc(tpl.key)}">
      <div class="ev-wizard-head">
        <h2>${svgIcon('plus')} Create Event</h2>
        <p class="ev-muted">Starting from: <strong>${esc(tpl.label)}</strong>. Everything can be changed before publishing.</p>
      </div>
      <div class="ev-steps" id="ev-steps">${wizardStepNavHTML()}</div>

      <form id="ev-wizard-form" class="ev-wizard-form" autocomplete="off">
        <!-- Step 1: Basic information -->
        <section class="ev-step-panel" data-step="0">
          <h3>Basic Information</h3>
          <div class="field">
            <label class="field-label" for="ev-name">Event name <span class="ev-req">*</span></label>
            <input type="text" id="ev-name" maxlength="100" value="${esc(pre.name || '')}" placeholder="e.g. Community Gaming Night" />
          </div>
          <div class="field">
            <label class="field-label" for="ev-description">Description</label>
            <textarea id="ev-description" rows="4" placeholder="Tell members what the event is about…">${esc(pre.description || '')}</textarea>
          </div>
          <div class="field">
            <label class="field-label">Event type</label>
            <div class="ev-type-cards" id="ev-type-cards">${eventTypeCardsHTML()}</div>
          </div>
          <div class="form-row">
            <div class="field"><label class="field-label" for="ev-image-url">Event image URL (optional)</label><input type="url" id="ev-image-url" placeholder="https://…/cover.png" /></div>
            <div class="field"><label class="field-label" for="ev-thumb-url">Thumbnail URL (optional)</label><input type="url" id="ev-thumb-url" placeholder="https://…/thumb.png" /></div>
          </div>
        </section>

        <!-- Step 2: Schedule -->
        <section class="ev-step-panel hidden" data-step="1">
          <h3>Schedule</h3>
          <div class="form-row">
            <div class="field"><label class="field-label" for="ev-start-date">Start date</label><input type="date" id="ev-start-date" /></div>
            <div class="field"><label class="field-label" for="ev-start-time">Start time</label><input type="time" id="ev-start-time" /></div>
            <div class="field"><label class="field-label" for="ev-timezone">Timezone</label><input type="text" id="ev-timezone" value="${esc(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')}" /></div>
          </div>
          <div class="form-row">
            <div class="field"><label class="field-label" for="ev-end-date">End date (optional)</label><input type="date" id="ev-end-date" /></div>
            <div class="field"><label class="field-label" for="ev-end-time">End time (optional)</label><input type="time" id="ev-end-time" /></div>
            <div class="field"><label class="field-label" for="ev-duration">…or duration (minutes)</label><input type="number" id="ev-duration" min="0" value="${pre.durationMinutes || ''}" placeholder="e.g. 120" /></div>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">No end time</div><div class="sl-desc">Leave the end blank for an open-ended event.</div></div>
            <label class="switch"><input type="checkbox" id="ev-no-end" ${pre.durationMinutes ? '' : 'checked'}/><span class="slider"></span></label>
          </div>
          <div class="field-hint">Times are entered in the timezone above and stored in UTC. The countdown uses each viewer's local clock.</div>
        </section>

        <!-- Step 3: Location -->
        <section class="ev-step-panel hidden" data-step="2">
          <h3>Location</h3>
          <div class="field">
            <label class="field-label" for="ev-location-type">Location type</label>
            <select id="ev-location-type" class="ev-select">
              ${LOCATION_TYPES.map(l => `<option value="${esc(l.key)}" ${pre.locationType === l.key ? 'selected' : ''}>${esc(l.label)}</option>`).join('')}
            </select>
          </div>
          <div class="field" id="ev-loc-channel-wrap"><label class="field-label" for="ev-location-channel">Discord channel</label><select id="ev-location-channel" data-channel-select></select></div>
          <div class="field hidden" id="ev-loc-url-wrap"><label class="field-label" for="ev-location-url">External URL</label><input type="url" id="ev-location-url" placeholder="https://…" /></div>
          <div class="field hidden" id="ev-loc-custom-wrap"><label class="field-label" for="ev-location-custom">Custom location</label><input type="text" id="ev-location-custom" maxlength="200" placeholder="e.g. Community Stage" /></div>
        </section>

        <!-- Step 4: Registration -->
        <section class="ev-step-panel hidden" data-step="3">
          <h3>Registration</h3>
          <div class="field">
            <label class="field-label">Registration</label>
            <div class="ev-radio-row">
              ${REGISTRATION_MODES.map(r => `<label class="ev-radio"><input type="radio" name="ev-reg-mode" value="${esc(r.key)}" ${(pre.registrationMode || 'open') === r.key ? 'checked' : ''}/> <span>${esc(r.label)}</span><em>${esc(r.description)}</em></label>`).join('')}
            </div>
          </div>
          <div class="form-row">
            <div class="field"><label class="field-label" for="ev-max-participants">Maximum participants</label><input type="number" id="ev-max-participants" min="1" value="${pre.maxParticipants || ''}" placeholder="Unlimited" /></div>
            <div class="field"><label class="field-label" for="ev-reg-deadline">Registration closes</label><input type="datetime-local" id="ev-reg-deadline" /></div>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Waiting list</div><div class="sl-desc">When full, members join a waiting list and are promoted automatically when someone leaves.</div></div>
            <label class="switch"><input type="checkbox" id="ev-waitlist" checked/><span class="slider"></span></label>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Track attendance / check-in</div><div class="sl-desc">Show a Check In button and record who attended.</div></div>
            <label class="switch"><input type="checkbox" id="ev-attendance" ${pre.trackAttendance ? 'checked' : ''}/><span class="slider"></span></label>
          </div>
        </section>

        <!-- Step 5: Roles & permissions -->
        <section class="ev-step-panel hidden" data-step="4">
          <h3>Roles &amp; Permissions</h3>
          <div class="form-row">
            <div class="field"><label class="field-label" for="ev-participant-role">Participant role</label><select id="ev-participant-role" data-role-select data-placeholder="— None —">${roleOptions(guild._roles, null)}</select><div class="field-hint">Assigned on join, removed on leave.</div></div>
            <div class="field"><label class="field-label" for="ev-staff-role">Event staff role</label><select id="ev-staff-role" data-role-select data-placeholder="— None —">${roleOptions(guild._roles, null)}</select><div class="field-hint">For organizers/moderators of this event.</div></div>
          </div>
          <div class="form-row">
            <div class="field"><label class="field-label" for="ev-winner-role">Winner role</label><select id="ev-winner-role" data-role-select data-placeholder="— None —">${roleOptions(guild._roles, null)}</select><div class="field-hint">Granted to the recorded winner.</div></div>
            <div class="field"><label class="field-label" for="ev-attendance-role">Attendance role</label><select id="ev-attendance-role" data-role-select data-placeholder="— None —">${roleOptions(guild._roles, null)}</select><div class="field-hint">Granted to members who check in.</div></div>
          </div>
          <div class="field">
            <label class="field-label" for="ev-manager-role">Event Manager role</label>
            <select id="ev-manager-role" data-role-select data-placeholder="— None —">${roleOptions(managerRoles, null)}</select>
            <div class="field-hint">Members with this role can manage events in this server (subject to the permissions below).</div>
          </div>
          <div class="field">
            <label class="field-label">Event Manager permissions</label>
            <div class="event-grid">${permissionTogglesHTML(null)}</div>
            <div class="field-hint">Server owner and administrators always have full control.</div>
          </div>
        </section>

        <!-- Step 6: Discord message -->
        <section class="ev-step-panel hidden" data-step="5">
          <h3>Discord Message</h3>
          <div class="field"><label class="field-label" for="ev-announce-channel">Announcement channel</label><select id="ev-announce-channel" data-channel-select></select><div class="field-hint">Where the event announcement is posted. Required to publish.</div></div>
          <div class="form-row">
            <div class="field"><label class="field-label" for="ev-embed-title">Embed title (optional)</label><input type="text" id="ev-embed-title" maxlength="256" placeholder="Defaults to the event name" /></div>
            <div class="field"><label class="field-label" for="ev-embed-color">Embed color</label>
              <div class="color-field"><input type="color" id="ev-embed-color" value="#5865F2" /><input type="text" id="ev-embed-color-text" value="#5865F2" style="flex:1" /></div>
            </div>
          </div>
          <div class="field"><label class="field-label" for="ev-embed-description">Embed description (optional)</label><textarea id="ev-embed-description" rows="3" placeholder="Overrides the description inside the embed only"></textarea></div>
          <div class="field"><label class="field-label" for="ev-embed-footer">Embed footer (optional)</label><input type="text" id="ev-embed-footer" maxlength="255" placeholder="PrimeBot Events" /></div>
          <div class="field">
            <label class="field-label">Fields</label>
            <div id="ev-embed-fields"></div>
            <button type="button" class="btn btn-secondary" id="ev-add-field">${svgIcon('plus')} Add field</button>
          </div>
          <div class="field">
            <label class="field-label">Live preview</label>
            <div class="ev-preview" id="ev-preview"></div>
          </div>
        </section>

        <!-- Step 7: Advanced settings -->
        <section class="ev-step-panel hidden" data-step="6">
          <h3>Advanced Settings</h3>
          <div class="field">
            <label class="field-label">Reminders</label>
            <div class="event-grid" id="ev-reminders">${reminderTogglesHTML(pre.reminders || ['24h', '1h'])}</div>
            <div class="field-hint">Each enabled reminder is posted once before the event starts. Duplicate sends are impossible.</div>
          </div>
          <div class="switch-row">
            <div class="switch-label"><div class="sl-title">Publish immediately</div><div class="sl-desc">Post the announcement as soon as the event is created. Otherwise it stays a draft.</div></div>
            <label class="switch"><input type="checkbox" id="ev-publish-now" checked/><span class="slider"></span></label>
          </div>
        </section>

        <!-- Step 8: Review -->
        <section class="ev-step-panel hidden" data-step="7">
          <h3>Review &amp; Publish</h3>
          <div class="ev-review" id="ev-review"></div>
        </section>
      </form>

      <div class="ev-wizard-nav">
        <button type="button" class="btn btn-secondary" id="ev-prev" disabled>${svgIcon('arrowLeft')} Back</button>
        <div class="ev-wizard-dots" id="ev-wizard-dots"></div>
        <button type="button" class="btn btn-primary" id="ev-next">Next ${svgIcon('arrowRight')}</button>
        <button type="button" class="btn btn-primary hidden" id="ev-save">${svgIcon('save')} Create Event</button>
      </div>
    </div>`;

    const body = `
    ${guildHeaderHTML(guild)}
    ${tabNavHTML(guild.id, 'events')}
    ${wrapUpcoming(innerPanelHTML, guild)}
    ${guildDataScript({ guildId: guild.id, channels: guild._channels, roles: guild._roles, extra: {} })}
    <script>
      window.__EVENT_TYPES=${jsonForScript(EVENT_TYPES)};
      window.__EVENT_LOCATION_TYPES=${jsonForScript(LOCATION_TYPES)};
      window.__EVENT_REMINDERS=${jsonForScript(REMINDER_PRESETS)};
      window.__EVENT_TEMPLATE=${jsonForScript(tpl)};
    </script>`;
    return { body, scripts: ['/js/guild-common.js', '/js/events-wizard.js'], title: `PrimeBot · ${guild.name} · New Event` };
}

// ── Manage page ─────────────────────────────────────────────────────────────

const MANAGE_TABS = [
    { key: 'overview', label: 'Overview', icon: 'info' },
    { key: 'participants', label: 'Participants', icon: 'users' },
    { key: 'announcements', label: 'Announcements', icon: 'megaphone' },
    { key: 'reminders', label: 'Reminders', icon: 'clock' },
    { key: 'settings', label: 'Settings', icon: 'sliders' },
    { key: 'activity', label: 'Activity Log', icon: 'activity' },
];

function manageTabsHTML(active) {
    return MANAGE_TABS.map(t => `
      <button type="button" class="ev-mtab${t.key === active ? ' active' : ''}" data-tab="${esc(t.key)}">${svgIcon(t.icon)} ${esc(t.label)}</button>`).join('');
}

function participantsPanelHTML(participants, event) {
    const rows = (participants || []).map(p => {
        const att = p.attendanceStatus === 'present' ? '✅' : (p.attendanceStatus === 'absent' ? '❌' : '—');
        return `
        <tr data-user-id="${esc(p.userId)}" data-status="${esc(p.status)}" data-attendance="${esc(p.attendanceStatus)}">
          <td class="ev-pt-name">${esc(p.username || '')} <span class="ev-muted">#${esc(p.userId)}</span></td>
          <td>${esc(p.userId)}</td>
          <td>${esc(fmtDate(p.registeredAt))}</td>
          <td>${p.status === 'waiting' ? '<span class="ev-badge">Waiting</span>' : '<span class="ev-badge">Registered</span>'}</td>
          <td class="ev-pt-att">${att}</td>
          <td class="ev-pt-actions">
            <button class="btn btn-secondary ev-pt-checkin" title="Toggle attendance">${svgIcon('userCheck')}</button>
            ${p.status === 'waiting' ? `<button class="btn btn-secondary ev-pt-promote" title="Promote from waiting list">${svgIcon('arrowUp')}</button>` : ''}
            <button class="btn btn-secondary ev-pt-remove" title="Remove participant">${svgIcon('userX')}</button>
          </td>
        </tr>`;
    }).join('');
    const registered = (participants || []).filter(p => p.status === 'registered').length;
    const waiting = (participants || []).filter(p => p.status === 'waiting').length;
    const present = (participants || []).filter(p => p.attendanceStatus === 'present').length;
    const absent = (participants || []).filter(p => p.attendanceStatus === 'absent').length;
    return `
      <div class="ev-pt-stats">
        <div class="ev-pt-stat"><strong>${registered}</strong><span>Registered</span></div>
        <div class="ev-pt-stat"><strong>${present}</strong><span>Checked in</span></div>
        <div class="ev-pt-stat"><strong>${absent}</strong><span>Absent</span></div>
        <div class="ev-pt-stat"><strong>${waiting}</strong><span>Waiting</span></div>
      </div>
      <div class="ev-toolbar">
        <div class="ev-search">${svgIcon('search')}<input type="search" id="ev-pt-search" placeholder="Search by username or ID…" /></div>
        <select id="ev-pt-filter" class="ev-select">
          <option value="">All</option>
          <option value="registered">Registered</option>
          <option value="waiting">Waiting list</option>
          <option value="present">Checked in</option>
          <option value="absent">Absent</option>
        </select>
        <div class="ev-add-pt">
          <input type="text" id="ev-add-pt-id" placeholder="Member user ID" />
          <button class="btn btn-primary" id="ev-add-pt">${svgIcon('userPlus')} Add</button>
        </div>
      </div>
      <div class="ev-pt-table-wrap">
        <table class="ev-pt-table" id="ev-pt-table">
          <thead><tr><th>Member</th><th>Discord ID</th><th>Registered</th><th>Status</th><th>Attendance</th><th></th></tr></thead>
          <tbody>${rows || `<tr><td colspan="6" class="ev-muted">No participants yet.</td></tr>`}</tbody>
        </table>
      </div>`;
}

function overviewPanelHTML(event) {
    const type = eventTypeMeta(event.type);
    return `
      <div class="ev-ov-grid">
        <div class="ev-ov-card"><div class="ev-ov-label">Status</div><div class="ev-ov-value">${statusBadge(event.status)}</div></div>
        <div class="ev-ov-card"><div class="ev-ov-label">Type</div><div class="ev-ov-value">${typeChip(event.type)}</div></div>
        <div class="ev-ov-card"><div class="ev-ov-label">Starts</div><div class="ev-ov-value">${esc(fmtDate(event.startAt))}</div></div>
        <div class="ev-ov-card"><div class="ev-ov-label">Ends</div><div class="ev-ov-value">${event.endAt ? esc(fmtDate(event.endAt)) : 'No end time'}</div></div>
        <div class="ev-ov-card"><div class="ev-ov-label">Registration</div><div class="ev-ov-value">${esc((REGISTRATION_MODES.find(r => r.key === event.registrationMode) || {}).label || 'Open')}</div></div>
        <div class="ev-ov-card"><div class="ev-ov-label">Max participants</div><div class="ev-ov-value">${event.maxParticipants || 'Unlimited'}${event.waitlistEnabled ? ' · waitlist' : ''}</div></div>
      </div>
      ${event.description ? `<div class="ev-ov-desc">${esc(event.description)}</div>` : ''}
      <div class="ev-ov-countdown">${countdownHTML(event.startAt, event.status)}</div>`;
}

function announcementsPanelHTML(event) {
    return `
      <div class="field"><label class="field-label">Announcement channel</label>
        <select id="ev-manage-channel" data-channel-select>${channelOptions(null, event.announcementChannelId)}</select>
        <div class="field-hint">Posting / updating uses this channel. The bot needs Send Messages there.</div>
      </div>
      <div class="ev-manage-actions">
        <button class="btn btn-primary" id="ev-publish">${svgIcon('send')} Publish announcement</button>
        <button class="btn btn-secondary" id="ev-update-announcement">${svgIcon('refresh')} Update existing message</button>
      </div>
      <p class="ev-muted">Updating edits the existing message in place — it never spams a new one.${event.announcementMessageId ? ` Message id <code>${esc(event.announcementMessageId)}</code>.` : ''}</p>`;
}

function remindersPanelHTML(event) {
    const enabled = new Set(event.reminders || []);
    return `
      <div class="field"><label class="field-label">Reminders</label>
        <div class="event-grid" id="ev-manage-reminders">
          ${REMINDER_PRESETS.map(r => `
            <label class="switch mini">
              <input type="checkbox" class="ev-manage-reminder" value="${esc(r.key)}" ${enabled.has(r.key) ? 'checked' : ''}/>
              <span class="slider"></span><span class="switch-text">${esc(r.label)}</span>
            </label>`).join('')}
        </div>
        <div class="field-hint">Saved with the settings below. Reminders already sent are never re-sent.</div>
      </div>`;
}

function settingsPanelHTML(event) {
    return `
      <div class="form-row">
        <div class="field"><label class="field-label" for="ev-s-name">Event name</label><input type="text" id="ev-s-name" maxlength="100" value="${esc(event.name)}" /></div>
        <div class="field"><label class="field-label" for="ev-s-type">Type</label>
          <select id="ev-s-type" class="ev-select">${EVENT_TYPES.map(t => `<option value="${esc(t.key)}" ${event.type === t.key ? 'selected' : ''}>${esc(t.label)}</option>`).join('')}</select>
        </div>
      </div>
      <div class="field"><label class="field-label" for="ev-s-desc">Description</label><textarea id="ev-s-desc" rows="3">${esc(event.description || '')}</textarea></div>
      <div class="form-row">
        <div class="field"><label class="field-label" for="ev-s-mode">Registration</label>
          <select id="ev-s-mode" class="ev-select">${REGISTRATION_MODES.map(r => `<option value="${esc(r.key)}" ${event.registrationMode === r.key ? 'selected' : ''}>${esc(r.label)}</option>`).join('')}</select>
        </div>
        <div class="field"><label class="field-label" for="ev-s-max">Max participants</label><input type="number" id="ev-s-max" min="1" value="${event.maxParticipants || ''}" placeholder="Unlimited" /></div>
      </div>
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Waiting list</div><div class="sl-desc">Auto-promote from the waiting list on leave.</div></div>
        <label class="switch"><input type="checkbox" id="ev-s-waitlist" ${event.waitlistEnabled ? 'checked' : ''}/><span class="slider"></span></label>
      </div>
      <div class="switch-row">
        <div class="switch-label"><div class="sl-title">Track attendance</div><div class="sl-desc">Enable check-in for this event.</div></div>
        <label class="switch"><input type="checkbox" id="ev-s-attendance" ${event.trackAttendance ? 'checked' : ''}/><span class="slider"></span></label>
      </div>
      <div class="form-row">
        <div class="field"><label class="field-label">Participant role</label><select id="ev-s-participant-role" data-role-select data-placeholder="— None —">${roleOptions(null, event.participantRoleId)}</select></div>
        <div class="field"><label class="field-label">Winner role</label><select id="ev-s-winner-role" data-role-select data-placeholder="— None —">${roleOptions(null, event.winnerRoleId)}</select></div>
      </div>
      <div class="field"><label class="field-label">Event Manager role</label><select id="ev-s-manager-role" data-role-select data-placeholder="— None —">${roleOptions(null, event.eventManagerRoleId)}</select></div>
      <div class="field"><label class="field-label">Event Manager permissions</label><div class="event-grid">${permissionTogglesHTML(event.eventPermissions)}</div></div>
      ${remindersPanelHTML(event)}
      <div class="ev-manage-danger">
        <button class="btn btn-secondary" id="ev-close-reg">${svgIcon('userX')} Close registration</button>
        <button class="btn btn-secondary" id="ev-duplicate">${svgIcon('copy')} Duplicate event</button>
        <button class="btn btn-danger" id="ev-cancel">${svgIcon('ban')} Cancel event</button>
        <button class="btn btn-danger" id="ev-delete">${svgIcon('trash')} Delete event</button>
      </div>`;
}

function activityPanelHTML(activity) {
    const rows = (activity || []).map(a => `
      <li class="ev-activity-row">
        <span class="ev-activity-dot"></span>
        <span class="ev-activity-body">
          <span class="ev-activity-action">${esc(a.action.replace(/_/g, ' '))}</span>
          ${a.detail ? `<span class="ev-activity-detail">${esc(a.detail)}</span>` : ''}
          <span class="ev-activity-meta">${a.username ? esc(a.username) + ' · ' : ''}${esc(fmtDate(a.createdAt))}</span>
        </span>
      </li>`).join('');
    return `<ul class="ev-activity-list" id="ev-activity-list">${rows || '<li class="ev-muted">No activity yet.</li>'}</ul>`;
}

function eventManagePage({ guild, user, event, participants = [], activity = [], activeTab = 'overview' }) {
    const registered = (participants || []).filter(p => p.status === 'registered').length;
    const statusActions = [];
    if (['draft', 'scheduled', 'registration_closed'].includes(event.status)) {
        statusActions.push(`<button class="btn btn-primary" id="ev-open-reg">${svgIcon('userCheck')} Open registration</button>`);
    }
    if (event.status === 'draft') statusActions.push(`<button class="btn btn-primary" id="ev-publish">${svgIcon('send')} Publish</button>`);
    if (event.status === 'live') statusActions.push(`<button class="btn btn-primary" id="ev-complete">${svgIcon('check')} Mark completed</button>`);

    const innerPanelHTML = `
    <div class="ev-manage" id="ev-manage" data-event-id="${event.id}" data-status="${esc(event.status)}">
      <div class="ev-manage-head">
        <div>
          <div class="breadcrumb"><a href="/guild/${esc(guild.id)}/events">Events</a> <span>/</span> <span>${esc(event.name)}</span></div>
          <h2>${svgIcon(eventTypeMeta(event.type).iconName)} ${esc(event.name)}</h2>
          <div class="ev-manage-meta">${statusBadge(event.status)} ${typeChip(event.type)} <span class="ev-muted">${esc(fmtDate(event.startAt))}</span></div>
        </div>
        <div class="ev-manage-quick">
          <a class="btn btn-secondary" href="/guild/${esc(guild.id)}/events/${event.id}?tab=participants">${svgIcon('users')} Participants ${registered}${event.maxParticipants ? ` / ${event.maxParticipants}` : ''}</a>
          ${statusActions.join('')}
        </div>
      </div>
      ${countdownHTML(event.startAt, event.status)}

      <div class="ev-mtabs" id="ev-mtabs">${manageTabsHTML(activeTab)}</div>
      <div class="ev-mpanels">
        <section class="ev-mpanel${activeTab === 'overview' ? '' : ' hidden'}" data-tab="overview">${overviewPanelHTML(event)}</section>
        <section class="ev-mpanel${activeTab === 'participants' ? '' : ' hidden'}" data-tab="participants">${participantsPanelHTML(participants, event)}</section>
        <section class="ev-mpanel${activeTab === 'announcements' ? '' : ' hidden'}" data-tab="announcements">${announcementsPanelHTML(event)}</section>
        <section class="ev-mpanel${activeTab === 'reminders' ? '' : ' hidden'}" data-tab="reminders">${remindersPanelHTML(event)}</section>
        <section class="ev-mpanel${activeTab === 'settings' ? '' : ' hidden'}" data-tab="settings">${settingsPanelHTML(event)}</section>
        <section class="ev-mpanel${activeTab === 'activity' ? '' : ' hidden'}" data-tab="activity">${activityPanelHTML(activity)}</section>
      </div>
    </div>`;

    const body = `
    ${guildHeaderHTML(guild)}
    ${tabNavHTML(guild.id, 'events')}
    ${wrapUpcoming(innerPanelHTML, guild)}
    ${guildDataScript({ guildId: guild.id, channels: guild._channels, roles: guild._roles, extra: {
        event,
        eventParticipants: participants,
        eventActivity: activity,
        eventChannels: guild._eventChannels || [],
        eventVoiceChannels: guild._eventVoiceChannels || [],
        eventStageChannels: guild._eventStageChannels || [],
    } })}
    <script>
      window.__EVENT_TYPES=${jsonForScript(EVENT_TYPES)};
      window.__EVENT_STATUSES=${jsonForScript(EVENT_STATUSES)};
      window.__EVENT_REMINDERS=${jsonForScript(REMINDER_PRESETS)};
    </script>`;
    return { body, scripts: ['/js/guild-common.js', '/js/events-manage.js'], title: `PrimeBot · ${guild.name} · ${event.name}` };
}

module.exports = {
    eventsPage,
    eventWizardPage,
    eventManagePage,
    WIZARD_STEPS,
    MANAGE_TABS,
};
