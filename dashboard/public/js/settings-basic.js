/* Welcome / leveling / prefix / reactions / broadcast settings pages.
 * Wires the floating "Save changes" bar (window.saveBar) to PATCH the right
 * /api endpoint for whichever section is on this page. The page tracks the
 * whole document for edits; when a field changes the bar appears, and Save
 * runs every registered saver.
 */

bindColorSync('welcome-color', 'welcome-color-text');
bindColorSync('logging-color', 'logging-color-text');
bindReactionRemovals();

// Auto-reactions: add/remove trigger rows.
const reactionsList = document.getElementById('reactions-list');
document.getElementById('reaction-add')?.addEventListener('click', () => {
  if (!reactionsList) return;
  const idx = reactionsList.children.length;
  reactionsList.insertAdjacentHTML('beforeend',
    `<div class="reaction-row" data-index="${idx}">
       <input type="text" class="r-trigger" value="" placeholder="trigger word" />
       <input type="text" class="r-emoji" value="" placeholder="🎉" maxlength="30" />
       <button class="reaction-remove" type="button">✕</button>
     </div>`);
  bindReactionRemovals();
  saveBar.markDirty();
});

const GUILD_ID = window.guildData?.guildId;

async function saveSettings(kind) {
  if (kind === 'welcome') {
    const body = {
      enabled: document.getElementById('welcome-enabled').checked,
      channelId: document.getElementById('welcome-channel').value || null,
      message: document.getElementById('welcome-message').value,
      bannerUrl: document.getElementById('welcome-banner').value || null,
      color: document.getElementById('welcome-color').value,
      dmEnabled: document.getElementById('welcome-dm-enabled').checked,
      dmMessage: document.getElementById('welcome-dm-message').value,
      showMemberCount: document.getElementById('welcome-show-count').checked,
      showJoinDate: document.getElementById('welcome-show-join').checked,
      showAccountAge: document.getElementById('welcome-show-age').checked,
      customTitle: document.getElementById('welcome-title').value || null,
      customFooter: document.getElementById('welcome-footer').value || null,
    };
    await api(`/api/guilds/${GUILD_ID}/welcome`, { method: 'PATCH', body: JSON.stringify(body) });
  } else if (kind === 'leveling') {
    const body = {
      leveling: {
        enabled: document.getElementById('leveling-enabled').checked,
        levelUpChannelId: document.getElementById('leveling-channel').value || null,
        xpMultiplier: Number(document.getElementById('leveling-multiplier').value),
        xpCooldown: Number(document.getElementById('leveling-cooldown').value),
      },
    };
    await api(`/api/guilds/${GUILD_ID}/server`, { method: 'PATCH', body: JSON.stringify(body) });
  } else if (kind === 'prefix') {
    const prefix = document.getElementById('prefix-value').value.trim();
    if (!prefix) throw new Error('Prefix cannot be empty.');
    await api(`/api/guilds/${GUILD_ID}/server`, { method: 'PATCH', body: JSON.stringify({ prefix }) });
  } else if (kind === 'reactions') {
    const reactions = [];
    document.querySelectorAll('#reactions-list .reaction-row').forEach(row => {
      const trigger = row.querySelector('.r-trigger').value.trim();
      const emoji = row.querySelector('.r-emoji').value.trim();
      if (trigger && emoji) reactions.push({ trigger, emoji, caseSensitive: false });
    });
    const body = {
      autoReactions: {
        enabled: document.getElementById('reactions-enabled').checked,
        reactions,
      },
    };
    await api(`/api/guilds/${GUILD_ID}/server`, { method: 'PATCH', body: JSON.stringify(body) });
  } else if (kind === 'broadcast') {
    const body = {
      receiveBroadcasts: document.getElementById('broadcast-enabled').checked,
      broadcastChannelId: document.getElementById('broadcast-channel').value || null,
    };
    await api(`/api/guilds/${GUILD_ID}/server`, { method: 'PATCH', body: JSON.stringify(body) });
  } else if (kind === 'logging') {
    const events = [];
    document.querySelectorAll('.log-event').forEach(cb => { if (cb.checked) events.push(cb.dataset.event); });
    const webhookUrl = document.getElementById('logging-webhook').value.trim();
    if (webhookUrl && !/^https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\//i.test(webhookUrl)) {
      throw new Error('Webhook URL must be a valid Discord webhook URL.');
    }
    const body = {
      enabled: document.getElementById('logging-enabled').checked,
      channelId: document.getElementById('logging-channel').value || null,
      webhookUrl: webhookUrl || null,
      webhookName: document.getElementById('logging-webhook-name').value.trim() || 'PrimeBot Logs',
      events,
      includeBots: document.getElementById('logging-include-bots').checked,
      color: document.getElementById('logging-color').value,
    };
    await api(`/api/guilds/${GUILD_ID}/logging`, { method: 'PATCH', body: JSON.stringify(body) });
  }
}

// Register the saver(s) for whichever section is present on this page. Each
// page only renders one section's form, so we detect by element presence.
if (document.getElementById('welcome-enabled')) {
  saveBar.register(() => saveSettings('welcome'));
}
if (document.getElementById('leveling-enabled')) {
  saveBar.register(() => saveSettings('leveling'));
}
if (document.getElementById('prefix-value')) {
  saveBar.register(() => saveSettings('prefix'));
}
if (document.getElementById('reactions-enabled')) {
  saveBar.register(() => saveSettings('reactions'));
}
if (document.getElementById('broadcast-enabled')) {
  saveBar.register(() => saveSettings('broadcast'));
}
if (document.getElementById('logging-enabled')) {
  saveBar.register(() => saveSettings('logging'));
}

// Track the whole settings area for edits so the floating bar appears.
saveBar.track(document.body);
