/**
 * Music interactive-control handlers.
 *
 * Routes the button/select customIds emitted by utils/music/musicEmbed.js:
 *   music_prev, music_pauseresume, music_skip, music_stop, music_shuffle,
 *   music_repeat, music_autoplay, music_queue, music_lyrics, music_247status,
 *   music_qpage:<n>, music_qclose, music_filter (select menu).
 *
 * Every handler re-validates the member's permission server-side (requester
 * protection) — hiding a button is never treated as authorization.
 */

const { MessageFlags } = require('discord.js');
const ui = require('./musicEmbed');
const perms = require('./musicPermissions');
const { REPEAT_MODES } = require('../../shared/musicConstants');

async function ensureControl(interaction, session) {
    if (!perms.canControl(interaction.member, session)) {
        await interaction.reply({ content: 'Join the music voice channel (or hold the DJ role / Manage Server) to control playback.', flags: MessageFlags.Ephemeral }).catch(() => {});
        return false;
    }
    return true;
}

async function refreshNowPlaying(interaction, m) {
    const snap = m.describe(interaction.guildId);
    const { embed, components } = ui.nowPlaying(snap);
    await interaction.update({ embeds: [embed], components: [components[0], ui.secondControlRow(snap)] }).catch(() => {});
}

/** Resolve the lyrics for the current track (or a query) and reply. */
async function replyLyrics(interaction, m) {
    const snap = m.describe(interaction.guildId);
    const track = snap && snap.current;
    if (!track) return interaction.reply({ embeds: [ui.errorEmbed('Nothing is playing right now.')], flags: MessageFlags.Ephemeral }).catch(() => {});
    await interaction.deferReply().catch(() => {});
    const { fetchLyrics } = require('./lyricsService');
    const res = await fetchLyrics({ track });
    if (!res.lyrics) return interaction.editReply({ embeds: [ui.errorEmbed(res.reason || 'No lyrics found.')] }).catch(() => {});
    const text = res.lyrics.length > 4000 ? res.lyrics.slice(0, 3980) + '\n…' : res.lyrics;
    return interaction.editReply({ embeds: [ui.trackInfoEmbed(track).setDescription(text)] }).catch(() => {});
}

/** Handle the audio-filter select menu (customId music_filter). */
async function handleSelect(interaction, mgr) {
    if (interaction.customId !== 'music_filter') {
        return interaction.reply({ content: 'Unknown music menu.', flags: MessageFlags.Ephemeral }).catch(() => {});
    }
    const session = mgr.getSession(interaction.guildId);
    if (!session) return interaction.reply({ content: 'Nothing is playing in this server.', flags: MessageFlags.Ephemeral }).catch(() => {});
    if (!perms.canControl(interaction.member, session)) {
        return interaction.reply({ content: 'Join the music voice channel (or hold the DJ role / Manage Server) to change filters.', flags: MessageFlags.Ephemeral }).catch(() => {});
    }
    const value = (interaction.values && interaction.values[0]) || 'clear';
    try {
        const snap = await mgr.setFilter(interaction.guildId, value === 'clear' ? null : value);
        const label = value === 'clear' ? 'Filters cleared' : `Filter set to **${require('./musicFilters').filterLabel(value)}**`;
        // Refresh the filter picker in place so the selection state stays live.
        const { embed, components } = ui.filterEmbed(snap.filter);
        return interaction.update({ embeds: [embed], components }).catch(() => interaction.reply({ embeds: [ui.successEmbed('🎛️ Filter', label)], flags: MessageFlags.Ephemeral }));
    } catch (err) {
        return interaction.reply({ content: err.message, flags: MessageFlags.Ephemeral }).catch(() => {});
    }
}

async function handleButton(interaction, mgr) {
    const m = mgr;
    const guildId = interaction.guildId;
    const id = interaction.customId;

    // Queue pagination / close (do not require an active-control check — it is read-only).
    if (id.startsWith('music_qpage:')) {
        const page = parseInt(id.split(':')[1], 10) || 0;
        const { embed, components } = ui.queueEmbed(m.describe(guildId, { queueLimit: 100 }), page);
        return interaction.update({ embeds: [embed], components }).catch(() => {});
    }
    if (id === 'music_qclose') {
        return interaction.message && interaction.message.delete().catch(() => {});
    }

    const session = m.getSession(guildId);
    if (!session) {
        return interaction.reply({ content: 'Nothing is playing in this server.', flags: MessageFlags.Ephemeral }).catch(() => {});
    }

    switch (id) {
        case 'music_prev':
            if (!(await ensureControl(interaction, session))) return;
            try { await m.previous(guildId); } catch (err) { return interaction.reply({ content: err.message, flags: MessageFlags.Ephemeral }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_pauseresume':
            if (!(await ensureControl(interaction, session))) return;
            try {
                if (session.state === 'playing' && !session.manualPause) await m.pause(guildId, { actor: interaction.user.id });
                else await m.resume(guildId);
            } catch (err) { return interaction.reply({ content: err.message, flags: MessageFlags.Ephemeral }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_skip':
            if (!(await ensureControl(interaction, session))) return;
            try { await m.skip(guildId, { actor: interaction.user.id }); } catch (err) { return interaction.reply({ content: err.message, flags: MessageFlags.Ephemeral }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_stop':
            if (!(await ensureControl(interaction, session))) return;
            try { await m.stop(guildId, { actor: interaction.user.id }); } catch (err) { return interaction.reply({ content: err.message, flags: MessageFlags.Ephemeral }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_shuffle':
            if (!(await ensureControl(interaction, session))) return;
            try { await m.shuffle(guildId); } catch (err) { return interaction.reply({ content: err.message, flags: MessageFlags.Ephemeral }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_repeat': {
            if (!(await ensureControl(interaction, session))) return;
            const order = [REPEAT_MODES.OFF, REPEAT_MODES.TRACK, REPEAT_MODES.QUEUE];
            const next = order[(order.indexOf(session.repeat) + 1) % order.length];
            await m.setRepeat(guildId, next);
            return refreshNowPlaying(interaction, m);
        }
        case 'music_autoplay': {
            if (!(await ensureControl(interaction, session))) return;
            await m.setAutoplay(guildId, !session.autoplay);
            return refreshNowPlaying(interaction, m);
        }
        case 'music_queue': {
            const { embed, components } = ui.queueEmbed(m.describe(guildId, { queueLimit: 100 }), 0);
            return interaction.reply({ embeds: [embed], components, flags: MessageFlags.Ephemeral }).catch(() => {});
        }
        case 'music_lyrics':
            return replyLyrics(interaction, m);
        case 'music_247status': {
            const snap = m.describe(guildId);
            return interaction.reply({ embeds: [ui.status247Embed(snap)], flags: MessageFlags.Ephemeral }).catch(() => {});
        }
        default:
            return interaction.reply({ content: 'Unknown music control.', flags: MessageFlags.Ephemeral }).catch(() => {});
    }
}

module.exports = { handleButton, handleSelect, replyLyrics };
