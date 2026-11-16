/**
 * Music interactive-control handlers.
 *
 * Routes the button customIds emitted by utils/music/musicEmbed.js:
 *   music_prev, music_pauseresume, music_skip, music_stop, music_shuffle,
 *   music_repeat, music_queue, music_247status, music_qpage:<n>
 *
 * Every handler re-validates the member's permission server-side (requester
 * protection) — hiding a button is never treated as authorization.
 */

const ui = require('./musicEmbed');
const perms = require('./musicPermissions');
const { REPEAT_MODES } = require('../../shared/musicConstants');

async function ensureControl(interaction, session) {
    if (!perms.canControl(interaction.member, session)) {
        await interaction.reply({ content: 'Join the music voice channel (or hold the DJ role / Manage Server) to control playback.', ephemeral: true }).catch(() => {});
        return false;
    }
    return true;
}

async function refreshNowPlaying(interaction, m) {
    const snap = m.describe(interaction.guildId);
    const { embed, components } = ui.nowPlaying(snap);
    await interaction.update({ embeds: [embed], components: [components[0], ui.secondControlRow()] }).catch(() => {});
}

async function handleButton(interaction, mgr) {
    const m = mgr;
    const guildId = interaction.guildId;
    const id = interaction.customId;

    // Queue pagination.
    if (id.startsWith('music_qpage:')) {
        const page = parseInt(id.split(':')[1], 10) || 0;
        const { embed, components } = ui.queueEmbed(m.describe(guildId), page);
        return interaction.update({ embeds: [embed], components }).catch(() => {});
    }

    const session = m.getSession(guildId);
    if (!session) {
        return interaction.reply({ content: 'Nothing is playing in this server.', ephemeral: true }).catch(() => {});
    }

    switch (id) {
        case 'music_prev':
            if (!(await ensureControl(interaction, session))) return;
            try { await m.previous(guildId); } catch (err) { return interaction.reply({ content: err.message, ephemeral: true }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_pauseresume':
            if (!(await ensureControl(interaction, session))) return;
            try {
                if (session.state === 'playing' && !session.manualPause) await m.pause(guildId, { actor: interaction.user.id });
                else await m.resume(guildId);
            } catch (err) { return interaction.reply({ content: err.message, ephemeral: true }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_skip':
            if (!(await ensureControl(interaction, session))) return;
            try { await m.skip(guildId, { actor: interaction.user.id }); } catch (err) { return interaction.reply({ content: err.message, ephemeral: true }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_stop':
            if (!(await ensureControl(interaction, session))) return;
            try { await m.stop(guildId, { actor: interaction.user.id }); } catch (err) { return interaction.reply({ content: err.message, ephemeral: true }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_shuffle':
            if (!(await ensureControl(interaction, session))) return;
            try { await m.shuffle(guildId); } catch (err) { return interaction.reply({ content: err.message, ephemeral: true }).catch(() => {}); }
            return refreshNowPlaying(interaction, m);
        case 'music_repeat': {
            if (!(await ensureControl(interaction, session))) return;
            const order = [REPEAT_MODES.OFF, REPEAT_MODES.TRACK, REPEAT_MODES.QUEUE];
            const next = order[(order.indexOf(session.repeat) + 1) % order.length];
            await m.setRepeat(guildId, next);
            return refreshNowPlaying(interaction, m);
        }
        case 'music_queue': {
            const { embed, components } = ui.queueEmbed(m.describe(guildId), 0);
            return interaction.reply({ embeds: [embed], components, ephemeral: true }).catch(() => {});
        }
        case 'music_247status': {
            const snap = m.describe(guildId);
            return interaction.reply({ embeds: [ui.status247Embed(snap)], ephemeral: true }).catch(() => {});
        }
        default:
            return interaction.reply({ content: 'Unknown music control.', ephemeral: true }).catch(() => {});
    }
}

module.exports = { handleButton };
