/**
 * Audio filters for the music engine.
 *
 * A filter is a REAL ffmpeg `-af` chain applied to the decoded PCM in the
 * playback pipeline (see utils/music/musicVoice.js `transcodeStream`). Nothing
 * here only rewrites embed text — an unknown filter id is rejected and an
 * empty chain means "no filtering".
 *
 * The presets are the Linix filter set (bassboost / nightcore / vaporwave /
 * 8D / karaoke / equalizer / treble / …) re-expressed as ffmpeg chains so they
 * run on PrimeBot's existing ffmpeg pipeline instead of a Lavalink node.
 *
 * Filter chains operate on s16le 48kHz stereo PCM (the format the pipeline
 * decodes to), so `volume`, `aecho` and `highpass`/`lowpass` behave predictably.
 */

const FILTERS = {
    bassboost: {
        id: 'bassboost',
        label: 'Bass Boost',
        emoji: '🔊',
        description: 'Boost low frequencies',
        args: ['-af', 'bass=g=10,dynaudnorm=f=200'],
    },
    nightcore: {
        id: 'nightcore',
        label: 'Nightcore',
        emoji: '🌙',
        description: 'Faster tempo, higher pitch',
        args: ['-af', 'asetrate=48000*1.25,aresample=48000,atempo=1.0'],
    },
    vaporwave: {
        id: 'vaporwave',
        label: 'Vaporwave',
        emoji: '🌊',
        description: 'Slower tempo, lower pitch',
        args: ['-af', 'asetrate=48000*0.8,aresample=48000,atempo=1.0'],
    },
    '8d': {
        id: '8d',
        label: '8D Audio',
        emoji: '🎧',
        description: 'Rotating stereo field',
        args: ['-af', 'apulsator=hz=0.125'],
    },
    karaoke: {
        id: 'karaoke',
        label: 'Karaoke',
        emoji: '🎤',
        description: 'Strip the centre vocal channel',
        args: ['-af', 'pan=stereo|c0=c0-c1|c1=c1-c0'],
    },
    equalizer: {
        id: 'equalizer',
        label: 'Equalizer',
        emoji: '🎚️',
        description: 'Balanced 3-band EQ',
        args: ['-af', 'equalizer=f=100:t=q:w=1:g=4,equalizer=f=1000:t=q:w=1:g=2,equalizer=f=6000:t=q:w=1:g=3'],
    },
    treble: {
        id: 'treble',
        label: 'Treble',
        emoji: '✨',
        description: 'Brighten high frequencies',
        args: ['-af', 'treble=g=8'],
    },
    soft: {
        id: 'soft',
        label: 'Soft',
        emoji: '🕊️',
        description: 'Gentle, mellow tone',
        args: ['-af', 'lowpass=f=3000,volume=0.85'],
    },
};

const FILTER_LIST = Object.values(FILTERS);
const VALID_FILTER_IDS = FILTER_LIST.map(f => f.id);

/** True when `id` is a known filter preset. */
function isFilter(id) {
    return !!FILTERS[String(id || '').toLowerCase()];
}

/** Look up a filter preset (or null). */
function getFilter(id) {
    return FILTERS[String(id || '').toLowerCase()] || null;
}

/**
 * Resolve the ffmpeg `-af` args for a filter id. Returns `[]` for 'clear',
 * null/undefined or an unknown id (an unknown id must never silently apply a
 * wrong chain).
 */
function filterArgs(id) {
    const f = getFilter(id);
    return f ? f.args.slice() : [];
}

/** Human label for a filter id ('None' when cleared). */
function filterLabel(id) {
    const f = getFilter(id);
    return f ? f.label : 'None';
}

module.exports = {
    FILTERS,
    FILTER_LIST,
    VALID_FILTER_IDS,
    isFilter,
    getFilter,
    filterArgs,
    filterLabel,
};
