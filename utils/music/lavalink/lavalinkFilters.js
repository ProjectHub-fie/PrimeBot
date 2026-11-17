/**
 * Map PrimeBot's audio-filter presets onto Lavalink filter settings.
 *
 * The direct engine applies real ffmpeg `-af` chains; Lavalink applies the
 * equivalent DSP on the node. A preset that has no faithful Lavalink mapping
 * returns `null` and the engine reports it as unsupported rather than silently
 * applying the wrong effect.
 *
 * Every mapping is a REAL filter (equalizer bands / timescale / rotation /
 * low-pass), never an embed-only decoration.
 */

/** 15-band equalizer gain curve from a simple "bass / mid / treble" description. */
function eqBands({ bass = 0, mid = 0, treble = 0 }) {
    const bands = [];
    for (let i = 0; i < 15; i++) {
        let gain;
        if (i <= 2) gain = bass;
        else if (i >= 12) gain = treble;
        else gain = mid;
        bands.push({ band: i, gain });
    }
    return bands;
}

const FILTER_SETTINGS = {
    bassboost: { equalizer: eqBands({ bass: 0.25, mid: 0.05, treble: 0 }) },
    nightcore: { timescale: { speed: 1.2, pitch: 1.2, rate: 1.0 } },
    vaporwave: { timescale: { speed: 0.85, pitch: 0.8, rate: 1.0 } },
    '8d': { rotation: { rotationHz: 0.2 } },
    karaoke: { karaoke: { level: 1.0, monoLevel: 1.0, filterBand: 220, filterWidth: 100 } },
    equalizer: { equalizer: eqBands({ bass: 0.2, mid: 0.1, treble: 0.15 }) },
    treble: { equalizer: eqBands({ bass: 0, mid: 0, treble: 0.25 }) },
    soft: { lowPass: { smoothing: 20.0 } },
};

/** The Lavalink FilterOptions for a preset id, or null when unsupported. */
function lavalinkFilterFor(id) {
    const key = String(id || '').toLowerCase();
    const f = FILTER_SETTINGS[key];
    return f ? { ...f } : null;
}

/** True when a preset can be reproduced faithfully on Lavalink. */
function supportsFilter(id) { return !!lavalinkFilterFor(id); }

/** The filter ids Lavalink can reproduce (for diagnostics/UI). */
function supportedFilterIds() { return Object.keys(FILTER_SETTINGS); }

module.exports = { FILTER_SETTINGS, lavalinkFilterFor, supportsFilter, supportedFilterIds, eqBands };
