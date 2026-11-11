#!/usr/bin/env node
/**
 * Generate `dashboard/public/version.json` for a production build.
 *
 * Vercel runs `npm run vercel-build` (this script) before deploying, so the
 * deployed artifact contains a version.json whose `version` is the Git commit
 * SHA for that deployment. The dashboard also resolves the same value at
 * runtime (`dashboard/deployVersion.js`), and serves `/version.json` with
 * `Cache-Control: no-store`, so the file is a belt-and-suspenders build
 * artifact — the feature works even if this step is skipped.
 *
 * Local development: with no CI environment variables set the version falls
 * back to a filesystem fingerprint, so a dev server still produces a
 * meaningful (changing) value instead of a hardcoded placeholder.
 */

const fs = require('fs');
const path = require('path');
const { getVersionPayload, getDeployVersion } = require('../dashboard/deployVersion');

const OUT = path.join(__dirname, '..', 'dashboard', 'public', 'version.json');

const payload = getVersionPayload();
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(payload, null, 2) + '\n', 'utf8');

console.log(`[version] wrote ${path.relative(path.join(__dirname, '..'), OUT)} → ${getDeployVersion()}`);
