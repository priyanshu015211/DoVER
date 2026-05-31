const crypto = require('crypto');
const { recordAuthFailure } = require('../utils/abuse');

/**
 * Constant-time comparison of two API key strings.
 *
 * Why not `===`:
 *   JavaScript's strict-equality operator short-circuits on the first
 *   differing byte. Under precise network timing an attacker can measure
 *   response latency to determine how many leading characters of a guessed
 *   key are correct, enabling byte-by-byte brute-force (timing attack).
 *
 * Why we hash first:
 *   `crypto.timingSafeEqual` requires both Buffers to be the same length.
 *   Rather than padding (which leaks length information), we hash both
 *   sides with SHA-256 first — the digests are always 32 bytes regardless
 *   of input length, so the comparison is both constant-time AND
 *   length-safe. The hash is not for secrecy; it solely normalises length.
 */
function apiKeysMatch(provided, system) {
    // Guard: if either value is missing, reject immediately without
    // calling timingSafeEqual (which would throw on empty input).
    if (!provided || !system) return false;

    const hash = (val) =>
        crypto.createHash('sha256').update(val, 'utf8').digest(); // returns Buffer

    return crypto.timingSafeEqual(hash(provided), hash(system));
}

/**
 * Middleware to validate API requests using a static API key.
 * Checks for 'x-api-key' header against process.env.API_KEY.
 */
const apiKeyMiddleware = async (req, res, next) => {
    const providedKey = req.headers['x-api-key'] || req.query.api_key;
    const systemKey = process.env.API_KEY;

    if (!providedKey) {
        return res.status(401).json({ error: 'API_KEY_MISSING' });
    }

    if (!apiKeysMatch(providedKey, systemKey)) {
        await recordAuthFailure(req.ip);
        return res.status(403).json({ error: 'API_KEY_INVALID' });
    }

    next();
};

module.exports = apiKeyMiddleware;
// apiKeysMatch is intentionally NOT exported — it is an internal
// security primitive and should not be callable from outside this module.
