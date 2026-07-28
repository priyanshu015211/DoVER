/**
 * server/routes/verify_public.js
 *
 * Public verification endpoints — no API key, no session required.
 *
 * Security properties
 * ───────────────────
 * 1. Rate-limited on every route via verifyLimiter.
 * 2. No raw key material, internal user IDs, or registry internals are
 *    returned.  All sensitive fields are filtered through buildPublicPayload().
 * 3. All registry/signature logic is delegated to verificationService —
 *    this file never touches key_registry or the crypto module directly.
 * 4. Mounted exclusively under /api/public/verify in app.js so it can
 *    never accidentally inherit auth middleware from the privileged router.
 */

'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../db/db');
const { verifyLimiter }         = require('../middleware/limiters');
const { resolveSignatureStatus, buildPublicPayload } = require('../utils/verificationService');
const { sendVerificationError } = require('../utils/errorHelper');

// ─────────────────────────────────────────────────────────────
// GET /api/public/verify/chain-root
// Returns the latest global Merkle root for the public verifier
// ─────────────────────────────────────────────────────────────
router.get('/chain-root', verifyLimiter, (req, res) => {
    try {
        const rootRecord = db.prepare("SELECT block_index, merkle_root, created_at FROM blocks ORDER BY block_index DESC LIMIT 1").get();
        if (!rootRecord) {
            return res.json({ success: true, merkle_root: null, updated_at: null });
        }
        return res.json({
            success: true,
            merkle_root: rootRecord.merkle_root,
            updated_at: rootRecord.created_at
        });
    } catch (err) {
        console.error('Public chain-root error:', err);
        return sendVerificationError(res, 500, 'INTERNAL_SERVER_ERROR', 'Internal server error');
    }
});

// ─────────────────────────────────────────────────────────────
// GET /api/public/verify/qr/:hash
// QR-code verification — same data shape, dedicated path so QR
// payloads can be versioned independently in future.
// ─────────────────────────────────────────────────────────────
router.get('/qr/:hash', verifyLimiter, async (req, res) => {
    try {
        const hash = req.params.hash;
        const doc  = db
            .prepare('SELECT * FROM documents WHERE block_hash = ?')
            .get(hash);

        if (!doc) {
            return sendVerificationError(res, 404, 'HASH_NOT_FOUND', 'No record found', { found: false });
        }

        const { signature_status, issuer_name } = resolveSignatureStatus(doc);
        return res.json(buildPublicPayload(doc, signature_status, issuer_name));

    } catch (error) {
        console.error('[PUBLIC_QR_VERIFY_ERROR]', error);
        return sendVerificationError(res, 500, 'VERIFICATION_FAILED', 'Verification failed');
    }
});

// ─────────────────────────────────────────────────────────────
// GET /api/public/verify/:hash
// Public hash-lookup — returns a minimal integrity summary.
// ─────────────────────────────────────────────────────────────
router.get('/:hash', verifyLimiter, async (req, res) => {
    try {
        const hash = req.params.hash;
        const doc  = db
            .prepare('SELECT * FROM documents WHERE block_hash = ?')
            .get(hash);

        if (!doc) {
            return sendVerificationError(res, 404, 'HASH_NOT_FOUND', 'No record found', { found: false });
        }

        const { signature_status, issuer_name } = resolveSignatureStatus(doc);
        return res.json(buildPublicPayload(doc, signature_status, issuer_name));

    } catch (error) {
        console.error('[PUBLIC_VERIFY_ERROR]', error);
        return sendVerificationError(res, 500, 'VERIFICATION_FAILED', 'Verification failed');
    }
});

module.exports = router;