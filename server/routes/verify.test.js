const { test } = require('node:test');
const assert = require('node:assert');

// Mock environment variable so the route exposes canAccessProof
process.env.NODE_ENV = 'test';
const verifyRouter = require('./verify');
const canAccessProof = verifyRouter.canAccessProof;

test('canAccessProof authorization logic', async (t) => {
    
    await t.test('denies access if user is null', () => {
        assert.strictEqual(canAccessProof(null, {}), false);
    });

    await t.test('grants access to authority role unconditionally', () => {
        const user = { role: 'authority', name: 'Admin', email: 'admin@gov.local' };
        const document = { uploader_email: 'other@gov.local' };
        assert.strictEqual(canAccessProof(user, document), true);
    });

    await t.test('grants access to exact email match (case-insensitive)', () => {
        const user = { role: 'citizen', name: 'Alice', email: 'Alice@Gov.Local' };
        const document = { uploader_email: 'alice@gov.local' };
        assert.strictEqual(canAccessProof(user, document), true);
    });

    await t.test('denies access on email mismatch', () => {
        const user = { role: 'citizen', name: 'Alice', email: 'alice2@gov.local' };
        const document = { uploader_email: 'alice@gov.local' };
        assert.strictEqual(canAccessProof(user, document), false);
    });

    await t.test('denies access for legacy records (no uploader_email) even if name matches (prevents spoofing)', () => {
        const user = { role: 'citizen', name: 'Alice Smith', email: 'alice.spoof@gov.local' };
        const document = { uploaded_by: 'Alice Smith', uploader_email: null };
        assert.strictEqual(canAccessProof(user, document), false);
    });

});

const express = require('express');
const verifyPublicRouter = require('./verify_public');
const db = require('../db/db');
const verificationService = require('../utils/verificationService');

test('Public Verification Endpoints Error Contracts', async (t) => {
    const app = express();
    app.use('/api/public/verify', verifyPublicRouter);
    
    let server;
    await new Promise((resolve) => {
        server = app.listen(0, resolve);
    });
    const port = server.address().port;

    await t.test('GET /api/public/verify/:hash returns 404 with unified error shape when not found', async () => {
        const originalPrepare = db.prepare;
        db.prepare = () => ({ get: () => null });
        
        try {
            const res = await fetch(`http://localhost:${port}/api/public/verify/invalid-hash-123`);
            const json = await res.json();
            
            assert.strictEqual(res.status, 404);
            assert.strictEqual(json.success, false);
            assert.strictEqual(json.status, 'error');
            assert.strictEqual(json.code, 'HASH_NOT_FOUND');
            assert.strictEqual(json.found, false);
        } finally {
            db.prepare = originalPrepare;
        }
    });

    server.close();
});

test('Privileged Verification Endpoints Error Contracts', async (t) => {
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => {
        req.user = { role: 'citizen', name: 'Tester', email: 'test@example.com' };
        next();
    });
    app.use('/api/verify', verifyRouter);

    let server;
    await new Promise((resolve) => {
        server = app.listen(0, resolve);
    });
    const port = server.address().port;

    const originalPrepare = db.prepare;
    const originalResolveSignatureStatus = verificationService.resolveSignatureStatus;

    t.afterEach(() => {
        db.prepare = originalPrepare;
        verificationService.resolveSignatureStatus = originalResolveSignatureStatus;
    });

    await t.test('GET /api/verify/:hash returns 404 for hash not found', async () => {
        db.prepare = () => ({ get: () => null });
        
        const res = await fetch(`http://localhost:${port}/api/verify/hash-123`);
        const json = await res.json();
        
        assert.strictEqual(res.status, 404);
        assert.strictEqual(json.success, false);
        assert.strictEqual(json.status, 'error');
        assert.strictEqual(json.code, 'HASH_NOT_FOUND');
    });
    
    await t.test('GET /api/verify/:hash returns 403 for permission denied', async () => {
        db.prepare = () => ({ get: () => ({ block_hash: 'hash-123', uploader_email: 'other@example.com' }) });
        
        const res = await fetch(`http://localhost:${port}/api/verify/hash-123`);
        const json = await res.json();
        
        assert.strictEqual(res.status, 403);
        assert.strictEqual(json.success, false);
        assert.strictEqual(json.status, 'error');
        assert.strictEqual(json.code, 'PERMISSION_DENIED');
    });

    await t.test('GET /api/verify/:hash returns 403 for legacy approval required', async () => {
        db.prepare = () => ({ get: () => ({ block_hash: 'hash-123', uploaded_by: 'Someone Else' }) });
        
        const res = await fetch(`http://localhost:${port}/api/verify/hash-123`);
        const json = await res.json();
        
        assert.strictEqual(res.status, 403);
        assert.strictEqual(json.success, false);
        assert.strictEqual(json.status, 'error');
        assert.strictEqual(json.code, 'LEGACY_APPROVAL_REQUIRED');
    });

    await t.test('GET /api/verify/:hash returns 503 for missing public key', async () => {
        db.prepare = () => ({ get: () => ({ block_hash: 'hash-123', uploader_email: 'test@example.com' }) });
        verificationService.resolveSignatureStatus = () => ({ signature_status: 'NO_KEY_CONFIGURED' });
        
        const res = await fetch(`http://localhost:${port}/api/verify/hash-123`);
        const json = await res.json();
        
        assert.strictEqual(res.status, 503);
        assert.strictEqual(json.success, false);
        assert.strictEqual(json.status, 'error');
        assert.strictEqual(json.code, 'PUBLIC_KEY_MISSING');
    });

    server.close();
});
