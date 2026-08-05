const { test } = require('node:test');
const assert = require('node:assert');
const express = require('express');

// Mock pdf-lib before anything else requires it
const Module = require('module');
const originalRequire = Module.prototype.require;
Module.prototype.require = function(id) {
    if (id === 'pdf-lib') {
        return { PDFDocument: { load: () => ({}) } };
    }
    return originalRequire.apply(this, arguments);
};

const chainRouter = require('./chain');
const db = require('../db/db');
const { emailsEqual } = require('../utils/email');

test('Chain Timeline Endpoints', async (t) => {
    const app = express();
    app.use(express.json());
    
    // Default to citizen user
    let currentUser = { role: 'citizen', name: 'Alice', email: 'alice@example.com' };
    
    app.use((req, res, next) => {
        req.user = currentUser;
        next();
    });
    app.use('/api/chain', chainRouter);

    let server;
    await new Promise((resolve) => {
        server = app.listen(0, resolve);
    });
    const port = server.address().port;

    const originalPrepare = db.prepare;

    t.afterEach(() => {
        db.prepare = originalPrepare;
        currentUser = { role: 'citizen', name: 'Alice', email: 'alice@example.com' };
    });

    await t.test('GET /api/chain/document/:id/timeline returns 403 for unprivileged user', async () => {
        db.prepare = (query) => {
            if (query.startsWith('SELECT block_index, parent_document_id')) {
                return { get: () => ({ block_index: 1, uploader_email: 'bob@example.com', filename: 'test.pdf' }) };
            }
            return { get: () => null };
        };

        const res = await fetch(`http://localhost:${port}/api/chain/document/1/timeline`);
        const json = await res.json();

        assert.strictEqual(res.status, 403);
        assert.strictEqual(json.success, false);
        assert.strictEqual(json.error, 'Permission denied');
    });

    await t.test('GET /api/chain/document/:id/timeline redacts proof downloads for non-authority', async () => {
        db.prepare = (query) => {
            if (query.startsWith('SELECT block_index, parent_document_id')) {
                return { get: () => ({ block_index: 1, parent_document_id: null, uploader_email: 'alice@example.com', filename: 'test.pdf' }) };
            }
            if (query.includes('WITH RECURSIVE descendants')) {
                return { all: () => [
                    { event_id: 2, document_id: 1, action: 'PROOF_DOWNLOADED', actor: 'bob@example.com', timestamp: '2023-01-02', details: 'Proof downloaded by Bob', version_number: 1 },
                    { event_id: 1, document_id: 1, action: 'UPLOAD', actor: 'alice@example.com', timestamp: '2023-01-01', details: 'Upload', version_number: 1 }
                ] };
            }
            return { get: () => null, all: () => [] };
        };

        const res = await fetch(`http://localhost:${port}/api/chain/document/1/timeline`);
        const json = await res.json();

        assert.strictEqual(res.status, 200);
        assert.strictEqual(json.timeline.length, 2);
        
        const proofEvent = json.timeline.find(e => e.category === 'proof');
        assert.strictEqual(proofEvent.actor, 'Redacted');
        assert.strictEqual(proofEvent.details_public, 'Proof downloaded');
        assert.strictEqual(proofEvent.details_private, undefined);
    });

    await t.test('GET /api/chain/document/:id/timeline includes details_private for authority', async () => {
        currentUser = { role: 'authority', name: 'Admin', email: 'admin@gov.local' };
        
        db.prepare = (query) => {
            if (query.startsWith('SELECT block_index, parent_document_id')) {
                return { get: () => ({ block_index: 1, parent_document_id: null, uploader_email: 'alice@example.com', filename: 'test.pdf' }) };
            }
            if (query.includes('WITH RECURSIVE descendants')) {
                return { all: () => [
                    { event_id: 2, document_id: 1, action: 'PROOF_DOWNLOADED', actor: 'bob@example.com', timestamp: '2023-01-02', details: 'Proof downloaded by Bob', version_number: 1 }
                ] };
            }
            return { get: () => null, all: () => [] };
        };

        const res = await fetch(`http://localhost:${port}/api/chain/document/1/timeline`);
        const json = await res.json();

        assert.strictEqual(res.status, 200);
        assert.strictEqual(json.timeline.length, 1);
        
        const proofEvent = json.timeline[0];
        assert.strictEqual(proofEvent.actor, 'bob@example.com');
        assert.strictEqual(proofEvent.details_private, 'Proof downloaded by Bob');
    });
    
    await t.test('GET /api/chain/document/:id/timeline captures correct lineage and categorizes events', async () => {
        db.prepare = (query) => {
            if (query.startsWith('SELECT block_index, parent_document_id')) {
                return { get: (id) => {
                    if (id === 2) return { block_index: 2, parent_document_id: 1, uploader_email: 'alice@example.com', filename: 'test.pdf' };
                    if (id === 1) return { block_index: 1, parent_document_id: null, uploader_email: 'alice@example.com', filename: 'test.pdf' };
                    return null;
                }};
            }
            if (query.includes('WITH RECURSIVE descendants')) {
                return { all: () => [
                    { event_id: 4, document_id: 2, action: 'AI_REANALYZE', actor: 'admin', timestamp: '2023-01-04', details: 'Reanalyze', version_number: 2 },
                    { event_id: 3, document_id: 2, action: 'VERSION_CREATE', actor: 'alice@example.com', timestamp: '2023-01-03', details: 'Version 2', version_number: 2 },
                    { event_id: 1, document_id: 1, action: 'UPLOAD', actor: 'alice@example.com', timestamp: '2023-01-01', details: 'Upload', version_number: 1 }
                ] };
            }
            return { get: () => null, all: () => [] };
        };

        const res = await fetch(`http://localhost:${port}/api/chain/document/2/timeline`);
        const json = await res.json();

        assert.strictEqual(res.status, 200);
        assert.strictEqual(json.timeline.length, 3);
        assert.strictEqual(json.timeline[0].category, 'admin');
        assert.strictEqual(json.timeline[1].category, 'version');
        assert.strictEqual(json.timeline[2].category, 'upload');
    });

    await t.test('GET /api/chain/document/:id/bundle returns 403 for unprivileged user', async () => {
        currentUser = { role: 'citizen', name: 'Alice', email: 'alice@example.com' };
        const res = await fetch(`http://localhost:${port}/api/chain/document/1/bundle`);
        const json = await res.json();
        
        assert.strictEqual(res.status, 403);
        assert.strictEqual(json.success, false);
        assert.strictEqual(json.error, 'Permission denied');
    });

    await t.test('GET /api/chain/document/:id/bundle returns 200 and valid JSON bundle for authority', async () => {
        currentUser = { role: 'authority', name: 'Admin', email: 'admin@gov.local' };
        
        db.prepare = (query) => {
            if (query.startsWith('SELECT * FROM documents WHERE block_index = ?')) {
                return { get: () => ({ block_index: 1, parent_document_id: null, uploader_email: 'alice@example.com', filename: '659b8c9d2f1b4a8e0b123456', file_type: 'application/pdf' }) };
            }
            if (query.startsWith('SELECT block_index, parent_document_id')) {
                return { get: () => ({ block_index: 1, parent_document_id: null, uploader_email: 'alice@example.com', filename: '659b8c9d2f1b4a8e0b123456' }) };
            }
            if (query.includes('WITH RECURSIVE descendants')) {
                return { all: () => [
                    { event_id: 1, document_id: 1, action: 'UPLOAD', actor: 'alice@example.com', timestamp: '2023-01-01', details: 'Upload', version_number: 1 }
                ] };
            }
            if (query.includes('INSERT INTO audit_log')) {
                return { run: () => ({ changes: 1 }) };
            }
            return { get: () => null, all: () => [], run: () => {} };
        };

        // Monkey-patch getBucket and mongoose for test
        const chainModule = require('./chain');
        const originalGetBucket = chainModule.__getBucket; // We can't easily mock it without rewriting test setup.
        
        // Wait, for this test we'd need to mock signatureEngine and getBucket. 
        // We will just mock auditBundle directly!
        const auditBundle = require('../utils/auditBundle');
        const origPdf = auditBundle.generateCertifiedPDF;
        auditBundle.generateCertifiedPDF = async () => Buffer.from('mockpdf');
        
        const res = await fetch(`http://localhost:${port}/api/chain/document/1/bundle`);
        const json = await res.json();
        
        auditBundle.generateCertifiedPDF = origPdf;
        
        assert.strictEqual(res.status, 200);
        assert.strictEqual(json.success, true);
        assert.ok(json.bundle);
        assert.strictEqual(json.bundle.document_id, 1);
        assert.strictEqual(json.bundle.bundle_version, '1.0');
        assert.strictEqual(json.bundle.certified_pdf_base64, 'bW9ja3BkZg=='); // base64 of 'mockpdf'
        assert.strictEqual(json.bundle.timeline.length, 1);
        assert.strictEqual(json.bundle.proof.document_id, 1);
    });

    server.close();
});
