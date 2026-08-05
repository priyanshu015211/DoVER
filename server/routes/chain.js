const express = require('express');
const router = express.Router();
const db = require('../db/db');
const documentQueue = require('../utils/queue');
const gemini = require('../utils/gemini');
const report = require('../utils/report');
const signatureEngine = require('../utils/signature_engine');
const { getBucket, mongoose } = require('../db/mongodb');
const fs = require('fs');
const path = require('path');
const { emailsEqual } = require('../utils/email');
const auditBundle = require('../utils/auditBundle');

/**
 * Helper to check if a user can access the full content/files of a document.
 * Authority can access all. Regular users can only access their own.
 * Note: Metadata is visible to authenticated users in the Global Ledger.
 */
function canAccessFullContent(user, document) {
    if (!user) return false;
    if (user.role === 'authority') return true;
    return emailsEqual(document.uploader_email, user.email);
}

router.get('/', (req, res) => {
    try {
        const isAuthority = req.user.role === 'authority';
        const mode = req.query.mode || 'b2c'; // Default to personal vault mode

        let documents;
        if (isAuthority) {
            // Authorities see everything for oversight
            documents = db.prepare('SELECT block_index, filename, file_type, uploaded_by, uploader_email, department, upload_timestamp, file_hash, block_hash, is_tampered, version_number, polygon_txid, merkle_root, merkle_proof FROM documents ORDER BY block_index DESC').all();
        } else if (mode === 'b2b') {
            // Institutional Ledger: Show documents that belong to B2B categories.
            const b2bDepts = ['Employee Records', 'Financial Audit', 'Compliance', 'Legal', 'Executive Office']; 
            const placeholders = b2bDepts.map(() => '?').join(',');
            
            // SECURITY FIX: Filter by uploader_email so standard users can only see their own B2B documents.
            documents = db.prepare(`
                SELECT block_index, filename, file_type, uploaded_by, uploader_email, department, upload_timestamp, file_hash, block_hash, is_tampered, version_number, polygon_txid, merkle_root, merkle_proof 
                FROM documents 
                WHERE department IN (${placeholders}) AND LOWER(uploader_email) = LOWER(?)
                ORDER BY block_index DESC
            `).all(...b2bDepts, req.user.email);
        } else {
            // Personal Ledger (B2C): Show only personal records.
            // We EXCLUDE B2B departments to ensure a clean separation.
            const b2bDepts = ['Employee Records', 'Financial Audit', 'Compliance', 'Legal', 'Executive Office'];
            const placeholders = b2bDepts.map(() => '?').join(',');
            
            documents = db.prepare(`
                SELECT block_index, filename, file_type, uploaded_by, uploader_email, department, upload_timestamp, file_hash, block_hash, is_tampered, version_number, polygon_txid, merkle_root, merkle_proof 
                FROM documents 
                WHERE LOWER(uploader_email) = LOWER(?) 
                AND department NOT IN (${placeholders})
                ORDER BY block_index DESC
            `).all(req.user.email, ...b2bDepts);
        }
        
        res.json(documents);
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Failed to retrieve chain' });
    }
});

router.get('/audit', (req, res) => {
    try {
        const isAuthority = req.user.role === 'authority';
        let auditLogs;
        if (isAuthority) {
            auditLogs = db.prepare(`
                SELECT a.document_id, d.filename, a.action, a.actor, a.timestamp, a.details
                FROM audit_log a
                LEFT JOIN documents d ON a.document_id = d.block_index
                ORDER BY a.timestamp DESC
            `).all();
        } else {
            auditLogs = db.prepare(`
                SELECT a.document_id, d.filename, a.action, a.actor, a.timestamp, a.details
                FROM audit_log a
                LEFT JOIN documents d ON a.document_id = d.block_index
                WHERE LOWER(d.uploader_email) = LOWER(?)
                ORDER BY a.timestamp DESC
            `).all(req.user.email);
        }
        res.json(auditLogs);
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Failed to retrieve audit logs' });
    }
});

router.get('/document/:id', (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const document = db.prepare('SELECT * FROM documents WHERE block_index = ?').get(id);

        if (!document) {
            return res.status(404).json({ success: false, error: 'Document not found' });
        }

        if (!canAccessFullContent(req.user, document)) {
            const isLegacy = !document.uploader_email && document.uploaded_by;
            return res.status(403).json({ success: false, error: isLegacy ? 'Legacy document requires authority approval' : 'Permission denied' });
        }

        res.json(document);
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Failed to retrieve document details' });
    }
});

router.get('/document/:id/history', (req, res) => {
    try {
        const doc = db.prepare('SELECT uploaded_by, uploader_email FROM documents WHERE block_index = ?').get(req.params.id);
        if (!doc) {
            return res.status(404).json({ success: false, error: 'Document not found' });
        }

        if (!canAccessFullContent(req.user, doc)) {
            const isLegacy = !doc.uploader_email && doc.uploaded_by;
            return res.status(403).json({ success: false, error: isLegacy ? 'Legacy document requires authority approval' : 'Permission denied' });
        }

        const history = db.prepare(`
            SELECT a.document_id, d.filename, a.action, a.actor, a.timestamp, a.details
            FROM audit_log a
            JOIN documents d ON a.document_id = d.block_index
            WHERE a.document_id = ?
            ORDER BY a.timestamp DESC
        `).all(req.params.id);
        res.json(history);
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Failed to retrieve document history' });
    }
});

// ── Batch Status ──
router.get('/batch/:batch_id/status', async (req, res) => {
    try {
        const batchId = parseInt(req.params.batch_id);

        // Fetch all jobs in parallel by checking the states selectively or getting a list of IDs.
        // Bull doesn't have a "getJobsByData" method, but we can avoid pulling all contents.
        // For this prototype, we'll use a more targeted approach if we had job IDs stored,
        // but since we don't store batch->job mapping in DB yet, we'll keep the logic but 
        // optimize it to not pull every job's full data if possible.
        
        // Read from DB batch_items table as the canonical source
        const batchItems = db.prepare('SELECT * FROM batch_items WHERE batch_id = ?').all(batchId);

        if (batchItems.length === 0) {
            return res.status(404).json({ success: false, error: 'No jobs found for this batch_id' });
        }

        // RBAC: Ensure user owns this batch OR is authority
        const isAuthority = req.user && req.user.role === 'authority';
        const ownsBatch = req.user && batchItems.every(j => emailsEqual(j.uploader_email, req.user.email));
        
        if (!req.user || (!isAuthority && !ownsBatch)) {
            return res.status(403).json({ success: false, error: 'Permission denied' });
        }

        // Map each item to a clean status object
        const jobs = batchItems.map(j => {
            // Check if document was created
            let document_id = null;
            if (j.status === 'completed') {
                const doc = db.prepare('SELECT block_index FROM documents WHERE storage_id = ?').get(j.storage_id);
                if (doc) document_id = doc.block_index;
            }

            return {
                job_id: j.job_id,
                storage_id: j.storage_id,
                filename: j.original_filename || 'Unknown file', 
                status: j.status,
                progress: 0,
                error: j.failed_reason || null,
                retryable: j.status === 'failed',
                document_id: document_id
            };
        });

        // Enrich with active progress from Bull if status is queued/processing
        try {
            const activeJobs = await documentQueue.getActive();
            activeJobs.forEach(job => {
                if (job && job.data && job.data.batch_id === batchId) {
                    const match = jobs.find(j => j.storage_id === job.data.storageId);
                    if (match) {
                        match.progress = job._progress || 0;
                        match.filename = job.data.originalname;
                    }
                }
            });
        } catch (e) {}

        const counts = jobs.reduce((acc, j) => {
            acc[j.status] = (acc[j.status] || 0) + 1;
            return acc;
        }, {});

        res.json({
            batch_id: batchId,
            total: jobs.length,
            completed: counts.completed || 0,
            failed: counts.failed || 0,
            processing: counts.processing || 0,
            queued: counts.queued || 0,
            jobs
        });

    } catch (error) {
        console.error('[BATCH_STATUS_ERROR]', error);
        res.status(500).json({ success: false, error: 'Failed to get batch status' });
    }
});

router.get('/document/:id/versions', (req, res) => {
    try {
        const id = parseInt(req.params.id);
        
        // 1. Find the current document
        let currentDoc = db.prepare('SELECT block_index, parent_document_id, uploaded_by, uploader_email, filename FROM documents WHERE block_index = ?').get(id);
        if (!currentDoc) {
            return res.status(404).json({ success: false, error: 'Document not found' });
        }

        // RBAC check
        if (!canAccessFullContent(req.user, currentDoc)) {
            const isLegacy = !currentDoc.uploader_email && currentDoc.uploaded_by;
            return res.status(403).json({ success: false, error: isLegacy ? 'Legacy document requires authority approval' : 'Permission denied' });
        }

        const targetFilename = currentDoc.filename;
        const targetEmail = currentDoc.uploader_email;

        // 2. Trace back to the root document (parent_document_id is NULL)
        let rootId = currentDoc.block_index;
        let parentId = currentDoc.parent_document_id;
        let safety = 0;
        
        while (parentId !== null && safety < 5000) {
            const parent = db.prepare('SELECT block_index, parent_document_id, filename, uploader_email FROM documents WHERE block_index = ?').get(parentId);
            
            // STRICT LINEAGE: Stop if parent metadata mismatch
            if (!parent || parent.filename !== targetFilename || !emailsEqual(parent.uploader_email, targetEmail)) {
                break;
            }

            rootId = parent.block_index;
            parentId = parent.parent_document_id;
            safety++;
        }

        // 3. Fetch all documents in the version chain starting from root
        // Using a recursive CTE to find all descendants, filtering by metadata for safety
        const versions = db.prepare(`
            WITH RECURSIVE descendants(id) AS (
                SELECT block_index FROM documents WHERE block_index = ?
                UNION
                SELECT d.block_index 
                FROM documents d 
                JOIN descendants ON d.parent_document_id = descendants.id
                WHERE d.filename = ? AND (LOWER(d.uploader_email) = LOWER(?) OR (d.uploader_email IS NULL AND ? IS NULL))
            )
            SELECT 
                version_number,
                block_index as document_id,
                filename,
                uploaded_by,
                upload_timestamp,
                version_note,
                block_hash,
                is_tampered
            FROM documents 
            WHERE block_index IN descendants 
            ORDER BY version_number ASC
        `).all(rootId, targetFilename, targetEmail, targetEmail);

        res.json(versions);
    } catch (error) {
        console.error('[VERSIONS_ERROR]', error);
        res.status(500).json({ success: false, error: 'Failed to retrieve version history' });
    }
});

router.get('/document/:id/timeline', (req, res) => {
    try {
        const id = parseInt(req.params.id);
        
        let currentDoc = db.prepare('SELECT block_index, parent_document_id, uploaded_by, uploader_email, filename FROM documents WHERE block_index = ?').get(id);
        if (!currentDoc) {
            return res.status(404).json({ success: false, error: 'Document not found' });
        }

        // RBAC check
        if (!canAccessFullContent(req.user, currentDoc)) {
            const isLegacy = !currentDoc.uploader_email && currentDoc.uploaded_by;
            return res.status(403).json({ success: false, error: isLegacy ? 'Legacy document requires authority approval' : 'Permission denied' });
        }

        const targetFilename = currentDoc.filename;
        const targetEmail = currentDoc.uploader_email;

        // Trace back to the root document
        let rootId = currentDoc.block_index;
        let parentId = currentDoc.parent_document_id;
        let safety = 0;
        
        while (parentId !== null && safety < 5000) {
            const parent = db.prepare('SELECT block_index, parent_document_id, filename, uploader_email FROM documents WHERE block_index = ?').get(parentId);
            
            // STRICT LINEAGE: Stop if parent metadata mismatch
            if (!parent || parent.filename !== targetFilename || !emailsEqual(parent.uploader_email, targetEmail)) {
                break;
            }

            rootId = parent.block_index;
            parentId = parent.parent_document_id;
            safety++;
        }

        const isAuthority = req.user.role === 'authority';
        const events = auditBundle.generateTimelineJSON(db, currentDoc, isAuthority);

        res.json({ success: true, timeline: events });
    } catch (error) {
        console.error('[TIMELINE_ERROR]', error);
        res.status(500).json({ success: false, error: 'Failed to retrieve timeline' });
    }
});

/**
 * Manual trigger for Gemini AI analysis.
 * Restricted to authorities.
 */
router.post('/document/:id/analyze', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const document = db.prepare('SELECT block_index, ocr_text, forensic_score FROM documents WHERE block_index = ?').get(id);

        if (!document) {
            return res.status(404).json({ success: false, error: 'Document not found' });
        }

        // RBAC: Only authorities can trigger manual AI analysis
        if (!req.user || req.user.role !== 'authority') {
            return res.status(403).json({ success: false, error: 'Authority privileges required' });
        }

        if (!document.ocr_text) {
            return res.status(400).json({ success: false, error: 'Document lacks OCR text for analysis' });
        }

        const forensicReport = document.forensic_score ? JSON.parse(document.forensic_score) : {};
        const summary = await gemini.generateDocumentSummary(document.ocr_text, forensicReport);

        db.prepare('UPDATE documents SET ai_summary = ? WHERE block_index = ?').run(JSON.stringify(summary), id);

        db.prepare(`INSERT INTO audit_log (document_id, action, actor, details) VALUES (?, ?, ?, ?)`)
            .run(id, 'AI_REANALYZE', req.user.name, 'Manual Gemini AI analysis triggered by authority');

        res.json({
            success: true,
            summary
        });

    } catch (error) {
        console.error('[AI_ANALYZE_ERROR]', error);
        res.status(500).json({ success: false, error: 'AI_ANALYSIS_FAILED' });
    }
});

/**
 * Official Audit Report Export.
 * Restricted to authorities.
 */
router.get('/document/:id/report', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        
        // RBAC: Authority only
        if (!req.user || req.user.role !== 'authority') {
            return res.status(403).json({ success: false, error: 'Authority privileges required' });
        }

        const pdfBuffer = await report.generateAuditReport(id);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=DoVER_Audit_Report_${id}.pdf`);
        res.send(pdfBuffer);
    } catch (error) {
        console.error('[REPORT_ENDPOINT_ERROR]', error);
        res.status(500).json({ success: false, error: 'REPORT_GENERATION_FAILED' });
    }
});

const { PDFDocument } = require('pdf-lib');

/**
 * Official Certified Document Export (Signed PDF).
 * Restricted to authorities.
 */
router.get('/document/:id/certified', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        
        // 1. Fetch metadata from SQLite
        const doc = db.prepare('SELECT * FROM documents WHERE block_index = ?').get(id);
        if (!doc) {
            return res.status(404).json({ success: false, error: 'Document not found' });
        }

        // RBAC: Authority OR Document Owner
        if (!canAccessFullContent(req.user, doc)) {
            const isLegacy = !doc.uploader_email && doc.uploaded_by;
            return res.status(403).json({ success: false, error: isLegacy ? 'Legacy document requires authority approval' : 'Permission denied' });
        }

        // 2. Build Certified PDF
        const bucket = getBucket();
        const signedBuffer = await auditBundle.generateCertifiedPDF(doc, bucket, mongoose, signatureEngine);

        // 5. Send Result
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=DoVER_Certified_${id}.pdf`);
        res.send(signedBuffer);

    } catch (error) {
        console.error('[CERTIFY_ENDPOINT_ERROR]', error);
        res.status(500).json({ success: false, error: 'CERTIFICATION_FAILED' });
    }
});

/**
 * Official Audit Bundle Export.
 * Restricted to authorities.
 */
router.get('/document/:id/bundle', async (req, res) => {
    try {
        if (req.user.role !== 'authority') {
            return res.status(403).json({ success: false, error: 'Permission denied' });
        }
        
        const id = parseInt(req.params.id);
        
        // 1. Fetch metadata from SQLite
        const doc = db.prepare('SELECT * FROM documents WHERE block_index = ?').get(id);
        if (!doc) {
            return res.status(404).json({ success: false, error: 'Document not found' });
        }

        // 2. Fetch everything
        const bucket = getBucket();
        
        console.log(`[BUNDLE] Generating export bundle for Block #${id}...`);
        
        const [pdfBuffer, timelineJSON] = await Promise.all([
            auditBundle.generateCertifiedPDF(doc, bucket, mongoose, signatureEngine),
            auditBundle.generateTimelineJSON(db, doc, true)
        ]);

        const proofJSON = auditBundle.generateProofJSON(doc);

        const bundle = {
            bundle_version: "1.0",
            generated_at: new Date().toISOString(),
            document_id: doc.block_index,
            proof: proofJSON,
            timeline: timelineJSON,
            certified_pdf_base64: pdfBuffer.toString('base64')
        };

        // Audit the bundle download
        db.prepare(`INSERT INTO audit_log (document_id, action, actor, details) VALUES (?, ?, ?, ?)`)
            .run(doc.block_index, 'AUDIT_BUNDLE_DOWNLOADED', req.user.name, `Authority ${req.user.name} exported the audit bundle`);

        res.json({ success: true, bundle: bundle });

    } catch (error) {
        console.error('[BUNDLE_ENDPOINT_ERROR]', error);
        res.status(500).json({ success: false, error: 'BUNDLE_GENERATION_FAILED' });
    }
});

module.exports = router;
