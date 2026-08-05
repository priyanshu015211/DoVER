const { PDFDocument } = require('pdf-lib');
const { emailsEqual } = require('./email');

async function generateCertifiedPDF(doc, bucket, mongoose, signatureEngine) {
    const storageId = doc.storage_id || doc.filename;
    
    if (!mongoose.Types.ObjectId.isValid(storageId)) {
        throw new Error('Legacy file content certification is no longer supported');
    }

    const downloadStream = bucket.openDownloadStream(new mongoose.Types.ObjectId(storageId));
    const chunks = [];
    for await (const chunk of downloadStream) {
        chunks.push(chunk);
    }
    let fileBuffer = Buffer.concat(chunks);

    // If the file is an image, we MUST wrap it in a PDF before signing.
    if (doc.file_type.includes('image') || /jpg|jpeg|png/.test(doc.filename.toLowerCase())) {
        console.log(`[CERTIFY] Converting ${doc.file_type} to PDF container...`);
        const pdfDoc = await PDFDocument.create();
        const image = doc.file_type.includes('png') ? await pdfDoc.embedPng(fileBuffer) : await pdfDoc.embedJpg(fileBuffer);
        
        const page = pdfDoc.addPage([image.width, image.height]);
        page.drawImage(image, { x: 0, y: 0, width: image.width, height: image.height });
        
        fileBuffer = Buffer.from(await pdfDoc.save());
    }

    // Prepare Proof Data for embedding
    const proof = generateProofJSON(doc);

    // Sign and Certify
    console.log(`[CERTIFY] Generating signed PDF for Block #${doc.block_index}...`);
    const signedBuffer = await signatureEngine.signPdf(fileBuffer, {
        reason: 'Official Document Certification',
        location: 'DoVER Digital Vault',
        proof: proof
    });

    return signedBuffer;
}

function generateProofJSON(doc) {
    return {
        document_id: doc.block_index,
        filename: doc.filename,
        uploaded_by: doc.uploaded_by,
        upload_timestamp: doc.upload_timestamp,
        file_hash: doc.file_hash,
        block_hash: doc.block_hash,
        block_index: doc.block_index,
        prev_hash: doc.prev_hash,
        signature: doc.signature,
        signer_fingerprint: doc.signer_fingerprint || null,
        ocr_text_stored: doc.ocr_text,
        forensic_score: doc.forensic_score ? JSON.parse(doc.forensic_score) : null,
        verified_at: new Date().toISOString()
    };
}

function generateTimelineJSON(db, doc, isAuthority) {
    const targetFilename = doc.filename;
    const targetEmail = doc.uploader_email;

    // Trace back to the root document
    let rootId = doc.block_index;
    let parentId = doc.parent_document_id;
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

    // Fetch audit logs for all descendants
    const events = db.prepare(`
        WITH RECURSIVE descendants(id) AS (
            SELECT block_index FROM documents WHERE block_index = ?
            UNION
            SELECT d.block_index 
            FROM documents d 
            JOIN descendants ON d.parent_document_id = descendants.id
            WHERE d.filename = ? AND (LOWER(d.uploader_email) = LOWER(?) OR (d.uploader_email IS NULL AND ? IS NULL))
        )
        SELECT 
            a.id as event_id,
            a.document_id, 
            a.action, 
            a.actor, 
            a.timestamp, 
            a.details,
            d.version_number
        FROM audit_log a
        JOIN documents d ON a.document_id = d.block_index
        WHERE a.document_id IN descendants
        ORDER BY a.timestamp DESC
    `).all(rootId, targetFilename, targetEmail, targetEmail);

    const timeline = events.map(e => {
        let category = 'system';
        let details_public = e.details;

        if (e.action === 'UPLOAD') category = 'upload';
        else if (e.action === 'VERSION_CREATE') category = 'version';
        else if (e.action.includes('PROOF')) category = 'proof';
        else if (['AI_REANALYZE', 'USER_UNFLAGGED', 'KEY_REQUEST_SUBMITTED', 'KEY_ISSUED', 'KEY_REVOKED', 'USER_PROMOTION', 'AUDIT_BUNDLE_DOWNLOADED'].includes(e.action)) category = 'admin';

        // Redact proof downloads and admin actions for non-authorities
        if (!isAuthority) {
            if (category === 'proof') {
                if (e.action === 'PROOF_DOWNLOADED') {
                    if (e.details && e.details.toLowerCase().includes('authority')) {
                        details_public = 'Downloaded by authority';
                    } else {
                        details_public = 'Proof downloaded';
                    }
                } else if (e.action === 'PROOF_ACCESS_DENIED') {
                    details_public = 'Proof access denied';
                }
            } else if (category === 'admin') {
                if (e.action === 'KEY_REQUEST_SUBMITTED') details_public = 'Key request submitted';
                else if (e.action === 'KEY_ISSUED') details_public = 'Key issued';
                else if (e.action === 'KEY_REVOKED') details_public = 'Key revoked';
                else if (e.action === 'USER_PROMOTION') details_public = 'User promoted';
                else if (e.action === 'USER_UNFLAGGED') details_public = 'User unflagged';
                else if (e.action === 'AI_REANALYZE') details_public = 'AI re-analysis performed';
                else if (e.action === 'AUDIT_BUNDLE_DOWNLOADED') details_public = 'Audit bundle exported';
                else details_public = 'Administrative action performed';
            }
        }

        return {
            event_id: e.event_id,
            document_id: e.document_id,
            timestamp: e.timestamp,
            action: e.action,
            category: category,
            actor: !isAuthority && (category === 'proof' || category === 'admin') ? 'Redacted' : e.actor,
            details_public: details_public,
            ...(isAuthority && { details_private: e.details }),
            version_number: e.version_number
        };
    });

    return timeline;
}

module.exports = {
    generateCertifiedPDF,
    generateProofJSON,
    generateTimelineJSON
};
