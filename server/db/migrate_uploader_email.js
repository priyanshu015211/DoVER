const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.resolve(__dirname, '..', '..', 'db.sqlite');
const db = new Database(dbPath);

console.log('[MIGRATE] Starting uploader_email backfill migration for legacy documents...');

// Get all documents where uploader_email is NULL
const legacyDocs = db.prepare(`SELECT block_index, uploaded_by FROM documents WHERE uploader_email IS NULL`).all();

console.log(`[MIGRATE] Found ${legacyDocs.length} legacy documents with NULL uploader_email.`);

if (legacyDocs.length === 0) {
    console.log('[MIGRATE] No legacy documents to migrate. Exiting.');
    process.exit(0);
}

// Get all users
const users = db.prepare(`SELECT id, name, email FROM users`).all();

// Create a map of normalized user names to lists of user emails
const userNameMap = new Map();
for (const user of users) {
    if (!user.name) continue;
    const normalizedName = user.name.trim().toLowerCase();
    if (!userNameMap.has(normalizedName)) {
        userNameMap.set(normalizedName, []);
    }
    userNameMap.get(normalizedName).push(user.email);
}

let backfilledCount = 0;
let ambiguousCount = 0;
let skippedCount = 0; // No matching user found

const updateStmt = db.prepare(`UPDATE documents SET uploader_email = ? WHERE block_index = ?`);

// Transaction for atomic update
const migrateTransaction = db.transaction((docs) => {
    for (const doc of docs) {
        if (!doc.uploaded_by || doc.uploaded_by.trim() === '') {
            updateStmt.run('legacy-archive@dover.io', doc.block_index);
            skippedCount++;
            continue;
        }

        const normalizedUploaderName = doc.uploaded_by.trim().toLowerCase();
        const matchedEmails = userNameMap.get(normalizedUploaderName) || [];

        if (matchedEmails.length === 1) {
            // Exactly one matching user found, backfill the email
            updateStmt.run(matchedEmails[0], doc.block_index);
            backfilledCount++;
        } else if (matchedEmails.length > 1) {
            // Multiple users with the same name, ambiguous. Backfill to stable archive owner.
            updateStmt.run('legacy-archive@dover.io', doc.block_index);
            ambiguousCount++;
        } else {
            // No matching user found. Backfill to stable archive owner.
            updateStmt.run('legacy-archive@dover.io', doc.block_index);
            skippedCount++;
        }
    }
});

try {
    migrateTransaction(legacyDocs);
    console.log(`[MIGRATE] ✓ Migration completed successfully.`);
    console.log(`[MIGRATE] Statistics:`);
    console.log(`          - Backfilled rows: ${backfilledCount}`);
    console.log(`          - Ambiguous rows (left as authority-only): ${ambiguousCount}`);
    console.log(`          - Skipped rows (no user match / empty name): ${skippedCount}`);
} catch (err) {
    console.error(`[MIGRATE] ✗ Migration failed:`, err);
    process.exit(1);
}
