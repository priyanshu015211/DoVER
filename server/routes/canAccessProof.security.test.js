const { test } = require('node:test');
const assert = require('node:assert');

process.env.NODE_ENV = 'test';
const verifyRouter = require('./verify');
const canAccessProof = verifyRouter.canAccessProof;

test('canAccessProof — display-name spoofing fix (#102)', async (t) => {

    await t.test('user whose name matches doc.uploaded_by but whose email does NOT match doc.uploader_email is denied (403)', () => {
        const user = { role: 'citizen', name: 'John Smith', email: 'imposter@evil.local' };
        const document = { uploaded_by: 'John Smith', uploader_email: 'john.smith@gov.local' };
        assert.strictEqual(canAccessProof(user, document), false);
    });

    await t.test('user whose name matches doc.uploaded_by on a legacy record (no uploader_email at all) is denied', () => {
        const user = { role: 'citizen', name: 'John Smith', email: 'imposter@evil.local' };
        const document = { uploaded_by: 'John Smith', uploader_email: null };
        assert.strictEqual(canAccessProof(user, document), false);
    });

    await t.test('legitimate owner (matching email, case-insensitive) retains access', () => {
        const user = { role: 'citizen', name: 'Someone Else', email: 'John.Smith@Gov.Local' };
        const document = { uploaded_by: 'John Smith', uploader_email: 'john.smith@gov.local' };
        assert.strictEqual(canAccessProof(user, document), true);
    });

    await t.test('authority role still receives access regardless of name/email', () => {
        const user = { role: 'authority', name: 'Admin', email: 'admin@gov.local' };
        const document = { uploaded_by: 'John Smith', uploader_email: 'john.smith@gov.local' };
        assert.strictEqual(canAccessProof(user, document), true);
    });

    await t.test('null user is always denied', () => {
        const document = { uploaded_by: 'John Smith', uploader_email: 'john.smith@gov.local' };
        assert.strictEqual(canAccessProof(null, document), false);
    });

});
