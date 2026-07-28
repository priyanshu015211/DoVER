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
