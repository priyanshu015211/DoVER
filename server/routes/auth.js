const express = require('express');
const router = express.Router();
const passport = require('../utils/passport');

// Initiate Google Login
router.get('/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

// Google Auth Callback
router.get('/google/callback', (req, res, next) => {
    passport.authenticate('google', { failureRedirect: '/?error=auth_failed' }, (err, user) => {
        if (err || !user) return res.redirect('/?error=auth_failed');

        req.session.regenerate((regenErr) => {
            if (regenErr) return next(regenErr);
            req.logIn(user, (loginErr) => {
                if (loginErr) return next(loginErr);
                res.redirect('/?authenticated=true');
            });
        });
    })(req, res, next);
});

// Logout
router.all('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        req.session.destroy((destroyErr) => {
            if (destroyErr) return next(destroyErr);
            res.clearCookie('connect.sid');
            res.redirect('/');
        });
    });
});

// Get Current User
router.get('/me', (req, res) => {
    if (req.isAuthenticated()) {
        const user = req.user;
        res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            picture: user.picture,
            role: user.role || 'user',
            department: user.department || null
        });
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});

module.exports = router;
