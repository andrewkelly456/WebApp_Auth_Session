const expres = require('express');
const router = expres.Router();
const requireSession = require('../middleware/session');

router.get('/account', requireSession, (req, res) => {
    res.json({
        message: "Welcome to your account",
        userId: req.user.user_id,
        username: req.user.username,
        email: req.user.email
    });
});

module.exports = router;
