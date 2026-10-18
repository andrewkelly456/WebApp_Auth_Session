const db = require('../config/db');

async function requireSession(req, res, next) {
    const token = req.cookies.session_token;

    if (!token) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    try {
        const [rows] = await db.query(
            'SELECT sessions.user_id, users.username, users.email FROM sessions JOIN users ON sessions.user_id = users.id WHERE session_token = ?',
            [token]
        );

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid or expired session' });
        }

        req.user = rows[0]; // attach user info to the request for later use
        next();
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

module.exports = requireSession;