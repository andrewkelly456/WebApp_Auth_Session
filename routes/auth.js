const express = require('express');
const router = express.Router();
const db = require('../config/db');

//Vulnerability #1 (intentional): passwords being stored in plaintext, no hashing
router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'username, email, and password are required' });
    }

    try {
        await db.query(
            'INSERT INTO users (username, email, password) VALUES(?, ?, ?)',
            [username, email, password]
        );
        res.status(201).json({ message: 'User registered succcessfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

//Login - checks credentials against the plaintext password (vulnerability #1 in action)
//No session/token is issued yet
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'username and password are required' });
    }

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = rows[0];

        if (user.password !== password) {
            return res.status(401).json({error: 'Invalid username or password' });
        }

        res.json({ message: 'Login successful', userId: user.id, username: user.username });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
