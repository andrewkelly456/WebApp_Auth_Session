require('dotenv').config();
const express = require('express');

const app = express();
const db = require('./config/db');
const authRoutes = require('./routes/auth');
app.use(express.json());

app.get('/api/ping', (req, res) => {
    res.json({ message: 'pong' });
})

const PORT = process.env.PORT || 3000;

app.use('/api', authRoutes);

app.get('/api/db-test', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT COUNT(*) AS userCount FROM users');
        res.json({ connected: true, userCount: rows[0].userCount });
    } catch (err) {
        res.status(500).json({ connected: false, error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});