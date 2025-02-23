const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const PORT = 3000;
const JWT_SECRET = 'your_secret_key';

// Database Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Saidulu76@',
    database: 'auth_system',
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit(1);
    }
    console.log('Connected to the MySQL database!');
});

// User Registration
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        
        db.query(query, [username, email, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ success: false, message: 'User already exists.' });
                }
                return res.status(500).json({ success: false, message: 'Error registering user.', error: err });
            }
            res.status(201).json({ success: true, message: 'Registration successful! Redirecting to login...' });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Internal server error.', error });
    }
});

// User Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Server error.', error: err });
        if (results.length === 0) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ success: true, message: 'Login successful! Redirecting...', token });
    });
});

// Middleware for Authentication
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).json({ success: false, message: 'Authorization required.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid token.' });
        req.user = user;
        next();
    });
};

// Protected Dashboard Route
app.get('/dashboard', authenticateToken, (req, res) => {
    res.json({ success: true, message: `Welcome to the dashboard, ${req.user.username}!` });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
