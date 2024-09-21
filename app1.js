const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const flash = require('connect-flash');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const http = require('http');
const { Server } = require('socket.io');
const subpageRouter = require('./routes/chat'); // Import the chat router

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const db = new sqlite3.Database('chat.db');

const JWT_SECRET = 'your_jwt_secret_key'; // Change this to a secure secret key

// Middleware setup
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(flash());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/css', express.static(path.join(__dirname, 'css')));

// Set up Pug as the view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// Initialize the SQLite database
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// Serve the authorization page at the root URL
app.get('/', (req, res) => {
    res.render('index'); // Renders the index.pug template for sign in and sign up
});

// Register route
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Server error' });

        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function (err) {
            if (err) return res.status(500).json({ message: 'User already exists' });
            res.status(200).json({ message: 'User registered successfully' });
        });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Invalid username or password' });

        bcrypt.compare(password, user.password, (err, match) => {
            if (err || !match) return res.status(401).json({ message: 'Invalid username or password' });

            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ token });
        });
    });
});

// Middleware to verify JWT token
const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Chat page (renders chat.pug)
app.get('/chat', authenticateJWT, (req, res) => {
    res.render('chat'); // Renders the chat.pug template
});

// Handle Socket.IO connections
io.on('connection', (socket) => {
    console.log('New client connected');

    socket.on('chatMessage', (data) => {
        const { user, message } = data;

        db.run('INSERT INTO messages (user, message) VALUES (?, ?)', [user, message], (err) => {
            if (err) {
                console.error('Error inserting message:', err);
            } else {
                io.emit('message', { user, message });
            }
        });
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

// Middleware to handle /chat refresh and referer check
app.use('/chat', subpageRouter);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});

module.exports = app;
