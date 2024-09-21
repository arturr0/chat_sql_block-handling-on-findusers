const express = require('express');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

const db = new sqlite3.Database('chat.db');
app.use(express.static(path.join(__dirname, 'public')));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// Encryption/Decryption functions
const ENCRYPTION_KEY = crypto.randomBytes(32); // Generate a secure random 32-byte key
const IV_LENGTH = 16; // For AES, this is always 16

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// Initialize the SQLite database
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        socketId TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        senderId INTEGER,
        recId INTEGER,
        message TEXT,
        FOREIGN KEY (senderId) REFERENCES users(id),
        FOREIGN KEY (recId) REFERENCES users(id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS blocked (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blocker INTEGER,
        blocked INTEGER,
        FOREIGN KEY (blocker) REFERENCES users(id),
        FOREIGN KEY (blocked) REFERENCES users(id)
    )`);
});


// Serve the authorization page
app.get('/', (req, res) => {
    res.render('index');
});

// Serve the chat page (after authentication)
app.get('/chat', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/'); // Redirect to login if not authenticated
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.redirect('/'); // Redirect to login if token is invalid
        }
        res.render('chat'); // Render chat.pug for authenticated users
    });
});

// User registration
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

// User login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Invalid username or password' });

        bcrypt.compare(password, user.password, (err, match) => {
            if (err || !match) return res.status(401).json({ message: 'Invalid username or password' });

            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, {
                httpOnly: true, 
                secure: true, 
                sameSite: 'None', // Explicitly set the SameSite attribute to 'None'
                maxAge: 3600000 // 1 hour in milliseconds
            });
            
            res.status(200).json({ message: 'Login successful' });
        });
    });
});

// Socket.IO handling
io.on('connection', (socket) => {
    console.log('A user connected with socket ID:', socket.id);

    socket.on('login', (username) => {
        db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
            if (err || !user) {
                console.error('User not found:', username);
                return;
            }

            // Update the user's socket ID
            db.run('UPDATE users SET socketId = ? WHERE id = ?', [socket.id, user.id], (err) => {
                if (err) {
                    console.error('Error updating socket ID:', err);
                } else {
                    console.log(`Socket ID ${socket.id} stored for user: ${username}`);
                }
            });
        });
    });

    // socket.on('chatMessage', ({ message }) => {
    //     db.get('SELECT id FROM users WHERE socketId = ?', [socket.id], (err, user) => {
    //         if (err || !user) {
    //             console.error('User not found for socket:', socket.id);
    //             return;
    //         }

    //         const encryptedMessage = encrypt(message);
    //         db.run('INSERT INTO messages (senderId, message) VALUES (?, ?)', [user.id, encryptedMessage], (err) => {
    //             if (err) {
    //                 console.error('Error saving message:', err);
    //                 return;
    //             }

    //             db.get('SELECT message FROM messages WHERE senderId = ? ORDER BY id DESC LIMIT 1', [user.id], (err, row) => {
    //                 if (err) {
    //                     console.error('Error retrieving message:', err);
    //                     return;
    //                 }

    //                 const decryptedMessage = decrypt(row.message);
    //                 io.to(socket.id).emit('message', { user: user.username, message: decryptedMessage });
    //             });
    //         });
    //     });
    // });
    socket.on('findUsers', (searchUser) => {
        // Get the sender ID based on socket ID
        db.get('SELECT id FROM users WHERE socketId = ?', [socket.id], (err, sender) => {
            if (err || !sender) {
                console.error('Sender not found:', err);
                return;
            }
    
            console.log('Sender ID:', sender.id);
    
            // SQL query to find users excluding the sender and those they have blocked
            const query = `
    SELECT u.id, u.username, u.socketId 
    FROM users u
    WHERE u.username LIKE ? COLLATE NOCASE 
    AND u.id != ?  -- Exclude the sender (blocker)
    AND u.id NOT IN (
        SELECT blocker FROM blocked WHERE blocked = ?
    )
`;

    
            db.all(query, [`%${searchUser}%`, sender.id, sender.id], (err, rows) => {
                if (err) {
                    console.error(err);
                    socket.emit('searchError', { message: 'Database query failed.' });
                } else {
                    console.log('Filtered users:', rows);
                    socket.emit('foundUsers', rows);
                }
            });
        });
    });
    
    
    socket.on('chatMessage', ({ user, message, receiver }) => {
        // Find sender's ID using socketId
        db.get('SELECT id FROM users WHERE socketId = ?', [socket.id], (err, sender) => {
            if (err || !sender) {
                console.error('Sender not found for socket:', socket.id);
                return;
            }
    
            // Find receiver's ID by username
            db.get('SELECT id, socketId FROM users WHERE username = ?', [receiver], (err, rec) => {
                if (err || !rec) {
                    console.error('Receiver not found:', receiver);
                    return;
                }
    
                const encryptedMessage = encrypt(message); // Encrypt the message for security
    
                // Insert message into database with sender and receiver IDs
                db.run('INSERT INTO messages (senderId, recId, message) VALUES (?, ?, ?)', 
                    [sender.id, rec.id, encryptedMessage], (err) => {
                    if (err) {
                        console.error('Error saving message:', err);
                        return;
                    }
    
                    // Decrypt message before sending (for demonstration purposes)
                    const decryptedMessage = decrypt(encryptedMessage);
    
                    // Send the message to the receiver using their socketId
                    io.to(rec.socketId).emit('message', { user: user, message: decryptedMessage });
                });
            });
        });
    });
    socket.on('block', (blockedUsername) => {
        // Find the ID of the user who is blocking
        db.get('SELECT id FROM users WHERE socketId = ?', [socket.id], (err, blocker) => {
            if (err || !blocker) {
                console.error('Blocker not found:', err);
                return;
            }
    
            // Find the ID of the user being blocked
            db.get('SELECT id FROM users WHERE username = ?', [blockedUsername], (err, blocked) => {
                if (err || !blocked) {
                    console.error('Blocked user not found:', err);
                    return;
                }
    
                // Insert into the blocked table
                db.run('INSERT INTO blocked (blocker, blocked) VALUES (?, ?)', [blocker.id, blocked.id], function(err) {
                    if (err) {
                        console.error('Error inserting into blocked table:', err);
                    } else {
                        console.log(`User ${blocker.id} blocked ${blocked.id}`);
                        // Optionally, notify the client about the successful block
                        socket.emit('blockSuccess', { message: `You have blocked ${blockedUsername}` });
                    }
                });
            });
        });
    });
    

    socket.on('disconnect', () => {
        console.log('A user disconnected');
        db.run('UPDATE users SET socketId = NULL WHERE socketId = ?', [socket.id], (err) => {
            if (err) {
                console.error('Error clearing socket ID:', err);
            }
        });
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
