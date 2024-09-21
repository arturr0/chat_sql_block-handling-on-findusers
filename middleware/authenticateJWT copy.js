const jwt = require('jsonwebtoken');
const JWT_SECRET = 'your_jwt_secret'; // Same secret as in server.js

const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        console.log('No token provided');
        return res.sendStatus(401);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log('Error verifying token:', err);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

module.exports = authenticateJWT;
