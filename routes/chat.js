const express = require('express');
const router = express.Router();

// Chat page route
router.get('/', (req, res) => {
    res.render('chat'); // Assuming you have a chat.pug for the chat interface
});

module.exports = router;
