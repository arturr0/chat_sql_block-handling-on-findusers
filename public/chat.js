const socket = io.connect('http://localhost:3000');

socket.on('connect', () => {
    const username = localStorage.getItem('username');
    
        socket.emit('login', username);  // Emit username to the server when connected
        console.log('Username emitted to server:', username); // Debugging output
    
});


const messages = document.getElementById('messages');
const formMessage = document.getElementById('chat-form');
const inputMessage = document.getElementById('message');
const receivers = document.getElementById('rec'); // Assume this is the inputMessage for the receiver(s)

formMessage.addEventListener('submit', (e) => {
    e.preventDefault();
    const message = inputMessage.value;
    const user = localStorage.getItem('username'); // Retrieve username from localStorage
    const receiver = receivers.value; // Get the receiver(s) from inputMessage
    if (message && receiver) {
        socket.emit('chatMessage', { user, message, receiver });
        inputMessage.value = ''; // Clear the message inputMessage field
    }
});


const formFindUser = document.getElementById('findUser');
const inputFindUser = document.getElementById('find');

formFindUser.addEventListener('submit', (e) => {
    e.preventDefault();
    const searchUser = inputFindUser.value;
    if (searchUser) {
        socket.emit('findUsers', searchUser);
        inputFindUser.value = ''; // Clear the message inputMessage field
    }
});



// socket.on('message', (data) => {
//     const item = document.createElement('li');
//     item.textContent = `${data.user}: ${data.message}`;
//     messages.appendChild(item);
//     window.scrollTo(0, document.body.scrollHeight);
// });
socket.on('message', ({ user, message }) => {
    console.log(`Message from ${user}: ${message}`);
    // Optionally, you can update the chat UI with the received message
});
socket.on('foundUsers', (rows) => {
    console.log(rows);
    const usersDiv = document.getElementById('users');

    // Clear any existing content in the 'users' div
    usersDiv.innerHTML = '';

    // Iterate through the array and create divs with class 'user'
    rows.forEach(user => {
        // Create a new div element with class 'user'
        const userDiv = document.createElement('div');
        userDiv.classList.add('user');
        
        // Add the username as text content
        userDiv.textContent = user.username;

        // Create an invite button element
        const inviteButton = document.createElement('button');
        inviteButton.classList.add('invite');
        inviteButton.setAttribute('value', user.username); // Set the value attribute
        inviteButton.textContent = 'INVITE'; // Button text

        // Create a block button element
        const blockButton = document.createElement('button'); // Create a new instance each time
        blockButton.classList.add('block');
        blockButton.setAttribute('value', user.username); // Set the value attribute
        blockButton.textContent = 'BLOCK'; // Button text

        // Add click event listener to the block button
        blockButton.addEventListener('click', () => {
            const blockedUser = blockButton.value; // Get the value from the button
            socket.emit('block', blockedUser); // Emit the value using Socket.IO
            console.log(blockedUser);

        });

        // Append the buttons to the userDiv
        userDiv.appendChild(inviteButton);
        userDiv.appendChild(blockButton);
        // Append the userDiv to the parent div (usersDiv)
        usersDiv.appendChild(userDiv);
    });
});

