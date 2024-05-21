const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
const PORT = 3000;
const secretKey = 'FSAD_2023sl93003';

app.use(bodyParser.json());

const users = [
  { id: 1, username: 'user1', password: '1234Abhishek' },
  { id: 2, username: 'user2', password: 'Abhishek1234' }
];

// Login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
  
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    bcrypt.compare(password, user.password, (err, result) => {
        if (err || !result) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Register route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Check if the username already exists
    const userExists = users.some(u => u.username === username);
    if (userExists) {
        return res.status(400).json({ message: 'Username already exists' });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = {
            id: users.length + 1,
            username,
            password: hashedPassword
        };

        // Store new user
        users.push(newUser);
        res.status(201).json({ message: 'User registered successfully' });
        console.log(users)
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Dummy protected route
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Protected route accessed successfully' });
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
  
    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
