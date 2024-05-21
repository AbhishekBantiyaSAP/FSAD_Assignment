const bcrypt = require('bcrypt');

let users = [
  { id: 1, username: 'user1', password: '1234Abhishek', role: 'user' },
  { id: 2, username: 'user2', password: 'Abhishek1234', role: 'admin' }
];

// First hash the passwords which are in plain format - Otherwise wont be able to access admin as it has plain text
const hashPasswords = async () => {
  for (let user of users) {
    user.password = await bcrypt.hash(user.password, 10);
  }
};
// Then run the rest of code
hashPasswords().then(() => {
  const express = require('express');
  const bodyParser = require('body-parser');
  const jwt = require('jsonwebtoken');
  const app = express();
  const PORT = 4000;
  const secretKey = 'FSAD_2023sl93003';

  app.use(bodyParser.json());

  app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // bcrypt compare method to check if hashed password match
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });
      res.json({ token });
    });
  });

  app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const userExists = users.some(u => u.username === username);
    if (userExists) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    try {
      //hash the password of new user
      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = {
        id: users.length + 1,
        username,
        password: hashedPassword,
        role: 'user' // Default
      };

      users.push(newUser);
      res.status(201).json({ message: 'User successfully registered' });
    } catch (error) {
      res.status(500).json({ message: 'server error' });
    }
  });

  //admin route
  app.get('/admin', authenticateToken, isAdmin, (req, res) => {
    res.json({ message: 'Admin route successfully accessed' });
  });

  // normal user route
  app.get('/user', authenticateToken, (req, res) => {
    res.json({ message: 'User route successfully accessed' });
  });

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

  //check if admin by verifying role
  function isAdmin(req, res, next) {
    const user = users.find(u => u.id === req.user.userId);
    if (user.role !== 'admin') {
      return res.status(403).json({ message: 'Access forbidden, admin rights required' });
    }
    next();
  }

  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
});
