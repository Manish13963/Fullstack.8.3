const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret_demo_key_change_me';
const TOKEN_EXPIRATION = '1h'; // adjust as needed


const users = [
  { id: 1, username: 'adminUser', password: 'admin123', role: 'Admin' },
  { id: 2, username: 'modUser', password: 'mod123', role: 'Moderator' },
  { id: 3, username: 'normalUser', password: 'user123', role: 'User' }
];


function generateToken(user) {
  const payload = {
    id: user.id,
    username: user.username,
    role: user.role
  };

  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });
}


function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) {
    return res.status(401).json({ message: 'Authorization header missing' });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(400).json({ message: 'Invalid Authorization header format. Use: Bearer <token>' });
  }

  const token = parts[1];

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    req.user = decoded; // { id, username, role, iat, exp }
    next();
  });
}


function permitRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(401).json({ message: 'Unauthenticated' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied: insufficient role' });
    }

    next();
  };
}


app.get('/', (req, res) => {
  res.send({ message: 'RBAC + JWT demo server running' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'username and password required' });
  }

  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = generateToken(user);
  res.json({ token });
});

app.get('/admin-dashboard', verifyToken, permitRoles('Admin'), (req, res) => {
  res.json({
    message: 'Welcome to the Admin dashboard',
    user: req.user
  });
});

app.get('/moderator-panel', verifyToken, permitRoles('Moderator'), (req, res) => {
  res.json({
    message: 'Welcome to the Moderator panel',
    user: req.user
  });
});

app.get('/management', verifyToken, permitRoles('Admin', 'Moderator'), (req, res) => {
  res.json({
    message: `Welcome to the management area, ${req.user.username}`,
    user: req.user
  });
});

app.get('/user-profile', verifyToken, (req, res) => {
  res.json({
    message: `Welcome to your profile, ${req.user.username}`,
    user: req.user
  });
});

app.get('/user-only-area', verifyToken, permitRoles('User'), (req, res) => {
  res.json({
    message: 'This area is only for regular Users',
    user: req.user
  });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`RBAC demo server listening on http://localhost:${PORT}`);
});
