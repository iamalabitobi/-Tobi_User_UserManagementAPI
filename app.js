// Import required modules
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const SECRET_KEY = 'your_secret_key'; // Replace this with a secure, environment-stored key

// Middleware to parse JSON
app.use(express.json());

// JWT Helper Functions
function generateToken(user) {
  return jwt.sign({ userId: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

function authorizeAdmin(req, res, next) {
  if (req.user.role !== 'Admin') return res.status(403).json({ error: 'Access denied' });
  next();
}

// Register a User (Public Access)
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword, role },
    });
    res.status(201).json({ user });
  } catch (error) {
    res.status(400).json({ error: 'User registration failed' });
  }
});

// Login a User (Public Access)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = generateToken(user); // Generate JWT token
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(400).json({ error: 'Login failed' });
  }
});

// Get All Users (Admin Access Only)
app.get('/users', authenticateToken, authorizeAdmin, async (req, res) => {
  const users = await prisma.user.findMany();
  res.json(users);
});

// Get User by ID (Authenticated Users)
app.get('/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const user = await prisma.user.findUnique({ where: { id: parseInt(id) } });
  if (user) res.json(user);
  else res.status(404).json({ error: 'User not found' });
});

// Update a User (Authenticated Users)
app.put('/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, email, password, role } = req.body;
  const hashedPassword = password ? await bcrypt.hash(password, 10) : undefined;

  try {
    const user = await prisma.user.update({
      where: { id: parseInt(id) },
      data: { name, email, password: hashedPassword, role },
    });
    res.json(user);
  } catch (error) {
    res.status(404).json({ error: 'User not found' });
  }
});

// Delete a User (Admin Access Only)
app.delete('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.user.delete({ where: { id: parseInt(id) } });
    res.json({ message: 'User deleted' });
  } catch (error) {
    res.status(404).json({ error: 'User not found' });
  }
});

// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
