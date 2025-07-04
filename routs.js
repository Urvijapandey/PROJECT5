const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

// Register
router.post('/register', [
  body('username').isAlphanumeric().isLength({ min: 3 }),
  body('password').isStrongPassword(),
  body('role').isIn(['admin', 'user'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json(errors.array());

  const { username, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  const stmt = db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
  stmt.run([username, hashed, role], (err) => {
    if (err) return res.status(400).json({ error: "User already exists" });
    res.json({ success: true });
  });
});

// Login
router.post('/login', [
  body('username').notEmpty(),
  body('password').notEmpty()
], (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, 'secret_key');
    res.json({ token });
  });
});

// Protected route
router.get('/admin-data', authenticate, authorize('admin'), (req, res) => {
  res.json({ data: 'Sensitive admin data' });
});

module.exports = router;
