const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  try {
    req.user = jwt.verify(token, 'secret_key');
    next();
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
}

function authorize(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.status(403).json({ error: 'Access denied' });
    next();
  };
}

module.exports = { authenticate, authorize };
