const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const JWT_SECRET = process.env.JWT_SECRET;
if(!JWT_SECRET){
  console.error('Missing JWT_SECRET environment variable. Set a long random string before starting the server.');
  process.exit(1);
}

function signToken(user){
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
}

function hashPassword(pw){
  return bcrypt.hashSync(pw, 10);
}
function checkPassword(pw, hash){
  return bcrypt.compareSync(pw, hash);
}

function requireAuth(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if(!token) return res.status(401).json({ error: 'Sign in required.' });
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    req.userRole = payload.role;
    next();
  }catch(e){
    return res.status(401).json({ error: 'Session expired — please sign in again.' });
  }
}

function requireAdmin(req, res, next){
  if(req.userRole !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

module.exports = { signToken, hashPassword, checkPassword, requireAuth, requireAdmin };
