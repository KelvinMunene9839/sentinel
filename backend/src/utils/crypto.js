const crypto = require('crypto');

const SCRYPT_KEYLEN = 64;

function hashPassword(plainPassword) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(plainPassword), salt, SCRYPT_KEYLEN).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(plainPassword, storedHash) {
  if (!storedHash || typeof storedHash !== 'string' || !storedHash.includes(':')) {
    return false;
  }
  const [salt, keyHex] = storedHash.split(':');
  const keyBuf = Buffer.from(keyHex, 'hex');
  const derivedBuf = crypto.scryptSync(String(plainPassword), salt, SCRYPT_KEYLEN);
  if (keyBuf.length !== derivedBuf.length) return false;
  return crypto.timingSafeEqual(keyBuf, derivedBuf);
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashSessionToken(rawToken) {
  return crypto.createHash('sha256').update(String(rawToken)).digest('hex');
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateSessionToken,
  hashSessionToken,
};
