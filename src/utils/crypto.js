/**
 * Encryption utility for secure secrets storage
 * Uses AES-256-CTR for encryption with a master key derived from PBKDF2
 */

const aesjs = require('aes-js');
const crypto = require('crypto');

class Crypto {
  constructor() {
    this.keyLength = 32; // 256 bits
    this.ivLength = 16;   // 128 bits
    this.pbkdf2Iterations = 100000;
  }

  /**
   * Derive a 256-bit key from a passphrase using PBKDF2
   * @param {string} passphrase - The master passphrase
   * @param {string} salt - Optional salt (hex encoded, generated if not provided)
   * @returns {Object} - { key, salt }
   */
  deriveKey(passphrase, salt = null) {
    if (!salt) {
      salt = crypto.randomBytes(16).toString('hex');
    }
    
    const saltBuffer = Buffer.from(salt, 'hex');
    const key = crypto.pbkdf2Sync(passphrase, saltBuffer, this.pbkdf2Iterations, this.keyLength, 'sha256');
    
    return { key, salt };
  }

  /**
   * Encrypt data using AES-256-CTR
   * @param {string} plaintext - Data to encrypt
   * @param {Buffer} key - 256-bit encryption key
   * @returns {string} - Base64 encoded encrypted data (iv + ciphertext)
   */
  encrypt(plaintext, key) {
    const iv = crypto.randomBytes(this.ivLength);
    
    const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(iv));
    const encryptedBytes = aesCtr.encrypt(aesjs.utils.utf8.toBytes(plaintext));
    
    const combined = Buffer.concat([iv, encryptedBytes]);
    return combined.toString('base64');
  }

  /**
   * Decrypt data using AES-256-CTR
   * @param {string} ciphertext - Base64 encoded encrypted data
   * @param {Buffer} key - 256-bit encryption key
   * @returns {string} - Decrypted plaintext
   */
  decrypt(ciphertext, key) {
    const combined = Buffer.from(ciphertext, 'base64');
    
    const iv = combined.slice(0, this.ivLength);
    const encryptedBytes = combined.slice(this.ivLength);
    
    const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(iv));
    const decryptedBytes = aesCtr.decrypt(encryptedBytes);
    
    return aesjs.utils.utf8.fromBytes(decryptedBytes);
  }

  /**
   * Hash a value
   * @param {string} value - Value to hash
   * @returns {string} - SHA-256 hash
   */
  hash(value) {
    const sha256 = crypto.createHash('sha256');
    return sha256.update(value).digest('hex');
  }

  /**
   * Generate a secure random secret
   * @param {number} length - Secret length (default 32)
   * @returns {string} - Random secret
   */
  generateSecret(length = 32) {
    const bytes = crypto.randomBytes(length);
    return bytes.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}

module.exports = new Crypto();
