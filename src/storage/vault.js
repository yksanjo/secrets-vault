/**
 * Secrets Vault Storage - Store various types of secrets
 */

const fs = require('fs');
const path = require('path');
const crypto = require('../utils/crypto');

class SecretsVault {
  constructor(vaultPath = null) {
    this.vaultPath = vaultPath || path.join(process.cwd(), '.secrets', 'vault.json');
    this.data = {
      version: 1,
      secrets: [],
      metadata: {
        createdAt: null,
        updatedAt: null,
        salt: null
      }
    };
    this.encryptionKey = null;
    this.isUnlocked = false;
  }

  async init(passphrase) {
    const dir = path.dirname(this.vaultPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const { key, salt } = crypto.deriveKey(passphrase);
    this.encryptionKey = key;
    
    this.data.metadata.createdAt = new Date().toISOString();
    this.data.metadata.updatedAt = new Date().toISOString();
    this.data.metadata.salt = salt;
    
    await this.save();
    this.isUnlocked = true;
    
    return { success: true, message: 'Secrets vault initialized successfully' };
  }

  async unlock(passphrase) {
    if (!fs.existsSync(this.vaultPath)) {
      throw new Error('Vault does not exist. Run "secrets init" first.');
    }

    await this.load();
    const { key } = crypto.deriveKey(passphrase, this.data.metadata.salt);
    this.encryptionKey = key;
    this.isUnlocked = true;
    
    return { success: true, message: 'Vault unlocked successfully' };
  }

  lock() {
    this.encryptionKey = null;
    this.isUnlocked = false;
    return { success: true, message: 'Vault locked' };
  }

  async load() {
    const raw = fs.readFileSync(this.vaultPath, 'utf8');
    this.data = JSON.parse(raw);
    return this.data;
  }

  async save() {
    const dir = path.dirname(this.vaultPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(this.vaultPath, JSON.stringify(this.data, null, 2));
  }

  exists() {
    return fs.existsSync(this.vaultPath);
  }

  isVaultUnlocked() {
    return this.isUnlocked;
  }

  _ensureUnlocked() {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Run "secrets unlock" first.');
    }
  }

  /**
   * Add a secret
   * @param {Object} secretData - Secret data
   */
  async addSecret(secretData) {
    this._ensureUnlocked();
    
    const secret = {
      id: crypto.generateSecret(16).replace(/[-_]/g, '').substring(0, 16),
      name: secretData.name,
      type: secretData.type || 'generic', // generic, password, token, certificate, key
      value: crypto.encrypt(secretData.value, this.encryptionKey),
      valueHash: crypto.hash(secretData.value),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      expiresAt: secretData.expiresAt || null,
      metadata: secretData.metadata || {},
      tags: secretData.tags || [],
      notes: secretData.notes || ''
    };

    this.data.secrets.push(secret);
    this.data.metadata.updatedAt = new Date().toISOString();
    await this.save();

    return {
      id: secret.id,
      name: secret.name,
      type: secret.type,
      value: secretData.value, // Return raw value only on creation
      expiresAt: secret.expiresAt
    };
  }

  /**
   * Get a secret by ID
   * @param {string} id - Secret ID
   */
  async getSecret(id) {
    this._ensureUnlocked();
    
    const secret = this.data.secrets.find(s => s.id === id);
    if (!secret) {
      throw new Error('Secret not found');
    }

    return {
      id: secret.id,
      name: secret.name,
      type: secret.type,
      value: crypto.decrypt(secret.value, this.encryptionKey),
      valueHash: secret.valueHash,
      createdAt: secret.createdAt,
      updatedAt: secret.updatedAt,
      expiresAt: secret.expiresAt,
      metadata: secret.metadata,
      tags: secret.tags,
      notes: secret.notes
    };
  }

  /**
   * Get secret metadata (without decrypted value)
   */
  async getSecretMeta(id) {
    this._ensureUnlocked();
    
    const secret = this.data.secrets.find(s => s.id === id);
    if (!secret) {
      throw new Error('Secret not found');
    }

    const { value, ...meta } = secret;
    return meta;
  }

  /**
   * List all secrets
   */
  async listSecrets() {
    this._ensureUnlocked();
    
    return this.data.secrets.map(secret => {
      const { value, ...meta } = secret;
      return meta;
    });
  }

  /**
   * Update a secret
   */
  async updateSecret(id, updates) {
    this._ensureUnlocked();
    
    const index = this.data.secrets.findIndex(s => s.id === id);
    if (index === -1) {
      throw new Error('Secret not found');
    }

    const secret = this.data.secrets[index];

    if (updates.name) secret.name = updates.name;
    if (updates.type) secret.type = updates.type;
    if (updates.value) {
      secret.value = crypto.encrypt(updates.value, this.encryptionKey);
      secret.valueHash = crypto.hash(updates.value);
    }
    if (updates.expiresAt !== undefined) secret.expiresAt = updates.expiresAt;
    if (updates.metadata) secret.metadata = { ...secret.metadata, ...updates.metadata };
    if (updates.tags) secret.tags = updates.tags;
    if (updates.notes !== undefined) secret.notes = updates.notes;

    secret.updatedAt = new Date().toISOString();
    this.data.metadata.updatedAt = new Date().toISOString();
    await this.save();

    return { success: true, message: 'Secret updated successfully' };
  }

  /**
   * Delete a secret
   */
  async deleteSecret(id) {
    this._ensureUnlocked();
    
    const index = this.data.secrets.findIndex(s => s.id === id);
    if (index === -1) {
      throw new Error('Secret not found');
    }

    this.data.secrets.splice(index, 1);
    this.data.metadata.updatedAt = new Date().toISOString();
    await this.save();

    return { success: true, message: 'Secret deleted successfully' };
  }

  /**
   * Search secrets
   */
  async searchSecrets(query) {
    this._ensureUnlocked();
    
    const q = query.toLowerCase();
    return this.data.secrets.filter(secret => {
      const { value, ...meta } = secret;
      return (
        meta.name.toLowerCase().includes(q) ||
        meta.type.toLowerCase().includes(q) ||
        meta.tags.some(tag => tag.toLowerCase().includes(q))
      );
    }).map(secret => {
      const { value, ...meta } = secret;
      return meta;
    });
  }

  /**
   * Get secrets by type
   */
  async getSecretsByType(type) {
    this._ensureUnlocked();
    
    return this.data.secrets.filter(s => s.type === type).map(secret => {
      const { value, ...meta } = secret;
      return meta;
    });
  }

  /**
   * Get expired secrets
   */
  async getExpiredSecrets() {
    this._ensureUnlocked();
    
    const now = new Date();
    return this.data.secrets.filter(secret => {
      if (!secret.expiresAt) return false;
      return new Date(secret.expiresAt) <= now;
    }).map(secret => {
      const { value, ...meta } = secret;
      return meta;
    });
  }

  /**
   * Export secrets (encrypted)
   */
  async exportVault() {
    this._ensureUnlocked();
    return JSON.stringify(this.data, null, 2);
  }

  /**
   * Import secrets
   */
  async importVault(data) {
    this._ensureUnlocked();
    const imported = JSON.parse(data);
    this.data = imported;
    await this.save();
    return { success: true, message: 'Secrets imported successfully' };
  }
}

module.exports = SecretsVault;
