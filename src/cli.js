#!/usr/bin/env node

/**
 * CLI - Command-line interface for Secrets Vault
 */

const { Command } = require('commander');
const readline = require('readline');
const SecretsVault = require('./storage/vault');
const crypto = require('./utils/crypto');

const vault = new SecretsVault();

function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer); }));
}

function promptPassword(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer); }));
}

const program = new Command();

program
  .name('secrets')
  .description('General-purpose secrets vault for storing sensitive configuration data')
  .version('1.0.0');

// Initialize vault
program
  .command('init')
  .description('Initialize a new secrets vault')
  .action(async () => {
    try {
      const passphrase = await promptPassword('Enter master passphrase: ');
      const confirm = await promptPassword('Confirm passphrase: ');
      
      if (passphrase !== confirm) {
        console.error('Passphrases do not match');
        process.exit(1);
      }

      if (vault.exists()) {
        console.error('Vault already exists. Use "secrets unlock" first.');
        process.exit(1);
      }

      const result = await vault.init(passphrase);
      console.log(result.message);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Unlock vault
program
  .command('unlock')
  .description('Unlock the vault')
  .action(async () => {
    try {
      if (!vault.exists()) {
        console.error('Vault does not exist. Run "secrets init" first.');
        process.exit(1);
      }

      const passphrase = await promptPassword('Enter master passphrase: ');
      await vault.unlock(passphrase);
      console.log('Vault unlocked successfully');
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Lock vault
program
  .command('lock')
  .description('Lock the vault')
  .action(async () => {
    try {
      vault.lock();
      console.log('Vault locked');
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Add a secret
program
  .command('add')
  .description('Add a new secret')
  .requiredOption('-n, --name <name>', 'Secret name')
  .requiredOption('-v, --value <value>', 'Secret value')
  .option('-t, --type <type>', 'Secret type (generic, password, token, certificate, key)', 'generic')
  .option('-e, --expires <date>', 'Expiration date (ISO format)')
  .option('--notes <notes>', 'Notes')
  .option('-tgs, --tags <tags>', 'Comma-separated tags')
  .action(async (options) => {
    try {
      if (!vault.isVaultUnlocked()) {
        console.error('Vault is locked. Run "secrets unlock" first.');
        process.exit(1);
      }

      const result = await vault.addSecret({
        name: options.name,
        value: options.value,
        type: options.type,
        expiresAt: options.expires || null,
        notes: options.notes || '',
        tags: options.tags ? options.tags.split(',').map(t => t.trim()) : []
      });

      console.log('Secret added successfully:');
      console.log(`  ID: ${result.id}`);
      console.log(`  Name: ${result.name}`);
      console.log(`  Type: ${result.type}`);
      console.log(`  Value: ${result.value} (shown once)`);
      if (result.expiresAt) console.log(`  Expires: ${result.expiresAt}`);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Get a secret
program
  .command('get <id>')
  .description('Get a secret by ID')
  .action(async (id) => {
    try {
      if (!vault.isVaultUnlocked()) {
        console.error('Vault is locked. Run "secrets unlock" first.');
        process.exit(1);
      }

      const secret = await vault.getSecret(id);
      console.log('Secret:');
      console.log(`  ID: ${secret.id}`);
      console.log(`  Name: ${secret.name}`);
      console.log(`  Type: ${secret.type}`);
      console.log(`  Value: ${secret.value}`);
      console.log(`  Created: ${secret.createdAt}`);
      console.log(`  Updated: ${secret.updatedAt}`);
      if (secret.expiresAt) console.log(`  Expires: ${secret.expiresAt}`);
      if (secret.tags.length) console.log(`  Tags: ${secret.tags.join(', ')}`);
      if (secret.notes) console.log(`  Notes: ${secret.notes}`);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// List secrets
program
  .command('list')
  .description('List all secrets')
  .option('-t, --type <type>', 'Filter by type')
  .action(async (options) => {
    try {
      if (!vault.isVaultUnlocked()) {
        console.error('Vault is locked. Run "secrets unlock" first.');
        process.exit(1);
      }

      let secrets = options.type 
        ? await vault.getSecretsByType(options.type)
        : await vault.listSecrets();

      console.log(`Found ${secrets.length} secret(s):\n`);
      secrets.forEach(s => {
        console.log(`ID: ${s.id}`);
        console.log(`  Name: ${s.name}`);
        console.log(`  Type: ${s.type}`);
        console.log(`  Updated: ${s.updatedAt}`);
        if (s.expiresAt) console.log(`  Expires: ${s.expiresAt}`);
        console.log('');
      });
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Search secrets
program
  .command('search <query>')
  .description('Search secrets')
  .action(async (query) => {
    try {
      if (!vault.isVaultUnlocked()) {
        console.error('Vault is locked. Run "secrets unlock" first.');
        process.exit(1);
      }

      const results = await vault.searchSecrets(query);
      console.log(`Found ${results.length} matching secret(s):\n`);
      results.forEach(s => {
        console.log(`ID: ${s.id}`);
        console.log(`  Name: ${s.name}`);
        console.log(`  Type: ${s.type}`);
        console.log('');
      });
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Update a secret
program
  .command('update <id>')
  .description('Update a secret')
  .option('-n, --name <name>', 'Secret name')
  .option('-v, --value <value>', 'Secret value')
  .option('-t, --type <type>', 'Secret type')
  .option('-e, --expires <date>', 'Expiration date')
  .option('--notes <notes>', 'Notes')
  .action(async (id, options) => {
    try {
      if (!vault.isVaultUnlocked()) {
        console.error('Vault is locked. Run "secrets unlock" first.');
        process.exit(1);
      }

      const updates = {};
      if (options.name) updates.name = options.name;
      if (options.value) updates.value = options.value;
      if (options.type) updates.type = options.type;
      if (options.expires) updates.expiresAt = options.expires;
      if (options.notes) updates.notes = options.notes;

      const result = await vault.updateSecret(id, updates);
      console.log(result.message);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Delete a secret
program
  .command('delete <id>')
  .description('Delete a secret')
  .option('-f, --force', 'Skip confirmation')
  .action(async (id, options) => {
    try {
      if (!vault.isVaultUnlocked()) {
        console.error('Vault is locked. Run "secrets unlock" first.');
        process.exit(1);
      }

      if (!options.force) {
        const confirm = await prompt(`Delete secret ${id}? (yes/no): `);
        if (confirm.toLowerCase() !== 'yes') {
          console.log('Cancelled');
          process.exit(0);
        }
      }

      const result = await vault.deleteSecret(id);
      console.log(result.message);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Check expired secrets
program
  .command('expired')
  .description('List expired secrets')
  .action(async () => {
    try {
      if (!vault.isVaultUnlocked()) {
        console.error('Vault is locked. Run "secrets unlock" first.');
        process.exit(1);
      }

      const expired = await vault.getExpiredSecrets();
      console.log(`Found ${expired.length} expired secret(s):\n`);
      expired.forEach(s => {
        console.log(`ID: ${s.id}`);
        console.log(`  Name: ${s.name}`);
        console.log(`  Expired: ${s.expiresAt}`);
        console.log('');
      });
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

// Generate a secret
program
  .command('generate')
  .description('Generate a new random secret')
  .option('-l, --length <length>', 'Secret length', '32')
  .action(async (options) => {
    const secret = crypto.generateSecret(parseInt(options.length));
    console.log('Generated Secret:');
    console.log(secret);
  });

program.parse(process.argv);
