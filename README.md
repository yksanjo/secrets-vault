# Secrets Vault

General-purpose secrets vault for storing sensitive configuration data.

## Features

- **Secure Storage**: AES-256 encryption with PBKDF2 key derivation
- **Multiple Secret Types**: Support for passwords, tokens, certificates, keys, and generic secrets
- **Expiration Tracking**: Set expiration dates for time-sensitive secrets
- **Search & Filter**: Find secrets by name, type, or tags
- **Import/Export**: Backup and restore your vault

## Installation

```bash
cd secrets-vault
npm install
```

## Usage

```bash
# Initialize vault
npm start -- init

# Unlock vault
npm start -- unlock

# Add a secret
npm start -- add -n "DB Password" -v "secret123" -t password

# List secrets
npm start -- list

# Search secrets
npm start -- search "db"

# Generate a secret
npm start -- generate

# Check expired secrets
npm start -- expired
```

## Commands

| Command | Description |
|---------|-------------|
| `secrets init` | Initialize vault |
| `secrets unlock` | Unlock vault |
| `secrets lock` | Lock vault |
| `secrets add -n <name> -v <value>` | Add secret |
| `secrets get <id>` | Get secret |
| `secrets list` | List secrets |
| `secrets search <query>` | Search secrets |
| `secrets update <id>` | Update secret |
| `secrets delete <id>` | Delete secret |
| `secrets expired` | List expired secrets |
| `secrets generate` | Generate random secret |

## License

MIT
