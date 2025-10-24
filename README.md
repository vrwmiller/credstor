# CredStor - Personal Credential Vault

A secure, encrypted personal credential store with CLI-only interface for maximum security.

## 🔒 Security Features

- **Application-level encryption**: All sensitive data encrypted with AES-256-GCM
- **Encrypted at rest**: Database storage with per-field encryption
- **Memory-only secrets**: Credentials never logged or written to disk unencrypted
- **Secure password hashing**: Argon2 for master password protection
- **Audit logging**: Comprehensive security event logging
- **No network exposure**: CLI-only interface eliminates remote attack vectors

## 🏗️ Architecture

```text
┌─────────────────┐    ┌─────────────────┐
│   CLI Interface │────│    Database     │
│                 │    │   (Encrypted)   │
│ • Commands      │    │ • PostgreSQL    │
│ • CSV Import    │    │ • SQLite        │
│ • Config        │    │ • AES-256-GCM   │
│ • Validation    │    │ • Audit Logs    │
│ • Authentication│    │ • Security Logs │
└─────────────────┘    └─────────────────┘
```

## 📊 Data Model

CredStor stores the following credential types:

- **Record ID**: Unique UUID identifier
- **Property/Website**: Service or website name
- **Username**: Login username
- **Password**: Encrypted password
- **API Token**: API keys and tokens
- **Public Key**: SSH/GPG public keys
- **Private Key**: SSH/GPG private keys (encrypted)

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- SQLite (default) or PostgreSQL (for shared/production use)
- Virtual environment (recommended)

### Database Setup

#### SQLite (Default - Recommended for Personal Use)

SQLite is the default database and perfect for personal credential storage:
- **No installation required** (included with Python)
- **No server setup** - just a local database file
- **Automatic creation** - database file created on first run
- **Encrypted storage** - all data encrypted with AES-256-GCM
- **Perfect for single-user** personal credential management

Simply run the setup script and choose SQLite (default option).

#### PostgreSQL (Alternative for Shared/Production Use)

For shared environments or production deployments, PostgreSQL is supported:

1. Install PostgreSQL:

```bash
# macOS with Homebrew
brew install postgresql

# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL service
brew services start postgresql  # macOS
sudo systemctl start postgresql  # Linux
```

2. Create database and user:

```bash
# Connect to PostgreSQL as superuser
psql postgres

# Create database and user
CREATE DATABASE credstor;
CREATE USER credstor_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE credstor TO credstor_user;
\q
```

### Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd credstor
```

2. Set up virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On macOS/Linux
# venv\Scripts\activate   # On Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run setup script:

```bash
./scripts/setup.sh
```

5. Configure database connection:

```bash
# Copy configuration template
cp config/config.example.yaml config/config.yaml

# For PostgreSQL (default): Set up database authentication
credstor init-auth

# For SQLite: Edit config.yaml to change database type to "sqlite"
# Edit config/config.yaml with your preferences
chmod 400 config/config.yaml
```

### Usage

#### CLI Commands

```bash
# Database setup and authentication
credstor init-auth    # Set up database authentication

# Check system health
credstor health       # Verify database connectivity and encryption

# Add a new credential
credstor add --property "github.com" --username "myuser" --password

# Search credentials
credstor search --property "github"

# List all credentials (without secrets)
credstor list

# Import from CSV
credstor import-csv --file credentials.csv --separator ","

# Export to CSV (encrypted)
credstor export --file backup.csv
```

## 🔧 Configuration

Configuration file located at `config/config.yaml` (permissions: 0400):

### PostgreSQL Configuration (Default)

```yaml
database:
  type: postgresql
  host: localhost
  port: 5432
  name: credstor
  # Credentials stored separately in ~/.credstor/credstor.conf (permissions: 0400)
  
security:
  master_password_required: true
  key_iterations: 100000
  
logging:
  level: INFO
  file: ~/.credstor/logs/app.log
```

### SQLite Configuration (Alternative)

```yaml
database:
  type: sqlite
  path: ~/.credstor/credentials.db
  encryption_key: <base64-encoded>
  
security:
  master_password_required: true
  key_iterations: 100000
  
logging:
  level: INFO
  file: ~/.credstor/logs/app.log
```

### Database Authentication

For PostgreSQL, credentials are stored separately in `~/.credstor/credstor.conf`:

```ini
[database]
username = credstor_user
password = your_secure_password
```

This file is automatically created with restricted permissions (0400) during setup.

## 🛡️ Security Best Practices

- **Database Authentication**: Separate authentication required for database access
- **Master Password**: Required for application-level access
- **Dual Encryption**: Database-level + application-level encryption
- **Encryption Keys**: Generated using secure random methods
- **File Permissions**: Config files restricted to owner only (0400)
- **Memory Management**: Secrets cleared from memory after use
- **Audit Trail**: All operations logged (without exposing secrets)
- **Input Validation**: All inputs sanitized and validated
- **No Network Exposure**: CLI-only interface eliminates remote attack vectors

## 📁 Project Structure

```text
credstor/
├── src/
│   ├── cli/           # Command-line interface
│   ├── database/      # Database models and operations
│   ├── security/      # Encryption and security utilities
│   └── utils/         # Common utilities
├── tests/             # Unit and integration tests
├── config/            # Configuration files
├── scripts/           # Installation and utility scripts
├── docs/              # Documentation
└── requirements.txt   # Python dependencies
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run security tests
pytest tests/security/
```

## 📝 Development

### Adding New Credential Types

1. Update database schema in `src/database/models.py`
2. Update CLI commands to handle new types
3. Add validation and encryption for new fields

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all security tests pass
5. Submit a pull request

## 🔐 Security Considerations

- **Dual Authentication**: Database-level authentication + application master password
- **Application Encryption**: All sensitive data encrypted with AES-256-GCM
- **Database Security**: PostgreSQL provides additional access controls and encryption
- **Key Management**: Encryption keys derived securely from master password
- **Access Control**: Multi-layer access control (database + application)
- **Audit Logging**: Monitor all credential access (without exposing secrets)
- **No Network Exposure**: CLI-only interface eliminates remote attacks
- **Credential Separation**: Database credentials stored separately from application config

## 📋 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This software is provided as-is for educational and personal use. Users are responsible for ensuring proper security practices in their deployment environment.

