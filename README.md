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
│ • Commands      │    │ • SQLite        │
│ • CSV Import    │    │ • AES-256-GCM   │
│ • Config        │    │ • Audit Logs    │
│ • Validation    │    │ • Security Logs │
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
- SQLite (included with Python)
- Virtual environment (recommended)

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
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your database credentials
chmod 400 config/config.yaml
```

### Usage

#### CLI Commands

```bash
# Add a new credential
credstor add --property "github.com" --username "myuser" --password

# Search credentials
credstor search --property "github"

# List all credentials (without secrets)
credstor list

# Import from CSV
credstor import --file credentials.csv --separator ","

# Export to CSV (encrypted)
credstor export --file backup.csv
```

## 🔧 Configuration

Configuration file located at `config/config.yaml` (permissions: 0400):

```yaml
database:
  type: sqlite
  path: ~/.credstor/credentials.db
  
security:
  encryption_key: <base64-encoded>
  master_password_required: true
  
logging:
  level: INFO
  file: /var/log/credstor/app.log
```

## 🛡️ Security Best Practices

- **Master Password**: Required for database access
- **Encryption Keys**: Generated using secure random methods
- **File Permissions**: Config files restricted to owner only (0400)
- **Memory Management**: Secrets cleared from memory after use
- **Audit Trail**: All operations logged (without exposing secrets)
- **Input Validation**: All inputs sanitized and validated

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

- **Application Encryption**: All sensitive data encrypted with AES-256-GCM
- **Key Management**: Encryption keys derived securely from master password
- **Access Control**: Master password required for all operations
- **Audit Logging**: Monitor all credential access (without exposing secrets)
- **No Network Exposure**: CLI-only interface eliminates remote attacks

## 📋 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This software is provided as-is for educational and personal use. Users are responsible for ensuring proper security practices in their deployment environment.
