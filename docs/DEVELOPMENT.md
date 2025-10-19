# CredStor Development Guide

This document provides development guidelines and setup instructions for CredStor contributors.

## 🚀 Quick Setup

1. **Clone and setup**:

```bash
cd /path/to/your/credstor
chmod +x scripts/setup.sh
./scripts/setup.sh
```

1. **Activate virtual environment**:

```bash
source venv/bin/activate
```

1. **Configure the system**:

```bash
# Edit the configuration with your settings
vim config/config.yaml

# Update the encryption key from the generated one
cat config/.encryption_key
# Copy this key to config.yaml under database.encryption_key
```

1. **Test the CLI**:

```bash
./venv/bin/credstor health
./venv/bin/credstor --help
```

1. **Start the API server**:

```bash
python src/api/server.py
```

## 📁 Project Structure

```text
credstor/
├── .github/                    # GitHub configuration
│   └── copilot-instructions.md
├── .vscode/                    # VS Code configuration
│   └── launch.json
├── src/                        # Source code
│   ├── api/                    # REST API server
│   │   ├── __init__.py
│   │   └── server.py           # FastAPI server
│   ├── cli/                    # Command-line interface
│   │   ├── __init__.py
│   │   └── credstor_cli.py     # CLI implementation
│   ├── database/               # Database layer
│   │   ├── __init__.py
│   │   ├── models.py           # SQLAlchemy models
│   │   └── connection.py       # Database connection management
│   ├── security/               # Security and encryption
│   │   ├── __init__.py
│   │   └── crypto.py           # Encryption utilities
│   ├── utils/                  # Utility modules
│   │   ├── __init__.py
│   │   ├── config.py           # Configuration management
│   │   └── logging_config.py   # Logging setup
│   └── __init__.py
├── tests/                      # Test suite
│   ├── api/                    # API tests
│   ├── cli/                    # CLI tests
│   ├── database/               # Database tests
│   ├── security/               # Security tests
│   │   └── test_crypto.py      # Crypto function tests
│   └── conftest.py             # Test configuration
├── config/                     # Configuration files
│   └── config.example.yaml     # Configuration template
├── templates/                  # Templates and examples
│   └── import_template.csv     # CSV import template
├── scripts/                    # Utility scripts
│   └── setup.sh               # Setup script
├── docs/                       # Documentation
├── data/                       # Database files (created by setup)
├── logs/                       # Log files (created by setup)
├── certs/                      # Certificates (created by setup)
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git ignore rules
└── README.md                   # Main documentation
```

## 🔧 Development Commands

### CLI Commands

```bash
# Health check
./venv/bin/credstor health

# Add a credential
./venv/bin/credstor add --property "example.com" --username "user@example.com"

# Search credentials
./venv/bin/credstor search --property "example"

# Import from CSV
./venv/bin/credstor import-csv --file templates/import_template.csv --dry-run

# Show credential (with secrets)
./venv/bin/credstor show <credential-id> --show-secrets
```

### API Development

```bash
# Start development server
python src/api/server.py

# The API will be available at:
# http://127.0.0.1:8080/docs (OpenAPI documentation)
# http://127.0.0.1:8080/health (Health check)
```

### Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/security/test_crypto.py -v
```

## 🔐 Security Considerations

### Data Handling
- **Never log sensitive data**: All logging functions sanitize sensitive fields
- **Memory management**: Use `SecureString` for sensitive data in memory
- **Encryption**: All sensitive database fields are encrypted with AES-256-GCM
- **Key management**: Encryption keys are derived from configuration

### File Permissions
```bash
# Configuration files should be readable only by owner
chmod 400 config/config.yaml
chmod 400 config/.encryption_key

# Certificate files should be protected
chmod 400 certs/*.key
chmod 444 certs/*.pem

# Log and data directories should be private
chmod 700 logs/ data/
```

### Authentication
- API uses Bearer token authentication (customize in production)
- CLI uses local file-based authentication
- Certificate-based authentication can be enabled in configuration

## 🗃️ Database Schema

### Main Tables

**credentials**: Stores encrypted credential data
- `id`: UUID primary key
- `property`: Website/service name (plaintext)
- `username`: Username (plaintext)
- `password_encrypted`: Encrypted password
- `api_token_encrypted`: Encrypted API token
- `public_key_encrypted`: Encrypted public key
- `private_key_encrypted`: Encrypted private key
- `notes_encrypted`: Encrypted notes
- `created_at`, `updated_at`, `last_accessed`: Timestamps
- `is_active`: Soft delete flag

**audit_logs**: Security and access audit trail
**security_events**: Security-related events
**encryption_keys**: Key rotation metadata

## 🔄 Configuration Management

Configuration is loaded from:
1. `CREDSTOR_CONFIG` environment variable
2. `config/config.yaml` (current directory)
3. `~/.credstor/config.yaml` (user home)
4. `/etc/credstor/config.yaml` (system-wide)

Environment variables can override config values:
```bash
export CREDSTOR_DATABASE__TYPE=postgresql
export CREDSTOR_API__PORT=9090
```

## 📊 Logging

Three types of logs are generated:
- **Application logs**: General application events (`logs/credstor.log`)
- **Security logs**: Security events and authentication (`logs/security.log`)
- **Audit logs**: Data access and modification audit trail (`logs/audit.log`)

All logs automatically sanitize sensitive data.

## 🚀 Adding New Features

### Adding New Credential Fields

1. **Update database model** (`src/database/models.py`):
```python
new_field_encrypted = Column(LargeBinary, nullable=True)
```

2. **Update API models** (`src/api/server.py`):
```python
class CredentialCreate(BaseModel):
    new_field: Optional[str] = Field(None, description="New field")
```

3. **Update CLI** (`src/cli/credstor_cli.py`):
```python
@click.option('--new-field', help='New field value')
```

4. **Update encryption functions** to handle the new field in both API and CLI.

### Adding New API Endpoints

1. Create the endpoint function in `src/api/server.py`
2. Add appropriate Pydantic models for request/response
3. Add authentication and authorization checks
4. Add audit logging for the new endpoint
5. Update API documentation

## 🧪 Testing Guidelines

- **Unit tests**: Test individual functions in isolation
- **Integration tests**: Test component interactions
- **Security tests**: Test encryption, authentication, and authorization
- **Mock external dependencies**: Use pytest fixtures for database and configuration
- **Test data**: Use non-sensitive test data only

### Test Structure
```python
def test_function_name():
    """Test description."""
    # Arrange
    # Act
    # Assert
```

## 📝 Code Style

- **Follow PEP 8**: Python code style guidelines
- **Type hints**: Use type hints throughout
- **Docstrings**: Document all public functions and classes
- **Error handling**: Implement comprehensive error handling
- **Security**: Never expose sensitive data in logs or error messages

### Pre-commit Hooks
```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run manually
pre-commit run --all-files
```

## 🔍 Debugging

### VS Code Configuration
The project includes VS Code launch configurations for:
- Running the API server
- Running the CLI
- Running tests
- Debugging current file

### Common Issues

1. **Database connection errors**: Check encryption key in config
2. **Import errors**: Ensure virtual environment is activated
3. **Permission errors**: Check file permissions on config and cert files
4. **Encryption errors**: Verify encryption key format (base64)

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Cryptography Documentation](https://cryptography.io/)
- [Click Documentation](https://click.palletsprojects.com/)
- [Rich Documentation](https://rich.readthedocs.io/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation
7. Submit a pull request

## 📞 Support

For questions or issues:
1. Check this development guide
2. Review the main README.md
3. Check existing issues
4. Create a new issue with detailed information