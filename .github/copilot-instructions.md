# GitHub Copilot Instructions for CredStor

## Project Overview
CredStor is a secure personal vault/credential store with the following architecture:
- Database backend with encryption at rest
- Python API layer with security logging
- CLI interface for user interaction
- CSV import/export capabilities

## Security Requirements
- **CRITICAL**: Never log, print, or expose secrets in code
- All sensitive data must be encrypted in database
- Configuration files should have restricted permissions (0400)
- Secrets should only exist in memory during processing
- Use secure coding practices for credential handling

## Code Style Guidelines
- Follow PEP 8 for Python code
- Use type hints throughout
- Implement comprehensive error handling
- Add docstrings for all public functions
- Use secure random generation for UUIDs and keys
- Do not use emojis in code comments or strings
- Only use emojis in documentation where appropriate and necessary

## Database Guidelines
- Use parameterized queries to prevent SQL injection
- Implement connection pooling
- Use database-level encryption features
- Log all database operations (without exposing secrets)

## API Guidelines
- Implement rate limiting
- Use secure authentication methods
- Validate all inputs thoroughly
- Return consistent error responses
- Implement request/response logging (sanitized)

## CLI Guidelines
- Use secure input methods for sensitive data
- Implement configuration file validation
- Provide clear error messages without exposing internals
- Support batch operations for CSV import

## Testing
- Mock all external dependencies
- Test error conditions
- Validate security constraints
- Use test fixtures for sample data (non-sensitive)