#!/bin/bash

# CredStor Setup Script
# This script sets up the CredStor environment and dependencies

set -e  # Exit on any error

echo "CredStor Setup Script"
echo "====================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if Python 3.9+ is available
print_step "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.9.0"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3,9) else 1)" 2>/dev/null; then
    print_error "Python 3.9+ is required. Current version: $python_version"
    exit 1
fi
print_status "Python version: $python_version ✓"

# Check if we're in the correct directory
if [[ ! -f "requirements.txt" ]] || [[ ! -d "src" ]]; then
    print_error "Please run this script from the CredStor root directory"
    exit 1
fi

# Create virtual environment if it doesn't exist
print_step "Setting up Python virtual environment..."
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
    print_status "Virtual environment created"
else
    print_status "Virtual environment already exists"
fi

# Activate virtual environment
print_step "Activating virtual environment..."
source venv/bin/activate
print_status "Virtual environment activated"

# Upgrade pip
print_step "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
print_step "Installing Python dependencies..."
pip install -r requirements.txt
print_status "Dependencies installed"

# Create necessary directories
print_step "Creating directory structure..."
mkdir -p data logs certs
print_status "Directory structure created"

# Set up configuration
print_step "Setting up configuration..."
if [[ ! -f "config/config.yaml" ]]; then
    cp config/config.example.yaml config/config.yaml
    print_status "Configuration template copied to config/config.yaml"
    print_warning "Please edit config/config.yaml with your settings"
else
    print_status "Configuration file already exists"
fi

# Generate encryption key
print_step "Generating encryption key..."
if [[ ! -f "config/.encryption_key" ]]; then
    python3 -c "
import base64
import secrets
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

from utils.user import get_current_username

key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
username = get_current_username()

with open('config/.encryption_key', 'w') as f:
    f.write(key)

print(f'Generated encryption key for user: {username}')
print(f'Encryption key: {key}')
print(f'Please update your config.yaml with this encryption key')
"
    chmod 400 config/.encryption_key
    print_status "Encryption key generated and saved to config/.encryption_key"
    print_warning "Update your config.yaml with this encryption key"
else
    print_status "Encryption key already exists"
fi

# Set file permissions
print_step "Setting secure file permissions..."
chmod 400 config/config.yaml 2>/dev/null || print_warning "Could not set config.yaml permissions"
chmod 700 data logs certs 2>/dev/null || print_warning "Could not set directory permissions"
print_status "File permissions set"

# Generate self-signed certificates for development
print_step "Generating development certificates..."
if [[ ! -f "certs/ca.pem" ]]; then
    # Generate CA key and certificate
    openssl genpkey -algorithm Ed25519 -out certs/ca.key 2>/dev/null || {
        print_warning "OpenSSL Ed25519 not available, using RSA"
        openssl genrsa -out certs/ca.key 4096
    }
    
    openssl req -new -x509 -key certs/ca.key -out certs/ca.pem -days 365 \
        -subj "/C=US/ST=Local/L=Local/O=CredStor/CN=CredStor-CA" \
        2>/dev/null || print_warning "Could not generate CA certificate"
    
    # Generate client key and certificate
    openssl genpkey -algorithm Ed25519 -out certs/client.key 2>/dev/null || {
        openssl genrsa -out certs/client.key 4096
    }
    
    openssl req -new -key certs/client.key -out certs/client.csr \
        -subj "/C=US/ST=Local/L=Local/O=CredStor/CN=CredStor-Client" \
        2>/dev/null || print_warning "Could not generate client CSR"
    
    openssl x509 -req -in certs/client.csr -CA certs/ca.pem -CAkey certs/ca.key \
        -out certs/client.pem -days 365 -CAcreateserial \
        2>/dev/null || print_warning "Could not generate client certificate"
    
    # Clean up CSR
    rm -f certs/client.csr
    
    # Set certificate permissions
    chmod 400 certs/*.key certs/*.pem
    
    print_status "Development certificates generated"
else
    print_status "Certificates already exist"
fi

# Initialize database
print_step "Initializing database..."
export PYTHONPATH="$(pwd)/src:$PYTHONPATH"
python3 -c "
try:
    from src.database.models import init_database
    init_database()
    print('Database initialized successfully')
except Exception as e:
    print(f'Database initialization will be completed when first run: {e}')
" 2>/dev/null || print_warning "Database will be initialized on first run"

# Create CLI symlink
print_step "Setting up CLI command..."
if [[ ! -f "venv/bin/credstor" ]]; then
    cat > venv/bin/credstor << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
export PYTHONPATH="$PROJECT_DIR/src:$PYTHONPATH"
"$SCRIPT_DIR/python" "$PROJECT_DIR/src/cli/credstor.py" "$@"
EOF
    chmod +x venv/bin/credstor
    print_status "CLI command 'credstor' created in virtual environment"
else
    print_status "CLI command already exists"
fi

echo ""
echo "CredStor setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Edit config/config.yaml with your settings"
echo "3. Update the encryption key in config.yaml from config/.encryption_key"
echo "4. Test the CLI: ./venv/bin/credstor --help"
echo ""
echo "For security:"
echo "- Keep config/config.yaml and config/.encryption_key secure (0400 permissions)"
echo "- Never commit these files to version control"
echo "- Use strong master passwords"
echo ""
print_status "Setup complete! Happy secure credential management!"