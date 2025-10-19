#!/bin/bash

# CredStor Setup Script
# This script sets up the CredStor environment and dependencies

set -e  # Exit on any error

echo "🔐 CredStor Setup Script"
echo "======================="

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
if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
    print_status "Virtual environment created"
else
    print_status "Virtual environment already exists"
fi

# Activate virtual environment
print_step "Activating virtual environment..."
source .venv/bin/activate
print_status "Virtual environment activated"

# Upgrade pip
print_step "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
print_step "Installing Python dependencies..."
pip install -r requirements.txt
print_status "Dependencies installed"

# Check for PostgreSQL installation (optional)
print_step "Checking for PostgreSQL availability..."
if command -v psql >/dev/null 2>&1; then
    pg_version=$(psql --version 2>/dev/null | awk '{print $3}' | head -1)
    print_status "PostgreSQL found: $pg_version"
    
    # Check if PostgreSQL is running
    if pg_isready >/dev/null 2>&1; then
        print_status "PostgreSQL server is running"
    else
        print_warning "PostgreSQL is installed but not running"
        print_warning "To start PostgreSQL: brew services start postgresql (macOS) or systemctl start postgresql (Linux)"
    fi
else
    print_warning "PostgreSQL not found - only SQLite will be available"
    print_warning "To install PostgreSQL: brew install postgresql (macOS) or apt-get install postgresql (Linux)"
fi

# Database authentication setup
print_step "Setting up database authentication..."
export PYTHONPATH="$(pwd)/src:$PYTHONPATH"
if ! python3 -c "
import sys
sys.path.insert(0, 'src')
from utils.config import verify_database_authentication
try:
    if verify_database_authentication():
        print('Database authentication already configured')
        exit(0)
    else:
        exit(1)
except:
    exit(1)
" 2>/dev/null; then
    print_status "Database authentication not configured yet"
    print_status "You can set it up later with: python -m src.cli.credstor init-auth"
    print_warning "Note: Database operations will require authentication setup"
else
    print_status "Database authentication already configured"
fi

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
print_step "Setting up database..."
echo "CredStor supports two database options:"
echo "1. SQLite (recommended for personal use)"
echo "2. PostgreSQL (for production/shared use)"
echo ""
read -p "Choose database type (sqlite/postgresql) [sqlite]: " db_type
db_type=${db_type:-sqlite}

if [[ "$db_type" == "postgresql" ]]; then
    print_step "Setting up PostgreSQL..."
    
    # Check if PostgreSQL is installed
    if ! command -v psql &> /dev/null; then
        print_warning "PostgreSQL is not installed."
        echo "To install PostgreSQL:"
        if [[ "$OSTYPE" == "darwin"* ]]; then
            echo "  brew install postgresql"
            echo "  brew services start postgresql"
        elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
            echo "  Ubuntu/Debian: sudo apt-get install postgresql postgresql-contrib"
            echo "  CentOS/RHEL: sudo yum install postgresql-server postgresql-contrib"
        fi
        echo ""
        read -p "Continue setup without PostgreSQL database creation? (y/n) [y]: " continue_setup
        continue_setup=${continue_setup:-y}
        if [[ "$continue_setup" != "y" ]]; then
            print_error "PostgreSQL installation required. Exiting."
            exit 1
        fi
    else
        print_status "PostgreSQL is installed"
        
        # Check if PostgreSQL is running
        if ! pg_isready -q 2>/dev/null; then
            print_warning "PostgreSQL is not running."
            echo "To start PostgreSQL:"
            if [[ "$OSTYPE" == "darwin"* ]]; then
                echo "  brew services start postgresql"
            elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
                echo "  sudo systemctl start postgresql"
            fi
            echo ""
            read -p "Continue setup without database creation? (y/n) [y]: " continue_setup
            continue_setup=${continue_setup:-y}
            if [[ "$continue_setup" != "y" ]]; then
                print_error "PostgreSQL must be running. Exiting."
                exit 1
            fi
        else
            print_status "PostgreSQL is running"
            
            # Attempt to create database and user
            echo ""
            echo "Setting up CredStor database and user in PostgreSQL..."
            read -p "Enter PostgreSQL admin username [postgres]: " pg_admin
            pg_admin=${pg_admin:-postgres}
            
            read -p "Enter CredStor database name [credstor]: " db_name
            db_name=${db_name:-credstor}
            
            read -p "Enter CredStor database username [credstor_user]: " db_user
            db_user=${db_user:-credstor_user}
            
            echo "Enter password for CredStor database user:"
            read -s db_password
            
            if [[ ${#db_password} -lt 12 ]]; then
                print_warning "Password should be at least 12 characters for security"
            fi
            
            # Create database and user
            print_step "Creating PostgreSQL database and user..."
            
            # Check if database exists
            if psql -U "$pg_admin" -lqt | cut -d \| -f 1 | grep -qw "$db_name"; then
                print_status "Database '$db_name' already exists"
            else
                if createdb -U "$pg_admin" "$db_name" 2>/dev/null; then
                    print_status "Database '$db_name' created successfully"
                else
                    print_warning "Could not create database '$db_name'. You may need to create it manually."
                fi
            fi
            
            # Create user (will show warning if user exists, which is fine)
            psql -U "$pg_admin" -d "$db_name" -c "
                DO \$\$
                BEGIN
                    CREATE USER $db_user WITH PASSWORD '$db_password';
                    GRANT ALL PRIVILEGES ON DATABASE $db_name TO $db_user;
                    GRANT ALL ON SCHEMA public TO $db_user;
                    PRINT_STATUS('User $db_user created and granted privileges');
                EXCEPTION WHEN duplicate_object THEN
                    ALTER USER $db_user WITH PASSWORD '$db_password';
                    GRANT ALL PRIVILEGES ON DATABASE $db_name TO $db_user;
                    GRANT ALL ON SCHEMA public TO $db_user;
                    RAISE NOTICE 'User $db_user already exists, updated password and privileges';
                END\$\$;
            " 2>/dev/null || print_warning "User setup may need manual configuration"
            
            # Update config.yaml with PostgreSQL settings
            print_step "Updating configuration for PostgreSQL..."
            if [[ -f "config/config.yaml" ]]; then
                python3 -c "
import yaml
try:
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f) or {}
    
    config.setdefault('database', {})
    config['database']['type'] = 'postgresql'
    config['database']['host'] = 'localhost'
    config['database']['port'] = 5432
    config['database']['name'] = '$db_name'
    config['database']['pool_size'] = 5
    config['database']['max_overflow'] = 10
    
    with open('config/config.yaml', 'w') as f:
        yaml.dump(config, f, default_flow_style=False, indent=2)
    
    print('✓ Configuration updated for PostgreSQL')
except Exception as e:
    print(f'⚠ Could not update config.yaml: {e}')
"
            fi
            
            # Create database credentials file
            print_step "Creating database credentials file..."
            mkdir -p config
            cat > config/credstor.conf << EOF
database:
  username: $db_user
  password: $db_password
  auth_token: ''
  created_at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF
            chmod 400 config/credstor.conf
            print_status "Database credentials saved to config/credstor.conf (0400 permissions)"
            
            print_status "PostgreSQL setup completed!"
            echo "  - Database: $db_name"
            echo "  - User: $db_user"
            echo "  - Credentials: config/credstor.conf"
        fi
    fi
    
elif [[ "$db_type" == "sqlite" ]]; then
    print_step "Configuring for SQLite..."
    
    # Update config.yaml for SQLite
    if [[ -f "config/config.yaml" ]]; then
        python3 -c "
import yaml
try:
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f) or {}
    
    config.setdefault('database', {})
    config['database']['type'] = 'sqlite'
    config['database']['path'] = 'data/credstor.db'
    
    with open('config/config.yaml', 'w') as f:
        yaml.dump(config, f, default_flow_style=False, indent=2)
    
    print('✓ Configuration updated for SQLite')
except Exception as e:
    print(f'⚠ Could not update config.yaml: {e}')
"
    fi
    
    # Create a simple credentials file for SQLite (minimal validation requirements)
    print_step "Creating credentials file for SQLite..."
    mkdir -p config
    cat > config/credstor.conf << EOF
database:
  username: sqlite_user
  password: local_sqlite_database_access
  auth_token: ''
  created_at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF
    chmod 400 config/credstor.conf
    print_status "SQLite setup completed!"
    print_status "Database will be created at: data/credstor.db"
    
elif [[ "$db_type" == "postgresql" ]]; then
    print_error "Invalid database type: $db_type"
    exit 1
fi

# Test database connection
print_step "Testing database connection..."
export PYTHONPATH="$(pwd)/src:$PYTHONPATH"
python3 -c "
try:
    from src.database.connection import init_database
    init_database()
    print('✓ Database connection successful')
except Exception as e:
    print(f'⚠ Database connection test failed: {e}')
    print('  This is normal if PostgreSQL is not running or configured yet')
" 2>/dev/null || print_warning "Database will be initialized on first successful connection"

# Create CLI symlink
print_step "Setting up CLI command..."
if [[ ! -f ".venv/bin/credstor" ]]; then
    cat > .venv/bin/credstor << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
export PYTHONPATH="$PROJECT_DIR/src:$PYTHONPATH"
"$SCRIPT_DIR/python" "$PROJECT_DIR/src/cli/credstor.py" "$@"
EOF
    chmod +x .venv/bin/credstor
    print_status "CLI command 'credstor' created in virtual environment"
else
    print_status "CLI command already exists"
fi

echo ""
echo "🎉 CredStor setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Activate the virtual environment: source .venv/bin/activate"

if [[ "$db_type" == "postgresql" ]]; then
    echo "2. Database is configured for PostgreSQL"
    echo "   - Connection settings are in config/config.yaml"
    echo "   - Credentials are in config/credstor.conf (keep secure!)"
    echo "3. Run database migrations: python -m src.cli.credstor db migrate"
elif [[ "$db_type" == "sqlite" ]]; then
    echo "2. Database is configured for SQLite"
    echo "   - Database file will be created at: data/credstor.db"
    echo "3. Initialize master password: python -m src.cli.credstor init-auth"
fi

echo "4. Test the CLI: ./.venv/bin/credstor --help"
echo "5. Check system health: python -m src.cli.credstor health"
echo "6. Add your first credential: python -m src.cli.credstor add"
echo ""
echo "Security reminders:"
echo "- config/credstor.conf contains database credentials (0400 permissions)"
echo "- config/config.yaml contains configuration (keep secure)"
echo "- config/.encryption_key contains encryption key (keep very secure!)"
echo "- Never commit these files to version control"
echo "- Use strong passwords for database and master password"
echo ""
if [[ "$db_type" == "postgresql" ]]; then
    echo "PostgreSQL management commands:"
    echo "- Backup database: python -m src.cli.credstor db backup"
    echo "- View database stats: python -m src.cli.credstor db stats"
    echo "- Check migration status: python -m src.cli.credstor db status"
    echo ""
fi
print_status "Setup complete! Happy secure credential management! 🔐"