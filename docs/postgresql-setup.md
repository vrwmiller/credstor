# PostgreSQL Setup Guide for CredStor

This guide provides detailed instructions for setting up PostgreSQL as the database backend for CredStor.

## Prerequisites

- CredStor application installed
- Administrative access to install PostgreSQL
- Basic familiarity with command line operations

## Installation

### macOS (Homebrew)

```bash
# Install PostgreSQL
brew install postgresql

# Start PostgreSQL service
brew services start postgresql

# Verify installation
psql --version
```

### Ubuntu/Debian

```bash
# Update package list
sudo apt update

# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Start and enable PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Verify installation
psql --version
```

### CentOS/RHEL/Fedora

```bash
# Install PostgreSQL
sudo dnf install postgresql-server postgresql-contrib  # Fedora
# sudo yum install postgresql-server postgresql-contrib  # CentOS/RHEL

# Initialize database
sudo postgresql-setup initdb

# Start and enable service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Verify installation
psql --version
```

### Windows

1. Download PostgreSQL installer from https://www.postgresql.org/download/windows/
2. Run the installer and follow the setup wizard
3. Remember the superuser password you set during installation
4. Add PostgreSQL bin directory to your PATH

## Database Configuration

### 1. Create CredStor Database

```bash
# Connect to PostgreSQL as superuser
sudo -u postgres psql

# Or on macOS with Homebrew:
psql postgres
```

### 2. Set Up Database and User

```sql
-- Create the database
CREATE DATABASE credstor;

-- Create a dedicated user
CREATE USER credstor_user WITH PASSWORD 'your_secure_password_here';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE credstor TO credstor_user;

-- Grant schema creation privileges
GRANT CREATE ON DATABASE credstor TO credstor_user;

-- Exit psql
\q
```

### 3. Configure PostgreSQL Authentication

Edit the PostgreSQL configuration file to allow connections:

#### Find Configuration Files

```bash
# Find postgresql.conf location
sudo -u postgres psql -c "SHOW config_file;"

# Find pg_hba.conf location
sudo -u postgres psql -c "SHOW hba_file;"
```

#### Edit postgresql.conf

```bash
# Edit postgresql.conf (adjust path based on your system)
sudo nano /etc/postgresql/14/main/postgresql.conf
```

Ensure these settings are configured:

```ini
# Connection settings
listen_addresses = 'localhost'
port = 5432

# Memory settings (adjust based on your system)
shared_buffers = 128MB
effective_cache_size = 256MB
```

#### Edit pg_hba.conf

```bash
# Edit pg_hba.conf (adjust path based on your system)
sudo nano /etc/postgresql/14/main/pg_hba.conf
```

Add or modify the following line for local connections:

```ini
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   credstor        credstor_user                           md5
host    credstor        credstor_user   127.0.0.1/32            md5
host    credstor        credstor_user   ::1/128                 md5
```

### 4. Restart PostgreSQL

```bash
# Ubuntu/Debian
sudo systemctl restart postgresql

# macOS (Homebrew)
brew services restart postgresql

# CentOS/RHEL/Fedora
sudo systemctl restart postgresql
```

### 5. Test Connection

```bash
# Test connection with the new user
psql -h localhost -U credstor_user -d credstor

# Enter the password when prompted
# If successful, you should see the PostgreSQL prompt
```

## CredStor Configuration

### 1. Initialize Database Authentication

```bash
# Navigate to CredStor directory
cd /path/to/credstor

# Activate virtual environment
source venv/bin/activate

# Initialize database authentication
python -m src.cli.credstor init-auth
```

When prompted, enter:
- **Database host**: `localhost`
- **Database port**: `5432` (default)
- **Database name**: `credstor`
- **Username**: `credstor_user`
- **Password**: The password you set earlier

### 2. Verify Configuration

```bash
# Check system health
python -m src.cli.credstor health
```

You should see output indicating successful database connection and table creation.

## Security Considerations

### Database Security

1. **Strong Password**: Use a strong, unique password for the `credstor_user`
2. **Limited Privileges**: The user only has access to the `credstor` database
3. **Local Access Only**: PostgreSQL is configured for local connections only
4. **Authentication Required**: All connections require password authentication

### File Permissions

The database credentials are stored in `~/.credstor/credstor.conf` with restricted permissions (0400):

```bash
# Verify file permissions
ls -la ~/.credstor/credstor.conf
# Should show: -r-------- 1 username username
```

### Backup and Recovery

#### Create Backup

```bash
# Create encrypted backup
pg_dump -h localhost -U credstor_user -d credstor > credstor_backup.sql

# Or create compressed backup
pg_dump -h localhost -U credstor_user -d credstor | gzip > credstor_backup.sql.gz
```

#### Restore from Backup

```bash
# Restore from backup
psql -h localhost -U credstor_user -d credstor < credstor_backup.sql

# Or restore from compressed backup
gunzip -c credstor_backup.sql.gz | psql -h localhost -U credstor_user -d credstor
```

## Troubleshooting

### Connection Issues

1. **Service Not Running**:
   ```bash
   sudo systemctl status postgresql
   sudo systemctl start postgresql
   ```

2. **Authentication Failed**:
   - Verify user credentials
   - Check pg_hba.conf configuration
   - Ensure password is correct

3. **Permission Denied**:
   - Verify user has correct privileges
   - Check database ownership

### Performance Tuning

For better performance with larger datasets:

```sql
-- Connect as superuser and tune PostgreSQL
-- Adjust based on your system resources

ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET checkpoint_completion_target = 0.9;

-- Reload configuration
SELECT pg_reload_conf();
```

### Monitoring

Monitor PostgreSQL performance:

```sql
-- Check active connections
SELECT count(*) as active_connections FROM pg_stat_activity WHERE state = 'active';

-- Check database size
SELECT pg_size_pretty(pg_database_size('credstor')) as database_size;

-- Check table sizes
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

## Migration from SQLite

If you're migrating from SQLite to PostgreSQL:

1. **Export data from SQLite**:
   ```bash
   python -m src.cli.credstor export --file export.csv
   ```

2. **Set up PostgreSQL** (follow this guide)

3. **Import data to PostgreSQL**:
   ```bash
   python -m src.cli.credstor import-csv --file export.csv
   ```

4. **Verify data integrity**:
   ```bash
   python -m src.cli.credstor list
   ```

## Support

For additional help:
- PostgreSQL Documentation: https://www.postgresql.org/docs/
- CredStor Issues: Check the project repository for known issues
- Community Support: PostgreSQL community forums and mailing lists