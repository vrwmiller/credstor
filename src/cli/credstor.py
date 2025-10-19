#!/usr/bin/env python3
"""
CredStor Command Line Interface

A secure command-line interface for managing credentials in the CredStor vault.
"""

import sys
import csv
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from getpass import getpass

import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import print as rprint

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config import load_config, get_config, create_database_credentials, verify_database_authentication
from database.connection import init_database, get_db, check_database_health
from database.models import Credential, AuditLog
from security.crypto import (
    get_encryption_key_from_config, encrypt_string, decrypt_string,
    SecureString, EncryptionError, DecryptionError
)
from utils.logging_config import setup_logging

# Console for rich output
console = Console()

# Global encryption key (loaded once per session)
_encryption_key: Optional[bytes] = None


def get_encryption_key() -> bytes:
    """Get or load the encryption key."""
    global _encryption_key
    
    if _encryption_key is None:
        try:
            _encryption_key = get_encryption_key_from_config()
        except Exception as e:
            rprint(f"[red]Error loading encryption key: {e}[/red]")
            sys.exit(1)
    
    return _encryption_key


def log_audit_event(event_type: str, description: str, credential_id: Optional[str] = None, success: bool = True, error: Optional[str] = None):
    """Log an audit event."""
    try:
        with get_db() as db:
            audit_log = AuditLog(
                event_type=event_type,
                event_description=description,
                credential_id=credential_id,
                success=success,
                error_message=error
            )
            db.add(audit_log)
            db.commit()
    except Exception as e:
        logging.error(f"Failed to log audit event: {e}")


def encrypt_credential_fields(credential_data: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypt sensitive fields in credential data."""
    key = get_encryption_key()
    encrypted_data = credential_data.copy()
    
    # Fields that should be encrypted
    sensitive_fields = ['password', 'api_token', 'public_key', 'private_key', 'notes']
    
    for field in sensitive_fields:
        if field in credential_data and credential_data[field]:
            try:
                encrypted_value = encrypt_string(credential_data[field], key)
                encrypted_data[f"{field}_encrypted"] = encrypted_value.encode('utf-8')
            except EncryptionError as e:
                rprint(f"[red]Error encrypting {field}: {e}[/red]")
                return {}
    
    # Remove plain text sensitive fields
    for field in sensitive_fields:
        if field in encrypted_data:
            del encrypted_data[field]
    
    return encrypted_data


def decrypt_credential_fields(credential: Credential) -> Dict[str, Any]:
    """Decrypt sensitive fields from credential object."""
    key = get_encryption_key()
    decrypted_data = {
        'id': str(credential.id),
        'property': credential.property,
        'username': credential.username,
        'created_at': credential.created_at,
        'updated_at': credential.updated_at,
        'last_accessed': credential.last_accessed
    }
    
    # Fields that should be decrypted
    encrypted_fields = {
        'password_encrypted': 'password',
        'api_token_encrypted': 'api_token',
        'public_key_encrypted': 'public_key',
        'private_key_encrypted': 'private_key',
        'notes_encrypted': 'notes'
    }
    
    for encrypted_field, plain_field in encrypted_fields.items():
        encrypted_value = getattr(credential, encrypted_field, None)
        if encrypted_value:
            try:
                decrypted_value = decrypt_string(encrypted_value.decode('utf-8'), key)
                decrypted_data[plain_field] = decrypted_value
            except DecryptionError as e:
                rprint(f"[yellow]Warning: Could not decrypt {plain_field}: {e}[/yellow]")
                decrypted_data[plain_field] = "[ENCRYPTED]"
        else:
            decrypted_data[plain_field] = None
    
    return decrypted_data


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, config, verbose):
    """CredStor - Secure Personal Credential Vault"""
    
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(level=log_level)
    
    # Load configuration
    try:
        if config:
            load_config(Path(config))
        else:
            load_config()
    except Exception as e:
        rprint(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)
    
    # Initialize database (skip for init-auth command)
    if ctx.invoked_subcommand != 'init-auth':
        try:
            init_database()
        except Exception as e:
            rprint(f"[red]Error initializing database: {e}[/red]")
            sys.exit(1)
    
    # Store context
    ctx.ensure_object(dict)


@cli.command()
def health():
    """Check system health and connectivity."""
    rprint("[blue]Checking CredStor system health...[/blue]")
    
    health_status = check_database_health()
    
    table = Table(title="System Health Check")
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Details")
    
    # Database connectivity
    try:
        config = get_config()
        db_type = config.database.type.lower()
        if db_type == "sqlite":
            connection_details = "Local database connection"
        elif db_type == "postgresql":
            connection_details = "PostgreSQL server connection"
        else:
            connection_details = f"{db_type.upper()} connection"
    except:
        connection_details = "Database connection"
    
    status = "[green]✓ Connected[/green]" if health_status["database_connected"] else "[red]✗ Failed[/red]"
    table.add_row("Database", status, connection_details)
    
    # Tables existence
    status = "[green]✓ Present[/green]" if health_status["tables_exist"] else "[red]✗ Missing[/red]"
    table.add_row("Tables", status, "Database schema")
    
    # Authentication
    auth_working = health_status.get("authentication_working", True)  # Default to True for backward compatibility
    status = "[green]✓ Working[/green]" if auth_working else "[red]✗ Failed[/red]"
    table.add_row("Authentication", status, "Database authentication")
    
    # Application-level encryption
    status = "[green]✓ Working[/green]" if health_status["encryption_working"] else "[red]✗ Failed[/red]"
    table.add_row("Data Encryption", status, "Application-level encryption")
    
    # Configuration
    try:
        config = get_config()
        status = "[green]OK Loaded[/green]"
        details = f"Database: {config.database.type}"
    except Exception as e:
        status = "[red]X Failed[/red]"
        details = str(e)
    
    table.add_row("Configuration", status, details)
    
    console.print(table)
    
    if health_status["error"]:
        rprint(f"[red]Error details: {health_status['error']}[/red]")
    
    # Log health check
    log_audit_event("HEALTH_CHECK", "System health check performed", success=not health_status["error"])


@cli.command()
@click.option('--property', '-p', required=True, help='Property/website name')
@click.option('--username', '-u', required=True, help='Username')
@click.option('--password', prompt=True, hide_input=True, help='Password')
@click.option('--api-token', help='API token')
@click.option('--public-key', help='Public key')
@click.option('--private-key', help='Private key')
@click.option('--notes', help='Additional notes')
def add(property, username, password, api_token, public_key, private_key, notes):
    """Add a new credential to the vault."""
    
    try:
        # Prepare credential data
        credential_data = {
            'property': property,
            'username': username,
            'password': password
        }
        
        if api_token:
            credential_data['api_token'] = api_token
        if public_key:
            credential_data['public_key'] = public_key
        if private_key:
            credential_data['private_key'] = private_key
        if notes:
            credential_data['notes'] = notes
        
        # Encrypt sensitive fields
        encrypted_data = encrypt_credential_fields(credential_data)
        if not encrypted_data:
            rprint("[red]Failed to encrypt credential data[/red]")
            return
        
        # Create credential object
        credential = Credential(
            property=property,
            username=username,
            **{k: v for k, v in encrypted_data.items() if k.endswith('_encrypted')}
        )
        
        # Save to database
        with get_db() as db:
            db.add(credential)
            db.commit()
            db.refresh(credential)
        
        rprint(f"[green]Credential added successfully[/green]")
        rprint(f"ID: {credential.id}")
        rprint(f"Property: {property}")
        rprint(f"Username: {username}")
        
        # Log the event
        log_audit_event("CREATE", f"Added credential for {property}", str(credential.id))
        
    except Exception as e:
        error_msg = f"Failed to add credential: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("CREATE", f"Failed to add credential for {property}", success=False, error=str(e))


@cli.command()
@click.option('--property', '-p', help='Filter by property/website')
@click.option('--username', '-u', help='Filter by username')
@click.option('--limit', '-l', default=50, help='Maximum number of results')
def search(property, username, limit):
    """Search for credentials."""
    
    try:
        with get_db() as db:
            query = db.query(Credential).filter(Credential.is_active == True)
            
            if property:
                query = query.filter(Credential.property.ilike(f"%{property}%"))
            
            if username:
                query = query.filter(Credential.username.ilike(f"%{username}%"))
            
            credentials = query.limit(limit).all()
        
        if not credentials:
            rprint("[yellow]No credentials found matching the criteria[/yellow]")
            return
        
        # Create results table
        table = Table(title=f"Search Results ({len(credentials)} found)")
        table.add_column("ID", style="dim", width=8)
        table.add_column("Property", style="cyan", no_wrap=True)
        table.add_column("Username", style="green")
        table.add_column("Has Password", style="yellow", justify="center")
        table.add_column("Has API Token", style="blue", justify="center")
        table.add_column("Created", style="dim")
        
        for credential in credentials:
            # Only show metadata, not actual secrets
            has_password = "Yes" if credential.password_encrypted else "No"
            has_token = "Yes" if credential.api_token_encrypted else "No"
            created = credential.created_at.strftime("%Y-%m-%d") if credential.created_at else "Unknown"
            
            table.add_row(
                str(credential.id)[:8],  # Short ID
                credential.property,
                credential.username,
                has_password,
                has_token,
                created
            )
        
        console.print(table)
        
        # Log the search
        search_terms = []
        if property:
            search_terms.append(f"property:{property}")
        if username:
            search_terms.append(f"username:{username}")
        
        log_audit_event("SEARCH", f"Searched credentials: {', '.join(search_terms) if search_terms else 'all'}")
        
    except Exception as e:
        error_msg = f"Search failed: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("SEARCH", "Credential search failed", success=False, error=str(e))


@cli.command()
@click.argument('credential_id')
@click.option('--show-secrets', is_flag=True, help='Show decrypted secrets (WARNING: will display on screen)')
def show(credential_id, show_secrets):
    """Show details of a specific credential."""
    
    try:
        with get_db() as db:
            credential = db.query(Credential).filter(
                Credential.id == credential_id,
                Credential.is_active == True
            ).first()
        
        if not credential:
            rprint(f"[red]Credential not found: {credential_id}[/red]")
            return
        
        # Update last accessed time
        with get_db() as db:
            credential.last_accessed = db.execute("SELECT CURRENT_TIMESTAMP").scalar()
            db.commit()
        
        # Display credential information
        rprint(f"\n[bold]Credential Details[/bold]")
        rprint(f"ID: {credential.id}")
        rprint(f"Property: {credential.property}")
        rprint(f"Username: {credential.username}")
        rprint(f"Created: {credential.created_at}")
        rprint(f"Updated: {credential.updated_at}")
        rprint(f"Last Accessed: {credential.last_accessed}")
        
        if show_secrets:
            # Decrypt and show sensitive data
            if not Confirm.ask("[yellow]This will display decrypted secrets on screen. Continue?[/yellow]"):
                return
            
            decrypted_data = decrypt_credential_fields(credential)
            
            rprint("\n[bold red]SENSITIVE DATA (handle with care):[/bold red]")
            
            if decrypted_data.get('password'):
                rprint(f"Password: {decrypted_data['password']}")
            
            if decrypted_data.get('api_token'):
                rprint(f"API Token: {decrypted_data['api_token']}")
            
            if decrypted_data.get('public_key'):
                rprint(f"Public Key: {decrypted_data['public_key'][:50]}...")
            
            if decrypted_data.get('private_key'):
                rprint(f"Private Key: [REDACTED - {len(decrypted_data['private_key'])} chars]")
            
            if decrypted_data.get('notes'):
                rprint(f"Notes: {decrypted_data['notes']}")
        else:
            rprint("\n[dim]Use --show-secrets to display decrypted data[/dim]")
        
        # Log the access
        log_audit_event("READ", f"Viewed credential {credential.property}", str(credential.id))
        
    except Exception as e:
        error_msg = f"Failed to show credential: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("READ", f"Failed to view credential {credential_id}", success=False, error=str(e))


@cli.command()
@click.option('--file', '-f', required=True, type=click.Path(exists=True), help='CSV file to import')
@click.option('--separator', '-s', default=',', help='CSV separator character')
@click.option('--dry-run', is_flag=True, help='Show what would be imported without saving')
def import_csv(file, separator, dry_run):
    """Import credentials from CSV file."""
    
    try:
        config = get_config()
        csv_config = config.csv_import
        
        imported_count = 0
        error_count = 0
        
        rprint(f"[blue]{'Previewing' if dry_run else 'Importing'} credentials from {file}...[/blue]")
        
        with open(file, 'r', encoding=csv_config.default_encoding) as csvfile:
            # Detect CSV format
            sniffer = csv.Sniffer()
            sample = csvfile.read(1024)
            csvfile.seek(0)
            
            try:
                dialect = sniffer.sniff(sample, delimiters=separator)
            except csv.Error:
                # Use default dialect
                dialect = csv.excel
                dialect.delimiter = separator
            
            reader = csv.DictReader(csvfile, dialect=dialect)
            
            # Validate headers
            required_fields = ['property', 'username', 'password']
            missing_fields = [field for field in required_fields if field not in reader.fieldnames]
            
            if missing_fields:
                rprint(f"[red]Missing required fields in CSV: {missing_fields}[/red]")
                rprint(f"Available fields: {reader.fieldnames}")
                return
            
            # Process rows
            for row_num, row in enumerate(reader, 1):
                try:
                    # Skip empty rows
                    if csv_config.skip_empty_rows and not any(row.values()):
                        continue
                    
                    # Validate required fields
                    if csv_config.validate_fields:
                        missing = [field for field in required_fields if not row.get(field)]
                        if missing:
                            rprint(f"[yellow]Row {row_num}: Missing required fields {missing}, skipping[/yellow]")
                            error_count += 1
                            continue
                    
                    # Prepare credential data
                    credential_data = {
                        'property': row['property'].strip(),
                        'username': row['username'].strip(),
                        'password': row['password']
                    }
                    
                    # Add optional fields
                    optional_fields = ['api_token', 'public_key', 'private_key', 'notes']
                    for field in optional_fields:
                        if field in row and row[field]:
                            credential_data[field] = row[field]
                    
                    if dry_run:
                        # Just preview
                        rprint(f"Row {row_num}: {credential_data['property']} - {credential_data['username']}")
                    else:
                        # Check for duplicates
                        with get_db() as db:
                            existing = db.query(Credential).filter(
                                Credential.property == credential_data['property'],
                                Credential.username == credential_data['username'],
                                Credential.is_active == True
                            ).first()
                            
                            if existing:
                                rprint(f"[yellow]Row {row_num}: Duplicate found for {credential_data['property']} - {credential_data['username']}, skipping[/yellow]")
                                error_count += 1
                                continue
                        
                        # Encrypt and save
                        encrypted_data = encrypt_credential_fields(credential_data)
                        if not encrypted_data:
                            rprint(f"[red]Row {row_num}: Encryption failed, skipping[/red]")
                            error_count += 1
                            continue
                        
                        credential = Credential(
                            property=credential_data['property'],
                            username=credential_data['username'],
                            **{k: v for k, v in encrypted_data.items() if k.endswith('_encrypted')}
                        )
                        
                        with get_db() as db:
                            db.add(credential)
                            db.commit()
                        
                        rprint(f"[green]Row {row_num}: Imported {credential_data['property']} - {credential_data['username']}[/green]")
                    
                    imported_count += 1
                    
                except Exception as e:
                    rprint(f"[red]Row {row_num}: Error processing row: {e}[/red]")
                    error_count += 1
        
        # Summary
        if dry_run:
            rprint(f"\n[blue]Preview complete:[/blue]")
            rprint(f"  Would import: {imported_count} credentials")
            rprint(f"  Errors/skipped: {error_count}")
            rprint("Use without --dry-run to actually import")
        else:
            rprint(f"\n[green]Import complete:[/green]")
            rprint(f"  Imported: {imported_count} credentials")
            rprint(f"  Errors/skipped: {error_count}")
            
            # Log the import
            log_audit_event("IMPORT", f"Imported {imported_count} credentials from CSV ({error_count} errors)")
        
    except Exception as e:
        error_msg = f"Import failed: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("IMPORT", "CSV import failed", success=False, error=str(e))


@cli.command()
@click.argument('credential_id')
def delete(credential_id):
    """Delete a credential (soft delete)."""
    
    try:
        with get_db() as db:
            credential = db.query(Credential).filter(
                Credential.id == credential_id,
                Credential.is_active == True
            ).first()
        
        if not credential:
            rprint(f"[red]Credential not found: {credential_id}[/red]")
            return
        
        # Confirm deletion
        rprint(f"Credential to delete:")
        rprint(f"  Property: {credential.property}")
        rprint(f"  Username: {credential.username}")
        
        if not Confirm.ask("[red]Are you sure you want to delete this credential?[/red]"):
            rprint("Deletion cancelled")
            return
        
        # Soft delete
        with get_db() as db:
            credential.is_active = False
            db.commit()
        
        rprint(f"[green]Credential deleted successfully[/green]")
        
        # Log the deletion
        log_audit_event("DELETE", f"Deleted credential {credential.property}", str(credential.id))
        
    except Exception as e:
        error_msg = f"Failed to delete credential: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("DELETE", f"Failed to delete credential {credential_id}", success=False, error=str(e))


@cli.command("init-auth")
def init_auth():
    """Initialize database authentication credentials."""
    rprint("[bold]Database Authentication Setup[/bold]")
    rprint("This will create or update database credentials in credstor.conf")
    rprint("")
    
    try:
        # Check if credentials already exist
        if verify_database_authentication():
            if not Confirm.ask("Database authentication is already configured. Update credentials?"):
                rprint("[yellow]Authentication setup cancelled.[/yellow]")
                return
        
        # Prompt for credentials
        rprint("[blue]Please provide database credentials:[/blue]")
        username = Prompt.ask("Database username")
        
        if not username:
            rprint("[red]Error: Username is required[/red]")
            return
        
        password = getpass("Database password: ")
        if not password:
            rprint("[red]Error: Password is required[/red]")
            return
        
        # Create credentials
        create_database_credentials(username, password)
        
        rprint("[green]Database authentication configured successfully![/green]")
        rprint("[yellow]Note: credstor.conf has been created with secure permissions (400)[/yellow]")
        
    except Exception as e:
        rprint(f"[red]Error setting up authentication: {e}[/red]")
        sys.exit(1)


@cli.group("db")
def database_commands():
    """Database management commands."""
    pass


@database_commands.command("migrate")
@click.option('--dry-run', is_flag=True, help='Show what migrations would be applied without applying them')
def migrate_cmd(dry_run):
    """Apply pending database migrations."""
    from ..database.migrations import migration_manager
    
    try:
        rprint("[bold]Database Migration[/bold]")
        
        # Check current status
        status = migration_manager.get_migration_status()
        
        if not status["integrity_valid"]:
            rprint("[red]❌ Migration integrity check failed - aborting[/red]")
            return
        
        if status["pending_count"] == 0:
            rprint("[green]✅ Database is up to date - no pending migrations[/green]")
            return
        
        rprint(f"[blue]Database type: {status['database_type']}[/blue]")
        rprint(f"[yellow]Found {status['pending_count']} pending migrations:[/yellow]")
        
        pending_migrations = migration_manager.get_pending_migrations()
        for migration in pending_migrations:
            rprint(f"  • {migration.version}: {migration.description}")
        
        if dry_run:
            rprint("\n[blue]Dry run complete - no changes made[/blue]")
            return
        
        if not Confirm.ask("\n[yellow]Apply these migrations?[/yellow]"):
            rprint("Migration cancelled")
            return
        
        # Apply migrations
        rprint("\n[blue]Applying migrations...[/blue]")
        success = migration_manager.migrate()
        
        if success:
            rprint("[green]✅ All migrations applied successfully[/green]")
            log_audit_event("MIGRATION", f"Applied {status['pending_count']} database migrations")
        else:
            rprint("[red]❌ Migration failed - check logs for details[/red]")
            log_audit_event("MIGRATION", "Database migration failed", success=False)
        
    except Exception as e:
        error_msg = f"Migration command failed: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("MIGRATION", "Migration command failed", success=False, error=str(e))


@database_commands.command("status")
def migration_status():
    """Show current migration status."""
    from ..database.migrations import migration_manager
    
    try:
        status = migration_manager.get_migration_status()
        
        rprint("[bold]Database Migration Status[/bold]")
        
        table = Table(title="Migration Information")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")
        
        table.add_row("Database Type", status["database_type"])
        table.add_row("Applied Migrations", str(status["applied_count"]))
        table.add_row("Pending Migrations", str(status["pending_count"]))
        table.add_row("Integrity Valid", "✅ Yes" if status["integrity_valid"] else "❌ No")
        
        console.print(table)
        
        if status["applied_versions"]:
            rprint("\n[bold]Applied Migrations:[/bold]")
            for version in status["applied_versions"]:
                rprint(f"  ✅ {version}")
        
        if status["pending_versions"]:
            rprint("\n[bold]Pending Migrations:[/bold]")
            for version in status["pending_versions"]:
                rprint(f"  📋 {version}")
        
        if not status["integrity_valid"]:
            rprint("\n[red]⚠️  Migration integrity check failed![/red]")
            rprint("[red]This indicates that applied migrations have been modified.[/red]")
            rprint("[red]Please verify your migration files and database state.[/red]")
        
    except Exception as e:
        error_msg = f"Failed to get migration status: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")


@database_commands.command("rollback")
@click.argument('version')
@click.option('--force', is_flag=True, help='Force rollback without confirmation')
def rollback_cmd(version, force):
    """Rollback a specific migration."""
    from ..database.migrations import migration_manager
    
    try:
        rprint(f"[bold]Rollback Migration {version}[/bold]")
        
        # Find the migration
        migration = next((m for m in migration_manager.migrations if m.version == version), None)
        if not migration:
            rprint(f"[red]❌ Migration {version} not found[/red]")
            return
        
        # Check if it's applied
        applied_versions = migration_manager.get_applied_migrations()
        if version not in applied_versions:
            rprint(f"[yellow]⚠️  Migration {version} is not currently applied[/yellow]")
            return
        
        rprint(f"[yellow]Migration to rollback:[/yellow]")
        rprint(f"  Version: {migration.version}")
        rprint(f"  Description: {migration.description}")
        
        if not force:
            rprint("\n[red]⚠️  WARNING: Rolling back migrations can cause data loss![/red]")
            if not Confirm.ask("[red]Are you sure you want to proceed?[/red]"):
                rprint("Rollback cancelled")
                return
        
        # Perform rollback
        rprint(f"\n[blue]Rolling back migration {version}...[/blue]")
        success = migration_manager.rollback_migration(version)
        
        if success:
            rprint(f"[green]✅ Migration {version} rolled back successfully[/green]")
            log_audit_event("MIGRATION_ROLLBACK", f"Rolled back migration {version}")
        else:
            rprint(f"[red]❌ Rollback failed - check logs for details[/red]")
            log_audit_event("MIGRATION_ROLLBACK", f"Failed to rollback migration {version}", success=False)
        
    except Exception as e:
        error_msg = f"Rollback command failed: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("MIGRATION_ROLLBACK", f"Rollback command failed for {version}", success=False, error=str(e))


@database_commands.command("backup")
@click.option('--file', '-f', required=True, type=click.Path(), help='Backup file path')
@click.option('--include-deleted', is_flag=True, help='Include soft-deleted credentials in backup')
def backup_db(file, include_deleted):
    """Create a backup of the database."""
    import json
    from datetime import datetime
    
    try:
        config = get_config()
        backup_data = {
            "metadata": {
                "created_at": datetime.utcnow().isoformat(),
                "database_type": config.database.type,
                "version": "1.0",
                "include_deleted": include_deleted
            },
            "credentials": [],
            "audit_logs": [],
            "security_events": []
        }
        
        rprint(f"[blue]Creating backup to {file}...[/blue]")
        
        # Backup credentials
        with get_db() as db:
            query = db.query(Credential)
            if not include_deleted:
                query = query.filter(Credential.is_active == True)
            
            credentials = query.all()
            
            for credential in credentials:
                # Decrypt fields for backup
                decrypted_data = decrypt_credential_fields(credential)
                backup_data["credentials"].append(decrypted_data)
            
            # Backup audit logs (last 1000 entries)
            audit_logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(1000).all()
            for log in audit_logs:
                backup_data["audit_logs"].append({
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "event_type": log.event_type,
                    "event_description": log.event_description,
                    "credential_id": str(log.credential_id) if log.credential_id else None,
                    "success": log.success,
                    "error_message": log.error_message
                })
        
        # Write backup file
        with open(file, 'w') as f:
            json.dump(backup_data, f, indent=2, default=str)
        
        # Set secure permissions
        import os
        os.chmod(file, 0o600)
        
        rprint(f"[green]✅ Backup created successfully[/green]")
        rprint(f"  Credentials: {len(backup_data['credentials'])}")
        rprint(f"  Audit logs: {len(backup_data['audit_logs'])}")
        rprint(f"  File: {file}")
        
        log_audit_event("BACKUP", f"Database backup created: {file}")
        
    except Exception as e:
        error_msg = f"Backup failed: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("BACKUP", "Database backup failed", success=False, error=str(e))


@database_commands.command("restore")
@click.option('--file', '-f', required=True, type=click.Path(exists=True), help='Backup file to restore')
@click.option('--force', is_flag=True, help='Force restore without confirmation')
@click.option('--clear-existing', is_flag=True, help='Clear existing data before restore')
def restore_db(file, force, clear_existing):
    """Restore database from backup file."""
    import json
    
    try:
        rprint(f"[blue]Loading backup from {file}...[/blue]")
        
        # Load backup data
        with open(file, 'r') as f:
            backup_data = json.load(f)
        
        # Validate backup format
        required_keys = ["metadata", "credentials"]
        if not all(key in backup_data for key in required_keys):
            rprint("[red]❌ Invalid backup file format[/red]")
            return
        
        metadata = backup_data["metadata"]
        credentials_count = len(backup_data["credentials"])
        
        rprint(f"[yellow]Backup Information:[/yellow]")
        rprint(f"  Created: {metadata.get('created_at', 'Unknown')}")
        rprint(f"  Database type: {metadata.get('database_type', 'Unknown')}")
        rprint(f"  Credentials: {credentials_count}")
        rprint(f"  Include deleted: {metadata.get('include_deleted', False)}")
        
        if not force:
            if clear_existing:
                rprint("\n[red]⚠️  WARNING: This will delete all existing data![/red]")
            else:
                rprint("\n[yellow]⚠️  This will add to existing data (duplicates may occur)[/yellow]")
            
            if not Confirm.ask("[yellow]Continue with restore?[/yellow]"):
                rprint("Restore cancelled")
                return
        
        # Clear existing data if requested
        if clear_existing:
            rprint("[blue]Clearing existing data...[/blue]")
            with get_db() as db:
                db.query(Credential).delete()
                db.commit()
        
        # Restore credentials
        rprint("[blue]Restoring credentials...[/blue]")
        restored_count = 0
        error_count = 0
        
        for cred_data in backup_data["credentials"]:
            try:
                # Prepare credential data
                credential_data = {
                    'property': cred_data['property'],
                    'username': cred_data['username'],
                    'password': cred_data.get('password', ''),
                    'api_token': cred_data.get('api_token'),
                    'public_key': cred_data.get('public_key'),
                    'private_key': cred_data.get('private_key'),
                    'notes': cred_data.get('notes')
                }
                
                # Remove None values
                credential_data = {k: v for k, v in credential_data.items() if v is not None}
                
                # Check for duplicates unless clearing existing data
                if not clear_existing:
                    with get_db() as db:
                        existing = db.query(Credential).filter(
                            Credential.property == credential_data['property'],
                            Credential.username == credential_data['username'],
                            Credential.is_active == True
                        ).first()
                        
                        if existing:
                            error_count += 1
                            continue
                
                # Encrypt and save
                encrypted_data = encrypt_credential_fields(credential_data)
                if not encrypted_data:
                    error_count += 1
                    continue
                
                credential = Credential(
                    property=credential_data['property'],
                    username=credential_data['username'],
                    **{k: v for k, v in encrypted_data.items() if k.endswith('_encrypted')}
                )
                
                with get_db() as db:
                    db.add(credential)
                    db.commit()
                
                restored_count += 1
                
            except Exception as e:
                rprint(f"[red]Failed to restore credential {cred_data.get('property', 'unknown')}: {e}[/red]")
                error_count += 1
        
        rprint(f"\n[green]✅ Restore completed[/green]")
        rprint(f"  Restored: {restored_count} credentials")
        rprint(f"  Errors/skipped: {error_count}")
        
        log_audit_event("RESTORE", f"Database restored from {file}: {restored_count} credentials")
        
    except Exception as e:
        error_msg = f"Restore failed: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("RESTORE", "Database restore failed", success=False, error=str(e))


@database_commands.command("stats")
def database_stats():
    """Show database statistics."""
    try:
        rprint("[bold]Database Statistics[/bold]")
        
        with get_db() as db:
            # Credential statistics
            total_credentials = db.query(Credential).count()
            active_credentials = db.query(Credential).filter(Credential.is_active == True).count()
            deleted_credentials = total_credentials - active_credentials
            
            # Recent activity
            from datetime import datetime, timedelta
            last_week = datetime.utcnow() - timedelta(days=7)
            recent_credentials = db.query(Credential).filter(
                Credential.created_at >= last_week,
                Credential.is_active == True
            ).count()
            
            # Audit statistics
            total_audit_logs = db.query(AuditLog).count()
            recent_audit_logs = db.query(AuditLog).filter(
                AuditLog.timestamp >= last_week
            ).count()
            
            # Most common event types
            from sqlalchemy import func, text
            event_stats = db.execute(text("""
                SELECT event_type, COUNT(*) as count 
                FROM audit_log 
                GROUP BY event_type 
                ORDER BY count DESC 
                LIMIT 5
            """)).fetchall()
        
        # Display statistics
        table = Table(title="Database Statistics")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green", justify="right")
        
        table.add_row("Total Credentials", str(total_credentials))
        table.add_row("Active Credentials", str(active_credentials))
        table.add_row("Deleted Credentials", str(deleted_credentials))
        table.add_row("Recent Credentials (7 days)", str(recent_credentials))
        table.add_row("Total Audit Logs", str(total_audit_logs))
        table.add_row("Recent Audit Logs (7 days)", str(recent_audit_logs))
        
        console.print(table)
        
        # Event type statistics
        if event_stats:
            rprint("\n[bold]Most Common Events:[/bold]")
            event_table = Table()
            event_table.add_column("Event Type", style="cyan")
            event_table.add_column("Count", style="green", justify="right")
            
            for event_type, count in event_stats:
                event_table.add_row(event_type, str(count))
            
            console.print(event_table)
        
        # Database configuration
        config = get_config()
        rprint(f"\n[bold]Configuration:[/bold]")
        rprint(f"  Database Type: {config.database.type}")
        if config.database.type == "postgresql":
            rprint(f"  Host: {config.database.host}")
            rprint(f"  Port: {config.database.port}")
            rprint(f"  Database: {config.database.name}")
        else:
            rprint(f"  Path: {config.database.path}")
        
        log_audit_event("STATS", "Database statistics viewed")
        
    except Exception as e:
        error_msg = f"Failed to get database statistics: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")


if __name__ == '__main__':
    cli()