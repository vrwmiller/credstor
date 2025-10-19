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

from utils.config import load_config, get_config
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
    
    # Initialize database
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
    status = "[green]✓ Connected[/green]" if health_status["database_connected"] else "[red]✗ Failed[/red]"
    table.add_row("Database", status, "SQLite connection")
    
    # Tables existence
    status = "[green]✓ Present[/green]" if health_status["tables_exist"] else "[red]✗ Missing[/red]"
    table.add_row("Tables", status, "Database schema")
    
    # Encryption
    status = "[green]✓ Working[/green]" if health_status["encryption_working"] else "[red]✗ Failed[/red]"
    table.add_row("Encryption", status, "SQLCipher encryption")
    
    # Configuration
    try:
        config = get_config()
        status = "[green]✓ Loaded[/green]"
        details = f"Database: {config.database.type}"
    except Exception as e:
        status = "[red]✗ Failed[/red]"
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
        
        rprint(f"[green]✓ Credential added successfully[/green]")
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
            has_password = "✓" if credential.password_encrypted else "✗"
            has_token = "✓" if credential.api_token_encrypted else "✗"
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
        
        rprint(f"[green]✓ Credential deleted successfully[/green]")
        
        # Log the deletion
        log_audit_event("DELETE", f"Deleted credential {credential.property}", str(credential.id))
        
    except Exception as e:
        error_msg = f"Failed to delete credential: {e}"
        rprint(f"[red]Error: {error_msg}[/red]")
        log_audit_event("DELETE", f"Failed to delete credential {credential_id}", success=False, error=str(e))


if __name__ == '__main__':
    cli()