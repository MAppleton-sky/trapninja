#!/usr/bin/env python3
"""
TrapNinja CLI - SNMPv3 Commands

Commands for managing SNMPv3 user credentials.
"""
import sys
import getpass
from typing import List

try:
    from ..snmpv3_credentials import get_credential_store, SNMPv3User
    CREDENTIALS_AVAILABLE = True
except ImportError as e:
    CREDENTIALS_AVAILABLE = False
    credentials_error = str(e)

try:
    from ..snmpv3_decryption import initialize_snmpv3_decryptor
    DECRYPTION_AVAILABLE = True
except ImportError as e:
    DECRYPTION_AVAILABLE = False
    decryption_error = str(e)


def check_dependencies() -> bool:
    """
    Check if SNMPv3 dependencies are available
    
    Returns:
        bool: True if available, False otherwise
    """
    if not CREDENTIALS_AVAILABLE:
        print("✗ Error: SNMPv3 credential module not available")
        print(f"  Details: {credentials_error}")
        print("\nPlease install required dependencies:")
        print("  pip3 install --break-system-packages cryptography")
        return False
    
    return True


def check_decryption_dependencies() -> bool:
    """
    Check if SNMPv3 decryption dependencies are available
    
    Returns:
        bool: True if available, False otherwise
    """
    if not DECRYPTION_AVAILABLE:
        print("✗ Error: SNMPv3 decryption module not available")
        print(f"  Details: {decryption_error}")
        print("\nPlease install required dependencies:")
        print("  pip3 install --break-system-packages pysnmp pyasn1")
        return False
    
    return True


def handle_snmpv3_add_user(args) -> int:
    """
    Add SNMPv3 user credentials
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    if not check_dependencies():
        return 1
    
    try:
        credential_store = get_credential_store()
        
        # Get credentials
        username = args.username
        engine_id = args.engine_id
        
        # Authentication
        auth_protocol = args.auth_protocol.upper()
        auth_passphrase = args.auth_passphrase
        
        # If auth passphrase not provided via args, prompt for it
        if not auth_passphrase and auth_protocol != 'NONE':
            auth_passphrase = getpass.getpass(f"Authentication passphrase for {username}: ")
            auth_passphrase_confirm = getpass.getpass("Confirm authentication passphrase: ")
            
            if auth_passphrase != auth_passphrase_confirm:
                print("Error: Passphrases do not match")
                return 1
        
        # Privacy
        priv_protocol = args.priv_protocol.upper()
        priv_passphrase = args.priv_passphrase
        
        # If priv passphrase not provided via args, prompt for it
        if not priv_passphrase and priv_protocol != 'NONE':
            priv_passphrase = getpass.getpass(f"Privacy passphrase for {username}: ")
            priv_passphrase_confirm = getpass.getpass("Confirm privacy passphrase: ")
            
            if priv_passphrase != priv_passphrase_confirm:
                print("Error: Passphrases do not match")
                return 1
        
        # Create user object
        user = SNMPv3User(
            username=username,
            auth_protocol=auth_protocol,
            auth_passphrase=auth_passphrase or '',
            priv_protocol=priv_protocol,
            priv_passphrase=priv_passphrase or '',
            engine_id=engine_id
        )
        
        # Add user
        success, message = credential_store.add_user(user)
        
        if success:
            print(f"✓ {message}")
            return 0
        else:
            print(f"✗ Error: {message}")
            return 1
            
    except Exception as e:
        print(f"✗ Error adding SNMPv3 user: {e}")
        return 1


def handle_snmpv3_remove_user(args) -> int:
    """
    Remove SNMPv3 user credentials
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    if not check_dependencies():
        return 1
    
    try:
        credential_store = get_credential_store()
        
        # Confirm removal
        if not args.yes:
            response = input(
                f"Remove user '{args.username}' for engine '{args.engine_id}'? (yes/no): "
            )
            if response.lower() not in ['yes', 'y']:
                print("Operation cancelled")
                return 0
        
        # Remove user
        success, message = credential_store.remove_user(args.engine_id, args.username)
        
        if success:
            print(f"✓ {message}")
            return 0
        else:
            print(f"✗ Error: {message}")
            return 1
            
    except Exception as e:
        print(f"✗ Error removing SNMPv3 user: {e}")
        return 1


def handle_snmpv3_list_users(args) -> int:
    """
    List SNMPv3 user credentials
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    if not check_dependencies():
        return 1
    
    try:
        credential_store = get_credential_store()
        
        users = credential_store.list_all_users()
        
        if not users:
            print("No SNMPv3 users configured")
            return 0
        
        print(f"\nConfigured SNMPv3 Users ({len(users)} total):\n")
        print(f"{'Engine ID':<40} {'Username':<20} {'Auth':<10} {'Priv':<10}")
        print("-" * 85)
        
        for user in sorted(users, key=lambda x: (x['engine_id'], x['username'])):
            print(
                f"{user['engine_id']:<40} "
                f"{user['username']:<20} "
                f"{user['auth_protocol']:<10} "
                f"{user['priv_protocol']:<10}"
            )
        
        print()
        return 0
        
    except Exception as e:
        print(f"✗ Error listing SNMPv3 users: {e}")
        return 1


def handle_snmpv3_show_user(args) -> int:
    """
    Show detailed information for a specific SNMPv3 user
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    if not check_dependencies():
        return 1
    
    try:
        credential_store = get_credential_store()
        
        user = credential_store.get_user(args.engine_id, args.username)
        
        if not user:
            print(f"✗ User '{args.username}' not found for engine '{args.engine_id}'")
            return 1
        
        print(f"\nSNMPv3 User Details:\n")
        print(f"  Engine ID:          {user.engine_id}")
        print(f"  Username:           {user.username}")
        print(f"  Auth Protocol:      {user.auth_protocol}")
        print(f"  Auth Passphrase:    {'***' if user.auth_passphrase else '(none)'}")
        print(f"  Privacy Protocol:   {user.priv_protocol}")
        print(f"  Privacy Passphrase: {'***' if user.priv_passphrase else '(none)'}")
        print()
        
        return 0
        
    except Exception as e:
        print(f"✗ Error showing SNMPv3 user: {e}")
        return 1


def handle_snmpv3_test_decrypt(args) -> int:
    """
    Test SNMPv3 decryption with a sample trap
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    if not check_dependencies() or not check_decryption_dependencies():
        return 1
    
    try:
        print("Initializing SNMPv3 decryptor...")
        
        decryptor = initialize_snmpv3_decryptor()
        
        # Read trap data from file or stdin
        if args.trap_file:
            with open(args.trap_file, 'rb') as f:
                trap_data = f.read()
            print(f"Loaded trap data from {args.trap_file} ({len(trap_data)} bytes)")
        else:
            print("Error: --trap-file is required for test-decrypt command")
            return 1
        
        # Attempt decryption
        print(f"Attempting to decrypt SNMPv3 trap...")
        
        result = decryptor.decrypt_snmpv3_trap(trap_data, args.engine_id)
        
        if not result:
            print("✗ Failed to decrypt SNMPv3 trap")
            print("  Possible issues:")
            print("  - No matching credentials configured")
            print("  - Incorrect credentials")
            print("  - Invalid trap format")
            return 1
        
        engine_id, trap_info = result
        
        print(f"✓ Successfully decrypted SNMPv3 trap")
        print(f"\n  Engine ID:     {engine_id}")
        print(f"  Varbinds:      {len(trap_info['varbinds'])}")
        
        if args.verbose:
            print("\n  Varbind Details:")
            for idx, vb in enumerate(trap_info['varbinds'], 1):
                print(f"    {idx}. OID: {vb['oid']}")
                print(f"       Type: {vb['type']}")
                print(f"       Value: {vb['value']}")
        
        # Test conversion to SNMPv2c
        if args.convert:
            print("\nConverting to SNMPv2c format...")
            
            snmpv2c_data = decryptor.convert_to_snmpv2c(trap_info, args.community)
            
            if snmpv2c_data:
                print(f"✓ Conversion successful ({len(snmpv2c_data)} bytes)")
                
                if args.output:
                    with open(args.output, 'wb') as f:
                        f.write(snmpv2c_data)
                    print(f"  Saved to: {args.output}")
            else:
                print("✗ Conversion to SNMPv2c failed")
                return 1
        
        print()
        return 0
        
    except FileNotFoundError:
        print(f"✗ Error: File not found: {args.trap_file}")
        return 1
    except Exception as e:
        print(f"✗ Error testing SNMPv3 decryption: {e}")
        import traceback
        if args.verbose:
            traceback.print_exc()
        return 1


def handle_snmpv3_status(args) -> int:
    """
    Show SNMPv3 subsystem status
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    if not check_dependencies():
        return 1
    
    try:
        credential_store = get_credential_store()
        
        users = credential_store.list_all_users()
        engine_ids = credential_store.get_engine_ids()
        
        print("\nSNMPv3 Subsystem Status:\n")
        print(f"  Configured Engine IDs: {len(engine_ids)}")
        print(f"  Configured Users:      {len(users)}")
        
        if engine_ids:
            print(f"\n  Engine IDs:")
            for engine_id in sorted(engine_ids):
                engine_users = credential_store.get_users_for_engine(engine_id)
                print(f"    - {engine_id} ({len(engine_users)} users)")
        
        print()
        return 0
        
    except Exception as e:
        print(f"✗ Error getting SNMPv3 status: {e}")
        return 1
