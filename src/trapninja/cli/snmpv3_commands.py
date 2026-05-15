#!/usr/bin/env python3
"""
TrapNinja CLI - SNMPv3 Commands

Commands for managing SNMPv3 user credentials.
"""
import struct
import sys
import getpass
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Pcap parsing helpers
# ---------------------------------------------------------------------------

_PCAP_MAGIC_LE  = b'\xd4\xc3\xb2\xa1'
_PCAP_MAGIC_BE  = b'\xa1\xb2\xc3\xd4'
_PCAPNG_MAGIC   = b'\x0a\x0d\x0d\x0a'

# Supported pcap link-layer types and their fixed L2 header sizes
_LINKTYPE_L2_SIZE = {
    0:   4,   # NULL / BSD loopback
    1:   14,  # Ethernet
    101: 0,   # Raw IP
    113: 16,  # Linux cooked (SLL)
    228: 0,   # Raw IPv4
}


def _is_pcap_file(data: bytes) -> bool:
    """Return True if data starts with a recognised pcap magic number."""
    return len(data) >= 4 and data[:4] in (
        _PCAP_MAGIC_LE, _PCAP_MAGIC_BE, _PCAPNG_MAGIC
    )


def _extract_snmp_from_pcap(
    data: bytes,
) -> Tuple[List[bytes], Optional[str]]:
    """
    Parse a pcap file and return all UDP port-162 SNMP payloads.

    Returns (payloads, error_message). On success error_message is None.
    Only pcap (not pcapng) is handled; pcapng produces a clear error with
    a conversion command.
    """
    if len(data) < 24:
        return [], "File too small to be a valid pcap"

    magic = data[:4]

    if magic == _PCAPNG_MAGIC:
        return [], (
            "pcapng format is not supported directly.\n"
            "Convert to pcap first:\n"
            "  tcpdump -r capture.pcapng -w capture.pcap"
        )

    if magic == _PCAP_MAGIC_LE:
        endian = '<'
    elif magic == _PCAP_MAGIC_BE:
        endian = '>'
    else:
        return [], "Not a pcap file (unrecognised magic bytes)"

    # Global header: magic(4) ver_maj(2) ver_min(2) zone(4) sig(4) snap(4) network(4)
    network = struct.unpack_from(f'{endian}I', data, 20)[0]

    l2_size = _LINKTYPE_L2_SIZE.get(network)
    if l2_size is None:
        return [], (
            f"Unsupported pcap link type: {network}.\n"
            "Try capturing with: tcpdump -i <iface> -s0 -w capture.pcap udp port 162"
        )

    payloads: List[bytes] = []
    offset = 24  # skip global header

    while offset + 16 <= len(data):
        # Per-packet header: ts_sec ts_usec incl_len orig_len
        _, _, incl_len, _ = struct.unpack_from(f'{endian}IIII', data, offset)
        offset += 16

        if offset + incl_len > len(data):
            break

        pkt = data[offset:offset + incl_len]
        offset += incl_len

        # Strip L2
        if len(pkt) <= l2_size:
            continue
        ip = pkt[l2_size:]

        # IPv4 only
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue

        # Protocol must be UDP (17)
        if ip[9] != 17:
            continue

        ip_hlen = (ip[0] & 0x0f) * 4
        if len(ip) < ip_hlen + 8:
            continue

        udp = ip[ip_hlen:]

        # Destination port must be 162 (SNMP trap)
        dst_port = struct.unpack_from('>H', udp, 2)[0]
        if dst_port != 162:
            continue

        snmp = udp[8:]
        if snmp:
            payloads.append(snmp)

    return payloads, None

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
    Test SNMPv3 decryption with a raw binary or pcap capture file.
    """
    if not check_dependencies() or not check_decryption_dependencies():
        return 1

    try:
        print("Initializing SNMPv3 decryptor...")
        decryptor = initialize_snmpv3_decryptor()

        with open(args.trap_file, 'rb') as f:
            file_data = f.read()

        print(f"Loaded {len(file_data)} bytes from {args.trap_file}")

        # ------------------------------------------------------------------
        # Pcap path
        # ------------------------------------------------------------------
        if _is_pcap_file(file_data):
            print("Detected pcap format — extracting SNMP trap packets...")

            payloads, err = _extract_snmp_from_pcap(file_data)
            if err:
                print(f"✗ Failed to parse pcap: {err}")
                return 1

            if not payloads:
                print("✗ No SNMP trap packets (UDP dport 162) found in capture.")
                return 1

            print(f"  Found {len(payloads)} SNMP trap packet(s).")

            if args.all_packets:
                return _test_decrypt_all(
                    decryptor, payloads, args
                )
            else:
                idx = args.packet_index
                if idx >= len(payloads):
                    print(
                        f"✗ --packet-index {idx} is out of range "
                        f"(capture contains {len(payloads)} trap(s), "
                        f"valid range: 0–{len(payloads) - 1})."
                    )
                    return 1
                print(f"  Attempting decryption of packet {idx}...")
                trap_data = payloads[idx]
        else:
            # ------------------------------------------------------------------
            # Raw binary path
            # ------------------------------------------------------------------
            trap_data = file_data

        return _attempt_decrypt(decryptor, trap_data, args)

    except FileNotFoundError:
        print(f"✗ File not found: {args.trap_file}")
        return 1
    except Exception as e:
        print(f"✗ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def _attempt_decrypt(decryptor, trap_data: bytes, args) -> int:
    """Attempt to decrypt a single SNMP PDU and report results."""
    engine_id = getattr(args, 'engine_id', None)

    result = decryptor.decrypt_snmpv3_trap(trap_data, engine_id)

    if not result:
        print("✗ Failed to decrypt SNMPv3 trap")
        print("  Possible issues:")
        print("  - No matching credentials configured (run: trapninja snmpv3 list-users)")
        print("  - Incorrect auth/priv protocol or passphrase")
        print("  - Packet is not encrypted (authNoPriv or noAuthNoPriv)")
        return 1

    engine_id_result, trap_info = result
    decrypted_user = trap_info.get('username', 'N/A')
    varbind_count = len(trap_info.get('varbinds', []))

    print(f"✓ Successfully decrypted SNMPv3 trap")
    print(f"\n  Engine ID:  {engine_id_result}")
    print(f"  Username:   {decrypted_user}")
    print(f"  Varbinds:   {varbind_count}")

    if args.verbose:
        print("\n  Varbind Details:")
        for i, vb in enumerate(trap_info.get('varbinds', []), 1):
            print(f"    {i}. OID:   {vb['oid']}")
            print(f"       Type:  {vb['type']}")
            print(f"       Value: {vb['value']}")

    if args.convert:
        print("\nConverting to SNMPv2c format...")
        v2c = decryptor.convert_to_snmpv2c(trap_info, args.community)
        if v2c:
            print(f"✓ Conversion successful ({len(v2c)} bytes)")
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(v2c)
                print(f"  Saved to: {args.output}")
        else:
            print("✗ Conversion to SNMPv2c failed")
            return 1

    print()
    return 0


def _test_decrypt_all(decryptor, payloads: List[bytes], args) -> int:
    """Attempt decryption of every SNMP trap in a pcap and print a summary."""
    success = 0
    failed = 0

    for i, trap_data in enumerate(payloads):
        engine_id = getattr(args, 'engine_id', None)
        result = decryptor.decrypt_snmpv3_trap(trap_data, engine_id)
        if result:
            engine_id_result, trap_info = result
            user = trap_info.get('username', 'N/A')
            vbs = len(trap_info.get('varbinds', []))
            print(f"  [{i}] ✓  engine={engine_id_result}  user={user}  varbinds={vbs}")
            success += 1
        else:
            print(f"  [{i}] ✗  Failed to decrypt")
            failed += 1

    print(f"\nSummary: {success} decrypted, {failed} failed out of {len(payloads)} packets.")
    return 0 if success > 0 else 1


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
