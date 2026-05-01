#!/usr/bin/env python3
"""
TrapNinja SNMPv3 Parser - Credential management subcommands.

Commands: add-user, remove-user, list-users, show-user, status, test-decrypt
"""

import textwrap

from .base import TrapNinjaHelpFormatter


def add_snmpv3_subcommands(subparsers):
    """Add SNMPv3 credential management subcommands."""
    snmpv3_parser = subparsers.add_parser(
        'snmpv3',
        help='SNMPv3 credential management',
        description='Manage SNMPv3 user credentials for trap decryption.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja snmpv3 add-user --username myuser --engine-id 80001f88...
              trapninja snmpv3 list-users           List configured users
              trapninja snmpv3 status               Show SNMPv3 status
              trapninja snmpv3 test-decrypt --trap-file /tmp/trap.bin
        ''')
    )
    snmpv3_parser.set_defaults(command_category='snmpv3')

    snmpv3_cmds = snmpv3_parser.add_subparsers(dest='command', metavar='<command>')

    # add-user
    add_user = snmpv3_cmds.add_parser('add-user', help='Add SNMPv3 user')
    add_user.add_argument('--username', required=True, help='Username')
    add_user.add_argument('--engine-id', required=True, help='Engine ID (hex)')
    add_user.add_argument('--auth-protocol',
                          choices=['NONE', 'MD5', 'SHA', 'SHA224', 'SHA256',
                                   'SHA384', 'SHA512'],
                          default='SHA', help='Auth protocol (default: SHA)')
    add_user.add_argument('--auth-passphrase', help='Auth passphrase')
    add_user.add_argument('--priv-protocol',
                          choices=['NONE', 'DES', '3DES', 'AES128', 'AES192',
                                   'AES256'],
                          default='AES128',
                          help='Privacy protocol (default: AES128)')
    add_user.add_argument('--priv-passphrase', help='Privacy passphrase')

    # remove-user
    remove_user = snmpv3_cmds.add_parser('remove-user', help='Remove SNMPv3 user')
    remove_user.add_argument('--username', required=True, help='Username')
    remove_user.add_argument('--engine-id', required=True, help='Engine ID')

    # list-users
    snmpv3_cmds.add_parser('list-users', help='List SNMPv3 users')

    # show-user
    show_user = snmpv3_cmds.add_parser('show-user', help='Show user details')
    show_user.add_argument('--username', required=True, help='Username')
    show_user.add_argument('--engine-id', required=True, help='Engine ID')

    # status
    snmpv3_cmds.add_parser('status', help='Show SNMPv3 status')

    # test-decrypt
    test_decrypt = snmpv3_cmds.add_parser('test-decrypt', help='Test decryption')
    test_decrypt.add_argument('--trap-file', required=True, help='Trap file path')
    test_decrypt.add_argument('--community', default='public',
                              help='Community for converted trap')
    test_decrypt.add_argument('--convert', action='store_true',
                              help='Convert to SNMPv2c')
    test_decrypt.add_argument('--output', help='Output file path')

    # help
    snmpv3_cmds.add_parser('help', help='Show SNMPv3 command help')
