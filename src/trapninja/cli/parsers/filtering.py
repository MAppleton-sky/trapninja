#!/usr/bin/env python3
"""
TrapNinja Filter Parser - IP and OID filtering/redirection subcommands.

Commands: block-ip, unblock-ip, list-blocked-ips, block-oid, unblock-oid,
          list-blocked-oids, redirect-ip, unredirect-ip, list-redirected-ips,
          redirect-oid, unredirect-oid, list-redirected-oids,
          add-redirect-dest, remove-redirect-dest, list-redirect-dests
"""

import textwrap

from .base import TrapNinjaHelpFormatter, validated_ip, validated_oid, validated_tag, validated_port


def add_filter_subcommands(subparsers):
    """Add filtering subcommands."""
    filter_parser = subparsers.add_parser(
        'filter',
        help='IP and OID filtering/redirection',
        description='Manage trap filtering and redirection rules.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja filter block-ip 10.0.0.1        Block an IP
              trapninja filter unblock-ip 10.0.0.1      Remove IP block
              trapninja filter list-blocked-ips         Show blocked IPs
              trapninja filter block-oid 1.3.6.1.4.1.9  Block OID prefix
              trapninja filter redirect-ip 10.0.0.1 --tag security
        ''')
    )
    filter_parser.set_defaults(command_category='filter')

    filter_cmds = filter_parser.add_subparsers(dest='command', metavar='<command>')

    # IP blocking
    block_ip = filter_cmds.add_parser('block-ip', help='Block an IP address')
    block_ip.add_argument('ip', type=validated_ip, help='IP address to block')

    unblock_ip = filter_cmds.add_parser('unblock-ip', help='Unblock an IP address')
    unblock_ip.add_argument('ip', type=validated_ip, help='IP address to unblock')

    filter_cmds.add_parser('list-blocked-ips', help='List all blocked IPs')

    # OID blocking
    block_oid = filter_cmds.add_parser('block-oid', help='Block an OID')
    block_oid.add_argument('oid', type=validated_oid, help='OID to block')

    unblock_oid = filter_cmds.add_parser('unblock-oid', help='Unblock an OID')
    unblock_oid.add_argument('oid', type=validated_oid, help='OID to unblock')

    filter_cmds.add_parser('list-blocked-oids', help='List all blocked OIDs')

    # IP redirection
    redirect_ip = filter_cmds.add_parser('redirect-ip',
                                          help='Redirect traps from IP')
    redirect_ip.add_argument('ip', type=validated_ip, help='IP address to redirect')
    redirect_ip.add_argument('--tag', type=validated_tag, required=True,
                             help='Destination group tag')

    unredirect_ip = filter_cmds.add_parser('unredirect-ip',
                                            help='Remove IP redirection')
    unredirect_ip.add_argument('ip', type=validated_ip,
                               help='IP to remove redirection')

    filter_cmds.add_parser('list-redirected-ips', help='List IP redirections')

    # OID redirection
    redirect_oid = filter_cmds.add_parser('redirect-oid',
                                           help='Redirect traps with OID')
    redirect_oid.add_argument('oid', type=validated_oid, help='OID to redirect')
    redirect_oid.add_argument('--tag', type=validated_tag, required=True,
                              help='Destination group tag')

    unredirect_oid = filter_cmds.add_parser('unredirect-oid',
                                             help='Remove OID redirection')
    unredirect_oid.add_argument('oid', type=validated_oid,
                                help='OID to remove redirection')

    filter_cmds.add_parser('list-redirected-oids', help='List OID redirections')

    # Redirect destinations
    add_dest = filter_cmds.add_parser('add-redirect-dest',
                                       help='Add redirect destination')
    add_dest.add_argument('--tag', type=validated_tag, required=True,
                          help='Destination group tag')
    add_dest.add_argument('--ip', type=validated_ip, required=True,
                          help='Destination IP')
    add_dest.add_argument('--port', type=validated_port, required=True,
                          help='Destination port')

    remove_dest = filter_cmds.add_parser('remove-redirect-dest',
                                          help='Remove redirect destination')
    remove_dest.add_argument('--tag', type=validated_tag, required=True,
                             help='Destination group tag')
    remove_dest.add_argument('--ip', type=validated_ip, required=True,
                             help='Destination IP')
    remove_dest.add_argument('--port', type=validated_port, required=True,
                             help='Destination port')

    filter_cmds.add_parser('list-redirect-dests', help='List redirect destinations')
    filter_cmds.add_parser('help', help='Show comprehensive redirection help')
