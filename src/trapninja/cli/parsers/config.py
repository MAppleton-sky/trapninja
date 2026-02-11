#!/usr/bin/env python3
"""
TrapNinja Config Parser - Configuration display subcommands.

Commands: show, destinations, blocked-ips, blocked-oids,
          redirected-ips, redirected-oids, redirect-dests,
          listen-ports, validate
"""

import textwrap

from .base import TrapNinjaHelpFormatter


def add_config_subcommands(subparsers):
    """Add configuration display subcommands."""
    config_parser = subparsers.add_parser(
        'config',
        help='View running configuration and rule lists',
        description='Display current TrapNinja configuration, filter rules, and routing tables.',
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja config show                 Full configuration overview
              trapninja config destinations          Show forwarding destinations
              trapninja config blocked-ips           Show blocked IP list
              trapninja config blocked-oids          Show blocked OID list
              trapninja config redirected-ips        Show IP redirection rules
              trapninja config redirected-oids       Show OID redirection rules
              trapninja config redirect-dests        Show redirect destination groups
              trapninja config listen-ports          Show configured listen ports
              trapninja config validate              Validate configuration files
        ''')
    )
    config_parser.set_defaults(command_category='config')

    config_cmds = config_parser.add_subparsers(dest='command', metavar='<command>')

    # show — full overview (replaces daemon config)
    show_cmd = config_cmds.add_parser(
        'show', help='Show full configuration overview (with rule data)')
    show_cmd.add_argument('--json', action='store_true',
                          help='Output in JSON format')
    show_cmd.add_argument('--brief', action='store_true',
                          help='Show counts only, no detail')

    # destinations
    dest_cmd = config_cmds.add_parser(
        'destinations', help='Show forwarding destinations')
    dest_cmd.add_argument('--json', action='store_true',
                          help='Output in JSON format')

    # blocked-ips
    bip_cmd = config_cmds.add_parser(
        'blocked-ips', help='Show blocked IP addresses')
    bip_cmd.add_argument('--json', action='store_true',
                         help='Output in JSON format')

    # blocked-oids
    boid_cmd = config_cmds.add_parser(
        'blocked-oids', help='Show blocked OIDs')
    boid_cmd.add_argument('--json', action='store_true',
                          help='Output in JSON format')

    # redirected-ips
    rip_cmd = config_cmds.add_parser(
        'redirected-ips', help='Show IP redirection rules')
    rip_cmd.add_argument('--json', action='store_true',
                         help='Output in JSON format')

    # redirected-oids
    roid_cmd = config_cmds.add_parser(
        'redirected-oids', help='Show OID redirection rules')
    roid_cmd.add_argument('--json', action='store_true',
                          help='Output in JSON format')

    # redirect-dests
    rdest_cmd = config_cmds.add_parser(
        'redirect-dests', help='Show redirect destination groups')
    rdest_cmd.add_argument('--json', action='store_true',
                           help='Output in JSON format')

    # listen-ports
    lp_cmd = config_cmds.add_parser(
        'listen-ports', help='Show configured listen ports')
    lp_cmd.add_argument('--json', action='store_true',
                        help='Output in JSON format')

    # validate
    config_cmds.add_parser(
        'validate', help='Validate configuration files')

    # help
    config_cmds.add_parser('help', help='Show config command help')
