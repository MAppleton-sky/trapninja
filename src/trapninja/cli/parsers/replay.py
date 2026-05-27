#!/usr/bin/env python3
"""
TrapNinja Replay Parser - Capture file replay subcommands.

Commands: run
Development/testing tool only — see docs/REPLAY.md
"""

import textwrap

from .base import TrapNinjaHelpFormatter


def add_replay_subcommands(subparsers):
    """
    Add replay subcommands for capture file replay.

    This is a development/testing tool — do not use on live production instances.
    """
    replay_parser = subparsers.add_parser(
        'replay',
        help='Replay a pcap capture file (dev/test tool)',
        description=textwrap.dedent('''\
            Replay a pcap capture file through the trap processing pipeline
            (development/testing tool — do not use on live production instances).

            WARNING: Injected packets ARE processed and forwarded to real
            destinations. On a system with live destinations configured,
            replayed traps WILL be forwarded to real NMS/OSS systems.
        '''),
        formatter_class=TrapNinjaHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              trapninja replay run /tmp/traps.pcap
              trapninja replay run /tmp/traps.pcap --replay-realtime
              trapninja replay run /tmp/traps.pcap --replay-count 3
              trapninja replay run /tmp/traps.pcap --replay-dry-run
              trapninja replay run /tmp/traps.pcap --replay-filter-src 10.0.0.1
        ''')
    )
    replay_parser.set_defaults(command_category='replay')

    replay_cmds = replay_parser.add_subparsers(dest='command', metavar='<command>')

    # run command
    run_cmd = replay_cmds.add_parser(
        'run',
        help='Replay packets from a capture file into the processing pipeline',
        description='Replay packets from a pcap/pcapng capture file into the TrapNinja processing pipeline.',
        formatter_class=TrapNinjaHelpFormatter,
    )

    # Positional argument: capture file
    run_cmd.add_argument(
        'capture_file',
        metavar='<capture-file>',
        help='Path to pcap/pcapng capture file'
    )

    # Optional flags
    run_cmd.add_argument(
        '--replay-realtime',
        action='store_true',
        dest='replay_realtime',
        help='Honour inter-packet timestamps from the capture (default: off, replay as fast as possible)'
    )

    run_cmd.add_argument(
        '--replay-count',
        type=int,
        default=1,
        dest='replay_count',
        metavar='N',
        help='Number of replay passes (default: 1; 0 = loop until Ctrl-C)'
    )

    run_cmd.add_argument(
        '--replay-filter-src',
        dest='replay_filter_src',
        metavar='IP',
        help='Only replay packets from this source IP address'
    )

    run_cmd.add_argument(
        '--replay-dry-run',
        action='store_true',
        dest='replay_dry_run',
        help='Parse and count packets but do NOT inject into the pipeline'
    )

    run_cmd.add_argument(
        '--replay-summary-json',
        dest='replay_summary_json',
        metavar='PATH',
        help='Write replay summary to this JSON file on completion'
    )

    run_cmd.add_argument(
        '--i-know-this-is-not-production',
        action='store_true',
        dest='i_know_this_is_not_production',
        help='Bypass the production safety gate (use with extreme caution)'
    )

    run_cmd.add_argument(
        '--regenerate-v3',
        action='store_true',
        dest='regenerate_v3',
        help='Regenerate SNMPv3 traps with fresh security state. '
             'Requires pycryptodome and credentials in /etc/trapninja/snmpv3_credentials.json'
    )

    # help command
    replay_cmds.add_parser('help', help='Show comprehensive replay help')
