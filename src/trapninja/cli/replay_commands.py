#!/usr/bin/env python3
"""
TrapNinja Replay CLI Commands

Implements: trapninja replay <capture-file> [options]

This module validates CLI args and delegates to ReplayEngine.
All replay logic lives in replay_engine.py, not here.

Development/testing tool only — see docs/REPLAY.md
"""
import os
import logging
from argparse import Namespace

logger = logging.getLogger("trapninja")


def run_replay(args: Namespace) -> int:
    """
    Entry point for: trapninja replay run <capture-file> [options]

    Validates the capture file path, constructs ReplayEngine,
    runs it, and returns its exit code.

    Returns:
        int: 0=success, 1=error, 2=safety gate blocked
    """
    from ..config import LOG_FILE, LOG_LEVEL, LOG_MAX_SIZE, LOG_BACKUP_COUNT, LOG_COMPRESS
    from ..logger import setup_logging
    from ..replay_engine import ReplayEngine

    # Use a dedicated replay log file by default to avoid mixing replay
    # diagnostics with normal operations logs.
    replay_log_file = getattr(args, 'replay_log_file', None)
    if replay_log_file:
        replay_log_file = os.path.abspath(replay_log_file)
    else:
        replay_log_file = os.path.join(
            os.path.dirname(LOG_FILE),
            'trapninja_replay.log'
        )

    try:
        setup_logging(
            console=True,
            log_file=replay_log_file,
            log_level=LOG_LEVEL,
            max_size=LOG_MAX_SIZE,
            backup_count=LOG_BACKUP_COUNT,
            compress=LOG_COMPRESS,
        )
    except Exception as e:
        print(f"Warning: failed to initialize replay logging at {replay_log_file}: {e}")

    capture_file = getattr(args, 'capture_file', None)
    if not capture_file:
        print("Error: capture file path is required.")
        print("Usage: trapninja replay run <capture-file> [options]")
        return 1

    capture_file = os.path.abspath(capture_file)
    if not os.path.exists(capture_file):
        print(f"Error: capture file not found: {capture_file}")
        return 1
    if not os.path.isfile(capture_file):
        print(f"Error: path is not a file: {capture_file}")
        return 1
    if not os.access(capture_file, os.R_OK):
        print(f"Error: capture file is not readable: {capture_file}")
        return 1

    engine = ReplayEngine(
        capture_file=capture_file,
        replay_realtime=getattr(args, 'replay_realtime', False),
        replay_count=getattr(args, 'replay_count', 1),
        filter_src_ip=getattr(args, 'replay_filter_src', None),
        dry_run=getattr(args, 'replay_dry_run', False),
        skip_safety_check=getattr(args, 'i_know_this_is_not_production', False),
        regenerate_v3=getattr(args, 'regenerate_v3', False),
    )

    exit_code = engine.run()

    # Optionally write JSON summary
    summary_json_path = getattr(args, 'replay_summary_json', None)
    if summary_json_path and exit_code == 0:
        _write_json_summary(engine.metrics, summary_json_path)

    return exit_code


def _write_json_summary(metrics, output_path: str) -> None:
    """Write ReplayMetrics to a JSON file alongside the capture."""
    import json
    import dataclasses

    try:
        output_path = os.path.abspath(output_path)
        data = dataclasses.asdict(metrics)
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Summary written to: {output_path}")
    except Exception as e:
        logger.warning(f"Failed to write JSON summary to {output_path}: {e}")
