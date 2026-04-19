"""
utils/logger.py — Centralized logging configuration for NetScanX
"""

import logging
import sys
from typing import Optional

_initialized = False


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger.  The root 'netscannx' logger is configured
    once on first call; subsequent calls just return child loggers.
    """
    global _initialized

    if not _initialized:
        _setup_root_logger()
        _initialized = True

    return logging.getLogger(f"netscannx.{name}")


def _setup_root_logger():
    """Configure the root 'netscannx' logger based on config settings."""
    from config import config  # late import to avoid circular deps

    root = logging.getLogger("netscannx")

    # Honour LOG_LEVEL env var
    level = getattr(logging, config.log_level.upper(), logging.INFO)
    root.setLevel(level)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Always log to stderr
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    # Optionally log to a file
    if config.log_file:
        fh = logging.FileHandler(config.log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)