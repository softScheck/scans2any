"""Utilities for printing highlighted terminal output."""

import contextlib
import logging
import sys
from typing import Any

from rich.console import Console

logger = logging.getLogger("scans2any")

# Stderr console for status spinners (keeps stdout clean)
_stderr_console = Console(stderr=True, force_terminal=True)

# Track the active progress/live context for proper log interleaving
_active_progress = None


class RichStatusHandler(logging.Handler):
    """Custom logging handler that prints through rich console."""

    def emit(self, record):
        try:
            msg = self.format(record)
            if _active_progress is not None:
                # When progress bar is active, use progress.print() to properly
                # interleave output above the progress bar
                _active_progress.print(msg, highlight=False)
            else:
                # Normal printing to stderr console
                _stderr_console.print(msg, highlight=False)
        except Exception:
            self.handleError(record)


def _ensure_handler():
    """Ensure the logger has at least a basic handler configured.

    This is called at module import time to ensure logging works
    in worker processes spawned by ProcessPoolExecutor.
    """
    if not logger.handlers:
        # Add a basic stderr handler so logs aren't lost in worker processes
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.propagate = False


# Ensure basic handler at import time (important for worker processes)
_ensure_handler()


class Colors:
    """Offers aliases for coloring terminal output, using ANSI escape sequences.

    E.g. include as {Colors.OKGREEN} in python f-strings to start coloring green.
    End any coloring with {Colors.ENDC}.

    Examples
    --------
    >>> print(f"{Colors.OKGREEN}Success message!{Colors.ENDC}")
    Success message!

    """

    HEADER = "\033[95m"  # Light Magenta
    OKBLUE = "\033[94m"  # Light Blue
    OKCYAN = "\033[96m"  # Light Cyan
    OKGREEN = "\033[92m"  # Light Green
    WARNING = "\033[93m"  # Light Yellow
    FAIL = "\033[91m"  # Light Red
    DEBUG = "\033[37m"  # Light gray
    ENDC = "\033[0m"  # Reset to default
    BOLD = "\033[1m"  # Bold
    UNDERLINE = "\033[4m"  # Underline


def success(msg: Any, *, return_msg: bool = False):
    """Print colored success message to terminal
    **OR** if `return_msg` is True return as colored string.

    Returns
    -------
    >>> f"{Colors.OKGREEN}{Colors.BOLD}[ + ]{Colors.ENDC} {msg}"

    """
    msg = f"{Colors.OKGREEN}{Colors.BOLD}[ + ]{Colors.ENDC} {msg}"
    return msg if return_msg else logger.info(msg)


def info(msg: Any, *, return_msg: bool = False):
    """Print colored info message to terminal
    **OR** if `return_msg` is True return as colored string.

    Returns
    -------
    >>> f"{Colors.OKCYAN}{Colors.BOLD}[ * ]{Colors.ENDC} {msg}"

    """
    msg = f"{Colors.OKCYAN}{Colors.BOLD}[ * ]{Colors.ENDC} {msg}"
    return msg if return_msg else logger.info(msg)


def failure(msg: Any, *, return_msg: bool = False):
    """Print colored failure message to terminal
    **OR** if `return_msg` is True return as colored string.

    Returns
    -------
    >>> f"{Colors.FAIL}{Colors.BOLD}[ - ] {msg} {Colors.ENDC} "

    """
    r_msg = f"[bold][red][ - ][/red][/bold] {msg}"
    msg = f"{Colors.FAIL}{Colors.BOLD}[ - ]{Colors.ENDC} {msg}"
    return r_msg if return_msg else logger.error(msg)


def error(msg: Any, *, return_msg: bool = False):
    """Print colored error message to terminal
    **OR** if `return_msg` is True return as colored string.

    Returns
    -------
    >>> f"{Colors.FAIL}{Colors.BOLD}[ X ]{Colors.ENDC} {msg}"

    """
    r_msg = f"[bold][red][ X ][/red][/bold] {msg}"
    msg = f"{Colors.FAIL}{Colors.BOLD}[ X ]{Colors.ENDC} {msg}"
    return r_msg if return_msg else logger.error(msg)


def warning(msg: Any, *, return_msg: bool = False):
    """Print colored warning message to terminal
    **OR** if `return_msg` is True return as colored string.

    Returns
    -------
    >>> f"{Colors.WARNING}{Colors.BOLD}[ ! ]{Colors.ENDC} {msg}"

    """
    r_msg = f"[bold][yellow][ ! ][/yellow][/bold] {msg}"
    msg = f"{Colors.BOLD}{Colors.WARNING}[ ! ]{Colors.ENDC} {msg}"
    return r_msg if return_msg else logger.warning(msg)


def status(msg: Any, *, return_msg: bool = False):
    """Print colored status message to terminal
    **OR** if `return_msg` is True return as colored string.

    Returns
    -------
    >>> f"{Colors.OKBLUE}{Colors.BOLD} ~ {Colors.ENDC}{msg}"

    """
    msg = f"{Colors.OKBLUE}{Colors.BOLD}~ {Colors.ENDC}{msg}"
    # level 15 is between DEBUG and INFO
    return msg if return_msg else logger.log(level=15, msg=msg)


def section(msg: Any, *, return_msg: bool = False):
    r"""Print colored section header to terminal
    **OR** if `return_msg` is True return as colored string.

    Returns
    -------
    >>> f"\n{Colors.HEADER}{Colors.BOLD}{Colors.UNDERLINE}{msg}{Colors.ENDC}"

    """
    msg = f"\n{Colors.HEADER}{Colors.BOLD}{Colors.UNDERLINE}{msg}{Colors.ENDC}"
    # Use print directly for section headers to avoid timestamp prefix if desired,
    # OR log it. If we want timestamp, we must log it.
    # But the user asked for "each logger output shows the current time".
    # The issue is that `logging` adds the timestamp at the beginning of the line.
    # If `msg` starts with `\n`, the timestamp will be on the empty line or before it?
    # Actually logging handles newlines by printing the prefix once usually.
    # Let's keep it as log.
    return msg if return_msg else logger.log(level=25, msg=msg)


def debug(msg: Any, *, return_msg: bool = False):
    """Print colored debug message to terminal
    **OR** if `return_msg` is True return as colored string.

    Returns
    -------
    >>> f"{Colors.OKCYAN} [ DEBUG ]{Colors.ENDC} {msg}"

    """
    if not return_msg and not logger.isEnabledFor(logging.DEBUG):
        return None
    msg = f"{Colors.DEBUG}[ DEBUG ]{Colors.ENDC} {msg}"
    return msg if return_msg else logger.debug(msg)


@contextlib.contextmanager
def status_section(msg: str, *, quiet: bool = False, verbose: bool = False):
    """Context manager that shows a rich spinner status on stderr.

    In quiet mode, nothing is displayed.
    In verbose mode, prints the section header and keeps it visible.
    In normal mode, shows a spinner that disappears when done.

    Usage:
        with printer.status_section("Loading data", quiet=args.quiet, verbose=args.verbose):
            # do work
    """
    if quiet:
        yield
        return

    if verbose:
        # In verbose mode, print section header and keep it visible
        section(msg)
        yield
        return

    with _stderr_console.status(f"[bold blue]{msg}[/bold blue]", spinner="dots"):
        yield


def setup_logging_handler(log_format: str = "%(message)s"):
    """Setup the rich-aware logging handler for the scans2any logger.

    Replaces any existing handlers with a RichStatusHandler that can
    interleave log messages with the progress bar.
    """
    # Remove existing handlers (including the basic one from _ensure_handler)
    for h in logger.handlers[:]:
        logger.removeHandler(h)

    handler = RichStatusHandler()
    handler.setFormatter(logging.Formatter(log_format, datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    logger.propagate = False  # Don't pass to root logger


def set_active_progress(progress):
    """Set the active progress bar for log message interleaving.

    Call with the Progress instance when entering a progress context,
    and with None when exiting.
    """
    global _active_progress
    _active_progress = progress
