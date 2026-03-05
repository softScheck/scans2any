#!/usr/bin/env python

"""
CLI entrypoint of scans2any.
"""

import concurrent.futures
import logging
import signal
from pathlib import Path
from sys import exit

from scans2any.helpers.cli import (
    list_available_filters,
    list_available_writers,
    parse_args_with_custom_options,
)
from scans2any.helpers.file_processing import parse_input_files
from scans2any.helpers.infrastructure import (
    apply_filters,
    check_for_remaining_conflicts,
    combine_infrastructure_scans,
    generate_output,
    handle_merge_file,
    resolve_infrastructure_conflicts,
)
from scans2any.internal import printer
from scans2any.writers import avail_writers, json_writer

__version__ = "1.0.0"

executor: concurrent.futures.Executor | None = None

# Handle SIGPIPE only on platforms that support it
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def signal_handler(signum: int, frame: object) -> None:
    """Handle interrupt signals."""
    printer.info("Received interrupt signal. Cleaning up ...")
    if executor is not None:
        executor.shutdown(wait=False, cancel_futures=True)
    exit(0)


def main():
    """Main function of `scans2any` tool."""
    parser, args = parse_args_with_custom_options(__version__)

    # Handle help and informational arguments
    if args.help:
        parser.print_help()
        return
    if args.version:
        print(f"scans2any v.{__version__}")  # noqa T201
        return
    if args.list_filters:
        list_available_filters()
        return
    if args.list_writers:
        list_available_writers()
        return

    # Setup logging
    log_format = "%(message)s"
    if args.verbose >= 2:
        log_format = "%(asctime)s.%(msecs)03d %(message)s"

    logging.basicConfig(format=log_format, datefmt="%H:%M:%S")
    logger = logging.getLogger("scans2any")
    logger.setLevel(25 - (args.verbose * 10))
    if args.quiet:
        logger.setLevel(logging.ERROR)

    # Setup rich-aware logging handler for status spinner compatibility
    printer.setup_logging_handler(log_format)

    # Parse merge file if provided
    merge_infra, auto_merge_ruleset = handle_merge_file(args.merge_file)

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    global executor

    # Parse input files
    all_infras = parse_input_files(args, parser)

    # Check if the selected writer requires ignoring conflicts
    selected_writer = next(
        (obj for obj in avail_writers if args.writer == obj.NAME), None
    )
    if (
        selected_writer
        and hasattr(selected_writer, "PROPERTIES")
        and selected_writer.PROPERTIES.get("ignore-conflicts", False)
    ):
        args.ignore_conflicts = True

    # Process infrastructure
    verbose = args.verbose > 0
    combined_infra = combine_infrastructure_scans(
        all_infras, quiet=args.quiet, verbose=verbose
    )
    printer.debug(combined_infra)
    combined_infra.merge_os_sources()

    # Apply filters
    filters = list(set(args.filters + args.enable_filters) - set(args.disable_filters))
    printer.debug(f"Enabled filters: {filters}")
    apply_filters(combined_infra, filters, args, quiet=args.quiet, verbose=verbose)

    # Handle merging and conflicts
    try:
        combined_infra = resolve_infrastructure_conflicts(
            combined_infra,
            merge_infra,
            auto_merge_ruleset,
            quiet=args.quiet,
            verbose=verbose,
        )
        printer.debug(combined_infra)
    except Exception as e:
        printer.failure(f"Merge failure: {e}")
        return

    # Apply automatic merging if not disabled
    if not args.no_auto_merge:
        combined_infra.auto_merge(quiet=args.quiet, verbose=verbose)
        printer.debug(combined_infra)

    # Check for remaining conflicts if not ignored
    if not args.ignore_conflicts and check_for_remaining_conflicts(
        combined_infra,
        passed_merge_file=bool(args.merge_file),
        buffer_file_path=args.buffer_file,
        quiet=args.quiet,
        verbose=verbose,
    ):
        with Path(args.buffer_file).open("w") as f:
            f.write(json_writer.write(combined_infra, args))
        return

    # Sort and generate output
    combined_infra.sort()
    output = generate_output(combined_infra, args, quiet=args.quiet, verbose=verbose)

    # Write output to file or print to stdout
    if args.out:
        mode = "w"
        if selected_writer and hasattr(selected_writer, "PROPERTIES"):
            mode = "wb" if selected_writer.PROPERTIES.get("binary", True) else "w"

        with Path(args.out).open(mode) as outfile:
            outfile.write(output)
        printer.success(f"Written to output file: {args.out}")
    else:
        print(output)  # noqa T201


if __name__ == "__main__":
    main()
