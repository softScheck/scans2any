"""
File processing utilities for scans2any.
"""

import concurrent.futures
import os
import sys
from pathlib import Path

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from scans2any.helpers.utils import is_special_fd
from scans2any.internal import Infrastructure, printer
from scans2any.internal.printer import _stderr_console, logger
from scans2any.parsers import avail_parsers


def _worker_init(log_level: int) -> None:
    """Initialize worker process with the correct log level."""
    logger.setLevel(log_level)


def _osc_progress_update(percentage: int) -> None:
    """Send OSC 9;4 progress update to terminal emulators that support it.

    Unsupported terminals silently ignore these codes.
    """
    os.write(sys.stderr.fileno(), f"\033]9;4;1;{percentage}\033\\".encode())


def _osc_progress_end() -> None:
    """Signal end of progress to terminal emulator."""
    os.write(sys.stderr.fileno(), b"\033]9;4;0;\033\\")


def process_file(parser_func, filename):
    """Process a single file with the given parser function."""
    try:
        return parser_func(filename), None
    except Exception as e:
        return None, e


def create_progress_bar(*, quiet: bool = False, verbose: bool = False) -> Progress:
    """Create a standardized rich progress bar that outputs to stderr."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40, complete_style="green", finished_style="bright_green"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=_stderr_console,
        disable=quiet or verbose,  # Disable in verbose mode to allow log output
        transient=True,
    )


def collect_scan_results(
    futures_map: dict[concurrent.futures.Future, Path],
    scan_type: str,
    *,
    quiet: bool = False,
    verbose: bool = False,
) -> list[Infrastructure]:
    """Collect results from futures with progress bar."""
    if not futures_map:
        return []

    results: list[Infrastructure] = []
    error_files: list[str | Path] = []
    successful: int = 0
    hosts: int = 0
    total = len(futures_map)
    completed = 0

    # In verbose mode, print section header since progress bar is disabled
    if verbose:
        printer.section(f"Parsing {scan_type} scans ({total} files)")

    try:
        with create_progress_bar(quiet=quiet, verbose=verbose) as progress:
            printer.set_active_progress(progress)
            task = progress.add_task(f"Parsing {scan_type} scans", total=total)

            for future in concurrent.futures.as_completed(futures_map):
                filename = futures_map[future]
                try:
                    result, error = future.result()
                except Exception as e:
                    result, error = None, e

                if result:
                    results.append(result)
                    successful += 1
                    hosts += len(result.hosts)
                else:
                    error_files.append(filename)
                    progress.console.print(
                        printer.error(
                            f"Failed to parse {scan_type} scan: {filename}",
                            return_msg=True,
                        )
                    )
                    if error:
                        progress.console.print(
                            printer.warning(
                                f"{type(error).__name__}: {error}", return_msg=True
                            )
                        )

                completed += 1
                progress.update(task, completed=completed)

                # Update terminal tab progress bar
                percentage = int((completed / total) * 100)
                _osc_progress_update(percentage)
    finally:
        printer.set_active_progress(None)
        _osc_progress_end()

    errors = len(error_files)
    if errors > 0:
        printer.warning(
            f"Parsing of {len(futures_map)} {scan_type} scans: {successful} "
            f"successful, {errors} with errors:"
        )
        for f in error_files:
            printer.warning(f"  - {f}")

    printer.success(
        f"Succesfull parsed {successful} {scan_type} scan(s) with {hosts} hosts."
    )
    return results


def parse_input_files(args, parser) -> list[Infrastructure]:
    """Parse all input files based on command line arguments."""
    input_args = {}

    # Get scan_group from parser
    scan_group = next(
        (
            group
            for group in parser._action_groups
            if group.title.startswith("input files")
        ),
        None,
    )

    # Check if any input file argument is provided and get name and value
    provided = False
    if scan_group:
        for action in scan_group._group_actions:
            value = getattr(args, action.dest, None)
            if value is not None:
                input_args[str(action.dest)] = value
                provided = True

    if not provided:
        parser.error("At least one input file argument must be provided.")

    def find_all_files(
        paths: list | str | Path, fileextensions: list[str]
    ) -> list[Path]:
        def find_all_files_from_path(
            path: Path, fileextensions: list[str], *, toplevel: bool = True
        ) -> list[Path]:
            if path.is_file():
                if toplevel:
                    return [path]
                if any(path.name.endswith(ext) for ext in fileextensions):
                    return [path]
                return []
            elif is_special_fd(path):
                return [path]

            if path.is_dir():
                return [
                    p
                    for p in path.rglob("*")
                    if p.is_file()
                    and any(p.name.endswith(ext) for ext in fileextensions)
                ]
            return []

        def flatten_list(nested_list):
            for item in nested_list:
                if isinstance(item, list):
                    yield from flatten_list(item)
                else:
                    yield item

        paths = [Path(p) for p in flatten_list(paths)]
        output = []
        for path in paths:
            output.extend(find_all_files_from_path(path, fileextensions))
        return output

    all_infras = []
    tasks = []  # List of (input_type, parser_func, files)
    total_files_count = 0

    # Process each input type if provided
    for input_type, files in input_args.items():
        if not files:
            continue

        # For provided types with dedicated parser modules use the CONFIG from the parser
        parser_name = f"{input_type}_parser"
        if parser_name not in avail_parsers:
            printer.warning(f"No parser available for {input_type} reports. Skipping.")
            continue

        config = avail_parsers[parser_name].CONFIG

        input_files = find_all_files(files, config["extensions"])
        if input_files:
            tasks.append((input_type, avail_parsers[parser_name].parse, input_files))
            total_files_count += len(input_files)

    # Adaptive strategy: Use ProcessPoolExecutor for large batches to bypass GIL,
    # but ThreadPoolExecutor for small batches to avoid process startup overhead.
    log_level = logger.level
    use_processes = total_files_count >= 10

    if use_processes:
        executor = concurrent.futures.ProcessPoolExecutor(
            initializer=_worker_init, initargs=(log_level,)
        )
    else:
        executor = concurrent.futures.ThreadPoolExecutor()

    with executor:
        # 1. Submit all tasks
        future_groups = []
        for input_type, parser_func, input_files in tasks:
            futures_map = {
                executor.submit(process_file, parser_func, f): f for f in input_files
            }
            future_groups.append((input_type, futures_map))

        # 2. Collect results (preserving output order)
        for input_type, futures_map in future_groups:
            printer.status(f"Parsing {input_type.capitalize()} Scans")
            all_infras += collect_scan_results(
                futures_map,
                scan_type=input_type,
                quiet=args.quiet,
                verbose=getattr(args, "verbose", 0) > 0,
            )

    return all_infras
