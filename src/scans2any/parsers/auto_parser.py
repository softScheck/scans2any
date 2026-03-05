"""Auto-detect the input file format and dispatch to the appropriate parser."""

from pathlib import Path

from scans2any.internal import Infrastructure, printer
from scans2any.parsers import avail_parsers

CONFIG = {
    "extensions": [""],
}


def add_arguments(parser):
    """
    Add arguments to the parser for input format.
    """
    parser.add_argument(
        "-a",
        "--auto",
        type=str,
        action="append",
        nargs="+",
        metavar="filename/directory",
        help="Auto-detect and import scans in a directory",
    )


def parse(filename: str | Path) -> Infrastructure:
    filename_path = Path(filename)
    for name, parser in avail_parsers.items():
        # don't call yourself
        if name == "auto_parser":
            continue

        # see if the file ends in one of the valid extensions
        # if not we continue with the next parser
        if not any(
            filename_path.name.endswith(extension)
            for extension in parser.CONFIG["extensions"]
        ):
            continue

        # attempt to parse with the selected parser
        try:
            printer.status(f"Trying parser '{name}' for file '{filename}'")
            infra = parser.parse(filename)
        except Exception:
            continue

        # if the infrastructure is not empty we use it. Otherwise let's try the
        # next parser.
        if infra.hosts:
            return infra

    printer.debug(f"The correct parser for {filename} could not be identified.")
    # return empty infrastructure. None would lead to error messages, that are
    # not wanted
    return Infrastructure()
