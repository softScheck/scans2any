"""
Writers for different output formats.
"""

import re
from importlib import import_module
from pathlib import Path

from scans2any.internal.protocols import ParserProtocol

module_files = (
    mod_file
    for mod_file in Path(__file__).parent.glob("*_parser.py")
    if mod_file.is_file()
)

avail_parsers: dict[str, ParserProtocol] = {}

for mod_file in module_files:
    mod_name = mod_file.stem
    # merge_file_parser ist not a normal parser, that we want to use for normal
    # parsing tasks
    if mod_name == "merge_file_parser":
        continue
    if re.match(r"^[a-zA-Z_]+_parser$", mod_name):
        pkg_name = f"{__package__}.{mod_name}"
        try:
            mod = import_module(pkg_name)
            avail_parsers[mod_name] = mod  # type: ignore[assignment]
        except ImportError as e:
            print(f"Failed to import {pkg_name}: {e}")  # noqa: T201

# Collect custom column declarations from all parsers.
# parser_custom_columns: mapping of normalized-lowercase -> canonical name for
#   every column explicitly declared by a parser.
#   sets CUSTOM_COLUMNS = None, meaning it accepts arbitrary column names.
parser_custom_columns: dict[str, str] = {}

for _mod in avail_parsers.values():
    _custom = getattr(_mod, "CUSTOM_COLUMNS", {})
    if isinstance(_custom, dict):
        parser_custom_columns.update(_custom)
