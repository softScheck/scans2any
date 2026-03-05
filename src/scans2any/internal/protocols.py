"""Structural protocols for parser and writer plug-ins.

Every parser module (``*_parser.py``) and writer module (``*_writer.py``) is
loaded dynamically at import time.  The protocols defined here document the
interface each module must satisfy.  They are decorated with
``@runtime_checkable`` so that ``isinstance`` checks can be used to narrow
types inside the application code.

Optional parser conventions (not part of the protocol, accessed via
``getattr`` with a fallback):

* ``CUSTOM_COLUMNS: dict[str, str] | None`` declares extra columns the
  parser can produce beyond the built-in set.  Each key is the
  normalised (lower-case) column name; the value is the display name shown
  to end-users.  ``None`` signals an *open-format* parser (e.g. the JSON
  round-trip parser) that accepts arbitrary column names.  Parsers that do
  not declare ``CUSTOM_COLUMNS`` are assumed to produce no custom columns.
"""

from argparse import ArgumentParser, _ArgumentGroup
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from scans2any.internal import Infrastructure


@runtime_checkable
class HasAddArguments(Protocol):
    """Protocol for writer modules that expose additional CLI arguments.

    Writers that need format-specific options (e.g. ``--markdown-style``)
    implement this method.  The CLI layer checks ``isinstance(obj,
    HasAddArguments)`` to decide whether to call it, so the protocol must be
    ``@runtime_checkable``.
    """

    def add_arguments(self, group: _ArgumentGroup) -> None:
        """Register writer-specific arguments into *group*.

        *group* is an :class:`argparse._ArgumentGroup` already attached to the
        main argument parser.  Implementations should call
        ``group.add_argument(...)`` for each option they need.
        """
        ...


@runtime_checkable
class ParserProtocol(Protocol):
    """Protocol for input-format parser modules.

    Each ``*_parser.py`` module under ``scans2any/parsers/`` must expose the
    attributes and methods defined here.  Modules are discovered and loaded
    dynamically; this protocol documents the expected interface.

    Attributes
    ----------
    CONFIG:
        A dict of file-extension (or format) metadata used by the auto-detect
        logic to decide which parser to apply to a given input file.

    Optional module-level attributes (not required by the protocol):

    CUSTOM_COLUMNS : dict[str, str] | None
        Declared extra output columns.  See the module docstring for details.
    """

    CONFIG: dict[str, Any]

    def add_arguments(self, parser: ArgumentParser) -> None:
        """Register parser-specific CLI arguments into *parser*."""
        ...

    def parse(self, filename: str | Path) -> Infrastructure:
        """Parse *filename* and return the resulting :class:`Infrastructure`."""
        ...


@runtime_checkable
class WriterProtocol(Protocol):
    """Protocol for output-format writer modules.

    Each ``*_writer.py`` module under ``scans2any/writers/`` must expose the
    attributes and method defined here.  Modules are discovered and loaded
    dynamically; this protocol documents the expected interface.

    Attributes
    ----------
    NAME:
        Short identifier for the writer, used as the value of the ``--writer``
        CLI option (e.g. ``"markdown"``, ``"csv"``).
    PROPERTIES:
        A dict of writer metadata (e.g. whether the output is binary, default
        file extension, etc.) consulted by the output layer.
    """

    NAME: str
    PROPERTIES: dict[str, Any]

    def write(self, infra: Infrastructure, args: Any) -> str | bytes:
        """Convert *infra* to the target format and return the result.

        Parameters
        ----------
        infra:
            The fully merged and filtered :class:`Infrastructure` to render.
        args:
            The parsed argument namespace; writers access their own options
            through attributes added via :meth:`HasAddArguments.add_arguments`.

        Returns
        -------
        str | bytes
            Rendered output.  Return ``bytes`` only for binary formats.
        """
        ...
