"""Prints a flattened CSV representation of the infrastructure."""

from scans2any.internal import Infrastructure, printer

NAME = "csv"
PROPERTIES = {
    "binary": False,
    "ignore-conflicts": False,
}


def add_arguments(parser):
    """
    Add merge symbol argument to the parser.
    """
    parser.add_argument(
        "--merge-symbol",
        type=str,
        default=" - ",
        help="Merge symbol for columns with multiple values",
    )


def write(infra: Infrastructure, args) -> str:
    """
    Convert the internal representation of the infrastructure
    into the csv format.
    """
    # Deferred import: keeps pandas/numpy out of the startup critical path.
    from scans2any.writers.dataframe_creator import create_flat_dataframe

    infra.cleanup_names(",-")  # Comma as separator, minus for multiple items

    # Create a flattened DataFrame (one row per service)
    df = create_flat_dataframe(
        infra, columns=args.columns, merge_symbol=args.merge_symbol
    )

    # Convert to CSV without index
    csv_output = df.to_csv(index=False)

    printer.success(f"CSV with {len(df)} rows has been created from parsed input data")

    return csv_output
