"""Prints a Excel representation of the infrastructure."""

import io

from scans2any.internal import Infrastructure, printer

NAME = "excel"
PROPERTIES = {
    "binary": True,
    "ignore-conflicts": False,
}


def add_arguments(parser):
    """
    Add flattened argument to the parser.
    """
    parser.add_argument(
        "--flattened",
        action="store_true",
        default=False,
        help="Creates flattened table format",
    )


def write(infra: Infrastructure, args) -> str | bytes:
    """
    Convert the internal representation of the infrastructure
    into Excel format.

    Parameters
    ----------
    infra : Infrastructure
        The infrastructure to convert
    columns : tuple[str, ...], optional
        The columns to include in the Excel file, by default all columns
    multi_table : bool, optional
        Whether to create one table for all hosts or one per host, by default True
    flattened : bool, optional
        Whether to create a flattened table (one row per service), by default False

    Returns
    -------
    bytes
        The Excel file as bytes
    """
    # Deferred imports: keeps pandas/numpy out of the startup critical path.
    import pandas as pd

    from scans2any.writers.dataframe_creator import (
        create_dataframes,
        create_flat_dataframe,
    )

    # infra.cleanup_names("")

    output = io.BytesIO()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        if args.flattened:
            # Create a flattened DataFrame (one row per service)
            df = create_flat_dataframe(infra, columns=args.columns, merge_symbol="\n")
            df.to_excel(writer, sheet_name="Services", index=False)
            printer.success(f"Excel sheet created with {len(df)} rows")
        else:
            # Create regular DataFrames
            dfs = create_dataframes(
                infra,
                columns=args.columns,
                multi_table=args.multi_table,
                merge_symbol="\n",
            )
            if args.multi_table:
                # Create a sheet per host
                for i, df in enumerate(dfs):
                    host_name = f"Host {i + 1}"
                    df.to_excel(writer, sheet_name=host_name, index=False)
                printer.success(f"Excel file created with {len(dfs)} host sheets")
            else:
                dfs[0].to_excel(writer, sheet_name="All Hosts", index=False)
                printer.success(f"Excel sheet created with {len(dfs[0])} hosts")

    # Return bytes
    output.seek(0)
    return output.getvalue()
