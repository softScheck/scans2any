"""Typed sorted set wrapper extending sortedcontainers.SortedSet."""

from typing import TypeVar

from sortedcontainers import SortedSet as BaseSortedSet

T = TypeVar("T")


class SortedSet[T](BaseSortedSet):
    def __str__(self) -> str:
        return "[" + ", ".join(f"'{item!s}'" for item in self) + "]"

    def __repr__(self) -> str:
        return self.__str__()
