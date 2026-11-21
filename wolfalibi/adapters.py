"""Small, proposal-oriented interfaces for future mediated resources.

No API, database, or remote-tool adapter is active in v0.1.  These types keep
their identifiers and event semantics explicit so a future implementation does
not accidentally reuse filesystem proof assumptions for a different resource.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol


@dataclass(frozen=True)
class ResourceEvent:
    """A canonical event proposed by an adapter before broker commitment."""

    resource_kind: str
    identity: bytes
    operation: str
    outcome: str
    metadata: Mapping[str, str] = field(default_factory=dict)

    def canonical_key(self) -> bytes:
        if not self.resource_kind or b"\0" in self.identity:
            raise ValueError("resource kind and identity must be canonical")
        return self.resource_kind.encode("ascii") + b"\0" + self.identity


class ResourceAdapter(Protocol):
    """Future adapters must define canonical identity and complete semantics."""

    kind: str

    def canonical_identity(self, reference: object) -> bytes:
        """Return a stable resource identifier or raise before any effect."""

    def event(self, reference: object, operation: str, outcome: str) -> ResourceEvent:
        """Describe attempted, authorized, actual, and completed states explicitly."""


class AdapterRegistry:
    """Explicit registry; duplicate kinds are a configuration error."""

    def __init__(self):
        self._adapters: dict[str, ResourceAdapter] = {}

    def register(self, adapter: ResourceAdapter) -> None:
        kind = getattr(adapter, "kind", None)
        if not isinstance(kind, str) or not kind:
            raise ValueError("adapter kind must be a nonempty string")
        if kind in self._adapters:
            raise ValueError(f"adapter kind already registered: {kind}")
        self._adapters[kind] = adapter

    def get(self, kind: str) -> ResourceAdapter:
        try:
            return self._adapters[kind]
        except KeyError as ex:
            raise KeyError(f"no adapter registered for {kind!r}") from ex

    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))
