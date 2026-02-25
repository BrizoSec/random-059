"""Abstract base class for all enrichment store implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod


class EnrichmentStore(ABC):
    @abstractmethod
    def load(self) -> dict:
        """Load and return the full enrichment dataset as a plain dict."""
        ...
