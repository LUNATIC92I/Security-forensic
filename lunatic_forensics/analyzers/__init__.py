"""Analyzer registry (extension point: :func:`register_analyzer`)."""
from __future__ import annotations

from . import android, browser, documents, generic, ios, media, messaging, recovery
from .base import Analyzer, ArtifactRecord, Category, FileContext

_REGISTRY: list[Analyzer] = [
    *android.ANALYZERS, *ios.ANALYZERS, *messaging.ANALYZERS, *browser.ANALYZERS,
    *generic.ANALYZERS, *media.ANALYZERS, *documents.ANALYZERS, *recovery.ANALYZERS,
]


def all_analyzers() -> list[Analyzer]:
    return list(_REGISTRY)


def register_analyzer(analyzer: Analyzer) -> None:
    if any(a.name == analyzer.name for a in _REGISTRY):
        raise ValueError(f"Analyzer '{analyzer.name}' already registered")
    _REGISTRY.insert(0, analyzer)


def get_analyzer(name: str) -> Analyzer:
    for a in _REGISTRY:
        if a.name == name:
            return a
    raise KeyError(name)


__all__ = ["Analyzer", "ArtifactRecord", "Category", "FileContext", "all_analyzers", "register_analyzer", "get_analyzer"]
