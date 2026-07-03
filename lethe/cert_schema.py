"""Machine verification of Lethe certificates: JSON-Schema shape check plus
key-pinned cryptographic verification with structured, agent-branchable reasons."""

import copy
import json
from functools import lru_cache
from importlib import resources

import jsonschema


@lru_cache(maxsize=1)
def _load_schema() -> dict:
    text = (
        resources.files("lethe").joinpath("schemas/certificate-v1.json").read_text()
    )
    return json.loads(text)


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(_load_schema())


def load_schema() -> dict:
    """Return the certificate v1 JSON Schema.

    Returns a defensive deep copy: the cached schema dict is shared process-wide,
    so callers must never be handed the mutable original.
    """
    return copy.deepcopy(_load_schema())


def schema_errors(data) -> list[str]:
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(
            _validator().iter_errors(data),
            key=lambda e: [str(x) for x in e.absolute_path],
        )
    ]
