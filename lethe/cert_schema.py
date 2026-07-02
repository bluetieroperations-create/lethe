"""Machine verification of Lethe certificates: JSON-Schema shape check plus
key-pinned cryptographic verification with structured, agent-branchable reasons."""

import json
from functools import lru_cache
from importlib import resources

import jsonschema


@lru_cache(maxsize=1)
def load_schema() -> dict:
    text = (
        resources.files("lethe").joinpath("schemas/certificate-v1.json").read_text()
    )
    return json.loads(text)


def schema_errors(data) -> list[str]:
    validator = jsonschema.Draft202012Validator(load_schema())
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    ]
