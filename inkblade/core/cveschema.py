# -*- coding: utf-8 -*-
"""Minimal JSON-Schema validator for CVE 5.x records.

The project ships no third-party runtime dependencies, so this module
implements the JSON Schema draft-07 subset that the official CVE record
schema (``disclosure/schema/CVE_Record_Format.json``) actually uses:
``$ref`` (local and ``file:`` imports), ``type``, ``required``, ``properties``,
``patternProperties``, ``additionalProperties``, ``items``, ``minItems``,
``maxItems``, ``uniqueItems``, ``contains``, ``enum``, ``const``, ``pattern``,
``minLength``, ``maxLength``, ``minimum``, ``maximum``, ``allOf``, ``anyOf``,
``oneOf`` and ``not``.

It is deliberately strict: an unknown keyword is ignored (JSON Schema
semantics), but a violated known keyword is reported with a JSON pointer so a
broken submission cannot pass silently.  Callers that have the optional
``jsonschema`` package installed can additionally run the reference validator
(see ``tests/test_disclosure_packages.py``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "disclosure" / "schema"
DEFAULT_SCHEMA = SCHEMA_ROOT / "CVE_Record_Format.json"


class SchemaError(ValueError):
    """Raised when an instance does not satisfy the bundled CVE schema."""

    def __init__(self, errors: Iterable[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors[:10]))


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _type_matches(value: Any, expected: str) -> bool:
    actual = _json_type(value)
    if expected == "number":
        return actual in ("number", "integer")
    return actual == expected


class Validator:
    def __init__(self, schema_path: Path | str = DEFAULT_SCHEMA):
        self.schema_path = Path(schema_path)
        self.root = json.loads(self.schema_path.read_text(encoding="utf-8"))
        self.base = self.schema_path.parent
        self._cache: dict[Path, dict] = {self.schema_path: self.root}

    def _load(self, path: Path) -> dict:
        if path not in self._cache:
            self._cache[path] = json.loads(path.read_text(encoding="utf-8"))
        return self._cache[path]

    def _resolve(self, ref: str, doc: dict, doc_path: Path) -> tuple[dict, dict, Path]:
        if ref.startswith("#/"):
            node: Any = doc
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                try:
                    node = node[part]
                except (KeyError, TypeError):
                    raise SchemaError([f"{ref}: unresolved local $ref in {doc_path.name}"])
            return node, doc, doc_path
        if ref.startswith("file:"):
            target = (self.base / ref[5:]).resolve()
            document = self._load(target)
            return document, document, target
        raise SchemaError([f"unsupported $ref {ref!r}"])

    def validate(self, instance: Any) -> None:
        errors: list[str] = []
        self._validate(instance, self.root, "$", errors, self.root, self.schema_path, depth=0)
        if errors:
            raise SchemaError(errors)

    def is_valid(self, instance: Any) -> bool:
        try:
            self.validate(instance)
        except SchemaError:
            return False
        return True

    # -- internals ---------------------------------------------------------
    def _validate(self, value: Any, schema: dict, path: str, errors: list[str],
                  doc: dict, doc_path: Path, depth: int) -> None:
        if depth > 64:
            errors.append(f"{path}: $ref depth exceeded")
            return
        if not isinstance(schema, dict):
            return
        if "$ref" in schema:
            target, target_doc, target_path = self._resolve(str(schema["$ref"]), doc, doc_path)
            self._validate(value, target, path, errors, target_doc, target_path, depth + 1)
            # draft-07 ignores sibling keywords of $ref
            return

        if "type" in schema:
            expected = schema["type"]
            types = expected if isinstance(expected, list) else [expected]
            if not any(_type_matches(value, t) for t in types):
                errors.append(f"{path}: expected type {expected}, got {_json_type(value)}")
                return

        if "const" in schema and value != schema["const"]:
            errors.append(f"{path}: expected const {schema['const']!r}, got {value!r}")
        if "enum" in schema and value not in schema["enum"]:
            errors.append(f"{path}: value {value!r} not in enum")

        if isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                errors.append(f"{path}: shorter than minLength {schema['minLength']}")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                errors.append(f"{path}: longer than maxLength {schema['maxLength']}")
            if "pattern" in schema and not re.search(schema["pattern"], value):
                errors.append(f"{path}: does not match pattern {schema['pattern']}")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                errors.append(f"{path}: below minimum {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                errors.append(f"{path}: above maximum {schema['maximum']}")

        if isinstance(value, list):
            if "minItems" in schema and len(value) < schema["minItems"]:
                errors.append(f"{path}: fewer than minItems {schema['minItems']}")
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                errors.append(f"{path}: more than maxItems {schema['maxItems']}")
            if schema.get("uniqueItems"):
                seen = set()
                for item in value:
                    key = json.dumps(item, sort_keys=True, ensure_ascii=False)
                    if key in seen:
                        errors.append(f"{path}: duplicate item with uniqueItems")
                        break
                    seen.add(key)
            if "items" in schema:
                for index, item in enumerate(value):
                    self._validate(item, schema["items"], f"{path}/{index}", errors, doc, doc_path, depth + 1)
            if "contains" in schema:
                if not any(self._branch_ok(item, schema["contains"], doc, doc_path) for item in value):
                    errors.append(f"{path}: no item matches contains")

        if isinstance(value, dict):
            if "minProperties" in schema and len(value) < schema["minProperties"]:
                errors.append(f"{path}: fewer than minProperties {schema['minProperties']}")
            if "maxProperties" in schema and len(value) > schema["maxProperties"]:
                errors.append(f"{path}: more than maxProperties {schema['maxProperties']}")
            for name in schema.get("required") or []:
                if name not in value:
                    errors.append(f"{path}: missing required property {name!r}")
            properties = schema.get("properties") or {}
            patterns = schema.get("patternProperties") or {}
            for name, item in value.items():
                matched = False
                if name in properties:
                    matched = True
                    self._validate(item, properties[name], f"{path}/{name}", errors, doc, doc_path, depth + 1)
                for pattern, subschema in patterns.items():
                    if re.search(pattern, name):
                        matched = True
                        self._validate(item, subschema, f"{path}/{name}", errors, doc, doc_path, depth + 1)
                if not matched:
                    extra = schema.get("additionalProperties", True)
                    if extra is False:
                        errors.append(f"{path}: additional property {name!r} is not allowed")
                    elif isinstance(extra, dict):
                        self._validate(item, extra, f"{path}/{name}", errors, doc, doc_path, depth + 1)

        if "allOf" in schema:
            for subschema in schema["allOf"]:
                self._validate(value, subschema, path, errors, doc, doc_path, depth + 1)
        if "anyOf" in schema:
            if not any(self._branch_ok(value, sub, doc, doc_path) for sub in schema["anyOf"]):
                errors.append(f"{path}: does not match any anyOf branch")
        if "oneOf" in schema:
            hits = sum(1 for sub in schema["oneOf"] if self._branch_ok(value, sub, doc, doc_path))
            if hits != 1:
                errors.append(f"{path}: matched {hits} oneOf branches, expected exactly 1")
        if "not" in schema and self._branch_ok(value, schema["not"], doc, doc_path):
            errors.append(f"{path}: matches a forbidden not schema")

    def _branch_ok(self, value: Any, schema: dict, doc: dict, doc_path: Path) -> bool:
        errors: list[str] = []
        self._validate(value, schema, "$", errors, doc, doc_path, depth=0)
        return not errors


def validate_cve_record(record: dict, schema_path: Path | str = DEFAULT_SCHEMA) -> None:
    Validator(schema_path).validate(record)
