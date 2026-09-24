"""PoC generation — builds reproducible proof-of-concept payloads from findings.

Generates curl commands, HTTP request transcripts, and step-by-step PoC
blocks suitable for HackerOne / Bugcrowd submissions.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def generate_curl_poc(
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    insecure: bool = True,
) -> str:
    """Generate a copy-pasteable curl command for a request."""
    parts = ["curl", f"-X {method.upper()}"]
    if insecure:
        parts.append("-k")
    for k, v in (headers or {}).items():
        if k.lower() in ("host", "content-length"):
            continue
        parts.append(f"-H {_shell_quote(f'{k}: {v}')}")
    if body:
        parts.append(f"--data-raw {_shell_quote(body)}")
    parts.append(_shell_quote(url))
    return " \\\n  ".join(parts)


def generate_http_transcript(
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    status: int = 0,
    response_snippet: str = "",
) -> str:
    """Generate a raw HTTP request/response transcript."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    host = parsed.netloc or "target"

    lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in (headers or {}).items():
        if k.lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)

    if status:
        lines.append("")
        lines.append(f"--- Response ({status}) ---")
        if response_snippet:
            lines.append(response_snippet[:500])

    return "\n".join(lines)


def inject_payload_into_url(url: str, param: str, payload: str) -> str:
    """Replace or append a query parameter with the payload."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    # Flatten multi-values
    flat = {k: v[0] if isinstance(v, list) and v else v for k, v in qs.items()}
    flat[param] = payload
    new_query = urlencode(flat, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def generate_poc_from_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a full PoC package from a finding dict.

    Returns:
        {
          "curl": str,
          "transcript": str,
          "steps": list[str],
          "payload": str | None,
        }
    """
    method = str(finding.get("method") or finding.get("http_method") or "GET")
    url = finding.get("endpoint") or finding.get("url") or finding.get("url") or ""
    headers = finding.get("request", {}).get("headers") if isinstance(finding.get("request"), dict) else finding.get("headers") or {}
    body = None
    if isinstance(finding.get("request"), dict):
        body = finding["request"].get("body") or finding["request"].get("data")
    elif finding.get("body"):
        body = finding["body"]

    evidence = finding.get("evidence", "")
    if isinstance(evidence, list):
        evidence_str = str(evidence[0]) if evidence else ""
    else:
        evidence_str = str(evidence)

    # Try to extract a payload from steps / evidence
    payload = finding.get("payload")
    param = finding.get("parameter") or finding.get("param")
    if not payload and param and url:
        # Heuristic: use first reproduction step if it contains the param
        pass

    # Build PoC URL with payload if we have both
    poc_url = url
    if payload and param and url:
        poc_url = inject_payload_into_url(url, param, payload)

    curl = generate_curl_poc(method=method, url=poc_url or url, headers=headers, body=body)
    transcript = generate_http_transcript(
        method=method,
        url=poc_url or url,
        headers=headers,
        body=body,
        status=finding.get("status_code") or finding.get("status") or 0,
        response_snippet=evidence_str,
    )

    # Prefer existing reproduction steps; else synthesize from finding fields
    steps = list(finding.get("reproduction") or finding.get("steps") or [])
    if isinstance(steps, str):
        steps = [s for s in steps.split("\n") if s.strip()]
    if not steps:
        steps = [
            f"Send {method.upper()} request to {poc_url or url}",
            "Observe the response matching the evidence below",
            f"Evidence: {evidence_str[:200]}" if evidence_str else "Confirm unauthorized behavior",
        ]

    return {
        "curl": curl,
        "transcript": transcript,
        "steps": steps,
        "payload": payload,
        "poc_url": poc_url,
    }


def render_poc_markdown(finding: dict[str, Any]) -> str:
    """Render a PoC block as Markdown for reports."""
    poc = generate_poc_from_finding(finding)
    lines = [
        "### Proof of Concept",
        "",
        "**Steps:**",
    ]
    for i, step in enumerate(poc["steps"], 1):
        lines.append(f"{i}. {step}")
    lines += [
        "",
        "**Request (curl):**",
        "",
        "```bash",
        poc["curl"],
        "```",
    ]
    if poc.get("payload"):
        lines += ["", f"**Payload:** `{poc['payload']}`"]
    lines += [
        "",
        "**Raw transcript:**",
        "",
        "```http",
        poc["transcript"],
        "```",
    ]
    return "\n".join(lines)
