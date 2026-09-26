"""Evidence-aware, deterministic security assessment rules.

The assessor accepts observed or explicitly supplied configuration values. It
never turns unavailable encrypted ESP information into a finding about a
specific algorithm or PFS setting.
"""

from __future__ import annotations

from typing import Any


ALGORITHM_STRENGTHS = {
    "aes128-cbc": "acceptable",
    "aes256-cbc": "strong",
    "aes128-ctr": "weak",
    "aes256-ctr": "weak",
    "aes128gcm16": "strong",
    "aes256gcm16": "strong",
    "3des": "weak",
    "des": "weak",
    "null": "critical",
    "md5": "critical",
    "sha1": "weak",
    "sha256": "acceptable",
    "sha384": "strong",
    "sha512": "strong",
    "prfsha256": "acceptable",
    "prfsha384": "strong",
    "modp1024": "weak",
    "modp1536": "weak",
    "modp2048": "acceptable",
    "modp3072": "strong",
    "modp4096": "strong",
    "ecp256": "strong",
    "ecp384": "strong",
    "ecp521": "strong",
    "x25519": "strong",
}

SEVERITY_SCORES = {"critical": 30, "weak": 15, "acceptable": 0, "strong": -5}
_UNKNOWN_VALUES = {None, "", "unknown", "not-observed", "not_observed"}


def evaluate_algorithm(category: str, algorithm: str) -> dict[str, Any]:
    """Assess one named algorithm and return a traceable rule result."""

    normalized = algorithm.lower()
    strength = ALGORITHM_STRENGTHS.get(normalized, "unknown")
    messages = {
        "critical": f"{category} algorithm '{algorithm}' provides no acceptable security.",
        "weak": f"{category} algorithm '{algorithm}' is weak or deprecated.",
        "acceptable": f"{category} algorithm '{algorithm}' provides acceptable baseline security.",
        "strong": f"{category} algorithm '{algorithm}' provides strong modern security.",
        "unknown": f"{category} algorithm '{algorithm}' is unrecognized and was not scored.",
    }
    severity = {"critical": "CRITICAL", "weak": "HIGH", "unknown": "WARNING"}.get(
        strength, "INFO"
    )
    return {
        "severity": severity,
        "message": messages[strength],
        "penalty": SEVERITY_SCORES.get(strength, 0),
        "evidence": {"category": category, "algorithm": algorithm, "strength": strength},
    }


def _append_algorithm_finding(
    findings: list[dict[str, Any]], category: str, value: Any
) -> int:
    if value in _UNKNOWN_VALUES:
        findings.append(
            {
                "severity": "INFO",
                "message": f"{category} was not observable in the supplied evidence and was not scored.",
                "evidence": {"category": category, "value": "unknown"},
            }
        )
        return 0
    result = evaluate_algorithm(category, str(value))
    findings.append({key: item for key, item in result.items() if key != "penalty"})
    return int(result["penalty"])


def assess_configuration(config: dict[str, Any]) -> dict[str, Any]:
    """Assess known configuration values without guessing missing IPsec details."""

    score = 100
    findings: list[dict[str, Any]] = []
    score -= _append_algorithm_finding(findings, "IKE encryption", config.get("enc_alg"))
    score -= _append_algorithm_finding(findings, "IKE PRF", config.get("hash_alg"))
    score -= _append_algorithm_finding(findings, "IKE key exchange", config.get("dh_group"))

    pfs = config.get("pfs_enabled")
    if pfs is True:
        findings.append(
            {
                "severity": "INFO",
                "message": "PFS is enabled in supplied configuration.",
                "evidence": {"category": "PFS", "value": True},
            }
        )
        score += 5
    elif pfs is False:
        findings.append(
            {
                "severity": "HIGH",
                "message": "PFS is disabled in supplied configuration.",
                "evidence": {"category": "PFS", "value": False},
            }
        )
        score -= 20
    else:
        findings.append(
            {
                "severity": "INFO",
                "message": "PFS is not observable from the supplied evidence and was not scored.",
                "evidence": {"category": "PFS", "value": "unknown"},
            }
        )

    esp_encryption = config.get("esp_enc")
    esp_integrity = config.get("esp_integrity")
    if esp_encryption in _UNKNOWN_VALUES:
        findings.append(
            {
                "severity": "INFO",
                "message": "ESP algorithms are encrypted or absent and were not scored.",
                "evidence": {"category": "ESP", "value": "unknown"},
            }
        )
    elif "gcm" in str(esp_encryption).lower() or "chacha20" in str(esp_encryption).lower():
        findings.append(
            {
                "severity": "INFO",
                "message": f"ESP uses supplied AEAD cipher '{esp_encryption}'; separate integrity is not required.",
                "evidence": {"category": "ESP encryption", "algorithm": esp_encryption},
            }
        )
    else:
        score -= _append_algorithm_finding(findings, "ESP encryption", esp_encryption)
        if esp_integrity in _UNKNOWN_VALUES:
            findings.append(
                {
                    "severity": "INFO",
                    "message": "ESP integrity was not observable and was not scored.",
                    "evidence": {"category": "ESP integrity", "value": "unknown"},
                }
            )
        elif str(esp_integrity).lower() == "none":
            findings.append(
                {
                    "severity": "CRITICAL",
                    "message": "Supplied non-AEAD ESP configuration uses null integrity.",
                    "evidence": {"category": "ESP integrity", "value": "none"},
                }
            )
            score -= 40
        else:
            score -= _append_algorithm_finding(findings, "ESP integrity", esp_integrity)

    score = max(0, min(100, score))
    risk_level = (
        "LOW" if score >= 90 else "MEDIUM" if score >= 70 else "HIGH" if score >= 40 else "CRITICAL"
    )
    return {
        "status": "assessed",
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
        "config": dict(config),
    }
