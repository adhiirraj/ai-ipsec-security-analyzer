"""Comprehensive Rule-Based Security Assessment Engine for IPsec."""

from typing import Any, Dict, List

# Comprehensive ranking of algorithms
ALGORITHM_STRENGTHS = {
    # Encryption (IKE and ESP)
    "null": {"strength": "critical", "score": -50, "threats": ["Eavesdropping", "Data Exfiltration"]},
    "des": {"strength": "critical", "score": -40, "threats": ["Brute Force"]},
    "3des": {"strength": "weak", "score": -20, "threats": ["Sweet32", "Brute Force"]},
    "rc4": {"strength": "critical", "score": -40, "threats": ["RC4 Biases", "Brute Force"]},
    "aes128-ctr": {"strength": "weak", "score": -15, "threats": ["Bit-Flipping (if no HMAC)"]},
    "aes256-ctr": {"strength": "weak", "score": -15, "threats": ["Bit-Flipping (if no HMAC)"]},
    "aes-ctr": {"strength": "weak", "score": -15, "threats": ["Bit-Flipping (if no HMAC)"]},
    "aes-cbc": {"strength": "acceptable", "score": 0, "threats": []},
    "aes128-cbc": {"strength": "acceptable", "score": 0, "threats": []},
    "aes192-cbc": {"strength": "acceptable", "score": 0, "threats": []},
    "aes256-cbc": {"strength": "strong", "score": 5, "threats": []},
    "aes-gcm": {"strength": "strong", "score": 10, "threats": []},
    "aes128gcm16": {"strength": "strong", "score": 10, "threats": []},
    "aes256gcm16": {"strength": "strong", "score": 10, "threats": []},
    "chacha20poly1305": {"strength": "strong", "score": 10, "threats": []},
    
    # Hashing / Integrity
    "none": {"strength": "critical", "score": -40, "threats": ["MITM", "Message Forgery", "Bit-Flipping"]},
    "md5": {"strength": "critical", "score": -30, "threats": ["Collision Attacks", "MITM"]},
    "sha1": {"strength": "weak", "score": -20, "threats": ["Collision Attacks"]},
    "sha256": {"strength": "acceptable", "score": 0, "threats": []},
    "sha384": {"strength": "strong", "score": 5, "threats": []},
    "sha512": {"strength": "strong", "score": 5, "threats": []},
    "prfsha256": {"strength": "acceptable", "score": 0, "threats": []},
    "prfsha384": {"strength": "strong", "score": 5, "threats": []},
    
    # DH Groups
    "none": {"strength": "critical", "score": -50, "threats": ["Key Compromise", "Passive Decryption"]},
    "modp768": {"strength": "critical", "score": -40, "threats": ["Logjam", "Precomputation"]},
    "modp1024": {"strength": "weak", "score": -20, "threats": ["Logjam", "State-Level Decryption"]},
    "modp1536": {"strength": "weak", "score": -15, "threats": ["State-Level Decryption"]},
    "modp2048": {"strength": "acceptable", "score": 0, "threats": []},
    "modp3072": {"strength": "strong", "score": 5, "threats": []},
    "modp4096": {"strength": "strong", "score": 5, "threats": []},
    "ecp256": {"strength": "strong", "score": 5, "threats": []},
    "ecp384": {"strength": "strong", "score": 5, "threats": []},
    "ecp521": {"strength": "strong", "score": 5, "threats": []},
    "curve25519": {"strength": "strong", "score": 10, "threats": []},
    "curve448": {"strength": "strong", "score": 10, "threats": []},
}

def evaluate_algorithm(category: str, alg: str) -> Dict[str, Any]:
    alg_lower = alg.lower()
    
    # Fallbacks and string matching
    if alg_lower == "unknown" or not alg_lower:
        return {"strength": "unknown", "score": -5, "message": f"{category} algorithm is unknown or missing.", "threats": ["Unknown Vulnerabilities"]}
        
    found_key = None
    for key in ALGORITHM_STRENGTHS.keys():
        if key in alg_lower or alg_lower in key:
            found_key = key
            break
            
    if not found_key:
        return {"strength": "unknown", "score": -5, "message": f"{category} algorithm '{alg}' is unrecognized.", "threats": ["Unknown Vulnerabilities"]}

    info = ALGORITHM_STRENGTHS[found_key]
    strength = info["strength"]
    
    if strength == "critical":
        msg = f"{category} ('{alg}') provides critically low or NO security. Immediate upgrade required."
    elif strength == "weak":
        msg = f"{category} ('{alg}') is considered weak/deprecated by modern standards (NIST/BSI)."
    elif strength == "acceptable":
        msg = f"{category} ('{alg}') provides acceptable baseline security."
    else:
        msg = f"{category} ('{alg}') provides strong, modern security."
        
    return {
        "strength": strength,
        "score": info["score"],
        "message": msg,
        "threats": info["threats"]
    }

def assess_configuration(config: Dict[str, Any]) -> Dict[str, Any]:
    score = 100
    findings = []
    threats = set()
    
    # Track metrics for reports
    is_aead = False
    pfs_enabled = config.get("pfs_enabled", False)
    
    # 1. IKE Encryption
    if config.get("enc_alg"):
        res = evaluate_algorithm("IKE Encryption", config["enc_alg"])
        findings.append({"category": "IKE Encryption", "severity": res["strength"].upper(), "message": res["message"]})
        score += res["score"]
        threats.update(res["threats"])
        
    # 2. IKE Hashing
    if config.get("hash_alg"):
        res = evaluate_algorithm("IKE Hashing", config["hash_alg"])
        findings.append({"category": "IKE Hashing", "severity": res["strength"].upper(), "message": res["message"]})
        score += res["score"]
        threats.update(res["threats"])
        
    # 3. Key Exchange (DH)
    if config.get("dh_group"):
        res = evaluate_algorithm("Key Exchange (DH)", config["dh_group"])
        findings.append({"category": "Key Exchange", "severity": res["strength"].upper(), "message": res["message"]})
        score += res["score"]
        threats.update(res["threats"])
        
    # 4. Perfect Forward Secrecy (PFS)
    if not pfs_enabled:
        findings.append({
            "category": "Forward Secrecy",
            "severity": "HIGH", 
            "message": "Perfect Forward Secrecy (PFS) is DISABLED. Long-term key compromise will expose all traffic."
        })
        score -= 25
        threats.add("Retrospective Decryption (Harvest Now, Decrypt Later)")
    else:
        findings.append({
            "category": "Forward Secrecy",
            "severity": "STRONG",
            "message": "Perfect Forward Secrecy (PFS) is enabled. Session keys are protected."
        })
        score += 10
        
    # 5. ESP Encryption and HMAC
    esp_enc = config.get("esp_enc", "unknown")
    esp_integrity = config.get("esp_integrity", "none")
    
    if esp_enc != "unknown":
        res_enc = evaluate_algorithm("ESP Encryption", esp_enc)
        findings.append({"category": "ESP Encryption", "severity": res_enc["strength"].upper(), "message": res_enc["message"]})
        score += res_enc["score"]
        threats.update(res_enc["threats"])
        
        if "gcm" in esp_enc.lower() or "chacha20" in esp_enc.lower():
            is_aead = True
            findings.append({
                "category": "ESP Integrity",
                "severity": "STRONG",
                "message": f"Phase 2 uses AEAD cipher ({esp_enc}). Integrity is built-in. No explicit HMAC needed."
            })
            score += 10
        else:
            if esp_integrity == "none" or not esp_integrity:
                findings.append({
                    "category": "ESP Integrity",
                    "severity": "CRITICAL",
                    "message": f"Phase 2 uses {esp_enc} WITHOUT an HMAC (Null Integrity)! Highly vulnerable to active manipulation."
                })
                score -= 40
                threats.add("Bit-Flipping")
                threats.add("Message Forgery")
            else:
                res_int = evaluate_algorithm("ESP Integrity (HMAC)", esp_integrity)
                findings.append({"category": "ESP Integrity", "severity": res_int["strength"].upper(), "message": res_int["message"]})
                score += res_int["score"]
                threats.update(res_int["threats"])

    # Traffic / Metadata analysis rules
    # IPsec hides payload but exposes traffic patterns
    threats.add("Traffic Analysis (Metadata Extraction)")
    
    # Cap score
    score = max(0, min(100, score))
    
    if score >= 90:
        risk = "LOW"
    elif score >= 70:
        risk = "MEDIUM"
    elif score >= 40:
        risk = "HIGH"
    else:
        risk = "CRITICAL"
        
    # Generate Executive Report
    if risk in ["LOW", "MEDIUM"]:
        exec_report = (
            f"The analyzed IPsec VPN tunnel demonstrates a {risk} risk posture with an overall security score of {score}/100. "
            "Confidentiality and integrity mechanisms are largely aligned with industry best practices, ensuring secure data transit."
        )
    else:
        exec_report = (
            f"The analyzed IPsec VPN tunnel is in a {risk} risk posture (Score: {score}/100). "
            "Critical vulnerabilities were detected in the cryptographic configuration that may allow attackers to intercept, "
            "decrypt, or manipulate sensitive data in transit. Immediate remediation is strongly advised."
        )

    # Generate Technical Report
    tech_report = (
        f"IKE Phase 1 negotiated {config.get('enc_alg', 'unknown').upper()} / {config.get('hash_alg', 'unknown').upper()} "
        f"with DH Group {config.get('dh_group', 'unknown').upper()}. "
        f"IPsec Phase 2 (ESP) utilizes {esp_enc.upper()}" + (f" with AEAD built-in integrity." if is_aead else f" paired with {esp_integrity.upper()} HMAC. ") +
        f"Perfect Forward Secrecy is {'ENABLED' if pfs_enabled else 'DISABLED'}."
    )
        
    return {
        "status": "assessed",
        "score": score,
        "risk_level": risk,
        "executive_report": exec_report,
        "technical_report": tech_report,
        "threat_matrix": list(threats),
        "findings": findings,
        "compliance": "NIST SP 800-77 Rev. 1 Compliant" if score >= 90 else "Non-Compliant with NIST/BSI Standards",
        "config": config
    }
