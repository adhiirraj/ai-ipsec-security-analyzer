"""Rule-Based Security Assessment Engine for IPsec configurations (NIST/BSI standards)."""

from typing import Any, Dict, List

# NIST / BSI Guidelines for Cryptographic Primitives
# We map common algorithm strings (from swanctl/IKE) to their security strengths.

ALGORITHM_STRENGTHS = {
    # Encryption
    "aes128-cbc": "acceptable",
    "aes256-cbc": "strong",
    "aes128gcm16": "strong",
    "aes256gcm16": "strong",
    "3des": "weak",
    "des": "weak",
    "null": "critical",
    
    # Hashing / Integrity
    "md5": "critical",
    "sha1": "weak",
    "sha256": "acceptable",
    "sha384": "strong",
    "sha512": "strong",
    "prfsha256": "acceptable",
    "prfsha384": "strong",
    
    # DH Groups
    "modp1024": "weak",      # DH Group 2
    "modp1536": "weak",      # DH Group 5
    "modp2048": "acceptable",# DH Group 14
    "modp3072": "strong",    # DH Group 15
    "modp4096": "strong",    # DH Group 16
    "ecp256": "strong",      # DH Group 19
    "ecp384": "strong",      # DH Group 20
    "ecp521": "strong",      # DH Group 21
}

# Penalty scores for vulnerabilities
SEVERITY_SCORES = {
    "critical": 30, # Massive drop in score
    "weak": 15,     # Noticeable drop
    "acceptable": 0,# Baseline (no penalty)
    "strong": -5    # Bonus points!
}

def evaluate_algorithm(category: str, alg: str) -> Dict[str, Any]:
    """Evaluates a single algorithm against known standards."""
    alg_lower = alg.lower()
    strength = ALGORITHM_STRENGTHS.get(alg_lower, "unknown")
    
    if strength == "critical":
        severity = "CRITICAL"
        msg = f"{category} algorithm '{alg}' is catastrophically broken or provides NO security. Immediate upgrade required."
    elif strength == "weak":
        severity = "HIGH"
        msg = f"{category} algorithm '{alg}' is considered weak/deprecated by modern NIST standards."
    elif strength == "acceptable":
        severity = "INFO"
        msg = f"{category} algorithm '{alg}' provides acceptable baseline security."
    elif strength == "strong":
        severity = "INFO"
        msg = f"{category} algorithm '{alg}' provides strong, modern security."
    else:
        severity = "WARNING"
        msg = f"{category} algorithm '{alg}' is unrecognized. Cannot assess strength."
        
    return {"severity": severity, "message": msg, "penalty": SEVERITY_SCORES.get(strength, 5)}

def assess_configuration(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates an IPsec configuration dictionary and returns a full Security Assessment.
    Expected keys: 'enc_alg', 'hash_alg', 'dh_group', 'pfs_enabled'.
    """
    score = 100
    findings = []
    
    # 1. Evaluate Encryption
    enc = config.get("enc_alg")
    if enc:
        eval_res = evaluate_algorithm("Encryption", enc)
        findings.append({"severity": eval_res["severity"], "message": eval_res["message"]})
        score -= eval_res["penalty"]
        
    # 2. Evaluate Hashing/Integrity
    hash_alg = config.get("hash_alg")
    if hash_alg:
        eval_res = evaluate_algorithm("Hashing", hash_alg)
        findings.append({"severity": eval_res["severity"], "message": eval_res["message"]})
        score -= eval_res["penalty"]
        
    # 3. Evaluate Key Exchange (DH)
    dh = config.get("dh_group")
    if dh:
        eval_res = evaluate_algorithm("Key Exchange (DH)", dh)
        findings.append({"severity": eval_res["severity"], "message": eval_res["message"]})
        score -= eval_res["penalty"]
        
    # 4. Check Perfect Forward Secrecy (PFS)
    pfs = config.get("pfs_enabled")
    if pfs is False:
        findings.append({
            "severity": "HIGH", 
            "message": "Perfect Forward Secrecy (PFS) is DISABLED. If the long-term key is compromised, all past traffic can be decrypted."
        })
        score -= 20
    elif pfs is True:
        findings.append({
            "severity": "INFO",
            "message": "Perfect Forward Secrecy (PFS) is enabled. Session keys are protected."
        })
        score += 5 # Bonus
        
    # Ensure score stays within 0-100 bounds
    score = max(0, min(100, score))
    
    # Determine overall risk level
    if score >= 90:
        risk = "LOW"
    elif score >= 70:
        risk = "MEDIUM"
    elif score >= 40:
        risk = "HIGH"
    else:
        risk = "CRITICAL"
        
    return {
        "status": "assessed",
        "score": score,
        "risk_level": risk,
        "findings": findings
    }
