import subprocess
import os

def extract_ike_with_tshark(pcap_path):
    try:
        res = subprocess.run(["tshark", "-r", pcap_path, "-Y", "isakmp", "-V"], capture_output=True, text=True, timeout=10)
        output = res.stdout
        
        config = {
            "enc_alg": "unknown",
            "hash_alg": "unknown",
            "dh_group": "unknown",
            "pfs_enabled": False
        }
        
        # Super simple text parsing of tshark output
        lines = output.split('\n')
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Transform: Encryption
            if "Transform Type: Encryption Algorithm (1)" in line:
                for j in range(1, 4):
                    if "Transform ID:" in lines[i+j]:
                        alg = lines[i+j].split("Transform ID:")[1].strip()
                        config["enc_alg"] = alg
                        break
            
            # Transform: PRF (Hash)
            if "Transform Type: Pseudo-random Function (2)" in line:
                for j in range(1, 4):
                    if "Transform ID:" in lines[i+j]:
                        alg = lines[i+j].split("Transform ID:")[1].strip()
                        config["hash_alg"] = alg
                        break
                        
            # Transform: DH
            if "Transform Type: Diffie-Hellman Group (4)" in line:
                for j in range(1, 4):
                    if "Transform ID:" in lines[i+j]:
                        alg = lines[i+j].split("Transform ID:")[1].strip()
                        config["dh_group"] = alg
                        break
                        
        print(config)
        return config
    except Exception as e:
        print(f"tshark error: {e}")
        return None

if __name__ == "__main__":
    import sys
    extract_ike_with_tshark(sys.argv[1])
