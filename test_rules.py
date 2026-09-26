from dashboard.backend.api import extract_ike_proposals
from src.ipsec_sentinel.analysis.rules import assess_configuration
import json

# Test with an existing weak PCAP
config = extract_ike_proposals("testbed/pcaps/custom_aes128sha256modp2048_aes128sha256_pfs_tunnel_ipv6_whatsapp.pcap", "custom_aes128sha256modp2048_aes128sha256_pfs_tunnel_ipv6_whatsapp.pcap")
res = assess_configuration(config)
print(json.dumps(res, indent=2))
