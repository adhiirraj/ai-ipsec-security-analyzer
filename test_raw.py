import json
from dashboard.backend.api import extract_ike_proposals
from src.ipsec_sentinel.analysis.rules import assess_configuration

config = extract_ike_proposals("testbed/pcaps/custom_aes128sha256modp2048_aes128sha256_pfs_tunnel_ipv6_whatsapp.pcap", "custom_aes128sha256modp2048_aes128sha256_pfs_tunnel_ipv6_whatsapp.pcap")
print(config.get("raw_payloads", "NO PAYLOADS"))
