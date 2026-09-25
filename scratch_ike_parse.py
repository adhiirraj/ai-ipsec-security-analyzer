from scapy.all import rdpcap, ISAKMP, ISAKMP_payload_SA, ISAKMP_payload_Transform
import sys

def test_parse(pcap_path):
    print(f"Parsing {pcap_path}")
    packets = rdpcap(pcap_path)
    for pkt in packets:
        if pkt.haslayer(ISAKMP) and pkt.haslayer(ISAKMP_payload_SA):
            print("Found ISAKMP SA!")
            sa = pkt[ISAKMP_payload_SA]
            # Print proposals
            try:
                # Scapy's IKEv2 dissection varies, let's just use show()
                sa.show()
                # If there are transforms, we can extract their ID
                # Actually, Scapy's IKEv2 layer in recent versions has IKEv2_payload_SA
            except Exception as e:
                print(f"Error: {e}")
            break

if __name__ == "__main__":
    test_parse(sys.argv[1])
