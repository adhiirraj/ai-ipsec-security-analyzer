#!/usr/bin/env python3
import os
import glob
import csv
import statistics
from scapy.all import rdpcap, ESP, IP, IPv6

def extract_features_from_pcap(pcap_path, label):
    print(f"Processing {pcap_path} (Label: {label})...")
    try:
        # Scapy rdpcap loads everything into memory. 
        # For huge PCAPs we'd use PcapReader, but for our 15s testbed this is fine.
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
        return []

    flows = {} # Map of SPI -> list of packets
    
    for pkt in packets:
        # Check if it has an ESP layer
        if ESP in pkt:
            # Handle both IPv4 and IPv6
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
            else:
                continue

            spi = pkt[ESP].spi
            # A unique flow is defined by (Source IP, Dest IP, SPI)
            flow_key = (src, dst, spi)
            
            if flow_key not in flows:
                flows[flow_key] = []
            flows[flow_key].append(pkt)
            
    features = []
    for flow_key, pkts in flows.items():
        # Ignore tiny flows (e.g., VPN teardown packets or anomalies)
        if len(pkts) < 10:
            continue
            
        src, dst, spi = flow_key
        
        # Sort packets strictly by timestamp
        pkts.sort(key=lambda x: x.time)
        
        sizes = [len(p) for p in pkts]
        # Inter-arrival times (differences between consecutive packet timestamps)
        iats = [float(pkts[i].time - pkts[i-1].time) for i in range(1, len(pkts))]
        
        if not iats:
            iats = [0.0]
            
        feat = {
            'spi': hex(spi),
            'src_ip': src,
            'dst_ip': dst,
            'packet_count': len(pkts),
            'total_bytes': sum(sizes),
            'mean_packet_size': round(statistics.mean(sizes), 2),
            'std_packet_size': round(statistics.stdev(sizes), 2) if len(sizes) > 1 else 0.0,
            'mean_iat': round(statistics.mean(iats), 6),
            'std_iat': round(statistics.stdev(iats), 6) if len(iats) > 1 else 0.0,
            'label': label
        }
        features.append(feat)
        
    return features

def main():
    pcaps_dir = "pcaps"
    output_csv = "dataset.csv"
    
    if not os.path.exists(pcaps_dir):
        print(f"Error: Directory '{pcaps_dir}' not found.")
        return
        
    all_features = []
    
    # Iterate over all pcaps in the directory
    for pcap_file in glob.glob(os.path.join(pcaps_dir, "*.pcap")):
        # Extract label from filename (e.g., aes128_tunnel_voip.pcap -> voip)
        basename = os.path.basename(pcap_file)
        # Assuming our format is always crypto_mode_traffic.pcap
        name_without_ext = os.path.splitext(basename)[0]
        
        try:
            traffic_label = name_without_ext.split('_')[-1]
        except IndexError:
            traffic_label = "unknown"
            
        flow_features = extract_features_from_pcap(pcap_file, traffic_label)
        all_features.extend(flow_features)
        
    if not all_features:
        print("No ESP flows found to extract.")
        return
        
    # Write to CSV
    keys = all_features[0].keys()
    with open(output_csv, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(all_features)
        
    print(f"\nSuccess! Extracted {len(all_features)} ESP flows into {output_csv}")

if __name__ == "__main__":
    main()
