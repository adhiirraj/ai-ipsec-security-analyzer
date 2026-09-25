#!/usr/bin/env python3
import os
import glob
import csv
import statistics
from scapy.all import rdpcap, ESP, IP, IPv6

def extract_features_from_pcap(pcap_path, label="unknown"):
    print(f"Processing {pcap_path} (Label: {label})...")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
        return []

    # Group by bidirectional IP pairs
    sessions = {}
    
    for pkt in packets:
        if ESP in pkt:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
            else:
                continue

            spi = pkt[ESP].spi
            
            # Use sorted tuple to group bidirectionally
            ip_pair = tuple(sorted([src, dst]))
            
            if ip_pair not in sessions:
                sessions[ip_pair] = []
            sessions[ip_pair].append((src, dst, spi, pkt))
            
    features = []
    for ip_pair, pkt_data in sessions.items():
        if len(pkt_data) < 10:
            continue
            
        # Sort chronologically
        pkt_data.sort(key=lambda x: x[3].time)
        
        # Determine forward direction from the first packet
        forward_src = pkt_data[0][0]
        
        forward_pkts = 0
        backward_pkts = 0
        forward_bytes = 0
        backward_bytes = 0
        sizes = []
        
        for src, dst, spi, pkt in pkt_data:
            size = len(pkt)
            sizes.append(size)
            if src == forward_src:
                forward_pkts += 1
                forward_bytes += size
            else:
                backward_pkts += 1
                backward_bytes += size
                
        duration = float(pkt_data[-1][3].time - pkt_data[0][3].time)
        if duration <= 0:
            duration = 0.000001
            
        packet_count = len(pkt_data)
        total_bytes = sum(sizes)
        
        feat = {
            'spi': hex(pkt_data[0][2]), # Just take first SPI as identifier
            'src_ip': pkt_data[0][0],
            'dst_ip': pkt_data[0][1],
            'duration': round(duration, 6),
            'packet_count': packet_count,
            'total_bytes': total_bytes,
            'mean_packet_size': round(statistics.mean(sizes), 2),
            'std_packet_size': round(statistics.stdev(sizes), 2) if len(sizes) > 1 else 0.0,
            'min_packet_size': min(sizes),
            'max_packet_size': max(sizes),
            'packet_rate': round(packet_count / duration, 2),
            'byte_rate': round(total_bytes / duration, 2),
            'forward_packets': forward_pkts,
            'backward_packets': backward_pkts,
            'forward_bytes': forward_bytes,
            'backward_bytes': backward_bytes,
            'direction_ratio': round(forward_pkts / max(1, backward_pkts), 4),
            'label': label
        }
        features.append(feat)
        
    return features

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pcaps_dir = os.path.join(base_dir, "pcaps")
    output_csv = os.path.join(base_dir, "../data/dataset.csv")
    
    if not os.path.exists(pcaps_dir):
        print(f"Error: Directory '{pcaps_dir}' not found.")
        return
        
    all_features = []
    for pcap_file in glob.glob(os.path.join(pcaps_dir, "*.pcap")):
        basename = os.path.basename(pcap_file)
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
        
    keys = all_features[0].keys()
    with open(output_csv, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(all_features)
        
    print(f"\nSuccess! Extracted {len(all_features)} ESP flows into {output_csv}")

if __name__ == "__main__":
    main()
