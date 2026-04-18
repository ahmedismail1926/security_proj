import base64
try:
    from scapy.all import rdpcap, TCP, IP
    
    pcap_file = r"a:\University\Spring2026\Security\Project\security_proj\ctf\CTF_DATA\CTF1\traffic.pcapng"
    print("Loading pcap...")
    packets = rdpcap(pcap_file)
    
    payloads = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[TCP].dport == 4444 or pkt[TCP].sport == 4444:
                if pkt[TCP].payload:
                    raw_data = bytes(pkt[TCP].payload)
                    if raw_data:
                        payloads.append(raw_data)
                        
    # Filter out MSG: and :EOF and concatenate
    clean_payloads = [p for p in payloads if p not in (b"MSG:", b":EOF")]
    b64_string = b"".join(clean_payloads)
    print("Base64 string:", b64_string.decode())
    
    flag = base64.b64decode(b64_string)
    print("Found flag:", flag.decode())
            
except ImportError:
    print("scapy is not installed yet. Please run: pip install scapy")
except Exception as e:
    print(f"Error: {e}")
