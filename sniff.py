from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
import sys

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ""
        
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"

        print(f"[+] {protocol} Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Payload display
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
                print(f"    Payload: {payload}")
            except Exception as e:
                print("    Payload: <non-decodable>")
        print('-' * 80)

def main():
    print("[*] Listing available interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")

    try:
        choice = int(input("Select interface number to sniff: "))
        iface = interfaces[choice]
    except (ValueError, IndexError):
        print("Invalid interface selection.")
        sys.exit(1)

    print(f"[*] Starting packet sniffing on {iface} (Press CTRL+C to stop)")
    sniff(filter="ip", prn=packet_callback, store=False, iface=iface)

if __name__ == "__main__":
    main()
