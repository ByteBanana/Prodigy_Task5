from scapy.all import sniff, IP, Raw

def sniff_packets(interface, count): 
    print("[+] Sniffing started on interface " + interface) 
    sniff(iface=interface, count=count, prn=process_packet)

def process_packet(packet): 
    if IP in packet: 
        ip_src = packet[IP].src 
        ip_dst = packet[IP].dst 
        protocol = packet[IP].proto

        print(f"IP Source: {ip_src} --> IP Destination: {ip_dst} Protocol: {protocol}")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"Raw Data: {payload.hex()}")

def main(): 
    interface = input("Enter the interface to sniff on (e.g., eth0): ") 
    count = int(input("Enter the number of packets to capture: ")) 
    sniff_packets(interface, count)

if __name__ == "__main__": 
    main()
