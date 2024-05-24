from scapy.all import sniff, send, IP, TCP, UDP, get_if_list, get_if_hwaddr, conf

def edit_packet(packet, new_src_ip=None, new_dst_ip=None):
    if IP in packet:
        if new_src_ip:
            print(f"Changing source IP from {packet[IP].src} to {new_src_ip}")
            packet[IP].src = new_src_ip
        if new_dst_ip:
            print(f"Changing destination IP from {packet[IP].dst} to {new_dst_ip}")
            packet[IP].dst = new_dst_ip
        del packet[IP].chksum  
    if TCP in packet:
        del packet[TCP].chksum
    return packet


def packet_callback(packet):
    #print(packet.summary())
    if filter_func(packet, dst_ip='74.125.250.244', protocol=UDP):
        edited_pkt = edit_packet(packet, new_src_ip='10.0.0.1', new_dst_ip='192.168.1.2')
        print(f"Sending edited packet from {edited_pkt[IP].src} to {edited_pkt[IP].dst}")
        send(edited_pkt)


def capture_packets(interface, count):
    print(f"Capturing {count} packets on interface {interface}...")
    packets = sniff(iface=interface, count=count, prn=packet_callback)
    print(f"Captured {len(packets)} packets")
    return packets

def filter_packets(packets, filter_func):
    filtered = [pkt for pkt in packets if filter_func(pkt)]
    print(f"Filtered {len(filtered)} packets out of {len(packets)}")
    return filtered


def choose_interface(partial_name):
    for iface in conf.ifaces.values():
        if partial_name in iface.name:
            return iface.name
    return None


def filter_func(pkt, dst_ip=None, protocol=None):
    if dst_ip is not None and IP in pkt and pkt[IP].dst != dst_ip:
        return False
    if protocol is not None and pkt.haslayer(protocol):
        return True
    return False

if __name__ == "__main__":

    partial_name = "Wi-Fi"

    chosen_interface = choose_interface(partial_name)

    if chosen_interface:
        print(f"Selected interface: {chosen_interface}")
        captured_packets = capture_packets(chosen_interface, 10)
    else:
        print("Interface not found.")
        exit()
