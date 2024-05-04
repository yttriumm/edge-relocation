import argparse
from scapy.all import sendp, Ether, IP

def send_raw_ipv4_packet(interface, ip):
    # Create an Ethernet frame
    eth = Ether(dst='ff:ff:ff:ff:ff:ff')  # Ethernet frame with broadcast MAC address
    
    # Create an IP packet
    ip = IP(src=ip, dst='255.255.255.255')  # IP packet destined for the broadcast address
    
    # Combine the Ethernet frame and IP packet
    packet = eth / ip
    
    # Send the packet from the specified interface with no additional payload
    sendp(packet, iface=interface)

def main():
    # Set up the argument parser
    parser = argparse.ArgumentParser(description='Send a raw IPv4 packet to the broadcast address.')
    parser.add_argument('iface', type=str, help='Network interface to send the packet from (e.g., eth0)')
    parser.add_argument('ip', type=str, help='IP address to register')

    # Parse command-line arguments
    args = parser.parse_args()

    # Run the function with the specified interface
    send_raw_ipv4_packet(args.iface, args.ip)

if __name__ == '__main__':
    main()
