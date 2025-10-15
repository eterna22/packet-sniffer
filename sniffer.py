#!/usr/bin/env python3
"""
Network Packet Sniffer
A tool for capturing and analyzing network packets in real-time.
Requires root/sudo privileges to run.
"""

import socket
import struct
import textwrap
import sys
import os

# Formatting constants
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

# Protocol mappings
PROTOCOL_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}


def check_root():
    """Check if script is running with root privileges"""
    if os.geteuid() != 0:
        print("[!] Error: This script requires root privileges.")
        print("[!] Please run with: sudo python3 packet_sniffer.py")
        sys.exit(1)


def main():
    """Main function to capture and analyze packets"""
    check_root()
    
    print("="*60)
    print("Network Packet Sniffer")
    print("="*60)
    print("[*] Starting packet capture...")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        # Create raw socket
        connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("[!] Error: Permission denied. Run with sudo.")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Error creating socket: {e}")
        sys.exit(1)

    packet_count = 0

    try:
        while True:
            raw_data, address = connection.recvfrom(65536)
            packet_count += 1
            
            print(f"\n{'='*60}")
            print(f"Packet #{packet_count}")
            print('='*60)
            
            dest_mac, src_mac, eth_protocol, data = ethernet_frame(raw_data)
            print('\nEthernet Frame: ')
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(
                dest_mac, src_mac, eth_protocol))

            # 8 for IPv4
            if eth_protocol == 8:
                try:
                    version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                    print(TAB_1 + 'IPv4 Packet: ')
                    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(
                        version, header_length, ttl))
                    print(TAB_2 + 'Protocol: {} ({}), Source: {}, Target: {}'.format(
                        proto, PROTOCOL_MAP.get(proto, 'Unknown'), src, target))

                    # ICMP Type
                    if proto == 1:
                        icmp_type, code, checksum, data = icmp_packet(data)
                        print(TAB_1 + 'ICMP Packet:')
                        print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(
                            icmp_type, code, checksum))
                        print(TAB_2 + 'ICMP Type: {}'.format(get_icmp_type(icmp_type)))
                        if data:
                            print(TAB_2 + 'Data:')
                            print(format_multi_line(DATA_TAB_3, data))

                    # TCP Type
                    elif proto == 6:
                        src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, \
                        flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_packet(data)
                        print(TAB_1 + 'TCP Segment:')
                        print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(
                            src_port, dest_port))
                        print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(
                            sequence, acknowledgement))
                        print(TAB_2 + 'Flags:')
                        print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                            flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                        
                        # Display connection state
                        print(TAB_2 + 'Connection State: {}'.format(
                            get_tcp_state(flag_syn, flag_ack, flag_fin, flag_rst)))
                        
                        if data:
                            print(TAB_2 + 'Data: ({} bytes)'.format(len(data)))
                            print(format_multi_line(DATA_TAB_3, data))

                    # UDP Type
                    elif proto == 17:
                        src_port, dest_port, size, data = udp_packet(data)
                        print(TAB_1 + 'UDP Datagram:')
                        print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(
                            src_port, dest_port, size))
                        if data:
                            print(TAB_2 + 'Data: ({} bytes)'.format(len(data)))
                            print(format_multi_line(DATA_TAB_3, data))

                    # Other protocols
                    else:
                        print(TAB_1 + 'Other Protocol Data:')
                        if data:
                            print(format_multi_line(DATA_TAB_2, data))
                
                except Exception as e:
                    print(f"[!] Error parsing IPv4 packet: {e}")
                    continue
            
            else:
                print(TAB_1 + 'Non-IPv4 packet (EtherType: {})'.format(eth_protocol))

    except KeyboardInterrupt:
        print("\n\n[*] Packet capture stopped by user.")
        print(f"[*] Total packets captured: {packet_count}")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)

def ethernet_frame(data):
    """Unpack Ethernet frame"""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

def get_mac_address(byte_address):
    """Return properly formatted MAC Address (e.g., AA:BB:CC:DD:EE:FF)"""
    bytes_str = map('{:02x}'.format, byte_address)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    """Unpack IPv4 packet"""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(address):
    """Return properly formatted IPv4 address (e.g., 192.168.1.1)"""
    return '.'.join(map(str, address))

def icmp_packet(data):
    """Unpack ICMP packet"""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def get_icmp_type(icmp_type):
    """Return ICMP type description"""
    icmp_types = {
        0: 'Echo Reply',
        3: 'Destination Unreachable',
        4: 'Source Quench',
        5: 'Redirect',
        8: 'Echo Request',
        11: 'Time Exceeded',
        12: 'Parameter Problem',
        13: 'Timestamp',
        14: 'Timestamp Reply'
    }
    return icmp_types.get(icmp_type, 'Unknown')

def tcp_packet(data):
    """Unpack TCP segment"""
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack(
        '! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, 
            flag_psh, flag_rst, flag_syn, flag_fin, data[offset:])

def get_tcp_state(syn, ack, fin, rst):
    """Determine TCP connection state based on flags"""
    if rst:
        return 'RESET'
    if syn and not ack:
        return 'SYN (Connection Request)'
    if syn and ack:
        return 'SYN-ACK (Connection Acknowledgment)'
    if fin:
        return 'FIN (Connection Termination)'
    if ack:
        return 'ESTABLISHED (Data Transfer)'
    return 'UNKNOWN'

def udp_packet(data):
    """Unpack UDP datagram"""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    """Format multi-line data for display"""
    size -= len(prefix)
    if isinstance(string, bytes):
        # Limit output for very large payloads
        if len(string) > 200:
            string = string[:200]
            suffix = '\n' + prefix + '... ({} more bytes)'.format(len(string) - 200)
        else:
            suffix = ''
        
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)]) + suffix
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    
if __name__ == '__main__':

    main()
