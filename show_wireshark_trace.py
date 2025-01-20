# script to show a simplified version of a wireshark trace. 
# david.portabella@gmail.com, January 2025
# capture a trace with Wireshark and save it to a file named trace_capture.pcapng
# and run:
# pip install pyshark
# python show_trace.py trace_capture_example.pcapng

import pyshark

def process_pcap(file_path):
    # Open the capture file
    capture = pyshark.FileCapture(file_path, display_filter='tcp')

    # Track connections and listening ports
    connections = {}
    listening_ports = set()

    print(f"packet_number\tfrom\tto\tdirection\tpayload")

    for packet in capture:
        try:
            # Extract relevant fields
            src_ip = packet.ip.src
            src_port = packet.tcp.srcport
            dst_ip = packet.ip.dst
            dst_port = packet.tcp.dstport

            # Convert flags to integer
            flags = int(packet.tcp.flags, 16)

            # Check for SYN packets to identify new connections
            if flags & 0x02 and not flags & 0x10:  # SYN set, ACK not set
                print(f"{packet.number}\t{src_ip}:{src_port}\t{dst_ip}:{dst_port}\tNEW CONNECTION")
                connections[(src_ip, src_port, dst_ip, dst_port)] = 'C->S'
                connections[(dst_ip, dst_port, src_ip, src_port)] = 'S->C'
                continue

            # Check for SYN-ACK packets to identify listening ports
            if flags & 0x12 == 0x12:  # SYN and ACK both set
                listening_ports.add((dst_ip, dst_port))
                continue

            # Determine direction
            direction = connections.get((src_ip, src_port, dst_ip, dst_port), 'Unknown')

            # Check if the packet has a payload
            if hasattr(packet.tcp, 'payload'):
                payload_hex = packet.tcp.payload
                payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
                try:
                    payload = payload_bytes.decode('utf-8', errors='replace')
                except UnicodeDecodeError:
                    payload = payload_bytes.decode('latin1', errors='replace')

                # Print the desired output
                # payload = "..."
                print(f"{packet.number}\t{src_ip}:{src_port}\t{dst_ip}:{dst_port}\t{direction}\t{payload}")

        except AttributeError:
            # Handle packets that may not have the expected attributes
            continue

    # Close the capture
    capture.close()

import sys
process_pcap(sys.argv[1])
