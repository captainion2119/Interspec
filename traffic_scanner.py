import curses
import threading
import time
import csv
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from collections import deque, Counter

# Global variables
packets_captured = 0
packet_data = deque(maxlen=1000)  # Stores the last 1000 packets for display
stop_event = threading.Event()
protocol_filter = None
scroll_position = 0
manual_scroll_mode = False
packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
total_bytes = 0
ip_filter = None
blacklist = set()  # IPs to be monitored for malicious activity
top_talkers = Counter()  # Track top talkers
suspicious_ports = {23, 445, 3389}  # Common ports for potentially malicious activity
dns_queries = deque(maxlen=10)  # Track last 10 DNS queries

# ASCII Art for NetSleuth
ascii_art = [
    "  _____       _            _____                 ",
    " |_   _|     | |          / ____|                ",
    "   | |  _ __ | |_ ___ _ _| (___  _ __   ___  ___ ",
    "   | | | '_ \\| __/ _ \\ '__\\___ \\| '_ \\ / _ \\/ __|",
    "  _| |_| | | | ||  __/ |  ____) | |_) |  __/ (__ ",
    " |_____|_| |_|\\__\\___|_| |_____/| .__/ \\___|\\___|",
    "                               | |              ",
    "                               |_|              ",
    "              ~ A Tool By AdithyaKarthik M (LtN0N4M3)"
]


def packet_handler(packet):
    global packets_captured, packet_data, protocol_filter, packet_counts, total_bytes, ip_filter, top_talkers, dns_queries
    packets_captured += 1

    # Check if the packet has an IP layer
    if IP in packet:
        # Extract relevant information from the packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl = packet[IP].ttl
        tos = packet[IP].tos
        identification = packet[IP].id
        protocol = packet[IP].proto
        checksum = packet[IP].chksum

        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"
        flags = packet[TCP].flags if TCP in packet else "N/A"
        window_size = packet[TCP].window if TCP in packet else "N/A"

        packet_len = len(packet)
        payload_size = len(packet[IP].payload)
        timestamp = time.strftime("%H:%M:%S", time.localtime())

        # Update packet counts based on protocol
        if protocol == 6:
            packet_type = "TCP"
        elif protocol == 17:
            packet_type = "UDP"
        elif protocol == 1:
            packet_type = "ICMP"
        else:
            packet_type = "Other"

        packet_counts[packet_type] += 1
        total_bytes += packet_len

        # Update top talkers
        top_talkers[src_ip] += 1
        top_talkers[dst_ip] += 1

        # Track DNS queries and determine the requested domain
        requested_domain = ""
        if DNS in packet and packet[DNS].qd is not None:
            requested_domain = packet[DNSQR].qname.decode("utf-8")
            dns_queries.append(f"{src_ip} queried {requested_domain}")

        # Filter based on the protocol and IP, if set
        if (protocol_filter and protocol_filter != packet_type) or (ip_filter and src_ip != ip_filter and dst_ip != ip_filter):
            return

        # Append packet data to the deque
        packet_data.append({
            'No': packets_captured,
            'Time': timestamp,
            'Source': f"{src_ip}:{src_port}",
            'Destination': f"{dst_ip}:{dst_port}",
            'Protocol': packet_type,
            'Length': packet_len,
            'TTL': ttl,
            'Flags': str(flags),
            'Window Size': window_size,
            'Checksum': checksum,
            'TOS': tos,
            'ID': identification,
            'Payload Size': payload_size,
            'Requested Domain': requested_domain if requested_domain else "N/A",
        })

        # Alert if a TCP SYN packet is detected
        if TCP in packet and packet[TCP].flags == "S":
            alert_message = f"ALERT: TCP SYN packet detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
            print(alert_message)

        # Highlight and alert if an IP is in the blacklist
        if src_ip in blacklist or dst_ip in blacklist:
            alert_message = f"ALERT: Packet involving blacklisted IP {src_ip if src_ip in blacklist else dst_ip}"
            print(alert_message)

        # Alert if the packet is using a suspicious port
        if (TCP in packet and (packet[TCP].sport in suspicious_ports or packet[TCP].dport in suspicious_ports)) or \
           (UDP in packet and (packet[UDP].sport in suspicious_ports or packet[UDP].dport in suspicious_ports)):
            alert_message = f"ALERT: Packet using suspicious port from {src_ip}:{src_port} to {dst_ip}:{dst_port}"
            print(alert_message)

def sniff_packets():
    sniff(prn=packet_handler, store=0, stop_filter=lambda x: stop_event.is_set())

def save_packets_to_file():
    with open("captured_packets.csv", "w", newline="") as csvfile:
        fieldnames = ["No", "Time", "Source", "Destination", "Protocol", "Length", "TTL", "Flags", "Window Size", "Checksum", "TOS", "ID", "Payload Size", "Requested Domain"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(packet_data)
    print("Packets saved to captured_packets.csv")

def get_ip_input(stdscr):
    """ Prompt user to enter an IP address. """
    curses.echo()
    input_y = len(ascii_art) + 10
    input_x = 0
    stdscr.addstr(input_y, input_x, "Enter IP to filter (press Enter to confirm): ")
    stdscr.move(input_y, len("Enter IP to filter (press Enter to confirm): "))
    stdscr.clrtoeol()  # Clear the rest of the line to remove any residual characters
    ip = stdscr.getstr(input_y, len("Enter IP to filter (press Enter to confirm): "), 15).decode("utf-8").strip()
    stdscr.clrtoeol()  # Clear the line again after input
    curses.noecho()
    return ip

def curses_display(stdscr):
    global packets_captured, packet_data, scroll_position, protocol_filter, manual_scroll_mode, packet_counts, total_bytes, ip_filter

    # Set up the curses screen
    curses.curs_set(0)  # Hide cursor
    stdscr.nodelay(1)  # Non-blocking input
    stdscr.timeout(500)  # Refresh every 500 ms

    # Set up colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)  # Default text
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Header text
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)  # Highlighted text
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)  # ASCII art text
    hacker_mode = False

    while True:
        # Handle user input for quitting and other commands
        key = stdscr.getch()
        if key == ord('q') or key == ord('Q'):
            stop_event.set()
            break
        elif key == ord('s') or key == ord('S'):
            save_packets_to_file()
        elif key == ord('t'):
            protocol_filter = "TCP" if protocol_filter != "TCP" else None
        elif key == ord('u'):
            protocol_filter = "UDP" if protocol_filter != "UDP" else None
        elif key == ord('i'):
            # Pause screen refreshes and take input for IP
            stdscr.nodelay(0)  # Set blocking input to avoid refresh issues
            ip_filter = get_ip_input(stdscr)
            stdscr.nodelay(1)  # Restore non-blocking input
        elif key == ord('h'):
            hacker_mode = not hacker_mode
            curses.init_pair(1, curses.COLOR_GREEN if hacker_mode else curses.COLOR_CYAN, curses.COLOR_BLACK)
        elif key == ord('m'):
            manual_scroll_mode = not manual_scroll_mode
            if not manual_scroll_mode:
                scroll_position = 0  # Reset scroll position when exiting manual scroll mode
        elif key == ord('c'):
            packet_data.clear()
            packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
            packets_captured = 0
            total_bytes = 0
        elif key == curses.KEY_UP and manual_scroll_mode:
            if scroll_position > 0:
                scroll_position -= 1
        elif key == curses.KEY_DOWN and manual_scroll_mode:
            if scroll_position < max(0, len(packet_data) - (curses.LINES - 10)):
                scroll_position += 1
        elif key == ord('b'):
            stdscr.nodelay(0)
            blacklist_ip = get_ip_input(stdscr)
            if blacklist_ip:
                blacklist.add(blacklist_ip)
            stdscr.nodelay(1)

        # Clear the screen
        stdscr.clear()

        # Draw ASCII art at the top
        for i, line in enumerate(ascii_art):
            stdscr.attron(curses.color_pair(4))  # Green color for ASCII art
            stdscr.addstr(i, 0, line)
            stdscr.attroff(curses.color_pair(4))

        # Draw header and instructions
        header_y = len(ascii_art) + 1
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(header_y, 0, "This is a Network Traffic Scanner Project.")
        stdscr.addstr(header_y + 1, 0, "Press Q to quit | S to save packets | ")
        if protocol_filter == "TCP":
            stdscr.attron(curses.color_pair(3))
        stdscr.addstr("T for TCP filter ")
        if protocol_filter == "TCP":
            stdscr.attroff(curses.color_pair(3))
        if protocol_filter == "UDP":
            stdscr.attron(curses.color_pair(3))
        stdscr.addstr("| U for UDP filter ")
        if protocol_filter == "UDP":
            stdscr.attroff(curses.color_pair(3))
        stdscr.addstr("| I to filter by IP | B to blacklist IP | C to clear packet data | H for Hacker Mode | M for Manual Scroll")
        stdscr.attroff(curses.color_pair(1))

        # Draw packet statistics
        stdscr.attron(curses.color_pair(2))
        stdscr.addstr(header_y + 3, 0, f"Packets Captured: {packets_captured} | Total Bytes: {total_bytes} bytes")
        stdscr.addstr(header_y + 4, 0, f"Packet Counts: TCP={packet_counts['TCP']} | UDP={packet_counts['UDP']} | ICMP={packet_counts['ICMP']} | Other={packet_counts['Other']}")
        stdscr.addstr(header_y + 5, 0, f"Filter: {protocol_filter or 'None'} | IP Filter: {ip_filter or 'None'} | Manual Scroll: {'On' if manual_scroll_mode else 'Off'}")
        stdscr.attroff(curses.color_pair(2))

        # Display DNS Queries and Top Talkers
        stdscr.attron(curses.color_pair(2))
        stdscr.addstr(header_y + 6, 0, "-" * 80)  # Add a horizontal line before "Top Talkers"
        stdscr.addstr(header_y + 7, 0, "Recent DNS Queries:")
        for idx, query in enumerate(dns_queries):
            stdscr.addstr(header_y + 8 + idx, 0, query)
        stdscr.addstr(header_y + 18, 0, "-" * 80)  # Add a horizontal line before "Top Talkers"
        stdscr.addstr(header_y + 19, 0, "Top Talkers:")
        for idx, (ip, count) in enumerate(top_talkers.most_common(5)):
            stdscr.addstr(header_y + 20 + idx, 0, f"{ip}: {count} packets")
        stdscr.attroff(curses.color_pair(2))

        # Draw packet details in a table-like format
        columns = ["No", "Time", "Source", "Destination", "Protocol", "Length", "TTL", "Flags", "Window Size", "Checksum", "TOS", "ID", "Payload Size", "Requested Domain"]
        col_widths = [5, 12, 25, 25, 8, 6, 4, 6, 12, 8, 4, 6, 12, 25]

        # Draw table headers with a box around them
        table_y = header_y + 27
        x = 0
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(table_y - 1, 0, "+" + "-" * (sum(col_widths) + len(col_widths) - 1) + "+")
        for i, col in enumerate(columns):
            stdscr.addstr(table_y, x, f"{col}".ljust(col_widths[i]))
            x += col_widths[i] + 1
        stdscr.addstr(table_y + 1, 0, "+" + "-" * (sum(col_widths) + len(col_widths) - 1) + "+")
        stdscr.attroff(curses.color_pair(1))

        # Draw the packet data, showing the last few packets based on scroll position or auto-scrolling
        start_y = table_y + 2
        max_rows = curses.LINES - start_y - 2
        if not manual_scroll_mode:
            scroll_position = max(0, len(packet_data) - max_rows)
        packet_list = list(packet_data)[scroll_position:scroll_position + max_rows]

        for idx, pkt in enumerate(packet_list):
            y = start_y + idx
            x = 0
            values = [
                str(pkt['No']),
                pkt['Time'],
                pkt['Source'],
                pkt['Destination'],
                pkt['Protocol'],
                str(pkt['Length']),
                str(pkt['TTL']),
                str(pkt['Flags']),
                str(pkt['Window Size']),
                str(pkt['Checksum']),
                str(pkt['TOS']),
                str(pkt['ID']),
                str(pkt['Payload Size']),
                pkt['Requested Domain']
            ]
            for i, value in enumerate(values):
                # Highlight the protocol field in red if it matches the selected filter
                if i == 4 and ((protocol_filter == "TCP" and value == "TCP") or (protocol_filter == "UDP" and value == "UDP")):
                    stdscr.attron(curses.color_pair(3))
                # Highlight if it's from/to a blacklisted IP
                if 'Source' in pkt and (pkt['Source'].split(':')[0] in blacklist or pkt['Destination'].split(':')[0] in blacklist):
                    stdscr.attron(curses.color_pair(3))
                stdscr.addstr(y, x, f"{value}".ljust(col_widths[i]))
                stdscr.attroff(curses.color_pair(3))  # Remove highlight for the rest of the row
                x += col_widths[i] + 1

        # Refresh the screen
        stdscr.refresh()

def main():
    global stop_event

    # Start the packet sniffing thread
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True  # Allow program to exit even if thread is running
    sniff_thread.start()

    # Start the curses interface
    curses.wrapper(curses_display)

    # Wait for sniffing thread to finish after quitting the UI
    stop_event.set()
    sniff_thread.join()

if __name__ == "__main__":
    main()
