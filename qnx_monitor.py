#!/usr/bin/env python3
import os
import time
import curses
import threading
import queue
import argparse
import ipaddress
from datetime import datetime
import re
import subprocess

class QNXMonitor:
    def __init__(self, ips, refresh_interval=5, ports=None, all_ports=False):
        self.refresh_interval = refresh_interval
        self.ips = ips
        self.ports = ports  # Specific ports to monitor
        self.all_ports = all_ports  # Flag to monitor all ports
        self.containers = {}
        self.log_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.container_status_lock = threading.Lock()

        self.log_colors = [
            # Priority order matters - first match wins
            (r'\b(error|failed|unreachable)\b', 3),      # Red
            (r'\[SYN\]', 6),                             # Magenta
            (r'\[FIN\]', 3),                              # Red
            (r'\[ACK\]', 7),                              # Blue
            (r'\b(reachable)\b', 1),                      # Green
            (r'\b(ping: [\d.]+ms)\b', 2),                 # Yellow
            (r'\[TCPDUMP_DEBUG\]', 8),      # Yellow for debug
            (r'\[TCPDUMP_COMMAND\]', 4),    # Cyan for commands
            (r'\[TCPDUMP_PROCESS\]', 4),    # Cyan for process info
            (r'\[TCPDUMP_STDOUT\]', 7),     # Blue for stdout
            (r'\[TCPDUMP_STDERR\]', 3),     # Red for stderr
            (r'\[TCPDUMP_PARSE\]', 2),      # Yellow for parsed
            (r'\[TCPDUMP_WARNING\]', 2),    # Yellow for warnings
            (r'\[TCPDUMP_ERROR\]', 3),      # Red for errors
            (r'\b(idle|pending)\b', 8),                   # Yellow
            (r'\b(received|sent|data)\b', 7),             # Blue
            (r'\b(connected)\b', 1),                      # Green
            (r'\d+\.\d+\.\d+\.\d+', 4)                    # Cyan for IP addresses
        ]
        self.compiled_colors = [(re.compile(pattern, re.IGNORECASE), color) for pattern, color in self.log_colors]

    def get_containers(self):
        """Initialize container entries from IPs"""
        try:
            with self.container_status_lock:
                for ip in self.ips:
                    container_name = f"qnx-container-{ip.replace('.', '-')}"
                    if container_name not in self.containers:
                        self.containers[container_name] = {
                            "ip": ip,
                            "status": "Unknown",
                            "containers": {"qnx": {"ready": True, "state": "manual"}},
                            "connected_to": set(),
                            "last_log_time": None
                        }
            return True
        except Exception as e:
            self.log_queue.put(f"Error initializing containers: {str(e)}")
            return False

    def capture_tcp_traffic(self):
        """Use tcpdump to capture TCP traffic between QNX containers with full verbosity"""
        try:
            # Get all pod IPs to create a filter expression
            with self.container_status_lock:
                pod_ips = [pod["ip"] for pod in self.containers.values()]
                self.log_queue.put(f"[TCPDUMP_DEBUG] Current monitored IPs: {', '.join(pod_ips)}")

            if not pod_ips:
                self.log_queue.put("[TCPDUMP_WARNING] No IP addresses available for monitoring, waiting...")
                time.sleep(5)
                return

            # Build tcpdump filter
            ip_filter = " or ".join([f"host {ip}" for ip in pod_ips])
            self.log_queue.put(f"[TCPDUMP_DEBUG] Generated IP filter: {ip_filter}")

            # Port filtering logic
            port_filter = ""
            if self.ports and not self.all_ports:
                port_expressions = [f"port {port}" for port in self.ports]
                port_filter = " or ".join(port_expressions)
                self.log_queue.put(f"[TCPDUMP_DEBUG] Generated port filter: {port_filter}")

                filter_expr = f"({ip_filter}) and ({port_filter})" if ip_filter and port_filter else port_filter
            else:
                filter_expr = ip_filter
                self.log_queue.put("[TCPDUMP_DEBUG] Monitoring all ports between specified IPs")

            self.log_queue.put(f"[TCPDUMP_DEBUG] Final filter expression: {filter_expr}")

            # Build tcpdump command
            cmd = ["tcpdump", "-l", "-n", "-v", filter_expr]
            cmd_str = " ".join(cmd)
            self.log_queue.put(f"[TCPDUMP_COMMAND] Executing: {cmd_str}")

            # Execute command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self.log_queue.put(f"[TCPDUMP_PROCESS] Started tcpdump with PID: {process.pid}")

            # Patterns for parsing
            tcp_pattern = re.compile(
                r'(\d+:\d+:\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags (\S+).*?(\d+) (\w+)'
            )

            last_traffic_time = time.time()
            last_warning_time = 0
            warning_interval = 10

            def log_tcpdump_output(source, line):
                """Helper to log output with timestamp and source"""
                timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                self.log_queue.put(f"[TCPDUMP_{source}:{timestamp}] {line.strip()}")

            # Monitor both stdout and stderr
            while not self.stop_event.is_set():
                # Check stdout
                stdout_line = process.stdout.readline()
                if stdout_line:
                    log_tcpdump_output("STDOUT", stdout_line)
                    last_traffic_time = time.time()

                    # Parse TCP line if it matches our pattern
                    match = tcp_pattern.search(stdout_line)
                    if match:
                        timestamp, src_ip, src_port, dst_ip, dst_port, flags, seq, ack = match.groups()
                        event_type = {
                            'S': 'SYN (Connection initiation)',
                            'F': 'FIN (Connection termination)',
                            'A': 'ACK (Acknowledgement)',
                            'P': 'PSH (Data push)',
                            'R': 'RST (Reset)'
                        }
                        events = [event_type[f] for f in event_type if f in flags]
                        event = " + ".join(events) if events else "Data transfer"
                        
                        log_tcpdump_output("PARSE", (
                            f"Packet: {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                            f"Flags: {flags} ({event}) | "
                            f"Seq: {seq} | Ack: {ack}"
                        ))
                    self._update_connections(stdout_line)

                # Check stderr
                stderr_line = process.stderr.readline()
                if stderr_line:
                    log_tcpdump_output("STDERR", stderr_line)

                # No output case
                if not stdout_line and not stderr_line:
                    current_time = time.time()
                    if (current_time - last_traffic_time) > warning_interval:
                        if (current_time - last_warning_time) > warning_interval:
                            log_tcpdump_output("WARNING", 
                                f"No TCP traffic detected for {warning_interval} seconds. "
                                f"Filter: {filter_expr}"
                            )
                            last_warning_time = current_time
                    time.sleep(0.1)  # Prevent CPU overload

            # Process ended
            return_code = process.poll()
            if return_code is not None:
                log_tcpdump_output("STATUS", f"tcpdump process ended with return code: {return_code}")

        except Exception as e:
            error_time = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            self.log_queue.put(f"[TCPDUMP_ERROR:{error_time}] {str(e)}")
            self.log_queue.put(f"[TCPDUMP_ERROR:{error_time}] Traceback: {traceback.format_exc()}")

    def _update_connections(self, tcp_line):
        """Update connection information between pods based on TCP traffic"""
        # Enhanced TCP pattern to extract more information
        tcp_pattern = re.compile(
            r'IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): '
            r'Flags \[([^\]]+)\], seq (\d+):?(\d+)?, (ack (\d+))?, win (\d+)'
            r'(?:, options \[([^\]]+)\])?(?:, length (\d+))?'
        )
        match = tcp_pattern.search(tcp_line)

        connection_details = {}
        if match:
            src_ip, src_port, dst_ip, dst_port, flags, seq_start, seq_end, _, ack_num, win, options, length = match.groups()
            connection_details = {
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'flags': flags,
                'seq': seq_start + (f":{seq_end}" if seq_end else ""),
                'ack': ack_num,
                'win': win,
                'options': options,
                'length': length
            }

        with self.container_status_lock:
            for src_pod_name, src_pod in self.containers.items():
                if src_pod["ip"] in tcp_line:
                    for dst_pod_name, dst_pod in self.containers.items():
                        if dst_pod_name != src_pod_name and dst_pod["ip"] in tcp_line:
                            src_pod["connected_to"].add(dst_pod_name)

                            # Store connection details in the pod info
                            if "connection_history" not in src_pod:
                                src_pod["connection_history"] = []

                            if connection_details:
                                # Add timestamp
                                connection_details['timestamp'] = datetime.now().isoformat()
                                connection_details['target_pod'] = dst_pod_name
                                src_pod["connection_history"].append(connection_details)
                                # Keep only the last 100 connection records
                                if len(src_pod["connection_history"]) > 100:
                                    src_pod["connection_history"].pop(0)

    def ping_containers(self):
        """Ping containers to check connectivity"""
        while not self.stop_event.is_set():
            with self.container_status_lock:
                for pod_name, pod_info in self.containers.items():
                    ip = pod_info["ip"]
                    try:
                        # Check if the host is reachable
                        cmd = ["ping", "-c", "1", "-W", "1", ip]
                        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                        if result.returncode == 0:
                            time_match = re.search(r'time=([\d.]+)\s*ms', result.stdout)
                            if time_match:
                                time_ms = time_match.group(1)
                                log_msg = f"[{pod_name}:{datetime.now().strftime('%H:%M:%S')}] Host {ip} is reachable (ping: {time_ms}ms)"
                            else:
                                log_msg = f"[{pod_name}:{datetime.now().strftime('%H:%M:%S')}] Host {ip} is reachable"
                            self.containers[pod_name]["status"] = "Reachable"
                            self.log_queue.put(log_msg)
                        else:
                            self.containers[pod_name]["status"] = "Unreachable"
                            self.log_queue.put(f"[{pod_name}:{datetime.now().strftime('%H:%M:%S')}] Unable to reach host {ip}")
                    except Exception as e:
                        self.log_queue.put(f"Error pinging {ip}: {str(e)}")

            time.sleep(self.refresh_interval)

    def monitor_containers(self):
        """Main monitoring loop"""
        # Initialize containers
        self.get_containers()

        # Start TCP traffic monitoring
        tcp_thread = threading.Thread(target=self.capture_tcp_traffic)
        tcp_thread.daemon = True
        tcp_thread.start()

        # Start the ping thread
        ping_thread = threading.Thread(target=self.ping_containers)
        ping_thread.daemon = True
        ping_thread.start()

        while not self.stop_event.is_set():
            time.sleep(self.refresh_interval)

    def get_log_color(self, log_line):
        """Returns a list of (start_pos, end_pos, color_pair) for colored segments"""
        colored_segments = []
        for pattern, color in self.compiled_colors:
            for match in pattern.finditer(log_line):
                colored_segments.append((match.start(), match.end(), curses.color_pair(color)))
        return colored_segments

    def display_connection_stats(self, stdscr):
        """Display detailed connection statistics in a new view"""
        curses.curs_set(0)
        height, width = stdscr.getmaxyx()

        try:
            while True:
                stdscr.clear()

                # Display header
                header = " QNX Connection Statistics "
                stdscr.addstr(0, 0, header.center(width), curses.color_pair(5) | curses.A_BOLD)

                row = 2
                with self.container_status_lock:
                    for pod_name, pod_info in sorted(self.containers.items()):
                        if "connection_history" in pod_info and pod_info["connection_history"]:
                            stdscr.addstr(row, 0, f"Pod: {pod_name}", curses.color_pair(4) | curses.A_BOLD)
                            row += 1

                            # Display connection summary
                            connections_by_target = {}
                            for conn in pod_info["connection_history"]:
                                target = conn.get('target_pod', 'unknown')
                                if target not in connections_by_target:
                                    connections_by_target[target] = {'count': 0, 'data_bytes': 0}
                                connections_by_target[target]['count'] += 1
                                if conn.get('length'):
                                    connections_by_target[target]['data_bytes'] += int(conn.get('length', 0))

                            for target, stats in connections_by_target.items():
                                if row < height - 1:
                                    stdscr.addstr(row, 2, f"→ {target}: {stats['count']} packets, {stats['data_bytes']} bytes")
                                    row += 1

                            # Show recent connections
                            if row < height - 1:
                                stdscr.addstr(row, 2, "Recent connections:", curses.A_BOLD)
                                row += 1

                            for conn in reversed(pod_info["connection_history"][-5:]):  # Show last 5 connections
                                if row < height - 1:
                                    timestamp = conn.get('timestamp', '').split('T')[1][:8]
                                    flags = conn.get('flags', '')
                                    src_port = conn.get('src_port', '')
                                    dst_port = conn.get('dst_port', '')
                                    length = conn.get('length', '0')
                                    target = conn.get('target_pod', 'unknown')

                                    conn_str = f"{timestamp} {flags} → {target}:{dst_port} ({length} bytes)"
                                    stdscr.addstr(row, 4, conn_str)
                                    row += 1

                            row += 1  # Add space between pods

                # Key help
                stdscr.addstr(height-1, 0, "Press 'b' to go back", curses.color_pair(5))

                stdscr.refresh()

                # Check for key input
                stdscr.timeout(500)
                key = stdscr.getch()
                if key == ord('b'):
                    break

        except Exception as e:
            self.log_queue.put(f"Error in connection stats: {str(e)}")

    def display_ui(self, stdscr):
        """Display the monitoring UI using curses"""
        curses.curs_set(0)  # Hide cursor
        curses.start_color()
        curses.use_default_colors()

        # Define color pairs
        curses.init_pair(1, curses.COLOR_GREEN, -1)  # Running/Reachable
        curses.init_pair(2, curses.COLOR_YELLOW, -1)  # Pending
        curses.init_pair(3, curses.COLOR_RED, -1)  # Failed/Error/Unreachable
        curses.init_pair(4, curses.COLOR_CYAN, -1)  # Headers
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Header background
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)   # SYN
        curses.init_pair(7, curses.COLOR_BLUE, -1)      # Data/ACK
        curses.init_pair(8, curses.COLOR_YELLOW, -1)    # Pending/Idle

        # Start monitoring in a separate thread
        monitor_thread = threading.Thread(target=self.monitor_containers)
        monitor_thread.daemon = True
        monitor_thread.start()

        # Log storage
        logs = []
        max_logs = 1000

        try:
            while True:
                stdscr.clear()
                height, width = stdscr.getmaxyx()

                # Get latest logs from queue
                while not self.log_queue.empty():
                    log = self.log_queue.get_nowait()
                    logs.append(log)
                    if len(logs) > max_logs:
                        logs.pop(0)

                # Display header
                header = f" QNX IP Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
                if self.all_ports:
                    header += " (ALL PORTS) "
                elif self.ports:
                    port_str = ", ".join(map(str, self.ports))
                    header += f" (Ports: {port_str}) "

                stdscr.addstr(0, 0, header.center(width), curses.color_pair(5) | curses.A_BOLD)

                # Display container information
                stdscr.addstr(2, 0, "MONITORED HOSTS:", curses.color_pair(4) | curses.A_BOLD)
                stdscr.addstr(3, 0, f"{'HOST NAME':<25} {'IP':<15} {'STATUS':<10} {'CONNECTED TO':<50}", curses.A_BOLD)

                row = 4
                with self.container_status_lock:
                    for pod_name, pod_info in sorted(self.containers.items()):
                        if row >= height - 10:  # Save space for logs
                            break

                        # Determine status color
                        color = curses.color_pair(1)  # Default: green
                        if pod_info["status"] == "Unknown":
                            color = curses.color_pair(2)
                        elif pod_info["status"] == "Unreachable":
                            color = curses.color_pair(3)

                        # Connected pods
                        connected_to = ", ".join(sorted(pod_info["connected_to"])) if pod_info["connected_to"] else "None"

                        # Display pod info
                        stdscr.addstr(row, 0, f"{pod_name:<25}", curses.A_BOLD)
                        stdscr.addstr(row, 25, f"{pod_info['ip']:<15}")
                        stdscr.addstr(row, 40, f"{pod_info['status']:<10}", color)
                        stdscr.addstr(row, 50, f"{connected_to:<50}")
                        row += 1

                # Display logs section
                log_start_row = row + 2
                stdscr.addstr(log_start_row - 1, 0, "LOGS:", curses.color_pair(4) | curses.A_BOLD)

                # Display the most recent logs that fit in the window
                available_rows = height - log_start_row - 1
                log_slice = logs[-available_rows:] if available_rows > 0 else []

                for i, log in enumerate(log_slice):
                    if log_start_row + i < height:
                        log_display = log[:width-1] if len(log) > width-1 else log
                        colored_segments = self.get_log_color(log_display)

                        # Display the log line first in default color
                        stdscr.addstr(log_start_row + i, 0, log_display)

                        # Then overlay the colored segments
                        for start, end, color in colored_segments:
                            if start < width and end <= width:
                                stdscr.addstr(log_start_row + i, start, log_display[start:end], color)

                # Status line
                status_line = "Press 'q' to exit | 'c' to clear logs | 's' for connection stats"
                stdscr.addstr(height-1, 0, status_line.ljust(width-1), curses.color_pair(5))

                stdscr.refresh()

                # Check for key input with timeout
                stdscr.timeout(100)
                key = stdscr.getch()
                if key == ord('q'):
                    break
                elif key == ord('c'):
                    logs.clear()
                elif key == ord('s'):
                    self.display_connection_stats(stdscr)

        except KeyboardInterrupt:
            pass
        finally:
            self.stop_event.set()
            monitor_thread.join(timeout=1)

def validate_ip(ip):
    """Validate that an IP address is properly formatted"""
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {ip}")

def validate_port(port_str):
    """Validate that a port is a number between 1 and 65535"""
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return port
        raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid port number: {port_str}. Must be between 1 and 65535.")

def main():
    parser = argparse.ArgumentParser(description='Monitor QNX hosts by IP addresses')
    parser.add_argument('--refresh', '-r', type=int, default=5, help='Status refresh interval in seconds')
    parser.add_argument('--ips', '-i', type=validate_ip, nargs='+', help='List of IP addresses to monitor')
    parser.add_argument('--ip-file', '-f', help='File containing IP addresses to monitor (one per line)')

    # Port filtering options - create a mutually exclusive group
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('--ports', '-p', type=validate_port, nargs='+',
                        help='Specific ports to monitor (e.g., 8080, 443, etc.)')
    port_group.add_argument('--all-ports', '-a', action='store_true',
                        help='Monitor all ports (default behavior)')

    args = parser.parse_args()

    # Process IP addresses
    ips = []
    if args.ips:
        ips = args.ips
    elif args.ip_file:
        try:
            with open(args.ip_file, 'r') as f:
                ips = [validate_ip(line.strip()) for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading IP file: {str(e)}")
            return
    else:
        print("Error: You must provide either --ips or --ip-file")
        parser.print_help()
        return

    monitor = QNXMonitor(
        ips=ips,
        refresh_interval=args.refresh,
        ports=args.ports,
        all_ports=args.all_ports or not args.ports  # Default to all ports if no ports specified
    )

    # Start the UI with curses
    curses.wrapper(monitor.display_ui)

if __name__ == "__main__":
    main()
