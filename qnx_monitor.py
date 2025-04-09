import os
import time
import threading
import argparse
import ipaddress
from datetime import datetime
import re
import subprocess
import signal
import sys
import traceback # Added for better error reporting

class QNXMonitor:
    def __init__(self, ips, refresh_interval=5, ports=None, all_ports=False):
        self.refresh_interval = refresh_interval
        self.ips = ips
        self.ports = ports  # Specific ports to monitor
        self.all_ports = all_ports  # Flag to monitor all ports
        self.containers = {}
        self.stop_event = threading.Event()
        self.container_status_lock = threading.Lock() # Lock remains useful for shared container dict

        # Initialize container entries from IPs
        self.initialize_containers()

        # Setup signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def log(self, message, level="INFO"):
        """Logs a message to standard output with a timestamp."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print(f"{timestamp} [{level}] {message}", flush=True) # Ensure output is flushed

    def signal_handler(self, signum, frame):
        """Handles termination signals."""
        self.log(f"Received signal {signum}. Shutting down...", level="WARN")
        self.stop_event.set()

    def initialize_containers(self):
        """Initialize container entries from IPs"""
        try:
            with self.container_status_lock:
                for ip in self.ips:
                    # Use a simpler name, or keep the old one if preferred
                    container_name = f"host-{ip}"
                    if container_name not in self.containers:
                        self.containers[container_name] = {
                            "ip": ip,
                            "status": "Unknown",
                            "last_ping_time": None,
                            "last_ping_ms": None,
                            "last_tcp_activity": None,
                        }
            self.log(f"Initialized monitoring for IPs: {', '.join(self.ips)}", level="INFO")
            return True
        except Exception as e:
            self.log(f"Error initializing containers: {str(e)}", level="ERROR")
            self.log(traceback.format_exc(), level="ERROR")
            return False

    def capture_tcp_traffic(self):
        """Use tcpdump to capture TCP traffic involving the monitored IPs."""
        self.log("Starting TCP traffic capture thread...", level="INFO")
        try:
            while not self.stop_event.is_set():
                pod_ips = []
                with self.container_status_lock:
                    pod_ips = [pod["ip"] for pod in self.containers.values()]

                if not pod_ips:
                    self.log("No IP addresses available for monitoring, waiting...", level="WARN")
                    time.sleep(5)
                    continue

                # Build tcpdump filter: capture traffic if *any* monitored IP is source OR destination
                ip_filter = " or ".join([f"host {ip}" for ip in pod_ips])
                self.log(f"Generated IP filter: {ip_filter}", level="DEBUG")

                # Port filtering logic
                port_filter = ""
                if self.ports and not self.all_ports:
                    port_expressions = [f"port {port}" for port in self.ports]
                    port_filter = " or ".join(port_expressions)
                    self.log(f"Generated port filter: {port_filter}", level="DEBUG")
                    # Combine filters: Match TCP protocol AND (ip filter) AND (port filter)
                    filter_expr = f"tcp and ({ip_filter}) and ({port_filter})"
                elif self.all_ports:
                     # Match TCP protocol AND (ip filter) - Monitor all TCP ports
                    filter_expr = f"tcp and ({ip_filter})"
                    self.log("Monitoring all TCP ports for specified IPs", level="DEBUG")
                else:
                    # Default case if neither --ports nor --all-ports specified (shouldn't happen with argparse logic, but safe)
                    # Match TCP protocol AND (ip filter) - Monitor all TCP ports
                    filter_expr = f"tcp and ({ip_filter})"
                    self.log("Defaulting to monitoring all TCP ports for specified IPs", level="DEBUG")

                self.log(f"Final tcpdump filter expression: '{filter_expr}'", level="INFO")

                # Build tcpdump command: -l line buffered, -n no name resolution, -v verbose
                cmd = ["tcpdump", "-l", "-n", "-v", filter_expr]
                cmd_str = " ".join(cmd)
                self.log(f"Executing tcpdump command: {cmd_str}", level="INFO")

                process = None
                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1, # Line buffered
                        universal_newlines=True
                    )
                    self.log(f"Started tcpdump with PID: {process.pid}", level="INFO")

                    # Process stdout
                    for line in iter(process.stdout.readline, ''):
                        if self.stop_event.is_set():
                            break
                        line = line.strip()
                        if line:
                            self.log(f"[TCPDUMP_STDOUT] {line}", level="TRAFFIC")
                            self._update_last_tcp_activity(line)

                    # Check for stderr after stdout closes or loop breaks
                    stderr_output = process.stderr.read()
                    if stderr_output:
                        for line in stderr_output.strip().split('\n'):
                             self.log(f"[TCPDUMP_STDERR] {line.strip()}", level="ERROR")

                    process.wait() # Wait for the process to finish if it hasn't
                    return_code = process.returncode
                    self.log(f"tcpdump process (PID: {process.pid}) exited with code {return_code}", level="WARN")

                except FileNotFoundError:
                     self.log("Error: 'tcpdump' command not found. Is it installed?", level="CRITICAL")
                     self.stop_event.set() # Stop monitoring if tcpdump isn't available
                     return
                except Exception as e:
                    self.log(f"Error running or reading from tcpdump: {str(e)}", level="ERROR")
                    self.log(traceback.format_exc(), level="ERROR")
                finally:
                    if process and process.poll() is None: # Check if process is still running
                        self.log(f"Terminating tcpdump process (PID: {process.pid})...", level="WARN")
                        process.terminate()
                        try:
                            process.wait(timeout=5) # Wait a bit for termination
                        except subprocess.TimeoutExpired:
                            self.log(f"tcpdump process (PID: {process.pid}) did not terminate gracefully, killing.", level="WARN")
                            process.kill()
                        self.log(f"tcpdump process (PID: {process.pid}) terminated.", level="INFO")

                # If the loop exits because tcpdump crashed, wait before restarting
                if not self.stop_event.is_set():
                    self.log("tcpdump process ended unexpectedly. Restarting in 5 seconds...", level="WARN")
                    time.sleep(5)

        except Exception as e:
            self.log(f"Fatal error in TCP capture thread: {str(e)}", level="CRITICAL")
            self.log(traceback.format_exc(), level="CRITICAL")
        finally:
             self.log("TCP traffic capture thread finished.", level="INFO")


    def _update_last_tcp_activity(self, tcp_line):
        """Update last activity timestamp based on parsed IPs"""
        # Basic IP extraction from tcpdump output line
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        found_ips = ip_pattern.findall(tcp_line)
        now = datetime.now()

        with self.container_status_lock:
            monitored_ips_in_line = {ip for ip in found_ips if ip in [p['ip'] for p in self.containers.values()]}
            for ip in monitored_ips_in_line:
                 for container_name, container_info in self.containers.items():
                     if container_info["ip"] == ip:
                         container_info["last_tcp_activity"] = now
                         # Optionally log this update if needed for debugging
                         # self.log(f"Updated last TCP activity for {container_name} ({ip}) to {now}", level="DEBUG")
                         break


    def ping_containers(self):
        """Periodically ping monitored IPs to check reachability."""
        self.log("Starting ping check thread...", level="INFO")
        while not self.stop_event.is_set():
            ips_to_ping = []
            with self.container_status_lock:
                 ips_to_ping = list(self.containers.items()) # Get ip and info

            if not ips_to_ping:
                 self.log("No IPs to ping.", level="DEBUG")

            for container_name, container_info in ips_to_ping:
                if self.stop_event.is_set(): break # Check stop event frequently

                ip = container_info["ip"]
                status = "Unreachable"
                ping_ms = None
                try:
                    # Using -W 1 for 1 second timeout
                    cmd = ["ping", "-c", "1", "-W", "1", ip]
                    # stderr=subprocess.DEVNULL prevents cluttering logs with ping errors unless verbose
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)

                    now = datetime.now()
                    if result.returncode == 0:
                        status = "Reachable"
                        time_match = re.search(r'time=([\d.]+)\s*ms', result.stdout)
                        if time_match:
                            ping_ms = float(time_match.group(1))
                            self.log(f"Ping {ip} ({container_name}): {status} ({ping_ms:.2f} ms)", level="HEALTH")
                        else:
                            self.log(f"Ping {ip} ({container_name}): {status} (time not parsed)", level="HEALTH")
                    else:
                        # Log detailed failure only if status changes or first time
                        if container_info.get("status") != "Unreachable":
                             self.log(f"Ping {ip} ({container_name}): {status}. Error: {result.stderr.strip()}", level="WARN")
                        status = "Unreachable"

                    # Update status in the shared dict
                    with self.container_status_lock:
                         self.containers[container_name]["status"] = status
                         self.containers[container_name]["last_ping_time"] = now
                         self.containers[container_name]["last_ping_ms"] = ping_ms

                except subprocess.TimeoutExpired:
                    self.log(f"Ping {ip} ({container_name}): Timeout", level="WARN")
                    with self.container_status_lock:
                        self.containers[container_name]["status"] = "Timeout"
                        self.containers[container_name]["last_ping_time"] = datetime.now()
                        self.containers[container_name]["last_ping_ms"] = None
                except Exception as e:
                    self.log(f"Error pinging {ip} ({container_name}): {str(e)}", level="ERROR")
                    self.log(traceback.format_exc(), level="ERROR")
                    with self.container_status_lock:
                         self.containers[container_name]["status"] = "Error"
                         self.containers[container_name]["last_ping_time"] = datetime.now()
                         self.containers[container_name]["last_ping_ms"] = None

            # Wait for the refresh interval before the next round
            self.stop_event.wait(self.refresh_interval)

        self.log("Ping check thread finished.", level="INFO")


    def run(self):
        """Starts the monitoring threads and keeps the main thread alive."""
        self.log("Starting QNX Monitor...", level="INFO")

        # Start TCP traffic monitoring
        tcp_thread = threading.Thread(target=self.capture_tcp_traffic, daemon=True)
        tcp_thread.start()

        # Start the ping thread
        ping_thread = threading.Thread(target=self.ping_containers, daemon=True)
        ping_thread.start()

        # Keep main thread alive doing nothing, waiting for stop signal
        while not self.stop_event.is_set():
            try:
                # Optional: Print a periodic status summary here if desired
                self.print_status_summary()
                time.sleep(1) # Keep alive loop
            except KeyboardInterrupt: # Catch Ctrl+C in main loop too
                self.log("KeyboardInterrupt caught in main loop. Shutting down...", level="WARN")
                self.stop_event.set()
                break

        # Wait for threads to finish
        self.log("Waiting for monitoring threads to stop...", level="INFO")
        ping_thread.join(timeout=self.refresh_interval + 2) # Give ping thread time to finish cycle
        tcp_thread.join(timeout=10) # Give tcpdump time to terminate

        if ping_thread.is_alive():
            self.log("Ping thread did not stop gracefully.", level="WARN")
        if tcp_thread.is_alive():
            self.log("TCP capture thread did not stop gracefully.", level="WARN")

        self.log("QNX Monitor stopped.", level="INFO")
        sys.exit(0)

    # Optional: Add a method to print a summary periodically if needed
    def print_status_summary(self):
         self.log("--- Status Summary ---", level="STATUS")
         with self.container_status_lock:
             if not self.containers:
                 self.log("No hosts configured.", level="STATUS")
                 return
             for name, info in sorted(self.containers.items()):
                 ip = info['ip']
                 status = info['status']
                 last_ping = info['last_ping_time'].strftime('%H:%M:%S') if info.get('last_ping_time') else 'N/A'
                 ping_ms = f"{info['last_ping_ms']:.2f}ms" if info.get('last_ping_ms') is not None else 'N/A'
                 last_tcp = info['last_tcp_activity'].strftime('%H:%M:%S') if info.get('last_tcp_activity') else 'None'
                 self.log(f"{name} ({ip}): Status={status}, Last Ping={last_ping} ({ping_ms}), Last TCP Activity={last_tcp}", level="STATUS")
         self.log("----------------------", level="STATUS")


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
    parser = argparse.ArgumentParser(description='Monitor QNX hosts by IP addresses and log to stdout')
    parser.add_argument('--refresh', '-r', type=int, default=10, help='Ping refresh interval in seconds (default: 10)')
    parser.add_argument('--ips', '-i', type=validate_ip, nargs='+', help='List of IP addresses to monitor')
    parser.add_argument('--ip-file', '-f', help='File containing IP addresses to monitor (one per line)')

    # Port filtering options - create a mutually exclusive group
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('--ports', '-p', type=validate_port, nargs='+',
                        help='Specific TCP ports to monitor (e.g., 8080 443)')
    port_group.add_argument('--all-ports', '-a', action='store_true',
                        help='Monitor all TCP ports (Default behavior if no ports are specified)')

    args = parser.parse_args()

    # Process IP addresses
    ips = []
    if args.ips:
        ips = args.ips
    elif args.ip_file:
        try:
            with open(args.ip_file, 'r') as f:
                ips = [validate_ip(line.strip()) for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
             print(f"Error: IP file not found: {args.ip_file}", file=sys.stderr)
             sys.exit(1)
        except Exception as e:
            print(f"Error reading IP file '{args.ip_file}': {str(e)}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: You must provide either --ips or --ip-file", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    if not ips:
         print("Error: No valid IP addresses found to monitor.", file=sys.stderr)
         sys.exit(1)

    # Determine if all ports should be monitored (explicitly or by default)
    monitor_all_ports = args.all_ports or not args.ports

    monitor = QNXMonitor(
        ips=list(set(ips)), # Ensure unique IPs
        refresh_interval=args.refresh,
        ports=args.ports,
        all_ports=monitor_all_ports
    )

    # Run the monitor
    monitor.run()

if __name__ == "__main__":
    main()
