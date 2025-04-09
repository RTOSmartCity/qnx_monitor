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
    def __init__(self, ips, refresh_interval=5, ports=None, all_ports=False, status_interval=30): # Added status_interval
        self.refresh_interval = refresh_interval
        self.status_interval = status_interval # Interval for printing status summary and tcpdump check
        self.ips = ips
        self.ports = ports  # Specific ports to monitor
        self.all_ports = all_ports  # Flag to monitor all ports
        self.containers = {}
        self.stop_event = threading.Event()
        self.container_status_lock = threading.Lock()
        self.tcpdump_process = None # To store the tcpdump subprocess object
        self.last_status_print_time = 0 # Track when status was last printed

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
        # Attempt to terminate tcpdump quickly on signal
        if self.tcpdump_process and self.tcpdump_process.poll() is None:
            self.log(f"Terminating tcpdump process (PID: {self.tcpdump_process.pid}) due to signal.", level="WARN")
            self.tcpdump_process.terminate()

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
        self.log("Note: tcpdump passively listens on host interfaces for traffic involving specified IPs.", level="INFO")
        self.log("It does NOT act as a 'man in the middle'.", level="INFO")
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
                # Add '-i any' to capture on all interfaces (useful in host mode, requires root/CAP_NET_RAW)
                # If '-i any' causes issues (e.g., permissions), remove it and let tcpdump pick default.
                cmd = ["tcpdump", "-l", "-n", "-v", "-i", "any", filter_expr]
                # If you encounter "any: No such device exists" or permission errors, try removing "-i", "any",
                # cmd = ["tcpdump", "-l", "-n", "-v", filter_expr]
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
                    self.tcpdump_process = process # Store the process object
                    self.log(f"Started tcpdump with PID: {self.tcpdump_process.pid}", level="INFO")

                    # Process stdout
                    for line in iter(process.stdout.readline, ''):
                        if self.stop_event.is_set():
                            break
                        line = line.strip()
                        if line:
                            # Lowering log level for individual packets to avoid flooding
                            self.log(f"[TCPDUMP] {line}", level="DEBUG")
                            self._update_last_tcp_activity(line)

                    # Check for stderr after stdout closes or loop breaks
                    stderr_output = process.stderr.read()
                    if stderr_output:
                        for line in stderr_output.strip().split('\n'):
                             self.log(f"[TCPDUMP_STDERR] {line.strip()}", level="ERROR")

                    # If loop finished without stop_event, check exit code
                    if not self.stop_event.is_set():
                        process.wait() # Wait for the process to finish if it hasn't
                        return_code = process.returncode
                        self.log(f"tcpdump process (PID: {process.pid}) exited unexpectedly with code {return_code}", level="WARN")

                except FileNotFoundError:
                     self.log("Error: 'tcpdump' command not found. Is it installed and in PATH?", level="CRITICAL")
                     self.stop_event.set() # Stop monitoring if tcpdump isn't available
                     self.tcpdump_process = None
                     return
                except PermissionError:
                    self.log("Error: Permission denied running tcpdump. Try running as root or granting CAP_NET_RAW capability.", level="CRITICAL")
                    self.log(traceback.format_exc(), level="ERROR")
                    self.stop_event.set()
                    self.tcpdump_process = None
                    return
                except Exception as e:
                    # Catch potential errors if tcpdump fails immediately (e.g., invalid filter, bad interface)
                    self.log(f"Error running or reading from tcpdump: {str(e)}", level="ERROR")
                    self.log(traceback.format_exc(), level="ERROR")
                    # No process might have been created or it died instantly
                    self.tcpdump_process = None # Ensure it's None if Popen failed
                finally:
                    # --- Cleanup for this specific tcpdump instance ---
                    local_pid = process.pid if process else "N/A"
                    if process and process.poll() is None: # Check if process is still running
                        self.log(f"Terminating tcpdump process (PID: {local_pid})...", level="WARN")
                        process.terminate()
                        try:
                            process.wait(timeout=5) # Wait a bit for termination
                        except subprocess.TimeoutExpired:
                            self.log(f"tcpdump process (PID: {local_pid}) did not terminate gracefully, killing.", level="WARN")
                            process.kill()
                        self.log(f"tcpdump process (PID: {local_pid}) terminated.", level="INFO")
                    elif process:
                        self.log(f"tcpdump process (PID: {local_pid}) already terminated.", level="DEBUG")

                    # Set the shared process reference to None *only if* it's the one we were managing
                    if self.tcpdump_process == process:
                         self.tcpdump_process = None
                         self.log(f"Cleared monitor reference to tcpdump process (PID: {local_pid}).", level="DEBUG")
                    # --- End cleanup ---


                # If the loop exits because tcpdump crashed/exited, wait before restarting
                if not self.stop_event.is_set():
                    self.log("tcpdump process ended. Restarting in 5 seconds...", level="WARN")
                    time.sleep(5)

        except Exception as e:
            self.log(f"Fatal error in TCP capture thread: {str(e)}", level="CRITICAL")
            self.log(traceback.format_exc(), level="CRITICAL")
        finally:
             self.tcpdump_process = None # Ensure it's None on final exit
             self.log("TCP traffic capture thread finished.", level="INFO")


    def _update_last_tcp_activity(self, tcp_line):
        """Update last activity timestamp based on parsed IPs"""
        # Basic IP extraction from tcpdump output line
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        found_ips = ip_pattern.findall(tcp_line)
        now = datetime.now()

        with self.container_status_lock:
            monitored_ips_in_line = {ip for ip in found_ips if ip in [p['ip'] for p in self.containers.values()]}
            if not monitored_ips_in_line: # Only update if a monitored IP was involved
                return

            updated_any = False
            for ip in monitored_ips_in_line:
                 for container_name, container_info in self.containers.items():
                     if container_info["ip"] == ip:
                         if container_info["last_tcp_activity"] != now: # Avoid redundant updates within same second
                            container_info["last_tcp_activity"] = now
                            updated_any = True
                         # Optionally log this update if needed for debugging
                         # self.log(f"Updated last TCP activity for {container_name} ({ip}) to {now}", level="TRACE")
                         break # Move to next IP once matched

            # Log only once per line processed if any update occurred
            # if updated_any:
            #     self.log(f"Processed TCP activity involving: {', '.join(monitored_ips_in_line)}", level="TRACE")


    def ping_containers(self):
        """Periodically ping monitored IPs to check reachability."""
        self.log("Starting ping check thread...", level="INFO")
        while not self.stop_event.is_set():
            ips_to_ping = []
            with self.container_status_lock:
                 # Create a copy to avoid holding lock during potentially slow pings
                 ips_to_ping = list(self.containers.items())

            if not ips_to_ping:
                 self.log("No IPs to ping.", level="DEBUG")

            ping_start_time = time.monotonic()

            for container_name, container_info in ips_to_ping:
                if self.stop_event.is_set(): break # Check stop event frequently

                ip = container_info["ip"]
                # Retrieve current status before pinging for comparison
                current_status = container_info.get("status", "Unknown")
                status = "Unreachable"
                ping_ms = None
                try:
                    # Using -W 1 for 1 second timeout, -c 1 for single ping
                    cmd = ["ping", "-c", "1", "-W", "1", ip]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=2) # 2s timeout for the subprocess call itself

                    now = datetime.now()
                    if result.returncode == 0:
                        status = "Reachable"
                        time_match = re.search(r'time=([\d.]+)\s*ms', result.stdout)
                        if time_match:
                            ping_ms = float(time_match.group(1))
                            # Log only if status changes or periodically? Let's log always for HEALTH check
                            self.log(f"Ping {ip} ({container_name}): {status} ({ping_ms:.2f} ms)", level="HEALTH")
                        else:
                            self.log(f"Ping {ip} ({container_name}): {status} (time not parsed)", level="HEALTH")
                    else:
                        status = "Unreachable"
                        # Log failure only if status changed from reachable/unknown to unreachable
                        if current_status != "Unreachable":
                             stderr_msg = result.stderr.strip()
                             stdout_msg = result.stdout.strip()
                             details = f"stdout: '{stdout_msg}', stderr: '{stderr_msg}'" if (stdout_msg or stderr_msg) else "No output"
                             self.log(f"Ping {ip} ({container_name}): {status}. RC={result.returncode}. {details}", level="WARN")
                        # No else needed - don't repeatedly log "Unreachable"

                    # Update status in the shared dict
                    with self.container_status_lock:
                         self.containers[container_name]["status"] = status
                         self.containers[container_name]["last_ping_time"] = now
                         self.containers[container_name]["last_ping_ms"] = ping_ms

                except subprocess.TimeoutExpired:
                    now = datetime.now()
                    status = "Timeout"
                    # Log only if status changed
                    if current_status != "Timeout":
                        self.log(f"Ping {ip} ({container_name}): {status}", level="WARN")
                    with self.container_status_lock:
                        self.containers[container_name]["status"] = status
                        self.containers[container_name]["last_ping_time"] = now
                        self.containers[container_name]["last_ping_ms"] = None
                except Exception as e:
                    now = datetime.now()
                    status = "Error"
                    # Log error always? Maybe only if status changes? Let's log always for errors.
                    self.log(f"Error pinging {ip} ({container_name}): {str(e)}", level="ERROR")
                    self.log(traceback.format_exc(), level="ERROR")
                    with self.container_status_lock:
                         self.containers[container_name]["status"] = status
                         self.containers[container_name]["last_ping_time"] = now
                         self.containers[container_name]["last_ping_ms"] = None

            # Calculate time spent pinging and sleep for the remaining interval
            ping_duration = time.monotonic() - ping_start_time
            sleep_time = max(0, self.refresh_interval - ping_duration)
            self.log(f"Ping cycle finished in {ping_duration:.2f}s. Sleeping for {sleep_time:.2f}s.", level="DEBUG")
            self.stop_event.wait(sleep_time) # Wait efficiently

        self.log("Ping check thread finished.", level="INFO")


    def run(self):
        """Starts the monitoring threads and keeps the main thread alive."""
        self.log("Starting QNX Monitor...", level="INFO")

        # Start TCP traffic monitoring
        tcp_thread = threading.Thread(target=self.capture_tcp_traffic, name="TCPCaptureThread", daemon=True)
        tcp_thread.start()

        # Start the ping thread
        ping_thread = threading.Thread(target=self.ping_containers, name="PingThread", daemon=True)
        ping_thread.start()

        # Keep main thread alive, periodically print status and check tcpdump
        while not self.stop_event.is_set():
            try:
                now = time.time()
                # Check if it's time to print status
                if now - self.last_status_print_time >= self.status_interval:
                    self.print_status_summary()
                    self.check_tcpdump_status() # Check tcpdump status when printing summary
                    self.last_status_print_time = now

                # Sleep for a short interval to avoid busy-waiting
                # Use wait on the stop event for responsiveness
                self.stop_event.wait(timeout=1.0)

            except KeyboardInterrupt: # Catch Ctrl+C in main loop too
                self.log("KeyboardInterrupt caught in main loop. Shutting down...", level="WARN")
                self.stop_event.set()
                break
            except Exception as e: # Catch unexpected errors in the main loop
                self.log(f"Unexpected error in main loop: {e}", level="CRITICAL")
                self.log(traceback.format_exc(), level="CRITICAL")
                self.stop_event.set() # Trigger shutdown on critical error
                break

        # Wait for threads to finish
        self.log("Waiting for monitoring threads to stop...", level="INFO")
        if ping_thread.is_alive():
            ping_thread.join(timeout=self.refresh_interval + 2) # Give ping thread time to finish cycle
        if tcp_thread.is_alive():
            tcp_thread.join(timeout=10) # Give tcpdump time to terminate

        if ping_thread.is_alive():
            self.log("Ping thread did not stop gracefully.", level="WARN")
        if tcp_thread.is_alive():
            self.log("TCP capture thread did not stop gracefully.", level="WARN")

        self.log("QNX Monitor stopped.", level="INFO")
        # Use os._exit to force exit if threads are stuck, though join should handle most cases
        # sys.exit(0) might hang if a daemon thread refuses to die.
        os._exit(0) # Force exit after cleanup attempt


    def check_tcpdump_status(self):
        """Checks and logs the status of the tcpdump process."""
        if self.tcpdump_process:
            # Check if the process object exists and is running
            if self.tcpdump_process.poll() is None:
                 self.log(f"TCPDump Status: Running (PID: {self.tcpdump_process.pid})", level="STATUS")
            else:
                 # Process object exists but has terminated
                 exit_code = self.tcpdump_process.poll()
                 self.log(f"TCPDump Status: Stopped (PID: {self.tcpdump_process.pid}, Exit Code: {exit_code}). Capture thread should restart it.", level="WARN")
                 # The capture_tcp_traffic thread is responsible for restarting it.
        else:
             # Process object is None. This is normal during startup, shutdown, or between restarts.
             if not self.stop_event.is_set():
                 # Check if the capture thread itself is still alive
                 capture_thread_alive = any(t.name == "TCPCaptureThread" and t.is_alive() for t in threading.enumerate())
                 if capture_thread_alive:
                    self.log("TCPDump Status: Not running (currently initializing or restarting).", level="STATUS")
                 else:
                    self.log("TCPDump Status: Not running (Capture thread seems inactive).", level="WARN")
             else:
                self.log("TCPDump Status: Stopped (Shutdown in progress).", level="STATUS")

    # Renamed level for clarity
    def print_status_summary(self):
         self.log("--- Host Status Summary ---", level="STATUS")
         with self.container_status_lock:
             if not self.containers:
                 self.log("No hosts configured.", level="STATUS")
                 return
             # Sort by IP address for consistent output
             sorted_items = sorted(self.containers.items(), key=lambda item: ipaddress.ip_address(item[1]['ip']))

             for name, info in sorted_items:
                 ip = info['ip']
                 status = info['status']
                 last_ping_dt = info.get('last_ping_time')
                 last_ping = last_ping_dt.strftime('%Y-%m-%d %H:%M:%S') if last_ping_dt else 'N/A'
                 ping_ms = f"{info['last_ping_ms']:.2f}ms" if info.get('last_ping_ms') is not None else 'N/A'
                 last_tcp_dt = info.get('last_tcp_activity')
                 last_tcp = last_tcp_dt.strftime('%Y-%m-%d %H:%M:%S') if last_tcp_dt else 'None Seen'
                 # Calculate time since last TCP activity
                 tcp_age = f" ({(datetime.now() - last_tcp_dt).total_seconds():.0f}s ago)" if last_tcp_dt else ""

                 self.log(f"{name:<15} ({ip:>15}): Status={status:<12} Last Ping={last_ping} ({ping_ms:<8}) Last TCP={last_tcp}{tcp_age}", level="STATUS")
         self.log("---------------------------", level="STATUS")


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
    parser = argparse.ArgumentParser(description='Monitor QNX hosts by IP addresses (Ping & TCP Traffic via tcpdump) and log to stdout')
    parser.add_argument('--refresh', '-r', type=int, default=10, help='Ping refresh interval in seconds (default: 10)')
    parser.add_argument('--status-interval', '-s', type=int, default=30, help='Interval for printing status summary and checking tcpdump status (seconds, default: 30)')
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
        ip_file_path = args.ip_file
        # Handle potential path issues if running in container vs local
        if not os.path.isabs(ip_file_path) and os.path.exists(f"/app/{ip_file_path}"):
             ip_file_path = f"/app/{ip_file_path}"
             print(f"Adjusted IP file path to container path: {ip_file_path}", file=sys.stderr) # Use stderr for info messages like this
        elif not os.path.exists(ip_file_path):
             # Check common container path if absolute path fails
             container_path = f"/app/config/{os.path.basename(ip_file_path)}"
             if os.path.exists(container_path):
                 ip_file_path = container_path
                 print(f"Using IP file from default container config path: {ip_file_path}", file=sys.stderr)

        try:
            with open(ip_file_path, 'r') as f:
                ips = [validate_ip(line.strip()) for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
             print(f"Error: IP file not found: {args.ip_file} (tried {ip_file_path})", file=sys.stderr)
             sys.exit(1)
        except Exception as e:
            print(f"Error reading IP file '{ip_file_path}': {str(e)}", file=sys.stderr)
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
        all_ports=monitor_all_ports,
        status_interval=args.status_interval # Pass the status interval
    )

    # Run the monitor
    monitor.run()

if __name__ == "__main__":
    main()
