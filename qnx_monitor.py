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
import traceback

class QNXMonitor:
    def __init__(self, ips, refresh_interval=5, ports=None, all_ports=False, status_interval=30, enable_mitm=False): # Added enable_mitm
        self.refresh_interval = refresh_interval
        self.status_interval = status_interval
        self.ips = list(set(ips))
        self.ports = ports
        self.all_ports = all_ports
        self.enable_mitm = enable_mitm
        self.mitm_interface = None
        self.containers = {}
        self.stop_event = threading.Event()
        self.container_status_lock = threading.Lock()
        self.tcpdump_process = None
        self.arpspoof_processes = []
        self.last_status_print_time = 0

        self.initialize_containers()

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        #if self.enable_mitm:
            #self._check_prerequisites()


    def _check_prerequisites(self):
        """Checks for arpspoof command and IP forwarding if MitM is enabled."""
        self.log("Checking MitM prerequisites...", level="INFO")
        try:
            subprocess.run(["arpspoof", "-h"], capture_output=True, check=True, text=True)
            self.log("Found 'arpspoof' command.", level="INFO")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log("No arpspoof found.", level="CRITICAL")
            self.enable_mitm = False
            return False

        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                ip_forward_status = f.read().strip()
                if ip_forward_status == "1":
                    self.log("IP forwarding (net.ipv4.ip_forward) is enabled.", level="INFO")
        except FileNotFoundError:
            self.log("MitM WARNING: Cannot check IP forwarding status (/proc/sys/net/ipv4/ip_forward not found).", level="WARN")
        except Exception as e:
            self.log(f"MitM WARNING: Error checking IP forwarding status: {e}", level="WARN")

        self.mitm_interface = self._detect_interface()
        if not self.mitm_interface:
            self.log("MitM CRITICAL: Could not automatically detect a suitable network interface for ARP spoofing.", level="CRITICAL")
            self.log("Disabling MitM functionality. You may need to specify it manually.", level="CRITICAL")
            self.enable_mitm = False
            return False
        else:
             self.log(f"Detected network interface for MitM: {self.mitm_interface}", level="INFO")

        return self.enable_mitm

    def _detect_interface(self):
        """Attempt to detect the primary network interface for MitM."""
        self.log("Attempting to detect network interface for MitM...", level="DEBUG")
        try:
            result = subprocess.run(
                ["ip", "route", "get", "8.8.8.8"],
                capture_output=True, text=True, check=True
            )
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                interface = match.group(1)
                self.log(f"Found interface '{interface}' via ip route.", level="DEBUG")
                if os.path.exists(f"/sys/class/net/{interface}"):
                    return interface
                else:
                    self.log(f"Interface '{interface}' found via ip route does not exist in /sys/class/net/", level="WARN")
            else:
                 self.log("Could not parse interface from 'ip route get 8.8.8.8' output.", level="WARN")

        except (FileNotFoundError, subprocess.CalledProcessError, Exception) as e:
            self.log(f"Error detecting interface using 'ip route': {e}", level="WARN")

        try:
            result = subprocess.run(["ip", "link"], capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()
            for i, line in enumerate(lines):
                if ": <" in line and "LOOPBACK" not in line and "UP" in line:
                    match = re.match(r'\d+:\s+([^:@]+)[:@]', line)
                    if match:
                        interface = match.group(1).strip()
                        if interface != 'lo':
                            self.log(f"Found potential interface '{interface}' via 'ip link' (fallback).", level="DEBUG")
                            if os.path.exists(f"/sys/class/net/{interface}"):
                                return interface
                            else:
                                 self.log(f"Fallback interface '{interface}' not in /sys/class/net/", level="WARN")
        except (FileNotFoundError, subprocess.CalledProcessError, Exception) as e:
            self.log(f"Error detecting interface using 'ip link': {e}", level="WARN")

        self.log("Interface detection failed.", level="ERROR")
        return None

    def log(self, message, level="INFO"):
        """Logs a message to standard output with a timestamp."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print(f"{timestamp} [{level}] {message}", flush=True)

    def signal_handler(self, signum, frame):
        """Handles termination signals."""
        self.log(f"Received signal {signum}. Shutting down...", level="WARN")
        self.stop_event.set()
        if self.enable_mitm:
            self._stop_arpspoofing()
        if self.tcpdump_process and self.tcpdump_process.poll() is None:
            self.log(f"Terminating tcpdump process (PID: {self.tcpdump_process.pid}) due to signal.", level="WARN")
            self.tcpdump_process.terminate()

    def initialize_containers(self):
        """Initialize container entries from IPs"""
        try:
            with self.container_status_lock:
                for ip in self.ips:
                    container_name = f"host-{ip}"
                    if container_name not in self.containers:
                        self.containers[container_name] = {
                            "ip": ip,
                            "status": "Unknown",
                            "last_ping_time": None,
                            "last_ping_ms": None,
                            "last_tcp_activity": None,
                            "is_private": ipaddress.ip_address(ip).is_private # Store if IP is private
                        }
            self.log(f"Initialized monitoring for IPs: {', '.join(self.ips)}", level="INFO")
            private_ips = [ip for ip in self.ips if ipaddress.ip_address(ip).is_private]
            public_ips = [ip for ip in self.ips if not ipaddress.ip_address(ip).is_private]
            if private_ips:
                self.log(f"Private IPs found: {', '.join(private_ips)}", level="DEBUG")
            if public_ips:
                 self.log(f"Public IPs found: {', '.join(public_ips)}", level="DEBUG")
            return True
        except Exception as e:
            self.log(f"Error initializing containers: {str(e)}", level="ERROR")
            self.log(traceback.format_exc(), level="ERROR")
            return False

    def _start_arpspoofing(self):
        self.arpspoof_processes = []
        spoofed_pairs = set()

        for i in range(len(private_ips_to_spoof)):
            for j in range(i + 1, len(private_ips_to_spoof)):
                ip_a = private_ips_to_spoof[i]
                ip_b = private_ips_to_spoof[j]
                pair = tuple(sorted((ip_a, ip_b)))

                if pair in spoofed_pairs:
                    continue

                self.log(f"Attempting to MitM between {ip_a} <-> {ip_b}", level="INFO")

                cmd_a_to_b = ["arpspoof", "-i", self.mitm_interface, "-t", ip_a, ip_b]
                cmd_b_to_a = ["arpspoof", "-i", self.mitm_interface, "-t", ip_b, ip_a]

                try:
                    self.log(f"Executing: {' '.join(cmd_a_to_b)}", level="DEBUG")
                    proc_a_to_b = subprocess.Popen(
                        cmd_a_to_b,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    self.arpspoof_processes.append(proc_a_to_b)
                    self.log(f"Started arpspoof PID {proc_a_to_b.pid} ({ip_a} -> {ip_b})", level="INFO")

                    self.log(f"Executing: {' '.join(cmd_b_to_a)}", level="DEBUG")
                    proc_b_to_a = subprocess.Popen(
                        cmd_b_to_a,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    self.arpspoof_processes.append(proc_b_to_a)
                    self.log(f"Started arpspoof PID {proc_b_to_a.pid} ({ip_b} -> {ip_a})", level="INFO")

                    spoofed_pairs.add(pair)
                    time.sleep(0.1)

                except FileNotFoundError:
                    self.log("MitM CRITICAL: 'arpspoof' command disappeared unexpectedly!", level="CRITICAL")
                    self.enable_mitm = False
                    self._stop_arpspoofing() 
                    return
                except Exception as e:
                    self.log(f"MitM ERROR: Failed to start arpspoof for {ip_a} <-> {ip_b}: {e}", level="ERROR")
                    self.log(traceback.format_exc(), level="ERROR")
                    if 'proc_a_to_b' in locals() and proc_a_to_b not in self.arpspoof_processes:
                        proc_a_to_b.terminate()
                        proc_a_to_b.wait()

        if not self.arpspoof_processes:
            self.log("MitM Info: No ARP spoofing processes were successfully started.", level="INFO")
        else:
            self.log(f"MitM: Started {len(self.arpspoof_processes)} arpspoof processes in total.", level="INFO")
            monitor_thread = threading.Thread(target=self._monitor_arpspoofers, daemon=True, name="ArpSpoofMonitor")
            monitor_thread.start()


    def _monitor_arpspoofers(self):
        """Monitors the stdout/stderr of running arpspoof processes."""
        self.log("Starting arpspoof monitor thread.", level="DEBUG")
        monitored_pids = {p.pid for p in self.arpspoof_processes if p.poll() is None}
        self.log(f"Monitoring PIDs: {monitored_pids}", level="DEBUG")

        while not self.stop_event.is_set() and monitored_pids:
            for process in list(self.arpspoof_processes):
                if process.poll() is not None:
                    if process.pid in monitored_pids:
                        self.log(f"MitM WARN: arpspoof process PID {process.pid} terminated unexpectedly with code {process.poll()}.", level="WARN")
                        stderr_output = process.stderr.read()
                        if stderr_output:
                             self.log(f"MitM arpspoof PID {process.pid} STDERR: {stderr_output.strip()}", level="WARN")
                        monitored_pids.remove(process.pid)
                    continue 
                try:
                    pass
                except Exception as e:
                     self.log(f"Error reading from arpspoof PID {process.pid}: {e}", level="ERROR")

            time.sleep(2)

        self.log("Arpspoof monitor thread finished.", level="DEBUG")


    def _stop_arpspoofing(self):
        """Terminates all running arpspoof processes."""
        if not self.arpspoof_processes:
            return 

        self.log(f"Stopping {len(self.arpspoof_processes)} arpspoof processes...", level="INFO")
        for process in self.arpspoof_processes:
            if process.poll() is None: # If process is still running
                self.log(f"Terminating arpspoof PID {process.pid}...", level="DEBUG")
                try:
                    process.terminate() # Send SIGTERM
                except Exception as e:
                     self.log(f"Error terminating arpspoof PID {process.pid}: {e}", level="WARN")

        # Wait for processes to terminate
        start_time = time.time()
        while time.time() - start_time < 10: # Max wait 10 seconds
            all_stopped = True
            running_pids = []
            for process in self.arpspoof_processes:
                if process.poll() is None:
                    all_stopped = False
                    running_pids.append(process.pid)
            if all_stopped:
                self.log("All arpspoof processes terminated gracefully.", level="INFO")
                break
            self.log(f"Waiting for arpspoof PIDs to stop: {running_pids}", level="DEBUG")
            time.sleep(0.5)
        else:
            # Force kill any remaining processes
            self.log("Timeout waiting for arpspoof processes. Force killing remaining...", level="WARN")
            for process in self.arpspoof_processes:
                if process.poll() is None:
                    self.log(f"Killing arpspoof PID {process.pid}...", level="WARN")
                    try:
                        process.kill() # Send SIGKILL
                    except Exception as e:
                        self.log(f"Error killing arpspoof PID {process.pid}: {e}", level="ERROR")

        self.log("Finished stopping arpspoof processes.", level="INFO")
        self.arpspoof_processes = [] # Clear the list


    def capture_tcp_traffic(self):
        """Use tcpdump to capture TCP traffic involving the monitored IPs."""
        # (Keep the existing tcpdump logic, it should see traffic if MitM is working)
        self.log("Starting TCP traffic capture thread...", level="INFO")
        if self.enable_mitm:
             self.log("MitM is enabled; tcpdump should capture intercepted traffic.", level="INFO")
        else:
             self.log("MitM is disabled; tcpdump will capture normally routed traffic seen by the host.", level="INFO")

        # --- Rest of the tcpdump logic remains the same as the previous version ---
        # --- (Includes Popen, reading stdout/stderr, filter building, etc.) ---
        try:
            while not self.stop_event.is_set():
                pod_ips = []
                with self.container_status_lock:
                    # Use all IPs for tcpdump filter, even if only private ones are spoofed
                    pod_ips = [pod["ip"] for pod in self.containers.values()]

                if not pod_ips:
                    self.log("No IP addresses available for tcpdump monitoring, waiting...", level="WARN")
                    time.sleep(5)
                    continue

                ip_filter = " or ".join([f"host {ip}" for ip in pod_ips])
                port_filter_str = ""
                if self.ports and not self.all_ports:
                    port_filter_str = " or ".join([f"port {port}" for port in self.ports])
                    filter_expr = f"tcp and ({ip_filter}) and ({port_filter_str})"
                else: # --all-ports or default
                    filter_expr = f"tcp and ({ip_filter})"

                self.log(f"Final tcpdump filter expression: '{filter_expr}'", level="INFO")

                # Use '-i any' if possible, requires privileges. If MitM is on, use the specific interface?
                # Using '-i any' is generally better even with MitM to catch everything on the host.
                # If '-i any' fails, remove it.
                if self.mitm_interface and self.enable_mitm:
                    # Option 1: Use specific interface (might miss non-MitM traffic)
                    # cmd = ["tcpdump", "-l", "-n", "-v", "-i", self.mitm_interface, filter_expr]
                    # Option 2: Stick with 'any' (probably better)
                    cmd = ["tcpdump", "-l", "-n", "-v", "-i", "any", filter_expr]
                else:
                    # Default when MitM off or interface unknown
                     cmd = ["tcpdump", "-l", "-n", "-v", "-i", "any", filter_expr]
                     # Fallback if '-i any' causes issues (e.g. permissions):
                     # cmd = ["tcpdump", "-l", "-n", "-v", filter_expr]


                cmd_str = " ".join(cmd)
                self.log(f"Executing tcpdump command: {cmd_str}", level="INFO")

                process = None
                try:
                    process = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, bufsize=1, universal_newlines=True
                    )
                    self.tcpdump_process = process
                    self.log(f"Started tcpdump with PID: {self.tcpdump_process.pid}", level="INFO")

                    for line in iter(process.stdout.readline, ''):
                        if self.stop_event.is_set(): break
                        line = line.strip()
                        if line:
                            self.log(f"[TCPDUMP] {line}", level="DEBUG") # Keep DEBUG level for packet lines
                            self._update_last_tcp_activity(line)

                    stderr_output = process.stderr.read()
                    if stderr_output:
                        for line in stderr_output.strip().split('\n'):
                             self.log(f"[TCPDUMP_STDERR] {line.strip()}", level="ERROR")

                    if not self.stop_event.is_set():
                        process.wait()
                        return_code = process.returncode
                        self.log(f"tcpdump process (PID: {process.pid}) exited unexpectedly with code {return_code}", level="WARN")

                except FileNotFoundError:
                     self.log("Error: 'tcpdump' command not found.", level="CRITICAL")
                     self.stop_event.set(); self.tcpdump_process = None; return
                except PermissionError:
                    self.log(f"Error: Permission denied running tcpdump (command: {cmd_str}). Requires CAP_NET_RAW/root.", level="CRITICAL")
                    self.log(traceback.format_exc(), level="ERROR"); self.stop_event.set(); self.tcpdump_process = None; return
                except Exception as e:
                    self.log(f"Error running or reading from tcpdump: {str(e)}", level="ERROR")
                    self.log(traceback.format_exc(), level="ERROR"); self.tcpdump_process = None
                finally:
                    local_pid = process.pid if process else "N/A"
                    if process and process.poll() is None:
                        self.log(f"Terminating tcpdump process (PID: {local_pid})...", level="WARN")
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill()
                        self.log(f"tcpdump process (PID: {local_pid}) terminated.", level="INFO")
                    if self.tcpdump_process == process: self.tcpdump_process = None

                if not self.stop_event.is_set():
                    self.log("tcpdump process ended. Restarting in 5 seconds...", level="WARN")
                    time.sleep(5)

        except Exception as e:
            self.log(f"Fatal error in TCP capture thread: {str(e)}", level="CRITICAL")
            self.log(traceback.format_exc(), level="CRITICAL")
        finally:
             self.tcpdump_process = None
             self.log("TCP traffic capture thread finished.", level="INFO")

    def _update_last_tcp_activity(self, tcp_line):
        """Update last activity timestamp based on parsed IPs"""
        # (No changes needed here)
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        found_ips = ip_pattern.findall(tcp_line)
        now = datetime.now()
        with self.container_status_lock:
            monitored_ips_in_line = {ip for ip in found_ips if ip in self.ips} # Check against all monitored IPs
            if not monitored_ips_in_line: return
            for ip in monitored_ips_in_line:
                 for container_name, container_info in self.containers.items():
                     if container_info["ip"] == ip:
                         container_info["last_tcp_activity"] = now
                         break

    def ping_containers(self):
        """Periodically ping monitored IPs to check reachability."""
        # (No changes needed here, ping is independent of MitM)
        self.log("Starting ping check thread...", level="INFO")
        while not self.stop_event.is_set():
            ips_to_ping = []
            with self.container_status_lock:
                 ips_to_ping = list(self.containers.items())
            if not ips_to_ping:
                 self.log("No IPs to ping.", level="DEBUG")

            ping_start_time = time.monotonic()
            for container_name, container_info in ips_to_ping:
                if self.stop_event.is_set(): break
                ip = container_info["ip"]
                current_status = container_info.get("status", "Unknown")
                status, ping_ms = "Unreachable", None
                try:
                    cmd = ["ping", "-c", "1", "-W", "1", ip]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                    now = datetime.now()
                    if result.returncode == 0:
                        status = "Reachable"
                        match = re.search(r'time=([\d.]+)\s*ms', result.stdout)
                        ping_ms = float(match.group(1)) if match else None
                        self.log(f"Ping {ip} ({container_name}): {status} ({ping_ms:.2f} ms)" if ping_ms else f"Ping {ip} ({container_name}): {status}", level="HEALTH")
                    else:
                        status = "Unreachable"
                        if current_status != "Unreachable":
                             details = f"RC={result.returncode}. stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}'"
                             self.log(f"Ping {ip} ({container_name}): {status}. {details}", level="WARN")
                    with self.container_status_lock:
                         self.containers[container_name].update({"status": status, "last_ping_time": now, "last_ping_ms": ping_ms})
                except subprocess.TimeoutExpired:
                    now = datetime.now(); status = "Timeout"
                    if current_status != "Timeout": self.log(f"Ping {ip} ({container_name}): {status}", level="WARN")
                    with self.container_status_lock: self.containers[container_name].update({"status": status, "last_ping_time": now, "last_ping_ms": None})
                except Exception as e:
                    now = datetime.now(); status = "Error"
                    self.log(f"Error pinging {ip} ({container_name}): {str(e)}", level="ERROR")
                    # self.log(traceback.format_exc(), level="ERROR") # Reduce noise maybe
                    with self.container_status_lock: self.containers[container_name].update({"status": status, "last_ping_time": now, "last_ping_ms": None})

            ping_duration = time.monotonic() - ping_start_time
            sleep_time = max(0, self.refresh_interval - ping_duration)
            self.log(f"Ping cycle finished in {ping_duration:.2f}s. Sleeping for {sleep_time:.2f}s.", level="DEBUG")
            self.stop_event.wait(sleep_time)
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

        if self.enable_mitm:
            self._start_arpspoofing()

        # Keep main thread alive
        while not self.stop_event.is_set():
            try:
                now = time.time()
                if now - self.last_status_print_time >= self.status_interval:
                    self.print_status_summary()
                    self.check_tcpdump_status()
                    if self.enable_mitm: # Check arpspoofers if MitM is running
                        self.check_arpspoofer_status()
                    self.last_status_print_time = now
                self.stop_event.wait(timeout=1.0)
            except KeyboardInterrupt:
                self.log("KeyboardInterrupt caught in main loop. Shutting down...", level="WARN")
                self.stop_event.set()
                break
            except Exception as e:
                self.log(f"Unexpected error in main loop: {e}", level="CRITICAL")
                self.log(traceback.format_exc(), level="CRITICAL")
                self.stop_event.set()
                break

        # Stop MitM processes first
        if self.enable_mitm:
            self._stop_arpspoofing()

        # Wait for threads to finish
        self.log("Waiting for monitoring threads to stop...", level="INFO")
        if ping_thread.is_alive(): ping_thread.join(timeout=self.refresh_interval + 2)
        if tcp_thread.is_alive(): tcp_thread.join(timeout=10)

        if ping_thread.is_alive(): self.log("Ping thread did not stop gracefully.", level="WARN")
        if tcp_thread.is_alive(): self.log("TCP capture thread did not stop gracefully.", level="WARN")

        self.log("QNX Monitor stopped.", level="INFO")
        os._exit(0) # Force exit

    def check_tcpdump_status(self):
        """Checks and logs the status of the tcpdump process."""
        # (No changes needed here)
        if self.tcpdump_process:
            if self.tcpdump_process.poll() is None:
                 self.log(f"TCPDump Status: Running (PID: {self.tcpdump_process.pid})", level="STATUS")
            else:
                 exit_code = self.tcpdump_process.poll()
                 self.log(f"TCPDump Status: Stopped (PID: {self.tcpdump_process.pid}, Exit Code: {exit_code}). Capture thread should restart it.", level="WARN")
        else:
             capture_thread_alive = any(t.name == "TCPCaptureThread" and t.is_alive() for t in threading.enumerate())
             if not self.stop_event.is_set():
                 if capture_thread_alive: self.log("TCPDump Status: Not running (initializing/restarting).", level="STATUS")
                 else: self.log("TCPDump Status: Not running (Capture thread seems inactive).", level="WARN")
             else: self.log("TCPDump Status: Stopped (Shutdown).", level="STATUS")

    def check_arpspoofer_status(self):
        """Checks and logs the status of arpspoof processes."""
        if not self.enable_mitm: return # Only check if MitM was intended

        running_count = 0
        stopped_count = 0
        running_pids = []
        stopped_pids = []

        for process in self.arpspoof_processes:
             if process.poll() is None:
                 running_count += 1
                 running_pids.append(process.pid)
             else:
                 stopped_count += 1
                 stopped_pids.append(f"{process.pid}(RC={process.poll()})")

        if running_count > 0 and stopped_count == 0:
            self.log(f"MitM Status: All {running_count} arpspoof processes Running (PIDs: {running_pids})", level="STATUS")
        elif running_count > 0 and stopped_count > 0:
            self.log(f"MitM Status: {running_count} arpspoof processes Running (PIDs: {running_pids}), {stopped_count} Stopped (PIDs: {stopped_pids})", level="WARN")
        elif running_count == 0 and stopped_count > 0:
             self.log(f"MitM Status: All {stopped_count} arpspoof processes Stopped (PIDs: {stopped_pids})", level="WARN")


    def print_status_summary(self):
         """Prints the status summary of monitored hosts."""
         # (No changes needed here)
         self.log("--- Host Status Summary ---", level="STATUS")
         with self.container_status_lock:
             if not self.containers:
                 self.log("No hosts configured.", level="STATUS"); return
             sorted_items = sorted(self.containers.items(), key=lambda item: ipaddress.ip_address(item[1]['ip']))
             for name, info in sorted_items:
                 ip = info['ip']; status = info['status']
                 last_ping_dt = info.get('last_ping_time'); last_tcp_dt = info.get('last_tcp_activity')
                 last_ping = last_ping_dt.strftime('%Y-%m-%d %H:%M:%S') if last_ping_dt else 'N/A'
                 ping_ms = f"{info['last_ping_ms']:.2f}ms" if info.get('last_ping_ms') is not None else 'N/A'
                 last_tcp = last_tcp_dt.strftime('%Y-%m-%d %H:%M:%S') if last_tcp_dt else 'None Seen'
                 tcp_age = f" ({(datetime.now() - last_tcp_dt).total_seconds():.0f}s ago)" if last_tcp_dt else ""
                 private_flag = "[P]" if info.get('is_private') else "[ ]" # Indicate private IPs

                 self.log(f"{private_flag}{name:<15} ({ip:>15}): Status={status:<12} Last Ping={last_ping} ({ping_ms:<8}) Last TCP={last_tcp}{tcp_age}", level="STATUS")
         self.log("---------------------------", level="STATUS")


# --- Helper Functions ---
def validate_ip(ip):
    try: ipaddress.ip_address(ip); return ip
    except ValueError: raise argparse.ArgumentTypeError(f"Invalid IP address: {ip}")

def validate_port(port_str):
    try: port = int(port_str); assert 1 <= port <= 65535; return port
    except (ValueError, AssertionError): raise argparse.ArgumentTypeError(f"Invalid port: {port_str}")

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(
        description='Monitor Host IPs (Ping & TCP Traffic) with optional MitM (ARP Spoofing).',
    )
    parser.add_argument('--refresh', '-r', type=int, default=10, help='Ping refresh interval (sec, default: 10)')
    parser.add_argument('--status-interval', '-s', type=int, default=30, help='Status print interval (sec, default: 30)')
    parser.add_argument('--ips', '-i', type=validate_ip, nargs='+', help='IP addresses to monitor')
    parser.add_argument('--ip-file', '-f', help='File with IP addresses (one per line)')
    parser.add_argument('--enable-mitm', action='store_true', help='Enable ARP spoofing')

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('--ports', '-p', type=validate_port, nargs='+', help='Specific TCP ports for tcpdump')
    port_group.add_argument('--all-ports', '-a', action='store_true', help='Monitor all TCP ports (Default)')

    args = parser.parse_args()

    # --- IP Address Loading ---
    ips = []
    if args.ips: ips = args.ips
    elif args.ip_file:
        ip_file_path = args.ip_file
        if not os.path.isabs(ip_file_path) and os.path.exists(f"/app/config/{os.path.basename(ip_file_path)}"):
             ip_file_path = f"/app/config/{os.path.basename(ip_file_path)}"
             print(f"[INFO] Using IP file: {ip_file_path}", file=sys.stderr)
        try:
            with open(ip_file_path, 'r') as f:
                ips = [validate_ip(line.strip()) for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError: print(f"[ERROR] IP file not found: {args.ip_file} (tried {ip_file_path})", file=sys.stderr); sys.exit(1)
        except Exception as e: print(f"[ERROR] Reading IP file '{ip_file_path}': {str(e)}", file=sys.stderr); sys.exit(1)
    else: parser.error("You must provide either --ips or --ip-file")
    if not ips: parser.error("No valid IP addresses found to monitor.")

    # --- Initialize and Run Monitor ---
    monitor_all_ports = args.all_ports or not args.ports
    monitor = QNXMonitor(
        ips=ips,
        refresh_interval=args.refresh,
        ports=args.ports,
        all_ports=monitor_all_ports,
        status_interval=args.status_interval,
        enable_mitm=args.enable_mitm # Pass flag
    )
    monitor.run()

if __name__ == "__main__":
    main()