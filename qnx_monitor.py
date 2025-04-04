#!/usr/bin/env python3
import os
import time
import curses
import json
import subprocess
import threading
import queue
import argparse
import ipaddress
from datetime import datetime

class QNXMonitor:
    def __init__(self, namespace="default", label_selector="app=qnx", refresh_interval=5, manual_ips=None):
        self.namespace = namespace
        self.label_selector = label_selector
        self.refresh_interval = refresh_interval
        self.manual_ips = manual_ips
        self.containers = {}
        self.log_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.container_status_lock = threading.Lock()
        self.ip_mode = manual_ips is not None

    def get_containers(self):
        """Get all QNX containers and their details"""
        try:
            if self.ip_mode:
                # In IP mode, manually create container entries from IPs
                with self.container_status_lock:
                    for ip in self.manual_ips:
                        container_name = f"qnx-container-{ip.replace('.', '-')}"
                        if container_name not in self.containers:
                            self.containers[container_name] = {
                                "ip": ip,
                                "status": "Manual",
                                "containers": {"qnx": {"ready": True, "state": "manual"}},
                                "connected_to": set(),
                                "last_log_time": None,
                                "manual": True
                            }
                return True
            else:
                # Standard Kubernetes label-based discovery
                cmd = [
                    "kubectl", "get", "pods",
                    "-n", self.namespace,
                    "-l", self.label_selector,
                    "-o", "json"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                pods_data = json.loads(result.stdout)

                with self.container_status_lock:
                    # Clear old containers that no longer exist
                    current_pod_names = set()
                    for pod in pods_data.get("items", []):
                        pod_name = pod["metadata"]["name"]
                        current_pod_names.add(pod_name)

                        # Get pod IP
                        pod_ip = pod["status"].get("podIP", "Pending")

                        # Get pod status
                        pod_status = pod["status"]["phase"]

                        # Get container statuses
                        container_statuses = {}
                        for container in pod["status"].get("containerStatuses", []):
                            container_name = container["name"]
                            ready = container["ready"]
                            state = list(container["state"].keys())[0]  # running, waiting, terminated
                            container_statuses[container_name] = {
                                "ready": ready,
                                "state": state
                            }

                        # Store container data
                        if pod_name not in self.containers:
                            self.containers[pod_name] = {
                                "ip": pod_ip,
                                "status": pod_status,
                                "containers": container_statuses,
                                "connected_to": set(),
                                "last_log_time": None,
                                "manual": False
                            }
                        else:
                            self.containers[pod_name]["ip"] = pod_ip
                            self.containers[pod_name]["status"] = pod_status
                            self.containers[pod_name]["containers"] = container_statuses

                    # Remove pods that no longer exist
                    for pod_name in list(self.containers.keys()):
                        if pod_name not in current_pod_names and not self.containers[pod_name].get("manual", False):
                            del self.containers[pod_name]

                return True
        except Exception as e:
            self.log_queue.put(f"Error getting containers: {str(e)}")
            return False

    def capture_tcp_traffic(self):
        """Use tcpdump to capture TCP traffic between QNX containers"""
        try:
            # Get all pod IPs to create a filter expression
            with self.container_status_lock:
                pod_ips = [pod["ip"] for pod in self.containers.values() if pod["ip"] != "Pending"]

            if not pod_ips:
                time.sleep(5)  # Wait a bit if no IPs are available yet
                return

            # Build tcpdump filter to capture traffic between QNX containers
            filter_expr = " or ".join([f"host {ip}" for ip in pod_ips])

            if self.ip_mode:
                # In IP mode, we run tcpdump directly on the host
                # This requires the script to be run on a node with tcpdump installed
                cmd = ["tcpdump", "-l", "-n", filter_expr]
            else:
                # In Kubernetes mode, run tcpdump on a kube-proxy pod
                cmd = [
                    "kubectl", "exec",
                    "-n", "kube-system",
                    "$(kubectl get pods -n kube-system -l k8s-app=kube-proxy -o jsonpath='{.items[0].metadata.name}')",
                    "--",
                    "tcpdump", "-l", "-n", filter_expr
                ]

            # Execute command
            if self.ip_mode:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            else:
                # Execute command as a string since we're using $() in the command
                full_cmd = " ".join(cmd)
                process = subprocess.Popen(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    shell=True, text=True)

            while not self.stop_event.is_set():
                line = process.stdout.readline()
                if not line:
                    break

                timestamp = datetime.now().strftime("%H:%M:%S")
                log_entry = f"[TCP:{timestamp}] {line.strip()}"
                self.log_queue.put(log_entry)

                # Update connection information between pods
                self._update_connections(line.strip())

        except Exception as e:
            self.log_queue.put(f"Error capturing TCP traffic: {str(e)}")

    def _update_connections(self, tcp_line):
        """Update connection information between pods based on TCP traffic"""
        with self.container_status_lock:
            for src_pod_name, src_pod in self.containers.items():
                if src_pod["ip"] != "Pending" and src_pod["ip"] in tcp_line:
                    for dst_pod_name, dst_pod in self.containers.items():
                        if dst_pod_name != src_pod_name and dst_pod["ip"] != "Pending" and dst_pod["ip"] in tcp_line:
                            src_pod["connected_to"].add(dst_pod_name)

    def capture_container_logs(self, pod_name):
        """Capture logs from a specific container"""
        try:
            # Skip log capture for manually added IPs
            with self.container_status_lock:
                if pod_name in self.containers and self.containers[pod_name].get("manual", False):
                    return

            cmd = [
                "kubectl", "logs",
                "-n", self.namespace,
                "--tail=10",
                "-f", pod_name
            ]

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            while not self.stop_event.is_set():
                line = process.stdout.readline()
                if not line:
                    break

                timestamp = datetime.now().strftime("%H:%M:%S")
                log_entry = f"[{pod_name}:{timestamp}] {line.strip()}"
                self.log_queue.put(log_entry)

                with self.container_status_lock:
                    if pod_name in self.containers:
                        self.containers[pod_name]["last_log_time"] = timestamp

        except Exception as e:
            self.log_queue.put(f"Error capturing logs for {pod_name}: {str(e)}")

    def ping_ip_containers(self):
        """For IP mode: ping containers to check connectivity"""
        if not self.ip_mode:
            return

        while not self.stop_event.is_set():
            with self.container_status_lock:
                for pod_name, pod_info in self.containers.items():
                    if pod_info.get("manual", False):
                        ip = pod_info["ip"]
                        try:
                            # Check if the host is reachable
                            cmd = ["ping", "-c", "1", "-W", "1", ip]
                            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                            if result.returncode == 0:
                                self.containers[pod_name]["status"] = "Reachable"
                                self.log_queue.put(f"[{pod_name}:{datetime.now().strftime('%H:%M:%S')}] Host {ip} is reachable")
                            else:
                                self.containers[pod_name]["status"] = "Unreachable"
                                self.log_queue.put(f"[{pod_name}:{datetime.now().strftime('%H:%M:%S')}] Unable to reach host {ip}")
                        except Exception as e:
                            self.log_queue.put(f"Error pinging {ip}: {str(e)}")

            time.sleep(self.refresh_interval)

    def monitor_containers(self):
        """Main monitoring loop"""
        # Start TCP traffic monitoring
        tcp_thread = threading.Thread(target=self.capture_tcp_traffic)
        tcp_thread.daemon = True
        tcp_thread.start()

        # For IP mode, start the ping thread
        if self.ip_mode:
            ping_thread = threading.Thread(target=self.ping_ip_containers)
            ping_thread.daemon = True
            ping_thread.start()

        log_threads = {}

        while not self.stop_event.is_set():
            # Get latest container information
            if self.get_containers():
                # Skip log capture for IP mode
                if not self.ip_mode:
                    # Start log capture for new containers
                    with self.container_status_lock:
                        for pod_name in self.containers:
                            if (pod_name not in log_threads or not log_threads[pod_name].is_alive()) and \
                               not self.containers[pod_name].get("manual", False):
                                log_threads[pod_name] = threading.Thread(
                                    target=self.capture_container_logs,
                                    args=(pod_name,)
                                )
                                log_threads[pod_name].daemon = True
                                log_threads[pod_name].start()

            time.sleep(self.refresh_interval)

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
                mode_str = "IP MODE" if self.ip_mode else "KUBERNETES MODE"
                header = f" QNX Container Monitor [{mode_str}] - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
                stdscr.addstr(0, 0, header.center(width), curses.color_pair(5) | curses.A_BOLD)

                # Display container information
                stdscr.addstr(2, 0, "CONTAINERS:", curses.color_pair(4) | curses.A_BOLD)
                stdscr.addstr(3, 0, f"{'CONTAINER NAME':<25} {'IP':<15} {'STATUS':<10} {'DETAILS':<20} {'CONNECTED TO':<30}", curses.A_BOLD)

                row = 4
                with self.container_status_lock:
                    for pod_name, pod_info in sorted(self.containers.items()):
                        if row >= height - 10:  # Save space for logs
                            break

                        # Determine status color
                        color = curses.color_pair(1)  # Default: green
                        if pod_info["status"] in ["Pending", "Manual"]:
                            color = curses.color_pair(2)
                        elif pod_info["status"] in ["Failed", "Error", "Unknown", "Unreachable"]:
                            color = curses.color_pair(3)

                        # Container details
                        if pod_info.get("manual", False):
                            containers_str = "Manual IP mode"
                        else:
                            containers_str = ", ".join([
                                f"{name}:{status['state']}"
                                for name, status in pod_info["containers"].items()
                            ])

                        # Connected pods
                        connected_to = ", ".join(sorted(pod_info["connected_to"])) if pod_info["connected_to"] else "None"

                        # Display pod info
                        stdscr.addstr(row, 0, f"{pod_name:<25}", curses.A_BOLD)
                        stdscr.addstr(row, 25, f"{pod_info['ip']:<15}")
                        stdscr.addstr(row, 40, f"{pod_info['status']:<10}", color)
                        stdscr.addstr(row, 50, f"{containers_str:<20}")
                        stdscr.addstr(row, 70, f"{connected_to:<30}")
                        row += 1

                # Display logs section
                log_start_row = row + 2
                stdscr.addstr(log_start_row - 1, 0, "LOGS:", curses.color_pair(4) | curses.A_BOLD)

                # Display the most recent logs that fit in the window
                available_rows = height - log_start_row - 1
                log_slice = logs[-available_rows:] if available_rows > 0 else []

                for i, log in enumerate(log_slice):
                    if log_start_row + i < height:
                        # Truncate log if too long for screen
                        log_display = log[:width-1] if len(log) > width-1 else log

                        # Color based on log type
                        if "[TCP:" in log:
                            stdscr.addstr(log_start_row + i, 0, log_display, curses.color_pair(4))
                        elif "Error" in log or "error" in log or "ERROR" in log or "Unreachable" in log:
                            stdscr.addstr(log_start_row + i, 0, log_display, curses.color_pair(3))
                        elif "Reachable" in log:
                            stdscr.addstr(log_start_row + i, 0, log_display, curses.color_pair(1))
                        else:
                            stdscr.addstr(log_start_row + i, 0, log_display)

                # Status line
                status_line = "Press 'q' to exit | Press 'c' to clear logs"
                stdscr.addstr(height-1, 0, status_line.ljust(width-1), curses.color_pair(5))

                stdscr.refresh()

                # Check for key input with timeout
                stdscr.timeout(100)
                key = stdscr.getch()
                if key == ord('q'):
                    break
                elif key == ord('c'):
                    logs.clear()

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

def main():
    parser = argparse.ArgumentParser(description='Monitor QNX containers in Kubernetes or by IP addresses')
    parser.add_argument('--namespace', '-n', default='default', help='Kubernetes namespace')
    parser.add_argument('--selector', '-l', default='app=qnx', help='Label selector for QNX pods')
    parser.add_argument('--refresh', '-r', type=int, default=5, help='Status refresh interval in seconds')
    parser.add_argument('--ips', '-i', type=validate_ip, nargs='+', help='List of IP addresses to monitor (enables IP mode)')
    parser.add_argument('--ip-file', '-f', help='File containing IP addresses to monitor (one per line)')
    args = parser.parse_args()

    # Process IP addresses
    manual_ips = None
    if args.ips:
        manual_ips = args.ips
    elif args.ip_file:
        try:
            with open(args.ip_file, 'r') as f:
                manual_ips = [validate_ip(line.strip()) for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading IP file: {str(e)}")
            return

    monitor = QNXMonitor(
        namespace=args.namespace,
        label_selector=args.selector,
        refresh_interval=args.refresh,
        manual_ips=manual_ips
    )

    # Start the UI with curses
    curses.wrapper(monitor.display_ui)

if __name__ == "__main__":
    main()
