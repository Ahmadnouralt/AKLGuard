import psutil
import win32gui
import win32process
import pandas as pd
import scapy.all as scapy
import socket
import pefile
import os
import time
import threading
from threading import Lock

class SysGuard:
    """
    SysGuard: A forensic system monitoring tool.
    Analyzes running processes, maps network connections to PIDs, 
    sniffs TCP traffic, and performs static PE import analysis.
    """
    
    def __init__(self, dns_reverse=True, conn_refresh_interval=1.0):
        """
        Initializes the monitoring engine and populates the initial process list.
        
        :param dns_reverse: Boolean, if True, performs reverse DNS lookups for IPs.
        :param conn_refresh_interval: Float, time in seconds between connection map refreshes.
        """
        # Snapshot current running processes
        self.all_processes = [
            (p.info.get('pid'), p.info.get('name'), p.info.get('exe'))
            for p in psutil.process_iter(['pid', 'name', 'exe'])
            if p.info.get('pid') is not None
        ]
        
        # Initialize the main DataFrame for data storage and analysis
        self.df = pd.DataFrame(self.all_processes, columns=['PID', 'Name', 'Executable'])

        # Feature columns for Forensic Analysis
        self.df['net_use']   = False  # True if process has active TCP connections
        self.df['HasWindow'] = False  # True if process owns a visible UI window
        self.df['src_ip']    = None
        self.df['src_host']  = None
        self.df['src_port']  = None
        self.df['dst_ip']    = None
        self.df['dst_host']  = None
        self.df['dst_port']  = None
        self.df['Process']   = None
        self.df['packet']    = None
        self.df['lib']       = None   # Stores imported DLL functions
        self.df['RiskScore'] = 0
        self.df['Suspicious']= False

        self.dns_reverse = dns_reverse
        self.conn_refresh_interval = conn_refresh_interval

        # Thread safety lock for DataFrame operations
        self.lock = Lock()

        # Connection mapping logic (Maps network tuples to PIDs)
        self.conn_map = {}
        self._stop_conn_thread = False
        self._conn_thread = threading.Thread(target=self._refresh_conn_map, daemon=True)
        self._conn_thread.start()

    def _refresh_conn_map(self):
        """
        Background worker that continuously refreshes the mapping 
        between active TCP connections and their respective PIDs.
        """
        while not self._stop_conn_thread:
            local_map = {}
            try:
                for c in psutil.net_connections(kind='tcp'):
                    if c.pid and c.laddr and c.raddr:
                        # Extract Local and Remote address details
                        l_ip = getattr(c.laddr, 'ip', None) or (c.laddr[0] if isinstance(c.laddr, tuple) else None)
                        l_port = getattr(c.laddr, 'port', None) or (c.laddr[1] if isinstance(c.laddr, tuple) else None)
                        r_ip = getattr(c.raddr, 'ip', None) or (c.raddr[0] if isinstance(c.raddr, tuple) else None)
                        r_port = getattr(c.raddr, 'port', None) or (c.raddr[1] if isinstance(c.raddr, tuple) else None)
                        
                        if l_ip and l_port and r_ip and r_port:
                            # Map connection in both directions for reliable sniffing correlation
                            local_map[(l_ip, l_port, r_ip, r_port)] = c.pid
                            local_map[(r_ip, r_port, l_ip, l_port)] = c.pid
            except Exception:
                pass
            self.conn_map = local_map
            time.sleep(self.conn_refresh_interval)

    def stop(self):
        """ Gracefully stops the background connection refresh thread. """
        self._stop_conn_thread = True
        if self._conn_thread.is_alive():
            self._conn_thread.join(timeout=1)

    def display_all_info(self):
        """ Prints the current state of the entire process DataFrame. """
        with self.lock:
            print(self.df)

    def display_header(self, num=10):
        """ Prints the top N processes for a quick overview. """
        with self.lock:
            print(f"{'='*10} Displaying Top {num} Processes {'='*10}")
            print(self.df.head(num))

    def information(self):
        """ Displays DataFrame info (Columns, Types, Memory usage). """
        with self.lock:
            self.df.info()

    def state_network(self):
        """
        Cross-references active TCP connections with the process list 
        to flag processes currently using the network.
        """
        try:
            active_pids = set()
            for c in psutil.net_connections(kind='tcp'):
                if c.pid:
                    active_pids.add(c.pid)
            with self.lock:
                self.df.loc[self.df['PID'].isin(active_pids), 'net_use'] = True
        except Exception:
            pass

    def has_window(self, pid):
        """
        Determines if a process has a visible GUI window.
        Hidden processes are often more interesting in forensic investigations.
        
        :param pid: Process ID to check.
        :return: Boolean, True if a window is visible.
        """
        hwnds = []
        titles = []
        def callback(hwnd, hwnds_list):
            try:
                _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                if found_pid == pid and win32gui.IsWindowVisible(hwnd):
                    hwnds_list.append(hwnd)
                    titles.append(win32gui.GetWindowText(hwnd))
            except Exception:
                pass
        try:
            win32gui.EnumWindows(callback, hwnds)
        except Exception:
            pass
        
        has_win = len(hwnds) > 0
        with self.lock:
            self.df.loc[self.df['PID'] == pid, 'HasWindow'] = has_win
            if has_win:
                self.df.loc[self.df['PID'] == pid, 'WindowTitle'] = "; ".join(titles)
        return has_win

    def _reverse_dns(self, ip, cache):
        """ Resolves an IP address to a Hostname using a local cache. """
        if not self.dns_reverse or ip is None:
            return None
        if ip in cache:
            return cache[ip]
        try:
            host = socket.gethostbyaddr(ip)[0]
            cache[ip] = host
            return host
        except Exception:
            cache[ip] = None
            return None

    def package_send(self, time_limit=5):
        """
        Initiates real-time packet sniffing on TCP traffic.
        Correlates sniffed packets with PIDs via the connection map.
        
        :param time_limit: Duration of the sniffing session in seconds.
        """
        dns_cache = {}

        def packet_callback(packet):
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
                ip_layer = packet.getlayer(scapy.IP)
                tcp_layer = packet.getlayer(scapy.TCP)

                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                sport  = tcp_layer.sport
                dport  = tcp_layer.dport

                # Lookup PID associated with this network flow
                pid = self.conn_map.get((src_ip, sport, dst_ip, dport))
                proc_name = None

                if pid:
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "Unknown"

                    src_host = self._reverse_dns(src_ip, dns_cache) or src_ip
                    dst_host = self._reverse_dns(dst_ip, dns_cache) or dst_ip

                    with self.lock:
                        idx = self.df.index[self.df['PID'] == pid]
                        if len(idx) > 0:
                            i = idx[0]
                            self.df.at[i, 'src_ip']   = src_ip
                            self.df.at[i, 'src_host'] = src_host
                            self.df.at[i, 'src_port'] = sport
                            self.df.at[i, 'dst_ip']   = dst_ip
                            self.df.at[i, 'dst_host'] = dst_host
                            self.df.at[i, 'dst_port'] = dport
                            self.df.at[i, 'Process']  = proc_name
                            self.df.at[i, 'packet']   = dport
                            self.df.at[i, 'net_use']  = True

                print(f"[+] {src_ip}:{sport} -> {dst_ip}:{dport} | Process: {proc_name or 'N/A'} | PID: {pid or 'N/A'}")

                # Optional: Display raw hex payload for deeper inspection
                if packet.haslayer(scapy.Raw):
                    data = bytes(packet[scapy.Raw].load)
                    trimmed = data[:256]
                    print(f"Payload(hex,256): {trimmed.hex()}")

        # Start sniffing with the defined filter and callback
        scapy.sniff(filter="tcp", prn=packet_callback, store=0, timeout=time_limit)

    def check_lib(self, max_pe_size_mb=50):
        """
        Performs static analysis on process executables using pefile.
        Extracts imported functions to identify suspicious API usage (e.g., Hooks, Network).
        
        :param max_pe_size_mb: Threshold to skip very large files for performance.
        """
        with self.lock:
            exe_list = self.df['Executable'].dropna().tolist()

        for exe_path in exe_list:
            if not isinstance(exe_path, str) or not os.path.isfile(exe_path):
                continue
            
            try:
                # Performance guard: skip massive binaries
                size_mb = os.path.getsize(exe_path) / (1024 * 1024)
                if size_mb > max_pe_size_mb:
                    print(f"Skip large PE ({size_mb:.1f} MB): {exe_path}")
                    continue
            except Exception:
                pass

            try:
                # Load PE file and parse Import Directory
                pe = pefile.PE(exe_path, fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
                )
                
                imports = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                name = imp.name.decode() if isinstance(imp.name, (bytes, bytearray)) else str(imp.name)
                                imports.append(name)
                                print(f"{exe_path} imports {name}")

                libs_str = "; ".join(imports) if imports else ""
                with self.lock:
                    self.df.loc[self.df['Executable'] == exe_path, 'lib'] = libs_str
            except Exception as e:
                print(f"Error parsing {exe_path}: {e}")