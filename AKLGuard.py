import SysGuard


class AKLGuard:
    """
    AKLGuard: A class designed to monitor running processes and evaluate
    their behavior to detect suspicious activities such as keylogging,
    clipboard access, or unusual network usage.
    """

    def __init__(self, types="fast"):
        """
        Initialize the AKLGuard instance.

        Args:
            types (str): Defines the scanning mode. Options:
                - "fast": Quick checks (network + window presence).
                - "slow": Extended checks (network, window, package sending, library scanning).

        Attributes:
            sysguard (SysGuard): Instance of SysGuard for system monitoring.
            snapshot_df (DataFrame): A snapshot of the current process data.
            types (str): Scan mode ("fast" or "slow").
            keyhook_lib (list): List of libraries and Windows API functions
                                commonly used for keylogging or suspicious input handling.
        """
        self.sysguard = SysGuard.SysGuard()
        self.snapshot_df = self.sysguard.df.copy()  
        self.types = types
        self.keyhook_lib = [
            # Python libraries often used for keylogging
            "pyHook", "pynput", "keyboard",

            # Windows API functions for keyboard hooks
            "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
            "SetWindowsHookEx", "CallNextHookEx", "UnhookWindowsHookEx",
            "GetMessage", "PeekMessage", "TranslateMessage", "DispatchMessage",

            # Clipboard-related functions
            "GetClipboardData", "SetClipboardData", "OpenClipboard", "CloseClipboard",

            # Window-related functions
            "FindWindow", "GetForegroundWindow", "GetWindowText",
            "GetClassName", "GetWindowThreadProcessId",

            # File I/O functions
            "CreateFile", "WriteFile", "ReadFile", "CloseHandle",

            # Library loading and input functions
            "LoadLibrary", "GetProcAddress", "RegisterHotKey",
            "SendInput", "MapVirtualKey", "VkKeyScan"
        ]


    def update_df(self):
        """
        Update the process DataFrame with the latest system state.

        Behavior:
            - In "fast" mode:
                * Check network state.
                * Verify if each process has a window.
            - In "slow" mode:
                * Perform the same checks as "fast".
                * Send packages with a time limit.
                * Scan libraries with a maximum PE size limit.

        After execution:
            - snapshot_df is refreshed with the latest process data.
        """
        if self.types == "fast":
            self.sysguard.state_network()
            for pid in self.snapshot_df['PID']:
                self.sysguard.has_window(pid)

        elif self.types == "slow":
            self.sysguard.state_network()
            for pid in self.snapshot_df['PID']:
                self.sysguard.has_window(pid)
            
            self.sysguard.package_send(time_limit=10)
            self.sysguard.check_lib(max_pe_size_mb=40)
        
        self.snapshot_df = self.sysguard.df.copy()


    def risk_score(self):
        """
        Calculate a risk score for each process based on suspicious behavior.

        Rules:
            - Processes without a window → increase risk.
            - Processes using network → increase risk.
            - Processes loading suspicious libraries (keylogging APIs) → increase risk.
            - Negative scores are reset to zero.

        Adds two new columns to snapshot_df:
            - 'RiskScore': Numeric score representing risk level.
            - 'Suspicious': Boolean flag (True if RiskScore >= 3).
        """
        def score_row(row):
            s = 0
            # Processes without a window are suspicious
            s += 1 if not row.get('HasWindow', True) else -10
            # Processes using network are suspicious
            s += 1 if row.get('net_use', True) else -10

            # Check for suspicious libraries
            libs = row.get('lib') or ""
            for x in self.keyhook_lib:
                if x in libs:
                    s += 1

            # Prevent negative scores
            if s < 0:
                s = 0
            return s

        # Apply scoring function to each row
        self.snapshot_df['RiskScore'] = self.snapshot_df.apply(score_row, axis=1)
        # Flag suspicious processes
        self.snapshot_df['Suspicious'] = self.snapshot_df['RiskScore'] >= 15