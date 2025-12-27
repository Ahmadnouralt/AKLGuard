# 🛡️ AKLGuard - Forensic System Monitor

**AKLGuard** is a digital forensic and security monitoring tool designed to analyze running processes, detect suspicious behaviors, and identify potential threats like keyloggers or unauthorized network activity on Windows systems.

---

## ✨ Features

* **🔍 Process Analysis:** Real-time snapshot of all running processes including PIDs and executable paths.
* **🌐 Network-to-Process Mapping:** Correlates active TCP connections with specific PIDs to identify which applications are communicating online.
* **👻 Hidden Process Detection:** Automatically flags processes that run without a visible GUI window (often a sign of persistence).
* **🛠️ Static PE Analysis:** Scans executables for suspicious DLL imports (e.g., Hooking APIs, Keylogging functions) using `pefile`.
* **📡 Traffic Sniffing:** Real-time TCP packet sniffing and hex payload inspection powered by `Scapy`.
* **⚖️ Risk Scoring:** An intelligent algorithm that calculates a "Risk Score" based on behavioral heuristics.
* **📊 Interactive Dashboard:** A modern UI built with `Streamlit` for easy filtering and forensic reporting.

---

## 🚀 Getting Started

### Prerequisites
- **Operating System:** Windows (Required for `pywin32` and PE analysis).
- **Python:** version 3.8 or higher.
- **Privileges:** **Administrator Privileges** are mandatory for network sniffing and process access.

### 🔧 System Requirements (Important)
To enable network sniffing features, you must install a packet capture driver:
* **Npcap:** [Download here](https://npcap.com/#download). 
* *Note: During installation, ensure 'Install Npcap with WinPcap API-compatible mode' is checked.*

### Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Ahmadnouralt/AKLGuard.git](https://github.com/Ahmadnouralt/AKLGuard.git)
   cd AKLGuard
2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt

3. **Running the Application:**
   ```bash
   streamlit run app.py



### ⚖️ Disclaimer
   For Educational and Research Purposes Only. This tool is designed for security professionals and students to understand system forensics. The author is not responsible for any misuse or damage caused by this software.
### 👤 Author
Ahmad Nouralt - GitHub Profile
