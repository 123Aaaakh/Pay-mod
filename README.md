# Paymod - Payload Modification & Analysis Tool

**Paymod** is a Terminal User Interface (TUI) based utility designed to interactively analyze, modify, and generate binary payloads. It combines the power of **Radare2** for static analysis and **MSFVenom** for payload generation into a single, easy-to-use interface.

---

##  Key Features

- **Hexdump Viewer**: Inspect binary contents in hex format with intuitive navigation.
- **String Manipulation**: Search for ASCII strings within the binary and replace them directly (search & replace).
- **Byte Patching**: Modify specific bytes at any given offset (e.g., replacing assembly instructions).
- **Radare2 Integration**: 
    - Automated analysis (`aaaa`).
    - Function disassembly (view assembly code).
    - Cross-Reference (XREFs) lookups to trace data execution flows.
    - View file segmentation (sections).
- **MSFVenom Integration**: 
    - Generate payloads (EXE, ELF, etc.) directly from the application menu.
    - List available payloads from the Metasploit Framework.

---

##  Installation

### Prerequisites
Ensure your system has the following installed:
1.  **Python 3.10+**
2.  **Radare2** (`sudo apt install radare2`)
3.  **Metasploit Framework** (for `msfvenom`)

### Setup Steps
1.  Clone this repository:
    ```bash
    git clone https://github.com/username/paymod.git
    cd paymod
    ```
2.  Create and activate a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## 📖 Usage Guide

Run the application with the following command:
```bash
python main.py
```

### 1. Generating a New Payload
If you don't have a file to test yet, use the MSF menu:
- Select the **MSF: Generate Payload** menu.
- Enter the payload type (e.g., `linux/x64/shell_reverse_tcp`).
- Enter LHOST (your IP) and LPORT (your listener port).
- Choose the format (e.g., `elf` for Linux or `exe` for Windows).
- Once finished, select **Yes** when prompted to load the file for analysis.

### 2. Searching & Replacing Text (IP/Path)
- Select the **Strings & Replace** menu.
- You will see a list of discovered strings (e.g., `/bin/sh` or `127.0.0.1`).
- Select the index number.
- Enter the replacement text. **Important**: The replacement must be the same length to avoid corrupting the file structure.

### 3. Analyzing Code (Reverse Engineering)
- Select the **R2: Analyze (aaaa)** menu.
- Once analysis is complete, use **R2: Disassemble Function**.
- Type `main` or `entry0` to view the machine instructions.
- Use **R2: Find Strings** for a deeper string search powered by Radare2.

### 4. Manual Byte Patching
If you want to change specific instructions (e.g., changing a `syscall` to a `nop`):
- Locate the offset via Hexdump or Disassembly.
- Select the **Patch Bytes** menu.
- Enter the offset (e.g., `0x000000af`).
- Enter the new bytes in hex format (e.g., `90 90` for NOP).

---

##  Project Structure
```text
paymod/
├── main.py              # Application entry point
├── src/
│   └── paymod/
│       ├── core.py      # Core binary manipulation logic
│       ├── analyzer.py  # Radare2 wrapper
│       ├── handler.py   # MSFVenom wrapper
│       ├── ui.py        # TUI interface
│       └── utils.py     # Utility functions
└── requirements.txt     # Python dependency list
```

---

##  Disclaimer
This tool is created for **educational purposes and legal security testing** (Penetration Testing) only. Any illegal use of this tool is the sole responsibility of the user.
