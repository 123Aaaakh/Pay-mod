# src/paymod/analyzer.py
import r2pipe
from typing import List, Optional

class Radare2Analyzer:
    """
    Static analyzer wrapper for Radare2 (r2pipe).
    Provides high-level methods for disassembly, xrefs, and section analysis.
    """
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.r2 = None
        self._open()

    def _open(self):
        """Initializes the r2pipe connection."""
        try:
            # Open in write mode to allow patching via r2 if needed
            self.r2 = r2pipe.open(self.filepath, flags=['-w'])
        except Exception:
            self.r2 = None

    def analyze(self) -> str:
        """Runs automated analysis (aaaa)."""
        if not self.r2:
            return "Radare2 is not available."
        try:
            return self.r2.cmd('aaaa')
        except Exception as e:
            return f"Analysis error: {e}"

    def get_functions(self) -> List[str]:
        """Returns a list of identified function names."""
        if not self.r2:
            return []
        try:
            functions = self.r2.cmdj('aflj')
            return [f['name'] for f in functions] if functions else []
        except Exception:
            return []

    def disassemble_function(self, func_name: str = 'main', limit: int = 5000) -> str:
        """Returns disassembly text for a specific function."""
        if not self.r2:
            return "Radare2 is not available."
        try:
            asm = self.r2.cmd(f'pdf @ {func_name}')
            if not asm:
                return f"Function '{func_name}' not found."
            return asm[:limit] + ('...' if len(asm) > limit else '')
        except Exception as e:
            return f"Disassembly error: {e}"

    def get_xrefs_to(self, address: str) -> str:
        """Finds cross-references to a specific address."""
        if not self.r2:
            return "Radare2 is not available."
        try:
            xrefs = self.r2.cmd(f'axt @ {address}')
            return xrefs[:5000] if xrefs else "No references found."
        except Exception as e:
            return f"XRef error: {e}"

    def get_sections(self) -> str:
        """Lists binary sections."""
        if not self.r2:
            return "Radare2 is not available."
        try:
            return self.r2.cmd('iS') or "No sections found."
        except Exception:
            return "Error retrieving sections."

    def find_strings(self, min_len: int = 4) -> str:
        """Finds strings using Radare2's 'izzq' command."""
        if not self.r2:
            return "Radare2 is not available."
        try:
            cmd = f'izzq | grep -E ".{{{min_len},}}"'
            strings = self.r2.cmd(cmd)
            return strings[:8000] if strings else "No strings found."
        except Exception:
            return "Error searching for strings."

    def close(self):
        """Closes the r2pipe session."""
        if self.r2:
            self.r2.quit()
            self.r2 = None
