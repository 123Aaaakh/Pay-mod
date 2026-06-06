# src/paymod/core.py
from typing import List, Tuple, Optional
from .utils import get_file_info, hexdump, find_ascii_strings

class PayloadManipulator:
    """
    Core class for managing payload binary data.
    Provides methods for loading, saving, analyzing, and patching bytes.
    """
    def __init__(self):
        self.data = bytearray()
        self.filepath: Optional[str] = None
        self.modified = False

    def load(self, filepath: str) -> bool:
        """Loads binary data from a file into memory."""
        try:
            with open(filepath, 'rb') as f:
                self.data = bytearray(f.read())
            self.filepath = filepath
            self.modified = False
            return True
        except Exception as e:
            raise IOError(f"Failed to load {filepath}: {e}")

    def save(self, output_path: Optional[str] = None) -> bool:
        """Saves current memory data back to a file."""
        target = output_path or self.filepath
        if not target:
            raise ValueError("No output path specified and no file is currently loaded.")
        try:
            with open(target, 'wb') as f:
                f.write(self.data)
            self.modified = False
            return True
        except Exception as e:
            raise IOError(f"Failed to save to {target}: {e}")

    def get_info(self) -> str:
        """Returns metadata and basic info about the payload."""
        return get_file_info(self.data, self.filepath)

    def hexdump(self, offset: int = 0, length: int = 256) -> str:
        """Generates a formatted hexdump of the data."""
        return hexdump(self.data, offset, length)

    def find_strings(self, min_len: int = 4) -> List[Tuple[int, str]]:
        """Extracts ASCII strings from the payload."""
        return find_ascii_strings(self.data, min_len)

    def replace_string(self, old: bytes, new: bytes) -> int:
        """Replaces all occurrences of 'old' bytes with 'new' bytes (must be same length)."""
        if len(old) != len(new):
            raise ValueError("Replacement bytes must be the exact same length as original.")
        
        count = 0
        idx = 0
        data_len = len(self.data)
        old_len = len(old)
        
        while idx <= data_len - old_len:
            if self.data[idx:idx+old_len] == old:
                self.data[idx:idx+old_len] = new
                count += 1
                idx += old_len
            else:
                idx += 1
                
        if count > 0:
            self.modified = True
        return count

    def patch_bytes(self, offset: int, values: bytes) -> bool:
        """Patches specific bytes at a given offset."""
        if 0 <= offset and offset + len(values) <= len(self.data):
            self.data[offset:offset+len(values)] = values
            self.modified = True
            return True
        return False
