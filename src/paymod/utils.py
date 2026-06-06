# src/paymod/utils.py
import hashlib
import puremagic

def get_file_info(data: bytes, filepath: str = None) -> str:
    """Mendapatkan informasi dasar file (size, hash, magic type)."""
    size = len(data)
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    
    info = f"File: {filepath or '(belum load)'}\n"
    info += f"Size: {size} bytes\n"
    info += f"MD5: {md5}\n"
    info += f"SHA256: {sha256}\n"

    if data:
        try:
            # puremagic returns a list of named tuples
            exts = puremagic.from_string(data[:2048])
            if exts:
                # Get the best match
                best = exts[0]
                info += f"Type: {best.name} ({best.mime})\n"
            else:
                info += "Type: Unknown / Data not recognized\n"
        except Exception:
            info += "Type: Detection error\n"
    
    return info

def hexdump(data: bytes, offset: int = 0, length: int = 256) -> str:
    """Generate hexdump string dari data."""
    if not data:
        return "<Empty>"
    end = min(offset + length, len(data))
    chunk = data[offset:end]
    lines = []
    for i in range(0, len(chunk), 16):
        line_addr = offset + i
        hex_part = ' '.join(f"{b:02x}" for b in chunk[i:i+8]) + ' ' + \
                   ' '.join(f"{b:02x}" for b in chunk[i+8:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk[i:i+16])
        lines.append(f"{line_addr:08x}  {hex_part:<48}  {ascii_part}")
    return '\n'.join(lines)

def find_ascii_strings(data: bytes, min_len: int = 4) -> list:
    """Ekstrak string ASCII dari data. Return list of (offset, string)."""
    strings = []
    current = []
    start_offset = 0
    for i, byte in enumerate(data):
        if 32 <= byte < 127:
            if not current:
                start_offset = i
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append((start_offset, ''.join(current)))
            current = []
    if len(current) >= min_len:
        strings.append((start_offset, ''.join(current)))
    return strings
