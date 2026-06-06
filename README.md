# Paymod - Payload Modification & Analysis Tool

**Paymod** adalah alat bantu berbasis Terminal User Interface (TUI) yang dirancang untuk menganalisis, memodifikasi, dan membuat payload binary secara interaktif. Alat ini menggabungkan kekuatan **Radare2** untuk analisis statis dan **MSFVenom** untuk pembuatan payload dalam satu antarmuka yang mudah digunakan.

---

## 🚀 Fitur Utama

- **Hexdump Viewer**: Melihat isi binary dalam format hex dengan navigasi yang mudah.
- **String Manipulation**: Mencari string ASCII dalam binary dan menggantinya secara langsung (search & replace).
- **Byte Patching**: Mengubah byte spesifik pada offset tertentu (misal: mengganti instruksi assembly).
- **Integrasi Radare2**: 
    - Analisis otomatis (`aaaa`).
    - Disassembly fungsi (melihat kode assembly).
    - Mencari Cross-References (XREFs) untuk melihat alur eksekusi data.
    - Melihat segmentasi file (sections).
- **Integrasi MSFVenom**: 
    - Membuat payload (EXE, ELF, dll) langsung dari menu aplikasi.
    - List daftar payload yang tersedia di Metasploit.
- **Dark Mode UI**: Antarmuka terminal modern menggunakan `prompt_toolkit`.

---

## 🛠️ Instalasi

### Prasyarat
Pastikan sistem Anda sudah terinstall:
1.  **Python 3.10+**
2.  **Radare2** (`sudo apt install radare2`)
3.  **Metasploit Framework** (untuk `msfvenom`)

### Langkah-langkah
1.  Clone repository ini:
    ```bash
    git clone https://github.com/username/paymod.git
    cd paymod
    ```
2.  Buat dan aktifkan virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  Install dependensi:
    ```bash
    pip install -r requirements.txt
    ```

---

## 📖 Panduan Penggunaan

Jalankan aplikasi dengan perintah:
```bash
python main.py
```

### 1. Membuat Payload Baru
Jika Anda belum punya file untuk diuji, gunakan menu MSF:
- Pilih menu **MSF: Generate Payload**.
- Masukkan tipe (misal: `linux/x64/shell_reverse_tcp`).
- Masukkan LHOST (IP Anda) dan LPORT (Port listener).
- Pilih format (misal: `elf` untuk Linux atau `exe` untuk Windows).
- Setelah selesai, pilih **Yes** saat ditanya untuk memuat file tersebut.

### 2. Mencari & Mengganti Teks (IP/Path)
- Pilih menu **Strings & Replace**.
- Anda akan melihat daftar string yang ditemukan (misal: `/bin/sh` atau `127.0.0.1`).
- Pilih nomor index-nya.
- Masukkan teks pengganti. **Penting**: Panjang teks harus sama agar tidak merusak struktur file.

### 3. Menganalisis Kode (Reverse Engineering)
- Pilih menu **R2: Analyze (aaaa)**.
- Setelah analisis selesai, gunakan **R2: Disassemble Function**.
- Ketik `main` atau `entry0` untuk melihat instruksi bahasa mesin.
- Gunakan **R2: Find Strings** jika ingin melihat hasil pencarian string yang lebih mendalam dari Radare2.

### 4. Melakukan Patching Byte
Jika Anda ingin mengubah instruksi (misal mengganti `syscall` menjadi `nop`):
- Cari offset-nya melalui Hexdump atau Disassembly.
- Pilih menu **Patch Bytes**.
- Masukkan offset (misal: `0x000000af`).
- Masukkan byte baru dalam format hex (misal: `90 90` untuk NOP).

---

## 📂 Struktur Proyek
```text
paymod/
├── main.py              # Entry point aplikasi
├── src/
│   └── paymod/
│       ├── core.py      # Logika utama manipulasi binary
│       ├── analyzer.py  # Wrapper untuk Radare2
│       ├── handler.py   # Wrapper untuk MSFVenom
│       ├── ui.py        # Antarmuka TUI (Prompt Toolkit)
│       └── utils.py     # Fungsi bantuan (hexdump, info)
└── requirements.txt     # Daftar dependensi Python
```

---

## ⚠️ Disclaimer
Alat ini dibuat untuk tujuan **edukasi dan pengujian keamanan yang legal** (Penetration Testing). Penggunaan alat ini untuk aktivitas ilegal adalah tanggung jawab pengguna sepenuhnya.
