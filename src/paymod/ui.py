# src/paymod/ui.py
from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import message_dialog, input_dialog, yes_no_dialog
from prompt_toolkit.shortcuts import ProgressBar
from prompt_toolkit.styles import Style
from .core import PayloadManipulator
from .analyzer import Radare2Analyzer
from . import handler as msf
import threading
import asyncio
import time

# ========== DARK MODE STYLE ==========
dark_style = Style.from_dict({
    'dialog':             'bg:#1e1e2e #ffffff',
    'dialog frame.label': 'bg:#1e1e2e #aaaaaa bold',
    'dialog.body':        'bg:#1e1e2e #ffffff',
    'dialog shadow':      'bg:#000000',
    'input-field':        'bg:#2d2d3a #ffffff',
    'input-field.prompt': 'bold #89b4fa',
    'button':             'bg:#45475a #ffffff',
    'button.focused':     'bg:#89b4fa #1e1e2e bold',
    'prompt':             'bold #cba6f7',
    'status':             '#a6e3a1',
    'label':              '#cdd6f4',
    'title':              'bold #f38ba8',
})
# =====================================

class PayloadTUI:
    def __init__(self):
        self.payload = PayloadManipulator()
        self.r2 = None
        self.session = PromptSession(style=dark_style)

    async def run(self):
        while True:
            choice = await self._main_menu()
            if choice == 'load':
                await self._load_file()
            elif choice == 'info':
                await self._show_info()
            elif choice == 'hexdump':
                await self._show_hexdump()
            elif choice == 'strings':
                await self._manage_strings()
            elif choice == 'patch':
                await self._patch_bytes()
            elif choice == 'r2_analyze':
                await self._r2_analyze()
            elif choice == 'r2_disasm':
                await self._r2_disassemble()
            elif choice == 'r2_xrefs':
                await self._r2_xrefs()
            elif choice == 'r2_sections':
                await self._r2_sections()
            elif choice == 'r2_strings':
                await self._r2_strings()
            elif choice == 'msf_generate':
                await self._msf_generate()
            elif choice == 'msf_list':
                await self._msf_list()
            elif choice == 'save':
                await self._save_file()
            elif choice == 'exit':
                if self.payload.modified:
                    confirm = await yes_no_dialog(
                        title="Konfirmasi",
                        text="Ada perubahan belum disimpan. Keluar?",
                        style=dark_style
                    ).run_async()
                    if not confirm:
                        continue
                break

    async def _main_menu(self) -> str:
        options = [
            ("Load Payload", "load"),
            ("Info File", "info"),
            ("Hexdump", "hexdump"),
            ("Strings & Replace", "strings"),
            ("Patch Bytes", "patch"),
            ("=== Radare2 ===", None),
            ("R2: Analyze (aaaa)", "r2_analyze"),
            ("R2: Disassemble Function", "r2_disasm"),
            ("R2: Show XREFs", "r2_xrefs"),
            ("R2: Show Sections", "r2_sections"),
            ("R2: Find Strings", "r2_strings"),
            ("=== MSFVenom ===", None),
            ("MSF: Generate Payload", "msf_generate"),
            ("MSF: List Payloads", "msf_list"),
            ("Save Payload", "save"),
            ("Exit", "exit"),
        ]
        text_lines = []
        for i, (label, _) in enumerate(options):
            if label:
                text_lines.append(f"{i+1}. {label}")
            else:
                text_lines.append(f"   {label}")
        text = "\n".join(text_lines)
        status_icon = "[MODIFIED]" if self.payload.modified else "[UNCHANGED]"
        loaded = self.payload.filepath or 'None'
        text += f"\n\nStatus: {status_icon} | Loaded: {loaded}\nPilih (1-{len(options)}): "
        try:
            ans = await self.session.prompt_async(text)
            idx = int(ans.strip()) - 1
            if 0 <= idx < len(options) and options[idx][1]:
                return options[idx][1]
        except (ValueError, KeyboardInterrupt):
            pass
        return 'exit'

    async def _load_file(self):
        path = await input_dialog(
            title="Load File",
            text="Masukkan path file payload:",
            style=dark_style
        ).run_async()
        if path and self.payload.load(path):
            self.r2 = Radare2Analyzer(path) if path else None
            await message_dialog(title="Sukses", text=f"Loaded: {path}", style=dark_style).run_async()

    async def _show_info(self):
        if not self.payload.data:
            await message_dialog(title="Info", text="Belum ada payload.", style=dark_style).run_async()
            return
        info = self.payload.get_info()
        await message_dialog(title="Informasi Payload", text=info, style=dark_style).run_async()

    async def _show_hexdump(self):
        if not self.payload.data:
            await message_dialog(title="Error", text="Load payload dulu.", style=dark_style).run_async()
            return
        offset = 0
        page = 256
        total = len(self.payload.data)
        while True:
            dump = self.payload.hexdump(offset, page)
            nav = f"Offset 0x{offset:08x} - 0x{min(offset+page, total):08x} / 0x{total:08x} | [n]ext [p]rev [g]oto [q]uit"
            ans = await self.session.prompt_async(dump + "\n\n" + nav + "\n> ")
            if ans.lower() == 'n' and offset + page < total:
                offset += page
            elif ans.lower() == 'p' and offset >= page:
                offset -= page
            elif ans.lower() == 'g':
                try:
                    new_off = await self.session.prompt_async("Offset (hex/dec): ")
                    new_off = int(new_off, 0)
                    if 0 <= new_off < total:
                        offset = new_off - (new_off % 16)
                except: pass
            elif ans.lower() == 'q':
                break

    async def _manage_strings(self):
        if not self.payload.data:
            await message_dialog(title="Error", text="Load payload dulu.", style=dark_style).run_async()
            return
        strings = self.payload.find_strings(4)
        if not strings:
            await message_dialog(title="Strings", text="Tidak ada string ASCII >=4 karakter.", style=dark_style).run_async()
            return
        str_list = "\n".join([f"{i}: 0x{off:x}  '{s}'" for i, (off, s) in enumerate(strings)])
        choice = await self.session.prompt_async(
            f"Strings ditemukan ({len(strings)}):\n{str_list}\n\nNomor string untuk replace, atau 'q': "
        )
        if choice.lower() == 'q':
            return
        try:
            idx = int(choice)
            if 0 <= idx < len(strings):
                off, old_str = strings[idx]
                new_str = await input_dialog(
                    title="Replace",
                    text=f"Ganti '{old_str}' dengan:",
                    style=dark_style
                ).run_async()
                if new_str:
                    old_bytes, new_bytes = old_str.encode(), new_str.encode()
                    if len(old_bytes) != len(new_bytes):
                        await message_dialog(title="Error", text="Panjang string harus sama.", style=dark_style).run_async()
                    else:
                        count = self.payload.replace_string(old_bytes, new_bytes)
                        await message_dialog(title="Result", text=f"Diganti {count} occurrence(s).", style=dark_style).run_async()
        except: pass

    async def _patch_bytes(self):
        if not self.payload.data:
            await message_dialog(title="Error", text="Load payload dulu.", style=dark_style).run_async()
            return
        off_str = await self.session.prompt_async("Offset (hex/dec): ")
        try:
            offset = int(off_str, 0)
        except:
            await message_dialog(title="Error", text="Offset tidak valid.", style=dark_style).run_async()
            return
        hex_str = await self.session.prompt_async("Bytes hex (contoh: 90 90 EB): ")
        hex_str = hex_str.replace(' ', '')
        try:
            bytes_val = bytes.fromhex(hex_str)
        except:
            await message_dialog(title="Error", text="Hex tidak valid.", style=dark_style).run_async()
            return
        if self.payload.patch_bytes(offset, bytes_val):
            await message_dialog(title="Patch", text=f"Patch {len(bytes_val)} byte(s) di 0x{offset:x}.", style=dark_style).run_async()
        else:
            await message_dialog(title="Error", text="Patch gagal (offset melebihi ukuran).", style=dark_style).run_async()

    async def _r2_analyze(self):
        if not self.r2:
            await message_dialog(title="Error", text="Load payload dulu atau pastikan Radare2 tersedia.", style=dark_style).run_async()
            return
        await message_dialog(title="Analisis", text="Memulai analisis...", style=dark_style).run_async()
        out = self.r2.analyze()
        await message_dialog(title="Hasil Analisis", text=out[:5000], style=dark_style).run_async()
        funcs = self.r2.get_functions()
        if funcs:
            await message_dialog(title="Fungsi", text=f"Ditemukan {len(funcs)} fungsi: {', '.join(funcs[:20])}", style=dark_style).run_async()

    async def _r2_disassemble(self):
        if not self.r2:
            await message_dialog(title="Error", text="Load payload dulu.", style=dark_style).run_async()
            return
        func = await input_dialog(
            title="Disassembly",
            text="Nama fungsi (default main):",
            default="main",
            style=dark_style
        ).run_async()
        out = self.r2.disassemble_function(func or "main")
        await message_dialog(title=f"Disassembly {func}", text=out[:8000], style=dark_style).run_async()

    async def _r2_xrefs(self):
        if not self.r2:
            await message_dialog(title="Error", text="Load payload dulu.", style=dark_style).run_async()
            return
        addr = await input_dialog(title="XREFs", text="Alamat (hex, contoh 0x401000):", style=dark_style).run_async()
        if addr:
            out = self.r2.get_xrefs_to(addr)
            await message_dialog(title="XREFs", text=out[:5000], style=dark_style).run_async()

    async def _r2_sections(self):
        if not self.r2:
            await message_dialog(title="Error", text="Load payload dulu.", style=dark_style).run_async()
            return
        out = self.r2.get_sections()
        await message_dialog(title="Sections", text=out, style=dark_style).run_async()

    async def _r2_strings(self):
        if not self.r2:
            await message_dialog(title="Error", text="Load payload dulu.", style=dark_style).run_async()
            return
        out = self.r2.find_strings()
        await message_dialog(title="Strings (R2)", text=out[:8000], style=dark_style).run_async()

    async def _msf_generate(self):
        # Parameter input
        payload = await input_dialog(title="MSFVenom", text="Payload type:", style=dark_style).run_async()
        if not payload: return
        lhost = await input_dialog(title="MSFVenom", text="LHOST:", style=dark_style).run_async()
        if not lhost: return
        lport = await input_dialog(title="MSFVenom", text="LPORT:", style=dark_style).run_async()
        if not lport: return
        fmt = await input_dialog(title="MSFVenom", text="Format (exe, elf, raw, python, c):", default="exe", style=dark_style).run_async()
        fmt = fmt or "exe"
        outfile = await input_dialog(title="MSFVenom", text="Output file:", default="payload", style=dark_style).run_async()
        outfile = outfile or "payload"
        if not outfile.endswith(f".{fmt}"):
            outfile += f".{fmt}"
        use_enc = await yes_no_dialog(title="Encoder", text="Gunakan encoder?", style=dark_style).run_async()
        encoder = "x86/shikata_ga_nai"
        iterations = 5
        if use_enc:
            encoder = await input_dialog(title="Encoder", text="Encoder name:", default="x86/shikata_ga_nai", style=dark_style).run_async()
            encoder = encoder or "x86/shikata_ga_nai"
            it_str = await input_dialog(title="Iterations", text="Iterations:", default="5", style=dark_style).run_async()
            try: iterations = int(it_str or "5")
            except: iterations = 5
        else:
            encoder = 'none'

        result_holder = [None, None]  # [success, message]

        def run_msfvenom():
            # Generate payload sekali saja
            success, msg = msf.generate_payload(payload, lhost, lport, fmt, outfile, encoder, iterations)
            result_holder[0] = success
            result_holder[1] = msg

        # Progress bar bawaan prompt_toolkit
        with ProgressBar(title=f"Generating {outfile}", style=dark_style) as pb:
            # Buat task indeterminate (100 langkah simulasi)
            task = pb(range(100), label=f"Payload: {payload}")
            iterator = iter(task)
            
            # Jalankan thread untuk msfvenom
            thread = threading.Thread(target=run_msfvenom)
            thread.daemon = True
            thread.start()
            
            # Update progress bar selama thread masih hidup
            while thread.is_alive():
                try:
                    next(iterator)
                except StopIteration:
                    # Jika kehabisan langkah, ulangi dari awal
                    iterator = iter(task)
                    next(iterator)
                await asyncio.sleep(0.1)
            
            # Pastikan progress bar mencapai 100%
            for _ in range(100):
                try:
                    next(iterator)
                except StopIteration:
                    break
            
            thread.join()

        success, msg = result_holder
        await message_dialog(title="Hasil", text=msg[:5000], style=dark_style).run_async()
        if success:
            load_it = await yes_no_dialog(title="Load", text=f"Load '{outfile}' untuk analisis?", style=dark_style).run_async()
            if load_it:
                self.payload.load(outfile)
                self.r2 = Radare2Analyzer(outfile)

    async def _msf_list(self):
        filt = await input_dialog(
            title="MSFVenom List",
            text="Filter payloads (misal: windows/linux) atau kosongkan:",
            style=dark_style
        ).run_async()
        out = msf.list_payloads(filt or "")
        await message_dialog(
            title="Daftar Payload MSFVenom",
            text=out[:10000],
            style=dark_style
        ).run_async()

    async def _save_file(self):
        if not self.payload.data:
            await message_dialog(title="Error", text="Tidak ada payload.", style=dark_style).run_async()
            return
        path = await input_dialog(title="Save As", text="Path (kosong untuk overwrite):", style=dark_style).run_async()
        if not path:
            path = self.payload.filepath
        if path and self.payload.save(path):
            await message_dialog(title="Sukses", text=f"Disimpan ke {path}", style=dark_style).run_async()
