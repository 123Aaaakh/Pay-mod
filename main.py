#!/usr/bin/env python3
import sys
import os
import asyncio

# Menambahkan folder src ke sys.path agar package paymod bisa ditemukan
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from paymod.ui import PayloadTUI

async def main():
    app = PayloadTUI()
    await app.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
