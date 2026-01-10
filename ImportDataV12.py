import asyncio
import struct
from datetime import datetime, timedelta
from bleak import BleakClient
import asyncio
import struct
import pandas as pd
from datetime import datetime, timedelta
from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- KONFIGURACJA ---
MAC_ADDRESS = "C3:0F:6C:1F:EF:57"
AUTH_KEY_HEX = "1b813e705e884c5046aeba4ada347f6d"
AUTH_KEY = bytes.fromhex(AUTH_KEY_HEX)

# UUIDs
UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"
UUID_DATA = "00000005-0000-3512-2118-0009af100700"

class MiBand5Trial:
    # ... (init i auth_handler bez zmian) ...

    async def notification_handler(self, sender, data):
        data = bytes(data)
        if sender.uuid == UUID_AUTH:
            # ... (logika autoryzacji OK) ...
            pass
        elif sender.uuid == UUID_FETCH:
            print(f"[ODPOWIEDŹ] {data.hex()}")
            if data.startswith(b'\x10\x01\x01'):
                print("!!! SUKCES: Zegarek zaakceptował ten format !!!")
                self.fetch_ok.set()
        elif sender.uuid == UUID_DATA:
            print(f"Dane płyną: {len(data)} bajtów")

    async def run(self):
        async with BleakClient(self.mac) as client:
            self.client = client
            await client.start_notify(UUID_AUTH, self.notification_handler)
            await client.start_notify(UUID_FETCH, self.notification_handler)
            await client.start_notify(UUID_DATA, self.notification_handler)
            
            # Autoryzacja
            await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)
            await asyncio.wait_for(self.auth_ok.wait(), timeout=10)

            # TESTY FORMATÓW:
            start = datetime.now() - timedelta(days=1)
            
            # Format A: 11 bajtów (Standard MB5)
            # 01 01 + Rok(2b) + Mies + Dzien + Godz + Min + Sek + TZ + 0x08
            ts_a = b'\x01\x01' + struct.pack("<HBBBBBB", start.year, start.month, start.day, start.hour, start.minute, 0, 0) + b'\x08'
            
            # Format B: 9 bajtów (Starszy protokół)
            ts_b = b'\x01\x01' + struct.pack("<HBBBBB", start.year, start.month, start.day, start.hour, start.minute)
            
            # Format C: Magiczne "0x02" (Niektóre firmware)
            ts_c = b'\x02' + struct.pack("<HBBBBBB", start.year, start.month, start.day, start.hour, start.minute, 0, 0)

            for trial, cmd in [("A (11b)", ts_a), ("B (9b)", ts_b), ("C (02+ts)", ts_c)]:
                print(f"Próba formatu {trial}: {cmd.hex()}")
                await client.write_gatt_char(UUID_FETCH, cmd, response=False)
                await asyncio.sleep(2) # Czekamy na reakcję
                if self.fetch_ok.is_set(): break
            
            if not self.fetch_ok.is_set():
                print("Zegarek nadal mówi 100102. Ostatnia szansa: synchronizacja czasu przed pobieraniem...")
                # Czasami MB5 wymaga ustawienia czasu przed pobraniem historii
                now = datetime.now()
                time_sync = struct.pack("<HBBBBBB", now.year, now.month, now.day, now.hour, now.minute, now.second, 0) + b'\x00\x00\x08'
                # Charakterystyka czasu (zwykle 00002a2b...)
                # Ale na razie sprawdźmy same formaty FETCH.
