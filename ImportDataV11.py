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

UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"
UUID_DATA = "00000005-0000-3512-2118-0009af100700"

class MiBand5Aggressive:
    def __init__(self, mac, key):
        self.mac = mac
        self.key = key
        self.auth_ok = asyncio.Event()
        self.fetch_ok = asyncio.Event()
        self.data_store = []
        self.cursor = None

    def encrypt_aes(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        return cipher.encryptor().update(data)

    async def notification_handler(self, sender, data):
        data = bytes(data)
        
        # Kanał autoryzacji
        if sender.uuid == UUID_AUTH:
            if data.startswith(b'\x10\x01'):
                await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
            elif data.startswith(b'\x10\x02\x01'):
                token = self.encrypt_aes(data[3:])
                await self.client.write_gatt_char(UUID_AUTH, b'\x03\x00' + token, response=False)
            elif data.startswith(b'\x10\x03\x01'):
                print("[+] Autoryzacja OK.")
                self.auth_ok.set()

        # Kanał kontrolny (FETCH)
        elif sender.uuid == UUID_FETCH:
            print(f"[DEBUG FETCH] Odebrano: {data.hex()}")
            if data.startswith(b'\x10\x01\x01'):
                y, m, d, h, mi, s = struct.unpack("<HBBBBB", data[3:10])
                self.cursor = datetime(y, m, d, h, mi, s)
                print(f"[!] Zegarek zaczyna nadawać od: {self.cursor}")
            elif data.startswith(b'\x10\x02\x01'):
                print("[!] Koniec transmisji.")
                self.fetch_ok.set()

        # Kanał danych (DATA)
        elif sender.uuid == UUID_DATA:
            print(f"DEBUG DATA: {len(data)} bajtów odebrano")
            for i in range(len(data) // 4):
                chunk = data[i*4 : (i+1)*4]
                exact_time = self.cursor + timedelta(minutes=len(self.data_store))
                self.data_store.append({
                    "timestamp": exact_time,
                    "steps": chunk[2],
                    "heart_rate": chunk[3] if chunk[3] != 255 else None,
                    "intensity": chunk[1],
                    "cat": chunk[0]
                })

    async def run(self):
        async with BleakClient(self.mac) as client:
            self.client = client
            print(f"--- Łączenie z {self.mac} ---")
            
            # 1. Włączamy powiadomienia na WSZYSTKIM przed wysłaniem komend
            await client.start_notify(UUID_AUTH, self.notification_handler)
            await client.start_notify(UUID_FETCH, self.notification_handler)
            await client.start_notify(UUID_DATA, self.notification_handler)
            
            # 2. Autoryzacja
            await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)
            await asyncio.wait_for(self.auth_ok.wait(), timeout=10)

            # 3. Formułujemy żądanie (Data + Czas + TZ)
            # Mi Band 5 wymaga czasem b'\x01\x01' a czasem b'\x02' w zależności od firmware
            start = datetime.now() - timedelta(days=2)
            # Format: rok(2b), mies, dzien, godz, min, sek, tz(0)
            ts = struct.pack("<HBBBBBB", start.year, start.month, start.day, start.hour, start.minute, 0, 0)
            
            print(f"--- Prośba o dane od: {start.strftime('%Y-%m-%d')} ---")
            # Wysyłamy komendę \x01\x01 (Pobierz aktywność)
            await client.write_gatt_char(UUID_FETCH, b'\x01\x01' + ts + b'\x00\x08', response=False)

            try:
                # Czekamy na dane (zwiększony timeout)
                await asyncio.wait_for(self.fetch_ok.wait(), timeout=60)
            except asyncio.TimeoutError:
                print(f"[!] Timeout. Odebrano rekordów: {len(self.data_store)}")

            if self.data_store:
                pd.DataFrame(self.data_store).to_csv("miband_raw.csv", index=False)
                print("Zapisano dane do miband_raw.csv")
            else:
                print("Spróbujmy alternatywnej komendy...")
                # Niektóre firmware używają \x02 zamiast \x01\x01
                await client.write_gatt_char(UUID_FETCH, b'\x02' + ts + b'\x00\x08', response=False)
                await asyncio.sleep(5)

if __name__ == "__main__":
    app = MiBand5Aggressive(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(app.run())
