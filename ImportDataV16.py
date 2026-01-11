import argparse
import asyncio
import struct
import pandas as pd
from datetime import datetime, timedelta
from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# --- KONFIGURACJA ---
MAC_ADDR = "E1:BB:8E:F3:A5:C0"
AUTH_KEY_HEX = "4dc98efade9c66bb0aba6f6e18528ec2"
AUTH_KEY = bytes.fromhex(AUTH_KEY_HEX)


# UUID charakterystyk (z Twoich logów bluetoothctl)
UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"
UUID_DATA = "00000005-0000-3512-2118-0009af100700"

class MiBand5MasterExtractor:
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
        
        # 1. OBSŁUGA AUTORYZACJI
        if sender.uuid == UUID_AUTH:
            if data.startswith(b'\x10\x01'):
                await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
            elif data.startswith(b'\x10\x02\x01'):
                token = self.encrypt_aes(data[3:])
                await self.client.write_gatt_char(UUID_AUTH, b'\x03\x00' + token, response=False)
            elif data.startswith(b'\x10\x03\x01'):
                print("[+] Autoryzacja zakończona sukcesem!")
                self.auth_ok.set()

        # 2. OBSŁUGA KANAŁU KONTROLNEGO (FETCH)
        elif sender.uuid == UUID_FETCH:
            print(f"[FETCH RESP] {data.hex()}")
            if data.startswith(b'\x10\x01\x01'):
                # Zegarek potwierdził czas (często wysyła go z powrotem)
                try:
                    y, m, d, h, mi, s = struct.unpack("<HBBBBB", data[3:10])
                    self.cursor = datetime(y, m, d, h, mi, s)
                    print(f"[!] Start strumienia danych od: {self.cursor}")
                except:
                    self.cursor = datetime.now() - timedelta(days=1)
            elif data.startswith(b'\x10\x02\x01'):
                print("[!] Otrzymano sygnał końca danych.")
                self.fetch_ok.set()
            elif data.startswith(b'\x10\x01\x02'):
                print("[BŁĄD] Zegarek odrzucił parametry (100102).")

        # 3. OBSŁUGA SUROWYCH DANYCH (DATA)
        elif sender.uuid == UUID_DATA:
            # Tu podsłuchujemy "Matrixa"
            # print(f"Raw packet: {data.hex()}")
            for i in range(len(data) // 4):
                chunk = data[i*4 : (i+1)*4]
                exact_time = self.cursor + timedelta(minutes=len(self.data_store))
                self.data_store.append({
                    "timestamp": exact_time,
                    "steps": chunk[2],
                    "heart_rate": chunk[3] if chunk[3] != 255 else None,
                    "intensity": chunk[1],
                    "category": chunk[0]
                })
            if len(self.data_store) % 100 == 0:
                print(f"Pobrano {len(self.data_store)} minut danych...")

    async def run(self):
        async with BleakClient(self.mac) as client:
            self.client = client
            print(f"--- Łączenie z {self.mac} ---")
            
            await client.start_notify(UUID_AUTH, self.notification_handler)
            await client.start_notify(UUID_FETCH, self.notification_handler)
            await client.start_notify(UUID_DATA, self.notification_handler)
            
            await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)
            await asyncio.wait_for(self.auth_ok.wait(), timeout=10)

            # --- PRÓBA 1: Precyzyjne 01 01 z wyzerowaną godziną ---
            # Ustawiamy na wczoraj, godzina 00:00:00
            start_time = datetime.now() - timedelta(days=1)
            start_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Format 11 bajtów: 01 01 + Rok(2) + Mies + Dzien + Godz + Min + Sek + TZ + 0x00
            ts_bytes = struct.pack("<HBBBBBB", 
                                   start_time.year, 
                                   start_time.month, 
                                   start_time.day, 
                                   start_time.hour, 
                                   start_time.minute, 
                                   0, 0)
            
            # Wiele źródeł podaje, że ostatnie dwa bajty to 0x00 0x17 dla MB5
            cmd_1 = b'\x01\x01' + ts_bytes + b'\x00\x17'
            
            print(f"--- Próba 1 (0101 + zero time): {cmd_1.hex()} ---")
            await client.write_gatt_char(UUID_FETCH, cmd_1, response=False)
            
            await asyncio.sleep(3) # Czekamy na reakcję
            
            if not self.data_store:
                # --- PRÓBA 2: Komenda 0x02 (Daj wszystko od ostatniego razu) ---
                # To jest najbardziej "pancerna" komenda w protokole Huami
                print("--- Próba 1 zawiodła. Próba 2 (Komenda 0x02): Daj wszystko ---")
                await client.write_gatt_char(UUID_FETCH, b'\x02', response=False)

            try:
                await asyncio.wait_for(self.fetch_ok.wait(), timeout=60)
            except asyncio.TimeoutError:
                print(f"Koniec prób. Liczba rekordów: {len(self.data_store)}")

            if self.data_store:
                pd.DataFrame(self.data_store).to_csv("miband_master.csv", index=False)
                print("Dane zapisane!")
if __name__ == "__main__":
    app = MiBand5MasterExtractor(MAC_ADDR, AUTH_KEY)
    asyncio.run(app.run())
