import asyncio
import struct
import pandas as pd
from datetime import datetime, timedelta
from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- KONFIGURACJA ---
MAC_ADDRESS = "FB:5D:2D:49:5A:2A"
AUTH_KEY_HEX = "A453B47B6646C8B4F76EA88A44D66F32"
AUTH_KEY = bytes.fromhex(AUTH_KEY_HEX)

# UUIDs
UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"
UUID_DATA = "00000005-0000-3512-2118-0009af100700"

class MiBand5FullData:
    def __init__(self, mac, key):
        self.mac = mac
        self.key = key
        self.auth_completed = asyncio.Event()
        self.fetch_completed = asyncio.Event()
        self.history_records = []
        self.current_packet_time = None

    def encrypt_aes(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decode_history_packet(self, data):
        """Dekoduje paczkę 4-bajtową (1 minuta aktywności)."""
        # Mi Band 5 przesyła dane w paczkach po 4 bajty
        for i in range(len(data) // 4):
            pkg = data[i*4 : (i+1)*4]
            raw_kind = pkg[0]
            intensity = pkg[1]
            steps = pkg[2]
            heart_rate = pkg[3]

            if self.current_packet_time:
                # Każdy kolejny rekord to kolejna minuta
                record_time = self.current_packet_time + timedelta(minutes=len(self.history_records))
                
                # Mapowanie snu dla AI
                sleep_type = "Wake"
                if raw_kind == 112: sleep_type = "Light Sleep"
                elif raw_kind == 121: sleep_type = "Deep Sleep"
                elif raw_kind == 122: sleep_type = "REM"

                self.history_records.append({
                    "timestamp": record_time,
                    "raw_kind": raw_kind,
                    "sleep_phase": sleep_type,
                    "steps": steps,
                    "heart_rate": heart_rate if heart_rate != 255 else None,
                    "intensity": intensity
                })

    async def notification_handler(self, sender, data):
        data = bytes(data)
        
        # Obsługa Autoryzacji
        if sender.uuid == UUID_AUTH:
            if data.startswith(b'\x10\x01'):
                await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
            elif data.startswith(b'\x10\x02\x01'):
                encrypted = self.encrypt_aes(data[3:])
                await self.client.write_gatt_char(UUID_AUTH, b'\x03\x00' + encrypted, response=False)
            elif data.startswith(b'\x10\x03\x01'):
                print("[+] Autoryzacja OK")
                self.auth_completed.set()

        # Obsługa Sterowania Transferem (Fetch)
        elif sender.uuid == UUID_FETCH:
            if data.startswith(b'\x10\x01\x01'):
                # Zegarek podaje czas startu danych w bajtach [7:13]
                try:
                    ts = struct.unpack("<HBBBBB", data[3:10])
                    self.current_packet_time = datetime(ts[0], ts[1], ts[2], ts[3], ts[4])
                    print(f"[+] Zegarek zaczyna nadawać od: {self.current_packet_time}")
                except:
                    print("[!] Błąd odczytu czasu startu")
            elif data.startswith(b'\x10\x02\x01'):
                print("[+] Transfer zakończony pomyślnie")
                self.fetch_completed.set()

        # Obsługa Surowych Danych
        elif sender.uuid == UUID_DATA:
            self.decode_history_packet(data)

    async def run(self):
        async with BleakClient(self.mac) as client:
            self.client = client
            print(f"--- Połączono z {self.mac} ---")
            
            await client.start_notify(UUID_AUTH, self.notification_handler)
            await client.start_notify(UUID_FETCH, self.notification_handler)
            await client.start_notify(UUID_DATA, self.notification_handler)
            
            # 1. Autoryzacja
            await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)
            await asyncio.wait_for(self.auth_completed.wait(), timeout=10)

            # 2. Prośba o dane (Ostatnie 24h)
            # Format: \x01\x01 + rok(2b) + mies + dzien + godz + min + sek + tz
            yesterday = datetime.now() - timedelta(days=1)
            time_trigger = struct.pack("<HBBBBBB", 
                yesterday.year, yesterday.month, yesterday.day, 
                yesterday.hour, yesterday.minute, yesterday.second, 0)
            
            print(f"--- Pobieranie historii od {yesterday.strftime('%Y-%m-%d %H:%M')} ---")
            # Wysyłamy komendę \x01\x01 (pobierz dane aktywności)
            await client.write_gatt_char(UUID_FETCH, b'\x01\x01' + time_trigger + b'\x00\x00', response=False)

            # Czekamy na spłynięcie wszystkich paczek (może to zająć chwilę)
            try:
                await asyncio.wait_for(self.fetch_completed.wait(), timeout=60)
            except asyncio.TimeoutError:
                print("[!] Osiągnięto limit czasu, zapisuję to co mam...")

            # 3. Zapis do CSV
            if self.history_records:
                df = pd.DataFrame(self.history_records)
                df.to_csv("miband_full_ai_data.csv", index=False)
                print(f"--- SUKCES! Zapisano {len(df)} minut historii do miband_full_ai_data.csv ---")
            else:
                print("[!] Nie udało się pobrać żadnych rekordów.")

if __name__ == "__main__":
    app = MiBand5FullData(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(app.run())
