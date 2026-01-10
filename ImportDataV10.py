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

class MiBand5Master:
    def __init__(self, mac, key):
        self.mac = mac
        self.key = key
        self.auth_ok = asyncio.Event()
        self.fetch_ok = asyncio.Event()
        self.data_store = []
        self.current_time_cursor = None

    def decrypt_aes(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        return cipher.encryptor().update(data)

    async def notification_handler(self, sender, data):
        data = bytes(data)
        
        # Logika Autoryzacji
        if sender.uuid == UUID_AUTH:
            if data.startswith(b'\x10\x01'):
                await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
            elif data.startswith(b'\x10\x02\x01'):
                token = self.decrypt_aes(data[3:])
                await self.client.write_gatt_char(UUID_AUTH, b'\x03\x00' + token, response=False)
            elif data.startswith(b'\x10\x03\x01'):
                print("[AI] Autoryzacja potwierdzona.")
                self.auth_ok.set()

        # Logika Pobierania (Fetch)
        elif sender.uuid == UUID_FETCH:
            if data.startswith(b'\x10\x01\x01'):
                # Wyciąganie czasu z nagłówka paczki
                y, m, d, h, mi, s = struct.unpack("<HBBBBB", data[3:10])
                self.current_time_cursor = datetime(y, m, d, h, mi, s)
                print(f"[AI] Pobieram paczkę danych od: {self.current_time_cursor}")
            elif data.startswith(b'\x10\x02\x01'):
                print("[AI] Transfer ukończony.")
                self.fetch_ok.set()

        # Logika Surowych Danych (Paczki 4-bajtowe)
        elif sender.uuid == UUID_DATA:
            # PODSŁUCH: Drukujemy surowe bajty w hexach
            print(f"[RAW DATA] Pakiet ({len(data)} bajtów): {data.hex()}")
            
            for i in range(len(data) // 4):
                chunk = data[i*4 : (i+1)*4]
                # Definicja bajtów Xiaomi: [Typ, Intensywność, Kroki, Tętno]
                category = chunk[0]
                intensity = chunk[1]
                steps = chunk[2]
                hr = chunk[3]
                
                # Co minutę przesuwamy zegar
                exact_time = self.current_time_cursor + timedelta(minutes=len(self.data_store))
                
                self.data_store.append({
                    "timestamp": exact_time,
                    "steps": steps,
                    "heart_rate": hr if hr != 255 else None,
                    "intensity": intensity,
                    "category_id": category
                })

    async def run(self):
        print(f"--- Łączenie z Mi Band 5 ({self.mac}) ---")
        async with BleakClient(self.mac) as client:
            self.client = client
            await client.start_notify(UUID_AUTH, self.notification_handler)
            await client.start_notify(UUID_FETCH, self.notification_handler)
            await client.start_notify(UUID_DATA, self.notification_handler)
            
            # Start
            await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)
            await asyncio.wait_for(self.auth_ok.wait(), timeout=10)

            # Prośba o dane z ostatnich 3 dni (kompletny zrzut)
            start_point = datetime.now() - timedelta(days=3)
            print(f"--- Żądanie danych od: {start_point.strftime('%Y-%m-%d')} ---")
            
            header = b'\x01\x01' + struct.pack("<HBBBBBB", 
                start_point.year, start_point.month, start_point.day, 
                start_point.hour, start_point.minute, 0, 0) + b'\x00\x00'
            
            await client.write_gatt_char(UUID_FETCH, header, response=False)

            try:
                # Czekamy aż zegarek skończy sypać danymi
                await asyncio.wait_for(self.fetch_ok.wait(), timeout=180)
            except:
                print("Przerwano pobieranie (timeout), ale zapisuję to co mam.")

            if self.data_store:
                df = pd.DataFrame(self.data_store)
                df.to_csv("miband_ai_master_dataset.csv", index=False)
                print(f"\n[SUKCES] Wyciągnięto {len(df)} rekordów do pliku CSV.")
                print(df.sample(5)) # Pokaż losowe próbki danych
            else:
                print("Błąd: Nie odebrano żadnych danych.")

if __name__ == "__main__":
    app = MiBand5Master(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(app.run())
