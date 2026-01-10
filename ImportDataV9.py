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

# UUIDs do historii
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"
UUID_DATA = "00000005-0000-3512-2118-0009af100700"
UUID_AUTH = "00000009-0000-3512-2118-0009af100700"

class MiBand5HistoryDump:
    def __init__(self, mac, key):
        self.mac = mac
        self.key = key
        self.auth_completed = asyncio.Event()
        self.fetch_completed = asyncio.Event()
        self.history_data = []
        self.start_time = None

    def encrypt_aes(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    async def notification_handler(self, sender, data):
        data = bytes(data)
        
        # 1. Autoryzacja (Taniec)
        if sender.uuid == UUID_AUTH:
            if data.startswith(b'\x10\x01'):
                await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
            elif data.startswith(b'\x10\x02\x01'):
                encrypted = self.encrypt_aes(data[3:])
                await self.client.write_gatt_char(UUID_AUTH, b'\x03\x00' + encrypted, response=False)
            elif data.startswith(b'\x10\x03\x01'):
                self.auth_completed.set()

        # 2. Nagłówek danych (Zegarek mówi, od kiedy ma dane)
        elif sender.uuid == UUID_FETCH:
            if data.startswith(b'\x10\x01\x01'):
                # Wyciągamy czas z paczki
                year, mon, day, hr, min, sec = struct.unpack("<HBBBBB", data[3:10])
                self.start_time = datetime(year, mon, day, hr, min, sec)
                print(f"[Streaming] Start danych od: {self.start_time}")
            elif data.startswith(b'\x10\x02\x01'):
                print("[Streaming] Koniec przesyłania danych.")
                self.fetch_completed.set()

        # 3. Surowe bajty (4 bajty = 1 minuta)
        elif sender.uuid == UUID_DATA:
            for i in range(len(data) // 4):
                chunk = data[i*4 : (i+1)*4]
                raw_type = chunk[0]
                intensity = chunk[1]
                steps = chunk[2]
                hr = chunk[3]
                
                # Obliczamy czas dla tej konkretnej minuty
                current_time = self.start_time + timedelta(minutes=len(self.history_data))
                
                # Interpretacja faz snu dla 10-latka i AI
                status = "Aktywność"
                if raw_type == 112: status = "Sen Lekki"
                elif raw_type == 121: status = "Sen Głęboki"
                elif raw_type == 122: status = "Sen REM"
                elif raw_type == 126: status = "Zdjęty z ręki"

                self.history_data.append({
                    "czas": current_time,
                    "kroki": steps,
                    "tetno": hr if hr != 255 else None,
                    "intensywnosc": intensity,
                    "status": status
                })

    async def run(self):
        async with BleakClient(self.mac) as client:
            self.client = client
            print("--- Łączenie i Autoryzacja ---")
            await client.start_notify(UUID_AUTH, self.notification_handler)
            await client.start_notify(UUID_FETCH, self.notification_handler)
            await client.start_notify(UUID_DATA, self.notification_handler)
            
            await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)
            await asyncio.wait_for(self.auth_completed.wait(), timeout=10)
            print("[+] Drzwi otwarte!")

            # TRIGGER: Prosimy o dane od wczoraj
            # \x01\x01 + data w formacie MiBand
            start_date = datetime.now() - timedelta(days=1)
            trigger_cmd = b'\x01\x01' + struct.pack("<HBBBBBB", 
                start_date.year, start_date.month, start_date.day, 
                start_date.hour, start_date.minute, 0, 0) + b'\x00\x00'
            
            print(f"--- Pobieranie historii (może potrwać 30-60s) ---")
            await client.write_gatt_char(UUID_FETCH, trigger_cmd, response=False)

            try:
                await asyncio.wait_for(self.fetch_completed.wait(), timeout=120)
            except asyncio.TimeoutError:
                print("Przekroczono czas, zapisuję to co odebrałem.")

            # ZAPIS DO CSV
            if self.history_data:
                df = pd.DataFrame(self.history_data)
                df.to_csv("miband_full_history.csv", index=False)
                print(f"[Sukces] Zapisano {len(df)} minut historii do miband_full_history.csv")
                print(df.tail(10)) # Pokaż końcówkę danych
            else:
                print("Brak danych w pamięci zegarka.")

if __name__ == "__main__":
    app = MiBand5HistoryDump(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(app.run())
