import asyncio
import struct
import pandas as pd
from datetime import datetime
from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- KONFIGURACJA ---
# --- KONFIGURACJA ---
MAC_ADDRESS = "FB:5D:2D:49:5A:2A"
AUTH_KEY_HEX = "A453B47B6646C8B4F76EA88A44D66F32"
AUTH_KEY = bytes.fromhex(AUTH_KEY_HEX)

# Charakterystyki z Twojego skanowania
UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_STEPS = "00000007-0000-3512-2118-0009af100700"
UUID_BATTERY = "00002a19-0000-1000-8000-00805f9b34fb"
UUID_HR_MEASURE = "00002a37-0000-1000-8000-00805f9b34fb"
UUID_HR_CONTROL = "00002a39-0000-1000-8000-00805f9b34fb"

class MiBandAICollector:
    def __init__(self, mac, key):
        self.mac = mac
        self.key = key
        self.auth_event = asyncio.Event()
        self.final_data = []

    def encrypt_aes(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    async def notification_handler(self, sender, data):
        data = bytes(data)
        # Obsługa tańca autoryzacji
        if data.startswith(b'\x10\x01'):
            await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
        elif data.startswith(b'\x10\x02\x01'):
            encrypted = self.encrypt_aes(data[3:])
            await self.client.write_gatt_char(UUID_AUTH, b'\x03\x00' + encrypted, response=False)
        elif data.startswith(b'\x10\x03\x01'):
            print("[+] Autoryzacja zakończona sukcesem!")
            self.auth_event.set()
            
        # Obsługa tętna (jeśli subskrybowane)
        elif sender.uuid == UUID_HR_MEASURE:
            hr = data[1]
            print(f"-> Tętno: {hr} BPM")
            self.final_data.append({"type": "heart_rate", "value": hr, "time": datetime.now()})

    async def run(self):
        print(f"--- Próba połączenia z {self.mac} ---")
        async with BleakClient(self.mac) as client:
            self.client = client
            await client.start_notify(UUID_AUTH, self.notification_handler)
            
            # Start autoryzacji
            await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)
            await asyncio.wait_for(self.auth_event.wait(), timeout=10)

            # 1. Pobierz Baterię
            batt_data = await client.read_gatt_char(UUID_BATTERY)
            battery = batt_data[0]
            print(f"[Dane] Bateria: {battery}%")

            # 2. Pobierz Kroki
            steps_raw = await client.read_gatt_char(UUID_STEPS)
            steps = int.from_bytes(steps_raw[1:4], byteorder='little')
            print(f"[Dane] Kroki: {steps}")

            # 3. Uruchom Tętno na 15 sekund
            print("--- Uruchamiam sensor tętna (30s) ---")
            await client.start_notify(UUID_HR_MEASURE, self.notification_handler)
            # Komenda 'Włącz ciągły pomiar'
            await client.write_gatt_char(UUID_HR_CONTROL, b'\x15\x01\x01', response=True)
            
            await asyncio.sleep(15) # Zbieraj tętno przez 15 sekund
            
            # Zapisz wszystko do CSV
            self.final_data.append({"type": "battery", "value": battery, "time": datetime.now()})
            self.final_data.append({"type": "steps", "value": steps, "time": datetime.now()})
            
            df = pd.DataFrame(self.final_data)
            df.to_csv("miband_ai_ready.csv", index=False)
            print("\n[GOTOWE] Dane zapisane do miband_ai_ready.csv")

if __name__ == "__main__":
    app = MiBandAICollector(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(app.run())
