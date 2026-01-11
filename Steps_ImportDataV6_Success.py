import asyncio
from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pandas as pd
from datetime import datetime

# --- KONFIGURACJA ---
# --- KONFIGURACJA ---
MAC_ADDRESS = "E1:BB:8E:F3:A5:C0"
AUTH_KEY_HEX = "4dc98efade9c66bb0aba6f6e18528ec2"
AUTH_KEY = bytes.fromhex(AUTH_KEY_HEX)

UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_STEPS = "00000007-0000-3512-2118-0009af100700"

class MiBand5Stable:
    def __init__(self, mac, key):
        self.mac = mac
        self.key = key
        self.authenticated = asyncio.Event()

    def encrypt_aes(self, data):
        # Stabilna metoda szyfrowania bez zewnętrznych segfaultów
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    async def auth_handler(self, sender, data):
        data = bytes(data)
        print(f"-> [Zegarek]: {data.hex()}")
        
        if data.startswith(b'\x10\x01'):
            print("-> [Krok 1]: Prośba o zagadkę...")
            await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
            
        elif data.startswith(b'\x10\x02\x01'):
            print("-> [Krok 2]: Szyfrowanie zagadki (Stable AES)...")
            random_nr = data[3:]
            encrypted = self.encrypt_aes(bytes(random_nr))
            
            response = b'\x03\x00' + encrypted
            await self.client.write_gatt_char(UUID_AUTH, response, response=False)
            
        elif data.startswith(b'\x10\x03\x01'):
            print("-> [Krok 3]: SUKCES! Zegarek odblokowany.")
            self.authenticated.set()

    async def run(self):
        print(f"--- Łączenie z {self.mac} ---")
        try:
            async with BleakClient(self.mac) as client:
                self.client = client
                await client.start_notify(UUID_AUTH, self.auth_handler)
                await asyncio.sleep(1)

                print("Wysyłam prośbę o autoryzację...")
                await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)

                await asyncio.wait_for(self.authenticated.wait(), timeout=15)
                
                # Pobieranie danych
                steps_data = await client.read_gatt_char(UUID_STEPS)
                steps = int.from_bytes(steps_data[1:4], byteorder='little')
                print(f"\n--- WYNIK DLA AI ---")
                print(f"KROKI: {steps}")
                
                # Zapis do CSV
                df = pd.DataFrame([{"timestamp": datetime.now(), "steps": steps}])
                df.to_csv("dane_ai.csv", index=False)
                print("Dane zapisane w dane_ai.csv. Sukces!")

        except Exception as e:
            print(f"Błąd podczas pracy: {e}")

if __name__ == "__main__":
    app = MiBand5Stable(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(app.run())
