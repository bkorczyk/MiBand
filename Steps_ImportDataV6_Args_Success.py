import argparse
import asyncio
from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pandas as pd
from datetime import datetime

# --- KONFIGURACJA ---
# --- KONFIGURACJA ---
#MAC_ADDRESS = "DF:D4:C3:61:45:5C"
#MAC_ADDRESS = "F7:00:2D:60:FE:A8"
#AUTH_KEY_HEX = "97b11418379005f4aabb4fd69a788483"
#AUTH_KEY = bytes.fromhex(AUTH_KEY_HEX)

# Argumenty linii poleceń
parser = argparse.ArgumentParser(description="Mi Band 4 - odczyt danych po uwierzytelnieniu")
parser.add_argument("config_file", type=str, help="Ścieżka do pliku konfiguracyjnego (format: MAC_ADDR;AUTH_KEY_HEX)")
args = parser.parse_args()

# Odczyt z pliku
try:
    with open(args.config_file, "r") as f:
        line = f.read().strip()
        parts = line.split(";")
        if len(parts) != 2:
            raise ValueError("Nieprawidłowy format pliku: oczekuje dokładnie jednego ';'")
        
        MAC_ADDR = parts[0].strip()
        AUTH_KEY_HEX = parts[1].strip()
        
        # Walidacja MAC
        if len(MAC_ADDR) != 17 or MAC_ADDR.count(":") != 5:
            raise ValueError(f"Nieprawidłowy format MAC: {MAC_ADDR} (oczekiwany: xx:xx:xx:xx:xx:xx)")
        
        # Walidacja Auth Key
        if len(AUTH_KEY_HEX) != 32 or not all(c in "0123456789abcdefABCDEF" for c in AUTH_KEY_HEX):
            raise ValueError(f"Nieprawidłowy format Auth Key: {AUTH_KEY_HEX} (oczekiwany: dokładnie 32 znaki hex)")
        
        AUTH_KEY = bytes.fromhex(AUTH_KEY_HEX)
        
        print(f"Wczytano: MAC = {MAC_ADDR}, Auth Key = {AUTH_KEY_HEX}")
except FileNotFoundError:
    print(f"Błąd: Plik '{args.config_file}' nie istnieje")
    exit(1)
except Exception as e:
    print(f"Błąd odczytu pliku: {e}")
    exit(1)

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
    app = MiBand5Stable(MAC_ADDR, AUTH_KEY)
    asyncio.run(app.run())
