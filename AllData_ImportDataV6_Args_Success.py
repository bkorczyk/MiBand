import argparse
import asyncio
from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pandas as pd
from datetime import datetime, timedelta




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


# --- KONFIGURACJA ---

#AUTH_KEY = bytes.fromhex(AUTH_KEY_HEX)
UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_CURRENT_ACTIVITY = "00000007-0000-3512-2118-0009af100700"  # Kroki, dystans, kalorie
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"  # Charakterystyka do fetch historycznych danych
UUID_ACTIVITY_DATA = "00000005-0000-3512-2118-0009af100700"  # Dane aktywności (historyczne)
UUID_BATTERY = "00002a19-0000-1000-8000-00805f9b34fb"  # Poziom baterii
UUID_HEART_RATE_CONTROL = "00002a39-0000-1000-8000-00805f9b34fb"  # Kontrola tętna
UUID_HEART_RATE_MEASUREMENT = "00002a37-0000-1000-8000-00805f9b34fb"  # Pomiar tętna
UUID_DEVICE_INFO = "00000003-0000-3512-2118-0009af100700"  # Informacje o urządzeniu

class MiBand5Stable:
    def __init__(self, mac, key):
        self.mac = mac
        self.key = key
        self.authenticated = asyncio.Event()
        self.fetch_done = asyncio.Event()
        self.historical_data = []  # Lista do przechowywania historycznych danych
        self.client = None
        self.current_hr = None

    def encrypt_aes(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    async def auth_handler(self, sender, data):
        data = bytes(data)
        print(f"-> [Zegarek - Auth]: {data.hex()}")

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

    async def heart_rate_handler(self, sender, data):
        data = bytes(data)
        print(f"-> [Zegarek - HR]: {data.hex()}")
        flags = data[0]
        self.current_hr = data[1] if flags == 0 else int.from_bytes(data[1:3], 'little')
        print(f"Aktualne tętno: {self.current_hr}")

    async def fetch_control_handler(self, sender, data):
        data = bytes(data)
        print(f"-> [Zegarek - Fetch Control]: {data.hex()}")

        if data == b'\x10\x01\x01':
            print("-> Fetch rozpoczęty pomyślnie.")
            await self.client.write_gatt_char(UUID_FETCH, b'\x02', response=False)  # ACK

        elif data == b'\x10\x01\xff':
            print("-> Fetch zakończony.")
            self.fetch_done.set()

        elif data == b'\x10\x01\x04':
            print("-> Fetch nieudany.")

    async def activity_data_handler(self, sender, data):
        data = bytes(data)
        print(f"-> [Zegarek - Activity Data]: {data.hex()}")

        if len(data) != 20:
            return

        num_samples = data[0]
        year = data[1] + (data[2] << 8)
        month = data[3]
        day = data[4]
        hour = data[5]
        minute = data[6]
        second = data[7]
        base_time = datetime(year, month, day, hour, minute, second)

        for i in range(num_samples):
            offs = 8 + i * 4
            category = data[offs]
            intensity = data[offs + 1]
            steps = data[offs + 2]
            hr = data[offs + 3] if data[offs + 3] != 255 else None
            sample_time = base_time + timedelta(minutes=i)
            self.historical_data.append({
                "timestamp": sample_time,
                "category": category,
                "intensity": intensity,
                "steps": steps,
                "heart_rate": hr
            })

        # ACK po przetworzeniu pakietu
        await self.client.write_gatt_char(UUID_FETCH, b'\x02', response=False)

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

                # Pobieranie danych bieżących
                current_activity_data = await client.read_gatt_char(UUID_CURRENT_ACTIVITY)
                steps = int.from_bytes(current_activity_data[1:4], byteorder='little')
                meters = int.from_bytes(current_activity_data[4:8], byteorder='little')
                calories = int.from_bytes(current_activity_data[8:12], byteorder='little')
                print(f"\n--- BIEŻĄCE DANE ---")
                print(f"KROKI: {steps}, DYSTANS: {meters}m, KALORIE: {calories}")

                # Poziom baterii
                battery_data = await client.read_gatt_char(UUID_BATTERY)
                battery_level = battery_data[0]
                print(f"POZIOM BATERII: {battery_level}%")

                # Informacje o urządzeniu
                device_info = await client.read_gatt_char(UUID_DEVICE_INFO)
                print(f"INFORMACJE O URZĄDZENIU: {device_info.hex()}")

                # Aktualne tętno (jednorazowy pomiar)
                await client.start_notify(UUID_HEART_RATE_MEASUREMENT, self.heart_rate_handler)
                await client.write_gatt_char(UUID_HEART_RATE_CONTROL, b'\x15\x02\x01', response=False)
                await asyncio.sleep(10)  # Czekaj na pomiar (ok. 5-10s)
                await client.stop_notify(UUID_HEART_RATE_MEASUREMENT)

                # Pobieranie danych historycznych (od 7 dni wstecz)
                start_time = datetime.now() - timedelta(days=7)
                time_bytes = bytes([
                    start_time.year % 256, start_time.year // 256,
                    start_time.month, start_time.day,
                    start_time.hour, start_time.minute, start_time.second
                ])
                await client.start_notify(UUID_FETCH, self.fetch_control_handler)
                await client.start_notify(UUID_ACTIVITY_DATA, self.activity_data_handler)
                await client.write_gatt_char(UUID_FETCH, b'\x01\x01' + time_bytes, response=False)
                await asyncio.wait_for(self.fetch_done.wait(), timeout=60)  # Czekaj na zakończenie fetch

                # Zapis do CSV
                current_df = pd.DataFrame([{
                    "timestamp": datetime.now(),
                    "steps": steps,
                    "distance_m": meters,
                    "calories": calories,
                    "battery_level": battery_level,
                    "heart_rate": self.current_hr
                }])
                historical_df = pd.DataFrame(self.historical_data)
                combined_df = pd.concat([current_df, historical_df], ignore_index=True)
                combined_df.to_csv("dane_mi_band.csv", index=False)
                print("Dane zapisane w dane_mi_band.csv. Sukces!")

        except Exception as e:
            print(f"Błąd podczas pracy: {e}")

if __name__ == "__main__":
    app = MiBand5Stable(MAC_ADDR, AUTH_KEY)
    asyncio.run(app.run())
