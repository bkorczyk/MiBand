import asyncio
import struct
import pandas as pd
from datetime import datetime, timedelta
from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Plik z auth keyami (jedna linia = jeden 32-znakowy hex key)
AUTH_KEYS_FILE = "auth_keys.txt"

# UUID charakterystyk (BLE Mi Band 5)
UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"
UUID_DATA = "00000005-0000-3512-2118-0009af100700"

# ------------------ Klasa dla jednej opaski ------------------
class MiBand5Extractor:
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
        # 1. Auth
        if sender.uuid == UUID_AUTH:
            if data.startswith(b'\x10\x01'):
                await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
            elif data.startswith(b'\x10\x02\x01'):
                token = self.encrypt_aes(data[3:])
                await self.client.write_gatt_char(UUID_AUTH, b'\x03\x00' + token, response=False)
            elif data.startswith(b'\x10\x03\x01'):
                print(f"[+] Auth OK dla {self.mac}")
                self.auth_ok.set()

        # 2. Fetch
        elif sender.uuid == UUID_FETCH:
            if data.startswith(b'\x10\x01\x01'):
                try:
                    y, m, d, h, mi, s = struct.unpack("<HBBBBB", data[3:10])
                    self.cursor = datetime(y, m, d, h, mi, s)
                except:
                    self.cursor = datetime.now() - timedelta(days=1)
            elif data.startswith(b'\x10\x02\x01'):
                self.fetch_ok.set()

        # 3. Raw Data
        elif sender.uuid == UUID_DATA:
            for i in range(len(data)//4):
                chunk = data[i*4 : (i+1)*4]
                exact_time = self.cursor + timedelta(minutes=len(self.data_store))
                self.data_store.append({
                    "timestamp": exact_time,
                    "steps": chunk[2],
                    "heart_rate": chunk[3] if chunk[3] != 255 else None,
                    "intensity": chunk[1],
                    "category": chunk[0]
                })

    async def run(self):
        try:
            async with BleakClient(self.mac) as client:
                self.client = client
                await client.start_notify(UUID_AUTH, self.notification_handler)
                await client.start_notify(UUID_FETCH, self.notification_handler)
                await client.start_notify(UUID_DATA, self.notification_handler)

                await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)
                await asyncio.wait_for(self.auth_ok.wait(), timeout=10)

                # fetch data od wczoraj
                start_time = datetime.now() - timedelta(days=1)
                start_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
                ts_bytes = struct.pack("<HBBBBBB", 
                                       start_time.year, start_time.month, start_time.day,
                                       start_time.hour, start_time.minute, 0, 0)
                cmd_1 = b'\x01\x01' + ts_bytes + b'\x00\x17'
                await client.write_gatt_char(UUID_FETCH, cmd_1, response=False)
                await asyncio.sleep(3)

                if not self.data_store:
                    await client.write_gatt_char(UUID_FETCH, b'\x02', response=False)

                try:
                    await asyncio.wait_for(self.fetch_ok.wait(), timeout=60)
                except asyncio.TimeoutError:
                    print(f"Koniec prób. Liczba rekordów: {len(self.data_store)}")

                if self.data_store:
                    pd.DataFrame(self.data_store).to_csv("miband_master.csv", index=False)
                    print("Dane zapisane!")

        except Exception as e:
            print(f"[!] Błąd podczas łączenia/auth: {e}")

# ------------------ Funkcja główna ------------------
async def main():
    # Wczytaj wszystkie AUTH_KEY
    with open(AUTH_KEYS_FILE, "r") as f:
        auth_keys = [bytes.fromhex(line.strip()) for line in f if line.strip()]

    # Skan BLE
    print("🔍 Skanowanie BLE...")
    devices = await BleakScanner.discover(timeout=5.0)
    miband_devices = [d for d in devices if d.name and "Mi Smart Band 5" in d.name]

    if not miband_devices:
        print("Nie znaleziono żadnej opaski MI Band 5 w zasięgu.")
        return

    # ------------------ Próba połączenia z każdym wykrytym urządzeniem ------------------
    for dev in miband_devices:
        print(f"Spróbuję połączyć się z {dev.address}")
        success = False
        for key in auth_keys:
            for attempt in range(3):  # retry 3 razy, bo opaska może chwilowo zniknąć
                try:
                    extractor = MiBand5Extractor(dev.address, key)
                    await extractor.run()
                    if extractor.data_store:
                        print(f"✅ Sukces z auth_key: {key.hex()} na {dev.address}")
                        success = True
                        break  # idziemy do następnego klucza
                except Exception as e:
                    print(f"[!] Próba {attempt+1} dla {dev.address} nie powiodła się: {e}")
                    await asyncio.sleep(2)
            if success:
                break  # idziemy do następnego urządzenia
        if not success:
            print(f"[!] Nie udało się połączyć z {dev.address} żadnym AUTH_KEY")


if __name__ == "__main__":
    asyncio.run(main())

