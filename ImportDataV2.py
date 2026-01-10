import asyncio
import struct
import pandas as pd
from datetime import datetime
from bleak import BleakClient
from Crypto.Cipher import AES

MAC_ADDRESS = "C3:0F:6C:1F:EF:57"
AUTH_KEY = "1b813e705e884c5046aeba4ada347f6d"


UUID_AUTH = "00000009-0000-3512-2118-0009af100700"

class MiBand5Fix:
    def __init__(self, mac, key_hex):
        self.mac = mac
        self.key = bytes.fromhex(key_hex)
        self.auth_event = asyncio.Event()

    async def auth_callback(self, sender, data):
        print(f"[Odebrano z zegarka]: {data.hex()}")
        
        # Etap 1: Zegarek prosi o rozwiązanie zagadki
        if data.startswith(b'\x10\x01\x01'):
            print(">>> Zegarek wysłał prośbę o auth. Proszę go o liczbę losową...")
            await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=True)
            
        # Etap 2: Zegarek wysłał liczbę losową (16 bajtów po b'\x10\x02\x01')
        elif data.startswith(b'\x10\x02\x01'):
            print(">>> Mam liczbę losową! Szyfruję ją kluczem AES...")
            random_nr = data[3:]
            cipher = AES.new(self.key, AES.MODE_ECB)
            encrypted = cipher.encrypt(random_nr)
            response = b'\x03\x00' + encrypted
            await self.client.write_gatt_char(UUID_AUTH, response, response=True)
            
        # Etap 3: Sukces!
        elif data.startswith(b'\x10\x03\x01'):
            print(">>> HURRA! Autoryzacja zakończona sukcesem!")
            self.auth_event.set()
        
        elif data.startswith(b'\x10\x03\x08'):
            print(">>> BŁĄD: Zły klucz AuthKey (Key Mismatch)!")
            self.auth_event.set()

    async def run(self):
        print(f"Łączenie z {self.mac}...")
        try:
            async with BleakClient(self.mac, timeout=20.0) as client:
                self.client = client
                print("Połączono! Próbuję sforsować drzwi (Autoryzacja)...")
                
                # Włączamy powiadomienia zanim cokolwiek wyślemy
                await client.start_notify(UUID_AUTH, self.auth_callback)
                
                # Próbujemy zainicjować autoryzację
                # Jeśli tu znów wystąpi NotSupported, spróbuj zamienić response=True na False
                try:
                    await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=True)
                except Exception as e:
                    print(f"Błąd zapisu: {e}. Próbuję alternatywną metodę...")
                    await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)

                # Czekamy na wynik tańca
                await asyncio.wait_for(self.auth_event.wait(), timeout=15)
                print("Możesz teraz dodać kod do pobierania danych (Etap 4-7).")
                
        except Exception as e:
            print(f"Wystąpił problem techniczny: {e}")

if __name__ == "__main__":
    app = MiBand5Fix(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(app.run())
