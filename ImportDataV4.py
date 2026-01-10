import asyncio
import struct
import pandas as pd
from datetime import datetime
from bleak import BleakClient
from Crypto.Cipher import AES

MAC_ADDRESS = "C3:0F:6C:1F:EF:57"
AUTH_KEY = "1b813e705e884c5046aeba4ada347f6d"


UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_STEPS = "00000007-0000-3512-2118-0009af100700"

class MiBand5UltraFix:
    def __init__(self, mac, key):
        self.mac = mac
        self.key = key
        self.authenticated = asyncio.Event()

    async def auth_handler(self, sender, data):
        print(f"-> [Zegarek wysłał]: {data.hex()}")
        
        # Start autoryzacji lub prośba o zagadkę
        if data.startswith(b'\x10\x01'):
            print("-> [Krok 1]: Zegarek prosi o zagadkę. Wysyłam 0200...")
            await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
            
        # Otrzymano zagadkę (16 bajtów)
        elif data.startswith(b'\x10\x02\x01'):
            print("-> [Krok 2]: Rozwiązuję zagadkę kluczem AES...")
            random_nr = data[3:]
            cipher = AES.new(self.key, AES.MODE_ECB)
            encrypted = cipher.encrypt(random_nr)
            response = b'\x03\x00' + encrypted
            await self.client.write_gatt_char(UUID_AUTH, response, response=False)
            
        # Sukces!
        elif data.startswith(b'\x10\x03\x01'):
            print("-> [Krok 3]: Sukces! Zegarek odblokowany.")
            self.authenticated.set()

    async def run(self):
        print(f"--- Łączenie z {self.mac} ---")
        async with BleakClient(self.mac) as client:
            self.client = client
            print("Połączono. Włączam nasłuchiwanie...")
            
            await client.start_notify(UUID_AUTH, self.auth_handler)
            await asyncio.sleep(1) # Chwila oddechu dla Bluetooth

            print("Wysyłam prośbę o autoryzację (tryb BEZ ODPOWIEDZI)...")
            try:
                # Kluczowy moment: zmieniamy response na False, aby ominąć błąd systemu
                await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)
            except Exception as e:
                print(f"Błąd zapisu: {e}")
                return

            try:
                await asyncio.wait_for(self.authenticated.wait(), timeout=15)
                print("Teraz pobieram Twoje dane dla AI!")
                
                # Odczyt kroków
                steps_data = await client.read_gatt_char(UUID_STEPS)
                steps = int.from_bytes(steps_data[1:4], byteorder='little')
                print(f"WYNIK: Masz dzisiaj {steps} kroków.")
                
                # Zapis
                pd.DataFrame([{"time": datetime.now(), "steps": steps}]).to_csv("dane_ai.csv", index=False)
                print("Zapisano do dane_ai.csv")
                
            except asyncio.TimeoutError:
                print("Błąd: Zegarek nie odpowiedział na czas. Sprawdź czy Bluetooth w telefonie jest WYŁĄCZONY.")

if __name__ == "__main__":
    app = MiBand5UltraFix(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(app.run())
