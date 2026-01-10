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

class MiBand5FinalFix:
    def __init__(self, mac, key):
        self.mac = mac
        self.key = key
        self.authenticated = asyncio.Event()

    async def auth_handler(self, sender, data):
        # Konwertujemy dane na format 'bytes', aby szyfrowanie AES nie zgłaszało błędu
        data = bytes(data)
        print(f"-> [Zegarek wysłał]: {data.hex()}")
        
        if data.startswith(b'\x10\x01'):
            print("-> [Krok 1]: Proszę o zagadkę...")
            await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=False)
            
        elif data.startswith(b'\x10\x02\x01'):
            print("-> [Krok 2]: Rozwiązuję zagadkę (Konwersja na bytes + AES)...")
            random_nr = data[3:] # To są te losowe bajty od zegarka
            
            # TU BYŁ BŁĄD - dodajemy jawne bytes()
            cipher = AES.new(self.key, AES.MODE_ECB)
            encrypted = cipher.encrypt(bytes(random_nr)) 
            
            response = b'\x03\x00' + encrypted
            await self.client.write_gatt_char(UUID_AUTH, response, response=False)
            
        elif data.startswith(b'\x10\x03\x01'):
            print("-> [Krok 3]: Sukces! Zegarek odblokowany.")
            self.authenticated.set()
        
        elif data.startswith(b'\x10\x03\x08'):
            print("-> [BŁĄD]: Zegarek odrzucił klucz. Sprawdź czy AUTH_KEY jest poprawny!")

    async def run(self):
        print(f"--- Łączenie z {self.mac} ---")
        async with BleakClient(self.mac) as client:
            self.client = client
            await client.start_notify(UUID_AUTH, self.auth_handler)
            await asyncio.sleep(1)

            print("Wysyłam prośbę o autoryzację...")
            await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=False)

            try:
                await asyncio.wait_for(self.authenticated.wait(), timeout=15)
                print("--- DOSTĘP PRZYZNANY ---")
                
                # Pobieramy kroki
                steps_data = await client.read_gatt_char(UUID_STEPS)
                steps = int.from_bytes(steps_data[1:4], byteorder='little')
                print(f"Dane dla AI: Kroki = {steps}")
                
                # Zapis do CSV
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                df = pd.DataFrame([{"timestamp": now, "steps": steps}])
                df.to_csv("dane_ai.csv", index=False)
                print(f"Plik 'dane_ai.csv' został zaktualizowany.")

            except asyncio.TimeoutError:
                print("Błąd: Timeout. Zegarek nie odpowiedział na rozwiązanie zagadki.")

if __name__ == "__main__":
    app = MiBand5FinalFix(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(app.run())
