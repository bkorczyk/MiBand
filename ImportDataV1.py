import asyncio
import struct
import pandas as pd
from datetime import datetime
from bleak import BleakClient
from Crypto.Cipher import AES

MAC_ADDRESS = "C3:0F:6C:1F:EF:57"
AUTH_KEY = "1b813e705e884c5046aeba4ada347f6d"

UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"
UUID_DATA = "00000005-0000-3512-2118-0009af100700"

class MiBand5Robot:
    def __init__(self, mac, key_hex):
        self.mac = mac
        self.key = bytes.fromhex(key_hex)
        self.data_store = []
        self.auth_event = asyncio.Event()

    def encrypt_data(self, data):
        # To jest nasze "kodowanie hasła" algorytmem AES
        aes = AES.new(self.key, AES.MODE_ECB)
        return aes.encrypt(data)

    async def auth_handler(self, sender, data):
        """Obsługuje etapy uwierzytelniania."""
        if data[:3] == b'\x10\x01\x01':
            print("[Auth] KROK A: Proszę zegarek o zagadkę...")
            await self.client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=True)
        
        elif data[:3] == b'\x10\x02\x01':
            print("[Auth] KROK B: Otrzymałem zagadkę, rozwiązuję ją kluczem AES...")
            random_number = data[3:]
            encrypted_number = self.encrypt_data(random_number)
            answer = b'\x03\x00' + encrypted_number
            await self.client.write_gatt_char(UUID_AUTH, answer, response=True)
            
        elif data[:3] == b'\x10\x03\x01':
            print("[Auth] KROK C: Sukces! Zegarek mnie rozpoznał.")
            self.auth_event.set()
        else:
            print(f"[Auth] Coś poszło nie tak: {data.hex()}")

    async def run(self):
        print(f"--- ETAP 1 & 2: Szukanie i Łączenie ---")
        async with BleakClient(self.mac) as client:
            self.client = client
            print(f"Połączono z {self.mac}")

            print(f"--- ETAP 3: Autoryzacja (Taniec z kluczem) ---")
            # Włączamy nasłuchiwanie na odpowiedzi autoryzacji
            await client.start_notify(UUID_AUTH, self.auth_handler)
            
            # Zaczynamy taniec wysyłając sygnał startowy
            await client.write_gatt_char(UUID_AUTH, b'\x01\x00', response=True)
            
            # Czekamy aż auth_handler ustawi flagę sukcesu
            try:
                await asyncio.wait_for(self.auth_event.wait(), timeout=10)
            except asyncio.TimeoutError:
                print("Błąd: Zegarek nie odpowiedział na czas. Sprawdź AuthKey!")
                return

            print(f"--- ETAP 4 & 5: Słuchanie i Prośba o Dane ---")
            def data_handler(sender, data):
                print(f"Odebrano paczkę: {len(data)} bajtów")
                self.data_store.append({"raw": data.hex(), "time": datetime.now()})

            await client.start_notify(UUID_DATA, data_handler)
            
            # Przykładowa komenda prośby o historię (ostatnie minuty)
            # Format: 0x01 (Fetch) + 0x01 (Typ) + timestamp
            print("Wysyłam prośbę o historię...")
            await client.write_gatt_char(UUID_FETCH, b'\x01\x01', response=True)

            await asyncio.sleep(5) # Zbieraj przez 5 sekund
            
            print(f"--- ETAP 6 & 7: Zapisywanie ---")
            pd.DataFrame(self.data_store).to_csv("dane_ai.csv", index=False)
            print("Zapisano do dane_ai.csv. Możesz teraz karmić swój model AI!")

if __name__ == "__main__":
    robot = MiBand5Robot(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(robot.run())
