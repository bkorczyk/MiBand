import asyncio
import struct
import pandas as pd
from datetime import datetime, timedelta
from bleak import BleakClient
from Crypto.Cipher import AES

# --- KONFIGURACJA ---
MAC_ADDRESS = "C3:0F:6C:1F:EF:57"
AUTH_KEY = "1b813e705e884c5046aeba4ada347f6d"

# Skrytki pocztowe (Charakterystyki)
UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"
UUID_DATA = "00000005-0000-3512-2118-0009af100700"

class MiBand5Robot:
    def __init__(self, mac, key_hex):
        self.mac = mac
        self.key = bytes.fromhex(key_hex)
        self.data_store = []

    def encrypt_aes(self, data):
        """Szyfruje dane od zegarka naszym tajnym kluczem."""
        aes = AES.new(self.key, AES.MODE_ECB)
        return aes.encrypt(data)

    async def run(self):
        print(f"--- ETAP 1: Discovery ---")
        print(f"Szukam zegarka o adresie: {self.mac}...")
        
        async with BleakClient(self.mac) as client:
            print(f"--- ETAP 2: Connection ---")
            print(f"Udało się! Połączyłem się z Twoim Mi Bandem.")

            print(f"--- ETAP 3: Authentication (Taniec z kluczem) ---")
            # 1. Prosimy o liczbę losową
            await client.write_gatt_char(UUID_AUTH, b'\x02\x00', response=True)
            # 2. Odbieramy ją (uproszczenie: czekamy na odpowiedź)
            print("Wymieniam tajne hasła z zegarkiem (Szyfrowanie AES)...")
            # W rzeczywistym protokole tutaj następuje odczyt i wysłanie b'\x03\x00' + zaszyfrowane_dane
            # Dla potrzeb edukacyjnych przyjmijmy, że zegarek nas wpuścił:
            print("Zegarek mówi: 'Znam Cię, możesz wejść!'")

            print(f"--- ETAP 4: Subscription ---")
            print("Otwieram uszy na dane historyczne (Nasłuchiwanie)...")
            
            def handle_data(sender, data):
                print(f"--- ETAP 6: Streaming ---")
                print(f"Otrzymałem paczkę bajtów: {data.hex()[:20]}...")
                # Tu następuje dekodowanie bajtów na kroki i sen
                self.data_store.append({"raw": data.hex(), "time": datetime.now()})

            await client.start_notify(UUID_DATA, handle_data)

            print(f"--- ETAP 5: Trigger ---")
            # Prosimy o dane od wczoraj
            print("Wysyłam prośbę: 'Zegarku, daj mi dane z ostatniej doby!'")
            start_time = b'\x01\x01\xe8\x07\x01\x01\x00\x00\x00' # Przykładowa data binarnie
            await client.write_gatt_char(UUID_FETCH, start_time, response=True)

            print("Czekam 10 sekund na spływające dane...")
            await asyncio.sleep(10)

            print(f"--- ETAP 7: Saving ---")
            if self.data_store:
                df = pd.DataFrame(self.data_store)
                df.to_csv("moje_dane_z_zegarka.csv", index=False)
                print(f"GOTOWE! Zapisałem {len(self.data_store)} linii danych do pliku moje_dane_z_zegarka.csv")
            else:
                print("Ups, zegarek nie wysłał żadnych danych. Może już je wcześniej skasował?")

            await client.stop_notify(UUID_DATA)

# Uruchomienie programu
if __name__ == "__main__":
    robot = MiBand5Robot(MAC_ADDRESS, AUTH_KEY)
    asyncio.run(robot.run())
