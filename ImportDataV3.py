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
UUID_HEART = "00002a37-0000-1000-8000-00805f9b34fb"

class MiBand5Final:
    def __init__(self, mac):
        self.mac = mac
        self.data_records = []

    async def heart_rate_handler(self, sender, data):
        """Odbiera tętno w czasie rzeczywistym."""
        heart_rate = data[1]
        print(f"[AI DATA] Tętno: {heart_rate} BPM")
        self.data_records.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "heart_rate",
            "value": heart_rate
        })

    async def run(self):
        print(f"Łączenie z {self.mac}...")
        async with BleakClient(self.mac) as client:
            print("Połączono! Zegarek jest gotowy.")

            # 1. Odczytujemy kroki (Direct Read)
            print("Pobieram aktualną liczbę kroków...")
            steps_data = await client.read_gatt_char(UUID_STEPS)
            # Dekodowanie kroków (bajty 1-3)
            steps = int.from_bytes(steps_data[1:4], byteorder='little')
            print(f"[AI DATA] Kroki: {steps}")
            self.data_records.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "steps",
                "value": steps
            })

            # 2. Włączamy pomiar tętna (Streaming)
            print("Uruchamiam ciągły pomiar tętna na 30 sekund...")
            # Komenda aktywująca sensor tętna (specyficzna dla Mi Band)
            # Serwis tętna: 0x180d, charakterystyka kontrolna: 0x2a39
            try:
                await client.start_notify(UUID_HEART, self.heart_rate_handler)
                # Wysłanie komendy "Zacznij mierzyć teraz"
                await client.write_gatt_char("00002a39-0000-1000-8000-00805f9b34fb", b'\x15\x01\x01', response=True)
                
                await asyncio.sleep(30) # Zbieramy dane przez pół minuty
                await client.stop_notify(UUID_HEART)
            except Exception as e:
                print(f"Uwaga: Nie udało się uruchomić sensora tętna: {e}")

            # 3. Zapis do CSV dla Twojego modelu AI
            if self.data_records:
                df = pd.DataFrame(self.data_records)
                df.to_csv("dane_dla_ai.csv", index=False)
                print("\n--- SUKCES ---")
                print("Dane zostały zapisane w pliku: dane_dla_ai.csv")
                print(df.tail())
            else:
                print("Brak danych do zapisu.")

if __name__ == "__main__":
    app = MiBand5Final(MAC_ADDRESS)
    asyncio.run(app.run())
