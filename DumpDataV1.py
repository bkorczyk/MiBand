#!/usr/bin/env python3
import argparse
import asyncio
from datetime import datetime, timedelta
from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pandas as pd

# ================= UUID =================
UUID_AUTH = "00000009-0000-3512-2118-0009af100700"
UUID_CURRENT_ACTIVITY = "00000007-0000-3512-2118-0009af100700"
UUID_FETCH = "00000004-0000-3512-2118-0009af100700"
UUID_ACTIVITY_DATA = "00000005-0000-3512-2118-0009af100700"
UUID_BATTERY = "00002a19-0000-1000-8000-00805f9b34fb"
UUID_HR_CONTROL = "00002a39-0000-1000-8000-00805f9b34fb"
UUID_HR_MEAS = "00002a37-0000-1000-8000-00805f9b34fb"


# ================= MiBand =================
class MiBand5:
    def __init__(self, mac: str, key: bytes):
        self.mac = mac
        self.key = key
        self.client = None

        self.auth_ok = asyncio.Event()
        self.fetch_done = asyncio.Event()

        self.history = []
        self.current_hr = None

    # ---------- AES ----------
    def aes_encrypt(self, data: bytes) -> bytes:
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.ECB(),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    # ---------- AUTH ----------
    async def auth_notify(self, _, data: bytearray):
        data = bytes(data)
        print(f"🔐 AUTH RX: {data.hex()}")

        if data.startswith(b"\x10\x01"):
            await self.client.write_gatt_char(UUID_AUTH, b"\x02\x00", response=False)

        elif data.startswith(b"\x10\x02\x01"):
            nonce = data[3:19]
            encrypted = self.aes_encrypt(nonce)
            await self.client.write_gatt_char(
                UUID_AUTH,
                b"\x03\x00" + encrypted,
                response=False
            )

        elif data.startswith(b"\x10\x03\x01"):
            print("✅ AUTH SUCCESS")
            self.auth_ok.set()

        elif data.startswith(b"\x10\x03\x04"):
            print("❌ AUTH FAILED")

    # ---------- HR ----------
    async def hr_notify(self, _, data):
        data = bytes(data)
        flags = data[0]
        self.current_hr = data[1] if flags == 0 else int.from_bytes(data[1:3], "little")

    # ---------- FETCH CTRL ----------
    async def fetch_ctrl_notify(self, _, data):
        data = bytes(data)
        print(f"📡 FETCH CTRL: {data.hex()}")

        if data == b"\x10\x01\x01":
            await self.client.write_gatt_char(UUID_FETCH, b"\x02", response=False)

        elif data in (b"\x10\x01\xff", b"\x10\x01\x04", b"\x10\x01\x02"):
            self.fetch_done.set()

    # ---------- ACTIVITY DATA ----------
    async def activity_notify(self, _, data):
        data = bytes(data)
        if len(data) != 20:
            return

        num = data[0]
        year = data[1] | (data[2] << 8)
        base = datetime(
            year,
            data[3], data[4],
            data[5], data[6], data[7]
        )

        for i in range(num):
            off = 8 + i * 4
            self.history.append({
                "timestamp": base + timedelta(minutes=i),
                "category": data[off],
                "intensity": data[off + 1],
                "steps": data[off + 2],
                "heart_rate": None if data[off + 3] == 255 else data[off + 3],
            })

        await self.client.write_gatt_char(UUID_FETCH, b"\x02", response=False)

    # ---------- MAIN ----------
    async def run(self):
        async with BleakClient(self.mac) as client:
            self.client = client
            print("🔗 Connected")

            # AUTH
            await client.start_notify(UUID_AUTH, self.auth_notify)
            await asyncio.sleep(0.3)
            await client.write_gatt_char(UUID_AUTH, b"\x01\x00", response=False)
            await asyncio.wait_for(self.auth_ok.wait(), timeout=10)

            # CURRENT ACTIVITY
            cur = await client.read_gatt_char(UUID_CURRENT_ACTIVITY)
            steps = int.from_bytes(cur[1:4], "little")
            meters = int.from_bytes(cur[4:8], "little")
            calories = int.from_bytes(cur[8:12], "little")

            # BATTERY
            battery = (await client.read_gatt_char(UUID_BATTERY))[0]

            # HR (one shot)
            await client.start_notify(UUID_HR_MEAS, self.hr_notify)
            await client.write_gatt_char(UUID_HR_CONTROL, b"\x15\x02\x01", response=False)
            await asyncio.sleep(10)
            await client.stop_notify(UUID_HR_MEAS)

            # HISTORY (7 days)
            start = datetime.now() - timedelta(days=7)
            ts = bytes([
                start.year & 0xFF, start.year >> 8,
                start.month, start.day,
                start.hour, start.minute
            ])

            await client.start_notify(UUID_FETCH, self.fetch_ctrl_notify)
            await client.start_notify(UUID_ACTIVITY_DATA, self.activity_notify)

            await client.write_gatt_char(UUID_FETCH, b"\x01\x01" + ts, response=False)
            await asyncio.wait_for(self.fetch_done.wait(), timeout=120)

            # SAVE CSV
            df = pd.DataFrame(self.history)
            df_current = pd.DataFrame([{
                "timestamp": datetime.now(),
                "category": None,
                "intensity": None,
                "steps": steps,
                "heart_rate": self.current_hr,
                "distance_m": meters,
                "calories": calories,
                "battery": battery
            }])

            pd.concat([df_current, df]).to_csv("miband5_data.csv", index=False)
            print("✅ Zapisano miband5_data.csv")


# ================= CLI =================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="plik: MAC;AUTH_KEY_HEX")
    args = parser.parse_args()

    mac, key_hex = open(args.config).read().strip().split(";")
    key = bytes.fromhex(key_hex)

    asyncio.run(MiBand5(mac, key).run())


if __name__ == "__main__":
    main()

