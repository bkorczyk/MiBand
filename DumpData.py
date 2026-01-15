import sys
import asyncio
import csv
import time
from bleak import BleakClient
from Crypto.Cipher import AES

# ===== UUID =====
SERVICE_UUID = "0000fed0-0000-3512-2118-0009af100700"
TX_UUID      = "00000010-0000-3512-2118-0009af100700"  # notify
RX_UUID      = "00000009-0000-3512-2118-0009af100700"  # write

# ===== TRANSPORT =====
MTU = 20
HEADER = 3
PAYLOAD = MTU - HEADER

packet_id = 1
rx_buffers = {}

# ===== AUTH =====
auth_nonce = None
auth_ok = False

# ===== CSV =====
csv_file = open("history.csv", "w", newline="")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["timestamp", "steps", "heart_rate", "raw_hex"])

# ===== UTILS =====
def aes_encrypt(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)

# ===== RX HANDLER =====
def handle_notify(_, data: bytearray):
    global auth_nonce, auth_ok

    pid = data[0]
    flags = data[1]
    payload = data[3:]

    if pid not in rx_buffers:
        rx_buffers[pid] = bytearray()

    rx_buffers[pid] += payload

    if flags not in (0x00, 0x20):
        return

    full = bytes(rx_buffers[pid])
    del rx_buffers[pid]

    print(f"\n📦 RX ({len(full)} bytes): {full.hex()}")

    # ---- AUTH ----
    if full[0] == 0x10:
        auth_nonce = full[1:17]
        print("🔐 AUTH NONCE:", auth_nonce.hex())
        return

    if full[0] == 0x03:
        if full[1] == 0x01:
            auth_ok = True
            print("✅ AUTH SUCCESS")
        else:
            print("❌ AUTH FAILED")
        return

    # ---- HISTORY DATA ----
    parse_history(full)

# ===== PARSER =====
def parse_history(data: bytes):
    i = 0
    while i + 7 <= len(data):
        ts = int.from_bytes(data[i:i+4], "little")
        steps = int.from_bytes(data[i+4:i+6], "little")
        hr = data[i+6]

        if ts < 1500000000 or ts > int(time.time()) + 3600:
            break

        print(f"🕒 {time.ctime(ts)} | 👣 {steps} | ❤️ {hr}")
        csv_writer.writerow([ts, steps, hr, data.hex()])
        csv_file.flush()

        i += 7

# ===== TX =====
async def send_packet(client, payload: bytes):
    global packet_id
    pid = packet_id & 0xFF
    packet_id += 1

    if len(payload) <= PAYLOAD:
        frame = bytes([pid, 0x00, 0x00]) + payload
        await client.write_gatt_char(RX_UUID, frame, response=False)
        return

    seq = 0
    first = True
    offset = 0

    while offset < len(payload):
        chunk = payload[offset:offset + PAYLOAD]
        offset += PAYLOAD

        if first:
            flag = 0x01
            first = False
        elif offset >= len(payload):
            flag = 0x20
        else:
            flag = 0x10

        frame = bytes([pid, flag, seq]) + chunk
        await client.write_gatt_char(RX_UUID, frame, response=False)
        seq += 1
        await asyncio.sleep(0.03)

# ===== AUTH FLOW =====
async def auth(client, auth_key):
    global auth_ok, client_global, auth_key_global

    client_global = client
    auth_key_global = auth_key
    auth_ok = False

    await client.start_notify(TX_UUID, auth_notify_handler)

    print("🔐 AUTH START")
    await client.write_gatt_char(RX_UUID, b'\x01\x00', response=False)

    # czekamy max 10s
    for _ in range(100):
        if auth_ok:
            return
        await asyncio.sleep(0.1)

    raise RuntimeError("AUTH FAILED")


# ===== HISTORY REQUEST =====
def history_request():
    return bytes([0x01, 0x01])

async def auth_notify_handler(sender, data: bytearray):
    global auth_ok, auth_nonce, client_global, auth_key_global

    data = bytes(data)
    print(f"🔐 AUTH RX: {data.hex()}")

    # 10 01 xx → band gotowy, prosi o nonce request
    if data.startswith(b'\x10\x01'):
        await client_global.write_gatt_char(
            RX_UUID,
            b'\x02\x00',
            response=False
        )

    # 10 02 01 <16B>
    elif data.startswith(b'\x10\x02\x01'):
        auth_nonce = data[3:19]
        encrypted = AES.new(auth_key_global, AES.MODE_ECB).encrypt(auth_nonce)
        await client_global.write_gatt_char(
            RX_UUID,
            b'\x03\x00' + encrypted,
            response=False
        )

    # 10 03 01 → success
    elif data.startswith(b'\x10\x03\x01'):
        print("✅ AUTH SUCCESS")
        auth_ok = True


# ===== MAIN =====
async def main():
    if len(sys.argv) != 2:
        print("Usage: python miband5_dump.py band.txt")
        return

    mac, key_hex = open(sys.argv[1]).read().strip().split(";")
    auth_key = bytes.fromhex(key_hex)

    print("📡 MAC:", mac)
    print("🔑 AUTH_KEY:", key_hex)

    async with BleakClient(mac) as client:
        print("🔗 Connected")

        await client.start_notify(TX_UUID, handle_notify)

        await auth(client, auth_key)

        print("📊 Requesting history...")
        await send_packet(client, history_request())

        await asyncio.sleep(20)

    csv_file.close()
    print("✅ DONE, zapisano history.csv")

if __name__ == "__main__":
    asyncio.run(main())

