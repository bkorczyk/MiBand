import asyncio
from bleak import BleakClient, BleakGATTCharacteristic

# Device MAC
MAC_ADDR = "C3:0F:6C:1F:EF:57"

# GATT Services and Characteristics (based on Mi Band protocol)
DEVICE_INFO_SERVICE = "0000180A-0000-1000-8000-00805F9B34FB"
SERIAL_NUMBER_CHAR = "00002A25-0000-1000-8000-00805F9B34FB"  # Serial
HW_REV_CHAR = "00002A27-0000-1000-8000-00805F9B34FB"        # Hardware revision
SW_REV_CHAR = "00002A28-0000-1000-8000-00805F9B34FB"        # Software revision

BATTERY_SERVICE = "0000180F-0000-1000-8000-00805F9B34FB"
BATTERY_LEVEL_CHAR = "00002A19-0000-1000-8000-00805F9B34FB"

CURRENT_TIME_SERVICE = "00001805-0000-1000-8000-00805F9B34FB"
CURRENT_TIME_CHAR = "00002A2B-0000-1000-8000-00805F9B34FB"

async def main():
    async with BleakClient(MAC_ADDR) as client:
        if not client.is_connected:
            print("Failed to connect.")
            return

        print("Connected successfully.")
        
        import binascii
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        # Auth service and characteristic
        AUTH_SERVICE = "0000FEE1-0000-1000-8000-00805F9B34FB"
        AUTH_CHAR = "00000009-0000-3512-2118-0009AF100700"

        # Your auth key (16 bytes, from hex)
        AUTH_KEY_HEX = "468928d1a14c8de6238e7571f401904d"  # e.g., "8fa9b42078627a654d22beff985655db"
        AUTH_KEY = binascii.unhexlify(AUTH_KEY_HEX)

        # Notification handler
        def auth_notification_handler(sender: BleakGATTCharacteristic, data: bytearray):
            print(f"Notification from {sender.uuid}: {data.hex()}")
            # Parse responses here (e.g., check for auth challenge or success)

        # Enable notifications on auth char
        await client.start_notify(AUTH_CHAR, auth_notification_handler)

        # Step 1: Send auth request (0x01 for key-based auth)
        auth_req = bytearray([0x01, 0x00]) + AUTH_KEY  # Or just [0x01] if key sent separately; adjust per protocol
        await client.write_gatt_char(AUTH_CHAR, auth_req)
        print("Sent auth request.")

        # Wait for challenge notification (tracker sends 16-byte random challenge)
        # (In practice, parse the notification data in handler; e.g., if data starts with certain bytes, extract challenge)
        await asyncio.sleep(2)  # Placeholder; replace with event wait

        # Assume challenge received (e.g., from handler); example chal = some_16_bytes
        chal = bytearray(b'\x00' * 16)  # Replace with actual challenge from notification

        # Step 2: Encrypt challenge with AES-ECB using auth key
        backend = default_backend()
        cipher = Cipher(algorithms.AES(AUTH_KEY), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        resp = encryptor.update(chal) + encryptor.finalize()

        # Step 3: Send response (0x03 prefix)
        auth_resp = bytearray([0x03, 0x00]) + resp
        await client.write_gatt_char(AUTH_CHAR, auth_resp)
        print("Sent encrypted response.")

        # Wait for auth OK notification (e.g., check handler for success)
        await asyncio.sleep(2)

        # Now read protected chars, e.g., steps
        STEPS_CHAR = "00000007-0000-3512-2118-0009AF100700"  # Steps char UUID
        steps = await client.read_gatt_char(STEPS_CHAR)
        # Parse steps (bytes: steps[2], meters[4], calories[4], etc.)
        print(f"Steps: {int.from_bytes(steps[1:3], 'little')}")

        # Stop notifications
        await client.stop_notify(AUTH_CHAR)

        # Read serial number
        serial = await client.read_gatt_char(SERIAL_NUMBER_CHAR)
        print(f"Serial: {serial.decode('utf-8')}")

        # Read hardware revision
        hw_rev = await client.read_gatt_char(HW_REV_CHAR)
        print(f"Hardware revision: {hw_rev.decode('utf-8')}")

        # Read software revision
        sw_rev = await client.read_gatt_char(SW_REV_CHAR)
        print(f"Software revision: {sw_rev.decode('utf-8')}")

        # Read battery level
        battery = await client.read_gatt_char(BATTERY_LEVEL_CHAR)
        print(f"Battery level: {int.from_bytes(battery, 'little')}%")


        # Read current time (bytes: year[2], month, day, hour, min, sec, day_of_week, fraction256, adjust_reason)
        time_bytes = await client.read_gatt_char(CURRENT_TIME_CHAR)
        year = int.from_bytes(time_bytes[0:2], 'little')
        month, day, hour, minute, second = time_bytes[2:7]
        print(f"Time: {year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}")

asyncio.run(main())
