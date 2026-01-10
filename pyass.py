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