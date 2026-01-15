#!/usr/bin/env python3
# pylint: disable=too-many-instance-attributes
# pylint: disable=invalid-name

# Copyright (c) 2020 Kirill Snezhko

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Main module"""

import argparse
import getpass
import json
import random
import shutil
import urllib
import uuid

import requests
from rich import box
from rich.console import Console
from rich.table import Table

# URLS and PAYLOADS (based on reverse-engineered API)
URLS = {
    "login_xiaomi": "https://account.xiaomi.com/oauth2/authorize?skip_confirm=false&redirect_uri=https%3A%2F%2Fhm.xiaomi.com%2Fwatch.do&response_type=code&client_id=2882303761517483916&pt=0&scope=1%206000%2010000%20phone%20email%20profile%20openid%20miui_deskboot%20mirefreshtoken&accessType=web&_locale=ru_RU",
    "tokens_amazfit": "https://account.huami.com/v2/account/login_with_email?user_email={user_email}&grant_type=password_credential&app_name=com.huami.midong&app_version=4.6.6&country_code=RU&device_id=02:00:00:00:00:00&third_name=huami_phone&device_model=android_phone&allow_registration=false",
    "login_amazfit": "https://api-mifit-ru.huami.com/users/band/social_profile.json?access_token={access_token}&appid=0&callid=0&country_code={country_code}&device_id={device_id}&device_type=0&lang=ru_RU&timezone=UTC%2B03:00&user_id=0&miid=0&third_name={third_name}&code={code}&grant_type={grant_type}",
    "devices": "https://api-mifit-ru.huami.com/v1/users/{user_id}/devices.json",
    "fw_updates": "https://api-mifit.huami.com/firmware/update/check.json",
    "agps": "https://api-mifit.huami.com/agps/{pack_name}.json",
    "logout": "https://account.huami.com/v1/account/logout.json"
}

PAYLOADS = {
    "tokens_amazfit": {
        "app_name": "com.huami.midong",
        "app_version": "4.6.6",
        "country_code": "RU",
        "device_id": "02:00:00:00:00:00",
        "third_name": "huami_phone",
        "device_model": "android_phone",
        "allow_registration": "false"
    },
    "login_amazfit": {
        "dn": "account.huami.com,api-user.huami.com,api-watch.huami.com,api-analytics.huami.com,app-analytics.huami.com,api-mifit.huami.com",
        "app_version": "4.6.6",
        "source": "com.huami.watch.hmwatchmanager",
        "country_code": "",
        "device_id": "",
        "third_name": "",
        "app_name": "com.huami.midong",
        "code": "",
        "grant_type": "",
        "device_model": "android_phone"
    },
    "devices": {
        "apptoken": ""
    },
    "fw_updates": {
        "app_version": "4.6.6",
        "appid": "0",
        "callid": "0",
        "channel": "",
        "country": "RU",
        "cv": "",
        "device_source": "",
        "firmware_version": "",
        "hardware_version": "",
        "lang": "ru_RU",
        "production_source": "",
        "support_8_bytes": "true",
        "user_id": "0",
        "v": "4.6.6"
    },
    "agps": {
        "apptoken": ""
    },
    "logout": {
        "login_token": ""
    }
}

# Errors mapping (partial)
ERRORS = {
    "auth_fail": "Authentication failed",
    "invalid_argument": "Invalid argument"
}

class HuamiAmazfit:
    """Class for logging in and receiving auth keys"""
    def __init__(self, method="amazfit", email=None, password=None):

        if method == 'amazfit' and (not email or not password):
            raise ValueError("For Amazfit method E-Mail and Password can not be null.")
        self.method = method
        self.email = email
        self.password = password
        self.access_token = None
        self.country_code = None

        self.app_token = None
        self.login_token = None
        self.user_id = None

        self.r = str(uuid.uuid4())

        # IMEI or something unique
        self.device_id = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                      random.randint(0, 255),
                                                      random.randint(0, 255))

    def get_access_token(self) -> str:
        """Get access token for log in"""
        print(f"Getting access token with {self.method} login method...")

        if self.method == 'xiaomi':
            login_url = URLS["login_xiaomi"]

            print(f"Copy this URL to web-browser \n\n{login_url}\n\nand login to your Mi account.")

            token_url = input("\nPaste URL after redirection here.\n")

            parsed_token_url = urllib.parse.urlparse(token_url)
            token_url_parameters = urllib.parse.parse_qs(parsed_token_url.query)

            if 'code' not in token_url_parameters:
                raise ValueError("No 'code' parameter in login url.")

            self.access_token = token_url_parameters['code'][0]
            self.country_code = 'US'

        elif self.method == 'amazfit':

            auth_url = URLS['tokens_amazfit'].format(user_email=urllib.parse.quote(self.email))

            data = PAYLOADS['tokens_amazfit'].copy()
            data['password'] = self.password

            response = requests.post(auth_url, data=data, allow_redirects=False)
            response.raise_for_status()

            # 'Location' parameter contains url with login status
            redirect_url = urllib.parse.urlparse(response.headers.get('Location'))
            redirect_url_parameters = urllib.parse.parse_qs(redirect_url.query)

            if 'error' in redirect_url_parameters:
                raise ValueError(f"Wrong E-mail or Password." \
                                 f"Error: {redirect_url_parameters['error'][0]}")

            if 'access' not in redirect_url_parameters:
                raise ValueError("No 'access' parameter in login url.")

            if 'country_code' not in redirect_url_parameters:
                # Sometimes for no reason server does not return country_code
                # In this case we extract country_code from region, because it looks
                # like this: 'eu-central-1'
                region = redirect_url_parameters['region'][0]
                self.country_code = region[0:2].upper()

            else:
                self.country_code = redirect_url_parameters['country_code'][0]

            self.access_token = redirect_url_parameters['access'][0]

        print("Token: {}".format(self.access_token))
        return self.access_token

    def login(self, external_token=None) -> None:
        """Perform login and get app and login tokens"""
        print("Logging in...")
        if external_token:
            self.access_token = external_token

        login_url = URLS['login_amazfit']

        data = PAYLOADS['login_amazfit'].copy()
        data['country_code'] = self.country_code
        data['device_id'] = self.device_id
        data['third_name'] = 'huami' if self.method == 'amazfit' else 'mi-watch'
        data['code'] = self.access_token
        data['grant_type'] = 'access_token' if self.method == 'amazfit' else 'request_token'

        response = requests.post(login_url, data=data, allow_redirects=False)
        response.raise_for_status()
        login_result = response.json()

        if 'error_code' in login_result:
            error_code = login_result['error_code']
            error_message = ERRORS.get(error_code, error_code)
            raise ValueError(f"Login error. Error: {error_message}")

        if 'token_info' not in login_result:
            raise ValueError("No 'token_info' parameter in login data.")
        token_info = login_result['token_info']
        if 'app_token' not in token_info:
            raise ValueError("No 'app_token' parameter in login data.")
        self.app_token = token_info['app_token']

        if 'login_token' not in token_info:
            raise ValueError("No 'login_token' parameter in login data.")
        self.login_token = token_info['login_token']

        if 'user_id' not in token_info:
            raise ValueError("No 'user_id' parameter in login data.")
        self.user_id = token_info['user_id']
        print("Logged in! User id: {}".format(self.user_id))

    def get_wearables(self) -> list:
        """Request a list of linked devices"""
        print("Getting linked wearables...")

        devices_url = URLS['devices'].format(user_id=urllib.parse.quote(self.user_id))

        headers = PAYLOADS['devices'].copy()
        headers['apptoken'] = self.app_token
        params = {'enableMultiDevice': 'true'}

        response = requests.get(devices_url, params=params, headers=headers)
        response.raise_for_status()
        device_request = response.json()
        if 'items' not in device_request:
            raise ValueError("No 'items' parameter in devices data.")
        devices = device_request['items']

        wearables = []

        for wearable in devices:
            if 'macAddress' not in wearable:
                raise ValueError("No 'macAddress' parameter in device data.")
            mac_address = wearable['macAddress']

            if 'additionalInfo' not in wearable:
                raise ValueError("No 'additionalInfo' parameter in device data.")
            device_info = json.loads(wearable['additionalInfo'])

            key_str = device_info.get('auth_key', '')
            auth_key = '0x' + (key_str if key_str != '' else '00')

            wearables.append(
                {
                    'active_status': str(wearable.get('activeStatus', '-1')),
                    'mac_address': mac_address,
                    'auth_key': auth_key,
                    'device_source': str(wearable.get('deviceSource', 0)),
                    'firmware_version': wearable.get('firmwareVersion', 'v-1'),
                    'hardware_version': device_info.get('hardwareVersion', 'v-1'),
                    'production_source': device_info.get('productVersion', '0')
                }
            )

        return wearables

    @staticmethod
    def get_firmware(wearable: dict) -> None:
        """Check and download updates for the firmware and fonts"""
        fw_url = URLS["fw_updates"]
        params = PAYLOADS["fw_updates"].copy()
        params['device_source'] = wearable['device_source']
        params['firmware_version'] = wearable['firmware_version']
        params['hardware_version'] = wearable['hardware_version']
        params['production_source'] = wearable['production_source']
        headers = {
            'appplatform': 'android_phone',
            'appname': 'com.huami.midong',
            'lang': 'en_US'
        }
        response = requests.get(fw_url, params=params, headers=headers)
        response.raise_for_status()
        fw_response = response.json()
        links = []
        hashes = []

        if 'firmwareUrl' in fw_response:
            links.append(fw_response['firmwareUrl'])
            hashes.append(fw_response['firmwareMd5'])
        if 'fontUrl' in fw_response:
            links.append(fw_response['fontUrl'])
            hashes.append(fw_response['fontMd5'])

        if not links:
            print("No updates found!")
        else:
            for link, hash_sum in zip(links, hashes):
                file_name = link.split('/')[-1]
                print(f"Downloading {file_name} with MD5-hash {hash_sum}...")
                with requests.get(link, stream=True) as r:
                    with open(file_name, 'wb') as f:
                        shutil.copyfileobj(r.raw, f)

    def logout(self) -> None:
        """Log out from the current account"""
        logout_url = URLS['logout']

        data = PAYLOADS['logout'].copy()
        data['login_token'] = self.login_token

        response = requests.post(logout_url, data=data)
        logout_result = response.json()

        if logout_result['result'] == 'ok':
            print("\nLogged out.")
        else:
            print("\nError logging out.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Obtain Bluetooth Auth key from Amazfit "
                                                 "servers for specific MAC address.")
    parser.add_argument("-m",
                        "--method",
                        choices=["amazfit", "xiaomi"],
                        default="amazfit",
                        required=True,
                        help="Login method ")
    parser.add_argument("-e",
                        "--email",
                        required=False,
                        help="Account e-mail address")

    parser.add_argument("-p",
                        "--password",
                        required=False,
                        help="Account Password")

    parser.add_argument("--mac",
                        required=True,
                        help="MAC address of the Mi Band (e.g., C8:0F:10:XX:XX:XX)")

    args = parser.parse_args()

    console = Console()
    table = Table(show_header=True, header_style="bold", box=box.ASCII)
    table.add_column("MAC", style="dim", width=17, justify='center')
    table.add_column("AUTH_KEY", width=45, justify='center')

    if args.password is None and args.method == "amazfit":
        args.password = getpass.getpass()

    device = HuamiAmazfit(method=args.method,
                          email=args.email,
                          password=args.password)
    device.get_access_token()
    device.login()

    wearables = device.get_wearables()
    found = False
    for wearable in wearables:
        if wearable['mac_address'].lower() == args.mac.lower():
            table.add_row(wearable['mac_address'], wearable['auth_key'])
            console.print(table)
            found = True
            break

    if not found:
        print(f"No device found with MAC {args.mac}. Make sure it's paired with your Xiaomi account.")

    device.logout()
