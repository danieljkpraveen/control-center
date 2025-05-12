"""
This code accepts user input and establishes a connection
to the firewall
"""

import ipaddress
from panos.firewall import Firewall


def get_valid_ip_and_api_key():
    while True:
        ip = input("\nEnter firewall IP: ")
        try:
            hostname = ipaddress.ip_address(ip)
            
            api_key = input("Enter API Key: ")
            if api_key.strip():
                return hostname, api_key
            else:
                print("\n⚠️ API key cannot be empty")
        except ValueError:
            print("\n⚠️ Invalid IP format")


def connect_to_firewall():
    hostname, api_key = get_valid_ip_and_api_key()
    print(f"\n✔️  Valid IP format - {hostname}")
    print(f"✔️  API key is not empty - {api_key}")
    print("\n⌛ Establishing connection to firewall\n")
    fw = Firewall(hostname, api_key)
    if fw:
        print(f"✔️  Connected successfully\nFirewall serial: {fw.serial}")
        return fw
        # return True
    else:
        print("Failed to connect to firewall")
