import netmiko
from netmiko import ConnectHandler
import re
from collections import defaultdict
import requests

NETBOX_URL = ""
NETBOX_TOKEN = ""

headers = {
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

device1 = {
    "device_type": "fortinet",
    "host": "host_ip",
    "username": "",
    "password": "",
    "port": 22, 
}


    # Establish SSH connection
net_connect = ConnectHandler(**device1)

    # Send a command
output = net_connect.send_command("execute dhcp lease-list")
#print(output)


networks = defaultdict(list)

# Split by lines and process
lines = output.strip().splitlines()
current_network = None
line_re = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+'
    r'(?P<rest>.+)$', re.IGNORECASE)

for line in lines:
    line = line.strip()
    if not line:
        continue
    elif re.match(r'^\S+$', line):
        current_network = line
    elif line.startswith("IP"):
        continue
    elif current_network:
        m = line_re.match(line)
        if not m:
            continue  # skip lines that don't match
        ip = m.group('ip')
        mac = m.group('mac')
        rest = m.group('rest').strip()

        # Remove trailing VCI and expiry from rest to isolate hostname
        # Known VCI pattern example: 'udhcp 1.34.1' or 'MSFT 5.0' or 'android-dhcp-15' (some text before expiry)
        # Expiry is usually a date at the end: 'Fri Jun  6 01:00:30 2025'

        # Try to strip expiry date (format: Day Mon dd hh:mm:ss yyyy)
        expiry_re = re.compile(
            r'(.*?)(?:\s+(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})$'
        )
        m_exp = expiry_re.match(rest)
        if m_exp:
            rest = m_exp.group(1).strip()

        # Now remove common VCI patterns at end of rest, e.g. 'udhcp 1.34.1', 'MSFT 5.0', 'android-dhcp-15'
        vci_patterns = [
            r'udhcp \d+(\.\d+)*', 
            r'MSFT \d+\.\d+',
            r'android-dhcp-\d+',
            r'FortiWiFi-\S+',
            r'FortiAP-\S+',
            # add more if you spot other common VCI formats
        ]
        for pat in vci_patterns:
            vci_re = re.compile(r'(.*)\s+' + pat + r'$')
            m_vci = vci_re.match(rest)
            if m_vci:
                rest = m_vci.group(1).strip()
                break

        hostname = rest

        networks[current_network].append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname
        })


# for device in networks['lan']:
#     print(f"Hostname: {device['hostname']}, IP: {device['ip']}")

def get_or_create_device(name):
    url = f"{NETBOX_URL}dcim/devices/?name={name}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    results = response.json()["results"]

    if results:
        return results[0]

    payload = {
        "name": name,
        "device_type": 1,
        "device_role": 1,
        "site": 1
    }
    response = requests.post(f"{NETBOX_URL}dcim/devices/", headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def get_or_create_interface(device_id, iface_name="eth0"):
    url = f"{NETBOX_URL}dcim/interfaces/?device_id={device_id}&name={iface_name}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    results = response.json()["results"]

    if results:
        return results[0]

    payload = {
        "device": device_id,
        "name": iface_name,
        "type": "1000base-t"
    }
    response = requests.post(f"{NETBOX_URL}dcim/interfaces/", headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def create_or_update_ip(ip_addr, interface_id):
    url = f"{NETBOX_URL}ipam/ip-addresses/?address={ip_addr}/32"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    results = response.json()["results"]

    if results:
        ip = results[0]

        assigned_id = ip.get("assigned_object_id")
        assigned_type = ip.get("assigned_object_type")

        # Re-assign if not linked or linked incorrectly
        if assigned_type != "dcim.interface" or assigned_id != interface_id:
            update_payload = {
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": interface_id
            }
            ip_id = ip["id"]
            update_url = f"{NETBOX_URL}ipam/ip-addresses/{ip_id}/"
            r = requests.patch(update_url, headers=headers, json=update_payload)
            r.raise_for_status()
            return r.json()

        return ip

    # Create if doesn't exist
    payload = {
        "address": f"{ip_addr}/32",
        "status": "active",
        "assigned_object_type": "dcim.interface",
        "assigned_object_id": interface_id
    }
    response = requests.post(f"{NETBOX_URL}ipam/ip-addresses/", headers=headers, json=payload)
    response.raise_for_status()
    return response.json()


def set_primary_ip(device_id, ip_id):
    url = f"{NETBOX_URL}dcim/devices/{device_id}/"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    device = response.json()

    if device.get("primary_ip4") and device["primary_ip4"]["id"] == ip_id:
        return  # Already set, no update needed

    payload = {
        "primary_ip4": ip_id
    }
    response = requests.patch(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

for device in networks['lan']:
    hostname = device["hostname"]
    ip_addr = device["ip"]

    dev = get_or_create_device(hostname)
    iface = get_or_create_interface(dev["id"])
    ip = create_or_update_ip(ip_addr, iface["id"])
    set_primary_ip(dev["id"], ip["id"])

    print(f"✅ Device {hostname} with IP {ip['address']} verified and set.")

for device in networks['IOT']:
    hostname = device["hostname"]
    ip_addr = device["ip"]

    dev = get_or_create_device(hostname)
    iface = get_or_create_interface(dev["id"])
    ip = create_or_update_ip(ip_addr, iface["id"])
    set_primary_ip(dev["id"], ip["id"])

    print(f"✅ Device {hostname} with IP {ip['address']} verified and set.")
