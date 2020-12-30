from asyncio.windows_events import NULL
import platform
import yaml
import os
import time

import subprocess
import pyshark
import requests

from pprint import pprint
# import numpy as np

print('\n')

# Show the OS properties and the initial config of the app
print("The current OS is " + platform.system())
print('\n')

print("The current config is :")

with open('Config.yml', 'r') as file:
    full_config = yaml.full_load(file)

for item, doc in full_config.items():
    print(' ' + item, ':', doc)

if not full_config['reports_path']:
    full_config['reports_path'] = input("Please set the path the reports should be stored! ")

print('\n')

# Save the config back into the file
with open('Config.yml', 'w') as file:
    dump_config = yaml.dump(full_config, file)

# Show all the network interfaces
network_interfaces = subprocess.Popen(['tshark', '-D'], stdout=subprocess.PIPE, universal_newlines=True)

for output in network_interfaces.stdout.readlines():
    print(output.strip())

print('\n')

# Constructing the traffic filter
traffic_filter = '(dns.response_to)'

for iter_domain in full_config['domains_excluded']:
    traffic_filter += ' and (not dns.resp.name contains ' + iter_domain + ')'

for iter_host in full_config['hosts_excluded']:
    traffic_filter += ' and (not dns.resp.name eq ' + iter_host + ')'

print("The traffic filter constructed is \n" + traffic_filter)
print('\n')

# Start capturing the traffic and get new hosts to test
capture = NULL
current_results = []

def dns_info(packet):
    if packet.dns.qry_name:
        print(packet.dns.qry_name)
    elif packet.dns.resp_name:
        print(packet.dns.resp_name)

    current_results.append(packet.dns.resp_name)

try:
    while True:
        try:
            capture = pyshark.LiveCapture('6', display_filter = traffic_filter)

            capture.sniff(packet_count=100)

            capture.apply_on_packets(dns_info, timeout=20)
            # Generates an error after the timeout passes

            print("\nPas1\n")

            # capture.close()
            # time.sleep(300)
            time.sleep(10)

            print("\nPas2\n")

            print(current_results)

            print("\nPas3\n")

            for current_result in current_results:
                if os.path.isdir(full_config['reports_path'] + current_result):
                    print("Check the site " + current_result)

                    r = requests.get('http://' + current_result)
                    if (r.status_code == 200):
                        print('## Aici trebuie call de Wapiti cu slash la final')
                        print('# wapiti -u URL_packet.dns.qry_name -v 2 -o "path" >> log')
                    else:
                        print("Site can't be accessed!")

                else:
                    print("Site has been scanned before!")

            print("\nPas4\n")

            time.sleep(10)

        except Exception as e:
            print("\nPas eroare\n")
            print('\n')

            print(str(e))

            print('\n')

            print(current_results)

            print("\nPas5\n")


            capture.close()
            continue
except:
    print("Hopa Penelopa")
