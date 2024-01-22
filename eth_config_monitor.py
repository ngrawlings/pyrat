import subprocess
import time
import subprocess
import time

def check_eth1_ip():
    result = subprocess.run(['ip', 'addr', 'show', 'dev', 'eth1'], capture_output=True, text=True)
    output = result.stdout

    # Parse the output to get the current IP address
    ip_address = None
    for line in output.split('\n'):
        if 'inet ' in line:
            ip_address = line.split('inet ')[1].split('/')[0]
            break

    return ip_address

def set_eth1_ip(ip_address):
    subprocess.run(['ip', 'addr', 'add', f'{ip_address}/24', 'dev', 'eth1'])

def check_wlan0_connection():
    result = subprocess.run(['iwconfig', 'wlan0'], capture_output=True, text=True)
    output = result.stdout

    # Parse the output to check the connection status
    if 'Not-Associated' in output:
        return False
    else:
        return True
    
def configure_wifi():
    subprocess.run(['iwlist', 'scan', 'wlan0'])
    time.sleep(10)
    subprocess.run(['kill', 'wpa_supplicant'])
    subprocess.run(['wpa_supplicant', '-B', '-i', 'wlan0', '-c', '/etc/wpa_supplicant/wpa_supplicant.conf'])

while True:
    current_ip = check_eth1_ip()
    if current_ip is None or current_ip != '10.0.1.1':
        set_eth1_ip('10.0.1.1')

    if not check_wlan0_connection():
        configure_wifi()

    time.sleep(60)  # Pause for 60 seconds (1 minute)
