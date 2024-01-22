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

while True:
    current_ip = check_eth1_ip()
    if current_ip is None or current_ip != '192.168.1.100':
        set_eth1_ip('192.168.1.100')
        
    time.sleep(60)  # Pause for 60 seconds (1 minute)
