import subprocess
import time

def add_iptables_rule():
    subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])

def remove_iptables_rule():
    subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])

if __name__ == "__main__":
    add_iptables_rule()
    print("Added iptables rule to allow port 22")

    time.sleep(600)  # Wait for 10 minutes

    remove_iptables_rule()
    print("Removed iptables rule to disallow port 22")
