# Overview

This Python-based Wireless Network Penetration Testing Suite is a comprehensive tool designed for security professionals and enthusiasts. It leverages Scapy for capturing Wi-Fi handshakes, scanning access points, performing dictionary attacks, deauthentication attacks, and capturing wireless traffic. The tool also integrates Hashcat for dictionary attacks.

# Features

Capture Wi-Fi Handshakes: Capture WPA/WPA2 handshakes for offline cracking. Dictionary Attack: Perform dictionary attacks on captured handshakes using Hashcat. Scan for Access Points: Detect nearby wireless access points and their details. Deauthentication Attack: Disrupt client connections with deauthentication packets. Capture Wireless Traffic: Monitor and capture wireless network traffic.

# Requirements
Python 3.x

Scapy

Hashcat (for dictionary attacks)

Root privileges (Linux) or Administrator privileges (Windows)

# Installation
Clone the repository:

```
git clone https://github.com/FrogMechRider/Wireless-Network-Security-Assessment-Tool.git

cd Wireless-Network-Security-Assessment-Tool
```

# Install required Python packages:
```
pip install scapy
```
Install Hashcat (for dictionary attacks) following the [Hashcat installation guide.](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#installation)

# Usage
Run the script with root/admin privileges:

```
sudo python Wireless-Network-penetration.py
```
Follow the on-screen menu to select options:

* Capture Wi-Fi Handshake

* Perform Dictionary Attack

* Scan for Access Points

* Perform Deauthentication Attack

* Capture Wireless Traffic


# Example

To capture a Wi-Fi handshake, choose option 1 from the menu and provide the required interface, SSID, and BSSID. For a dictionary attack, choose option 2 and specify the handshake file and mask.

# Notes

Ensure your wireless adapter supports monitor mode and packet injection.

The script is intended for educational purposes and ethical testing only. Use responsibly and only on networks you own or have explicit permission to test.
Contributing

Feel free to open issues or submit pull requests. Contributions are welcome!

# License
This project is licensed under the MIT License - see the LICENSE file for details.

# Contact
For any questions or suggestions, please contact me at JasonL41902@gmail.com.
