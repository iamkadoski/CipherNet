#!/bin/bash

# Ensure the script is executed with root privileges
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 
  exit 1
fi

# Kill the VPN processes
killall vpn_demo

# Cleanup iptables (you might want to adjust this based on your setup)
iptables -t nat -D POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE
iptables -D FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -D FORWARD -d 10.8.0.0/16 -j ACCEPT

echo "VPN server and client teardown complete."

