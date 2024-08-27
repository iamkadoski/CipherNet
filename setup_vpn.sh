#!/bin/bash

# Ensure the script is executed with root privileges
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root"
  exit 1
fi

# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <SERVER|CLIENT> <IP_ADDRESS>"
  exit 1
fi

MODE="$1"
IP_ADDRESS="$2"

# Validate MODE argument
if [ "$MODE" != "SERVER" ] && [ "$MODE" != "CLIENT" ]; then
  echo "First argument must be either 'SERVER' or 'CLIENT'"
  exit 1
fi

# Run the vpn_demo with the appropriate arguments
if [ "$MODE" == "SERVER" ]; then
  ./vpn_demo SERVER &
  SERVER_PID=$!
  echo "VPN server started with PID: $SERVER_PID"
  
  # Wait for the server to start
  sleep 5

elif [ "$MODE" == "CLIENT" ]; then
  ./vpn_demo CLIENT "$IP_ADDRESS" &
  CLIENT_PID=$!
  echo "VPN client started with PID: $CLIENT_PID"
fi

# Keep the script running to monitor the processes
wait $SERVER_PID
wait $CLIENT_PID

