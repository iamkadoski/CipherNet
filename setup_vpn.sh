#!/bin/bash

# Ensure the script is executed with root privileges
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root"
  exit 1
fi

# Check if the required arguments are provided
if [ $# -lt 3 ]; then
  echo "Usage: $0 <APP_NAME> <SERVER|CLIENT> <AES_KEY> [SERVER_IP]"
  exit 1
fi

APP_NAME=$1
MODE=$2
AES_KEY=$3

if [ "$MODE" == "SERVER" ]; then
  # Start the VPN server
  ./$APP_NAME SERVER $AES_KEY &
  SERVER_PID=$!
  echo "VPN server started with PID: $SERVER_PID"

elif [ "$MODE" == "CLIENT" ]; then
  if [ $# -ne 4 ]; then
    echo "Usage: $0 <APP_NAME> CLIENT <AES_KEY> <SERVER_IP>"
    exit 1
  fi
  SERVER_IP=$4
  # Start the VPN client
  ./$APP_NAME CLIENT $AES_KEY $SERVER_IP &
  CLIENT_PID=$!
  echo "VPN client started with PID: $CLIENT_PID"

else
  echo "Invalid mode. Use 'SERVER' or 'CLIENT'."
  exit 1
fi

# Wait for the server/client to finish
wait
