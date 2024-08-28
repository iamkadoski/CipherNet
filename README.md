# CipherNet - Your Secure Gateway to Private Networks

## Overview

**CipherNet** (A fork of Simple VPN) is a robust and lightweight VPN implementation designed to secure communications between multiple clients and a server. Leveraging a custom VPN interface (`tun0`), CipherNet encrypts data using the AES-256-CFB algorithm, ensuring that your network communications remain confidential and protected from prying eyes.

## Project Structure

- **`setup_vpn.sh`**: A shell script to start the VPN server or client.
- **`teardown_vpn.sh`**: A shell script to stop the VPN server and client, and clean up any configurations.
- **`vpn.c`**: The main C source code file that implements the VPN functionality.
- **`vpndemo`**: The compiled executable from `vpn.c`.

## Features

- **Multi-Client Support**: Allows multiple clients to connect securely to a single server.
- **Strong Encryption**: Uses AES-256-CFB to safeguard your data.
- **Flexible Configuration**: Server and client IP addresses can be configured dynamically at runtime.
- **Easy Setup and Teardown**: Includes scripts to automate the setup and teardown process.

## Prerequisites

- **Operating System**: Linux (with TUN/TAP support)
- **Compiler**: GCC
- **Dependencies**: OpenSSL library (for encryption)

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/iamkadoski/CipherNet.git
   cd CipherNet
   gcc -o <APP_NAME> ciphervpn.c -lcrypto -lssl -pthread 
    
2.  **Verify the Files**:Ensure the following files are in the CipherNet directory:
	
    *   setup_vpn.sh
        
    *   teardown_vpn.sh
        
    *   ciphervpn.c
        
          

Usage
-----

### Starting the VPN


  ``` bash
   sudo ./setup_vpn.sh <APP_NAME> <SERVER|CLIENT> <AES_KEY> <SERVER_IP> 
    
   sudo ./setup_vpn.sh <APP_NAME> CLIENT <AES_KEY> <SERVER_IP> 
   ```

### Stopping the VPN

Use the following command to stop the VPN server and client, and clean up:
```bash
sudo ./teardown_vpn.sh  
```

Example Commands
----------------
```bash
sudo ./setup_vpn.sh ciper SERVER mysecurekey1234567890 192.168.1.1    
sudo ./setup_vpn.sh cipher CLIENT mysecurekey1234567890 192.168.1.1    
sudo ./teardown_vpn.sh
```   


Security Considerations
-----------------------

*   **Encryption**: CipherNet uses AES-256-CFB encryption, which is highly secure. Ensure that the AES key and initialization vector (IV) are managed securely and are not exposed to unauthorized parties.
    
*   **OpenSSL Version**: CipherNet relies on OpenSSL for encryption. Regularly update OpenSSL to mitigate any vulnerabilities.
    

Troubleshooting
---------------

*   **Compilation Errors**: Ensure that the OpenSSL library is installed. If you encounter deprecation warnings with OpenSSL 3.0+, refer to the updated aes\_encrypt\_decrypt function in the vpn.c file.
    
*   **Connection Issues**: Verify that the server IP is correctly configured and that there are no firewall rules blocking the connection.
    

Contributing
------------

If you find bugs or have suggestions for improvements, feel free to submit issues or pull requests on the project repository.


