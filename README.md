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
   git clone <repository-url>
   cd CipherNet
   gcc -o vpn vpn.c -lcrypto -lssl -pthread 
    
2.  **Verify the Files**:Ensure the following files are in the CipherNet directory:
	
    *   setup\_vpn.sh
        
    *   teardown\_vpn.sh
        
    *   vpn.c
        
    *   vpn (If the vpn file is missing, compile vpn.c to generate it.)
        

Usage
-----

### Starting the VPN


  ``` bash
   sudo ./setup\_vpn.sh SERVER <IPAddress> Replace with the IP address where you want the server to bind.
    
   sudo ./setup\_vpn.sh CLIENT <IPAddress> Replace with the IP address of the VPN server.
   ```

### Stopping the VPN

Use the following command to stop the VPN server and client, and clean up:


sudo ./teardown_vpn.sh  



Example Commands
----------------


*   sudo ./setup\_vpn.sh SERVER 192.168.1.1
    
*   sudo ./setup\_vpn.sh CLIENT 192.168.1.1
    
*   sudo ./teardown\_vpn.sh
    


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

License
-------

This project is licensed under the MIT License.
