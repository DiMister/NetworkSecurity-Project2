# NetworkSecurity-Project2

This project implements a Diffie-Hellman key exchange demonstration with client-server communication.

## Components

- **FastModExp**: Fast modular exponentiation class for cryptographic operations
- **DiffeHellman**: Diffie-Hellman key exchange implementation
- **Client/Server**: Network communication demonstrating the key exchange protocol
- **SDES**: Simplified Data Encryption Standard implementation

## Building and Running

### Prerequisites
- GCC/g++ compiler with C++17 support
- Linux/Unix environment (POSIX sockets required)
- For Windows: Use WSL, MinGW/MSYS2, or similar POSIX-compatible environment

### Compilation

#### Compile Client and Server:
```bash
g++ -std=c++17 -O2 -Wall client.cpp server.cpp DiffeHellman.cpp FastModExp.cpp net_utils.cpp -o dh_demo
```

#### Or compile separately:
```bash
# Compile server
g++ -std=c++17 -O2 -Wall server.cpp DiffeHellman.cpp FastModExp.cpp net_utils.cpp -o server

# Compile client  
g++ -std=c++17 -O2 -Wall client.cpp DiffeHellman.cpp FastModExp.cpp net_utils.cpp -o client
```

### Running the Diffie-Hellman Demo

#### Option 1: Start server and client in separate terminals

**Terminal 1 - Start the server:**
```bash
./server [port]
# Example: ./server 8421
# Default port is 8421 if not specified
```

**Terminal 2 - Run the client:**
```bash
./client [server_ip] [port]
# Example: ./client 127.0.0.1 8421
# Default: connects to localhost:8421
```

#### Option 2: Quick test with background server
```bash
# Start server in background
./server &

# Run client
./client

# Stop background server
pkill server
```

### Expected Output

**Server output:**
```
Server listening on port 8421 (accepting 1 client)
Accepted connection from 127.0.0.1:xxxxx
Server: shared secret verified
```

**Client output:**
```
Connected to 127.0.0.1:8421
Client: computed shared secret = [number]
Client: server acknowledged shared secret
```

### Protocol Overview

The client and server perform this handshake:
1. Client → `PARAM p g` (send DH parameters)
2. Server → `ACK` (acknowledge parameters)  
3. Client → `PUB A` (send client public key)
4. Server → `PUB B` (send server public key)
5. Client → `SHARED s` (send computed shared secret for verification)
6. Server → `OK` or `ERR` (verify shared secret matches)

### Legacy SDES Demo

#### Linux/Unix with GCC:
##### Alice
```bash
g++ -o alice client.cpp DiffeHellman.cpp net_utils.cpp SDESModes.cpp SDES.cpp FastModExp.cpp
./alice
```
##### Bob
```bash
g++ -o bob server.cpp DiffeHellman.cpp net_utils.cpp SDESModes.cpp SDES.cpp FastModExp.cpp
./bob
```

   

