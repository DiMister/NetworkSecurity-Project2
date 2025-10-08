# NetworkSecurity-Project2

This project implements a Diffie-Hellman key exchange demonstration with client-server communication.
### Compilation wsl
```bash
# Compile server
g++ -o server server.cpp DiffeHellman.cpp net_utils.cpp SDESModes.cpp SDES.cpp FastModExp.cpp

# Compile client  
g++ -o client client.cpp DiffeHellman.cpp net_utils.cpp SDESModes.cpp SDES.cpp FastModExp.cpp
```
### Compilation Mac
```bash
# Compile server
clang++ -std=c++17 server.cpp DiffeHellman.cpp net_utils.cpp SDESModes.cpp SDES.cpp FastModExp.cpp -o server

# Compile client  
clang++ -std=c++17 client.cpp DiffeHellman.cpp net_utils.cpp SDESModes.cpp SDES.cpp FastModExp.cpp -o client
```


### Running the Diffie-Hellman Demo
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

   

