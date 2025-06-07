# PS-project
Final project for network programming course.

How to compile:
```
gcc server.c -o server -lpthread
gcc client.c -o client
```

How to run:
1. Server requires to provide your own room name and network interface (np. `eth0`, `wlan0`).
```
./server <NAME> <INTERFACE>
```
2. Client requires to provide room ID, IP address and port. Those can be obtained by running program with a "search" argument in order to scan network for available servers.
```
./client search
./client connect <ID> <IPv4> <PORT>
```