# PS-project
Final project for network programming course.

How to compile:
```
gcc server.c -o server -lpthread -lsqlite3
gcc client.c -o client
```

How to run:
1. Server requires to provide your own room name and network interface (np. `eth0`, `wlan0`). Creating a server means essentially creating a database file (and shared folder) for the new server that will be used in the future to contain chat history and user credentials.
```
./server create <name>
./server start <name> <interface>
```
2. Client requires to provide room ID, IP address and port. Those can be obtained by running program with a "search" argument in order to scan network for available servers.
```
./client search
./client connect <login|register> <ID> <IP> <PORT>
./client upload <ID> <IP> <PORT> <filename to upload>
./client download <ID> <IP> <PORT> <filename to download>
```
