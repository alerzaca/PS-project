# PS-project
Final project for network programming course.

## How to compile:
To compile server and client programs you must enter the corresponding directory (server/ or client/) and and use the "make" command.
Server is using sqlite3 database library, so it is required to have it installed. On the client side, the ssl library is used, which must also be installed beforehand. 

For ubuntu:
```
sudo apt install libsqlite3-dev libssl-dev
```

## How to run:
1. Server requires to provide your own room name and network interface (np. `eth0`, `wlan0`). Creating a server means essentially creating a database file (and a shared folder) for the new server.
```
./server create <name>
./server start <name> <interface>
```
2. Client requires to provide room ID, IP address, and port. Those can be obtained by running program with a "search" argument in order to scan network for available servers.
```
./client search
./client connect <login|register> <ID> <IP> <PORT>
./client upload <ID> <IP> <PORT> <filename to upload>
./client download <ID> <IP> <PORT> <filename to download>
```
