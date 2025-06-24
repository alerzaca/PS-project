#ifndef NETWORK_H
#define NETWORK_H

#define MAX_SERVERS 10
#define BUFFER_SIZE 1024
#define MULTICAST_GROUP "239.0.0.1"
#define MULTICAST_PORT 12345

struct server_info {
    char id[64];
    char name[128];
    char ip[INET_ADDRSTRLEN];
    int port;
};

void add_server(const char *id, const char *name, const char *ip, int port);
void search_servers();
void connect_to_server(const char *mode, const char *server_id, const char *ip, int port);
int receive_welcome_and_history(int sock);
void chat_loop(int sock, const char *username);

#endif
