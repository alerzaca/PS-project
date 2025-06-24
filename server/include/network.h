#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>

#define BACKLOG 3                   // Maksymalna liczba oczekujących połączeń
#define MAX_CLIENTS 10              // Maksymalna liczba jednocześnie połączonych klientów
#define BUFFER_SIZE 1024            // Rozmiar bufora do odbierania wiadomości

#define MULTICAST_GROUP "239.0.0.1" // Adres grupy multicast, na której serwer będzie się ogłaszał
#define MULTICAST_PORT 12345        // Port UDP multicast, na którym serwer będzie się ogłaszał
#define TCP_PORT 8080               // Port TCP, na którym serwer będzie obsługiwał chat
#define SERVER_ID_LEN 7             // 6 znaków heksadecymalnych + '\0'

// Struktura argumentów dla wątku multicast
struct thread_args {
    char server_name[128];
    char server_id[SERVER_ID_LEN];
    char ip[INET_ADDRSTRLEN];
    int tcp_port;
};

// Funkcja multicastow
void* multicast_broadcast(void *arg);

// Serwer TCP: główne funkcje
void run_tcp_server(const char *dbfile, const char *server_name, char *server_id, int tcp_port);
void server_main_loop(int server_fd, const char *dbfile, const char *server_name);

// Obsługa klienta
void handle_client(
    int i,
    int sd,
    const char *dbfile,
    const char *server_name,
    int *client_sockets,
    struct sockaddr_in *client_addresses,
    char *buffer,
    int valread
);

// Obsługa plików
int handle_upload(int sd, const char *server_name, char *buffer);
int handle_download(int sd, const char *server_name, char *buffer);

#endif
