#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/sha.h>

#include "network.h"
#include "credentials.h"

struct server_info servers[MAX_SERVERS];
int server_count = 0;

// Dodanie serwera do listy unikalnych serwerów
void add_server(const char *id, const char *name, const char *ip, int port) {
    for (int i = 0; i < server_count; ++i) {
        if (strcmp(servers[i].id, id) == 0) return; // już jest na liście
    }
    if (server_count < MAX_SERVERS) {
        strncpy(servers[server_count].id, id, sizeof(servers[server_count].id));
        strncpy(servers[server_count].name, name, sizeof(servers[server_count].name));
        strncpy(servers[server_count].ip, ip, sizeof(servers[server_count].ip));
        servers[server_count].port = port;
        server_count++;
        printf("Server found: %s [ID: %s] on %s:%d\n", name, id, ip, port);
    }
}

// Wyszukiwanie serwerów (multicast)
void search_servers() {
    int sock;
    struct sockaddr_in addr;
    struct ip_mreq mreq;
    char buffer[BUFFER_SIZE];

    // Tworzenie gniazda UDP
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    // Konfiguracja adresu lokalnego
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(MULTICAST_PORT);

    // Przypisanie gniazda do adresu i portu
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind error");
        exit(EXIT_FAILURE);
    }

    // Dołączenie do grupy multicast
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt error");
        exit(EXIT_FAILURE);
    }

    printf("Listening for servers (press Ctrl+C to exit)...\n");

    // Odbieranie komunikatów multicast i wyświetlanie unikalnych serwerów
    while (1) {
        int n = recvfrom(sock, buffer, sizeof(buffer)-1, 0, NULL, 0);
        if (n < 0) {
            perror("recvfrom");
            break;
        }
        buffer[n] = '\0';

        // Oczekiwany format: <ID>:<NAZWA>:<IP>:<PORT>
        char id[64], name[128], ip[INET_ADDRSTRLEN];
        int port;
        if (sscanf(buffer, "%63[^:]:%127[^:]:%15[^:]:%d", id, name, ip, &port) == 4) {
            add_server(id, name, ip, port);
        }
    }
    close(sock);
}

// Tryb połączenia TCP z serwerem
void connect_to_server(const char *mode, const char *server_id, const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket error");
        return;
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton error");
        close(sock);
        return;
    }
    printf("Connecting to server [%s] at %s:%d...\n", server_id, ip, port);
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect error");
        close(sock);
        return;
    }
    printf("Connected to server [%s] (%s:%d)\n", server_id, ip, port);
    char username[64], password[64], hash_str[SHA256_DIGEST_LENGTH*2+1], buffer[BUFFER_SIZE];
    get_user_credentials(username, sizeof(username), password, sizeof(password));
    hash_password_hex(password, hash_str);

    // Logowanie lub rejestracja
    snprintf(buffer, sizeof(buffer), "%s %s %s\n", 
             (strcmp(mode, "login") == 0) ? "LOGIN" : "REGISTER", username, hash_str);
    send(sock, buffer, strlen(buffer), 0);
    int n = recv(sock, buffer, sizeof(buffer)-1, 0);
    if (n <= 0) {
        printf("Disconnected from server\n");
        close(sock);
        return;
    }
    buffer[n] = '\0';
    if (strcmp(mode, "login") == 0) {
        if (strcmp(buffer, "LOGIN_OK\n") == 0) {
            printf("Logged in successfully.\n");
        } else {
            printf("Invalid username or password.\n");
            close(sock);
            return;
        }
    } else if (strcmp(mode, "register") == 0) {
        if (strcmp(buffer, "REGISTER_OK\n") == 0) {
            printf("Registered successfully.\n");
        } else if (strcmp(buffer, "REGISTER_EXISTS\n") == 0) {
            printf("This user already exists.\n");
            close(sock);
            return;
        } else {
            printf("Registration error.\n");
            close(sock);
            return;
        }
    }
    printf("\n");
    if (receive_welcome_and_history(sock) != 0) {
        close(sock);
        return;
    }
    chat_loop(sock, username);
    close(sock);
}

// Odbiieranie powitania i historii czatu od serwera
int receive_welcome_and_history(int sock) {
    uint32_t len_net;
    size_t received = 0;
    while (received < sizeof(len_net)) {
        ssize_t n = recv(sock, (char*)&len_net + received, sizeof(len_net) - received, 0);
        if (n <= 0) return -1;
        received += n;
    }

    uint32_t msg_len = ntohl(len_net);
    char *msg = malloc(msg_len + 1);
    if (!msg) return -1;

    uint32_t total_received = 0;  // Użyj tego samego typu co msg_len
    while (total_received < msg_len) {
        ssize_t n = recv(sock, msg + total_received, msg_len - total_received, 0);
        if (n <= 0) {
            free(msg);
            return -1;
        }
        total_received += n;
    }

    msg[msg_len] = '\0';
    printf("%s", msg);
    free(msg);
    return 0;
}

// Główna pętla czatu - wysyłanie i odbieranie wiadomości
void chat_loop(int sock, const char *username) {
    char buffer[BUFFER_SIZE];
    int show_prompt = 1;
    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);
        int maxfd = sock > STDIN_FILENO ? sock : STDIN_FILENO;
        if (show_prompt) {
            printf("[%s]: ", username);
            fflush(stdout);
            show_prompt = 0;
        }
        select(maxfd+1, &readfds, NULL, NULL, NULL);
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buffer, sizeof(buffer), stdin) == NULL) break;
            send(sock, buffer, strlen(buffer), 0);
            show_prompt = 1;
        }
        if (FD_ISSET(sock, &readfds)) {
            int n = recv(sock, buffer, sizeof(buffer)-1, 0);
            if (n <= 0) {
                printf("Disconnected from server\n");
                break;
            }
            buffer[n] = '\0';
            printf("\r%s", buffer);
            show_prompt = 1;
        }
    }
}

