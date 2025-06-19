#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#define MULTICAST_GROUP "239.0.0.1"     // Adres grupy multicast, na której serwer będzie się ogłaszał
#define MULTICAST_PORT 12345            // Port UDP multicast, na którym serwer będzie się ogłaszał

#define MAX_SERVERS 10                  // Maksymalna liczba buforowanych pokoi czatu
#define BUFFER_SIZE 1024                // Rozmiar bufora do odbierania wiadomości

struct server_info {
    char id[64];
    char name[128];
    char ip[INET_ADDRSTRLEN];
    int port;
};

struct server_info servers[MAX_SERVERS];
int server_count = 0;

// Dodaje serwer do listy jeśli nie ma już takiego ID
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
        printf("id: %s", id); //test
        printf("Server found: %s [ID: %s] on %s:%d\n", name, id, ip, port);
    }
}

// Tryb wyszukiwania serwerów (multicast)
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

    char username[64], password[64], buffer[BUFFER_SIZE];

    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';

    // Wysyłamy komendę: "LOGIN <login> <hasło>" lub "REGISTER <login> <hasło>"
    snprintf(buffer, sizeof(buffer), "%s %s %s\n", 
             (strcmp(mode, "login") == 0) ? "LOGIN" : "REGISTER", username, password);
    send(sock, buffer, strlen(buffer), 0);

    // Oczekiwanie na odpowiedź serwera
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
        }
        else {
            printf("Invalid username or password.\n");
            close(sock);
            return;
        }
    }
    else if (strcmp(mode, "register") == 0) {
        if (strcmp(buffer, "REGISTER_OK\n") == 0) {
            printf("Registered successfully.\n");
        }
        else if (strcmp(buffer, "REGISTER_EXISTS\n") == 0) {
            printf("This user already exists.\n");
            close(sock);
            return;
        }
        else {
            printf("Registration error.\n");
            close(sock);
            return;
        }
    }

    // Prosty chat: wysyłanie i odbieranie wiadomości
    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        // Ustawienie maksymalnego deskryptora pliku do select
        int maxfd = sock > STDIN_FILENO ? sock : STDIN_FILENO;
        select(maxfd+1, &readfds, NULL, NULL, NULL);

        // Odczyt z klawiatury i wysyłka do serwera
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buffer, sizeof(buffer), stdin) == NULL) break;
            send(sock, buffer, strlen(buffer), 0);
        }
        
        // Sprawdzenie, czy gniazdo serwera jest gotowe do odczytu
        // jeśli tak, to odbieramy wiadomość
        if (FD_ISSET(sock, &readfds)) {
            int n = recv(sock, buffer, sizeof(buffer)-1, 0);

            // Sprawdzenie błędów odczytu, jeśli n <= 0, to wystąpił błąd lub serwer zamknął połączenie
            if (n <= 0) {
                printf("Disconnected from server\n");
                break;
            }

            // Dodanie znaku końca łańcucha i wyświetlenie wiadomości
            buffer[n] = '\0';
            printf("%s", buffer);
        }
    }
    close(sock);
}

int main(int argc, char *argv[]) {
    // Tryb wyszukiwania serwerów przez multicast
    if (argc == 2 && strcmp(argv[1], "search") == 0) {
        search_servers();
    }
    // Tryb połączenia TCP z serwerem (bez multicast)
    else if (argc == 6 && strcmp(argv[1], "connect") == 0) {
        const char *mode = argv[2];
        const char *id = argv[3];
        const char *ip = argv[4];
        int port = atoi(argv[5]);
        
        if (strcmp(mode, "login") == 0 || strcmp(mode, "register") == 0) {
            connect_to_server(mode, id, ip, port);
        }
        else {
            printf("Invalid parameter. Use './client connect login ...' to login or './client connect register ...' to register new user.\n");
        }

    }
    // Nieprawidłowe wywołanie programu
    else {
        printf("Usage:\n");
        printf("  %s search\n", argv[0]);
        printf("  %s connect <login|register> <ID> <IP> <PORT>\n", argv[0]);
    }
    return 0;
}
