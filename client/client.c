#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>                     // Na potrzeby getpass do bezwyświetleniowego pozyskiwania hasła od użytkownika
#include <openssl/sha.h>                // Na potrzeby funkcjonalności hashowania hasła użytkownika

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

// Funkcja do pobrania nazwy użytkownika i hasła
void get_user_credentials(char *username, size_t ulen, char *password, size_t plen) {
    printf("Username: ");
    fgets(username, ulen, stdin);
    username[strcspn(username, "\n")] = '\0';
    char *password_ptr = getpass("Password: ");
    strncpy(password, password_ptr, plen - 1);
    password[plen - 1] = '\0';
}

// Funkcja do wysyłania komendy logowania lub rejestracji do serwera
int send_login_or_register(int sock, const char *mode, const char *username, const char *hash_str, char *buffer) {
    snprintf(buffer, BUFFER_SIZE, "%s %s %s\n", mode, username, hash_str);
    send(sock, buffer, strlen(buffer), 0);
    int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (n <= 0) return -1;
    buffer[n] = '\0';
    return 0;
}

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

// Funkcja hashująca hasło użytkownika przed przesłaniem przez sieć
void hash_password(const char *password, unsigned char *output) {
    SHA256((unsigned char*)password, strlen(password), output);
}

// Funkcja do hashowania hasła na format szesnastkowy
void hash_password_hex(const char *password, char *hash_str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hash_str + i * 2, "%02x", hash[i]);
    hash_str[SHA256_DIGEST_LENGTH * 2] = '\0';
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

// Odbiieranie powitania i historii czatu od serwera
int receive_welcome_and_history(int sock) {
    uint32_t len_net;
    int received = 0;
    while (received < sizeof(len_net)) {
        int n = recv(sock, ((char*)&len_net) + received, sizeof(len_net) - received, 0);
        if (n <= 0) return -1;
        received += n;
    }
    uint32_t msg_len = ntohl(len_net);
    char *welcome_buf = malloc(msg_len + 1);
    if (!welcome_buf) return -1;
    received = 0;
    while (received < msg_len) {
        int n = recv(sock, welcome_buf + received, msg_len - received, 0);
        if (n <= 0) { free(welcome_buf); return -1; }
        received += n;
    }
    welcome_buf[msg_len] = '\0';
    printf("%s", welcome_buf);
    free(welcome_buf);
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

// nowa funkcja !
void handle_connect_mode(int argc, char *argv[]) {
    // Tryb połączenia TCP z serwerem (bez multicast)
    if (argc == 6 && strcmp(argv[1], "connect") == 0) {
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
}

// Logika logowania do serwera plików
int login_to_file_server(int sock, char *username, char *password, char *buffer) {
    char hash_str[SHA256_DIGEST_LENGTH*2 + 1];
    hash_password_hex(password, hash_str);
    snprintf(buffer, BUFFER_SIZE, "LOGIN %s %s\n", username, hash_str);
    send(sock, buffer, strlen(buffer), 0);
    int n = recv(sock, buffer, BUFFER_SIZE-1, 0);
    if (n <= 0 || strncmp(buffer, "LOGIN_OK\n", 9) != 0) {
        printf("Login failed\n");
        return 1;
    }
    return 0;
}

// Logika przesyłania plików
int upload_file(int sock, const char *filename, char *buffer) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    int filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    snprintf(buffer, BUFFER_SIZE, "UPLOAD %s %d\n", filename, filesize);
    send(sock, buffer, strlen(buffer), 0);
    int n = recv(sock, buffer, BUFFER_SIZE-1, 0);
    if (n <= 0 || strncmp(buffer, "UPLOAD_OK", 9) != 0) {
        printf("Upload failed\n");
        fclose(file);
        return 1;
    }
    while ((n = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        send(sock, buffer, n, 0);
    }
    fclose(file);
    printf("File uploaded successfully\n");
    return 0;
}

// Logika pobierania plików
int download_file(int sock, const char *filename, char *buffer) {
    snprintf(buffer, BUFFER_SIZE, "DOWNLOAD %s\n", filename);
    send(sock, buffer, strlen(buffer), 0);
    int n = recv(sock, buffer, BUFFER_SIZE-1, 0);
    if (n <= 0) {
        printf("Download failed\n");
        return 1;
    }
    int filesize;
    if (sscanf(buffer, "DOWNLOAD %d", &filesize) != 1) {
        printf("Download failed\n");
        return 1;
    }
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("fopen");
        return 1;
    }
    int total = 0;
    while (total < filesize) {
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n <= 0) break;
        fwrite(buffer, 1, n, file);
        total += n;
    }
    fclose(file);
    printf("File downloaded successfully\n");
    return 0;
}

// Obsługa przesyłania plików (upload/download)
int handle_file_transfer(int argc, char *argv[]) {
    if ((argc == 6) && (strcmp(argv[1], "upload") == 0 || strcmp(argv[1], "download") == 0)) {
        const char *mode = argv[1];
        const char *server_id = argv[2];
        const char *ip = argv[3];
        int port = atoi(argv[4]);
        const char *filename = argv[5];

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &serv_addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("connect error");
            return 1;
        }

        char username[64], password[64], buffer[BUFFER_SIZE];
        get_user_credentials(username, sizeof(username), password, sizeof(password));
        if (login_to_file_server(sock, username, password, buffer) != 0) {
            close(sock);
            return 1;
        }
        int result = 0;
        if (strcmp(mode, "upload") == 0) {
            result = upload_file(sock, filename, buffer);
        } else if (strcmp(mode, "download") == 0) {
            result = download_file(sock, filename, buffer);
        }
        close(sock);
        exit(result);
    }
    return 0;
}

// nowa funkcja !
void print_usage(char *argv[]) {
    // Nieprawidłowe wywołanie programu
    printf("Usage:\n");
    printf("  %s search\n", argv[0]);
    printf("  %s connect <login|register> <ID> <IP> <PORT>\n", argv[0]);
    printf("  %s upload <ID> <IP> <PORT> <filename to upload>\n", argv[0]);
    printf("  %s download <ID> <IP> <PORT> <filename to download>\n", argv[0]);
}

int main(int argc, char *argv[]) {
    // Tryb wyszukiwania serwerów przez multicast
    if (argc == 2 && strcmp(argv[1], "search") == 0) {
        search_servers();
    }
    else {
        handle_connect_mode(argc, argv);
        handle_file_transfer(argc, argv);
        print_usage(argv);
    }
    return 0;
}
