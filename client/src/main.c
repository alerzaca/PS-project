#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "network.h"
#include "filetransfer.h"
#include "credentials.h"

// nowa funkcja !
void print_usage(char *argv[]) {
    // Nieprawidłowe wywołanie programu
    printf("Usage:\n");
    printf("  %s search\n", argv[0]);
    printf("  %s connect <login|register> <ID> <IP> <PORT>\n", argv[0]);
    printf("  %s upload <ID> <IP> <PORT> <filename to upload>\n", argv[0]);
    printf("  %s download <ID> <IP> <PORT> <filename to download>\n", argv[0]);
}

// Tryb połączenia TCP z czatem (login/rejestracja)
int handle_connect_mode(int argc, char *argv[]) {
    if (argc == 6 && strcmp(argv[1], "connect") == 0) {
        const char *mode = argv[2];
        const char *id = argv[3];
        const char *ip = argv[4];
        int port = atoi(argv[5]);

        if (strcmp(mode, "login") == 0 || strcmp(mode, "register") == 0) {
            connect_to_server(mode, id, ip, port);
            return 1;  // obsłużono
        } else {
            fprintf(stderr, "Invalid mode: %s. Use 'login' or 'register'.\n", mode);
            return 1;  // też uznajemy za obsłużone, bo wypisaliśmy błąd
        }
    }
    return 0;  // nie dotyczy tego trybu
}

// Obsługa przesyłania plików (upload/download)
int handle_file_transfer(int argc, char *argv[]) {
    if ((argc == 6) && (strcmp(argv[1], "upload") == 0 || strcmp(argv[1], "download") == 0)) {
        const char *mode = argv[1];
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
