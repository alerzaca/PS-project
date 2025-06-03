#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 8080

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buffer[1024] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Błąd tworzenia gniazda\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Konwersja adresu IP
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("Nieprawidłowy adres / Adres nie wspierany\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Połączenie nieudane\n");
        return -1;
    }

    send(sock, hello, strlen(hello), 0);
    printf("Wiadomość wysłana\n");
    read(sock, buffer, 1024);
    printf("Odpowiedź serwera: %s\n", buffer);

    close(sock);
    return 0;
}
