#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <time.h>

#define MULTICAST_GROUP "239.0.0.1" // Adres grupy multicast, na której serwer będzie się ogłaszał
#define MULTICAST_PORT 12345        // Port UDP multicast, na którym serwer będzie się ogłaszał
#define TCP_PORT 8080               // Port TCP, na którym serwer będzie obsługiwał chat

#define BACKLOG 3                   // Maksymalna liczba oczekujących połączeń
#define MAX_CLIENTS 10              // Maksymalna liczba jednocześnie połączonych klientów
#define SERVER_ID_LEN 7             // 6 znaków + '\0'

// Generowanie prostego unikalnego ID na podstawie czasu i PID
void generate_id(char *id, size_t size) {
    unsigned int hash = (unsigned int)time(NULL) ^ (unsigned int)getpid();
    snprintf(id, size, "%06X", hash % 0xFFFFFF); // np. "A1B2C3"
}

// Struktura argumentów dla wątku multicast
struct thread_args {
    char server_name[128];
    char server_id[SERVER_ID_LEN];
    char ip[INET_ADDRSTRLEN];
};

// Wątek rozgłaszania multicast
void* multicast_broadcast(void *arg) {
    struct thread_args *targs = (struct thread_args*)arg;
    char *server_name = targs->server_name;
    char *server_id = targs->server_id;
    char *ip = targs->ip;

    int sock;
    struct sockaddr_in addr;
    char message[256];

    // Tworzenie gniazda UDP
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP socket error");
        pthread_exit(NULL);
    }

    // Konfiguracja adresu multicast
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);
    addr.sin_port = htons(MULTICAST_PORT);

    // Rozgłaszanie informacji o serwerze co 5 sekund
    while(1) {
        // Przygotowanie wiadomości do rozgłoszenia
        // Format: <ID>:<Name>:<IP>:<Port>
        snprintf(message, sizeof(message), "%s:%s:%s:%d", server_id, server_name, ip, TCP_PORT);

        if (sendto(sock, message, strlen(message), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("sendto error");
            close(sock);
            pthread_exit(NULL);
        }
        
        // Można odkomentować poniższą linię, aby zobaczyć wysyłane wiadomości, ale szybko może to zapełnić konsolę
        //printf("[Multicast message]: '%s'\n", message);
        sleep(5);
    }

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_name> <network interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_name = argv[1];
    char *ifname = argv[2];
    char ip[INET_ADDRSTRLEN] = "0.0.0.0";

    // Pobieranie adresu IP interfejsu sieciowego
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr &&
            ifa->ifa_addr->sa_family == AF_INET &&
            strcmp(ifa->ifa_name, ifname) == 0) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
            break;
        }
    }
    freeifaddrs(ifaddr);

    // Obliczenie unikalnego ID serwera
    char server_id[SERVER_ID_LEN];
    generate_id(server_id, sizeof(server_id));

    // Przygotowanie argumentów do wątku
    struct thread_args *targs = malloc(sizeof(struct thread_args));
    strncpy(targs->server_name, server_name, sizeof(targs->server_name)-1);
    strncpy(targs->server_id, server_id, sizeof(targs->server_id)-1);
    strncpy(targs->ip, ip, INET_ADDRSTRLEN);

    // Uruchomienie nowego wątku multicast
    pthread_t multicast_thread;
    if (pthread_create(&multicast_thread, NULL, multicast_broadcast, targs) != 0) {
        perror("pthread_create");
        free(targs);
        return 1;
    }

    // Inicjalizacja gniazda TCP
    int server_fd, new_socket;
    struct sockaddr_in server_addr, client_addr;
    int opt = 1;
    char buffer[1024];

    // Tworzenie gniazda
    // AF_INET - IPv4, SOCK_STREAM - TCP, 0 - domyślny protokół
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("TCP socket error");
        exit(EXIT_FAILURE);
    }

    // Ustawianie opcji gniazda
    // SO_REUSEADDR - pozwala na ponowne użycie adresu (przy restartach serwera)
    // SO_REUSEPORT - pozwala wielu procesom na nasłuchiwanie na tym samym porcie
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt error");
        exit(EXIT_FAILURE);
    }

    // Konfiguracja adresu serwera
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TCP_PORT);

    // Bind - przypisanie gniazda do adresu i portu
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind error");
        exit(EXIT_FAILURE);
    }

    printf("Server opened as '%s' [ID: %s] on port %d \n", server_name, server_id, TCP_PORT);

    // Listen
    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen error");
        exit(EXIT_FAILURE);
    }

    // Główna pętla serwera
    while (1) {
        socklen_t client_addrlen = sizeof(client_addr);

        if ((new_socket = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t*)&client_addrlen)) < 0) {
            perror("accept error");
            continue;
        }

        // Pobranie adresu IP i portu klienta
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);

        printf("New connection from %s:%d\n", client_ip, client_port);

        int valread;
        while ((valread = read(new_socket, buffer, sizeof(buffer)-1)) > 0) {
            buffer[valread] = '\0';
            printf("Message received from %s:%d: %s", client_ip, client_port, buffer);
            send(new_socket, buffer, valread, 0);
        }
        printf("Client %s:%d disconnected\n", client_ip, client_port);
        close(new_socket);
    }

    pthread_cancel(multicast_thread);
    pthread_join(multicast_thread, NULL);
    close(server_fd);
    free(targs);
    return 0;
}
